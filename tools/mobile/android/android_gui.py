#!/usr/bin/env python3
"""
secV Android Pentest GUI
Full-featured web GUI for all android pentest operations.

Launched via android_pentest: set mode gui; run
Standalone: python3 android_gui.py [--port 8897] [--serial <device>]
"""
import argparse, json, os, queue, re, shutil, subprocess, sys
import threading, time, webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

# ── Globals ────────────────────────────────────────────────────────────────────
_GUI_PORT    = 8897
_C2_PORT     = 8891
_MODULE_DIR  = Path(__file__).parent
_SCRIPT      = _MODULE_DIR / "android_pentest.py"
_C2_SCRIPT   = _MODULE_DIR / "c2_gui.py"
_PYTHON      = sys.executable

_current_proc: Optional[subprocess.Popen] = None
_c2_proc:      Optional[subprocess.Popen] = None
_proc_lock    = threading.Lock()
_sse_clients: list = []          # list of queue.Queue, one per SSE connection
_sse_lock     = threading.Lock()
_op_status    = {"running": False, "op": "", "pid": None}
_gui_settings = {"lhost": "", "lport": "4444", "bore_server": "bore.pub",
                 "nvd_api_key": "", "c2_host": "", "c2_port": "8889"}
_captured_qr: list = []          # QR strings/ASCII captured from operation output

# ── Broadcast helpers ──────────────────────────────────────────────────────────

def _broadcast(line: str):
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _run_operation(context: dict):
    global _current_proc
    payload = json.dumps(context).encode()
    with _proc_lock:
        _op_status["running"] = True
        _op_status["op"]      = context.get("params", {}).get("operation", "?")
    _broadcast(f"\x1b[32m[+] Starting: {_op_status['op']}\x1b[0m")
    try:
        proc = subprocess.Popen(
            [_PYTHON, str(_SCRIPT)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=1,
        )
        with _proc_lock:
            _current_proc = proc
            _op_status["pid"] = proc.pid
        proc.stdin.write(payload)
        proc.stdin.close()
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode(errors="replace").rstrip("\n")
            _broadcast(line)
            _maybe_capture_qr(line)
        proc.wait()
        _broadcast(f"\x1b[33m[*] Exit code: {proc.returncode}\x1b[0m")
    except Exception as e:
        _broadcast(f"\x1b[31m[!] Error: {e}\x1b[0m")
    finally:
        with _proc_lock:
            _current_proc = None
            _op_status["running"] = False
            _op_status["pid"]     = None
        _broadcast("\x1b[35m[done]\x1b[0m")


def _adb(*args) -> str:
    adb = shutil.which("adb") or "adb"
    try:
        r = subprocess.run([adb] + list(args), capture_output=True, text=True, timeout=10)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)


_qr_buf: list = []
def _maybe_capture_qr(line: str):
    """Buffer consecutive lines that look like ASCII QR art, then store them."""
    stripped = line.strip()
    # detect QR block start/end (dense ░▓█ characters or ▄▀ style)
    if any(c in stripped for c in ("█", "▄", "▀", "░", "▓", "▐", "▌")):
        _qr_buf.append(line)
    else:
        if len(_qr_buf) >= 4:
            _captured_qr.append("\n".join(_qr_buf))
            _broadcast("\x1b[35m[qr-captured]\x1b[0m")
        _qr_buf.clear()
    # also capture QR delivery URLs
    if "bore.pub" in line or "trycloudflare.com" in line:
        m = re.search(r'https?://\S+', line)
        if m:
            _captured_qr.append(f"URL: {m.group()}")
            _broadcast(f"\x1b[35m[qr-url-captured] {m.group()}\x1b[0m")


def _c2_running() -> bool:
    global _c2_proc
    if _c2_proc and _c2_proc.poll() is None:
        return True
    _c2_proc = None
    return False


def _ensure_c2(port: int = _C2_PORT) -> bool:
    global _c2_proc
    if _c2_running():
        return True
    if not _C2_SCRIPT.exists():
        return False
    try:
        _c2_proc = subprocess.Popen(
            [_PYTHON, str(_C2_SCRIPT), "--port", str(port), "--no-browser"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        return _c2_proc.poll() is None
    except Exception:
        return False


# ── HTTP Handler ───────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):

    def log_message(self, *_):
        pass

    # ── routing ──────────────────────────────────────────────────────────────

    def do_GET(self):
        p = urlparse(self.path).path
        if   p == "/" or p == "/index.html":   self._serve_html()
        elif p == "/api/devices":              self._api_devices()
        elif p == "/api/stream":               self._api_sse()
        elif p == "/api/status":               self._api_status()
        elif p == "/api/applist":              self._api_applist()
        elif p == "/api/devinfo":              self._api_devinfo()
        elif p == "/api/deps":                 self._api_deps()
        elif p == "/api/workdir":              self._api_workdir()
        elif p == "/api/lhost":                self._api_lhost()
        elif p == "/api/qr":                   self._api_qr()
        elif p == "/api/settings":             self._api_get_settings()
        elif p == "/api/c2/launch":            self._api_c2_launch()
        elif p == "/api/c2/stop":              self._api_c2_stop()
        elif p == "/api/c2/status":            self._api_c2_status()
        else:                                  self._send(404, "text/plain", b"not found")

    def do_POST(self):
        p = urlparse(self.path).path
        body = self._read_body()
        if   p == "/api/run":      self._api_run(body)
        elif p == "/api/kill":     self._api_kill()
        elif p == "/api/adb":      self._api_adb(body)
        elif p == "/api/settings": self._api_settings(body)
        else:                      self._send(404, "text/plain", b"not found")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send(self, code: int, ct: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data):
        self._send(200, "application/json", json.dumps(data).encode())

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length) if length else b"{}"
        try:    return json.loads(raw)
        except: return {}

    # ── endpoints ─────────────────────────────────────────────────────────────

    def _api_devices(self):
        out  = _adb("devices", "-l")
        devs = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "offline" in line: continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                info = {"serial": parts[0], "tags": " ".join(parts[2:])}
                devs.append(info)
        self._json({"devices": devs})

    def _api_devinfo(self):
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        prefix = ["-s", serial] if serial else []
        props  = {}
        for prop in ["ro.product.model", "ro.product.brand", "ro.build.version.release",
                     "ro.build.version.sdk", "ro.product.cpu.abi", "ro.serialno"]:
            val = _adb(*prefix, "shell", "getprop", prop)
            props[prop] = val.strip()
        self._json(props)

    def _api_applist(self):
        qs       = parse_qs(urlparse(self.path).query)
        serial   = (qs.get("serial") or [""])[0]
        prefix   = ["-s", serial] if serial else []
        out      = _adb(*prefix, "shell", "pm", "list", "packages", "-3")
        packages = sorted(l.replace("package:", "").strip() for l in out.splitlines() if l.startswith("package:"))
        self._json({"packages": packages})

    def _api_status(self):
        with _proc_lock:
            self._json(dict(_op_status))

    def _api_run(self, body: dict):
        if _op_status["running"]:
            self._json({"ok": False, "error": "operation already running"})
            return
        threading.Thread(target=_run_operation, args=(body,), daemon=True).start()
        self._json({"ok": True})

    def _api_kill(self):
        with _proc_lock:
            p = _current_proc
        if p:
            try:
                p.terminate()
                _broadcast("\x1b[31m[!] Operation killed\x1b[0m")
            except Exception as e:
                _broadcast(f"\x1b[31m[!] Kill failed: {e}\x1b[0m")
        self._json({"ok": True})

    def _api_adb(self, body: dict):
        args = body.get("args", [])
        if not isinstance(args, list):
            self._json({"output": "invalid args"})
            return
        out = _adb(*args)
        self._json({"output": out})

    def _api_qr(self):
        self._json({"qr": list(_captured_qr)})

    def _api_get_settings(self):
        self._json({"settings": _gui_settings})

    def _api_lhost(self):
        import socket as _sock
        ip = ""
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        self._json({"lhost": ip})

    def _api_deps(self):
        tools = {
            # system
            "adb":          {"cmd": "adb", "install": "pacman -S android-tools  # or apt install adb"},
            "apktool":      {"cmd": "apktool", "install": "pacman -S apktool  # or apt install apktool"},
            "aapt2":        {"cmd": "aapt2", "install": "included with Android SDK build-tools"},
            "aapt":         {"cmd": "aapt", "install": "pacman -S android-tools"},
            "jadx":         {"cmd": "jadx", "install": "pacman -S jadx  # or apt install jadx"},
            "keytool":      {"cmd": "keytool", "install": "apt install default-jdk"},
            "msfvenom":     {"cmd": "msfvenom", "install": "apt install metasploit-framework"},
            "msfconsole":   {"cmd": "msfconsole", "install": "apt install metasploit-framework"},
            "frida":        {"cmd": "frida", "install": "pip3 install frida-tools"},
            "objection":    {"cmd": "objection", "install": "pip3 install objection"},
            "bore":         {"cmd": "bore", "install": "curl -sL https://github.com/ekzhang/bore/releases/download/v0.5.1/bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C ~/.local/bin"},
            "cloudflared":  {"cmd": "cloudflared", "install": "apt install cloudflared"},
            "nmap":         {"cmd": "nmap", "install": "pacman -S nmap  # or apt install nmap"},
            "qrencode":     {"cmd": "qrencode", "install": "apt install qrencode"},
            # python
            "paramiko":     {"cmd": None, "pymod": "paramiko", "install": "pip3 install paramiko"},
            "requests":     {"cmd": None, "pymod": "requests", "install": "pip3 install requests"},
            "qrcode":       {"cmd": None, "pymod": "qrcode", "install": "pip3 install qrcode[pil]"},
            "cryptography": {"cmd": None, "pymod": "cryptography", "install": "pip3 install cryptography"},
            "frida-py":     {"cmd": None, "pymod": "frida", "install": "pip3 install frida"},
        }
        result = {}
        for name, info in tools.items():
            if info.get("cmd"):
                ok = shutil.which(info["cmd"]) is not None
            else:
                try:
                    __import__(info["pymod"])
                    ok = True
                except ImportError:
                    ok = False
            result[name] = {"ok": ok, "install": info["install"]}
        self._json({"deps": result})

    def _api_workdir(self):
        base = Path.home() / ".secv" / "android"
        files = []
        if base.exists():
            for p in sorted(base.rglob("*"))[-200:]:
                if p.is_file():
                    try:
                        files.append({
                            "path": str(p.relative_to(Path.home())),
                            "full": str(p),
                            "size": p.stat().st_size,
                            "mtime": int(p.stat().st_mtime),
                        })
                    except Exception:
                        pass
        files.sort(key=lambda x: x["mtime"], reverse=True)
        self._json({"files": files[:100], "base": str(base)})

    def _api_settings(self, body: dict):
        _gui_settings.update({k: v for k, v in body.items() if k in
            ("lhost", "lport", "bore_server", "nvd_api_key", "c2_host", "c2_port")})
        self._json({"ok": True, "settings": _gui_settings})

    def _api_c2_status(self):
        qs   = parse_qs(urlparse(self.path).query)
        port = int((qs.get("port") or [str(_C2_PORT)])[0])
        self._json({"running": _c2_running(), "port": port,
                    "url": f"http://127.0.0.1:{port}"})

    def _api_c2_launch(self):
        qs   = parse_qs(urlparse(self.path).query)
        port = int((qs.get("port") or [str(_C2_PORT)])[0])
        ok   = _ensure_c2(port)
        self._json({"ok": ok, "port": port, "url": f"http://127.0.0.1:{port}"})

    def _api_c2_stop(self):
        global _c2_proc
        with _proc_lock:
            p = _c2_proc
        if p:
            try:
                p.terminate()
                _c2_proc = None
            except Exception:
                pass
        self._json({"ok": True})

    def _api_sse(self):
        q: queue.Queue = queue.Queue(maxsize=512)
        with _sse_lock:
            _sse_clients.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()
        try:
            while True:
                try:
                    line = q.get(timeout=20)
                    data = "data: " + line.replace("\n", " ") + "\n\n"
                    self.wfile.write(data.encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            with _sse_lock:
                try: _sse_clients.remove(q)
                except ValueError: pass

    def _serve_html(self):
        html = _HTML.encode()
        self._send(200, "text/html; charset=utf-8", html)


# ── Embedded HTML ──────────────────────────────────────────────────────────────
_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>secV · Android Pentest</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;1,300&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#060606;--bg1:#0e0e0e;--bg2:#161616;--bg3:#1e1e1e;--bg4:#282828;
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.14);--border3:rgba(255,255,255,0.24);
  --text:#a0a0a0;--muted:#4a4a4a;--white:#efefef;--off:#cccccc;--grey:#707070;
  --green:#4caf50;--red:#e53935;--blue:#3d8bcd;--green-dim:rgba(76,175,80,0.15);
  --red-dim:rgba(229,57,53,0.12);--blue-dim:rgba(61,139,205,0.12);
  --mono:'JetBrains Mono',monospace;--disp:'Syne',sans-serif;--t:0.14s ease;
}
*{box-sizing:border-box;margin:0;padding:0;}
html{-webkit-font-smoothing:antialiased;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);
  height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:13px;line-height:1.6;}
a{color:var(--blue);text-decoration:none;}
::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--bg4);}

/* TOP BAR */
#topbar{
  display:flex;align-items:center;gap:14px;padding:0 18px;height:52px;
  background:var(--bg);border-bottom:1px solid var(--border2);flex-shrink:0;
}
#topbar .logo{
  font-family:var(--disp);font-size:1.05rem;font-weight:800;
  color:var(--white);letter-spacing:-0.02em;white-space:nowrap;
}
#topbar .logo-sep{color:var(--muted);font-weight:400;margin:0 4px;}
#topbar .logo-sub{
  font-family:var(--mono);font-size:0.6rem;letter-spacing:0.14em;
  text-transform:uppercase;color:var(--muted);
}
#topbar .devbadge{
  display:flex;align-items:center;gap:8px;
  border:1px solid var(--border2);padding:4px 12px;
}
#topbar .devbadge #dev-name{color:var(--white);font-size:0.72rem;font-family:var(--mono);}
#topbar .devbadge #dev-os{color:var(--muted);font-size:0.6rem;}
#topbar .tb-btn{
  background:none;border:1px solid var(--border2);
  color:var(--muted);padding:5px 12px;cursor:pointer;font-family:var(--mono);
  font-size:0.65rem;letter-spacing:0.08em;text-transform:uppercase;white-space:nowrap;
  transition:border-color var(--t),color var(--t);
}
#topbar .tb-btn:hover{border-color:var(--border3);color:var(--white);}
#topbar #kill-btn{border-color:rgba(229,57,53,0.4);color:var(--red);}
#topbar #kill-btn:hover{background:var(--red-dim);border-color:var(--red);}
#topbar #kill-btn.active{animation:pulse .7s infinite;}
@keyframes pulse{0%{opacity:1}50%{opacity:.35}100%{opacity:1}}
#lhost-display{font-size:0.58rem;letter-spacing:0.1em;color:var(--muted);margin-left:auto;}

/* MAIN */
#main{display:flex;flex:1;overflow:hidden;}

/* SIDEBAR */
#sidebar{
  width:220px;flex-shrink:0;background:var(--bg1);border-right:1px solid var(--border2);
  display:flex;flex-direction:column;overflow-y:auto;
}
#dev-selector{padding:10px 12px;border-bottom:1px solid var(--border2);}
#dev-selector select{
  width:100%;background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  padding:6px 8px;font-family:var(--mono);font-size:0.72rem;
}
#dev-selector button{
  width:100%;margin-top:6px;background:none;border:1px solid var(--border2);
  color:var(--muted);padding:5px;font-family:var(--mono);font-size:0.62rem;
  letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;
  transition:color var(--t),border-color var(--t);
}
#dev-selector button:hover{color:var(--white);border-color:var(--border3);}
.op-group{border-bottom:1px solid var(--border);}
.op-group-title{
  padding:8px 12px;color:var(--muted);font-size:0.58rem;text-transform:uppercase;
  letter-spacing:0.18em;cursor:pointer;user-select:none;display:flex;
  justify-content:space-between;align-items:center;
  transition:color var(--t);
}
.op-group-title:hover{color:var(--grey);}
.op-group-title .arrow{transition:.2s;font-size:0.5rem;}
.op-group.collapsed .arrow{transform:rotate(-90deg);}
.op-group.collapsed .op-list{display:none;}
.op-item{
  padding:8px 14px;cursor:pointer;color:var(--grey);font-size:0.72rem;
  border-left:2px solid transparent;transition:color var(--t),background var(--t);
}
.op-item:hover{color:var(--white);background:var(--bg2);}
.op-item.active{color:var(--white);border-left-color:var(--white);background:var(--bg2);}

/* RIGHT */
#right{display:flex;flex-direction:column;flex:1;overflow:hidden;}

/* PARAMS PANEL */
#params-panel{
  background:var(--bg1);border-bottom:1px solid var(--border2);
  padding:14px 18px;flex-shrink:0;overflow-y:auto;max-height:240px;
}
#params-panel .op-title{
  font-family:var(--disp);font-size:1rem;font-weight:700;letter-spacing:-0.02em;
  color:var(--white);margin-bottom:4px;
}
#params-panel .op-desc{color:var(--muted);font-size:0.68rem;margin-bottom:12px;line-height:1.7;}
#params-form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;}
.field{display:flex;flex-direction:column;gap:4px;min-width:150px;}
.field label{
  color:var(--muted);font-size:0.58rem;text-transform:uppercase;letter-spacing:0.12em;
}
.field input,.field select{
  background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  padding:6px 8px;font-family:var(--mono);font-size:0.75rem;width:100%;
  transition:border-color var(--t);
}
.field input:focus,.field select:focus{outline:none;border-color:var(--border3);}
#run-btn{
  background:var(--white);color:var(--bg);border:none;padding:7px 20px;
  font-family:var(--disp);font-size:0.78rem;font-weight:700;letter-spacing:0.04em;
  cursor:pointer;height:32px;margin-top:auto;text-transform:uppercase;
  transition:background var(--t);
}
#run-btn:hover{background:var(--off);}
#run-btn:disabled{background:var(--bg4);cursor:not-allowed;color:var(--muted);}

/* TABS */
#tabs{
  display:flex;background:var(--bg1);border-bottom:1px solid var(--border2);
  flex-shrink:0;overflow-x:auto;
}
.tab{
  padding:10px 16px;cursor:pointer;color:var(--muted);
  font-size:0.65rem;letter-spacing:0.1em;text-transform:uppercase;
  border-bottom:2px solid transparent;transition:color var(--t),border-color var(--t);white-space:nowrap;
}
.tab:hover{color:var(--grey);}
.tab.active{color:var(--white);border-bottom-color:var(--white);}
.tab .badge{
  display:inline-block;background:var(--red);color:var(--white);
  font-size:0.5rem;padding:1px 5px;margin-left:5px;letter-spacing:0;
}

/* TERMINAL */
#terminal-wrap{flex:1;overflow:hidden;display:flex;flex-direction:column;}
#terminal{
  flex:1;overflow-y:auto;padding:14px 18px;background:var(--bg);
  font-family:var(--mono);font-size:0.78rem;line-height:1.75;white-space:pre-wrap;word-break:break-all;
}
#terminal .ln{display:block;}
#terminal .ts{color:var(--muted);margin-right:8px;user-select:none;font-size:0.62rem;}

/* ADB CONSOLE */
#adb-console{display:none;flex-direction:column;flex:1;overflow:hidden;}
#adb-output{
  flex:1;overflow-y:auto;padding:14px 18px;background:var(--bg);
  font-family:var(--mono);font-size:0.78rem;line-height:1.75;white-space:pre-wrap;
}
#adb-input-row{
  display:flex;gap:8px;padding:10px 14px;background:var(--bg1);
  border-top:1px solid var(--border2);align-items:center;
}
#adb-input-row span{color:var(--green);font-size:0.75rem;}
#adb-input{
  flex:1;background:transparent;border:none;color:var(--white);
  font-family:var(--mono);font-size:0.78rem;outline:none;
}

/* FINDINGS */
#findings-panel{display:none;flex-direction:column;flex:1;overflow-y:auto;padding:16px;}
.finding-card{
  background:var(--bg1);border:1px solid var(--border2);
  margin-bottom:8px;padding:14px 16px;
}
.finding-card .fh{display:flex;gap:8px;align-items:center;margin-bottom:6px;}
.sev{font-size:0.52rem;letter-spacing:0.1em;text-transform:uppercase;padding:2px 8px;font-weight:600;}
.sev.CRITICAL{background:var(--red-dim);color:var(--red);border:1px solid rgba(229,57,53,0.3);}
.sev.HIGH{background:rgba(230,120,40,0.1);color:#e67828;border:1px solid rgba(230,120,40,0.3);}
.sev.MEDIUM{background:rgba(200,170,50,0.1);color:#c8aa32;border:1px solid rgba(200,170,50,0.3);}
.sev.LOW{background:var(--blue-dim);color:var(--blue);border:1px solid rgba(61,139,205,0.3);}
.sev.INFO{background:var(--green-dim);color:var(--green);border:1px solid rgba(76,175,80,0.3);}
.finding-card .fdesc{font-size:0.75rem;color:var(--text);line-height:1.7;}

/* QR TAB */
#qr-panel{display:none;flex-direction:column;flex:1;overflow-y:auto;padding:16px;}
.qr-card{
  background:var(--bg1);border:1px solid var(--border2);
  margin-bottom:12px;padding:14px 16px;
}
.qr-card pre{color:var(--green);font-size:0.68rem;line-height:1.1;overflow-x:auto;}
.qr-url{color:var(--blue);font-size:0.8rem;word-break:break-all;}

/* SETUP/DEPS TAB */
#setup-panel{display:none;flex-direction:column;flex:1;overflow-y:auto;padding:16px;}
.dep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1px;
  background:var(--border2);border:1px solid var(--border2);margin-bottom:16px;}
.dep-card{
  background:var(--bg1);padding:12px 14px;display:flex;align-items:center;gap:10px;
}
.dep-card .dep-dot{width:6px;height:6px;flex-shrink:0;}
.dep-card .dep-dot.ok{background:var(--green);}
.dep-card .dep-dot.miss{background:var(--red);}
.dep-card .dep-name{font-size:0.75rem;color:var(--white);flex:1;}
.dep-card .dep-install{font-size:0.6rem;color:var(--muted);margin-top:2px;}
.settings-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin-top:12px;}
.settings-grid .field{min-width:unset;}
#save-settings{
  background:var(--white);color:var(--bg);border:none;padding:7px 18px;
  font-family:var(--disp);font-size:0.72rem;font-weight:700;letter-spacing:0.06em;
  text-transform:uppercase;cursor:pointer;margin-top:12px;transition:background var(--t);
}
#save-settings:hover{background:var(--off);}

/* FILES TAB */
#files-panel{display:none;flex-direction:column;flex:1;overflow-y:auto;padding:16px;}
.file-row{
  display:flex;align-items:center;gap:10px;padding:8px 10px;
  border-bottom:1px solid var(--border);font-size:0.72rem;transition:background var(--t);
}
.file-row:hover{background:var(--bg2);}
.file-row .fn{color:var(--white);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.file-row .fsz{color:var(--muted);white-space:nowrap;}
.file-row .fts{color:var(--muted);white-space:nowrap;}
.file-row .copy-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  padding:2px 8px;font-size:0.58rem;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;
  transition:color var(--t),border-color var(--t);
}
.file-row .copy-btn:hover{color:var(--white);border-color:var(--border3);}

/* C2 PANEL */
#c2-panel{display:none;flex-direction:column;flex:1;overflow:hidden;}
#c2-toolbar{
  display:flex;align-items:center;gap:10px;padding:10px 16px;
  background:var(--bg1);border-bottom:1px solid var(--border2);flex-shrink:0;
}
#c2-toolbar span{color:var(--muted);font-size:0.65rem;letter-spacing:0.08em;text-transform:uppercase;}
#c2-port-inp{
  width:64px;background:var(--bg2);border:1px solid var(--border2);
  color:var(--white);font-family:var(--mono);font-size:0.75rem;padding:5px 8px;
}
.c2-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  padding:5px 14px;font-family:var(--mono);font-size:0.65rem;letter-spacing:0.08em;
  text-transform:uppercase;cursor:pointer;transition:all var(--t);
}
.c2-btn:hover{color:var(--white);border-color:var(--border3);}
.c2-btn.launch{background:var(--white);color:var(--bg);border-color:var(--white);}
.c2-btn.launch:hover{background:var(--off);}
.c2-btn.stop{border-color:rgba(229,57,53,0.4);color:var(--red);}
.c2-btn.stop:hover{background:var(--red-dim);border-color:var(--red);}
#c2-frame-wrap{flex:1;overflow:hidden;background:var(--bg);}
#c2-placeholder{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;color:var(--muted);gap:14px;
}
#c2-placeholder .c2-icon{
  font-family:var(--disp);font-size:3rem;font-weight:800;
  color:var(--bg4);letter-spacing:-0.06em;
}
#c2-placeholder .c2-title{font-family:var(--disp);font-size:1.1rem;font-weight:700;color:var(--grey);}
#c2-placeholder .c2-hint{font-size:0.68rem;color:var(--muted);}
#c2-iframe{display:none;width:100%;height:100%;border:none;}

/* STATUS BAR */
#statusbar{
  display:flex;align-items:center;gap:10px;padding:6px 16px;
  background:var(--bg1);border-top:1px solid var(--border2);flex-shrink:0;
  font-size:0.6rem;letter-spacing:0.08em;text-transform:uppercase;color:var(--muted);
}
#status-dot{width:5px;height:5px;background:var(--muted);}
#status-dot.active{background:var(--green);box-shadow:0 0 6px var(--green);}
#status-text{flex:1;color:var(--grey);}
#status-time{color:var(--muted);}
#workdir-link{color:var(--muted);cursor:pointer;transition:color var(--t);}
#workdir-link:hover{color:var(--white);}
</style>
</head>
<body>

<!-- TOP BAR -->
<div id="topbar">
  <div class="logo">secV<span class="logo-sep">/</span><span class="logo-sub">android pentest</span></div>
  <div class="devbadge">
    <div id="dev-name">no device</div>
    <div id="dev-os"></div>
  </div>
  <span id="lhost-display"></span>
  <button class="tb-btn" onclick="refreshDevices()">⟳</button>
  <button class="tb-btn" onclick="clearTerminal()">⌧ clear</button>
  <button class="tb-btn" onclick="switchTab('setup')">⚙ setup</button>
  <button class="tb-btn" id="kill-btn" onclick="killOp()">✕ kill</button>
</div>

<!-- MAIN -->
<div id="main">
  <!-- SIDEBAR -->
  <div id="sidebar">
    <div id="dev-selector">
      <select id="dev-select" onchange="onDeviceChange()">
        <option value="">-- device --</option>
      </select>
      <button onclick="loadAppList()">↓ load apps</button>
    </div>
    <div id="op-groups"></div>
  </div>

  <!-- RIGHT -->
  <div id="right">
    <!-- PARAMS -->
    <div id="params-panel">
      <div class="op-title" id="op-title">Select an operation</div>
      <div class="op-desc" id="op-desc">Click any operation in the sidebar to configure and run it.</div>
      <div id="params-form"></div>
    </div>

    <!-- TABS -->
    <div id="tabs">
      <div class="tab active" onclick="switchTab('terminal')">Terminal</div>
      <div class="tab" onclick="switchTab('adb')">ADB Console</div>
      <div class="tab" onclick="switchTab('findings')">Findings <span id="findings-badge" class="badge" style="display:none">0</span></div>
      <div class="tab" onclick="switchTab('qr')">QR Codes <span id="qr-badge" class="badge" style="display:none">0</span></div>
      <div class="tab" onclick="switchTab('files')">Files</div>
      <div class="tab" onclick="switchTab('setup')">Setup/Deps</div>
      <div class="tab" id="c2-tab" onclick="switchTab('c2')">C2 Dashboard</div>
    </div>

    <!-- TERMINAL TAB -->
    <div id="terminal-wrap"><div id="terminal"></div></div>
    <!-- ADB CONSOLE TAB -->
    <div id="adb-console">
      <div id="adb-output"></div>
      <div id="adb-input-row">
        <span>adb&gt;&nbsp;</span>
        <input id="adb-input" type="text" placeholder="shell getprop ro.product.model" onkeydown="adbEnter(event)">
      </div>
    </div>
    <!-- FINDINGS TAB -->
    <div id="findings-panel"></div>
    <!-- QR TAB -->
    <div id="qr-panel"></div>
    <!-- FILES TAB -->
    <div id="files-panel"></div>
    <!-- SETUP TAB -->
    <div id="setup-panel">
      <div style="color:var(--muted);font-size:0.68rem;margin-bottom:8px;letter-spacing:0.02em;">Global defaults applied to all operations. Dependency status auto-detected.</div>
      <div style="color:var(--grey);font-size:0.58rem;margin-bottom:6px;letter-spacing:0.18em;text-transform:uppercase;">Global Settings</div>
      <div class="settings-grid">
        <div class="field"><label>LHOST (attacker IP)</label><input id="s-lhost" type="text" placeholder="auto-detect"></div>
        <div class="field"><label>LPORT</label><input id="s-lport" type="text" value="4444"></div>
        <div class="field"><label>Bore server</label><input id="s-bore" type="text" value="bore.pub"></div>
        <div class="field"><label>NVD API key</label><input id="s-nvd" type="text" placeholder="optional"></div>
        <div class="field"><label>C2 host</label><input id="s-c2host" type="text" placeholder="auto-detect"></div>
        <div class="field"><label>C2 port</label><input id="s-c2port" type="text" value="8889"></div>
      </div>
      <button id="save-settings" onclick="saveSettings()">💾 Save settings</button>
      <button class="tb-btn" style="margin-left:8px;margin-top:8px;" onclick="detectLhost()">⟳ Auto-detect LHOST</button>
      <div style="color:var(--grey);font-size:0.58rem;margin:12px 0 6px;letter-spacing:0.18em;text-transform:uppercase;">Dependencies</div>
      <div id="dep-grid" class="dep-grid">
        <div style="color:var(--muted);font-size:0.68rem;padding:12px 14px;">Loading...</div>
      </div>
    </div>
    <!-- C2 PANEL -->
    <div id="c2-panel">
      <div id="c2-toolbar">
        <span>port:</span>
        <input id="c2-port-inp" type="text" value="8891">
        <button class="c2-btn launch" onclick="launchC2()">▶ Launch C2</button>
        <button class="c2-btn stop" onclick="stopC2()">✕ Stop</button>
        <span id="c2-status-badge" style="font-size:0.6rem;color:var(--muted);margin-left:6px;letter-spacing:0.06em;"></span>
        <a id="c2-open-link" href="#" target="_blank" style="font-size:0.65rem;letter-spacing:0.06em;display:none;margin-left:4px;">↗ open</a>
      </div>
      <div id="c2-frame-wrap">
        <div id="c2-placeholder">
          <div class="c2-icon">C2</div>
          <div class="c2-title">secV C2 Dashboard</div>
          <div class="c2-hint">Click <b style="color:var(--white)">▶ Launch C2</b> to start.</div>
          <div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.08em;text-transform:uppercase;">Sessions · Bore · MSF · QR · Agent Callbacks · Encrypted Logs</div>
        </div>
        <iframe id="c2-iframe" style="display:none;width:100%;height:100%;border:none;" src="" allow="same-origin"></iframe>
      </div>
    </div>
  </div>
</div>

<!-- STATUS BAR -->
<div id="statusbar">
  <div id="status-dot"></div>
  <div id="status-text">idle</div>
  <div id="status-time"></div>
  <div id="workdir-link" onclick="switchTab('files');loadFiles()">~/.secv/android/</div>
</div>

<script>
// ── Operation definitions ─────────────────────────────────────────────────────
const OPS = {
  "Recon & Analysis": [
    {id:"recon", label:"recon", desc:"Device fingerprinting: model, Android ver, root, SELinux, bootloader, chipset, patch level",
     fields:[]},
    {id:"app_scan", label:"app scan", desc:"Full APK analysis: manifest, permissions, components, secrets, security score",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank=all)"},
       {n:"deep_analysis",p:"false",t:"select",opts:["false","true"],label:"Deep (jadx)"},
       {n:"search_secrets",p:"true",t:"select",opts:["true","false"],label:"Search secrets"},
       {n:"scan_limit",p:"5",t:"text",label:"App limit"},
       {n:"bypass_ssl",p:"false",t:"select",opts:["false","true"],label:"SSL bypass patch"},
     ]},
    {id:"vuln_scan", label:"vuln scan", desc:"Device+app CVE assessment (2019-2026, MediaTek, NVD live lookups)",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank=all)"},
       {n:"nvd_api_key",p:"",t:"text",label:"NVD API key (opt)"},
     ]},
    {id:"exploit", label:"exploit", desc:"Intent injection, SQL injection on content providers, path traversal, exported components",
     fields:[{n:"package",p:"com.target.app",t:"text",label:"Package (required)"}]},
    {id:"network", label:"network", desc:"Packet capture (tcpdump via root) + logcat credential leakage analysis",
     fields:[{n:"package",p:"",t:"text",label:"Package (opt)"}]},
    {id:"forensics", label:"forensics", desc:"DB/SharedPrefs extraction (root), logcat, ADB backup, SQLite inspection",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package (required)"},
       {n:"backup",p:"false",t:"select",opts:["false","true"],label:"ADB backup"},
     ]},
    {id:"device_net_scan", label:"device net scan", desc:"Scan device WiFi subnet via netrecon — detect open ADB TCP, web services",
     fields:[]},
    {id:"full", label:"full scan", desc:"All of: recon + app_scan + vuln_scan + exploit + network + forensics",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank=all)"},
       {n:"deep_analysis",p:"false",t:"select",opts:["false","true"],label:"Deep (jadx)"},
       {n:"search_secrets",p:"true",t:"select",opts:["true","false"],label:"Search secrets"},
     ]},
  ],
  "Access & Escalation": [
    {id:"adb_wifi", label:"adb wifi", desc:"Enable ADB over TCP/WiFi (adb tcpip 5555) — drop USB dependency",
     fields:[{n:"adb_port",p:"5555",t:"text",label:"ADB TCP port"}]},
    {id:"get_root", label:"get root", desc:"Multi-vector root: Magisk su → adb root → CVE-2024-0044 → mtk-su → KernelSU",
     fields:[]},
    {id:"exploit_cve", label:"exploit CVE", desc:"Targeted CVE exploitation. Supported: CVE-2024-0044, CVE-2023-45866, CVE-2024-31317",
     fields:[
       {n:"cve",p:"CVE-2024-0044",t:"select",
        opts:["CVE-2024-0044","CVE-2023-45866","CVE-2024-31317"],label:"CVE ID"},
     ]},
    {id:"cve_chain", label:"CVE chain", desc:"Chain multiple CVEs: bt_to_root, sandbox_exfil, zero_click_full, or custom list",
     fields:[
       {n:"chain",p:"bt_to_root",t:"select",
        opts:["bt_to_root","sandbox_exfil","zero_click_full","custom"],label:"Chain"},
       {n:"chain_custom",p:"",t:"text",label:"Custom chain (comma-sep CVEs)"},
     ]},
    {id:"zero_click", label:"zero click", desc:"Zero-click attack surface: Bluetooth HID, NFC NDEF, WiFi broadcast, media parser",
     fields:[
       {n:"vector",p:"all",t:"select",opts:["all","bt","nfc","wifi","media"],label:"Vector"},
     ]},
  ],
  "Payload & Delivery": [
    {id:"backdoor_apk", label:"backdoor APK", desc:"Pull APK, inject msfvenom payload (-x template), sign, optionally install",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (or leave blank for local APK)"},
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"install",p:"false",t:"select",opts:["false","true"],label:"Install on device"},
     ]},
    {id:"deploy_shell", label:"deploy shell", desc:"Generate fresh msfvenom APK + install via adb (no root required)",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
     ]},
    {id:"rebuild", label:"rebuild APK", desc:"Build BootBuddy WAN C2 APK: BootReceiver + DexClassLoader + bore + QR delivery",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"msf",p:"false",t:"select",opts:["false","true"],label:"Merge MSF payload"},
       {n:"msf_lport",p:"4444",t:"text",label:"MSF LPORT"},
       {n:"bore_dex_port",p:"21062",t:"text",label:"bore DEX port"},
       {n:"bore_msf_port",p:"37993",t:"text",label:"bore MSF port"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
     ]},
    {id:"objection_patch", label:"objection patch", desc:"Embed Frida gadget into APK via objection — no root needed at runtime",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package"},
       {n:"install",p:"false",t:"select",opts:["false","true"],label:"Install patched APK"},
     ]},
    {id:"wan_expose", label:"WAN expose", desc:"Expose MSF listener + APK over Cloudflare Tunnel; auto-falls back to bore",
     fields:[
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"serve_port",p:"8888",t:"text",label:"APK serve port"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
     ]},
    {id:"qr_exploit", label:"QR exploit", desc:"Generate QR for APK URL, Intent URI, ADB wireless pairing, deeplink, or WAN bore tunnel",
     fields:[
       {n:"qr_mode",p:"apk",t:"select",opts:["apk","intent","adb_pair","deeplink","wan","custom"],label:"QR mode"},
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"8888",t:"text",label:"LPORT / serve port"},
       {n:"apk_path",p:"",t:"text",label:"APK path (wan mode)"},
       {n:"pair_port",p:"37001",t:"text",label:"Pairing port (adb_pair)"},
       {n:"pair_code",p:"123456",t:"text",label:"Pairing code (adb_pair)"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server (wan)"},
     ]},
  ],
  "Instrumentation": [
    {id:"frida_hook", label:"frida hook", desc:"Auto-deploy frida-server, SSL unpin + root bypass + cred dump + trace",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package (required)"},
       {n:"hook_mode",p:"all",t:"select",opts:["all","ssl_unpin","root_bypass","dump_creds","trace"],label:"Hook mode"},
       {n:"hook_timeout",p:"30",t:"text",label:"Timeout (s)"},
       {n:"trace_method",p:"",t:"text",label:"Trace method (trace mode)"},
     ]},
    {id:"hook", label:"LSPosed hook", desc:"Three-vector persistence hook: Magisk service.sh, SharedUID shell, LSPosed/Zygote",
     fields:[{n:"package",p:"com.target.app",t:"text",label:"Package"}]},
    {id:"unhook", label:"unhook", desc:"Remove all injected hooks planted by the hook operation",
     fields:[]},
  ],
  "Persistence": [
    {id:"persist", label:"persist", desc:"Boot Receiver (no root) + Magisk post-fs-data.d script + Magisk module service.sh",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
     ]},
  ],
  "C2 & Agent": [
    {id:"inject_agent", label:"inject agent", desc:"Push native ARM64/shell agent, receive JSON recon + TCP C2 callback, auto-escalate",
     fields:[
       {n:"agent_mode",p:"recon",t:"select",opts:["recon","exploit","c2"],label:"Agent mode"},
       {n:"c2_host",p:"",t:"text",label:"C2 host (auto)"},
       {n:"c2_port",p:"8889",t:"text",label:"C2 port"},
       {n:"c2_timeout",p:"20",t:"text",label:"Callback timeout (s)"},
       {n:"escalate",p:"false",t:"select",opts:["false","true"],label:"Auto escalate"},
       {n:"lhost",p:"",t:"text",label:"Shell LHOST (escalate)"},
       {n:"lport",p:"4444",t:"text",label:"Shell LPORT (escalate)"},
     ]},
    {id:"msf_handler", label:"MSF handler", desc:"Generate + launch Metasploit multi/handler + start msfrpcd for RPC",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"launch",p:"false",t:"select",opts:["false","true"],label:"Launch msfconsole"},
     ]},
    {id:"c2_gui", label:"C2 dashboard (ext)", desc:"Launch secV C2 web dashboard as a separate server (also available as the C2 tab)",
     fields:[{n:"c2_port",p:"8891",t:"text",label:"GUI port"}]},
    {id:"c2_cli", label:"C2 CLI", desc:"Launch C2 server in CLI mode (headless, no browser)",
     fields:[]},
  ],
  "Automated Chains": [
    {id:"full_pwn", label:"full pwn", desc:"recon → adb_wifi → get_root → device_net_scan → deploy_shell → persist → wan_expose",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
     ]},
    {id:"multi_device", label:"multi device", desc:"Run any operation on ALL connected devices simultaneously",
     fields:[
       {n:"sub_operation",p:"recon",t:"select",
        opts:["recon","vuln_scan","full_pwn","inject_agent","app_scan","get_root","persist"],
        label:"Sub-operation"},
     ]},
  ],
};

// ── State ─────────────────────────────────────────────────────────────────────
let currentOp = null;
let appList    = [];
let findings   = [];
let qrList     = [];
let findingsCount = 0;
let qrCount    = 0;
let es         = null;
let opStartTs  = null;
let settings   = {lhost:"",lport:"4444",bore_server:"bore.pub",nvd_api_key:"",c2_host:"",c2_port:"8889"};

// ── Init ──────────────────────────────────────────────────────────────────────
window.onload = () => {
  buildSidebar();
  refreshDevices();
  connectSSE();
  loadSettings();
  detectLhost();
  setInterval(updateStatus, 1500);
  setInterval(updateStatusTime, 500);
};

// ── Sidebar ───────────────────────────────────────────────────────────────────
function buildSidebar() {
  const cont = document.getElementById('op-groups');
  cont.innerHTML = '';
  for (const [grp, ops] of Object.entries(OPS)) {
    const g = document.createElement('div');
    g.className = 'op-group';
    const t = document.createElement('div');
    t.className = 'op-group-title';
    t.innerHTML = `<span>${grp}</span><span class="arrow">▾</span>`;
    t.onclick = () => g.classList.toggle('collapsed');
    const l = document.createElement('div'); l.className = 'op-list';
    for (const op of ops) {
      const i = document.createElement('div');
      i.className = 'op-item'; i.textContent = op.label; i.dataset.id = op.id;
      i.onclick = () => selectOp(op, i);
      l.appendChild(i);
    }
    g.append(t, l); cont.appendChild(g);
  }
}

function selectOp(op, el) {
  document.querySelectorAll('.op-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  currentOp = op;
  renderParams(op);
}

// ── Params ────────────────────────────────────────────────────────────────────
function renderParams(op) {
  document.getElementById('op-title').textContent = op.label;
  document.getElementById('op-desc').textContent = op.desc;
  const form = document.getElementById('params-form');
  form.innerHTML = '';

  for (const f of (op.fields || [])) {
    // use app dropdown if apps loaded and field is 'package'
    if (f.n === 'package' && appList.length > 0) {
      const wrap = mkField(f.label);
      const s = document.createElement('select');
      s.id = 'f_' + f.n; s.name = f.n;
      const blank = document.createElement('option');
      blank.value = ''; blank.textContent = '-- any --'; s.appendChild(blank);
      for (const pkg of appList) {
        const o = document.createElement('option');
        o.value = o.textContent = pkg; s.appendChild(o);
      }
      wrap.appendChild(s); form.appendChild(wrap); continue;
    }
    const wrap = mkField(f.label);
    if (f.t === 'select') {
      const s = document.createElement('select');
      s.id = 'f_' + f.n; s.name = f.n;
      for (const o of f.opts) {
        const opt = document.createElement('option');
        opt.value = o; opt.textContent = o;
        if (o === f.p) opt.selected = true;
        s.appendChild(opt);
      }
      wrap.appendChild(s);
    } else {
      const i = document.createElement('input');
      i.id = 'f_' + f.n; i.name = f.n; i.type = 'text';
      // pre-fill from global settings where applicable
      const settingsMap = {lhost:'lhost',lport:'lport',bore_server:'bore_server',
                           nvd_api_key:'nvd_api_key',c2_host:'c2_host',c2_port:'c2_port'};
      i.value = (f.n in settingsMap && settings[settingsMap[f.n]]) ? settings[settingsMap[f.n]] : (f.p || '');
      i.placeholder = f.p || '';
      wrap.appendChild(i);
    }
    form.appendChild(wrap);
  }

  const btn = document.createElement('button');
  btn.id = 'run-btn'; btn.textContent = '▶ RUN';
  btn.onclick = runOp;
  form.appendChild(btn);
}

function mkField(label) {
  const w = document.createElement('div'); w.className = 'field';
  const l = document.createElement('label'); l.textContent = label;
  w.appendChild(l); return w;
}

// ── Run ───────────────────────────────────────────────────────────────────────
function runOp() {
  if (!currentOp) return;
  const serial = document.getElementById('dev-select').value;
  const params = { operation: currentOp.id };
  if (serial) params.device = serial;
  // global settings fallbacks
  if (settings.lhost)      params._lhost_default    = settings.lhost;
  if (settings.bore_server) params._bore_default    = settings.bore_server;
  if (settings.nvd_api_key) params.nvd_api_key      = settings.nvd_api_key;
  for (const f of (currentOp.fields || [])) {
    const el = document.getElementById('f_' + f.n);
    if (el && el.value.trim()) params[f.n] = el.value.trim();
  }
  // apply lhost/lport from settings if not explicitly set
  if (!params.lhost && settings.lhost)   params.lhost = settings.lhost;
  if (!params.lport && settings.lport)   params.lport = settings.lport;
  if (!params.c2_host && settings.c2_host) params.c2_host = settings.c2_host;
  if (!params.c2_port && settings.c2_port) params.c2_port = settings.c2_port;
  // clean internal keys
  delete params._lhost_default; delete params._bore_default;
  const context = { target: serial || 'device', params };
  switchTab('terminal');
  termLine(`\x1b[36m[*] Launching: ${currentOp.label}\x1b[0m`);
  opStartTs = Date.now();
  fetch('/api/run', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(context)
  }).then(r => r.json()).then(d => {
    if (!d.ok) termLine(`\x1b[31m[!] ${d.error}\x1b[0m`);
  });
}

// ── SSE Terminal ──────────────────────────────────────────────────────────────
function connectSSE() {
  if (es) es.close();
  es = new EventSource('/api/stream');
  es.onmessage = (e) => {
    const line = e.data;
    termLine(line);
    if (line === '[qr-captured]' || line.includes('[qr-url-captured]')) {
      setTimeout(loadQR, 500);
    }
    tryParseFindings(line);
  };
  es.onerror = () => setTimeout(connectSSE, 3000);
}

function termLine(raw) {
  const term = document.getElementById('terminal');
  const span = document.createElement('span'); span.className = 'ln';
  const ts = document.createElement('span'); ts.className = 'ts'; ts.textContent = now();
  span.appendChild(ts);
  span.innerHTML = ts.outerHTML + ansiToHtml(raw);
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}
function clearTerminal() { document.getElementById('terminal').innerHTML = ''; }

// ── ANSI ──────────────────────────────────────────────────────────────────────
const ANSI_MAP = {
  '30':'#555','31':'#ff4444','32':'#00ff88','33':'#ffcc44','34':'#4488ff',
  '35':'#aa66ff','36':'#44ddff','37':'#c0c0d8','90':'#505070','91':'#ff6666',
  '92':'#44ff99','93':'#ffdd66','94':'#66aaff','95':'#cc88ff','96':'#66ddff','97':'#ffffff',
};
function ansiToHtml(s) {
  const txt = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const parts = txt.split(/(\x1b\[[0-9;]*m)/);
  let result = ''; let open = false;
  for (const p of parts) {
    const m = p.match(/^\x1b\[([0-9;]*)m$/);
    if (m) {
      if (open) { result += '</span>'; open = false; }
      for (const code of m[1].split(';')) {
        const col = ANSI_MAP[code];
        if (col) { result += `<span style="color:${col}">`; open = true; }
      }
    } else { result += p; }
  }
  if (open) result += '</span>';
  return result;
}

// ── Findings ──────────────────────────────────────────────────────────────────
let _jsonBuf = '';
function tryParseFindings(line) {
  _jsonBuf += line;
  try {
    const obj = JSON.parse(_jsonBuf);
    _jsonBuf = '';
    const vulns = obj?.data?.vulnerabilities || obj?.vulnerabilities || [];
    if (vulns.length) {
      findings = findings.concat(vulns);
      findingsCount = findings.length;
      const b = document.getElementById('findings-badge');
      b.textContent = findingsCount; b.style.display = 'inline';
      renderFindings();
    }
  } catch(e) { if (!_jsonBuf.includes('{')) _jsonBuf = ''; }
}

function renderFindings() {
  const panel = document.getElementById('findings-panel');
  panel.innerHTML = '';
  if (!findings.length) {
    panel.innerHTML = '<div style="padding:16px;color:var(--muted);font-size:0.68rem;">No findings yet. Run an operation first.</div>';
    return;
  }
  for (const f of findings) {
    const sev = f.severity || 'INFO';
    const card = document.createElement('div'); card.className = 'finding-card';
    card.innerHTML = `<div class="fh"><span class="sev ${sev}">${sev}</span>
      <b style="font-size:0.75rem;color:var(--white)">${f.id||f.type||'Finding'}</b></div>
      <div class="fdesc">${f.desc||f.description||''}</div>`;
    panel.appendChild(card);
  }
}

// ── QR ────────────────────────────────────────────────────────────────────────
function loadQR() {
  fetch('/api/qr').then(r => r.json()).then(d => {
    qrList = d.qr || [];
    qrCount = qrList.length;
    const b = document.getElementById('qr-badge');
    if (qrCount) { b.textContent = qrCount; b.style.display = 'inline'; }
    renderQR();
  });
}

function renderQR() {
  const panel = document.getElementById('qr-panel');
  panel.innerHTML = '';
  if (!qrList.length) {
    panel.innerHTML = '<div style="padding:16px;color:var(--muted);font-size:0.68rem;">No QR codes yet. Run qr_exploit, wan_expose, or rebuild to generate them.</div>';
    return;
  }
  for (const q of qrList) {
    const card = document.createElement('div'); card.className = 'qr-card';
    if (q.startsWith('URL:')) {
      card.innerHTML = `<div style="color:var(--muted);font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px;">Delivery URL</div>
        <div class="qr-url">${q.replace('URL: ','')}</div>`;
    } else {
      card.innerHTML = `<div style="color:var(--muted);font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px;">QR Code</div>
        <pre>${q.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre>`;
    }
    panel.appendChild(card);
  }
}

// ── Files ─────────────────────────────────────────────────────────────────────
function loadFiles() {
  const panel = document.getElementById('files-panel');
  panel.innerHTML = '<div style="padding:8px;color:var(--muted);font-size:0.68rem;">Loading...</div>';
  fetch('/api/workdir').then(r => r.json()).then(d => {
    panel.innerHTML = `<div style="padding:5px 10px;color:var(--muted);font-size:0.58rem;letter-spacing:0.08em;text-transform:uppercase;border-bottom:1px solid var(--border)">
      Base: ${d.base} · ${(d.files||[]).length} files (newest first)</div>`;
    for (const f of (d.files||[])) {
      const row = document.createElement('div'); row.className = 'file-row';
      const sz = f.size > 1048576 ? (f.size/1048576).toFixed(1)+'MB' :
                 f.size > 1024    ? (f.size/1024).toFixed(1)+'KB' : f.size+'B';
      const ts = new Date(f.mtime*1000).toLocaleString();
      row.innerHTML = `<span class="fn" title="${f.full}">${f.path}</span>
        <span class="fsz">${sz}</span>
        <span class="fts">${ts}</span>
        <button class="copy-btn" onclick="navigator.clipboard.writeText('${f.full.replace(/'/g,"\\'")}')">copy</button>`;
      panel.appendChild(row);
    }
    if (!(d.files||[]).length)
      panel.innerHTML += '<div style="padding:12px;color:var(--muted);font-size:0.68rem;">No work files yet. Run an operation first.</div>';
  });
}

// ── Setup/Deps ────────────────────────────────────────────────────────────────
function loadSettings() {
  fetch('/api/settings').then(r => r.json()).then(d => {
    settings = d.settings || settings;
    document.getElementById('s-lhost').value   = settings.lhost||'';
    document.getElementById('s-lport').value   = settings.lport||'4444';
    document.getElementById('s-bore').value    = settings.bore_server||'bore.pub';
    document.getElementById('s-nvd').value     = settings.nvd_api_key||'';
    document.getElementById('s-c2host').value  = settings.c2_host||'';
    document.getElementById('s-c2port').value  = settings.c2_port||'8889';
  });
}

function saveSettings() {
  settings.lhost      = document.getElementById('s-lhost').value.trim();
  settings.lport      = document.getElementById('s-lport').value.trim();
  settings.bore_server = document.getElementById('s-bore').value.trim();
  settings.nvd_api_key = document.getElementById('s-nvd').value.trim();
  settings.c2_host    = document.getElementById('s-c2host').value.trim();
  settings.c2_port    = document.getElementById('s-c2port').value.trim();
  fetch('/api/settings', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(settings)
  }).then(() => {
    updateLhostDisplay();
    termLine(`\x1b[32m[+] Settings saved — LHOST=${settings.lhost||'auto'}, LPORT=${settings.lport}\x1b[0m`);
  });
}

function detectLhost() {
  fetch('/api/lhost').then(r => r.json()).then(d => {
    if (d.lhost && !settings.lhost) {
      settings.lhost = d.lhost;
      document.getElementById('s-lhost').value = d.lhost;
    }
    updateLhostDisplay();
  });
}

function updateLhostDisplay() {
  const el = document.getElementById('lhost-display');
  el.textContent = settings.lhost ? `lhost: ${settings.lhost}` : '';
}

function loadDeps() {
  const grid = document.getElementById('dep-grid');
  grid.innerHTML = '<div style="color:var(--muted);font-size:0.68rem;padding:12px 14px;">Checking...</div>';
  fetch('/api/deps').then(r => r.json()).then(d => {
    grid.innerHTML = '';
    for (const [name, info] of Object.entries(d.deps||{})) {
      const card = document.createElement('div'); card.className = 'dep-card';
      card.innerHTML = `<div class="dep-dot ${info.ok?'ok':'miss'}"></div>
        <div style="flex:1">
          <div class="dep-name">${name} ${info.ok?'<span style="color:var(--green);font-size:0.6rem;">✓</span>':'<span style="color:var(--red);font-size:0.6rem;">✗</span>'}</div>
          ${!info.ok?`<div class="dep-install">${info.install}</div>`:''}
        </div>`;
      grid.appendChild(card);
    }
  });
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(tab) {
  const names = ['terminal','adb','findings','qr','files','setup','c2'];
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', names[i]===tab));
  document.getElementById('terminal-wrap').style.display  = tab==='terminal' ? 'flex':'none';
  document.getElementById('adb-console').style.display    = tab==='adb'      ? 'flex':'none';
  document.getElementById('findings-panel').style.display = tab==='findings' ? 'flex':'none';
  document.getElementById('qr-panel').style.display       = tab==='qr'       ? 'flex':'none';
  document.getElementById('files-panel').style.display    = tab==='files'    ? 'flex':'none';
  document.getElementById('setup-panel').style.display    = tab==='setup'    ? 'flex':'none';
  document.getElementById('c2-panel').style.display       = tab==='c2'       ? 'flex':'none';
  if (tab === 'qr')     { loadQR(); }
  if (tab === 'files')  { loadFiles(); }
  if (tab === 'setup')  { loadDeps(); }
  if (tab === 'c2')     { checkC2Status(); }
}

// ── ADB Console ───────────────────────────────────────────────────────────────
function adbEnter(e) {
  if (e.key !== 'Enter') return;
  const inp = document.getElementById('adb-input');
  const cmd = inp.value.trim(); if (!cmd) return;
  inp.value = '';
  const serial = document.getElementById('dev-select').value;
  const args = serial ? ['-s', serial, ...cmd.split(' ')] : cmd.split(' ');
  adbPrint(`\x1b[36madb ${args.join(' ')}\x1b[0m`);
  fetch('/api/adb', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({args})
  }).then(r => r.json()).then(d => adbPrint(d.output||''));
}
function adbPrint(line) {
  const out = document.getElementById('adb-output');
  const s = document.createElement('div');
  s.innerHTML = ansiToHtml(line); out.appendChild(s); out.scrollTop = out.scrollHeight;
}

// ── Devices ───────────────────────────────────────────────────────────────────
function refreshDevices() {
  fetch('/api/devices').then(r => r.json()).then(d => {
    const sel = document.getElementById('dev-select');
    const cur = sel.value;
    sel.innerHTML = '<option value="">-- device --</option>';
    for (const dev of d.devices) {
      const o = document.createElement('option');
      o.value = dev.serial;
      o.textContent = dev.serial + (dev.tags ? ' ('+dev.tags+')' : '');
      if (dev.serial === cur) o.selected = true;
      sel.appendChild(o);
    }
    if (!cur && d.devices.length === 1) {
      sel.value = d.devices[0].serial;
      loadDevInfo(d.devices[0].serial);
    }
  });
}

function onDeviceChange() {
  const serial = document.getElementById('dev-select').value;
  if (serial) loadDevInfo(serial);
  appList = [];
  if (currentOp) renderParams(currentOp);
}

function loadDevInfo(serial) {
  fetch('/api/devinfo?serial='+encodeURIComponent(serial)).then(r => r.json()).then(d => {
    document.getElementById('dev-name').textContent =
      (d['ro.product.brand']||'') + ' ' + (d['ro.product.model']||serial);
    document.getElementById('dev-os').textContent =
      'Android '+(d['ro.build.version.release']||'?')+
      ' (SDK '+(d['ro.build.version.sdk']||'?')+')';
  });
}

function loadAppList() {
  const serial = document.getElementById('dev-select').value;
  const url = '/api/applist' + (serial ? '?serial='+encodeURIComponent(serial) : '');
  fetch(url).then(r => r.json()).then(d => {
    appList = d.packages||[];
    termLine(`\x1b[32m[+] Loaded ${appList.length} apps\x1b[0m`);
    if (currentOp) renderParams(currentOp);
  });
}

// ── C2 Dashboard ──────────────────────────────────────────────────────────────
function getC2Port() { return parseInt(document.getElementById('c2-port-inp').value)||8891; }

function checkC2Status() {
  const port = getC2Port();
  fetch('/api/c2/status?port='+port).then(r => r.json()).then(d => {
    const badge = document.getElementById('c2-status-badge');
    const link  = document.getElementById('c2-open-link');
    if (d.running) {
      badge.textContent = '● :'+d.port; badge.style.color = 'var(--green)';
      showC2Frame(d.url); link.href = d.url; link.style.display = 'inline';
    } else {
      badge.textContent = '○ stopped'; badge.style.color = 'var(--muted)';
      link.style.display = 'none';
    }
  });
}

function showC2Frame(url) {
  const iframe = document.getElementById('c2-iframe');
  const ph     = document.getElementById('c2-placeholder');
  if (iframe.src !== url) iframe.src = url;
  ph.style.display = 'none'; iframe.style.display = 'block';
}

function launchC2() {
  const port = getC2Port();
  const badge = document.getElementById('c2-status-badge');
  badge.textContent = '… starting'; badge.style.color = 'var(--yellow)';
  fetch('/api/c2/launch?port='+port).then(r => r.json()).then(d => {
    if (d.ok) {
      showC2Frame(d.url);
      document.getElementById('c2-open-link').href = d.url;
      document.getElementById('c2-open-link').style.display = 'inline';
      badge.textContent = '● :'+d.port; badge.style.color = 'var(--green)';
    } else {
      badge.textContent = '✗ failed'; badge.style.color = 'var(--red)';
    }
  });
}

function stopC2() {
  fetch('/api/c2/stop').then(() => {
    const iframe = document.getElementById('c2-iframe');
    iframe.src = ''; iframe.style.display = 'none';
    document.getElementById('c2-placeholder').style.display = 'flex';
    document.getElementById('c2-status-badge').textContent = '○ stopped';
    document.getElementById('c2-status-badge').style.color = 'var(--muted)';
    document.getElementById('c2-open-link').style.display = 'none';
  });
}

// ── Status ────────────────────────────────────────────────────────────────────
function updateStatus() {
  fetch('/api/status').then(r => r.json()).then(d => {
    const dot  = document.getElementById('status-dot');
    const txt  = document.getElementById('status-text');
    const kill = document.getElementById('kill-btn');
    if (d.running) {
      dot.className = 'active';
      txt.textContent = 'running: ' + d.op + (d.pid ? ' [pid '+d.pid+']' : '');
      kill.classList.add('active');
      const rb = document.getElementById('run-btn');
      if (rb) rb.disabled = true;
    } else {
      dot.className = '';
      txt.textContent = 'idle';
      kill.classList.remove('active');
      const rb = document.getElementById('run-btn');
      if (rb) rb.disabled = false;
      opStartTs = null;
    }
  });
}

function updateStatusTime() {
  if (opStartTs) {
    const s = Math.floor((Date.now()-opStartTs)/1000);
    document.getElementById('status-time').textContent = s+'s';
  } else {
    document.getElementById('status-time').textContent = '';
  }
}

function killOp() { fetch('/api/kill',{method:'POST'}); }

// ── Utils ─────────────────────────────────────────────────────────────────────
function now() {
  return new Date().toLocaleTimeString('en-GB',{hour12:false,
    hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
</script>
</body>
</html>
"""


# ── Server launcher ────────────────────────────────────────────────────────────

def launch(port: int = _GUI_PORT, serial: str = "", open_browser: bool = True):
    """Start the GUI HTTP server. Blocks until KeyboardInterrupt."""
    server = HTTPServer(("127.0.0.1", port), _Handler)
    url    = f"http://127.0.0.1:{port}"
    print(f"\x1b[32m[+] secV Android GUI running at {url}\x1b[0m", file=sys.stderr)
    print(f"    Press Ctrl+C to stop", file=sys.stderr)
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\x1b[33m[*] Stopped\x1b[0m", file=sys.stderr)
    finally:
        server.server_close()


# ── CLI entry ─────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="secV Android Pentest GUI")
    ap.add_argument("--port",   type=int, default=_GUI_PORT, help="HTTP port (default 8897)")
    ap.add_argument("--serial", default="",                  help="Default ADB device serial")
    ap.add_argument("--no-browser", action="store_true",     help="Do not auto-open browser")
    args = ap.parse_args()
    launch(port=args.port, serial=args.serial, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
