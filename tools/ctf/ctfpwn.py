#!/usr/bin/env python3
"""
ctfpwn v1.0.0 — secV CTF Autopwn Module
Syncs github.com/0xb0rn3/CTFs, lists rooms, runs autopwn scripts, extracts flags.
Author : dezthejackal | 0xb0rn3
Usage  : echo '{"target":"<ip>","params":{"operation":"run","ctf":"simplectf"}}' | python3 ctfpwn.py
"""

import sys
import os
import json
import subprocess
import shutil
import re
import time
from pathlib import Path
from datetime import datetime

VERSION      = "1.1.0"
REPO_URL     = "https://github.com/0xb0rn3/CTFs"
REPO_DIR     = Path.home() / ".secv" / "ctfs"
OUT_ROOT     = Path.home() / "ZX01C" / "CTF"
STATE_FILE   = Path.home() / ".secv" / "ctfs_state.json"
PLATFORMS    = ["THM", "HTB"]

R  = '\033[0;31m'
G  = '\033[0;32m'
Y  = '\033[1;33m'
C  = '\033[0;36m'
P  = '\033[0;35m'
B  = '\033[1m'
NC = '\033[0m'

_EXT_TYPE = {".sh": "bash", ".py": "python", ".js": "node", ".rb": "ruby", ".pl": "perl"}
_FLAG_PATTERNS = [
    r'THM\{[^}]+\}', r'HTB\{[^}]+\}', r'flag\{[^}]+\}', r'FLAG\{[^}]+\}',
    r'\[FLAG\][^\n]+', r'user\.txt\s*[:\-]\s*(\S+)', r'root\.txt\s*[:\-]\s*(\S+)',
]


class CTFPwn:
    def __init__(self, target: str, params: dict):
        self.target    = target.strip()
        self.params    = params
        self.operation = params.get("operation", "list").lower()
        self.ctf       = params.get("ctf", "").strip()
        self.platform  = params.get("platform", "THM").upper()
        self.query     = params.get("query", "").strip()
        self.findings  = []
        self.errors    = []

    # ── logging ──────────────────────────────────────────────────────────────

    def log(self, msg):  print(f"{C}[*]{NC} {msg}", flush=True)
    def ok(self, msg):   print(f"{G}[+]{NC} {msg}", flush=True)
    def warn(self, msg): print(f"{Y}[!]{NC} {msg}", flush=True)
    def err(self, msg):  print(f"{R}[-]{NC} {msg}", flush=True)
    def flag(self, msg): print(f"{G}{B}[FLAG]{NC}{B} {msg}{NC}", flush=True)

    # ── repo management ───────────────────────────────────────────────────────

    def _sync_repo(self) -> bool:
        if REPO_DIR.exists():
            self.log("Pulling latest from 0xb0rn3/CTFs...")
            r = subprocess.run(
                ["git", "-C", str(REPO_DIR), "pull", "--ff-only"],
                capture_output=True, text=True, timeout=60
            )
            msg = r.stdout.strip() or r.stderr.strip()
            if r.returncode == 0:
                self.ok(f"Repo up to date: {msg}")
            else:
                self.warn(f"git pull warning: {msg}")
        else:
            self.log(f"Cloning {REPO_URL} → {REPO_DIR}")
            REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                ["git", "clone", REPO_URL, str(REPO_DIR)],
                capture_output=True, text=True, timeout=120
            )
            if r.returncode != 0:
                self.errors.append(f"git clone failed: {r.stderr.strip()}")
                return False
            self.ok("Repo cloned")
        return True

    # ── state tracking (new-room detection) ──────────────────────────────────

    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass
        return {"known_rooms": [], "last_pull": None}

    def _save_state(self, rooms: list):
        state = {
            "known_rooms": [f"{r['platform']}/{r['name']}" for r in rooms],
            "last_pull": datetime.now().isoformat(),
        }
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))

    def _new_rooms(self, current: list) -> list:
        state = self._load_state()
        known = set(state.get("known_rooms", []))
        return [r for r in current if f"{r['platform']}/{r['name']}" not in known]

    # ── room discovery ────────────────────────────────────────────────────────

    def _commit_date(self, rel_path: str) -> str:
        r = subprocess.run(
            ["git", "-C", str(REPO_DIR), "log", "-1", "--format=%as", "--", rel_path],
            capture_output=True, text=True
        )
        return r.stdout.strip() or "unknown"

    def _room_info(self, plat: str, room_dir: Path) -> dict:
        name = room_dir.name
        files = [f for f in room_dir.iterdir() if f.is_file()]
        # primary exploit script: not a README/writeup, not an SSH key
        scripts = [
            f for f in files
            if f.suffix.lower() in _EXT_TYPE or (f.suffix == "" and os.access(f, os.X_OK))
            and f.name.lower() not in ("id_rsa",)
        ]
        # prefer .py > .sh > .js > other
        priority = {".py": 0, ".sh": 1, ".js": 2}
        scripts.sort(key=lambda f: priority.get(f.suffix.lower(), 9))
        script = scripts[0] if scripts else None
        stype  = _EXT_TYPE.get(script.suffix.lower(), "exec") if script else "none"
        readme = next(
            (f for f in files if f.name.lower() in ("readme.md", "readme.MD", "writeup.md")),
            None
        )
        date = self._commit_date(f"{plat}/{name}/")
        return {
            "platform":    plat,
            "name":        name,
            "date":        date,
            "script":      str(script) if script else None,
            "script_name": script.name if script else None,
            "type":        stype,
            "has_writeup": readme is not None,
            "writeup":     str(readme) if readme else None,
            "out_dir":     str(OUT_ROOT / name),
            "extra_files": [f.name for f in files if f != script and f != readme],
        }

    def _all_rooms(self, platform: str = None) -> list:
        rooms = []
        plats = [platform] if platform and platform != "ALL" else PLATFORMS
        for plat in plats:
            plat_dir = REPO_DIR / plat
            if not plat_dir.exists():
                continue
            for rd in sorted(plat_dir.iterdir()):
                if rd.is_dir():
                    rooms.append(self._room_info(plat, rd))
        rooms.sort(key=lambda x: x["date"], reverse=True)
        return rooms

    def _find_room(self, name: str) -> dict | None:
        name_l = name.lower()
        for room in self._all_rooms():
            if room["name"].lower() == name_l:
                return room
        for room in self._all_rooms():
            if name_l in room["name"].lower():
                return room
        return None

    # ── flag extraction ───────────────────────────────────────────────────────

    def _extract_flags(self, text: str) -> list:
        found = []
        for pat in _FLAG_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                found.append(m.group(0).strip())
        return list(dict.fromkeys(found))

    # ── readme display ────────────────────────────────────────────────────────

    def _print_readme(self, room: dict):
        if not room["writeup"]:
            self.warn("No writeup found for this room")
            return
        content = Path(room["writeup"]).read_text(errors="replace")
        print(f"\n{B}{'═'*64}{NC}")
        print(f"{P}  {room['platform']}/{room['name']}  [{room['date']}]{NC}")
        print(f"{B}{'═'*64}{NC}")
        # strip markdown image tags for cleaner terminal output
        content = re.sub(r'!\[.*?\]\(.*?\)', '', content)
        print(content[:4000])
        if len(content) > 4000:
            print(f"\n{Y}[...] full writeup → {room['writeup']}{NC}")
        print()

    # ── exploit runner ────────────────────────────────────────────────────────

    def _run_exploit(self, room: dict, target_ip: str):
        if not room["script"]:
            self.warn(f"No exploit script for {room['name']} — writeup only room")
            self._print_readme(room)
            return
        script   = Path(room["script"])
        out_dir  = Path(room["out_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        # copy all room files into out_dir for local reference
        room_dir = REPO_DIR / room["platform"] / room["name"]
        for f in room_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, out_dir / f.name)
        # build command
        ext = script.suffix.lower()
        if ext == ".py":
            cmd = [sys.executable, str(script), target_ip]
        elif ext == ".js":
            cmd = ["node", str(script), target_ip]
        elif ext == ".rb":
            cmd = ["ruby", str(script), target_ip]
        else:
            # sh or executable with no ext
            os.chmod(script, 0o755)
            cmd = [str(script), target_ip]
        print(f"\n{B}{'═'*64}{NC}")
        print(f"{P}  AUTOPWN ▶  {room['platform']}/{room['name']}  →  {target_ip}{NC}")
        print(f"{B}{'═'*64}{NC}\n")
        log_file = out_dir / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.log(f"Script : {script.name}")
        self.log(f"Log    : {log_file}")
        self.log(f"Output : {out_dir}\n")
        exit_code = -1
        output_buf = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(out_dir),
            )
            with open(log_file, "w") as lf:
                for line in proc.stdout:
                    print(line, end="", flush=True)
                    lf.write(line)
                    output_buf.append(line)
            proc.wait()
            exit_code = proc.returncode
        except FileNotFoundError as e:
            self.errors.append(f"Interpreter not found: {e}")
            return
        except Exception as e:
            self.errors.append(f"Run failed: {e}")
            return

        full_output = "".join(output_buf)
        flags = self._extract_flags(full_output)
        print(f"\n{B}{'─'*64}{NC}")
        if flags:
            for fl in flags:
                self.flag(fl)
        else:
            self.warn("No flags automatically extracted — check log for output")
        self.ok(f"Exit code: {exit_code}  |  Log: {log_file}")
        self.findings.append({
            "category":  "run",
            "room":      room["name"],
            "platform":  room["platform"],
            "target":    target_ip,
            "script":    str(script),
            "type":      room["type"],
            "exit_code": exit_code,
            "log":       str(log_file),
            "out_dir":   str(out_dir),
            "flags":     flags,
        })

    # ── operations ────────────────────────────────────────────────────────────

    def _op_pull(self):
        if not self._sync_repo():
            return
        rooms = self._all_rooms()
        new   = self._new_rooms(rooms)
        OUT_ROOT.mkdir(parents=True, exist_ok=True)
        synced = []
        for room in rooms:
            src = REPO_DIR / room["platform"] / room["name"]
            dst = Path(room["out_dir"])
            dst.mkdir(parents=True, exist_ok=True)
            for f in src.iterdir():
                if f.is_file():
                    shutil.copy2(f, dst / f.name)
            synced.append(room["name"])
        self._save_state(rooms)
        if new:
            self.ok(f"{len(new)} NEW room(s) since last pull:")
            for r in new:
                print(f"    {G}+{NC} {P}{r['platform']}/{r['name']}{NC}  [{r['date']}]  {r['type']}")
        else:
            self.ok("No new rooms since last pull")
        self.ok(f"Synced {len(synced)} rooms → {OUT_ROOT}")
        print(f"\n  {'PLATFORM':<8} {'DATE':<12} {'ROOM':<30} {'SCRIPT TYPE'}")
        print(f"  {'─'*8} {'─'*12} {'─'*30} {'─'*12}")
        new_names = {r["name"] for r in new}
        for room in rooms:
            marker = f" {G}← NEW{NC}" if room["name"] in new_names else ""
            print(f"  {room['platform']:<8} {room['date']:<12} {room['name']:<30} {room['type']}{marker}")
        self.findings.append({
            "category":     "pull",
            "rooms_synced": len(synced),
            "new_rooms":    [r["name"] for r in new],
            "output_root":  str(OUT_ROOT),
            "rooms":        synced,
        })

    def _op_list(self):
        if not self._sync_repo():
            return
        plat  = self.platform if self.platform != "ALL" else None
        rooms = self._all_rooms(plat)
        new   = {r["name"] for r in self._new_rooms(rooms)}
        total = len(rooms)
        print(f"\n  {B}{'#':<4} {'DATE':<12} {'PLATFORM':<8} {'ROOM':<30} {'TYPE':<8} {'WRITEUP'}{NC}")
        print(f"  {'─'*4} {'─'*12} {'─'*8} {'─'*30} {'─'*8} {'─'*7}")
        for i, r in enumerate(rooms, 1):
            wp     = f"{G}YES{NC}" if r["has_writeup"] else f"{Y}─{NC}"
            marker = f" {G}NEW{NC}" if r["name"] in new else ""
            name_col = f"{P}{r['name']:<30}{NC}"
            print(f"  {i:<4} {r['date']:<12} {r['platform']:<8} {name_col} {r['type']:<8} {wp}{marker}")
        if new:
            print(f"\n  {G}{len(new)} new room(s) since last pull{NC} — run 'new' for details")
        print(f"\n  {total} room(s) across platform(s): {', '.join({r['platform'] for r in rooms})}\n")
        self.findings.append({
            "category":  "list",
            "total":     total,
            "new_count": len(new),
            "rooms":     rooms,
        })

    def _op_new(self):
        if not self._sync_repo():
            return
        rooms = self._all_rooms()
        new   = self._new_rooms(rooms)
        state = self._load_state()
        last  = state.get("last_pull", "never")
        if not new:
            self.ok(f"No new CTFs since last pull ({last})")
            print(f"  Total rooms: {len(rooms)}")
        else:
            self.ok(f"{len(new)} new CTF(s) since last pull ({last}):\n")
            for r in new:
                print(f"  {G}+{NC} {B}{r['platform']}/{r['name']}{NC}")
                print(f"      Added   : {r['date']}")
                print(f"      Script  : {r['script_name'] or '─'} ({r['type']})")
                print(f"      Writeup : {'YES' if r['has_writeup'] else 'NO'}")
                print(f"      Run with: set operation run; set ctf {r['name']}; run <target_ip>")
                print()
        self.findings.append({
            "category":    "new",
            "last_pull":   last,
            "new_count":   len(new),
            "new_rooms":   new,
            "total_rooms": len(rooms),
        })

    def _op_latest(self):
        if not self._sync_repo():
            return
        rooms = self._all_rooms()
        if not rooms:
            self.errors.append("No CTF rooms found — try: pull")
            return
        latest = rooms[0]
        print(f"\n{B}  Latest CTF:{NC} {P}{latest['name']}{NC}  [{latest['platform']}]  added {latest['date']}")
        print(f"  Script  : {latest['script_name'] or '─'}")
        print(f"  Writeup : {'YES' if latest['has_writeup'] else 'NO'}")
        print(f"  Out dir : {latest['out_dir']}\n")
        self._print_readme(latest)
        self.findings.append({"category": "latest", **latest})
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', self.target):
            self.log(f"Target IP detected — launching autopwn for {latest['name']}")
            self._run_exploit(latest, self.target)

    def _op_run(self):
        if not self._sync_repo():
            return
        name = self.ctf or self.params.get("room", "")
        if not name:
            rooms = self._all_rooms()
            if not rooms:
                self.errors.append("No rooms found — run: pull")
                return
            room = rooms[0]
            self.warn(f"No ctf specified — using latest: {room['name']}")
        else:
            room = self._find_room(name)
            if not room:
                self.errors.append(f"Room not found: {name!r} — use 'list' to see available rooms")
                return
        target_ip = self.target
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target_ip):
            self.errors.append("Valid target IP required for 'run'. e.g. run 10.10.10.1")
            return
        self._run_exploit(room, target_ip)

    def _op_info(self):
        if not self._sync_repo():
            return
        name = self.ctf or self.target
        if not name or re.match(r'^\d', name):
            self.errors.append("Specify room name: set ctf <room_name>")
            return
        room = self._find_room(name)
        if not room:
            self.errors.append(f"Room not found: {name!r}")
            return
        self._print_readme(room)
        print(f"  Script  : {room['script_name'] or '─'} ({room['type']})")
        print(f"  Added   : {room['date']}")
        print(f"  Out dir : {room['out_dir']}")
        if room["extra_files"]:
            print(f"  Files   : {', '.join(room['extra_files'])}")
        self.findings.append({"category": "info", **room})

    def _op_search(self):
        if not self._sync_repo():
            return
        q = (self.query or self.target).lower()
        if not q or re.match(r'^\d+\.\d', q):
            self.errors.append("Provide a search query: set query <term>")
            return
        matches = []
        for room in self._all_rooms():
            hit_where = []
            if q in room["name"].lower():
                hit_where.append("name")
            if room["writeup"]:
                try:
                    content = Path(room["writeup"]).read_text(errors="replace").lower()
                    if q in content:
                        hit_where.append("writeup")
                except Exception:
                    pass
            if room["script"]:
                try:
                    content = Path(room["script"]).read_text(errors="replace").lower()
                    if q in content:
                        hit_where.append("script")
                except Exception:
                    pass
            if hit_where:
                matches.append({**room, "matched_in": hit_where})
        print(f"\n  {B}Search:{NC} {q!r}  →  {len(matches)} result(s)\n")
        for m in matches:
            where = ", ".join(m["matched_in"])
            print(f"  {P}{m['platform']}/{m['name']:<28}{NC} [{m['date']}]  matched: {where}")
        if not matches:
            self.warn(f"No rooms matched {q!r}")
        self.findings.append({
            "category": "search",
            "query":    q,
            "total":    len(matches),
            "results":  matches,
        })

    # ── entry ─────────────────────────────────────────────────────────────────

    def execute(self) -> dict:
        ops = {
            "list":   self._op_list,
            "pull":   self._op_pull,
            "latest": self._op_latest,
            "run":    self._op_run,
            "info":   self._op_info,
            "search": self._op_search,
        }
        fn = ops.get(self.operation)
        if not fn:
            self.errors.append(
                f"Unknown operation: {self.operation!r}. Valid: {', '.join(ops)}"
            )
        else:
            fn()
        return {
            "success": len(self.errors) == 0,
            "data": {
                "operation":      self.operation,
                "target":         self.target,
                "findings":       self.findings,
                "summary": {
                    "timestamp":      datetime.now().isoformat(),
                    "operation":      self.operation,
                    "total_findings": len(self.findings),
                    "errors":         len(self.errors),
                },
            },
            "errors": self.errors,
        }


# ── CLI ────────────────────────────────────────────────────────────────────────

BANNER = f"""{P}{B}
  ╔══════════════════════════════════════════════════════╗
  ║   ctfpwn v{VERSION}  —  secV CTF Autopwn Module      ║
  ║   github.com/0xb0rn3/CTFs  |  0xb0rn3 | dezthejackal ║
  ╚══════════════════════════════════════════════════════╝{NC}"""

HELP = f"""{BANNER}

{B}USAGE:{NC}
  use ctfpwn
  set operation <op>
  run <target_ip_or_none>

{B}OPERATIONS:{NC}
  list      List all CTFs in the repo (auto-pulls latest)
  pull      Clone/update repo + mirror every room to ~/ZX01C/CTF/
  latest    Show newest CTF; if target IP given, run its autopwn script
  run       Run a specific room's autopwn script against a target IP
  info      Show README / writeup for a room
  search    Full-text search across room names, writeups, and scripts

{B}PARAMETERS:{NC}
  operation   Operation to run (default: list)
  ctf         Room name for run/info (e.g. simplectf, Rabbit_Store, 0day)
  platform    THM | HTB  (default: THM)
  query       Search term for 'search' operation

{B}EXAMPLES:{NC}
  # List all rooms
  secV ❯ use ctfpwn
  secV (ctfpwn) ❯ set operation list
  secV (ctfpwn) ❯ run none

  # Run latest CTF against a target
  secV (ctfpwn) ❯ set operation latest
  secV (ctfpwn) ❯ run 10.10.85.42

  # Run a specific room
  secV (ctfpwn) ❯ set operation run
  secV (ctfpwn) ❯ set ctf simplectf
  secV (ctfpwn) ❯ run 10.10.85.42

  # Search for SSTI rooms
  secV (ctfpwn) ❯ set operation search
  secV (ctfpwn) ❯ set query ssti
  secV (ctfpwn) ❯ run none

  # Pull all rooms to ~/ZX01C/CTF/
  secV (ctfpwn) ❯ set operation pull
  secV (ctfpwn) ❯ run none
"""


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(HELP)
        sys.exit(0)

    try:
        raw = sys.stdin.read()
        context = json.loads(raw)
    except Exception as e:
        print(json.dumps({"success": False, "errors": [f"Invalid JSON input: {e}"]}))
        sys.exit(1)

    target = context.get("target", "")
    params = context.get("params", {})

    print(BANNER)

    tool = CTFPwn(target, params)
    try:
        result = tool.execute()
        print(json.dumps(result, indent=2, default=str))
    except KeyboardInterrupt:
        print(json.dumps({"success": False, "errors": ["Interrupted"]}))
        sys.exit(1)
    except Exception as e:
        import traceback
        print(json.dumps({"success": False, "errors": [str(e), traceback.format_exc()]}))
        sys.exit(1)


if __name__ == "__main__":
    main()
