#!/usr/bin/env python3
"""
gen_module.py — secV module.json generator

Scans a contributor tool directory or file and generates a module.json
compatible with the Go secV loader (Module / ModuleHelp / ParameterHelp structs).

Supported patterns:
  Python — context.get() / params.get()  (secV native stdin-JSON pattern)
  Python — argparse add_argument()
  Bash   — jq -r '.params.NAME' / ${PARAM_NAME:-default}

Usage:
    python3 gen_module.py <path>            # print JSON to stdout
    python3 gen_module.py <path> --write    # write module.json into tool dir
    python3 gen_module.py <path> --update   # merge new params into existing module.json
"""

import ast
import re
import json
import sys
import os
import argparse as _ap
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─── stdlib module set (for dependency detection) ────────────────────────────
_STDLIB: set = set()
if hasattr(sys, "stdlib_module_names"):            # Python 3.10+
    _STDLIB = sys.stdlib_module_names              # type: ignore
else:
    _STDLIB = {
        "abc","aifc","argparse","array","ast","asynchat","asyncio","asyncore",
        "atexit","audioop","base64","bdb","binascii","bisect","builtins","bz2",
        "calendar","cgi","cgitb","chunk","cmath","cmd","code","codecs","codeop",
        "collections","colorsys","compileall","concurrent","configparser",
        "contextlib","contextvars","copy","copyreg","cProfile","csv","ctypes",
        "curses","dataclasses","datetime","dbm","decimal","difflib","dis",
        "distutils","doctest","email","encodings","enum","errno","faulthandler",
        "fcntl","filecmp","fileinput","fnmatch","fractions","ftplib","functools",
        "gc","getopt","getpass","gettext","glob","grp","gzip","hashlib","heapq",
        "hmac","html","http","idlelib","imaplib","importlib","inspect","io",
        "ipaddress","itertools","json","keyword","lib2to3","linecache","locale",
        "logging","lzma","mailbox","marshal","math","mimetypes","mmap",
        "modulefinder","multiprocessing","netrc","numbers","operator","optparse",
        "os","pathlib","pdb","pickle","pickletools","pkgutil","platform",
        "plistlib","poplib","posix","posixpath","pprint","profile","pstats",
        "pty","pwd","py_compile","pydoc","queue","random","re","readline",
        "reprlib","resource","rlcompleter","runpy","sched","secrets","select",
        "selectors","shelve","shlex","shutil","signal","site","smtplib","socket",
        "socketserver","spwd","sqlite3","ssl","stat","statistics","string",
        "stringprep","struct","subprocess","sys","sysconfig","syslog","tarfile",
        "telnetlib","tempfile","termios","textwrap","threading","time","timeit",
        "tkinter","token","tokenize","tomllib","trace","traceback","tracemalloc",
        "tty","turtle","types","typing","unicodedata","unittest","urllib","uuid",
        "venv","warnings","wave","weakref","webbrowser","xml","xmlrpc","zipapp",
        "zipfile","zipimport","zlib","zoneinfo","_thread","__future__",
    }

# ─── helpers ──────────────────────────────────────────────────────────────────

def _type_from_default(val: Any) -> str:
    if isinstance(val, bool):   return "boolean"
    if isinstance(val, int):    return "integer"
    if isinstance(val, float):  return "float"
    if isinstance(val, list):   return "array"
    if isinstance(val, dict):   return "object"
    return "string"


def _parse_version(text: str) -> str:
    m = re.search(r'v?(\d+\.\d+(?:\.\d+)?)', text)
    return m.group(1) if m else ""


def _parse_author(text: str) -> str:
    m = re.search(r'Author\s*[:：]\s*(.+)', text, re.IGNORECASE)
    if m:
        return m.group(1).strip().split('\n')[0].strip()
    return ""


def _category_from_path(path: Path) -> str:
    parts = path.parts
    if "tools" in parts:
        idx = list(parts).index("tools")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _detect_executable(tool_dir: Path) -> str:
    candidates = sorted(tool_dir.glob("*.py")) + sorted(tool_dir.glob("*.sh"))
    best = None
    best_score = -1
    for f in candidates:
        try:
            src = f.read_text(errors="replace")
        except Exception:
            continue
        score = src.count("params.get(") + src.count("context.get(") + \
                src.count("add_argument(") + src.count("sys.stdin")
        if score > best_score:
            best_score = score
            best = f
    if best is None:
        return ""
    if best.suffix == ".py":
        return f"python3 {best.name}"
    return f"bash {best.name}"


# ─── Python AST analyser ──────────────────────────────────────────────────────

class _PythonAnalyser:
    """Extract parameters, metadata, and imports from Python source via AST."""

    _BOOL_FUNCS = {"_bool", "_parse_bool", "parse_bool", "str_to_bool", "tobool"}
    _SKIP_PARAMS = {"target", "params", "context", "debug", "verbose"}

    def __init__(self, source: str):
        self.params:      Dict[str, dict] = {}
        self.module_doc:  str = ""
        self.class_doc:   str = ""
        self.version:     str = ""
        self.author:      str = ""
        self.imports:     List[str] = []

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return

        self.module_doc = ast.get_docstring(tree) or ""

        # First class docstring
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                self.class_doc = ast.get_docstring(node) or ""
                break

        # Header comments (first 30 lines)
        for line in source.splitlines()[:30]:
            line = line.strip()
            if line.startswith("#"):
                body = line.lstrip("#").strip()
                if not self.version:
                    self.version = _parse_version(body) if re.search(r'\bv?\d+\.\d+', body) else ""
                if not self.author:
                    self.author = _parse_author(body)

        if not self.version and self.module_doc:
            self.version = _parse_version(self.module_doc)
        if not self.author and self.module_doc:
            self.author = _parse_author(self.module_doc)

        # Imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in _STDLIB:
                        self.imports.append(top)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    if top not in _STDLIB:
                        self.imports.append(top)

        self._extract_params_get(tree)
        self._extract_argparse(tree)

    # ── params.get / context.get ──────────────────────────────────────────────

    def _find_params_holders(self, tree: ast.AST) -> set:
        """
        Return a set of (kind, name) tuples identifying which variables/attributes
        hold the secV params dict (i.e. were assigned from context.get('params', ...)).
        kind is 'name' for bare vars or 'attr' for self.X.
        Falls back to common defaults if nothing is detected.
        """
        holders: set = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            v = node.value
            if not (isinstance(v, ast.Call) and
                    isinstance(v.func, ast.Attribute) and
                    v.func.attr == "get" and
                    v.args and isinstance(v.args[0], ast.Constant) and
                    v.args[0].value == "params"):
                continue
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    holders.add(("name", tgt.id))
                elif isinstance(tgt, ast.Attribute):
                    holders.add(("attr", tgt.attr))
        if not holders:
            holders = {("name", "params"), ("attr", "params")}
        return holders

    @staticmethod
    def _is_params_recv(node: ast.expr, holders: set) -> bool:
        if isinstance(node, ast.Name):
            return ("name", node.id) in holders
        if isinstance(node, ast.Attribute):
            return ("attr", node.attr) in holders
        return False

    def _extract_operations(self, tree: ast.AST) -> List[str]:
        """
        Detect all operation string literals compared against a variable named
        'operation', 'op', 'mode', 'action', 'cmd', 'command'.
        Handles: if op == 'scan', if op in ['a','b'], elif op == 'deep'.
        """
        ops: List[str] = []
        op_var_names = {"operation", "op", "mode", "action", "cmd", "command"}
        seen: set = set()

        def _collect_strings(node) -> List[str]:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return [node.value]
            if isinstance(node, (ast.List, ast.Tuple)):
                out = []
                for elt in node.elts:
                    out.extend(_collect_strings(elt))
                return out
            return []

        for node in ast.walk(tree):
            # if <var> == 'op' or 'op' == <var>
            if isinstance(node, ast.Compare):
                left = node.left
                for op, comp in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.Eq, ast.In, ast.NotIn)):
                        # left is varname, comp is string/list
                        if isinstance(left, ast.Name) and left.id in op_var_names:
                            for s in _collect_strings(comp):
                                if s and s not in seen:
                                    seen.add(s)
                                    ops.append(s)
                        # comp is varname, left is string/list
                        if isinstance(comp, ast.Name) and comp.id in op_var_names:
                            for s in _collect_strings(left):
                                if s and s not in seen:
                                    seen.add(s)
                                    ops.append(s)

            # match/case (Python 3.10+) - ast.Match with ast.MatchValue
            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                if isinstance(node.subject, ast.Name) and node.subject.id in op_var_names:
                    for case in node.cases:
                        pat = case.pattern
                        if hasattr(pat, "value") and isinstance(pat.value, ast.Constant):
                            s = pat.value.value
                            if isinstance(s, str) and s not in seen:
                                seen.add(s)
                                ops.append(s)

        # Filter out generic values that aren't real operation names
        _skip = {"", "default", "none", "null", "true", "false", "all", "both"}
        return [o for o in ops if o.lower() not in _skip]

    def _extract_optional_imports(self, tree: ast.AST) -> List[str]:
        """Detect imports inside try/except blocks - these are optional dependencies."""
        optional: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for child in ast.walk(node):
                    if isinstance(child, ast.Import):
                        for alias in child.names:
                            top = alias.name.split(".")[0]
                            if top not in _STDLIB:
                                optional.append(top)
                    elif isinstance(child, ast.ImportFrom) and child.module:
                        top = child.module.split(".")[0]
                        if top not in _STDLIB:
                            optional.append(top)
        return list(set(optional))

    def _extract_features(self, source: str) -> List[str]:
        """Extract bullet-point features from docstring (lines starting with - or *)."""
        features: List[str] = []
        doc = self.module_doc or self.class_doc
        if not doc:
            # Fall back to scanning comment lines in first 100 lines
            for line in source.splitlines()[:100]:
                stripped = line.strip()
                if stripped.startswith("#") and any(
                    stripped.lstrip("#").strip().startswith(ch) for ch in ("-", "*", "•")
                ):
                    feat = stripped.lstrip("#").strip().lstrip("-*•").strip()
                    if feat and len(feat) > 5:
                        features.append(feat)
            return features[:20]
        for line in doc.splitlines():
            stripped = line.strip()
            if stripped.startswith(("-", "*", "•")):
                feat = stripped.lstrip("-*•").strip()
                if feat and len(feat) > 5:
                    features.append(feat)
        return features[:20]

    def _extract_params_get(self, tree: ast.AST):
        holders = self._find_params_holders(tree)

        # Collect .get() calls on the params holder only
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and node.func.attr == "get"):
                continue
            if not self._is_params_recv(node.func.value, holders):
                continue
            if not (node.args and isinstance(node.args[0], ast.Constant) and
                    isinstance(node.args[0].value, str)):
                continue

            pname = node.args[0].value
            if pname in self._SKIP_PARAMS:
                continue

            default = None
            has_default = len(node.args) > 1
            if has_default:
                try:
                    default = ast.literal_eval(node.args[1])
                except Exception:
                    default = None

            if pname not in self.params:
                self.params[pname] = {
                    "description": "",
                    "type": _type_from_default(default),
                    "required": not has_default,
                    "default": default,
                    "examples": [],
                    "options": [],
                }

        # Detect type casts wrapping params.get() calls
        _CAST_MAP = {"int": "integer", "float": "float", "str": "string", "list": "array"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # int(self.params.get('name', ...))
            if isinstance(node.func, ast.Name) and node.func.id in _CAST_MAP:
                inner = node.args[0] if node.args else None
                pname = self._get_params_call_name(inner, holders)
                if pname and pname in self.params:
                    self.params[pname]["type"] = _CAST_MAP[node.func.id]
            # self._bool(params.get('name', ...))
            is_bool_method = (isinstance(node.func, ast.Attribute) and
                              node.func.attr in self._BOOL_FUNCS)
            is_bool_func   = (isinstance(node.func, ast.Name) and
                              (node.func.id == "bool" or node.func.id in self._BOOL_FUNCS))
            if is_bool_method or is_bool_func:
                inner = node.args[0] if node.args else None
                pname = self._get_params_call_name(inner, holders)
                if pname and pname in self.params:
                    self.params[pname]["type"] = "boolean"

    def _get_params_call_name(self, node, holders: set) -> Optional[str]:
        """If node is a params_holder.get('name', ...) call, return 'name'."""
        if not isinstance(node, ast.Call):
            return None
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "get"):
            return None
        if not self._is_params_recv(node.func.value, holders):
            return None
        if not (node.args and isinstance(node.args[0], ast.Constant) and
                isinstance(node.args[0].value, str)):
            return None
        return node.args[0].value

    @staticmethod
    def _get_call_param(node) -> Optional[str]:
        """If node is X.get('name', ...) call (any receiver), return 'name'."""
        if not isinstance(node, ast.Call):
            return None
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "get"):
            return None
        if not (node.args and isinstance(node.args[0], ast.Constant) and
                isinstance(node.args[0].value, str)):
            return None
        return node.args[0].value

    # ── argparse ──────────────────────────────────────────────────────────────

    def _extract_argparse(self, tree: ast.AST):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and
                    node.func.attr == "add_argument"):
                continue

            # Collect positional string args (flag names)
            flag_names = [
                a.value for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            ]
            if not flag_names:
                continue

            # Primary param name: prefer --flag over positional
            pname = None
            for n in flag_names:
                if n.startswith("--"):
                    pname = n.lstrip("-").replace("-", "_")
                    break
            if pname is None:
                pname = flag_names[0].lstrip("-").replace("-", "_")

            if pname in self._SKIP_PARAMS:
                continue

            # Parse keyword args
            kw: Dict[str, Any] = {}
            for k in node.keywords:
                if k.arg is None:
                    continue
                try:
                    kw[k.arg] = ast.literal_eval(k.value)
                except Exception:
                    if isinstance(k.value, ast.Name):
                        kw[k.arg] = k.value.id
                    elif isinstance(k.value, ast.Attribute):
                        kw[k.arg] = k.value.attr

            action  = kw.get("action", "")
            default = kw.get("default", None)
            desc    = str(kw.get("help", ""))
            choices = kw.get("choices", [])
            nargs   = kw.get("nargs", None)

            # Type inference
            ptype = "string"
            if action in ("store_true", "store_false"):
                ptype = "boolean"
                default = False if action == "store_true" else True
            elif kw.get("type") in ("int", int):
                ptype = "integer"
            elif kw.get("type") in ("float", float):
                ptype = "float"
            elif nargs in ("*", "+"):
                ptype = "array"
            elif isinstance(default, bool):
                ptype = "boolean"
            elif isinstance(default, int):
                ptype = "integer"
            elif isinstance(default, float):
                ptype = "float"

            required = bool(kw.get("required", False)) and default is None

            if pname not in self.params:
                self.params[pname] = {
                    "description": desc,
                    "type": ptype,
                    "required": required,
                    "default": default,
                    "examples": [],
                    "options": [str(c) for c in choices] if choices else [],
                }


# ─── Bash analyser ────────────────────────────────────────────────────────────

def _analyse_bash(source: str) -> Dict[str, dict]:
    params: Dict[str, dict] = {}

    # jq -r '.params.NAME // "default"'  or  jq -r '.params.NAME'
    for m in re.finditer(r"jq\s+(?:-r\s+)?['\"]\.params\.(\w+)(?:\s*//\s*['\"]?([^'\"]+)['\"]?)?['\"]", source):
        pname   = m.group(1)
        default = m.group(2)
        params.setdefault(pname, {
            "description": "",
            "type": "string",
            "required": default is None,
            "default": default,
            "examples": [],
            "options": [],
        })

    # TARGET=$(echo "$INPUT" | jq -r '.target')
    # Also env-var style: ${PARAM_NAME:-default}
    for m in re.finditer(r'\$\{(\w+):-([^}]*)\}', source):
        raw_name = m.group(1)
        default  = m.group(2)
        # Only capture UPPER_CASE names that look like params
        if raw_name.isupper() and "_" in raw_name:
            pname = raw_name.lower()
            params.setdefault(pname, {
                "description": "",
                "type": "string",
                "required": False,
                "default": default or None,
                "examples": [],
                "options": [],
            })

    return params


# ─── main logic ───────────────────────────────────────────────────────────────

def _collect_source_files(tool_path: Path) -> List[Path]:
    if tool_path.is_file():
        return [tool_path]
    files: List[Path] = []
    # Primary: Python / Bash files directly in the tool dir (non-recursive)
    for pat in ("*.py", "*.sh"):
        files.extend(sorted(tool_path.glob(pat)))
    return files


# ─── Smart description generator ─────────────────────────────────────────────

_PARAM_DESCRIPTIONS = {
    "operation":  "Operation to perform - see options list for available operations",
    "op":         "Operation to perform",
    "mode":       "Scan/run mode (e.g. quick, normal, deep, aggressive)",
    "target":     "Target IP address, hostname, CIDR range, or URL",
    "host":       "Target hostname or IP address",
    "port":       "Target port number (1-65535)",
    "ports":      "Port range to scan (e.g. 1-1000, 22,80,443, all, top-1000)",
    "output":     "Output file path for results",
    "output_dir": "Directory to write output files",
    "timeout":    "Timeout in seconds before giving up",
    "threads":    "Number of concurrent threads to use",
    "verbose":    "Enable verbose output (true/false)",
    "debug":      "Enable debug output (true/false)",
    "lhost":      "Local/listener IP address for reverse connections",
    "lport":      "Local/listener port for reverse connections",
    "rhost":      "Remote host IP address",
    "rport":      "Remote host port",
    "username":   "Username for authentication",
    "password":   "Password for authentication",
    "interface":  "Network interface to use (e.g. eth0, wlan0mon)",
    "wordlist":   "Path to wordlist file for brute-force or dictionary attacks",
    "url":        "Target URL",
    "domain":     "Target domain name",
    "package":    "Android package name (e.g. com.example.app)",
    "payload":    "Payload type or string to deliver",
    "depth":      "Recursion or scan depth",
    "rate":       "Packets per second or request rate limit",
    "delay":      "Delay between attempts in seconds",
    "proxy":      "Proxy URL (e.g. http://127.0.0.1:8080)",
    "format":     "Output format (e.g. json, csv, table, xml)",
    "profile":    "Scan profile or configuration name",
    "script":     "Script file path to execute or load",
    "command":    "Command to run on the target",
    "device":     "Device identifier (e.g. ADB serial, interface name)",
    "apk":        "Path to the APK file to analyze or patch",
    "key":        "Encryption key or API key",
    "cert":       "Certificate file path",
    "channel":    "Radio channel number (1-14 for 2.4GHz, 36-165 for 5GHz)",
    "bssid":      "Target access point MAC address (BSSID)",
    "ssid":       "Target network name (SSID)",
}


def _smart_description(pname: str, ptype: str, default: Any) -> str:
    """Generate a human-readable description for a parameter based on its name."""
    if pname.lower() in _PARAM_DESCRIPTIONS:
        return _PARAM_DESCRIPTIONS[pname.lower()]
    # Guess from suffix patterns
    if pname.endswith("_file") or pname.endswith("_path"):
        return f"Path to {pname.replace('_file','').replace('_path','')} file"
    if pname.endswith("_dir"):
        return f"Directory path for {pname.replace('_dir','')}"
    if pname.endswith("_list"):
        return f"Comma-separated list of {pname.replace('_list','').replace('_','-')} values"
    if pname.startswith("enable_") or pname.startswith("use_") or pname.startswith("with_"):
        return f"Enable {pname.split('_',1)[1].replace('_',' ')} feature (true/false)"
    if ptype == "boolean":
        return f"Enable {pname.replace('_',' ')} (true/false)"
    if ptype == "integer":
        return f"Numeric value for {pname.replace('_',' ')}"
    # Title-case the name as last resort
    return pname.replace("_", " ").capitalize()


def _detect_executable_extended(tool_dir: Path) -> str:
    """Detect executable command supporting Python, Bash, Ruby, Node, Go binaries."""
    # Score files by secV-pattern matches
    candidates = []
    for pat in ("*.py", "*.sh", "*.rb", "*.js", "*.ts"):
        candidates.extend(sorted(tool_dir.glob(pat)))

    best = None
    best_score = -1
    best_lang = ""

    for f in candidates:
        try:
            src = f.read_text(errors="replace")
        except Exception:
            continue
        score = (src.count("params.get(") + src.count("context.get(") +
                 src.count("sys.stdin") + src.count("jq -r '.params") +
                 src.count("STDIN.read") + src.count("process.stdin"))
        if score > best_score:
            best_score = score
            best = f
            best_lang = f.suffix

    if best is None:
        # Check for compiled binaries
        for f in tool_dir.iterdir():
            if f.is_file() and not f.suffix and f.stat().st_mode & 0o111:
                return f"./{f.name}"
        return ""

    interpreters = {".py": "python3", ".sh": "bash", ".rb": "ruby",
                    ".js": "node", ".ts": "node"}
    interp = interpreters.get(best_lang, "bash")
    return f"{interp} {best.name}"


def _generate_examples(name: str, operations: List[str], params: Dict[str, dict]) -> List[dict]:
    """Auto-generate usage examples from detected operations and parameters."""
    examples: List[dict] = []
    key_params = [p for p in params if p not in ("operation", "op", "mode")][:3]

    if not operations:
        # Generic example
        cmds = [f"use {name}"]
        for p in key_params:
            info = params[p]
            ex_val = info.get("examples", [None])[0] or info.get("default") or f"<{p}>"
            cmds.append(f"set {p} {ex_val}")
        cmds.append("run <target>")
        examples.append({"description": f"Basic {name} usage", "commands": cmds})
        return examples

    for op in operations[:4]:  # generate up to 4 examples
        cmds = [f"use {name}", f"set operation {op}"]
        for p in key_params:
            info = params[p]
            ex_val = info.get("examples", [None])[0] or info.get("default") or f"<{p}>"
            if ex_val is not None:
                cmds.append(f"set {p} {ex_val}")
        cmds.append("run <target>")
        examples.append({"description": f"{op.replace('_',' ').capitalize()} operation", "commands": cmds})

    # Add a global-params example if there are connection params
    conn_params = [p for p in params if p in ("lhost", "lport", "rhost")]
    if conn_params:
        setg_cmds = [f"setg {p} <value>" for p in conn_params[:2]]
        setg_cmds += [f"use {name}", f"run <target>"]
        examples.append({
            "description": "[v2.4.3] Use setg for persistent connection params",
            "commands": setg_cmds
        })

    return examples


def _build_inputs(params: Dict[str, dict]) -> dict:
    """Build the inputs schema from the parameters dict."""
    inputs: dict = {}
    for pname, info in params.items():
        entry: Dict[str, Any] = {
            "type":     info.get("type", "string"),
            "required": info.get("required", False),
        }
        if info.get("default") is not None:
            entry["default"] = info["default"]
        if info.get("description"):
            entry["description"] = info["description"]
        if info.get("options"):
            entry["options"] = info["options"]
        inputs[pname] = entry
    return inputs


def scan_tool(tool_path: Path) -> dict:
    """Scan a tool path and return a complete module dict ready for JSON."""
    if tool_path.is_file():
        tool_dir = tool_path.parent
    else:
        tool_dir = tool_path

    files = _collect_source_files(tool_path)

    all_params:    Dict[str, dict] = {}
    all_imports:   List[str] = []
    all_optional:  List[str] = []
    all_ops:       List[str] = []
    all_features:  List[str] = []
    module_doc = class_doc = version = author = ""

    for f in files:
        try:
            src = f.read_text(errors="replace")
        except Exception:
            continue

        if f.suffix == ".py":
            a = _PythonAnalyser(src)
            all_params.update(a.params)
            all_imports.extend(a.imports)
            if not module_doc and a.module_doc:
                module_doc = a.module_doc
            if not class_doc and a.class_doc:
                class_doc = a.class_doc
            if not version and a.version:
                version = a.version
            if not author and a.author:
                author = a.author
            # New: extract operations, optional deps, features
            ops_found = a._extract_operations(ast.parse(src))
            for op in ops_found:
                if op not in all_ops:
                    all_ops.append(op)
            all_optional.extend(a._extract_optional_imports(ast.parse(src)))
            if not all_features:
                all_features = a._extract_features(src)
        elif f.suffix == ".sh":
            all_params.update(_analyse_bash(src))

    # ── Metadata ──────────────────────────────────────────────────────────────
    name = tool_dir.name
    category = _category_from_path(tool_dir)
    executable = _detect_executable_extended(tool_dir) if tool_path.is_dir() else \
                 (f"python3 {tool_path.name}" if tool_path.suffix == ".py"
                  else f"bash {tool_path.name}" if tool_path.suffix == ".sh"
                  else f"ruby {tool_path.name}" if tool_path.suffix == ".rb"
                  else f"node {tool_path.name}" if tool_path.suffix in (".js", ".ts")
                  else f"./{tool_path.name}")

    # Description: first non-empty line of module_doc or class_doc
    description = ""
    for doc in (module_doc, class_doc):
        if doc:
            first_line = next((l.strip() for l in doc.splitlines() if l.strip()), "")
            if first_line:
                description = first_line
                break
    if not description:
        description = f"{name} secV module"

    # Help description: full docstring, else same as description
    help_desc = (module_doc or class_doc or description).strip()

    # Dependencies: required third-party imports (not optional)
    optional_set = set(all_optional)
    required_deps = sorted(set(i for i in all_imports if i not in optional_set))
    optional_deps: Dict[str, str] = {
        dep: f"Optional feature - pip3 install {dep}" for dep in sorted(optional_set)
    }

    # ── Inject operation parameter if operations were detected ─────────────────
    if all_ops and "operation" not in all_params:
        all_params["operation"] = {
            "description": "Operation to perform - see options list for available operations",
            "type": "string",
            "required": True,
            "default": all_ops[0],
            "examples": all_ops[:3],
            "options": all_ops,
        }
    elif all_ops and "operation" in all_params:
        # Update options list if we found operations
        if not all_params["operation"].get("options"):
            all_params["operation"]["options"] = all_ops
        if not all_params["operation"].get("examples"):
            all_params["operation"]["examples"] = all_ops[:3]

    # ── Build ParameterHelp entries with smart descriptions ───────────────────
    parameters: Dict[str, dict] = {}
    for pname, pinfo in sorted(all_params.items()):
        desc = pinfo.get("description") or _smart_description(
            pname, pinfo.get("type", "string"), pinfo.get("default"))
        entry: Dict[str, Any] = {
            "description": desc,
            "type": pinfo.get("type", "string"),
            "required": pinfo.get("required", False),
        }
        if pinfo.get("default") is not None:
            entry["default"] = str(pinfo["default"]) if not isinstance(
                pinfo["default"], (bool, int, float, list)) else pinfo["default"]
        if pinfo.get("options"):
            entry["options"] = pinfo["options"]
        if pinfo.get("examples"):
            entry["examples"] = pinfo["examples"]
        parameters[pname] = entry

    # ── Auto-generate examples ─────────────────────────────────────────────────
    examples = _generate_examples(name, all_ops, parameters)

    # ── Standard v2.4.3 notes ─────────────────────────────────────────────────
    notes = [
        "[v2.4.3] setg <param> <value> sets a global parameter that persists across module switches",
        "[v2.4.3] Bare run (no target) reuses the last target automatically",
        "[v2.4.3] options shortcut for show options | modules shortcut for show modules",
        "[v2.4.3] Tab after set shows all parameter names for the loaded module",
    ]

    module = {
        "name":        name,
        "version":     version or "1.0.0",
        "category":    category,
        "description": description,
        "author":      author or "unknown",
        "executable":  executable,
        "dependencies": required_deps,
        "optional_dependencies": optional_deps,
        "help": {
            "description": help_desc,
            "parameters":  parameters,
            "examples":    examples,
            "features":    all_features,
            "installation_tiers": {
                "basic":    "Core functionality with stdlib only",
                "standard": "Recommended - includes optional scanning deps",
                "full":     "All features enabled",
            },
            "notes": notes,
        },
        "inputs":  _build_inputs(parameters),
        "outputs": {
            "success":  {"type": "boolean",  "description": "True if the operation completed without fatal error"},
            "findings": {"type": "array",    "description": "List of findings with title, severity, detail fields"},
            "data":     {"type": "object",   "description": "Structured result data specific to this operation"},
            "errors":   {"type": "array",    "description": "List of non-fatal error strings"},
        },
        "timeout": 300,
    }
    return module


def _merge(existing: dict, generated: dict) -> dict:
    """Merge generated params into existing module.json without overwriting hand-written fields."""
    merged = dict(existing)
    # Update only empty/missing top-level fields
    for key in ("version", "category", "description", "author", "executable",
                "dependencies", "timeout"):
        if not existing.get(key):
            merged[key] = generated[key]
    # Merge parameters: add new ones, don't touch existing
    ex_params = (existing.get("help") or {}).get("parameters") or {}
    ge_params = (generated.get("help") or {}).get("parameters") or {}
    merged_params = dict(ge_params)
    merged_params.update(ex_params)   # existing wins
    merged.setdefault("help", {})
    merged["help"] = dict(existing.get("help") or {})
    merged["help"]["parameters"] = merged_params
    return merged


# ─── ANSI colour helpers (wizard) ────────────────────────────────────────────

_C_CYAN    = "\033[0;36m"
_C_GREEN   = "\033[0;32m"
_C_YELLOW  = "\033[1;33m"
_C_RED     = "\033[0;31m"
_C_BOLD    = "\033[1m"
_C_DIM     = "\033[2m"
_C_RESET   = "\033[0m"

_VALID_CATEGORIES = {"web", "network", "mobile", "AD", "ctf", "phys", "misc"}
_VALID_PARAM_TYPES = {"string", "boolean", "number", "integer", "float", "array"}


def _cprint(color: str, text: str, **kwargs) -> None:
    """Print text wrapped in an ANSI color code."""
    print(f"{color}{text}{_C_RESET}", **kwargs)


def _ask(prompt: str, default: str = "", required: bool = False,
         choices: Optional[List[str]] = None) -> str:
    """
    Display a coloured prompt, read a line from stdin, and validate it.

    - If the user presses Enter with no input and *default* is set, return *default*.
    - If *required* is True and the user gives no input (and there is no default),
      keep asking.
    - If *choices* is given, validate the answer against the list (case-insensitive).
    """
    default_hint = f" {_C_DIM}[{default}]{_C_RESET}" if default else ""
    choices_hint = (
        f" {_C_DIM}({'/'.join(choices)}){_C_RESET}" if choices else ""
    )
    full_prompt = (
        f"{_C_CYAN}{prompt}{_C_RESET}{choices_hint}{default_hint}: "
    )
    while True:
        try:
            raw = input(full_prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if raw == "" and default:
            return default
        if raw == "" and required:
            _cprint(_C_YELLOW, "  (this field is required)")
            continue
        if choices and raw.lower() not in [c.lower() for c in choices]:
            _cprint(_C_YELLOW, f"  choices: {', '.join(choices)}")
            continue
        return raw


def _ask_name(prompt: str, default: str = "") -> str:
    """Like _ask() but validates alphanumeric + underscore."""
    default_hint = f" {_C_DIM}[{default}]{_C_RESET}" if default else ""
    full_prompt = f"{_C_CYAN}{prompt}{_C_RESET}{default_hint}: "
    while True:
        try:
            raw = input(full_prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if raw == "" and default:
            return default
        if not re.match(r'^[a-zA-Z0-9_]+$', raw):
            _cprint(_C_YELLOW, "  name must be alphanumeric/underscore only")
            continue
        return raw


def _wizard(out_dir: Optional[Path] = None) -> None:
    """
    Interactive Q&A wizard that builds module.json from scratch.
    Loops until the user confirms, edits, or cancels.
    """

    defaults: Dict[str, Any] = {}

    while True:
        print()
        _cprint(_C_BOLD + _C_CYAN, "  secV module wizard")
        _cprint(_C_DIM, "  ─" * 30)
        print()

        # ── Step 1/9 – name ──────────────────────────────────────────────────
        name = _ask_name(
            "[1/9] Module name (e.g. myscan)",
            default=defaults.get("name", ""),
        )
        defaults["name"] = name

        # ── Step 2/9 – version ───────────────────────────────────────────────
        version = _ask(
            "[2/9] Version",
            default=defaults.get("version", "1.0.0"),
        ) or "1.0.0"
        defaults["version"] = version

        # ── Step 3/9 – category ──────────────────────────────────────────────
        category = _ask(
            "[3/9] Category",
            default=defaults.get("category", "network"),
            choices=sorted(_VALID_CATEGORIES),
        )
        defaults["category"] = category

        # ── Step 4/9 – description ───────────────────────────────────────────
        description = _ask(
            "[4/9] One-line description",
            default=defaults.get("description", ""),
            required=True,
        )
        defaults["description"] = description

        # ── Step 5/9 – author ────────────────────────────────────────────────
        author = _ask(
            "[5/9] Author",
            default=defaults.get("author", "anonymous"),
        ) or "anonymous"
        defaults["author"] = author

        # ── Step 6/9 – executable ────────────────────────────────────────────
        executable = _ask(
            f"[6/9] Executable command (e.g. python3 {name}.py)",
            default=defaults.get("executable", f"python3 {name}.py"),
            required=True,
        )
        defaults["executable"] = executable

        # ── Step 7/9 – operations ────────────────────────────────────────────
        ops_raw = _ask(
            "[7/9] Operations this module supports (comma-separated, or Enter to skip)",
            default=defaults.get("operations_raw", ""),
        )
        defaults["operations_raw"] = ops_raw
        operations: List[str] = [o.strip() for o in ops_raw.split(",") if o.strip()]

        # ── Step 8/9 – dependencies ──────────────────────────────────────────
        deps_raw = _ask(
            "[8/9] Dependencies (comma-separated tools, e.g. nmap,python3)",
            default=defaults.get("deps_raw", ""),
        )
        defaults["deps_raw"] = deps_raw
        dependencies: List[str] = [d.strip() for d in deps_raw.split(",") if d.strip()]

        # ── Step 9/9 – timeout ───────────────────────────────────────────────
        timeout_str = _ask(
            "[9/9] Timeout in seconds",
            default=str(defaults.get("timeout", 120)),
        )
        try:
            timeout = int(timeout_str)
        except ValueError:
            timeout = 120
        defaults["timeout"] = timeout

        # ── Parameters wizard ────────────────────────────────────────────────
        print()
        _cprint(_C_CYAN, "Now let's add parameters. Press Enter with no name to finish.")
        print()

        prev_params: Dict[str, dict] = dict(defaults.get("parameters", {}))
        parameters: Dict[str, dict] = {}

        while True:
            pname_raw = _ask_name(
                "  Parameter name (or Enter to finish)",
                default="",
            )
            if pname_raw == "":
                # User pressed Enter with empty input — done with params.
                break

            prev = prev_params.get(pname_raw, {})

            ptype = _ask(
                "  > Type",
                default=prev.get("type", "string"),
                choices=["string", "boolean", "number", "integer"],
            )
            req_str = _ask(
                "  > Required?",
                default="yes" if prev.get("required") else "no",
                choices=["yes", "no"],
            )
            required_flag = req_str.lower() in ("yes", "y")

            default_val_str = _ask(
                "  > Default value (Enter to skip)",
                default=str(prev.get("default", "")) if prev.get("default") is not None else "",
            )
            default_val: Any = None
            if default_val_str:
                # Attempt to coerce to the right type
                if ptype in ("boolean",):
                    default_val = default_val_str.lower() in ("true", "1", "yes")
                elif ptype in ("number", "integer"):
                    try:
                        default_val = int(default_val_str)
                    except ValueError:
                        try:
                            default_val = float(default_val_str)
                        except ValueError:
                            default_val = default_val_str
                else:
                    default_val = default_val_str

            pdesc = _ask(
                "  > Description",
                default=prev.get("description", ""),
            )
            print()

            parameters[pname_raw] = {
                "description": pdesc,
                "type": ptype,
                "required": required_flag,
                "default": default_val,
                "examples": [],
                "options": [],
            }
            prev_params[pname_raw] = parameters[pname_raw]

        defaults["parameters"] = prev_params

        # ── Inject "operation" parameter if operations were specified ─────────
        if operations:
            parameters["operation"] = {
                "description": "Operation to run",
                "type": "string",
                "required": True,
                "default": operations[0],
                "examples": operations[:3],
                "options": operations,
            }

        # ── Auto-generate examples and inputs ─────────────────────────────────
        auto_examples = _generate_examples(name, operations, parameters)
        auto_inputs   = _build_inputs(parameters)

        # ── Build module dict ─────────────────────────────────────────────────
        module: Dict[str, Any] = {
            "name":        name,
            "version":     version,
            "category":    category,
            "description": description,
            "author":      author,
            "executable":  executable,
            "dependencies": dependencies,
            "optional_dependencies": {},
            "help": {
                "description": description,
                "parameters":  parameters,
                "examples":    auto_examples,
                "features":    [],
                "installation_tiers": {
                    "basic":    "Core functionality with stdlib only",
                    "standard": "Recommended - includes common deps",
                    "full":     "All features enabled",
                },
                "notes": [
                    "[v2.4.3] setg <param> <value> sets a global parameter that persists across module switches",
                    "[v2.4.3] Bare run (no target) reuses the last target automatically",
                    "[v2.4.3] Tab after set shows all parameter names for this module",
                ],
            },
            "inputs":  auto_inputs,
            "outputs": {
                "success":  {"type": "boolean",  "description": "True if operation completed without fatal error"},
                "findings": {"type": "array",    "description": "List of findings with title, severity, detail fields"},
                "data":     {"type": "object",   "description": "Structured result data for this operation"},
                "errors":   {"type": "array",    "description": "List of non-fatal error strings"},
            },
            "timeout": timeout,
        }

        # ── Preview ───────────────────────────────────────────────────────────
        pretty = json.dumps(module, indent=2)
        print()
        _cprint(_C_BOLD, "Preview:")
        _cprint(_C_DIM, pretty)
        print()

        # ── Confirm ───────────────────────────────────────────────────────────
        choice = _ask(
            "Write to ./module.json?",
            default="yes",
            choices=["yes", "no", "edit"],
        ).lower()

        if choice in ("no", "n"):
            _cprint(_C_YELLOW, "Cancelled.")
            return

        if choice == "edit":
            # Loop again with the current answers as defaults.
            continue

        # ── Write ─────────────────────────────────────────────────────────────
        dest_dir = out_dir if out_dir is not None else Path(".")
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "module.json"
        dest.write_text(pretty + "\n", encoding="utf-8")

        _cprint(_C_GREEN, f"\n  module.json written → run:  secV ❯ use {name}\n")
        return


def main():
    ap = _ap.ArgumentParser(description="Generate secV module.json from tool source")
    ap.add_argument("path", nargs="?", default=None,
                    help="Tool directory or main script file (not needed for --wizard)")
    ap.add_argument("--write",  action="store_true",
                    help="Write module.json into the tool directory")
    ap.add_argument("--update", action="store_true",
                    help="Merge new params into existing module.json (implies --write)")
    ap.add_argument("--wizard", action="store_true",
                    help="Interactive Q&A wizard to build module.json from scratch")
    args = ap.parse_args()

    # ── Wizard mode ───────────────────────────────────────────────────────────
    if args.wizard:
        out_dir = Path(args.path).expanduser().resolve() if args.path else None
        _wizard(out_dir=out_dir)
        return

    # ── Normal scan mode ──────────────────────────────────────────────────────
    if args.path is None:
        ap.error("path is required unless --wizard is used")

    tool_path = Path(args.path).expanduser().resolve()
    if not tool_path.exists():
        sys.exit(f"error: path not found: {tool_path}")

    tool_dir = tool_path if tool_path.is_dir() else tool_path.parent
    generated = scan_tool(tool_path)

    existing_path = tool_dir / "module.json"
    if args.update and existing_path.exists():
        try:
            existing = json.loads(existing_path.read_text())
        except Exception:
            existing = {}
        result = _merge(existing, generated)
    else:
        result = generated

    output = json.dumps(result, indent=2)

    if args.write or args.update:
        existing_path.write_text(output + "\n")
        print(f"[+] Written: {existing_path}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
