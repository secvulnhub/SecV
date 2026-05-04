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


def scan_tool(tool_path: Path) -> dict:
    """Scan a tool path and return a partial module dict ready for JSON."""
    if tool_path.is_file():
        tool_dir = tool_path.parent
    else:
        tool_dir = tool_path

    files = _collect_source_files(tool_path)

    all_params:  Dict[str, dict] = {}
    all_imports: List[str] = []
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
        elif f.suffix == ".sh":
            all_params.update(_analyse_bash(src))

    # ── Metadata ──────────────────────────────────────────────────────────────
    name = tool_dir.name
    category = _category_from_path(tool_dir)
    executable = _detect_executable(tool_dir) if tool_path.is_dir() else \
                 (f"python3 {tool_path.name}" if tool_path.suffix == ".py"
                  else f"bash {tool_path.name}")

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

    # Dependencies: third-party imports
    deps = sorted(set(all_imports))

    # ── Build ParameterHelp entries ───────────────────────────────────────────
    parameters: Dict[str, dict] = {}
    for pname, pinfo in sorted(all_params.items()):
        entry: Dict[str, Any] = {
            "description": pinfo.get("description", ""),
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

    module = {
        "name":        name,
        "version":     version or "1.0.0",
        "category":    category,
        "description": description,
        "author":      author or "unknown",
        "executable":  executable,
        "dependencies": deps,
        "optional_dependencies": {},
        "help": {
            "description": help_desc,
            "parameters":  parameters,
            "examples":    [],
            "features":    [],
            "installation_tiers": {},
            "notes":       [],
        },
        "inputs":  {},
        "outputs": {},
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

_VALID_CATEGORIES = {"web", "network", "mobile", "ctf", "misc"}
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
            default=defaults.get("category", "misc"),
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
                "examples":    [],
                "features":    [],
                "installation_tiers": {},
                "notes":       [],
            },
            "inputs":  {},
            "outputs": {},
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
