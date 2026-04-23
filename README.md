<div align="center">

```
 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 █                                █
 █   ███████╗███████╗ ██████╗██╗  █
 █   ██╔════╝██╔════╝██╔════╝██║  █
 █   ███████╗█████╗  ██║     ██║  █
 █   ╚════██║██╔══╝  ██║     ╚╝   █
 █   ███████║███████╗╚██████╗     █
 █   ╚══════╝╚══════╝ ╚═════╝  ⚡ █
 █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█
```

### polyglot cybersecurity orchestration platform

`Go` · `Python` · `Bash` · `PowerShell` · `Rust` · `C++` — one shell to run them all

---

[![Version](https://img.shields.io/badge/v2.4.0-release-0d1117?style=flat-square&labelColor=00d9ff&color=0d1117)](https://github.com/SecVulnHub/SecV)
[![License](https://img.shields.io/badge/MIT-license-0d1117?style=flat-square&labelColor=8b5cf6&color=0d1117)](LICENSE)
[![Go](https://img.shields.io/badge/Go_1.18+-required-0d1117?style=flat-square&labelColor=00ADD8&color=0d1117)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Linux%20%7C%20macOS%20%7C%20Windows-0d1117?style=flat-square&labelColor=3a3f4b&color=0d1117)](#)

</div>

---

## Overview

SecV is a **native Go shell** that loads and orchestrates security modules written in any language. Think Metasploit's interface — but your modules can be Python, Bash, Go, PowerShell, Rust, or C++. The loader handles discovery, I/O marshaling, timeouts, validation, and output formatting. You write the logic.

The v2.4.0 rewrite replaced the Python shell with a compiled Go binary. The result: **8ms startup, 12MB memory, 2.1MB binary.**

```
secV ➤ use portscan
secV (portscan) ➤ set engine syn
secV (portscan) ➤ set ports top-100
secV (portscan) ➤ run target.com
```

---

## Performance

| Metric          | Python v2.3 | Go v2.4 | Delta     |
|-----------------|-------------|---------|-----------|
| Startup         | 800ms       | 8ms     | **100×**  |
| Memory          | 45MB        | 12MB    | **−73%**  |
| Module load     | 120ms       | 5ms     | **24×**   |
| Command latency | 50ms        | 2ms     | **25×**   |
| Binary size     | —           | 2.1MB   | portable  |

No interpreter. No warm-up. No overhead.

---

## Installation

```bash
git clone https://github.com/SecVulnHub/SecV.git
cd SecV
chmod +x install.sh && ./install.sh
```

**Tiers:**

| Tier         | Size    | Description                          |
|--------------|---------|--------------------------------------|
| `basic`      | ~5MB    | Core shell only                      |
| `standard`   | ~50MB   | + Scanning stack *(recommended)*     |
| `full`       | ~100MB  | All features                         |
| `elite`      | ~100MB  | + Masscan for large-scale recon      |

Then launch:

```bash
./secV          # from repo directory
secV            # if installed system-wide
```

---

## Shell Commands

```
# Navigation
show modules          list all available modules
show categories       browse by category
search <keyword>      fuzzy search modules
use <module>          load a module
back                  unload current module
reload                rescan tools/ directory
info <module>         show module metadata

# Module interaction
show options          list parameters and defaults
set <key> <value>     assign a parameter
run <target>          execute against target
help module           context-aware docs

# System
update                pull latest + recompile if needed
clear                 clear terminal
exit
```

---

## Module Architecture

SecV communicates with modules via **JSON over stdin/stdout**. The loader sends an execution context; your module reads it, does work, and prints a JSON result. That's the contract.

```json
// Input  (sent to your module's stdin)
{
  "target": "example.com",
  "params": {
    "ports": "top-100",
    "engine": "syn"
  }
}

// Output  (your module writes to stdout)
{
  "success": true,
  "data": { ... },
  "errors": []
}
```

### Python

```python
#!/usr/bin/env python3
import json, sys

ctx    = json.loads(sys.stdin.read())
target = ctx["target"]
params = ctx.get("params", {})

# --- your logic ---

print(json.dumps({"success": True, "data": {"target": target}}))
```

### Go

```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
)

func main() {
    raw, _ := io.ReadAll(os.Stdin)
    var ctx map[string]any
    json.Unmarshal(raw, &ctx)

    // --- your logic ---

    out, _ := json.Marshal(map[string]any{
        "success": true,
        "data":    map[string]any{"target": ctx["target"]},
    })
    fmt.Println(string(out))
}
```

### Bash

```bash
#!/usr/bin/env bash
input=$(cat)
target=$(echo "$input" | jq -r '.target')

# --- your logic ---

jq -n --arg t "$target" '{"success": true, "data": {"target": $t}}'
```

### `module.json`

Every module needs a manifest alongside its executable:

```json
{
  "name":        "my-scanner",
  "version":     "1.0.0",
  "category":    "scanning",
  "description": "Brief description",
  "author":      "you",
  "executable":  "python3 scanner.py",

  "dependencies": ["python3"],
  "optional_dependencies": {
    "scapy": "SYN scan support — pip3 install scapy"
  },

  "inputs": {
    "target": { "type": "string",  "required": true },
    "ports":  { "type": "string",  "default": "1-1000" },
    "threads":{ "type": "integer", "default": 50 }
  },

  "timeout": 300
}
```

Drop your module into `tools/<category>/<name>/` and run `reload`. SecV auto-discovers it.

### Graceful degradation pattern

```python
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

def scan(target):
    if HAS_SCAPY:
        return syn_scan(target)       # full capability
    return connect_scan(target)       # stdlib fallback

if not HAS_SCAPY:
    print("INFO: install scapy for SYN mode", file=sys.stderr)
```

Modules that degrade gracefully work across all installation tiers without crashing.

---

## Built-in Modules

### `portscan` — Elite Port Scanner v3.0
**Category:** scanning

Four scan engines with intelligent fallback: TCP connect → SYN stealth → Nmap → Masscan. Includes service fingerprinting (50+ signatures), HTTP tech detection (30+ frameworks), OS fingerprinting, TLS/SSL inspection, CVE correlation, DNS enumeration, and adaptive timeout via 95th-percentile sampling. Up to 500 concurrent threads.

```bash
use portscan
set engine auto      # tcp | syn | nmap | masscan | auto
set ports web        # web | top-100 | top-1000 | all | custom range
set threads 200
run target.com
```

---

### `android_pentest` — Android Security Suite v1.0
**Category:** mobile | **Author:** 0xb0rn3

Seven operation modes covering the OWASP Mobile Top 10.

| Operation    | Description                                          |
|--------------|------------------------------------------------------|
| `recon`      | Device fingerprint, root status, SELinux             |
| `app_scan`   | Static APK analysis, manifest audit, security score  |
| `vuln_scan`  | 50+ vuln checks, OWASP Mobile Top 10                 |
| `exploit`    | Intent injection, SQLi, path traversal               |
| `network`    | Traffic capture, SSL inspection, proxy               |
| `forensics`  | Data extraction, artifact analysis, timeline         |
| `advanced`   | Frida hooks, SSL pinning bypass, secret search       |

```bash
use android_pentest
set operation app_scan
set package com.target.app
run device
```

---

### `mac_spoof` — MAC Address Manipulation v2.0
**Category:** network | **Author:** 0xb0rn3

Per-interface background daemons, locally-administered address generation, state persistence, configurable rotation interval, dry-run mode.

```bash
sudo secV
use mac_spoof
set iface wlan0
set interval 300    # rotate every 5 min
run localhost
```

---

## Module Index

| Category       | Modules                                               |
|----------------|-------------------------------------------------------|
| scanning       | `portscan`, `nmap-wrapper`, `masscan-integration`     |
| mobile         | `android_pentest`, `apk-analyzer`, `frida-hooks`      |
| network        | `mac_spoof`, `arp-spoof`, `dns-spoof`                 |
| web            | `web-enum`, `sql-injection`, `xss-scanner`            |
| recon          | `subdomain-enum`, `shodan-search`, `theHarvester`     |
| vulnerability  | `vuln-scan`, `cve-checker`, `nessus-wrapper`          |
| exploitation   | `metasploit-bridge`, `exploit-db`                     |
| wireless       | `wifi-crack`, `evil-twin`, `bluetooth-scan`           |
| forensics      | `memory-dump`, `file-carving`, `timeline`             |

---

## Update System v4.1

SecV silently checks for updates every 24 hours. On startup, if a newer version exists:

```
┌─────────────────────────────────────────┐
│  Update available — v2.4.1              │
└─────────────────────────────────────────┘
Update now? [Y/n]:

[1/8] backup ............... ✓ 20250111_143052
[2/8] local changes ........ ✓ none detected
[3/8] git pull ............. ✓ fast-forward
[4/8] obsolete files ....... ✓ removed 3
[5/8] recompile ............ ✓ 2.1MB (main.go changed)
[6/8] dependencies ......... ✓ no changes
[7/8] version info ......... ✓ updated
[8/8] cleanup .............. ✓

Restart SecV to load new components.
```

Manual controls:

```bash
secV ➤ update                      # interactive update

python3 update.py                  # check and apply
python3 update.py --status         # component status
python3 update.py --verify         # integrity check
python3 update.py --repair         # fix common issues
python3 update.py --rollback       # restore last backup
python3 update.py --list-backups   # show available backups
```

Keeps the last 5 timestamped backups. Recompiles the Go binary only when `main.go` changes. Installs Python deps only when `requirements.txt` changes. Smart-stashes local modifications before pulling; restores after.

---

## Module Development Quickstart

```bash
# scaffold
mkdir -p tools/scanning/my-tool && cd tools/scanning/my-tool

# create manifest
cat > module.json << 'EOF'
{
  "name": "my-tool",
  "version": "1.0.0",
  "category": "scanning",
  "description": "Does a thing",
  "author": "you",
  "executable": "python3 main.py",
  "dependencies": ["python3"],
  "inputs": {
    "target": { "type": "string", "required": true }
  },
  "timeout": 60
}
EOF

# create entrypoint
cat > main.py << 'EOF'
#!/usr/bin/env python3
import json, sys

ctx = json.loads(sys.stdin.read())

# your logic here

print(json.dumps({"success": True, "data": {"target": ctx["target"]}}))
EOF

chmod +x main.py
```

```bash
# test it
cd ../../..
./secV
secV ➤ reload
secV ➤ use my-tool
secV (my-tool) ➤ run example.com
```

**Checklist before submitting a PR:**

- [ ] Works on Basic tier (stdlib only), degrades gracefully otherwise
- [ ] `module.json` is valid JSON and includes all required fields
- [ ] `README.md` inside module directory with usage examples
- [ ] Handles all errors — never unhandled exceptions to stdout
- [ ] Cross-platform (or explicitly documents platform requirement)
- [ ] Follows language style: PEP 8 / `gofmt` / ShellCheck

---

## Troubleshooting

**Module not found after adding**
```bash
secV ➤ reload
```

**Permission denied on startup**
```bash
chmod +x secV install.sh
```

**Go binary won't compile**
```bash
# install Go first
sudo apt install golang-go    # Debian/Ubuntu
sudo pacman -S go             # Arch
brew install go               # macOS

go build -o secV main.go
```

**Update fails with merge conflict**
```bash
git stash && git pull && git stash pop
# or full rollback:
python3 update.py --rollback
```

**Debug mode**
```bash
./secV --debug
# or per-module:
set verbose true
```

---

## Roadmap

```
v2.4.0  ██████████  current
        Go loader, smart updates, android pentest, port scanner v3

v2.5.0  ██░░░░░░░░  Q2 2025
        Web dashboard, REST API, module marketplace,
        cloud scanning (AWS/Azure/GCP), PostgreSQL backend,
        advanced reporting engine

v3.0.0  ░░░░░░░░░░  Q4 2025
        Plugin SDK, workflow automation, ML integration,
        threat intel feeds, multi-user + RBAC,
        Docker/Kubernetes, mobile app
```

---

## Contributing

```bash
# fork, then:
git clone https://github.com/YOUR_USERNAME/SecV.git
cd SecV
git checkout -b feature/module-name

# build your module under tools/
# test it with ./secV
# add deps to requirements.txt with a comment linking to your module

git commit -m "feat(modules): add <name> — <one-line description>"
git push origin feature/module-name
# open PR on GitHub
```

---

## Legal

SecV is for **authorized security testing only.** You must have explicit written permission before scanning, probing, or testing any system you do not own.

Unauthorized use may violate computer fraud statutes (CFAA, Computer Misuse Act, and equivalents). The authors accept no liability for misuse. By using this tool you accept full responsibility for your actions.

> When in doubt — don't. Get written authorization first.

---

## License

MIT © 2024–2025 SecVulnHub Team

---

<div align="center">

**SecV** — *orchestrating security, one module at a time*

built by ethical hackers · powered by Go · extended by everything else

</div>
