# SecV Module Index

Complete reference of all SecV security modules.

**Version:** 2.4.0  
**Total Modules:** 7  
**Categories:** network (3), mobile (2), web (2)

---

## Quick Navigation

- [Network](#network)
- [Mobile](#mobile)
- [Web](#web)
- [Module Development](#module-development)

---

## Network

### `netrecon` v1.0.0
**Concurrent Multi-Engine Network Profiler**

Runs nmap, masscan, rustscan, arp-scan, and Shodan simultaneously, merges results, and correlates CVEs against detected service versions via live NVD lookups. Detects iOS/Apple devices (port 62078, mDNS). Supports passive-only mode, proxy chains, and evasion techniques.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `normal` | Scan mode: `normal`, `quick`, `deep`, `network`, `stealth` |
| `ports` | string | `top-1000` | Port range or preset: `top-100`, `top-1000`, `web`, `db`, `all` |
| `threads` | integer | `20` | Concurrent scanning threads |
| `rate` | integer | `1000` | Packets/sec (masscan) |
| `timeout` | integer | `5` | Per-host timeout (seconds) |
| `os_detection` | boolean | `false` | Enable OS fingerprinting (requires root) |
| `vuln_scripts` | boolean | `false` | Run nmap vuln scripts |
| `shodan_key` | string | — | Shodan API key for enrichment |
| `interface` | string | — | Network interface to bind |
| `exclude` | string | — | Comma-separated hosts/CIDRs to skip |
| `passive_only` | boolean | `false` | No active probing — Shodan/DNS only |

**Installation Tiers:**
- Basic: TCP connect, DNS, WHOIS, ASN lookup
- Standard: + SYN scan (scapy), Nmap integration
- Full: + Shodan enrichment, live NVD CVE correlation

**Quick Start:**
```
secV ❯ use netrecon
secV (netrecon) ❯ set mode network
secV (netrecon) ❯ set ports top-100
secV (netrecon) ❯ run 192.168.1.0/24
```

---

### `mac_spoof` v2.1.0
**Connection-Aware MAC Address Rotator**

Per-interface background daemons with multiple rotation strategies, active connection tracking (no drops), locally-administered OUI prefix (`02:00:00`), and state persistence across restarts.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `iface` | string | — | Interface name or comma-separated list |
| `all_up` | boolean | `false` | Target all UP non-loopback interfaces |
| `action` | string | `start` | `start`, `stop`, `status` |
| `mode` | string | `smart` | `smart`, `session`, `periodic`, `aggressive` |
| `interval` | float | `30.0` | Rotation interval (seconds, periodic mode) |
| `preserve_connections` | boolean | `true` | Skip change when active TCP connections exist |
| `wait_for_quiet` | boolean | `true` | Wait for connections to drop before rotating |
| `max_wait` | integer | `30` | Max wait time (seconds) before forcing change |
| `dry_run` | boolean | `false` | Preview without applying changes |

**Modes:**
- `smart` — changes only when no active connections (safest)
- `session` — changes between connection sessions
- `periodic` — fixed interval with connection checks
- `aggressive` — rapid rotation regardless of connections

**Quick Start:**
```
sudo secV
secV ❯ use mac_spoof
secV (mac_spoof) ❯ set iface wlan0
secV (mac_spoof) ❯ set interval 300
secV (mac_spoof) ❯ run localhost
```

---

### `wifi_monitor` v1.0.0
**Smart WiFi Network Monitor & Threat Detector**

Real-time host discovery via ARP (scapy) with TCP-ping fallback, async per-host port scanning, SSL/HTTP/SSH banner grabbing, CVE lookup via CIRCL API (24h cache), device fingerprinting (IoT, router, NAS, database, web server), and threat detection for exposed databases, Telnet, FTP, and end-of-life SSH.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `monitor` | `monitor`, `passive`, `deep` |
| `ports` | string | `top-20` | Port range or preset: `top-20`, `top-100`, `full` |
| `port_scan` | boolean | `true` | Enable per-host port scanning |
| `cve_lookup` | boolean | `true` | Look up CVEs for detected services |
| `timeout` | integer | `3` | Per-host/port timeout (seconds) |
| `concurrency` | integer | `50` | Concurrent scan workers |

**Quick Start:**
```
sudo secV
secV ❯ use wifi_monitor
secV (wifi_monitor) ❯ run 192.168.1.0/24
```

---

## Mobile

### `android_pentest` v1.0.0
**Full-Lifecycle Android Pentesting Suite**

Device recon to active exploitation and persistence. Supports rooted and non-rooted devices, ADB over USB and WiFi, multi-device sweeps, and on-device native agent deployment with TCP+HTTP C2.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `operation` | string | — | Operation to run (see table below) |
| `device` | string | — | ADB device serial (auto-detect if single device) |
| `package` | string | — | Target app package name |
| `frida` | boolean | `false` | Enable Frida runtime instrumentation |
| `proxy` | boolean | `false` | Enable HTTP proxy interception |
| `proxy_host` | string | `127.0.0.1` | Proxy host |
| `proxy_port` | integer | `8080` | Proxy port |
| `bypass_ssl` | boolean | `false` | Bypass SSL pinning via Frida |
| `backup` | boolean | `false` | Create ADB backup before testing |
| `search_secrets` | boolean | `true` | Scan for hardcoded secrets and credentials |
| `mirror` | boolean | `false` | Mirror device screen during testing |
| `record` | boolean | `false` | Record screen during operation |

**Operations:**

| Operation          | Description                                                                        |
|--------------------|------------------------------------------------------------------------------------|
| `recon`            | Device fingerprint, root status, SELinux, chipset                                  |
| `app_scan`         | APK analysis, manifest audit, security score                                       |
| `vuln_scan`        | 50+ checks, OWASP Mobile Top 10, NVD live CVEs                                    |
| `exploit`          | Intent injection, SQLi, content provider attacks                                   |
| `network`          | Traffic capture, SSL inspection, proxy setup                                       |
| `forensics`        | Data extraction, artifact analysis                                                 |
| `frida_hook`       | Deploy frida-server, auto-hook app: SSL unpin, root bypass, cred dump, trace       |
| `objection_patch`  | Embed Frida gadget (no root at runtime), repackage and sign APK                    |
| `get_root`         | Multi-vector root: Magisk, adb root, CVE-2024-0044, mtk-su, KernelSU              |
| `inject_agent`     | Push native recon agent, receive JSON report via TCP C2, auto-escalate             |
| `adb_wifi`         | Enable ADB over WiFi, drop USB dependency                                          |
| `deploy_shell`     | Generate and install Meterpreter APK (no root required)                            |
| `backdoor_apk`     | Pull APK, inject msfvenom payload (-x template), sign, optionally install          |
| `rebuild`          | Build Termux:Boot WAN C2 APK with BootReceiver + DexClassLoader + bore + QR       |
| `persist`          | Termux:Boot + Magisk module persistence                                            |
| `hook`             | Three-vector hook: Magisk service.sh injection, SharedUID shell, LSPosed/Zygote    |
| `unhook`           | Remove all persistence hooks planted by the hook operation                         |
| `exploit_cve`      | Targeted CVE exploitation (CVE-2024-0044, CVE-2023-45866, CVE-2024-31317, etc.)   |
| `cve_chain`        | Run predefined CVE chain: bt_to_root, sandbox_exfil, zero_click_full               |
| `zero_click`       | Probe zero-click surfaces: Bluetooth HID, NFC, WiFi broadcast, media parsing       |
| `qr_exploit`       | Generate QR for APK URL, Android Intent URI, ADB WiFi pairing, deeplink            |
| `device_net_scan`  | Scan device WiFi via netrecon, detect exposed ADB TCP and web services             |
| `wan_expose`       | Expose MSF listener and APK server via Cloudflare Tunnel for WAN delivery          |
| `msf_handler`      | Launch Metasploit multi/handler and start msfrpcd for GUI session management       |
| `full_pwn`         | 7-step chain: recon + adb_wifi + get_root + device_net_scan + shell + persist + WAN|
| `multi_device`     | Run any operation across all connected devices simultaneously                      |
| `c2_gui`           | Launch secV web C2 dashboard (bore, MSF, QR, operations, encrypted session logs)  |
| `c2_cli`           | Launch C2 server in CLI mode                                                       |
| `full`             | Complete assessment: recon + vuln_scan + exploit + network + forensics             |

**On-Device Agent** (`tools/mobile/android/agent/`):
- `secv_agent.sh` - shell script, any Android without compilation
- `secv_agent.c` - compiled ARM64 binary via NDK (`build.sh`)
- `c2_server.py` - standalone TCP+HTTP C2 with interactive REPL

**APK Backdoor Tool** (`tools/mobile/android/apk_backdoor/`):
- `build_bootbuddy.py` - repackage any APK with BootReceiver + AgentService + DexClassLoader chain, WAN C2 via bore tunnels, QR delivery

**C2 Web Dashboard** (`tools/mobile/android/c2_gui.py`):
- Sessions, Bore tunnels, MSF sessions, QR delivery, Operations, Logs
- 5-layer encrypted .scv session archives (PBKDF2 + SHA3 + Scrypt + AES-GCM + ChaCha20)

**Quick Start:**
```
secV ❯ use android_pentest
secV (android_pentest) ❯ set operation inject_agent
secV (android_pentest) ❯ set agent_mode recon
secV (android_pentest) ❯ run device

# C2 server (separate terminal)
python3 tools/mobile/android/agent/c2_server.py --auto-exploit --lhost 192.168.1.100
```

**Dependencies:** `adb` (system binary — installed by `install.sh`)

---

### `ios_pentest` v1.0.0
**iOS Security Testing**

IPA static analysis, binary protection checks (PIE, stack canary, ARC, encryption), ATS/Info.plist audit, keychain dumping, Frida SSL bypass, and live iOS CVE assessment via NVD. Covers non-jailbroken and jailbroken paths.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `operation` | string | `recon` | `recon`, `app_scan`, `vuln_scan`, `exploit`, `full` |
| `udid` | string | — | Device UDID (auto-detect if single device) |
| `bundle_id` | string | — | Target app bundle ID |
| `ipa_path` | string | — | Path to local IPA for static analysis |
| `ssh_host` | string | — | Jailbroken device IP for SSH access |
| `ssh_port` | integer | `22` | SSH port |
| `ssh_user` | string | `root` | SSH user |
| `ssh_pass` | string | `alpine` | SSH password |
| `search_secrets` | boolean | `true` | Scan for hardcoded secrets |
| `deep_analysis` | boolean | `false` | Extended binary analysis |
| `ssl_bypass` | boolean | `false` | Frida SSL pinning bypass |
| `frida` | boolean | `false` | Enable Frida instrumentation |
| `nvd_api_key` | string | — | NVD API key (higher rate limit) |

**Prerequisites:**
- Non-jailbroken: `ideviceinfo` + local IPA file
- Jailbroken: + SSH root access (checkra1n / unc0ver / palera1n / dopamine) + frida-server running on device

**Quick Start:**
```
secV ❯ use ios_pentest
secV (ios_pentest) ❯ run device

# Jailbroken deep test
secV ❯ use ios_pentest
secV (ios_pentest) ❯ set operation full
secV (ios_pentest) ❯ set ssh_host 192.168.1.50
secV (ios_pentest) ❯ set ssl_bypass true
secV (ios_pentest) ❯ run device
```

---

## Web

### `websec` v1.0.0
**Web Security Research Tool**

Burp Suite-style terminal tool for security researchers and bug bounty hunters. Covers web OSINT, security header auditing, CORS testing, cookie analysis, directory discovery, SQLi, XSS, web spidering, Google dork generation, WAF fingerprinting, and a built-in OWASP vulnerability knowledge base. Every operation prints `[LEARN]` context. Works with stdlib only, enhanced with `requests` and `beautifulsoup4`.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `operation` | string | `recon` | Operation to run (see table below) |
| `test_url` | string | — | URL with params for SQLi/XSS testing |
| `threads` | integer | `10` | Concurrent threads (1-50) |
| `timeout` | number | `10.0` | HTTP request timeout in seconds |
| `max_pages` | integer | `50` | Max pages to crawl in spider operation |
| `wordlist_file` | string | — | Path to custom wordlist for directory discovery |
| `verbose` | boolean | `false` | Verbose output |

**Operations:**

| Operation  | Description                                                         |
|------------|---------------------------------------------------------------------|
| `recon`    | DNS, WHOIS, SSL cert, robots.txt, Wayback Machine, tech stack       |
| `headers`  | Security headers audit (HSTS, CSP, X-Frame-Options, etc.)          |
| `cors`     | CORS misconfiguration: wildcard, origin reflection, credentials     |
| `cookies`  | Cookie flag audit: Secure, HttpOnly, SameSite                       |
| `dirs`     | Directory/file discovery with 100+ built-in paths + custom wordlist |
| `sqli`     | Error-based SQL injection (15+ database error patterns)             |
| `xss`      | Reflected XSS via input reflection testing                          |
| `spider`   | Crawl site, map URLs, forms, JS files                               |
| `dork`     | Generate 18+ Google dork queries and OSINT resource links           |
| `ssl`      | Deep SSL/TLS: version, cipher suites, cert details                  |
| `waf`      | Detect Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5        |
| `full`     | All non-intrusive checks in one pass                                |
| `vulnlib`  | Browse built-in OWASP vulnerability knowledge base                  |

**Quick Start:**
```
secV ❯ use websec
secV (websec) ❯ set operation recon
secV (websec) ❯ run https://example.com
```

**Authorization required** - only test systems you own or have explicit written permission to test.

---

### `webscan` v1.0.0
**Web Vulnerability Scanner**

OWASP Top 10 web scanner: error-based and time-based SQL injection, reflected XSS, CSRF detection, 403 bypass (header injection + path tricks), open redirect, Jira/AEM/Confluence CVEs, security headers audit, file upload detection, and rate limit testing. Supports authenticated scanning via cookies and custom headers.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | — | URL with query params for SQLi/XSS (e.g. `https://example.com/search?q=test`) |
| `sqli` | boolean | `true` | Error-based and time-based SQL injection |
| `xss` | boolean | `true` | Reflected XSS testing |
| `csrf` | boolean | `true` | CSRF token detection |
| `bypass_403` | boolean | `false` | 403 bypass via header injection + path manipulation |
| `bypass_path` | string | `/admin` | Path to test 403 bypass on |
| `open_redirect` | boolean | `true` | Open redirect via common redirect params |
| `framework_cves` | boolean | `true` | Jira, AEM, Confluence CVE checks |
| `file_upload` | boolean | `true` | File upload endpoint detection |
| `rate_limit` | boolean | `false` | Rate limit enforcement test |
| `cookies` | string | — | Session cookies: `key=value; key2=value2` |
| `headers_str` | string | — | Custom request headers |
| `user_agent` | string | `Mozilla/5.0` | User-Agent string |

**Quick Start:**
```
secV ❯ use webscan
secV (webscan) ❯ set url https://example.com/search?q=test
secV (webscan) ❯ run https://example.com
```

**Authorization required** — only scan applications you own or have explicit written permission to test.

---

## Module Development

### Quick Start

```bash
mkdir -p tools/category/my-tool
cd tools/category/my-tool

# Generate module.json from source code
python3 ../../../gen_module.py . --write

# Or scaffold manually
cat > module.json << 'EOF'
{
  "name": "my-tool",
  "version": "1.0.0",
  "category": "category",
  "description": "One-line description",
  "author": "you",
  "executable": "python3 main.py",
  "dependencies": [],
  "optional_dependencies": {},
  "help": {
    "description": "Extended description",
    "parameters": {
      "param_name": {
        "description": "What it does",
        "type": "string",
        "required": false,
        "default": "value",
        "options": ["option1", "option2"]
      }
    },
    "examples": [
      {
        "description": "Basic usage",
        "commands": ["use my-tool", "run target"]
      }
    ],
    "features": [],
    "notes": []
  },
  "timeout": 300
}
EOF
```

Module stdin receives `{"target": "...", "params": {...}}` as JSON. Read with:
```python
import json, sys
ctx    = json.loads(sys.stdin.read())
target = ctx["target"]
params = ctx.get("params", {})
```

After adding: `secV ❯ reload`

### `gen_module.py` — Module JSON Generator

Auto-generates `module.json` from source code. Scans Python `params.get()` and `argparse`, and Bash `jq .params.X` patterns.

```bash
# Print generated JSON
python3 gen_module.py tools/network/my-tool/

# Write module.json into the tool directory
python3 gen_module.py tools/network/my-tool/ --write

# Merge newly detected params into existing hand-written module.json
python3 gen_module.py tools/network/my-tool/ --update
```

What is auto-detected: parameter names, types (`int(params.get(...))` → `integer`, `_bool(...)` → `boolean`), defaults, argparse `help=`/`choices=`/`required=`, version/author from docstrings, third-party imports as dependencies, executable.

Descriptions and `examples` blocks must be filled in manually.

### Contribution Checklist

- [ ] Module works at Basic tier (no optional deps)
- [ ] `module.json` with complete `help.parameters` section
- [ ] `README.md` inside the module directory
- [ ] No unhandled exceptions reaching stdout
- [ ] Binary names (not pip packages) in `dependencies`
- [ ] New pip packages added to `requirements.txt` with tier comment
- [ ] Update this `MODULES.md` file

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## Compatibility Matrix

| Module | Basic | Standard | Full | Linux | macOS |
|--------|-------|----------|------|-------|-------|
| `netrecon` | TCP/DNS | + SYN/Nmap | + Shodan/CVE | ✓ | ✓ |
| `mac_spoof` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `wifi_monitor` | TCP-ping | + ARP/scapy | + CVE lookup | ✓ | ✓ |
| `android_pentest` | recon/adb | + Frida | + all ops | ✓ | ✓ |
| `ios_pentest` | static IPA | + idevice | + Frida/JB | ✓ | ✓ |
| `websec` | stdlib/DNS | + requests | + bs4/spider | ✓ | ✓ |
| `webscan` | headers/CSRF | + SQLi/XSS | + CVE checks | ✓ | ✓ |

---

*Maintained by SecVulnHub · 0xb0rn3*
