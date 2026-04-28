# SecV Module Index

Complete reference of all SecV security modules.

**Version:** 2.4.0  
**Total Modules:** 4  
**Categories:** network (2), mobile (2)

---

## Quick Navigation

- [Network](#network)
- [Mobile](#mobile)
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

| Operation | Description |
|-----------|-------------|
| `recon` | Device fingerprint, root status, SELinux, chipset |
| `app_scan` | APK analysis, manifest audit, security score |
| `vuln_scan` | 50+ checks, OWASP Mobile Top 10, NVD live CVEs |
| `exploit` | Intent injection, SQLi, content provider attacks |
| `network` | Traffic capture, SSL inspection, proxy setup |
| `forensics` | Data extraction, artifact analysis |
| `get_root` | Multi-vector root acquisition (Magisk, CVE-2024-0044, mtk-su, KernelSU) |
| `inject_agent` | Push native recon agent, receive JSON report via TCP C2 |
| `adb_wifi` | Enable ADB over WiFi — drop USB dependency |
| `deploy_shell` | Generate and install Meterpreter APK (no root required) |
| `persist` | Termux:Boot + Magisk module persistence |
| `exploit_cve` | Targeted CVE exploitation |
| `full_pwn` | Automated chain: recon → root → shell → persist → WAN |
| `multi_device` | Run any operation across all connected devices simultaneously |
| `full` | Complete assessment: recon + vuln_scan + exploit + network + forensics |

**On-Device Agent** (`tools/mobile/android/agent/`):
- `secv_agent.sh` — shell script, any Android without compilation
- `secv_agent.c` — compiled ARM64 binary via NDK (`build.sh`)
- `c2_server.py` — standalone TCP+HTTP C2 with interactive REPL

**APK Backdoor Tool** (`tools/mobile/android/apk_backdoor/`):
- `build_termux_boot.py` — repackage any APK with persistent meterpreter payload, boot receiver, WAN C2 via bore.pub tunnels, DexClassLoader runtime staging, Play Protect bypass

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
| `android_pentest` | recon/adb | + Frida | + all ops | ✓ | ✓ |
| `ios_pentest` | static IPA | + idevice | + Frida/JB | ✓ | ✓ |

---

*Maintained by SecVulnHub · 0xb0rn3*
