# SecV Installation Guide

## Quick Install

```bash
git clone https://github.com/SecVulnHub/SecV.git
cd SecV
chmod +x install.sh && ./install.sh
```

The installer detects your distro (Arch, Debian, Fedora, Alpine) and handles everything:
compiles the Go binary, installs system tools (`adb`, `apktool`, `nmap`, etc.), and
installs Python module dependencies. Optionally installs `secV` to `/usr/local/bin`.

```bash
./secV          # from repo directory
secV            # if installed system-wide
```

---

## What the Installer Does

1. Detects distro and package manager (`pacman`, `apt`, `dnf`, `apk`)
2. Checks Python 3.8+ and installs if missing
3. Installs `curl`, `unzip`, `java` (for Android RE tools)
4. Downloads and installs Android tools: `aapt`, `apktool`, `jadx`
5. Checks Go 1.21+ and installs if missing
6. Compiles the Go binary: `go build -o secV .`
7. Installs Python module dependencies via `requirements.txt`
8. Optionally links binary to `/usr/local/bin/secV`

---

## Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Go | 1.21+ | Compile the secV binary |
| Python | 3.8+ | Module execution |
| pip | any | Python dependency installation |
| git | any | Cloning and updates |

**OS:** Linux (Arch, Debian/Ubuntu, Fedora, Alpine) or macOS

---

## Manual Installation

If you prefer to install step by step:

```bash
# 1. Compile the binary
go build -o secV .

# 2. Install Python dependencies
pip3 install -r requirements.txt --break-system-packages

# 3. Make executable and run
chmod +x secV
./secV
```

---

## Installation Options

### Local (no sudo required)
```bash
./install.sh
# Answer N when asked about system-wide install
./secV
```

### System-Wide (recommended)
```bash
./install.sh
# Answer Y when asked about system-wide install
secV             # available from anywhere
```

### Manual system-wide link
```bash
sudo ln -sf "$(pwd)/secV" /usr/local/bin/secV
```

---

## Verification

```bash
./secV
secV ❯ show modules      # should list netrecon, mac_spoof, wifi_monitor, android_pentest, ios_pentest, webscan
secV ❯ show categories
secV ❯ help
secV ❯ exit
```

---

## Directory Structure

After installation:

```
SecV/
├── secV                          # Compiled Go binary
├── install.sh                    # Installer
├── uninstall.sh                  # Uninstaller
├── update.py                     # Updater
├── gen_module.py                 # Module JSON generator
├── requirements.txt              # Python dependencies (tiered)
├── go.mod / go.sum               # Go module manifest
├── main.go                       # Shell source
└── tools/
    ├── network/
    │   ├── netrecon/             # Multi-engine network recon
    │   ├── mac_spoof/            # Connection-aware MAC rotator
    │   └── wifi_monitor/         # Smart WiFi monitor + threat detector
    ├── mobile/
    │   ├── android/              # Android pentesting suite
    │   │   ├── module.json
    │   │   ├── android_pentest.py
    │   │   ├── agent/            # On-device C2 agent
    │   │   ├── apk_backdoor/     # APK repackaging + WAN C2
    │   │   └── c2_persistence/   # systemd service + watchdog for C2 attacker side
    │   └── ios/                  # iOS pentesting suite
    │       ├── module.json
    │       └── ios_pentest.py
    └── web/
        └── webscan/              # Web vulnerability scanner (SQLi, XSS, CSRF, ...)
```

---

## Module Dependencies

SecV uses a tiered dependency model. The installer installs everything in `requirements.txt`.

| Tier | Packages | Notes |
|------|----------|-------|
| Core | `psutil`, `requests`, `cryptography`, `netifaces`, `scapy`, `python-nmap`, `aiohttp`, `rich` | Always installed |
| Full | `beautifulsoup4`, `dnspython`, `pycryptodome`, `paramiko`, `pyyaml`, `frida-tools`, `objection` | Enabled by default |

`install.sh` also installs system tools (`adb`, `apktool`, `jadx`, `nmap`, `masscan`, `arp-scan`) and [bore](https://github.com/ekzhang/bore) for WAN tunneling.

For raw socket operations (SYN scanning, masscan) run with `sudo`:
```bash
sudo secV
# or
sudo ./secV
```

---

## Updating

```bash
secV ❯ update                 # interactive update (inside shell)

python3 update.py             # apply updates
python3 update.py --status    # check component status
python3 update.py --verify    # integrity check
python3 update.py --rollback  # restore last backup
```

---

## Uninstalling

```bash
chmod +x uninstall.sh && ./uninstall.sh    # removes system-wide binary

# Full removal
cd .. && rm -rf SecV/
```

---

## Troubleshooting

**Go binary won't compile**
```bash
sudo pacman -S go          # Arch
sudo apt install golang    # Debian/Ubuntu
brew install go            # macOS

go mod tidy
go build -o secV .
```

**Module not found after adding**
```bash
secV ❯ reload
```

**Permission denied**
```bash
chmod +x secV install.sh
```

**Missing adb / apktool**
```bash
./install.sh               # re-run installer — it skips already-installed components
```

**Python dependency missing**
```bash
pip3 install -r requirements.txt --break-system-packages
```

---

## Support

- Issues: https://github.com/SecVulnHub/SecV/issues
- Docs: [README.md](README.md), [MODULES.md](MODULES.md), [CONTRIBUTING.md](CONTRIBUTING.md)
