# Android Penetration Testing Module for SecV

**Category:** Mobile Security  
**Version:** 1.0.0  
**Author:** SecVulnHub Team | Enhanced by 0xb0rn3  
**License:** MIT

Complete Android security testing suite combining device reconnaissance, static/dynamic analysis, vulnerability scanning, exploitation testing, network interception, forensics, and advanced features from droidB and HacknDroid.

---

## 🎯 Features

### Core Capabilities
- ✅ **Device Reconnaissance** - Complete fingerprinting and security posture
- ✅ **Application Analysis** - Static APK analysis with security scoring
- ✅ **Vulnerability Scanning** - 50+ vulnerability types detected
- ✅ **Exploitation Testing** - Ethical PoC exploitation
- ✅ **Network Analysis** - Traffic capture and inspection
- ✅ **Forensics** - Data extraction and artifact analysis

### Advanced Features (HacknDroid Integration)
- 🔍 **Advanced Secret Search** - Recursive pattern matching for 15+ secret types
- 🔧 **Frida Integration** - Runtime instrumentation and hooking
- 🌐 **Proxy Setup** - Automated HTTP/HTTPS proxy configuration
- 🔓 **SSL Pinning Bypass** - Certificate pinning circumvention
- 💾 **Automated Backups** - Full device/app backup capabilities
- 📱 **Screen Operations** - Screenshot and video recording
- 🔄 **Process Analysis** - Running process enumeration
- 📡 **Network Intelligence** - WiFi info, connections, listening ports
- 🔐 **Certificate Management** - TLS certificate extraction

---

## 📦 Installation

### Basic Requirements
```bash
# Install ADB
apt install android-tools-adb  # Debian/Ubuntu
pacman -S android-tools        # Arch Linux
brew install android-platform-tools  # macOS

# Python requirements
pip3 install --user --break-system-packages \
    requests cryptography psutil netifaces
```

### Optional Tools (Enhanced Features)
```bash
# APK analysis
apt install aapt apktool jadx

# Frida (for runtime instrumentation)
pip3 install frida-tools objection

# Additional utilities
apt install keytool default-jdk
```

### Installation Tiers

| Tier | Dependencies | Capabilities |
|------|-------------|--------------|
| **Basic** | adb + python | Device recon, basic app analysis |
| **Standard** | + aapt, keytool | Static APK analysis, certificate validation |
| **Advanced** | + apktool, jadx | Code decompilation, deep analysis |
| **Full** | + frida, objection | Runtime instrumentation, SSL bypass |

---

## 🚀 Quick Start

### 1. Connect Device
```bash
# USB connection
adb devices

# Network connection
adb connect 192.168.1.100:5555

# Verify connection
adb shell echo "Connected!"
```

### 2. Basic Reconnaissance
```bash
secV > use android_pentest
secV (android_pentest) > set operation recon
secV (android_pentest) > run device
```

### 3. Scan Application
```bash
secV (android_pentest) > set operation app_scan
secV (android_pentest) > set package com.example.app
secV (android_pentest) > run device
```

---

## 📖 Operations Guide

### RECON - Device Reconnaissance
Complete device fingerprinting and security assessment.

**Usage:**
```bash
set operation recon
run device
```

**Detects:**
- Device model, manufacturer, Android version
- Root status (3 detection methods)
- Bootloader unlock status
- SELinux enforcement mode
- Encryption status
- Developer mode and USB debugging
- Security patch level
- Battery, uptime, kernel version

**Output:**
```json
{
  "device": {
    "rooted": true,
    "bootloader_unlocked": true,
    "selinux_status": "Permissive",
    "security_patch": "2024-01-01",
    "android_version": "14",
    ...
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "finding": "Device is rooted - all security controls bypassed"
    }
  ]
}
```

---

### APP_SCAN - Application Security Analysis
Comprehensive application security audit with scoring.

**Usage:**
```bash
set operation app_scan
set package com.target.app
run device
```
