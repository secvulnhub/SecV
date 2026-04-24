# SecV Module Index

Complete reference of all SecV security modules organized by category.

**Last Updated:** 2025-10-05  
**Total Modules:** [Auto-updated by system]

---

## Quick Navigation

- [Scanning](#scanning) - Port scanning, service enumeration, network discovery
- [Network](#network) - Network manipulation, spoofing, routing
- [Vulnerability](#vulnerability) - Vulnerability assessment and detection
- [Exploitation](#exploitation) - Exploit frameworks and PoC tools
- [Reconnaissance](#reconnaissance) - OSINT, information gathering
- [Web](#web) - Web application testing
- [Wireless](#wireless) - WiFi and Bluetooth attacks
- [Forensics](#forensics) - Digital forensics and analysis
- [Post-Exploitation](#post-exploitation) - Privilege escalation, persistence
- [Reporting](#reporting) - Report generation and documentation
- [Miscellaneous](#miscellaneous) - Utilities and helper tools

---

## Scanning

### PortScan v2.0
**Advanced Multi-Engine Network Scanner**

Professional-grade port scanner with multiple engines and intelligent fallback.

**Features:**
- Multiple scan engines (Connect, SYN, Nmap)
- 20+ service fingerprints
- Banner grabbing and version detection
- HTTP technology detection
- Pre-defined port sets (top-20, web, db, etc.)
- Concurrent scanning (50 threads)

**Installation Tiers:**
- Basic: TCP connect scan
- Standard: + SYN scan (requires scapy)
- Full: + HTTP detection (requires requests)

**Quick Start:**
```bash
secV > use portscan
secV (portscan) > help module
secV (portscan) > set ports web
secV (portscan) > run example.com
```

**Documentation:** [tools/scanning/portscan/README.md](tools/scanning/portscan/README.md)

---

### Network Discovery v1.0
**ICMP Ping Sweep and Host Discovery**

Fast network reconnaissance to identify live hosts.

**Features:**
- ICMP ping sweep
- CIDR notation support
- Multi-threaded scanning
- Response time measurement

**Installation Tiers:**
- Basic: Standard ping
- Standard: + Raw socket support

**Quick Start:**
```bash
secV > use network-discovery
secV (network-discovery) > run 192.168.1.0/24
```

**Documentation:** [tools/scanning/network-discovery/README.md](tools/scanning/network-discovery/README.md)

---

## Network

### MAC Spoof v1.0
**MAC Address Spoofing Tool**

Change network interface MAC addresses for anonymity or testing.

**Features:**
- Random MAC generation
- Vendor-specific MAC addresses
- Interface backup and restore
- Cross-platform (Linux/macOS/Windows)

**Installation Tiers:**
- Basic: Works on all tiers

**Quick Start:**
```bash
secV > use macspoof
secV (macspoof) > set interface eth0
secV (macspoof) > run localhost
```

**Documentation:** [tools/network/spoof/README.md](tools/network/spoof/README.md)

---

## Web

### Web Enumeration v1.0
**Web Application Discovery and Analysis**

Comprehensive web application enumeration including technology detection.

**Features:**
- Technology fingerprinting
- HTTP header analysis
- Common file discovery
- Directory bruteforcing
- SSL/TLS analysis

**Installation Tiers:**
- Basic: Basic enumeration (urllib)
- Standard: + Technology detection (requests)
- Full: + HTML parsing (beautifulsoup4)

**Quick Start:**
```bash
secV > use web-enum
secV (web-enum) > set mode standard
secV (web-enum) > run https://example.com
```

**Documentation:** [tools/web/web-enum/README.md](tools/web/web-enum/README.md)

---

## Reconnaissance

### Subdomain Enumeration v1.0
**Subdomain Discovery Tool**

Discover subdomains using multiple techniques.

**Features:**
- DNS bruteforcing
- Certificate transparency logs
- Search engine queries
- Custom wordlists
- Multi-source aggregation

**Installation Tiers:**
- Basic: Basic DNS queries
- Full: + Advanced queries (dnspython)

**Quick Start:**
```bash
secV > use subdomain-enum
secV (subdomain-enum) > set wordlist common
secV (subdomain-enum) > run example.com
```

**Documentation:** [tools/reconnaissance/subdomain-enum/README.md](tools/reconnaissance/subdomain-enum/README.md)

---

## Post-Exploitation

### Privilege Escalation Checker v1.0
**Linux Privilege Escalation Vector Scanner**

Automated checking for common Linux privilege escalation vectors.

**Features:**
- SUID/SGID binary enumeration
- Writable file discovery
- Kernel exploit checking
- Cron job analysis
- Service misconfiguration detection

**Installation Tiers:**
- Basic: Works on all tiers (bash)

**Quick Start:**
```bash
secV > use priv-esc-check
secV (priv-esc-check) > set checks all
secV (priv-esc-check) > run localhost
```

**Documentation:** [tools/post-exploitation/priv-esc-check/README.md](tools/post-exploitation/priv-esc-check/README.md)

---

## Module Development

### Creating Your Own Module

Want to contribute a module? Follow these steps:

1. **Read the guides:**
   - [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
   - [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md) - Development guide
   - [MODULE_HELP_GUIDE.md](MODULE_HELP_GUIDE.md) - Help documentation

2. **Create module structure:**
   ```bash
   mkdir -p tools/category/module-name
   cd tools/category/module-name
   ```

3. **Add required files:**
   - `module.json` - Module configuration with help section
   - `module.py` (or your executable) - Module implementation
   - `README.md` - Comprehensive documentation

4. **Update global requirements:**
   - Add dependencies to [requirements.txt](requirements.txt)
   - Document which module requires them
   - Test across all tiers

5. **Test thoroughly:**
   ```bash
   # Test at Basic tier
   pip uninstall scapy requests -y
   ./secV
   secV > use your-module
   
   # Test at Standard tier
   pip install scapy
   
   # Test at Full tier
   pip install -r requirements.txt
   ```

6. **Submit PR:**
   - Update this MODULES.md with your module
   - Include comprehensive documentation
   - Follow contribution guidelines

---

## Module Template

```json
{
  "name": "module-name",
  "version": "1.0.0",
  "category": "category",
  "description": "One-line description",
  "author": "Your Name",
  "executable": "python3 module.py",
  
  "dependencies": ["python3"],
  
  "optional_dependencies": {
    "library": "Description - Install: pip3 install library"
  },
  
  "help": {
    "description": "Extended description",
    "parameters": {
      "param": {
        "description": "What it does",
        "examples": ["value1", "value2"],
        "default": "default_value"
      }
    },
    "examples": [
      {
        "description": "Use case",
        "commands": ["use module-name", "run target"]
      }
    ],
    "features": ["Feature 1", "Feature 2"],
    "notes": ["Important note"]
  },
  
  "timeout": 300
}
```

---

## Module Status Legend

- ✅ **Stable** - Production ready, thoroughly tested
- 🔧 **Beta** - Functional but may have issues
- 🚧 **Alpha** - Early development, use with caution
- 📦 **Planned** - Documented but not yet implemented

---

## Coming Soon

These modules are planned for future releases:

### Scanning
- **ServiceEnum** 📦 - Comprehensive service enumeration
- **VulnScanner** 📦 - Vulnerability scanner integration

### Web
- **SQLMap Integration** 📦 - SQL injection testing
- **XSS Scanner** 📦 - Cross-site scripting detection
- **Directory Bruteforcer** 📦 - Advanced directory enumeration

### Exploitation
- **Metasploit Bridge** 📦 - Metasploit framework integration
- **Exploit-DB Search** 📦 - Search and execute exploits

### Wireless
- **WiFi Cracker** 📦 - WPA/WPA2 password cracking
- **Evil Twin** 📦 - Rogue access point creation

---

## Module Compatibility Matrix

| Module | Basic | Standard | Full | Linux | macOS | Windows |
|--------|-------|----------|------|-------|-------|---------|
| portscan | ✅ | ✅✅ | ✅✅✅ | ✅ | ✅ | ⚠️ |
| macspoof | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| web-enum | ✅ | ✅✅ | ✅✅✅ | ✅ | ✅ | ✅ |
| priv-esc-check | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ |

**Legend:**
- ✅ Basic functionality
- ✅✅ Enhanced functionality
- ✅✅✅ Full functionality
- ⚠️ Limited support
- ❌ Not supported

---

## Module Statistics

- **Total Modules:** Auto-updated
- **By Category:**
  - Scanning: 2
  - Network: 1
  - Web: 1
  - Reconnaissance: 1
  - Post-Exploitation: 1
  - Others: Check repository

---

## Getting Help

**Module-specific help:**
```bash
secV > info <module-name>          # View help before loading
secV > use <module-name>
secV (module) > help module         # View detailed help
```

**General help:**
- [README.md](README.md) - Project overview
- [INSTALL.md](INSTALL.md) - Installation guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guide
- [GitHub Discussions](https://github.com/SecVulnHub/SecV/discussions)

---

## Contributing Modules

We welcome module contributions! Your modules help expand SecV's capabilities.

**Requirements:**
1. Follow module development guide
2. Include comprehensive help documentation
3. Support Basic tier (graceful degradation)
4. Test across all platforms
5. Add dependencies to global requirements.txt
6. Update this MODULES.md file

**Process:**
1. Fork repository
2. Create module following guidelines
3. Test thoroughly
4. Submit PR with documentation
5. Address review feedback

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

*Module index maintained by SecVulnHub Team*  
*Last updated: Auto-generated*
