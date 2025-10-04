# SecV - The Polyglot Cybersecurity Orchestration Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/SecVulnHub/SecV)
[![Community](https://img.shields.io/badge/community-SecVulnHub-green.svg)](https://github.com/SecVulnHub)

SecV is a next-generation cybersecurity orchestration platform featuring a Metasploit-style interactive shell for executing security modules written in any programming language. Built for ethical hackers, penetration testers, and security researchers who need a unified interface for their diverse toolkit.

```
╔═══════════════════════════════════════════════════════════════════╗
║   ███████╗███████╗ ██████╗██╗   ██╗                             ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║                             ║
║   ███████╗█████╗  ██║     ██║   ██║                             ║
║   ╚════██║██╔══╝  ██║     ╚██╗ ██╔╝                             ║
║   ███████║███████╗╚██████╗ ╚████╔╝                              ║
║   ╚══════╝╚══════╝ ╚═════╝  ╚═══╝                               ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## Features

**Metasploit-Style Interface**
- Interactive shell with rich terminal output
- Module loading and management system
- Context-aware command prompt
- Tab completion and command history

**Polyglot Module Support**
- Write modules in Python, Bash, PowerShell, Go, Rust, or any executable format
- Cross-platform executable definitions
- Standardized JSON-based module configuration
- Automatic module discovery and loading

**Developer-Friendly**
- Simple module structure (just add a folder with `module.json`)
- Rich terminal output with tables, panels, and syntax highlighting
- Comprehensive error handling and logging
- Easy contribution workflow

**Security-Focused**
- Timeout management for module execution
- Isolated execution contexts
- Structured result handling
- Category-based organization

---

## Quick Start

### Installation

SecV offers **three installation tiers** to suit your needs:

```bash
# Clone the repository
git clone https://github.com/SecVulnHub/SecV.git
cd SecV

# Run the interactive installer
chmod +x install.sh secV
./install.sh

# Choose your installation tier:
# 1) Basic - Core functionality only (~5MB)
# 2) Standard - Core + scanning tools (~50MB) ⭐ Recommended
# 3) Full - All features (~100MB)
```

The installer will:
- Check Python 3.8+ and pip
- Install dependencies based on your choice
- Set up executable permissions
- Optionally install system-wide

**Installation Tiers Explained:**

| Tier | Dependencies | Best For | Module Support |
|------|-------------|----------|----------------|
| **Basic** | cmd2, rich | Minimal setup, basic modules | Core modules only |
| **Standard** | Basic + python-nmap, scapy | Most users, full scanning | All scanning modules |
| **Full** | Everything in requirements.txt | Power users, all features | All modules + extras |

### Quick Start After Installation

```bash
# Start SecV (local installation)
./secV

# OR if installed system-wide
secV

# Inside SecV shell
secV > show modules              # List all available modules
secV > show categories           # List module categories
secV > use portscan             # Load the port scanner
secV (portscan) > show options  # View configuration
secV (portscan) > run target.com # Execute scan
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

---

## Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `show modules` | List all available modules | `show modules` |
| `show categories` | List all categories | `show categories` |
| `show options` | Display current module options | `show options` |
| `use <module>` | Load a module | `use port-scanner` |
| `info [module]` | Display module information | `info spoof` |
| `search <query>` | Search for modules | `search web` |
| `set <option> <value>` | Set module parameter | `set timeout 60` |
| `run [target]` | Execute loaded module | `run 192.168.1.1` |
| `back` | Unload current module | `back` |
| `clear` | Clear the screen | `clear` |
| `help` | Show help menu | `help` |
| `exit` | Exit SecV shell | `exit` |

---

## Module Categories

SecV organizes modules into logical categories:

- **Scanning** - Port scanning, service enumeration, network discovery
- **Network** - Network manipulation, spoofing, routing
- **Vulnerability** - Vulnerability assessment and detection
- **Exploitation** - Exploit frameworks and PoC tools
- **Reconnaissance** - OSINT, information gathering, footprinting
- **Web** - Web application testing, fuzzing, crawling
- **Wireless** - WiFi attacks, Bluetooth exploitation
- **Forensics** - Digital forensics, memory analysis
- **Post-Exploitation** - Privilege escalation, persistence, lateral movement
- **Reporting** - Report generation, documentation tools
- **Misc** - Utilities and helper tools

---

## Featured Modules

### PortScan - Advanced Network Scanner
*Author: 0xbv1 | 0xb0rn3*

Multi-engine network scanner with masscan-speed capabilities:

**Features:**
- Multiple scan engines (auto-select, connect, masscan-style, nmap, scapy)
- 20+ service fingerprints (HTTP, SSH, MySQL, Redis, etc.)
- TLS/SSL certificate analysis
- HTTP technology detection (WordPress, React, Angular, etc.)
- OS fingerprinting and device identification
- Masscan-speed async scanning (~500-1000 ports/sec)
- Works without external dependencies (graceful degradation)

**Usage:**
```bash
secV > use portscan
secV (portscan) > set ports top-100
secV (portscan) > set use_masscan_speed true
secV (portscan) > run example.com
```

**Installation Tiers:**
- Basic: TCP connect scan only
- Standard: + nmap-style + SYN scanning
- Full: All features + enhanced detection

See [tools/scanning/portscan/README.md](tools/scanning/portscan/README.md) for details.

---

## Creating Your First Module

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete guide. Here's a quick example:

### 1. Create Module Directory

```bash
mkdir -p tools/network/my-module
cd tools/network/my-module
```

### 2. Create `module.json`

```json
{
  "name": "my-module",
  "version": "1.0.0",
  "category": "network",
  "description": "My awesome security module",
  "author": "YourName",
  "executable": "python3 module.py",
  "dependencies": [],
  "inputs": {
    "target": {
      "type": "string",
      "description": "Target IP or hostname",
      "required": true
    }
  },
  "outputs": {
    "status": {
      "type": "string",
      "description": "Execution status"
    }
  },
  "timeout": 300,
  "concurrent": false
}
```

### 3. Create `module.py`

```python
#!/usr/bin/env python3
import json
import sys

# Read execution context from stdin
context = json.loads(sys.stdin.read())
target = context['target']

# Perform your security operations here
result = {
    "success": True,
    "data": {
        "target": target,
        "status": "Operation completed"
    },
    "errors": []
}

# Output result as JSON to stdout
print(json.dumps(result))
```

### 4. Make It Executable

```bash
chmod +x module.py
```

### 5. Test Your Module

```bash
secV
secV > use my-module
secV (my-module) > run 192.168.1.1
```

That's it! SecV automatically discovers and loads your module.

---

## Project Structure

```
SecV/
├── secV                    # Main executable
├── install.sh              # Installation script
├── uninstall.sh            # Uninstallation script
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── INSTALL.md              # Installation guide
├── CONTRIBUTING.md         # Contributor guide
└── tools/                  # Module repository
    ├── network/
    │   ├── spoof/
    │   │   ├── module.json
    │   │   ├── macspoof.sh
    │   │   └── macspoof.ps1
    │   └── port-scanner/
    │       ├── module.json
    │       └── scanner.py
    ├── scanning/
    ├── vulnerability/
    ├── exploitation/
    └── ...
```

---

## Requirements

**Minimum:**
- Python 3.8 or later
- pip (Python package installer)
- Operating System: Linux, macOS, or Windows (WSL)

**Python Dependencies by Tier:**

*Basic Tier (Required):*
- `cmd2` >= 2.4.3 - Advanced CLI framework
- `rich` >= 13.0.0 - Terminal formatting

*Standard Tier (Recommended):*
- `python-nmap` >= 0.7.1 - Nmap integration for scanning modules
- `scapy` >= 2.5.0 - Raw packet manipulation for advanced scanning

*Full Tier (All Features):*
- `requests` >= 2.31.0 - HTTP operations
- `beautifulsoup4` >= 4.12.0 - HTML parsing
- `dnspython` >= 2.4.0 - DNS operations
- `pycryptodome` >= 3.19.0 - Cryptography
- `paramiko` >= 3.4.0 - SSH operations
- `pyyaml` >= 6.0.1 - Configuration parsing

**Platform-Specific Notes:**
- **Linux**: Scapy requires `libpcap-dev` (`sudo apt install libpcap-dev`)
- **macOS**: All dependencies work out of the box
- **Windows**: Scapy requires Npcap driver installation
- **Raw Packet Operations**: SYN scanning requires root/sudo privileges

---

## Contributing

We welcome contributions from the security community! Whether you're adding new modules, improving the core platform, or fixing bugs - your help makes SecV better.

**Ways to Contribute:**
1. **Add new security modules** - Expand SecV's capabilities
2. **Improve existing modules** - Enhance features or fix bugs
3. **Improve documentation** - Help others understand and use SecV
4. **Report bugs** - Help us identify and fix issues
5. **Suggest features** - Share your ideas for improvements

**Module Development:**
- Modules should work at **Basic** installation tier (graceful degradation)
- Use optional dependencies intelligently (detect and fallback)
- Follow the patterns in [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md)
- Test across all installation tiers before submitting

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines and [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md) for module development best practices.

**Quick Links:**
- [Contribution Guidelines](CONTRIBUTING.md)
- [Module Development Guide](MODULE_DEVELOPMENT.md)
- [Installation Guide](INSTALL.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

---

## Community & Support

- **Issues**: [GitHub Issues](https://github.com/SecVulnHub/SecV/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SecVulnHub/SecV/discussions)
- **Documentation**: [GitHub Wiki](https://github.com/SecVulnHub/SecV/wiki)
- **Team**: SecVulnHub Collective

---

## Ethical Use Statement

SecV is designed exclusively for **authorized security testing, research, and educational purposes**. Users must:

- Obtain proper authorization before testing any systems
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Respect privacy and data protection laws

**You are responsible for your actions.** Misuse of this tool for unauthorized access, damage, or malicious purposes is illegal and unethical.

---

## License

SecV is released under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built by the SecVulnHub team - a collective of ethical hackers, penetration testers, and security researchers passionate about building tools that matter.

Special thanks to all contributors who make this project possible.

---

## Roadmap

**Current Version: v0.2.0**

**Completed:**
- ✅ Metasploit-style interactive shell
- ✅ Module loading and management system
- ✅ Multi-tier installation system
- ✅ Advanced port scanner with multiple engines
- ✅ Rich terminal output and formatting
- ✅ Cross-platform support (Linux, macOS, Windows)
- ✅ Graceful dependency handling
- ✅ Comprehensive documentation

**Upcoming Features:**
- 🔄 Additional scanning modules (web, DNS, subdomain)
- 🔄 Workflow orchestration for multi-stage attacks
- 🔄 Module dependency auto-resolution
- 🔄 Built-in report generation
- 🔄 Result caching and history
- 🔄 Advanced tab completion
- 🔄 Plugin system for extensions
- 🔄 Integration with Metasploit modules
- 🔄 Web interface (optional)

**Module Development:**
- More scanning modules (masscan-style, vulnerability scanners)
- Exploitation modules (SQLmap wrapper, web exploits)
- Reconnaissance modules (OSINT tools, subdomain enumeration)
- Post-exploitation modules (privilege escalation, persistence)

**Community Contributions Welcome!**

---

<div align="center">

**Made with ❤️ by ethical hackers, for ethical hackers**

[Report Bug](https://github.com/SecVulnHub/SecV/issues) • [Request Feature](https://github.com/SecVulnHub/SecV/issues) • [Documentation](https://github.com/SecVulnHub/SecV/wiki)

</div>
