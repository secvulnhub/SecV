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

## What's New in v2.1

- **Enhanced Module Help System** - Comprehensive inline help for every module
- **Advanced Port Scanner v2.0** - Multi-engine scanner with intelligent fallback
- **Better Dependency Handling** - Graceful degradation across installation tiers
- **Professional Documentation** - Complete guides for users and contributors

---

## Features

**Metasploit-Style Interface**
- Interactive shell with rich terminal output
- Module loading and management system
- Context-aware command prompt
- Tab completion and command history
- **NEW: Integrated module help system**

**Polyglot Module Support**
- Write modules in Python, Bash, PowerShell, Go, Rust, or any executable format
- Cross-platform executable definitions
- Standardized JSON-based module configuration
- Automatic module discovery and loading

**Enhanced User Experience**
- **NEW: `help module` - View detailed help for any module**
- **NEW: `info <module>` - See documentation before loading**
- Rich terminal output with tables, panels, and syntax highlighting
- Comprehensive error handling and logging
- Easy contribution workflow

**Security-Focused**
- Timeout management for module execution
- Isolated execution contexts
- Structured result handling
- Category-based organization
- Dependency-aware execution

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

# Inside SecV shell - NEW enhanced help!
secV > help                      # Show all commands
secV > show modules              # List all available modules
secV > info portscan             # View module help
secV > use portscan              # Load the port scanner
secV (portscan) > help module    # View detailed module help
secV (portscan) > show options   # View configuration
secV (portscan) > set ports web  # Configure for web ports
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
| `use <module>` | Load a module | `use portscan` |
| **`info <module>`** | **Display module help (new!)** | **`info portscan`** |
| **`help module`** | **Show loaded module help (new!)** | **`help module`** |
| `search <query>` | Search for modules | `search web` |
| `set <option> <value>` | Set module parameter | `set timeout 60` |
| `run [target]` | Execute loaded module | `run 192.168.1.1` |
| `back` | Unload current module | `back` |
| `reload` | Rescan module directory | `reload` |
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

### PortScan v2.0 - Advanced Multi-Engine Network Scanner
*Author: SecVulnHub Team*

Professional-grade port scanner with multiple scanning engines and intelligent fallback:

**Features:**
- **Multiple Scan Engines:**
  - TCP Connect (always available)
  - SYN Stealth Scan (requires scapy + root)
  - Nmap Integration (requires python-nmap)
- **Service Detection:**
  - 20+ service fingerprints (HTTP, SSH, MySQL, Redis, etc.)
  - Banner grabbing with version detection
  - HTTP technology detection (WordPress, React, Angular, etc.)
- **Pre-defined Port Sets:**
  - `top-20` - Fast reconnaissance (default)
  - `top-100`, `top-1000` - Comprehensive scans
  - `web` - Web ports only (80, 443, 8080, etc.)
  - `db` - Database ports (MySQL, PostgreSQL, MongoDB, etc.)
  - `common` - Most frequently used ports
- **Performance:**
  - Concurrent scanning (50 threads)
  - Response time measurement
  - Configurable timeouts
- **Smart Fallback:**
  - Works without optional dependencies
  - Auto-detects capabilities
  - Informs users of available features

**Usage:**
```bash
secV > use portscan
secV (portscan) > help module        # View comprehensive help
secV (portscan) > set ports top-100  # Scan top 100 ports
secV (portscan) > set engine syn     # Use SYN scan (needs root)
secV (portscan) > run example.com    # Execute scan
```

**Installation Tiers:**
- **Basic:** TCP connect scan (stdlib only)
- **Standard:** + SYN scan (pip3 install scapy)
- **Full:** + HTTP tech detection (pip3 install requests)
- **Complete:** + Nmap integration (pip3 install python-nmap)

**Quick Examples:**
```bash
# Quick web scan
secV (portscan) > set ports web
secV (portscan) > run example.com

# Database server check
secV (portscan) > set ports db
secV (portscan) > run 192.168.1.100

# Stealth scan (requires root)
sudo secV
secV (portscan) > set engine syn
secV (portscan) > set ports top-1000
secV (portscan) > run target.local
```

See [tools/scanning/portscan/README.md](tools/scanning/portscan/README.md) for complete documentation.

---

## Module Help System

**NEW in v2.1:** Every module now includes comprehensive inline help!

### Viewing Module Help

```bash
# Before loading a module
secV > info portscan
# Shows: description, parameters, examples, features, notes

# After loading a module
secV > use portscan
secV (portscan) > help module
# Shows: detailed help for current module
```

### Help Content Includes:

- **Description** - What the module does and when to use it
- **Parameters** - All options with examples and defaults
- **Usage Examples** - Step-by-step command sequences
- **Features** - Key capabilities
- **Installation Tiers** - What works at each level
- **Notes** - Important warnings and tips

### Example Help Output:

```
╔═══════════════════════════════════════════════════════════════════╗
║                    PortScan Module Help                           ║
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  Advanced multi-engine network port scanner with service detection,
  banner grabbing, and intelligent fallback mechanisms.

PARAMETERS:
  ports           Port specification (default: top-20)
                  Options: top-20, top-100, web, db, 1-1000, 80,443
  
  engine          Scan engine (default: auto)
                  Options: auto, connect, syn, nmap
  
  timeout         Timeout per port in seconds (default: 1.0)

EXAMPLES:
  1. Quick scan of common ports:
     secV > use portscan
     secV (portscan) > run example.com
  
  2. Web application scan:
     secV (portscan) > set ports web
     secV (portscan) > run webapp.com

FEATURES:
  • Multiple scan engines (connect, SYN, nmap)
  • Service detection and banner grabbing
  • Pre-defined port sets for common tasks
  • Works at all installation tiers
```

---

## Creating Your First Module

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete guide. Here's a quick example:

### 1. Create Module Directory

```bash
mkdir -p tools/network/my-module
cd tools/network/my-module
```

### 2. Create `module.json` with Help

```json
{
  "name": "my-module",
  "version": "1.0.0",
  "category": "network",
  "description": "My awesome security module",
  "author": "YourName",
  "executable": "python3 module.py",
  
  "dependencies": [],
  
  "help": {
    "description": "Extended description of what your module does",
    "parameters": {
      "target": {
        "description": "Target IP or hostname",
        "required": true,
        "examples": ["192.168.1.1", "example.com"]
      }
    },
    "examples": [
      {
        "description": "Basic usage",
        "commands": [
          "use my-module",
          "run example.com"
        ]
      }
    ],
    "features": [
      "Feature 1",
      "Feature 2"
    ]
  },
  
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
  
  "timeout": 300
}
```

### 3. Create `module.py` with Help Support

```python
#!/usr/bin/env python3
import json
import sys

def show_help():
    """Display module help"""
    print("""
Module Help Text Here
    """)

def main():
    # Support --help flag
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        show_help()
        sys.exit(0)
    
    # Read execution context
    context = json.loads(sys.stdin.read())
    target = context['target']
    
    # Your security operations here
    result = {
        "success": True,
        "data": {"target": target, "status": "Complete"},
        "errors": []
    }
    
    print(json.dumps(result))

if __name__ == '__main__':
    main()
```

### 4. Make It Executable and Test

```bash
chmod +x module.py

# Test help
python3 module.py --help

# Test in SecV
cd ../../..
./secV
secV > info my-module     # View help
secV > use my-module
secV (my-module) > help module
secV (my-module) > run 192.168.1.1
```

---

## Project Structure

```
SecV/
├── secV                    # Main executable (enhanced v2.1)
├── install.sh              # Installation script
├── uninstall.sh            # Uninstallation script
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── INSTALL.md              # Installation guide
├── CONTRIBUTING.md         # Contributor guide
├── MODULE_HELP_GUIDE.md    # NEW: Help documentation guide
└── tools/                  # Module repository
    ├── scanning/
    │   └── portscan/       # NEW: Enhanced v2.0
    │       ├── module.json
    │       ├── portscan.py
    │       └── README.md
    ├── network/
    │   └── spoof/
    │       ├── module.json
    │       ├── macspoof.sh
    │       └── macspoof.ps1
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
3. **Add module help documentation** - Make modules easier to use
4. **Improve documentation** - Help others understand and use SecV
5. **Report bugs** - Help us identify and fix issues
6. **Suggest features** - Share your ideas for improvements

**Module Development Guidelines:**
- Modules should work at **Basic** installation tier (graceful degradation)
- **Always include help section in module.json**
- Use optional dependencies intelligently (detect and fallback)
- Follow the patterns in [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md)
- See [MODULE_HELP_GUIDE.md](MODULE_HELP_GUIDE.md) for help documentation
- Test across all installation tiers before submitting

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

**Quick Links:**
- [Contribution Guidelines](CONTRIBUTING.md)
- [Module Development Guide](MODULE_DEVELOPMENT.md)
- [Module Help Guide](MODULE_HELP_GUIDE.md) - NEW!
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

**Current Version: v2.1.0**

**Completed:**
- ✅ Metasploit-style interactive shell
- ✅ Module loading and management system
- ✅ Multi-tier installation system
- ✅ **Enhanced module help system** (v2.1)
- ✅ **Advanced port scanner with multiple engines** (v2.0)
- ✅ Rich terminal output and formatting
- ✅ Cross-platform support (Linux, macOS, Windows)
- ✅ Graceful dependency handling
- ✅ Comprehensive documentation

**Upcoming Features:**
- Additional scanning modules (web, DNS, subdomain)
- Workflow orchestration for multi-stage attacks
- Module dependency auto-resolution
- Built-in report generation
- Result caching and history
- Advanced tab completion for parameters
- Plugin system for extensions
- Integration with Metasploit modules
- Web interface (optional)
- IPv6 support for scanners

**Module Development:**
- More scanning modules (vulnerability scanners)
- Exploitation modules (SQLmap wrapper, web exploits)
- Reconnaissance modules (OSINT tools, subdomain enumeration)
- Post-exploitation modules (privilege escalation, persistence)

**Community Contributions Welcome!**

---

<div align="center">

**Made with ❤️ by ethical hackers, for ethical hackers**

[Report Bug](https://github.com/SecVulnHub/SecV/issues) • [Request Feature](https://github.com/SecVulnHub/SecV/issues) • [Documentation](https://github.com/SecVulnHub/SecV/wiki)

</div>
