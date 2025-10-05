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
- **Smart Update System** - Non-intrusive update checking with user control
- **Enhanced UI** - Improved visual styling and better user experience

---

## Features

**Metasploit-Style Interface**
- Interactive shell with rich terminal output
- Module loading and management system
- Context-aware command prompt with enhanced styling
- Tab completion and command history
- Integrated module help system
- Smart update management

**Polyglot Module Support**
- Write modules in Python, Bash, PowerShell, Go, Rust, or any executable format
- Cross-platform executable definitions
- Standardized JSON-based module configuration
- Automatic module discovery and loading

**Enhanced User Experience**
- `help module` - View detailed help for any module
- `info <module>` - See documentation before loading
- `update` - Manual update control
- `autoupdate` - Toggle automatic updates
- Rich terminal output with Unicode symbols
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
# Clone the repository (recommended for auto-updates)
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

# Inside SecV shell - enhanced UI!
secV ➤ help                      # Show all commands
secV ➤ show modules              # List all available modules
secV ➤ info portscan             # View module help
secV ➤ use portscan              # Load the port scanner
secV (portscan) ➤ help module    # View detailed module help
secV (portscan) ➤ show options   # View configuration
secV (portscan) ➤ set ports web  # Configure for web ports
secV (portscan) ➤ run target.com # Execute scan
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
| `info <module>` | Display module help | `info portscan` |
| `help module` | Show loaded module help | `help module` |
| `search <query>` | Search for modules | `search web` |
| `set <option> <value>` | Set module parameter | `set timeout 60` |
| `run [target]` | Execute loaded module | `run 192.168.1.1` |
| `back` | Unload current module | `back` |
| `reload` | Rescan module directory | `reload` |
| `update` | Check for and install updates | `update` |
| `autoupdate` | Toggle automatic updates | `autoupdate` |
| `clear` | Clear the screen | `clear` |
| `help` | Show help menu | `help` |
| `exit` | Exit SecV shell | `exit` |

---

## Update Management

SecV includes a smart update system that balances convenience with user control.

### Automatic Updates

By default, SecV checks for updates once every 24 hours (only if installed from git):

```bash
# Auto-checks happen silently in background
secV

# Disable automatic update checks
secV ➤ autoupdate
⚠ Auto-update disabled
Use 'update' command to manually check for updates

# Re-enable automatic checks
secV ➤ autoupdate
✓ Auto-update enabled
```

### Manual Updates

Update anytime with the `update` command:

```bash
secV ➤ update
╔═══════════════════════════════════════════════════════════════════╗
║ SecV Update                                                       ║
╚═══════════════════════════════════════════════════════════════════╝

Checking for updates...
✓ You're already on the latest version!
```

**Update Behavior:**
- Only works with git-cloned installations
- Shows helpful message if not a git repo
- Updates both core platform and modules
- Reminds you to reload modules after update

### Update Requirements

For automatic updates to work:
- SecV must be installed via `git clone`
- `.git` directory must exist
- Git must be installed on system

**Installed from ZIP?** Auto-update won't work, but you can manually update:
```bash
cd /path/to/SecV
git init
git remote add origin https://github.com/SecVulnHub/SecV.git
git fetch
git reset --hard origin/main
```

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
- Multiple scan engines (TCP Connect, SYN, Nmap)
- Service detection with 20+ fingerprints
- Banner grabbing and version detection
- HTTP technology detection
- Pre-defined port sets (top-20, web, db, common)
- Concurrent scanning (50 threads)
- Smart fallback for missing dependencies

**Usage:**
```bash
secV ➤ use portscan
secV (portscan) ➤ help module        # View comprehensive help
secV (portscan) ➤ set ports top-100  # Scan top 100 ports
secV (portscan) ➤ set engine syn     # Use SYN scan (needs root)
secV (portscan) ➤ run example.com    # Execute scan
```

**Installation Tiers:**
- **Basic:** TCP connect scan (stdlib only)
- **Standard:** + SYN scan (requires scapy)
- **Full:** + HTTP tech detection (requires requests)

See [tools/scanning/portscan/README.md](tools/scanning/portscan/README.md) for complete documentation.

### MAC Spoof v2.0 - Network Interface MAC Address Spoofer
*Author: 0xb0rn3 (oxbv1) - Enhanced*

Automated MAC address spoofer with background daemon support:

**Features:**
- Per-interface background daemons
- Locally-administered MAC addresses (02:00:00 prefix)
- State persistence and restoration
- Multi-interface support
- Dry-run mode for testing
- Configurable rotation intervals

**Usage:**
```bash
sudo secV
secV ➤ use mac_spoof
secV (mac_spoof) ➤ set iface wlan0
secV (mac_spoof) ➤ run target
```

See [tools/network/mac_spoof/README.md](tools/network/mac_spoof/README.md) for complete documentation.

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
secV ➤ info my-module     # View help
secV ➤ use my-module
secV (my-module) ➤ help module
secV (my-module) ➤ run 192.168.1.1
```

---

## Project Structure

```
SecV/
├── secV                    # Main executable (enhanced v2.1)
├── install.sh              # Installation script
├── uninstall.sh            # Uninstallation script
├── update.py               # Smart update script
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── INSTALL.md              # Installation guide
├── CONTRIBUTING.md         # Contributor guide
├── MODULE_HELP_GUIDE.md    # Help documentation guide
├── MODULE_DEVELOPMENT.md   # Module development guide
└── tools/                  # Module repository
    ├── scanning/
    │   └── portscan/       # Enhanced v2.0
    │       ├── module.json
    │       ├── portscan.py
    │       └── README.md
    ├── network/
    │   └── mac_spoof/      # Enhanced v2.0
    │       ├── module.json
    │       ├── mac_spoof.py
    │       └── README.md
    └── ...
```

---

## Requirements

**Minimum:**
- Python 3.8 or later
- pip (Python package installer)
- Operating System: Linux, macOS, or Windows (WSL)
- Git (for automatic updates)

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
- [Module Help Guide](MODULE_HELP_GUIDE.md)
- [Installation Guide](INSTALL.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

---

## Enhanced UI Features

SecV v2.1 includes visual improvements for better user experience:

**Enhanced Prompt:**
```
secV ➤                    # Clean, modern prompt
secV (portscan) ➤         # Shows active module
```

**Visual Feedback:**
- ✓ Success messages in green
- ✗ Error messages in red
- ➤ Info messages in blue
- ⚠ Warning messages in yellow
- ⚙ Execution indicators

**Better Formatting:**
- Box drawing characters for headers
- Dimmed text for metadata
- Color-coded parameters
- Aligned output columns
- Unicode symbols for clarity

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
- ✓ Metasploit-style interactive shell
- ✓ Module loading and management system
- ✓ Multi-tier installation system
- ✓ Enhanced module help system (v2.1)
- ✓ Advanced port scanner with multiple engines (v2.0)
- ✓ MAC address spoofer with daemon support (v2.0)
- ✓ Rich terminal output and formatting
- ✓ Smart update management
- ✓ Cross-platform support (Linux, macOS, Windows)
- ✓ Graceful dependency handling
- ✓ Comprehensive documentation

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
