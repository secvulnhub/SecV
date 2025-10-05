# SecV - The Polyglot Cybersecurity Orchestration Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/SecVulnHub/SecV)
[![Version](https://img.shields.io/badge/version-2.3.0-green.svg)](https://github.com/SecVulnHub/SecV)

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

## What's New in v2.3

- **Rich Output Formatting** - Beautiful formatted tables for complex module outputs
- **Capability Detection** - Automatic detection and warnings for missing optional dependencies
- **Parameter Validation** - Type checking, range validation, and option validation from module.json
- **Enhanced Error Messages** - Clear, actionable feedback on validation failures
- **Pre-execution Preview** - See parameters and configuration before running modules
- **Formatted Scan Results** - Special formatting for port scanners and other complex tools
- **100% Backwards Compatible** - All existing modules work without modification

---

## Features

### Metasploit-Style Interface
- Interactive shell with rich terminal output
- Module loading and management system
- Context-aware command prompt with enhanced styling
- Tab completion and command history
- Integrated module help system with detailed documentation
- Smart update management with auto-check capability
- Real-time module status dashboard (optional)

### Enhanced Module System
- **Polyglot Support** - Write modules in Python, Bash, PowerShell, Go, Rust, or any executable format
- **Cross-platform** - Platform-specific executable definitions
- **Standardized** - JSON-based module configuration with validation
- **Automatic Discovery** - Modules auto-loaded from directory structure
- **Capability Detection** - Warns about missing optional dependencies at load time
- **Parameter Validation** - Type checking, range validation, option validation
- **Rich Output** - Intelligent formatting of complex JSON outputs

### Enhanced User Experience
- `help module` - View detailed help for any module with dependency status
- `info <module>` - See documentation and capabilities before loading
- `update` - Manual update control with dependency management
- `autoupdate` - Toggle automatic updates (checks every 24 hours)
- `dashboard` - Real-time module execution status (if available)
- Rich terminal output with Unicode symbols and color coding
- Comprehensive error handling with actionable messages
- Pre-execution parameter preview
- Easy contribution workflow

### Security-Focused
- Timeout management for module execution
- Isolated execution contexts
- Structured result handling with validation
- Category-based organization
- Dependency-aware execution with graceful degradation

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
secV ➤ info portscan             # View module help with capability status
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
| `show modules` | List all available modules with categories | `show modules` |
| `show categories` | List all module categories | `show categories` |
| `show options` | Display current module options | `show options` |
| `show dashboard` | View real-time module execution status | `show dashboard` |
| `use <module>` | Load a module (with capability detection) | `use portscan` |
| `info <module>` | Display module help and capabilities | `info portscan` |
| `help module` | Show loaded module detailed help | `help module` |
| `search <query>` | Search for modules | `search web` |
| `set <option> <value>` | Set module parameter (with validation) | `set timeout 60` |
| `run [target]` | Execute loaded module | `run 192.168.1.1` |
| `back` | Unload current module | `back` |
| `reload` | Rescan module directory | `reload` |
| `update` | Check for and install updates | `update` |
| `autoupdate` | Toggle automatic updates | `autoupdate` |
| `dashboard` | Quick access to execution dashboard | `dashboard` |
| `clear` | Clear the screen | `clear` |
| `help` | Show help menu | `help` |
| `exit` | Exit SecV shell | `exit` |

---

## Enhanced Features in v2.3

### 1. Capability Detection

SecV now automatically detects missing optional dependencies when loading modules:

```bash
secV > use portscan
✓ Loaded: portscan
  Category: scanning
  Path: /path/to/tools/scanning/portscan

⚠ Optional Dependencies Missing
Module will work with reduced features

  • scapy: For SYN stealth scanning - pip3 install scapy
  • python-nmap: For nmap integration - pip3 install python-nmap
  • masscan: For ultra-fast scanning - apt install masscan

Install with: pip3 install scapy python-nmap
Or use: ./install.sh to reinstall with dependencies

Type 'help module' for detailed usage
```

### 2. Parameter Validation

SecV validates parameters based on module.json schema:

```bash
# Type validation
secV (portscan) > set threads abc
✗ Parameter 'threads' must be a number (got: abc)

# Range validation
secV (portscan) > set threads 1000
✗ Parameter 'threads' must be between 1 and 500

# Option validation
secV (portscan) > set engine turbo
✗ Parameter 'engine' must be one of: auto connect syn nmap masscan

# Success
secV (portscan) > set engine syn
engine → syn
```

### 3. Rich Output Formatting

Complex module outputs are automatically formatted for readability:

```bash
secV (portscan) > run scanme.nmap.org

⚙ Executing portscan against scanme.nmap.org...
Parameters:
  engine: syn
  ports: top-20
  threads: 200
Timeout: 600s

✓ Module completed successfully

Host Information
─────────────────────────────────────────────────────────────────────
IP Address: 45.33.32.156
Hostname: scanme.nmap.org
OS: Linux/Unix (confidence: 80%)

Open Ports (5 found)
─────────────────────────────────────────────────────────────────────

22/tcp → ssh OpenSSH 6.6.1p1
  
80/tcp → http Apache 2.4.7
  Title: Go ahead and ScanMe!
  Tech: Apache
  
443/tcp → https Apache 2.4.7
  ⚠  CVEs: CVE-2021-41773

Scan Statistics
─────────────────────────────────────────────────────────────────────
Duration: 8.45s
Scan Type: syn (capability: advanced)
Results: 5 open, 12 closed, 3 filtered

✓ Completed in 8450ms
```

### 4. Pre-execution Preview

See what will be executed before running:

```bash
secV (portscan) > run example.com

⚙ Executing portscan against example.com...
Parameters:
  engine: syn
  ports: top-100
  threads: 200
  service_detection: true
Timeout: 600s

[Scan begins...]
```

### 5. Enhanced Module Information

```bash
secV > info portscan

╔═══════════════════════════════════════════════════════════════════╗
║ Module: portscan                                                  ║
╚═══════════════════════════════════════════════════════════════════╝

Description: Elite port scanner with multi-engine support...
Author: SecVulnHub Team (Enhanced with r3cond0g features)
Version: 3.0.0
Category: scanning
Status: ✓ All dependencies available

📖 Detailed documentation: /path/to/tools/scanning/portscan/README.md
```

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
✓ An update is available!

Do you want to pull the latest changes? [Y/n]: y

Pulling latest updates from the repository...
✓ Project files updated successfully.

⚙ requirements.txt has changed in this update.

╔═══════════════════════════════════════════════════════════════════╗
║                   Dependency Changes Detected                     ║
╚═══════════════════════════════════════════════════════════════════╝

New Dependencies Added:
  + beautifulsoup4>=4.12.0
  + lxml>=4.9.0

Installing/Updating Python Dependencies...
✓ Dependencies installed successfully!

✓ All dependencies are up to date!
```

**Update Features:**
- Automatic dependency installation when requirements.txt changes
- Displays what dependencies were added/removed
- Multiple installation strategies for maximum compatibility
- Graceful handling of installation failures
- Module reload reminder

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

### PortScan v3.0 - Elite Multi-Engine Network Scanner
*Author: SecVulnHub Team (Enhanced with r3cond0g features)*

Professional-grade port scanner with multiple scanning engines and intelligent fallback:

**Features:**
- 4 scan engines (TCP Connect, SYN, Nmap, Masscan) with auto-selection
- 50+ service fingerprint probes with version detection
- 30+ HTTP technology detection (WordPress, Django, React, etc.)
- 100+ MAC vendor OUI database with device type recognition
- Automatic CVE vulnerability correlation
- TLS/SSL certificate inspection and analysis
- OS fingerprinting (TTL + service-based)
- Adaptive timeout management (95th percentile)
- DNS enumeration and reverse lookup
- Concurrent scanning (up to 500 threads)
- Smart rate limiting

**Installation Tiers:**
- **Basic:** TCP connect scan (stdlib only)
- **Standard:** + SYN scan (requires scapy)
- **Advanced:** + Nmap integration (requires python-nmap)
- **Full:** + HTTP detection, DNS (requires requests, beautifulsoup4, dnspython)
- **Elite:** + Masscan ultra-fast (requires masscan binary)

**Quick Start:**
```bash
secV > use portscan
secV (portscan) > help module        # View comprehensive help
secV (portscan) > set engine auto    # Let it choose best engine
secV (portscan) > set ports top-100  # Scan top 100 ports
secV (portscan) > run example.com    # Execute scan
```

**Advanced Usage:**
```bash
# Stealth SYN scan
secV (portscan) > set engine syn
secV (portscan) > set ports top-1000
secV (portscan) > set rate_limit 100

# Ultra-fast masscan
secV (portscan) > set engine masscan
secV (portscan) > set ports common
secV (portscan) > set rate 10000

# Full security audit
secV (portscan) > set engine auto
secV (portscan) > set ports common
secV (portscan) > set service_detection true
secV (portscan) > set http_analysis true
secV (portscan) > set os_detection true
```

**Detected Information:**
- Device Types: Cisco/Juniper/Arista routers, Dell/HP servers, VMware VMs, Raspberry Pi, etc.
- OS Detection: Linux/Unix, Windows, Cisco IOS, network devices
- Technologies: Apache, nginx, WordPress, Django, React, PHP, ASP.NET, and 20+ more
- Vulnerabilities: Automatic CVE correlation for Apache, OpenSSH, MySQL, nginx, etc.

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
secV > use mac_spoof
secV (mac_spoof) > set iface wlan0
secV (mac_spoof) > run target
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

### 2. Create `module.json` with Enhanced Schema

```json
{
  "name": "my-module",
  "version": "1.0.0",
  "category": "network",
  "description": "My awesome security module",
  "author": "YourName",
  "executable": "python3 module.py",
  
  "dependencies": [],
  
  "optional_dependencies": {
    "scapy": "For advanced features - pip3 install scapy"
  },
  
  "help": {
    "description": "Extended description of what your module does",
    "parameters": {
      "target": {
        "description": "Target IP or hostname",
        "required": true,
        "examples": ["192.168.1.1", "example.com"]
      },
      "threads": {
        "description": "Number of threads",
        "type": "number",
        "default": 10,
        "range": "1-100"
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
    },
    "threads": {
      "type": "number",
      "description": "Number of threads",
      "required": false,
      "default": 10,
      "range": "1-100"
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
╔═══════════════════════════════════════════════════════════════════╗
║                    My Module Help                                 ║
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  What your module does

USAGE:
  secV > use my-module
  secV (my-module) > run target
    """)

def main():
    # Support --help flag
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        show_help()
        sys.exit(0)
    
    # Read execution context
    context = json.loads(sys.stdin.read())
    target = context['target']
    threads = context.get('params', {}).get('threads', 10)
    
    # Your security operations here
    result = {
        "success": True,
        "data": {
            "target": target,
            "threads": threads,
            "status": "Complete"
        },
        "errors": []
    }
    
    # SecV v2.3 will format this automatically
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
```

### 4. Test Your Module

```bash
chmod +x module.py

# Test help
python3 module.py --help

# Test in SecV with capability detection and validation
cd ../../..
./secV
secV > info my-module          # View help and check dependencies
secV > use my-module           # Load with capability detection
secV (my-module) > set threads 50  # Validated against range
secV (my-module) > help module  # View detailed help
secV (my-module) > run 192.168.1.1  # Execute with formatted output
```

---

## Project Structure

```
SecV/
├── secV                    # Main executable (v2.3 - enhanced)
├── install.sh              # Installation script
├── uninstall.sh            # Uninstallation script
├── update.py               # Smart update script with dependency management
├── dashboard.py            # Real-time module status dashboard
├── requirements.txt        # Python dependencies (tiered)
├── README.md               # This file
├── INSTALL.md              # Installation guide
├── CONTRIBUTING.md         # Contributor guide
├── MODULE_HELP_GUIDE.md    # Help documentation guide
├── MODULE_DEVELOPMENT.md   # Module development guide
├── CONTRIBUTOR-REQUIREMENTS-GUIDE.md  # Dependency management guide
└── tools/                  # Module repository
    ├── scanning/
    │   └── portscan/       # Elite Scanner v3.0
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
- **Always include help section in module.json** with parameter validation specs
- Use optional dependencies intelligently (detect and fallback)
- Follow the patterns in [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md)
- See [MODULE_HELP_GUIDE.md](MODULE_HELP_GUIDE.md) for help documentation
- See [CONTRIBUTOR-REQUIREMENTS-GUIDE.md](CONTRIBUTOR-REQUIREMENTS-GUIDE.md) for dependency management
- Test across all installation tiers before submitting

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

**Quick Links:**
- [Contribution Guidelines](CONTRIBUTING.md)
- [Module Development Guide](MODULE_DEVELOPMENT.md)
- [Module Help Guide](MODULE_HELP_GUIDE.md)
- [Dependency Management Guide](CONTRIBUTOR-REQUIREMENTS-GUIDE.md)
- [Installation Guide](INSTALL.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

---

## Enhanced UI Features

SecV v2.3 includes visual improvements for better user experience:

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
- Formatted tables for complex data
- CVE highlighting
- Technology stack display

---

## Dashboard System (Optional)

SecV v2.3 includes an optional real-time dashboard for monitoring module execution:

```bash
# View full dashboard
secV > show dashboard
secV > dashboard

# Shows:
# - Active running modules with runtime
# - Recently completed modules
# - Recent failures with duration
# - Real-time statistics
```

**Dashboard Features:**
- Real-time module execution tracking
- Success/failure statistics
- Duration measurements
- Active module list
- Completion history

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

**Current Version: v2.3.0**

**Completed:**
- ✓ Metasploit-style interactive shell
- ✓ Module loading and management system
- ✓ Multi-tier installation system
- ✓ Enhanced module help system
- ✓ Advanced port scanner with multiple engines (v3.0)
- ✓ Rich terminal output and formatting
- ✓ Smart update management with dependency handling
- ✓ Cross-platform support (Linux, macOS, Windows)
- ✓ Graceful dependency handling
- ✓ Comprehensive documentation
- ✓ **Parameter validation system (v2.3)**
- ✓ **Capability detection (v2.3)**
- ✓ **Rich output formatting (v2.3)**
- ✓ **Enhanced error messages (v2.3)**

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
- Module marketplace/repository

**Module Development:**
- More scanning modules (vulnerability scanners)
- Exploitation modules (SQLmap wrapper, web exploits)
- Reconnaissance modules (OSINT tools, subdomain enumeration)
- Post-exploitation modules (privilege escalation, persistence)

**Community Contributions Welcome!**

---

## Version History

- **2.3.0** - Enhanced module handling with validation, capability detection, and rich output formatting
- **2.2.0** - Smart update system, dashboard, enhanced UI
- **2.1.0** - Enhanced module help system, improved scanner
- **2.0.0** - Multi-tier installation, graceful dependency handling
- **1.0.0** - Initial release with basic scanning

---

<div align="center">

**Made with ❤️ by ethical hackers, for ethical hackers**

[Report Bug](https://github.com/SecVulnHub/SecV/issues) • [Request Feature](https://github.com/SecVulnHub/SecV/issues) • [Documentation](https://github.com/SecVulnHub/SecV/wiki)

</div>
