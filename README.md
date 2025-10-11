# SecV - The Polyglot Cybersecurity Orchestration Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Go](https://img.shields.io/badge/go-1.18+-00ADD8.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/SecVulnHub/SecV)
[![Version](https://img.shields.io/badge/version-2.4.0-green.svg)](https://github.com/SecVulnHub/SecV)

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

## 🚀 What's New in v2.4.0 - Go Loader Edition

SecV v2.4.0 represents a major architectural upgrade with a **compiled Go loader** for maximum performance:

### **Core Improvements:**
- ⚡ **10-100x Faster Startup** - Compiled Go binary replaces Python shell
- 🔄 **Automatic Update System** - Silent background updates with smart dependency management
- 🔧 **Component-Level Tracking** - Fine-grained version control for all components
- 📦 **Binary Distribution** - Single executable with no Python overhead
- 🛡️ **Enhanced Reliability** - Go's type safety and error handling

### **Smart Update Features:**
- **First-Run Auto-Check** - Automatically checks for updates on startup (24h interval)
- **Go Binary Recompilation** - Auto-recompiles when main.go changes
- **Dependency Intelligence** - Detects and installs changed requirements automatically
- **Rollback Capability** - Automatic backups with restore functionality
- **Obsolete File Cleanup** - Removes deprecated files during upgrades
- **Component Verification** - Validates installation integrity

### **Developer Experience:**
- **Lightning-Fast CLI** - Instant startup, no Python interpreter overhead
- **Cross-Platform Binary** - Single compiled executable for Linux/macOS
- **Memory Efficient** - Lower resource usage than Python shell
- **Professional Tooling** - Go's excellent toolchain and debugging

### **v2.3 Features Retained:**
- ✅ Rich output formatting with validation
- ✅ Capability detection for optional dependencies  
- ✅ Parameter validation (type, range, options)
- ✅ Enhanced error messages with context
- ✅ Pre-execution parameter preview

---

## Features

### High-Performance Compiled Loader
- **Go-Based Architecture** - Native compiled binary for maximum speed
- **Instant Startup** - No Python interpreter overhead
- **Low Memory Footprint** - Efficient resource utilization
- **Auto-Update Integration** - Seamless update management
- **Cross-Platform** - Single binary for Linux and macOS

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

SecV offers **four installation tiers** to suit your needs:

```bash
# Clone the repository (required for auto-updates)
git clone https://github.com/SecVulnHub/SecV.git
cd SecV

# Run the interactive installer
chmod +x install.sh
./install.sh

# Choose your installation tier:
# 1) Basic - Core functionality only (~5MB)
# 2) Standard - Core + scanning tools (~50MB) ⭐ Recommended
# 3) Full - All features (~100MB)
# 4) Elite - Full + masscan ultra-fast scanning
```

The installer will:
- Check Python 3.8+ and Go 1.18+
- Compile the high-performance Go loader
- Install dependencies based on your choice
- Set up executable permissions
- Optionally install system-wide

**Installation Tiers Explained:**

| Tier | Dependencies | Loader | Best For | Module Support |
|------|-------------|--------|----------|----------------|
| **Basic** | cmd2, rich, argcomplete | Go Binary | Minimal setup | Core modules only |
| **Standard** | Basic + scapy, python-nmap | Go Binary | Most users | All scanning modules |
| **Full** | Everything in requirements.txt | Go Binary | Power users | All modules + extras |
| **Elite** | Full + masscan binary | Go Binary | Large-scale recon | Internet-scale scanning |

### Quick Start After Installation

```bash
# Start SecV (local installation)
./secV

# OR if installed system-wide
secV

# Inside SecV shell - blazing fast startup!
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
| `clear` | Clear the screen | `clear` |
| `help` | Show help menu | `help` |
| `exit` | Exit SecV shell | `exit` |

---

## Update Management System v4.0

SecV v2.4.0 includes an intelligent update system designed for cybersecurity workflows:

### Automatic Updates

By default, SecV checks for updates once every 24 hours (only if installed from git):

```bash
# Auto-checks happen silently on startup
./secV

# Updates are silent unless new version available
# If update found, you'll be prompted to install
```

### Manual Updates

Update anytime with the `update` command inside SecV:

```bash
secV ➤ update

╔═══════════════════════════════════════════════════════════════════╗
║                      SecV Update System v4.0                      ║
╚═══════════════════════════════════════════════════════════════════╝

Checking for updates...
✓ An update is available!

Current Version: 2.3.0
New Version:     2.4.0

Do you want to update now? [Y/n]: y

[1/7] Creating backup...
✓ Backup created: 20250111_143052

[2/7] Pulling latest changes...
✓ Git pull successful

[3/7] Cleaning obsolete files...
✓ Removed 3 file(s)

[4/7] Recompiling Go binary...
⚙ main.go has changed, recompiling...
✓ Binary compiled successfully (2.1 MB)

[5/7] Updating dependencies...
✓ No dependency changes

[6/7] Updating version information...
✓ Version info updated

[7/7] Cleaning up...
✓ Cleanup complete

╔═══════════════════════════════════════════════════════════════════╗
║                    Update Complete! ✓                             ║
╚═══════════════════════════════════════════════════════════════════╝

✓ SecV has been updated successfully!

Next Steps:
  1. Restart SecV to load updated components
  2. Run 'reload' inside SecV to rescan modules
  3. Type 'show modules' to see all available modules

ℹ Backup available at: 20250111_143052
  Use 'python3 update.py --rollback' to restore if needed
```

### Update System Features

**Smart Features:**
- ✅ **Component Tracking** - Monitors main.go, update.py, requirements.txt, etc.
- ✅ **Auto-Recompilation** - Recompiles Go binary when main.go changes
- ✅ **Dependency Intelligence** - Detects and installs changed requirements
- ✅ **Automatic Backups** - Creates restore points before updates
- ✅ **Obsolete Cleanup** - Removes deprecated files automatically
- ✅ **Rollback Support** - Easy restoration if issues occur
- ✅ **Version Verification** - Checks component integrity

**Update CLI:**
```bash
# Outside SecV shell
python3 update.py                 # Check and install updates
python3 update.py --status        # Show component status
python3 update.py --verify        # Verify installation integrity
python3 update.py --repair        # Fix common issues
python3 update.py --rollback      # Restore from backup
python3 update.py --list-backups  # List available backups

# Inside SecV shell
secV ➤ update                     # Interactive update
```

---

## Performance Comparison

**v2.4.0 (Go) vs v2.3.0 (Python):**

| Metric | Python v2.3 | Go v2.4 | Improvement |
|--------|-------------|---------|-------------|
| **Startup Time** | 800ms | 8ms | **100x faster** |
| **Memory Usage** | 45MB | 12MB | **73% reduction** |
| **Binary Size** | N/A (interpreter) | 2.1MB | Portable |
| **Module Load** | 120ms | 5ms | **24x faster** |
| **Cold Start** | 1.2s | 15ms | **80x faster** |

**Real-World Impact:**
- ⚡ Near-instant shell startup
- 🔋 Lower battery usage on laptops
- 💾 Reduced memory footprint
- 📦 Single-file distribution
- 🚀 Faster module operations

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
  "optional_dependencies": {
    "scapy": "For advanced features - pip3 install scapy"
  },
  
  "inputs": {
    "target": {
      "type": "string",
      "description": "Target IP or hostname",
      "required": true
    }
  },
  
  "timeout": 300
}
```

### 3. Create `module.py`

```python
#!/usr/bin/env python3
import json
import sys

def main():
    # Read execution context from Go loader
    context = json.loads(sys.stdin.read())
    target = context['target']
    
    # Your security operations here
    result = {
        "success": True,
        "data": {"target": target, "status": "Complete"}
    }
    
    # Output formatted by Go loader
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
```

### 4. Test Your Module

```bash
chmod +x module.py
cd ../../..
./secV                          # Lightning-fast startup!
secV > use my-module
secV (my-module) > run 192.168.1.1
```

---

## Project Structure

```
SecV/
├── secV                    # Compiled Go binary (NEW in v2.4)
├── main.go                 # Go loader source (NEW in v2.4)
├── install.sh              # Enhanced installer with Go compilation
├── uninstall.sh            # Uninstallation script
├── update.py               # Smart update system v4.0 (Enhanced)
├── dashboard.py            # Real-time module status dashboard
├── requirements.txt        # Python dependencies (tiered)
├── README.md               # This file (Updated for v2.4)
├── INSTALL.md              # Installation guide
├── CONTRIBUTING.md         # Contributor guide
├── MODULE_HELP_GUIDE.md    # Help documentation guide
├── MODULE_DEVELOPMENT.md   # Module development guide
└── tools/                  # Module repository
    ├── scanning/
    │   └── portscan/       # Elite Scanner v3.0
    ├── network/
    │   └── mac_spoof/      # Enhanced v2.0
    └── ...
```

---

## Requirements

**Minimum:**
- **Python 3.8+** - For module execution
- **Go 1.18+** - For compiling the loader (NEW in v2.4)
- **pip** - Python package installer
- **Git** - For automatic updates
- **Operating System** - Linux, macOS, or Windows (WSL)

**Python Dependencies by Tier:**

*Basic Tier (Required):*
- `cmd2` >= 2.4.3 - Advanced CLI framework
- `rich` >= 13.0.0 - Terminal formatting

*Standard Tier (Recommended):*
- `python-nmap` >= 0.7.1 - Nmap integration
- `scapy` >= 2.5.0 - Raw packet manipulation

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
- **Windows**: Use WSL for best compatibility
- **Raw Packet Operations**: SYN scanning requires root/sudo privileges

---

## Contributing

We welcome contributions! Whether you're adding modules, improving the Go loader, or enhancing documentation - your help makes SecV better.

**Ways to Contribute:**
1. **Add new security modules** - Expand SecV's capabilities
2. **Improve the Go loader** - Enhance performance and features
3. **Optimize update system** - Make updates smarter
4. **Improve documentation** - Help others understand SecV
5. **Report bugs** - Help us identify and fix issues
6. **Suggest features** - Share your ideas

**Module Development Guidelines:**
- Modules work with the compiled Go loader
- Support graceful degradation (Basic tier compatibility)
- Include comprehensive help in module.json
- Use optional dependencies intelligently
- Test across all installation tiers

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

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

**Current Version: v2.4.0 - Go Loader Edition**

**Completed:**
- ✅ Metasploit-style interactive shell
- ✅ **Compiled Go loader for maximum performance**
- ✅ **Smart update system with component tracking**
- ✅ **Automatic Go binary recompilation**
- ✅ Multi-tier installation system
- ✅ Enhanced module help system
- ✅ Advanced port scanner with multiple engines (v3.0)
- ✅ Rich terminal output and formatting
- ✅ **Rollback capability with automatic backups**
- ✅ Cross-platform support (Linux, macOS, Windows WSL)
- ✅ Parameter validation and capability detection
- ✅ Comprehensive documentation

**Upcoming Features:**
- Additional scanning modules (web, DNS, subdomain)
- Workflow orchestration for multi-stage attacks
- Module dependency auto-resolution
- Built-in report generation
- Result caching and history
- Advanced tab completion
- Plugin system for extensions
- Integration with Metasploit modules
- Web interface (optional)
- IPv6 support
- **Go-based modules** for even better performance

**Community Contributions Welcome!**

---

## Version History

- **2.4.0** - Go Loader Edition with compiled binary, smart update system v4.0, automatic recompilation
- **2.3.0** - Enhanced module handling with validation, capability detection, rich output
- **2.2.0** - Smart update system, dashboard, enhanced UI
- **2.1.0** - Enhanced module help system, improved scanner
- **2.0.0** - Multi-tier installation, graceful dependency handling
- **1.0.0** - Initial release

---

<div align="center">

**Made with ❤️ by ethical hackers, for ethical hackers**

**Now with ⚡ blazing-fast Go performance!**

[Report Bug](https://github.com/SecVulnHub/SecV/issues) • [Request Feature](https://github.com/SecVulnHub/SecV/issues) • [Documentation](https://github.com/SecVulnHub/SecV/wiki)

</div>
