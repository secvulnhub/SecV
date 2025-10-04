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

```bash
# Clone the repository
git clone https://github.com/SecVulnHub/SecV.git
cd SecV

# Run the installer
chmod +x install.sh secV
./install.sh

# Start SecV
./secV              # Local execution
# OR
secV                # If installed system-wide
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

### Basic Usage

```bash
# Start the interactive shell
secV

# Inside SecV shell
secV > show modules              # List all available modules
secV > show categories           # List module categories
secV > search network            # Search for modules
secV > use spoof                 # Load a module
secV (spoof) > show options      # View module parameters
secV (spoof) > set interface eth0
secV (spoof) > set new_mac random
secV (spoof) > run 192.168.1.1   # Execute the module
secV (spoof) > back              # Unload module
secV > exit                      # Quit SecV
```

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

- **Network** - Network manipulation, spoofing, routing
- **Scanning** - Port scanning, service enumeration, discovery
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

- **Python**: 3.8 or later
- **pip**: Python package installer
- **OS**: Linux, macOS, or Windows (WSL)

**Python Dependencies:**
- `cmd2` - Advanced command-line interface framework
- `rich` - Beautiful terminal formatting and output

---

## Contributing

We welcome contributions from the security community! Whether you're adding new modules, improving the core platform, or fixing bugs - your help makes SecV better.

**Ways to Contribute:**
1. Add new security modules
2. Improve existing modules
3. Fix bugs or improve documentation
4. Suggest new features

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

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

**Upcoming Features:**
- Workflow orchestration for multi-stage attacks
- Module dependency resolution
- Remote module repositories
- Built-in report generation
- Result caching and history
- Advanced tab completion
- Plugin system for extensions

---

<div align="center">

**Made with ❤️ by ethical hackers, for ethical hackers**

[Report Bug](https://github.com/SecVulnHub/SecV/issues) • [Request Feature](https://github.com/SecVulnHub/SecV/issues) • [Documentation](https://github.com/SecVulnHub/SecV/wiki)

</div>
