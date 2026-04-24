# SecV Module Help Documentation Guide

## For Contributors & Maintainers

This guide explains how to add comprehensive help documentation to your SecV modules, making them easier to use and maintain.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Help System Architecture](#help-system-architecture)
3. [Enhanced module.json Format](#enhanced-modulejson-format)
4. [Built-in Help Implementation](#built-in-help-implementation)
5. [Best Practices](#best-practices)
6. [Examples](#examples)

---

## Quick Start

### Accessing Module Help

```bash
# General help
secV > help

# Help for current module
secV (portscan) > help module

# Help for specific module (without loading)
secV > info portscan
secV > help module portscan
```

### Adding Help to Your Module

**Option 1: Enhanced module.json (Recommended)**

Add a `help` section to your `module.json`:

```json
{
  "name": "mymodule",
  "version": "1.0.0",
  "help": {
    "description": "Detailed description here",
    "parameters": { ... },
    "examples": [ ... ],
    "features": [ ... ]
  }
}
```

**Option 2: Built-in Help Command**

Make your executable respond to `--help`, `-h`, or `help`:

```python
#!/usr/bin/env python3
import sys

if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
    print("Module Help Text Here")
    sys.exit(0)
```

---

## Help System Architecture

### Help Display Priority

1. **Built-in help** - Module executable's `--help` output (if available)
2. **Enhanced JSON** - `help` section in module.json
3. **Basic JSON** - Auto-generated from `inputs`/`outputs`
4. **README.md** - Link shown if available

### Command Flow

```
User: help module portscan
  ↓
SecV: Find module path
  ↓
SecV: Try executable --help
  ↓ (if fails)
SecV: Parse module.json help section
  ↓ (if missing)
SecV: Generate basic help from inputs/outputs
  ↓
Display formatted help
```

---

## Enhanced module.json Format

### Complete Structure

```json
{
  "name": "module-name",
  "version": "1.0.0",
  "category": "scanning",
  "description": "One-line description",
  "author": "Your Name",
  "executable": "python3 module.py",
  
  "dependencies": ["python3"],
  
  "optional_dependencies": {
    "library-name": "Description and install command"
  },
  
  "help": {
    "description": "Detailed multi-line description",
    
    "parameters": {
      "param1": {
        "description": "What this parameter does",
        "examples": ["value1", "value2"],
        "options": ["opt1", "opt2"],
        "default": "default_value",
        "type": "string",
        "range": "1-100"
      }
    },
    
    "examples": [
      {
        "description": "Example use case",
        "commands": [
          "use module-name",
          "set param1 value",
          "run target.com"
        ]
      }
    ],
    
    "features": [
      "Feature 1",
      "Feature 2"
    ],
    
    "installation_tiers": {
      "basic": "What works at basic level",
      "standard": "What standard adds",
      "full": "What full installation provides"
    },
    
    "notes": [
      "Important note 1",
      "Important note 2"
    ]
  },
  
  "inputs": {
    "param1": {
      "type": "string",
      "description": "Parameter description",
      "required": true,
      "default": "value"
    }
  },
  
  "outputs": {
    "result_field": {
      "type": "string",
      "description": "What this output contains"
    }
  },
  
  "timeout": 300,
  "concurrent": false
}
```

### Field Descriptions

#### help.description
Extended description of what your module does, how it works, and when to use it.

#### help.parameters
Detailed parameter documentation with:
- `description` - What the parameter does
- `examples` - Example values
- `options` - Valid options (for enums)
- `default` - Default value
- `type` - Data type
- `range` - Valid range (for numbers)

#### help.examples
Array of usage examples showing:
- `description` - What the example demonstrates
- `commands` - Array of SecV commands to execute

#### help.features
Array of bullet points highlighting key features.

#### help.installation_tiers
Explains what works at each installation level:
- `basic` - Core only (stdlib)
- `standard` - + common tools
- `full` - All features

#### help.notes
Important warnings, tips, or caveats about using the module.

---

## Built-in Help Implementation

### Python Module with Help

```python
#!/usr/bin/env python3
"""
Module Name - Short Description
Author: Your Name
Version: 1.0.0
"""

import json
import sys

def show_help():
    """Display comprehensive help"""
    help_text = """
╔═══════════════════════════════════════════════════════════════════╗
║                    Module Name Help                               ║
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  Detailed description of what your module does.

USAGE:
  secV > use module-name
  secV (module-name) > set parameter value
  secV (module-name) > run target

PARAMETERS:
  parameter1    Description of parameter 1
                Options: opt1, opt2, opt3
                Default: opt1
  
  parameter2    Description of parameter 2
                Type: integer
                Range: 1-1000

EXAMPLES:
  1. Basic usage:
     secV > use module-name
     secV (module-name) > run example.com
  
  2. Advanced usage:
     secV (module-name) > set parameter1 opt2
     secV (module-name) > set parameter2 100
     secV (module-name) > run target.local

FEATURES:
  • Feature 1
  • Feature 2
  • Feature 3

REQUIREMENTS:
  Basic: Works with stdlib only
  Full: pip3 install optional-lib

NOTES:
  • Important note about usage
  • Limitation or warning

AUTHOR: Your Name
VERSION: 1.0.0
"""
    print(help_text)

def main():
    # Check for help flag
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        show_help()
        sys.exit(0)
    
    # Normal module execution
    try:
        context = json.loads(sys.stdin.read())
        # ... your module logic ...
        
    except Exception as e:
        result = {
            'success': False,
            'errors': [str(e)]
        }
        print(json.dumps(result))

if __name__ == '__main__':
    main()
```

### Bash Module with Help

```bash
#!/bin/bash
# Module Name - Description
# Author: Your Name

show_help() {
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════╗
║                    Module Name Help                               ║
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  What your module does

USAGE:
  secV > use module-name
  secV (module-name) > run target

PARAMETERS:
  param1    Description
  param2    Description

EXAMPLES:
  secV > use module-name
  secV (module-name) > set param1 value
  secV (module-name) > run target.com
EOF
}

# Check for help flag
if [[ "$1" == "--help" || "$1" == "-h" || "$1" == "help" ]]; then
    show_help
    exit 0
fi

# Read JSON input and execute
INPUT=$(cat)
# ... module logic ...
```

---

## Best Practices

### DO

**1. Provide Clear Examples**
```json
"examples": [
  {
    "description": "Scan top 100 ports quickly",
    "commands": [
      "use portscan",
      "set ports top-100",
      "set timeout 0.5",
      "run target.com"
    ]
  }
]
```

**2. Document All Parameters**
```json
"parameters": {
  "ports": {
    "description": "Port specification",
    "examples": ["top-20", "1-1000", "80,443,8080"],
    "default": "top-20"
  }
}
```

**3. Explain Installation Tiers**
```json
"installation_tiers": {
  "basic": "TCP connect scan (stdlib only)",
  "standard": "+ SYN scan (pip3 install scapy)",
  "full": "+ HTTP detection (pip3 install requests)"
}
```

**4. Add Important Notes**
```json
"notes": [
  "SYN scanning requires root privileges",
  "Use lower timeout for faster scans of live hosts",
  "Combine with vuln-scan for complete assessment"
]
```

**5. List Features**
```json
"features": [
  "Multiple scan engines (connect, SYN, nmap)",
  "Service detection and banner grabbing",
  "Concurrent scanning up to 50 threads",
  "Pre-defined port sets for common tasks"
]
```

### DON'T

**1. Don't Skip Parameter Descriptions**
```json
// BAD
"parameters": {
  "ports": {}
}

// GOOD
"parameters": {
  "ports": {
    "description": "Port specification - presets, ranges, or lists",
    "examples": ["top-20", "1-1000", "80,443"]
  }
}
```

**2. Don't Forget Optional Dependencies**
```json
// BAD
"dependencies": ["python3", "scapy", "nmap"]

// GOOD
"dependencies": ["python3"],
"optional_dependencies": {
  "scapy": "For SYN scanning - pip3 install scapy",
  "nmap": "For nmap engine - pip3 install python-nmap"
}
```

**3. Don't Use Jargon Without Explanation**
```json
// BAD
"description": "Performs SYN stealth scan"

// GOOD
"description": "Performs SYN stealth scan (half-open TCP scan that doesn't complete handshake)"
```

**4. Don't Provide Examples Without Context**
```json
// BAD
"examples": ["use portscan", "run target"]

// GOOD
"examples": [
  {
    "description": "Quick scan of common ports",
    "commands": ["use portscan", "set ports common", "run target"]
  }
]
```

---

## Examples

### Example 1: Simple Scanner Module

```json
{
  "name": "ping-sweep",
  "version": "1.0.0",
  "category": "scanning",
  "description": "Fast ICMP ping sweep to discover live hosts",
  "author": "SecVulnHub",
  "executable": "python3 ping_sweep.py",
  
  "help": {
    "description": "Quickly discovers live hosts on a network using ICMP echo requests (ping). Supports CIDR notation and multiple threading.",
    
    "parameters": {
      "threads": {
        "description": "Number of concurrent ping threads",
        "type": "integer",
        "default": 50,
        "range": "1-200"
      },
      "timeout": {
        "description": "Timeout per host in seconds",
        "type": "float",
        "default": 1.0,
        "range": "0.1-5.0"
      }
    },
    
    "examples": [
      {
        "description": "Scan a /24 network",
        "commands": [
          "use ping-sweep",
          "run 192.168.1.0/24"
        ]
      },
      {
        "description": "Fast scan with more threads",
        "commands": [
          "use ping-sweep",
          "set threads 100",
          "set timeout 0.5",
          "run 10.0.0.0/16"
        ]
      }
    ],
    
    "features": [
      "CIDR notation support",
      "Multi-threaded scanning",
      "Live host discovery",
      "Response time measurement"
    ],
    
    "notes": [
      "Some hosts may block ICMP",
      "Requires raw socket access (may need sudo)",
      "Use smaller subnets for faster results"
    ]
  },
  
  "inputs": {
    "threads": {
      "type": "number",
      "description": "Concurrent threads",
      "default": 50
    },
    "timeout": {
      "type": "number",
      "description": "Timeout per host",
      "default": 1.0
    }
  },
  
  "outputs": {
    "live_hosts": {
      "type": "array",
      "description": "List of responding hosts"
    },
    "scan_time": {
      "type": "number",
      "description": "Total scan duration"
    }
  }
}
```

### Example 2: Web Scanner Module

```json
{
  "name": "web-enum",
  "version": "1.0.0",
  "category": "web",
  "description": "Web application enumeration and technology detection",
  "author": "SecVulnHub",
  "executable": "python3 web_enum.py",
  
  "optional_dependencies": {
    "requests": "For HTTP operations - pip3 install requests",
    "beautifulsoup4": "For HTML parsing - pip3 install beautifulsoup4"
  },
  
  "help": {
    "description": "Comprehensive web application enumeration including technology detection, header analysis, and common file discovery.",
    
    "parameters": {
      "mode": {
        "description": "Scan mode",
        "options": ["quick", "standard", "deep"],
        "default": "standard",
        "examples": [
          "quick - Headers and tech detection only",
          "standard - + Common files",
          "deep - + Full directory bruteforce"
        ]
      },
      "wordlist": {
        "description": "Custom wordlist for directory bruteforce",
        "type": "string",
        "default": "built-in",
        "examples": ["/path/to/wordlist.txt", "built-in"]
      },
      "threads": {
        "description": "Concurrent requests",
        "type": "integer",
        "default": 10,
        "range": "1-50"
      }
    },
    
    "examples": [
      {
        "description": "Quick technology detection",
        "commands": [
          "use web-enum",
          "set mode quick",
          "run https://example.com"
        ]
      },
      {
        "description": "Standard enumeration",
        "commands": [
          "use web-enum",
          "run https://target.com"
        ]
      },
      {
        "description": "Deep scan with custom wordlist",
        "commands": [
          "use web-enum",
          "set mode deep",
          "set wordlist /usr/share/wordlists/dirb/common.txt",
          "set threads 20",
          "run https://target.com"
        ]
      }
    ],
    
    "features": [
      "Technology fingerprinting (WordPress, Joomla, frameworks)",
      "HTTP header analysis",
      "Common file discovery (robots.txt, sitemap.xml)",
      "Directory bruteforcing",
      "SSL/TLS certificate analysis",
      "Response code analysis"
    ],
    
    "installation_tiers": {
      "basic": "Basic enumeration with urllib (stdlib)",
      "standard": "+ Technology detection (pip3 install requests)",
      "full": "+ HTML parsing (pip3 install beautifulsoup4)"
    },
    
    "notes": [
      "Respect robots.txt in production environments",
      "Use lower thread counts to avoid detection",
      "Deep mode can take considerable time",
      "Always get authorization before scanning"
    ]
  },
  
  "timeout": 600
}
```

### Example 3: Post-Exploitation Module

```json
{
  "name": "priv-esc-check",
  "version": "1.0.0",
  "category": "post-exploitation",
  "description": "Linux privilege escalation vector checker",
  "author": "SecVulnHub",
  "executable": "bash priv_esc.sh",
  
  "help": {
    "description": "Automated checking for common Linux privilege escalation vectors including SUID binaries, writable files, kernel exploits, and misconfigurations.",
    
    "parameters": {
      "checks": {
        "description": "Which checks to run",
        "options": ["all", "suid", "writable", "kernel", "cron", "services"],
        "default": "all",
        "examples": [
          "all - Run all checks",
          "suid - SUID binaries only",
          "writable - Writable files/directories"
        ]
      },
      "output_format": {
        "description": "Output format",
        "options": ["text", "json", "html"],
        "default": "text"
      }
    },
    
    "examples": [
      {
        "description": "Full privilege escalation check",
        "commands": [
          "use priv-esc-check",
          "run localhost"
        ]
      },
      {
        "description": "Check only SUID binaries",
        "commands": [
          "use priv-esc-check",
          "set checks suid",
          "run localhost"
        ]
      },
      {
        "description": "Generate HTML report",
        "commands": [
          "use priv-esc-check",
          "set output_format html",
          "run localhost"
        ]
      }
    ],
    
    "features": [
      "SUID/SGID binary enumeration",
      "Writable file discovery",
      "Kernel exploit checking",
      "Cron job analysis",
      "Service misconfiguration detection",
      "Environment variable inspection",
      "Password file analysis"
    ],
    
    "notes": [
      "Must be run on target system",
      "Some checks require elevated privileges",
      "Review output carefully for false positives",
      "Combine with manual enumeration"
    ]
  }
}
```

---

## Testing Your Help Documentation

### Checklist

- [ ] Help displays correctly with `help module`
- [ ] Help displays for unloaded module with `info <module>`
- [ ] All parameters are documented
- [ ] At least 2-3 examples provided
- [ ] Features list is complete
- [ ] Optional dependencies clearly marked
- [ ] Installation tiers explained (if applicable)
- [ ] Important notes included
- [ ] Formatting is clean and readable
- [ ] No typos or grammar errors

### Test Commands

```bash
# Test help display
secV > info your-module
secV > use your-module
secV (your-module) > help module

# Verify JSON syntax
jq empty module.json

# Test built-in help (if implemented)
python3 your_module.py --help
```

---

## Maintenance Guidelines

### When to Update Help

1. **Parameter Changes** - Update parameter documentation
2. **New Features** - Add to features list and examples
3. **Dependency Changes** - Update optional_dependencies
4. **Bug Fixes** - Update notes if behavior changes
5. **Breaking Changes** - Add migration examples

### Version Your Help

When making significant changes, bump the version:

```json
{
  "version": "2.0.0",
  "help": {
    "changelog": {
      "2.0.0": "Added SYN scan engine, rewrote scanner core",
      "1.5.0": "Added HTTP technology detection",
      "1.0.0": "Initial release"
    }
  }
}
```

---

## Summary

Good module help documentation:

1. **Is Discoverable** - Users can find it easily
2. **Is Complete** - Covers all parameters and features
3. **Provides Examples** - Shows real usage patterns
4. **Explains Dependencies** - Clear about requirements
5. **Warns Appropriately** - Notes limitations and caveats
6. **Is Maintainable** - Easy to update as module evolves

By following this guide, you'll create modules that are both powerful and easy to use!

---

**Questions? Issues?**
- Open a GitHub Discussion
- Check existing module examples
- Refer to CONTRIBUTING.md

**Happy Module Building!**
