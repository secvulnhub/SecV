# Contributing to SecV

Welcome to the SecV contributor guide! Whether you're adding a single module or maintaining the entire platform, this guide will help you understand how to contribute effectively.

## Table of Contents

- [Getting Started](#getting-started)
- [Module Development Guide](#module-development-guide)
- [Module Structure](#module-structure)
- [Programming Language Support](#programming-language-support)
- [Testing Your Module](#testing-your-module)
- [Submission Guidelines](#submission-guidelines)
- [Platform Development](#platform-development)
- [Code of Conduct](#code-of-conduct)

---

## Getting Started

### Prerequisites

Before you start contributing:

1. Fork the SecV repository
2. Clone your fork locally
3. Install SecV following [INSTALL.md](INSTALL.md)
4. Create a branch for your contribution

```bash
git clone https://github.com/YOUR_USERNAME/SecV.git
cd SecV
git checkout -b feature/my-awesome-module
```

### Understanding SecV Architecture

SecV consists of three main components:

1. **Module Loader** - Discovers and loads modules from the `tools/` directory
2. **Execution Engine** - Executes modules with proper context and timeout handling
3. **Interactive Shell** - Metasploit-style interface for user interaction

Modules are self-contained units that communicate via JSON over stdin/stdout.

---

## Module Development Guide

### Quick Start: Create Your First Module

Let's create a simple port checker module:

```bash
# 1. Create module directory
mkdir -p tools/scanning/port-checker
cd tools/scanning/port-checker

# 2. Create module.json
cat > module.json << 'EOF'
{
  "name": "port-checker",
  "version": "1.0.0",
  "category": "scanning",
  "description": "Check if a specific port is open on target",
  "author": "YourName",
  "executable": "python3 checker.py",
  "dependencies": [],
  "inputs": {
    "port": {
      "type": "number",
      "description": "Port number to check",
      "required": true
    }
  },
  "outputs": {
    "open": {
      "type": "boolean",
      "description": "Whether the port is open"
    }
  },
  "timeout": 30,
  "concurrent": true
}
EOF

# 3. Create checker.py
cat > checker.py << 'EOF'
#!/usr/bin/env python3
import json
import sys
import socket

# Read execution context from stdin
context = json.loads(sys.stdin.read())
target = context['target']
port = context['params'].get('port', 80)

# Perform port check
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result_code = sock.connect_ex((target, int(port)))
    sock.close()
    
    is_open = (result_code == 0)
    
    result = {
        "success": True,
        "data": {
            "target": target,
            "port": port,
            "open": is_open,
            "status": f"Port {port} is {'open' if is_open else 'closed'}"
        },
        "errors": []
    }
except Exception as e:
    result = {
        "success": False,
        "data": None,
        "errors": [str(e)]
    }

# Output result as JSON
print(json.dumps(result))
EOF

# 4. Make executable
chmod +x checker.py

# 5. Test it
cd ../../..
./secV
secV > use port-checker
secV (port-checker) > set port 80
secV (port-checker) > run example.com
```

---

## Module Structure

### Directory Layout

Every module must follow this structure:

```
tools/
└── <category>/
    └── <module-name>/
        ├── module.json          # Required: Module metadata
        ├── <executable>         # Required: Your tool/script
        ├── README.md            # Recommended: Module documentation
        └── test.sh              # Optional: Test script
```

### module.json Specification

The `module.json` file defines your module's interface:

```json
{
  "name": "module-name",
  "version": "1.0.0",
  "category": "category-name",
  "description": "Brief description of what this module does",
  "author": "Your Name or Organization",
  
  "executable": "python3 script.py",
  
  "executablesByOS": {
    "linux": "./script.sh",
    "darwin": "./script.sh",
    "windows": "powershell.exe -File script.ps1"
  },
  
  "dependencies": [
    "nmap",
    "python3-requests"
  ],
  
  "inputs": {
    "parameter_name": {
      "type": "string|number|boolean|array|object",
      "description": "Parameter description",
      "required": true,
      "default": "optional_default_value"
    }
  },
  
  "outputs": {
    "result_field": {
      "type": "string|number|boolean|array|object",
      "description": "What this output field contains"
    }
  },
  
  "timeout": 300,
  "concurrent": false
}
```

### Field Descriptions

**Required Fields:**

- `name` - Unique module identifier (lowercase, hyphen-separated)
- `version` - Semantic version (major.minor.patch)
- `category` - Module category (see [Categories](#module-categories))
- `description` - One-line description (max 120 characters)
- `author` - Your name or organization
- `executable` OR `executablesByOS` - How to run your module

**Optional Fields:**

- `dependencies` - Array of required system packages
- `inputs` - Expected input parameters with types and descriptions
- `outputs` - Expected output fields with types and descriptions
- `timeout` - Max execution time in seconds (default: 300)
- `concurrent` - Whether module can run concurrently (default: false)

### Module Categories

Choose the most appropriate category for your module:

| Category | Description | Examples |
|----------|-------------|----------|
| `network` | Network manipulation and analysis | MAC spoofing, routing, traffic shaping |
| `scanning` | Port scanning and service detection | Nmap wrappers, custom scanners |
| `vulnerability` | Vulnerability assessment | CVE checkers, config auditors |
| `exploitation` | Exploit frameworks and PoCs | Exploit scripts, payload generators |
| `reconnaissance` | Information gathering | OSINT tools, subdomain enumeration |
| `web` | Web application testing | Fuzzing, crawling, injection testing |
| `wireless` | Wireless network attacks | WiFi cracking, Bluetooth exploitation |
| `forensics` | Digital forensics | Memory analysis, artifact extraction |
| `post-exploitation` | Post-compromise activities | Privilege escalation, persistence |
| `reporting` | Documentation and reporting | Report generators, formatters |
| `misc` | Utilities and helpers | Encoders, converters, utilities |

---

## 📦 **SecV Installation & Dependencies**

### Installation Tiers

SecV supports three installation levels to accommodate different use cases:

```bash
./install.sh
```

**1. Basic Installation** - Core functionality only
- Dependencies: `cmd2`, `rich`
- Use case: Basic module execution, shell interface
- Size: Minimal (~5MB)

**2. Standard Installation** ⭐ Recommended
- Dependencies: Core + `python-nmap`, `scapy`
- Use case: Full scanning capabilities, most modules
- Size: ~50MB

**3. Full Installation** - All features
- Dependencies: Everything in `requirements.txt`
- Use case: All modules including web scraping, SSH, crypto
- Size: ~100MB

### Writing Dependency-Aware Modules

**IMPORTANT**: Your modules should gracefully handle missing optional dependencies!

**✅ GOOD - Graceful degradation:**
```python
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

def advanced_scan():
    if HAS_SCAPY:
        # Use scapy for advanced features
        return scapy_scan()
    else:
        # Fall back to basic method
        return basic_scan()
```

**❌ BAD - Hard requirement:**
```python
import scapy.all as scapy  # Crashes if not installed!

def scan():
    return scapy_scan()  # No fallback!
```

### Declaring Dependencies in module.json

Use the `optional_dependencies` field for libraries that enhance but aren't required:

```json
{
  "name": "mymodule",
  "dependencies": ["python3"],
  "optional_dependencies": {
    "scapy": "For advanced packet manipulation",
    "requests": "For HTTP features"
  }
}
```

### Testing Your Module Across Installation Tiers

Before submitting, test your module with different dependency configurations:

```bash
# Test with minimal dependencies
pip3 uninstall scapy python-nmap -y
./secV
secV > use mymodule
secV (mymodule) > run target

# Test with full dependencies
pip3 install -r requirements.txt
./secV
secV > use mymodule
secV (mymodule) > run target
```

Your module should:
- ✅ Work at basic level (even if with reduced features)
- ✅ Auto-detect available libraries
- ✅ Inform users about missing optional features
- ✅ Never crash due to missing optional dependencies

### Example: Multi-Tier Module Pattern

```python
#!/usr/bin/env python3

# Try importing optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

def scan_web(url):
    """Scan with best available method"""
    
    if HAS_REQUESTS and HAS_BS4:
        # Full featured scan
        return advanced_web_scan(url)
    elif HAS_REQUESTS:
        # Basic HTTP scan
        return basic_http_scan(url)
    else:
        # Fallback to urllib (stdlib)
        return urllib_scan(url)

def advanced_web_scan(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    # Extract detailed information
    return {"method": "advanced", "data": soup}

def basic_http_scan(url):
    response = requests.get(url)
    # Basic analysis
    return {"method": "basic", "data": response.text}

def urllib_scan(url):
    import urllib.request
    response = urllib.request.urlopen(url)
    # Minimal analysis
    return {"method": "fallback", "data": response.read()}
```

### Dependencies Best Practices

1. **Use stdlib when possible** - `socket`, `json`, `urllib`, etc.
2. **Make advanced features optional** - Don't require heavy libraries for basic functionality
3. **Inform users** - Tell them what they're missing:
   ```python
   if not HAS_SCAPY:
       print("Note: Install scapy for SYN scan support: pip3 install scapy")
   ```
4. **Document requirements** - List optional dependencies in module README
5. **Provide alternatives** - Offer multiple implementation paths

### Common Optional Dependencies

| Library | Use Case | Installation Tier |
|---------|----------|------------------|
| `python-nmap` | Nmap integration | Standard |
| `scapy` | Raw packets, SYN scan | Standard |
| `requests` | HTTP operations | Full |
| `beautifulsoup4` | HTML parsing | Full |
| `paramiko` | SSH operations | Full |
| `dnspython` | DNS queries | Full |
| `pycryptodome` | Cryptography | Full |

### Platform-Specific Notes

**Linux:**
- `scapy` requires: `sudo apt install libpcap-dev`
- Raw sockets need: `sudo` for SYN scanning

**macOS:**
- `scapy` works out of the box
- Raw sockets need: `sudo` for SYN scanning

**Windows:**
- `scapy` requires: Npcap driver
- Some features may have limited support

### Contribution Checklist - Dependencies

When submitting a module, ensure:

- [ ] Module works with Basic installation (core only)
- [ ] Optional dependencies are properly detected
- [ ] Fallback methods provided for missing libraries
- [ ] `module.json` lists optional dependencies
- [ ] README documents what features need which libraries
- [ ] No hard imports of optional libraries at module level
- [ ] User-friendly messages for missing optional features
- [ ] Tested on at least 2 dependency configurations

## Programming Language Support

SecV is **truly polyglot** - write modules in any language that can:
1. Read JSON from stdin
2. Write JSON to stdout
3. Be executed on the target platform

### Python Modules

**Template:**

```python
#!/usr/bin/env python3
import json
import sys

def main():
    # Read execution context
    context = json.loads(sys.stdin.read())
    target = context['target']
    params = context.get('params', {})
    
    # Your security logic here
    try:
        # Perform operations
        data = perform_security_operation(target, params)
        
        result = {
            "success": True,
            "data": data,
            "errors": []
        }
    except Exception as e:
        result = {
            "success": False,
            "data": None,
            "errors": [str(e)]
        }
    
    # Output result
    print(json.dumps(result))

if __name__ == '__main__':
    main()
```

**module.json:**
```json
{
  "executable": "python3 module.py"
}
```

### Bash Modules

**Template:**

```bash
#!/bin/bash

# Read JSON input from stdin
INPUT=$(cat)
TARGET=$(echo "$INPUT" | jq -r '.target')
PARAM=$(echo "$INPUT" | jq -r '.params.param_name // "default"')

# Your security logic here
if perform_operation "$TARGET" "$PARAM"; then
    # Success
    jq -n \
        --arg target "$TARGET" \
        --arg result "$RESULT" \
        '{
            success: true,
            data: {
                target: $target,
                result: $result
            },
            errors: []
        }'
else
    # Failure
    jq -n \
        --arg error "$ERROR_MSG" \
        '{
            success: false,
            data: null,
            errors: [$error]
        }'
fi
```

**module.json:**
```json
{
  "executable": "./module.sh",
  "dependencies": ["jq"]
}
```

### PowerShell Modules

**Template:**

```powershell
# Read JSON from stdin
$jsonInput = [Console]::In.ReadToEnd()
$context = $jsonInput | ConvertFrom-Json

$target = $context.target
$params = $context.params

try {
    # Your security logic here
    $data = Invoke-SecurityOperation -Target $target -Params $params
    
    $result = @{
        success = $true
        data = $data
        errors = @()
    } | ConvertTo-Json -Depth 10
    
    Write-Output $result
}
catch {
    $result = @{
        success = $false
        data = $null
        errors = @($_.Exception.Message)
    } | ConvertTo-Json -Depth 10
    
    Write-Output $result
}
```

**module.json:**
```json
{
  "executablesByOS": {
    "windows": "powershell.exe -ExecutionPolicy Bypass -File module.ps1"
  }
}
```

### Go Modules

**Template:**

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
)

type Context struct {
    Target string                 `json:"target"`
    Params map[string]interface{} `json:"params"`
}

type Result struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data"`
    Errors  []string    `json:"errors"`
}

func main() {
    // Read stdin
    input, _ := ioutil.ReadAll(os.Stdin)
    
    var ctx Context
    json.Unmarshal(input, &ctx)
    
    // Your security logic here
    data, err := performOperation(ctx.Target, ctx.Params)
    
    result := Result{
        Success: err == nil,
        Data:    data,
        Errors:  []string{},
    }
    
    if err != nil {
        result.Errors = append(result.Errors, err.Error())
    }
    
    // Output JSON
    output, _ := json.Marshal(result)
    fmt.Println(string(output))
}
```

**module.json:**
```json
{
  "executable": "./module"
}
```

Note: Remember to compile your Go binary before testing!

---

## Testing Your Module

### Manual Testing

```bash
# Start SecV
./secV

# Load your module
secV > use your-module

# Check options
secV (your-module) > show options

# Set parameters
secV (your-module) > set param1 value1

# Execute
secV (your-module) > run target-host
```

### Automated Testing

Create a `test.sh` script in your module directory:

```bash
#!/bin/bash

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test 1: Valid input
echo '{"target": "127.0.0.1", "params": {"port": 80}}' | \
    python3 "$MODULE_DIR/module.py" | \
    jq -e '.success == true' || exit 1

# Test 2: Error handling
echo '{"target": "invalid", "params": {}}' | \
    python3 "$MODULE_DIR/module.py" | \
    jq -e '.success == false' || exit 1

echo "All tests passed!"
```

Make it executable:
```bash
chmod +x test.sh
```

### Input/Output Contract

Your module MUST:

**Receive (stdin):**
```json
{
  "target": "192.168.1.1",
  "params": {
    "param1": "value1",
    "param2": 123
  },
  "results": {},
  "workflow_id": null,
  "step_id": null
}
```

**Return (stdout):**
```json
{
  "success": true,
  "data": {
    "key": "value"
  },
  "errors": []
}
```

**Never:**
- Print to stdout except final JSON result
- Read from external files without documenting
- Modify system state without authorization
- Include hardcoded credentials

---

## Submission Guidelines

### Before Submitting

- [ ] Module follows directory structure
- [ ] `module.json` is valid and complete
- [ ] Module accepts JSON input via stdin
- [ ] Module outputs JSON to stdout
- [ ] Error handling is implemented
- [ ] Module has been tested locally
- [ ] README.md explains usage (recommended)
- [ ] Test script included (recommended)

### Creating a Pull Request

1. **Commit your changes**
```bash
git add tools/category/your-module/
git commit -m "Add your-module for category"
```

2. **Push to your fork**
```bash
git push origin feature/your-module
```

3. **Create Pull Request**
- Go to the SecV repository
- Click "New Pull Request"
- Select your branch
- Fill in the template

### PR Description Template

```markdown
## Module: [Module Name]

### Description
Brief description of what your module does.

### Category
- [ ] Network
- [ ] Scanning
- [ ] Vulnerability
- [ ] Exploitation
- [ ] Reconnaissance
- [ ] Web
- [ ] Wireless
- [ ] Forensics
- [ ] Post-Exploitation
- [ ] Reporting
- [ ] Misc

### Testing
- [ ] Tested on Linux
- [ ] Tested on macOS
- [ ] Tested on Windows (if applicable)
- [ ] All tests pass

### Checklist
- [ ] Module.json is complete
- [ ] Follows coding standards
- [ ] Documentation included
- [ ] No hardcoded credentials
- [ ] Ethical use only
```

---

## Platform Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/SecVulnHub/SecV.git
cd SecV

# Install development dependencies
pip3 install -r requirements-dev.txt

# Install pre-commit hooks (optional)
pip3 install pre-commit
pre-commit install
```

### Core Platform Components

**secV (Main Executable)**
- Interactive shell implementation
- Command handlers
- User interface

**Module Loader**
- Module discovery
- Validation
- Metadata parsing

**Execution Engine**
- Context management
- Process execution
- Timeout handling

### Code Style

**Python:**
- Follow PEP 8
- Use type hints where appropriate
- Document functions with docstrings
- Keep functions focused and small

**Shell Scripts:**
- Use `#!/bin/bash` shebang
- Set `set -e` for error handling
- Quote variables
- Use meaningful variable names

### Adding New Features

1. Open an issue to discuss the feature
2. Wait for maintainer approval
3. Create a feature branch
4. Implement with tests
5. Submit PR with documentation

---

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the community
- Accept responsibility for mistakes

### Ethical Guidelines

- All modules must be for authorized testing only
- Include clear usage warnings
- Never include exploits for unpatched vulnerabilities
- Follow responsible disclosure

### Unacceptable Behavior

- Harassment or discrimination
- Malicious code or backdoors
- Unauthorized testing tools
- Violation of laws or regulations

---

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email security@secvulnhub.local
- **Chat**: Join our community channel

---

## Recognition

Contributors are recognized in:
- Module author field
- GitHub contributors list
- Release notes
- Project documentation

Significant contributors may be invited to become maintainers.

---

## License

By contributing to SecV, you agree that your contributions will be licensed under the MIT License.

---

## Quick Reference

### Module Checklist
```
✓ module.json present and valid
✓ Executable works on target platforms
✓ Reads JSON from stdin
✓ Outputs JSON to stdout
✓ Handles errors gracefully
✓ Documentation included
✓ Tested locally
```

### Testing Command
```bash
echo '{"target":"127.0.0.1","params":{}}' | python3 module.py | jq
```

### Validation
```bash
jq empty module.json  # Validate JSON syntax
./test.sh             # Run tests
```

---

<div align="center">

**Thank you for contributing to SecV!**

Together we're building the future of ethical hacking tools.

</div>
