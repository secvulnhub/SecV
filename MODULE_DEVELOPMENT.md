# SecV Module Development Guide
## For Contributors Building Security Modules

---

## 📚 Table of Contents

1. [Quick Start](#quick-start)
2. [Handling Dependencies](#handling-dependencies)
3. [Module Structure](#module-structure)
4. [Testing Across Environments](#testing-across-environments)
5. [Examples & Patterns](#examples--patterns)
6. [Best Practices](#best-practices)

---

## Quick Start

### Creating Your First Module

```bash
# 1. Create module directory
mkdir -p tools/category/modulename
cd tools/category/modulename

# 2. Create module.json
# 3. Create your executable (Python, Bash, etc.)
# 4. Test it
# 5. Submit PR
```

---

## Handling Dependencies

### The Golden Rule: **Never Break Basic Installation**

Your module MUST work with the Basic installation (just `cmd2` and `rich`). Advanced features can require optional dependencies, but core functionality should always work.

### Dependency Detection Pattern

**Python Example:**

```python
#!/usr/bin/env python3
"""
MyModule - Description
Author: YourName
"""

import json
import sys
import socket  # stdlib - always available

# Optional dependency detection
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    scapy = None  # Prevent NameError

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None


class MyScanner:
    def __init__(self, target, params):
        self.target = target
        self.params = params
        
        # Inform about capabilities
        self.capabilities = self._detect_capabilities()
    
    def _detect_capabilities(self):
        """Detect what features are available"""
        caps = {
            'basic': True,  # Always true
            'advanced_scan': HAS_SCAPY,
            'http_features': HAS_REQUESTS
        }
        return caps
    
    def scan(self):
        """Main scan function with fallbacks"""
        
        # Select best available method
        if HAS_SCAPY and self.params.get('use_syn', False):
            return self._syn_scan()
        elif HAS_REQUESTS:
            return self._http_scan()
        else:
            return self._basic_scan()
    
    def _syn_scan(self):
        """Advanced scan using scapy"""
        # Use scapy features
        return {"method": "syn", "data": "..."}
    
    def _http_scan(self):
        """HTTP scan using requests"""
        # Use requests library
        return {"method": "http", "data": "..."}
    
    def _basic_scan(self):
        """Basic scan using stdlib only"""
        # Use only socket, urllib, etc.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # ... basic implementation
        return {"method": "basic", "data": "..."}


def main():
    context = json.loads(sys.stdin.read())
    scanner = MyScanner(context['target'], context.get('params', {}))
    
    # Warn about missing features
    if not HAS_SCAPY:
        print("INFO: Install scapy for SYN scan support", file=sys.stderr)
    
    result = scanner.scan()
    
    output = {
        "success": True,
        "data": result,
        "errors": [],
        "capabilities": scanner.capabilities
    }
    
    print(json.dumps(output))


if __name__ == '__main__':
    main()
```

### Bash Example with Dependency Checking

```bash
#!/bin/bash
# MyModule - Bash implementation
# Author: YourName

# Check for optional tools
HAS_JQ=false
HAS_NMAP=false

if command -v jq &> /dev/null; then
    HAS_JQ=true
fi

if command -v nmap &> /dev/null; then
    HAS_NMAP=true
fi

# Read input
INPUT=$(cat)
TARGET=$(echo "$INPUT" | jq -r '.target' 2>/dev/null || echo "$INPUT")

# Select method based on available tools
if [ "$HAS_NMAP" = true ]; then
    # Use nmap for advanced scanning
    RESULT=$(nmap -sV "$TARGET" -oX -)
    METHOD="nmap"
elif [ "$HAS_JQ" = true ]; then
    # Use jq for JSON processing
    # ... implementation with jq
    METHOD="jq"
else
    # Basic implementation without dependencies
    # Use only built-in bash features
    METHOD="basic"
fi

# Output result
jq -n \
    --arg method "$METHOD" \
    --arg data "$RESULT" \
    '{
        success: true,
        data: {
            method: $method,
            result: $data
        },
        errors: []
    }'
```

---

## Module Structure

### module.json with Optional Dependencies

```json
{
  "name": "mymodule",
  "version": "1.0.0",
  "category": "scanning",
  "description": "My awesome scanner module",
  "author": "YourName",
  "executable": "python3 mymodule.py",
  
  "dependencies": [
    "python3"
  ],
  
  "optional_dependencies": {
    "scapy": "For SYN scanning and raw packet manipulation",
    "requests": "For advanced HTTP features",
    "beautifulsoup4": "For HTML parsing capabilities"
  },
  
  "inputs": {
    "scan_type": {
      "type": "string",
      "description": "Scan type: basic, advanced (requires scapy)",
      "required": false,
      "default": "basic"
    }
  },
  
  "notes": {
    "requirements": [
      "Works with basic installation (no optional deps)",
      "Install scapy for advanced features: pip3 install scapy",
      "Full features require: pip3 install scapy requests"
    ]
  }
}
```

### Directory Structure

```
tools/
└── category/
    └── mymodule/
        ├── module.json          # Module configuration
        ├── mymodule.py          # Main executable
        ├── README.md            # Documentation
        ├── test.sh              # Test script
        └── requirements.txt     # Optional: module-specific deps
```

---

## Testing Across Environments

### Test Matrix

Test your module in these configurations:

| Configuration | Dependencies | Expected Behavior |
|--------------|--------------|-------------------|
| **Basic** | cmd2, rich only | Core features work |
| **Standard** | + python-nmap, scapy | Enhanced features work |
| **Full** | All requirements.txt | All features work |

### Testing Script Template

```bash
#!/bin/bash
# test_module.sh - Test module across dependency levels

MODULE_NAME="mymodule"

echo "Testing $MODULE_NAME across dependency levels..."

# Test 1: Basic (uninstall optional deps)
echo "[1/3] Testing with BASIC dependencies..."
pip3 uninstall -y scapy requests beautifulsoup4 2>/dev/null
./secV << EOF
use $MODULE_NAME
run 127.0.0.1
exit
EOF

if [ $? -eq 0 ]; then
    echo "✓ BASIC test passed"
else
    echo "✗ BASIC test failed - MODULE MUST WORK AT BASIC LEVEL"
    exit 1
fi

# Test 2: Standard
echo "[2/3] Testing with STANDARD dependencies..."
pip3 install -q python-nmap scapy
./secV << EOF
use $MODULE_NAME
set advanced_features true
run 127.0.0.1
exit
EOF

if [ $? -eq 0 ]; then
    echo "✓ STANDARD test passed"
else
    echo "⚠ STANDARD test failed - check optional dependency handling"
fi

# Test 3: Full
echo "[3/3] Testing with FULL dependencies..."
pip3 install -q -r requirements.txt
./secV << EOF
use $MODULE_NAME
set all_features true
run 127.0.0.1
exit
EOF

if [ $? -eq 0 ]; then
    echo "✓ FULL test passed"
else
    echo "⚠ FULL test failed - check all optional dependencies"
fi

echo "Testing complete!"
```

---

## Examples & Patterns

### Pattern 1: Feature Flags Based on Dependencies

```python
class Scanner:
    def __init__(self):
        self.features = {
            'basic_scan': True,  # Always available
            'syn_scan': HAS_SCAPY,
            'http_analysis': HAS_REQUESTS,
            'html_parse': HAS_BS4
        }
    
    def list_features(self):
        """Show user what features are available"""
        available = [k for k, v in self.features.items() if v]
        unavailable = [k for k, v in self.features.items() if not v]
        
        return {
            'available': available,
            'unavailable': unavailable,
            'install_hint': self._get_install_hints(unavailable)
        }
    
    def _get_install_hints(self, missing_features):
        """Provide helpful installation hints"""
        hints = {
            'syn_scan': 'pip3 install scapy',
            'http_analysis': 'pip3 install requests',
            'html_parse': 'pip3 install beautifulsoup4'
        }
        return [hints.get(f) for f in missing_features if f in hints]
```

### Pattern 2: Graceful Degradation

```python
def scan_target(target, mode='auto'):
    """Scan with best available method"""
    
    if mode == 'auto':
        # Auto-select based on available libs
        if HAS_SCAPY:
            mode = 'syn'
        elif HAS_REQUESTS:
            mode = 'http'
        else:
            mode = 'basic'
    
    # Validate mode is possible
    if mode == 'syn' and not HAS_SCAPY:
        print("WARNING: SYN mode requires scapy, falling back to basic")
        mode = 'basic'
    
    # Execute with selected mode
    if mode == 'syn':
        return syn_scan(target)
    elif mode == 'http':
        return http_scan(target)
    else:
        return basic_scan(target)
```

### Pattern 3: User-Friendly Warnings

```python
def check_and_warn():
    """Inform user about missing optional features"""
    warnings = []
    
    if not HAS_SCAPY:
        warnings.append({
            'feature': 'SYN Scanning',
            'install': 'pip3 install scapy',
            'impact': 'Limited to TCP connect scans'
        })
    
    if not HAS_REQUESTS:
        warnings.append({
            'feature': 'HTTP Analysis',
            'install': 'pip3 install requests',
            'impact': 'Basic HTTP only, no advanced features'
        })
    
    if warnings:
        print("OPTIONAL FEATURES UNAVAILABLE:", file=sys.stderr)
        for w in warnings:
            print(f"  - {w['feature']}: {w['install']}", file=sys.stderr)
            print(f"    Impact: {w['impact']}", file=sys.stderr)
```

---

## Best Practices

### ✅ DO

1. **Use stdlib whenever possible**
   - `socket`, `json`, `urllib`, `subprocess`, `re`, `time`
   - These are always available

2. **Detect dependencies at runtime**
   - Use try/except for imports
   - Set feature flags based on availability

3. **Provide fallback implementations**
   - Basic features work without optional deps
   - Advanced features enhance, not replace

4. **Inform users helpfully**
   - Tell them what's missing
   - Show exactly how to install it
   - Explain what features they're missing

5. **Document everything**
   - List optional dependencies in module.json
   - Explain in README what each dependency enables
   - Show examples with and without optional features

6. **Test thoroughly**
   - Test with no optional deps (Basic)
   - Test with some optional deps (Standard)
   - Test with all optional deps (Full)

### ❌ DON'T

1. **Never hard-import optional dependencies**
   ```python
   # BAD
   import scapy.all as scapy  # Crashes if not installed
   
   # GOOD
   try:
       import scapy.all as scapy
       HAS_SCAPY = True
   except ImportError:
       HAS_SCAPY = False
   ```

2. **Never require optional dependencies for basic features**
   ```python
   # BAD
   def scan():
       return scapy_scan()  # Only works with scapy
   
   # GOOD
   def scan():
       if HAS_SCAPY:
           return advanced_scan()
       return basic_scan()
   ```

3. **Don't crash on missing dependencies**
   - Always handle ImportError
   - Always provide fallback
   - Always inform user gracefully

4. **Don't assume installation tier**
   - Your module might run on Basic installation
   - Detect, don't assume

---

## Dependency Reference

### Standard Library (Always Available)

| Module | Use Case |
|--------|----------|
| `socket` | Network connections |
| `json` | JSON parsing |
| `urllib` | HTTP requests (basic) |
| `subprocess` | Execute commands |
| `re` | Regular expressions |
| `time` | Timing operations |
| `os` | File operations |
| `sys` | System operations |

### Optional - Standard Tier

| Module | Use Case | Install Command |
|--------|----------|-----------------|
| `scapy` | Raw packets, SYN scan | `pip3 install scapy` |
| `python-nmap` | Nmap integration | `pip3 install python-nmap` |

### Optional - Full Tier

| Module | Use Case | Install Command |
|--------|----------|-----------------|
| `requests` | HTTP operations | `pip3 install requests` |
| `beautifulsoup4` | HTML parsing | `pip3 install beautifulsoup4` |
| `paramiko` | SSH operations | `pip3 install paramiko` |
| `dnspython` | DNS queries | `pip3 install dnspython` |
| `pycryptodome` | Cryptography | `pip3 install pycryptodome` |

---

## Submission Checklist

Before submitting your module:

- [ ] Works with Basic installation (core only)
- [ ] Optional dependencies detected with try/except
- [ ] Fallback methods provided for missing libraries
- [ ] module.json lists all optional_dependencies
- [ ] README documents dependency requirements
- [ ] User-friendly messages for missing features
- [ ] Tested on Basic, Standard, and Full installations
- [ ] No hardcoded imports of optional libraries
- [ ] Code follows SecV style guidelines
- [ ] Documentation is clear and complete

---

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Module Ideas**: Check existing discussions
- **Security**: Email security@secvulnhub.local

---

**Remember**: A module that works everywhere (even with reduced features) is better than a module that only works with all dependencies installed!

**Happy Module Building! 🔧**

---

*This guide is maintained by the SecVulnHub Team*
