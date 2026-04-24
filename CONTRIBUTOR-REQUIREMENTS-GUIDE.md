# SecV Contributor Requirements Guide
## Managing Python Dependencies the Right Way

---

## 🎯 **Quick Rules for Contributors**

When adding a new module to SecV:

1. ✅ **Always add Python dependencies to `requirements.txt`**
2. ✅ **Document which module needs each dependency**
3. ✅ **Test your module with and without optional dependencies**
4. ✅ **Use `--break-system-packages` compatible installation**
5. ✅ **Mark optional dependencies clearly in `module.json`**

---

## 📦 **How SecV Handles Dependencies**

### Installation Tiers

SecV has three installation levels:

| Tier | Dependencies | When to Use |
|------|--------------|-------------|
| **Basic** | Core only (cmd2, rich) | Testing, minimal setup |
| **Standard** | Core + scanning (scapy, nmap) | Most users |
| **Full** | Everything in requirements.txt | Power users |

### The Installer's Job

The `install.sh` script:
- Runs **once** during initial setup
- Installs dependencies based on selected tier
- Uses `--break-system-packages` for compatibility
- Works across all major Linux distributions
- Sets up the SecV environment

### The Updater's Job

The `update.py` script:
- Runs when users execute `update` command
- Detects changes to `requirements.txt`
- **Automatically installs new dependencies**
- Shows what was added/removed
- Maintains dependency hash for tracking
- Handles installation failures gracefully

---

## 📝 **Adding Dependencies: Step-by-Step**

### Step 1: Identify Your Dependencies

Before creating your module, list all Python packages it needs:

```python
# Example module using requests and beautifulsoup4
import requests  # HTTP client
from bs4 import BeautifulSoup  # HTML parsing
```

### Step 2: Update requirements.txt

Add your dependencies to the **global** `requirements.txt` file:

```bash
# Open requirements.txt
nano requirements.txt

# Add your dependencies with comments
# Web Scraping - Required by: web-scraper, content-discovery
requests>=2.31.0               # HTTP operations
beautifulsoup4>=4.12.0         # HTML/XML parsing
lxml>=4.9.0                    # Fast parser for BS4
```

**Format Rules:**
- Use version constraints (`>=`, `==`, `~=`)
- Add comments indicating which modules need it
- Group related dependencies together
- Use full tier sections (CORE, STANDARD, FULL)

### Step 3: Update module.json

Declare dependencies in your module configuration:

```json
{
  "name": "web-scraper",
  "version": "1.0.0",
  "category": "web",
  
  "dependencies": ["python3"],
  
  "optional_dependencies": {
    "requests": "For HTTP operations - pip3 install requests",
    "beautifulsoup4": "For HTML parsing - pip3 install beautifulsoup4",
    "lxml": "For faster parsing - pip3 install lxml"
  }
}
```

### Step 4: Make Your Module Gracefully Degrade

**Critical:** Your module should work even without optional dependencies!

```python
#!/usr/bin/env python3
"""
Web Scraper Module
Author: YourName
"""

import json
import sys

# Try importing optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    BeautifulSoup = None


def scrape_advanced(url):
    """Advanced scraping with requests + BeautifulSoup"""
    if not HAS_REQUESTS or not HAS_BS4:
        return None
    
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    return {"title": soup.title.string, "links": [a['href'] for a in soup.find_all('a')]}


def scrape_basic(url):
    """Basic scraping with urllib (stdlib)"""
    import urllib.request
    from html.parser import HTMLParser
    
    response = urllib.request.urlopen(url)
    content = response.read().decode('utf-8')
    # Basic parsing...
    return {"content": content[:500]}


def main():
    context = json.loads(sys.stdin.read())
    url = context['target']
    
    # Inform user about capabilities
    if not HAS_REQUESTS:
        print("INFO: Install requests for better features: pip3 install requests", file=sys.stderr)
    
    # Choose best available method
    if HAS_REQUESTS and HAS_BS4:
        result = scrape_advanced(url)
        method = "advanced"
    else:
        result = scrape_basic(url)
        method = "basic"
    
    output = {
        "success": True,
        "data": {
            "method": method,
            "result": result
        },
        "errors": []
    }
    
    print(json.dumps(output))


if __name__ == '__main__':
    main()
```

---

## 🔄 **The Update Workflow**

### What Happens When Users Update

1. User runs: `secV > update`
2. Updater pulls latest changes from git
3. Updater compares old vs new `requirements.txt`
4. Updater shows what dependencies changed
5. Updater installs new dependencies automatically
6. User's SecV installation is fully updated

### Example Update Output

```bash
secV > update

╔═══════════════════════════════════════════════════════════════════╗
║                      SecV Git Updater v2.2                        ║
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

═══════════════════════════════════════════════════════════════════
           Installing/Updating Python Dependencies...
═══════════════════════════════════════════════════════════════════

Attempt 1: pip install --user -r requirements.txt...
✓ Dependencies installed successfully!

✓ All dependencies are up to date!

╔═══════════════════════════════════════════════════════════════════╗
║                         Update Complete!                          ║
╚═══════════════════════════════════════════════════════════════════╝

✓ SecV has been updated successfully!

Next Steps:
  1. Restart SecV to load updated modules
  2. Run 'reload' inside SecV to rescan modules
  3. Type 'show modules' to see all available modules
```

---

## ✅ **Pre-Submission Checklist**

Before submitting your module PR, ensure:

- [ ] All Python dependencies added to `requirements.txt`
- [ ] Dependencies documented with comments
- [ ] Version constraints specified (>=, ==, ~=)
- [ ] Module section added to requirements.txt comments
- [ ] `optional_dependencies` listed in module.json
- [ ] Module works without optional dependencies
- [ ] Graceful degradation implemented
- [ ] User-friendly messages for missing deps
- [ ] Tested on Basic tier (no optional deps)
- [ ] Tested on Full tier (all deps installed)

---

## 🏗️ **requirements.txt Structure**

The global `requirements.txt` follows this format:

```python
# SecV Global Dependencies
# Version: 2.2.0
# 
# Installation: pip3 install -r requirements.txt --break-system-packages
# 
# TIER STRUCTURE:
# - CORE: Required for basic functionality (always installed)
# - STANDARD: Recommended for most users (scanning, pentesting)
# - FULL: Complete feature set (web, crypto, advanced features)

# ============================================================================
# CORE TIER - Required (always installed)
# ============================================================================

# CLI Framework
cmd2>=2.4.3                    # Interactive shell framework
rich>=13.0.0                   # Terminal formatting and output
argcomplete>=3.0.0             # Shell completion support

# ============================================================================
# STANDARD TIER - Recommended (scanning & pentesting)
# ============================================================================

# Network Scanning - Required by: portscan, network-discovery
scapy>=2.5.0                   # Raw packet manipulation, SYN scanning
python-nmap>=0.7.1             # Nmap integration

# ============================================================================
# FULL TIER - Complete (all features)
# ============================================================================

# HTTP Operations - Required by: portscan (tech detection), web-enum
requests>=2.31.0               # HTTP client library
urllib3>=2.0.0                 # HTTP client (requests dependency)

# Web Scraping - Required by: web-enum, content-discovery
beautifulsoup4>=4.12.0         # HTML/XML parsing
lxml>=4.9.0                    # Fast XML/HTML parser

# YOUR NEW DEPENDENCIES GO HERE
# YourModule - Required by: your-module
your-package>=1.0.0            # Description

# ============================================================================
# MODULE DEPENDENCY REFERENCE
# ============================================================================
# 
# MODULE: your-module v1.0
#   CORE: None (stdlib only for basic functionality)
#   STANDARD: None
#   FULL: your-package (advanced features)
```

---

## 🎓 **Common Patterns**

### Pattern 1: Network/Protocol Library

```python
# In requirements.txt
paramiko>=3.4.0                # SSH operations - Required by: ssh-scanner

# In module
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
```

### Pattern 2: Data Processing Library

```python
# In requirements.txt
pandas>=2.0.0                  # Data analysis - Required by: log-analyzer

# In module
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    # Fallback to manual CSV processing
```

### Pattern 3: Multiple Related Dependencies

```python
# In requirements.txt
# Cryptography Suite - Required by: crypto-tools
pycryptodome>=3.19.0           # Encryption/decryption
cryptography>=41.0.0           # Modern crypto library

# In module
try:
    from Crypto.Cipher import AES
    import cryptography
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
```

---

## 🚫 **Common Mistakes to Avoid**

### ❌ **WRONG: Module-Specific requirements.txt**

```bash
# DON'T do this!
tools/
└── web/
    └── scraper/
        ├── module.json
        ├── scraper.py
        └── requirements.txt  ❌ NO!
```

### ✅ **RIGHT: Global requirements.txt**

```bash
# DO this instead!
SecV/
├── requirements.txt  ✅ YES!
└── tools/
    └── web/
        └── scraper/
            ├── module.json
            └── scraper.py
```

### ❌ **WRONG: Hard Import Without Fallback**

```python
# DON'T do this!
import requests  # Crashes if not installed!

def scan(url):
    return requests.get(url)  # No fallback!
```

### ✅ **RIGHT: Try/Except with Fallback**

```python
# DO this instead!
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def scan(url):
    if HAS_REQUESTS:
        return requests.get(url)
    else:
        import urllib.request
        return urllib.request.urlopen(url)
```

---

## 📚 **Additional Resources**

- [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md) - Complete module development guide
- [MODULE_HELP_GUIDE.md](MODULE_HELP_GUIDE.md) - Help documentation guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - General contribution guidelines
- [requirements.txt](requirements.txt) - Current global dependencies

---

## ❓ **FAQ**

### Q: Can I use dependencies not in requirements.txt?

**A:** No. All Python dependencies MUST be in the global requirements.txt. This ensures:
- The updater can install them automatically
- Users know what's needed
- Installation is consistent across all systems

### Q: What if my dependency conflicts with existing ones?

**A:** Open an issue first! We'll work together to resolve conflicts before merging.

### Q: Should I pin exact versions (==) or use ranges (>=)?

**A:** Use ranges (`>=`) unless there's a specific compatibility reason. This gives users flexibility.

### Q: What about system packages (apt, yum, pacman)?

**A:** Document these in your module's README.md. The installer handles common ones like libpcap-dev.

### Q: My module needs a huge library (TensorFlow, PyTorch). What do?

**A:** For very large dependencies:
1. Make them optional
2. Provide clear installation instructions
3. Consider excluding from default Full tier
4. Discuss with maintainers before adding

---

## 🤝 **Getting Help**

- **Questions:** Open a GitHub Discussion
- **Bugs:** Open a GitHub Issue  
- **Dependency Conflicts:** Tag `@maintainers` in issue
- **Security:** Email secvulnhub@proton.me

---

**Thank you for contributing to SecV responsibly!**

*By following these guidelines, you help ensure SecV remains easy to install, update, and maintain for everyone.*
