# SecV Installation Guide

## Quick Install

```bash
# 1. Make the installer and SecV executable
chmod +x install.sh secV

# 2. Run the installer
./install.sh

# 3. Start SecV
./secV              # Local execution
# OR
secV                # If installed system-wide
```

## What the Installer Does

1. ✅ Checks Python 3.8+ installation
2. ✅ Installs pip if missing
3. ✅ Installs Python dependencies (cmd2, rich)
4. ✅ Makes SecV executable
5. ✅ Optionally installs system-wide to `/usr/local/bin/secV`
6. ✅ Creates tools directory structure

## Requirements

- **Python**: 3.8 or later
- **pip**: Python package installer
- **OS**: Linux, macOS, or Windows (with WSL)

## Installation Options

### Option 1: Local Installation (No sudo required)
```bash
./install.sh
# Answer 'N' when asked about system-wide installation
# Run with: ./secV
```

### Option 2: System-Wide Installation (Recommended)
```bash
./install.sh
# Answer 'Y' when asked about system-wide installation
# Run with: secV (from anywhere)
```

## Verification

After installation, verify SecV is working:

```bash
# Start the shell
./secV    # or just 'secV' if installed system-wide

# Inside SecV shell
secV > show modules
secV > show categories
secV > help
secV > exit
```

## Manual Installation

If you prefer to install manually:

```bash
# Install dependencies
pip3 install cmd2 rich --user

# Make executable
chmod +x secV

# Run
./secV
```

## Uninstallation

To remove system-wide installation:

```bash
chmod +x uninstall.sh
./uninstall.sh
```

To completely remove SecV including local files:

```bash
cd ..
rm -rf SecV/
```

## Troubleshooting

### Python not found
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip

# macOS
brew install python3

# Or download from python.org
```

### Permission denied when running ./secV
```bash
chmod +x secV
```

### Module not found: cmd2 or rich
```bash
pip3 install cmd2 rich --user
# Or run installer again
./install.sh
```

### System-wide installation fails
```bash
# Ensure you have sudo access
sudo ln -s $(pwd)/secV /usr/local/bin/secV
```

## Directory Structure

After installation:

```
SecV/
├── secV                # Main executable
├── install.sh          # Installation script
├── uninstall.sh        # Uninstallation script
├── requirements.txt    # Python dependencies
├── README.md           # Main documentation
├── INSTALL.md          # This file
└── tools/              # Module directory
    ├── network/
    │   └── spoof/
    │       ├── module.json
    │       └── macspoof.sh
    └── scanning/
        └── port-scanner/
            ├── module.json
            └── scanner.py
```

## Next Steps

After installation:

1. **Add modules**: Place your security tools in `tools/category/module-name/`
2. **Read docs**: Check out the main README.md
3. **Start hacking**: Run `secV` and type `help`

## Support

- **Issues**: https://github.com/SecVulnHub/SecV/issues
- **Docs**: https://github.com/SecVulnHub/SecV
- **Community**: SecVulnHub Team

---

**Ready to hack?** Run `./secV` and type `help` to get started! 🔒
