#!/usr/bin/env bash
#
# SecV Installation Script v2.1
# Enhanced with tier selection and better dependency management
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
BREAK="--break-system-packages"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SECV_BIN="$SCRIPT_DIR/secV"

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗███████╗ ██████╗██╗   ██╗                             ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║                             ║
║   ███████╗█████╗  ██║     ██║   ██║                             ║
║   ╚════██║██╔══╝  ██║     ╚██╗ ██╔╝                             ║
║   ███████║███████╗╚██████╗ ╚████╔╝                              ║
║   ╚══════╝╚══════╝ ╚═════╝  ╚═══╝                               ║
║                                                                   ║
║   SecV Installer v2.1 - The Polyglot Security Platform           ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] Starting SecV installation...${NC}\n"

# ============================================================================
# Check Prerequisites
# ============================================================================

echo -e "${YELLOW}[1/7] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed!${NC}"
    echo -e "${YELLOW}    Please install Python 3.8 or later and try again.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED}[!] Python 3.8 or later is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Python $PYTHON_VERSION found${NC}\n"

# ============================================================================
# Check pip
# ============================================================================

echo -e "${YELLOW}[2/7] Checking pip installation...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip3 is not installed!${NC}"
    echo -e "${YELLOW}    Installing pip...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y python3-pip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        python3 -m ensurepip --upgrade $BREAK 2>/dev/null || true
    else
        echo -e "${RED}[!] Unable to install pip automatically. Please install manually.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[✓] pip3 found${NC}\n"

# ============================================================================
# Installation Tier Selection
# ============================================================================

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}║   Installation Tier Selection                                     ║${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${YELLOW}Choose your installation tier:${NC}\n"

echo -e "${GREEN}1) Basic${NC} - Core functionality only (~5MB)"
echo -e "   • cmd2, rich (required)"
echo -e "   • TCP connect scanning"
echo -e "   • All modules work with reduced features"
echo -e "   ${BLUE}Best for: Minimal footprint, testing${NC}\n"

echo -e "${GREEN}2) Standard${NC} - Core + scanning tools (~50MB) ${MAGENTA}⭐ Recommended${NC}"
echo -e "   • Basic + scapy, python-nmap"
echo -e "   • SYN scanning (stealth)"
echo -e "   • Nmap integration"
echo -e "   • Full port scanner features"
echo -e "   ${BLUE}Best for: Most users, penetration testing${NC}\n"

echo -e "${GREEN}3) Full${NC} - All features (~100MB)"
echo -e "   • Standard + requests, beautifulsoup4, dnspython"
echo -e "   • HTTP technology detection"
echo -e "   • Web scraping capabilities"
echo -e "   • DNS operations"
echo -e "   • Complete module support"
echo -e "   ${BLUE}Best for: Advanced users, full features${NC}\n"

read -p "Select tier [1-3] (default: 2): " TIER
TIER=${TIER:-2}

case $TIER in
    1)
        TIER_NAME="Basic"
        INSTALL_DEPS="cmd2>=2.4.3 rich>=13.0.0"
        ;;
    2)
        TIER_NAME="Standard"
        INSTALL_DEPS="cmd2>=2.4.3 rich>=13.0.0 scapy>=2.5.0 python-nmap>=0.7.1"
        ;;
    3)
        TIER_NAME="Full"
        INSTALL_DEPS="cmd2>=2.4.3 rich>=13.0.0 scapy>=2.5.0 python-nmap>=0.7.1 requests>=2.31.0 beautifulsoup4>=4.12.0 dnspython>=2.4.0"
        ;;
    *)
        echo -e "${RED}[!] Invalid selection. Using Standard tier.${NC}"
        TIER=2
        TIER_NAME="Standard"
        INSTALL_DEPS="cmd2>=2.4.3 rich>=13.0.0 scapy>=2.5.0 python-nmap>=0.7.1"
        ;;
esac

echo -e "\n${GREEN}[✓] Selected: $TIER_NAME tier${NC}\n"

# ============================================================================
# Platform-Specific Dependencies
# ============================================================================

if [ $TIER -ge 2 ]; then
    echo -e "${YELLOW}[3/7] Checking platform-specific dependencies...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if ! dpkg -l | grep -q libpcap-dev; then
            echo -e "${YELLOW}[i] Scapy requires libpcap-dev on Linux${NC}"
            read -p "Install libpcap-dev? (recommended) [Y/n]: " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
                sudo apt-get update && sudo apt-get install -y libpcap-dev
                echo -e "${GREEN}[✓] libpcap-dev installed${NC}"
            else
                echo -e "${YELLOW}[!] Skipped. SYN scanning may not work properly.${NC}"
            fi
        else
            echo -e "${GREEN}[✓] libpcap-dev already installed${NC}"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${GREEN}[✓] macOS - no additional dependencies needed${NC}"
    fi
else
    echo -e "${YELLOW}[3/7] Platform-specific dependencies...${NC}"
    echo -e "${GREEN}[✓] Basic tier - no additional dependencies needed${NC}"
fi
echo

# ============================================================================
# Install Python Dependencies
# ============================================================================

echo -e "${YELLOW}[4/7] Installing Python dependencies ($TIER_NAME tier)...${NC}"

# Try user install first, fallback to break-system-packages if needed
if pip3 install $INSTALL_DEPS --user 2>/dev/null; then
    echo -e "${GREEN}[✓] Dependencies installed (user)${NC}"
elif pip3 install $INSTALL_DEPS --user $BREAK 2>/dev/null; then
    echo -e "${GREEN}[✓] Dependencies installed (user, with override)${NC}"
else
    echo -e "${YELLOW}[!] User install failed, trying without --user...${NC}"
    if pip3 install $INSTALL_DEPS 2>/dev/null; then
        echo -e "${GREEN}[✓] Dependencies installed (system)${NC}"
    else
        echo -e "${RED}[!] Failed to install dependencies${NC}"
        echo -e "${YELLOW}    Try manual installation: pip3 install $INSTALL_DEPS${NC}"
        exit 1
    fi
fi
echo

# ============================================================================
# Verify Installation
# ============================================================================

echo -e "${YELLOW}[5/7] Verifying installation...${NC}"

# Check core dependencies
if python3 -c "import cmd2, rich" 2>/dev/null; then
    echo -e "${GREEN}[✓] Core dependencies verified${NC}"
else
    echo -e "${RED}[!] Core dependencies failed to verify${NC}"
    exit 1
fi

# Check tier-specific dependencies
if [ $TIER -ge 2 ]; then
    if python3 -c "import scapy.all" 2>/dev/null; then
        echo -e "${GREEN}[✓] Scapy installed and working${NC}"
    else
        echo -e "${YELLOW}[!] Scapy import failed - SYN scanning may not work${NC}"
    fi
    
    if python3 -c "import nmap" 2>/dev/null; then
        echo -e "${GREEN}[✓] python-nmap installed and working${NC}"
    else
        echo -e "${YELLOW}[!] python-nmap import failed${NC}"
    fi
fi

if [ $TIER -ge 3 ]; then
    if python3 -c "import requests, bs4, dns" 2>/dev/null; then
        echo -e "${GREEN}[✓] Full tier dependencies verified${NC}"
    else
        echo -e "${YELLOW}[!] Some full tier dependencies may be missing${NC}"
    fi
fi
echo

# ============================================================================
# Make SecV Executable
# ============================================================================

echo -e "${YELLOW}[6/7] Setting executable permissions...${NC}"
chmod +x "$SECV_BIN"

if [ -x "$SECV_BIN" ]; then
    echo -e "${GREEN}[✓] SecV is now executable${NC}\n"
else
    echo -e "${RED}[!] Failed to make SecV executable${NC}"
    exit 1
fi

# ============================================================================
# Create Directory Structure
# ============================================================================

if [ ! -d "$SCRIPT_DIR/tools" ]; then
    echo -e "${YELLOW}Creating tools directory...${NC}"
    mkdir -p "$SCRIPT_DIR/tools"
    echo -e "${GREEN}[✓] Tools directory created${NC}"
fi

if [ ! -d "$SCRIPT_DIR/.cache" ]; then
    mkdir -p "$SCRIPT_DIR/.cache"
fi

# ============================================================================
# System-Wide Installation
# ============================================================================

echo -e "${YELLOW}[7/7] System-wide installation...${NC}\n"

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}║   System-Wide Installation (Optional)                             ║${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${YELLOW}Would you like to install SecV system-wide?${NC}"
echo -e "${BLUE}This will allow you to run 'secV' from anywhere on your system.${NC}"
echo -e "${BLUE}Installation location: /usr/local/bin/secV${NC}\n"

read -p "Install system-wide? [y/N]: " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n${YELLOW}Installing system-wide (requires sudo)...${NC}"
    
    INSTALL_PATH="/usr/local/bin/secV"
    
    # Remove existing installation if present
    if [ -L "$INSTALL_PATH" ] || [ -f "$INSTALL_PATH" ]; then
        echo -e "${YELLOW}Removing existing installation...${NC}"
        sudo rm -f "$INSTALL_PATH"
    fi
    
    # Create symlink
    sudo ln -s "$SECV_BIN" "$INSTALL_PATH"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] SecV installed to $INSTALL_PATH${NC}"
        echo -e "${GREEN}[✓] You can now run 'secV' from anywhere!${NC}\n"
        INSTALLED_GLOBALLY=true
    else
        echo -e "${RED}[!] Failed to install system-wide${NC}"
        echo -e "${YELLOW}    You can still run SecV with: ./secV${NC}"
        INSTALLED_GLOBALLY=false
    fi
else
    echo -e "\n${BLUE}[i] Local installation complete.${NC}"
    echo -e "${BLUE}    Run SecV with: ./secV${NC}"
    INSTALLED_GLOBALLY=false
fi

# ============================================================================
# Installation Summary
# ============================================================================

echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}║   Installation Complete!                                          ║${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}✓ SecV v2.1 is ready to use!${NC}\n"

echo -e "${BLUE}Installation Summary:${NC}"
echo -e "  Tier: ${GREEN}$TIER_NAME${NC}"
echo -e "  Python: ${GREEN}$PYTHON_VERSION${NC}"
echo -e "  Location: ${GREEN}$SCRIPT_DIR${NC}"

if [ "$INSTALLED_GLOBALLY" = true ]; then
    echo -e "  Global: ${GREEN}Yes${NC} (/usr/local/bin/secV)\n"
else
    echo -e "  Global: ${YELLOW}No${NC} (local only)\n"
fi

echo -e "${BLUE}Capabilities:${NC}"
echo -e "  Core Framework: ${GREEN}✓${NC}"
echo -e "  Module Help System: ${GREEN}✓${NC}"

if [ $TIER -ge 2 ]; then
    if python3 -c "import scapy.all" 2>/dev/null; then
        echo -e "  SYN Scanning: ${GREEN}✓${NC} (requires root)"
    else
        echo -e "  SYN Scanning: ${YELLOW}✗${NC} (scapy import failed)"
    fi
    
    if python3 -c "import nmap" 2>/dev/null; then
        echo -e "  Nmap Integration: ${GREEN}✓${NC}"
    else
        echo -e "  Nmap Integration: ${YELLOW}✗${NC} (python-nmap import failed)"
    fi
else
    echo -e "  SYN Scanning: ${YELLOW}✗${NC} (Standard tier needed)"
    echo -e "  Nmap Integration: ${YELLOW}✗${NC} (Standard tier needed)"
fi

if [ $TIER -ge 3 ]; then
    if python3 -c "import requests" 2>/dev/null; then
        echo -e "  HTTP Detection: ${GREEN}✓${NC}"
    else
        echo -e "  HTTP Detection: ${YELLOW}✗${NC} (requests import failed)"
    fi
else
    echo -e "  HTTP Detection: ${YELLOW}✗${NC} (Full tier needed)"
fi

echo -e "\n${BLUE}Quick Start:${NC}"
if [ "$INSTALLED_GLOBALLY" = true ]; then
    echo -e "  ${YELLOW}secV${NC}                    # Start SecV shell"
else
    echo -e "  ${YELLOW}./secV${NC}                  # Start SecV shell"
fi
echo -e "  ${YELLOW}help${NC}                    # Show all commands"
echo -e "  ${YELLOW}show modules${NC}            # List available modules"
echo -e "  ${YELLOW}info portscan${NC}           # View module help"
echo -e "  ${YELLOW}use portscan${NC}            # Load port scanner"
echo -e "  ${YELLOW}help module${NC}             # Module-specific help"
echo -e "  ${YELLOW}run target.com${NC}          # Execute scan\n"

echo -e "${BLUE}Documentation:${NC}"
echo -e "  ${CYAN}README.md${NC}               - Main documentation"
echo -e "  ${CYAN}MODULE_HELP_GUIDE.md${NC}    - Help system guide"
echo -e "  ${CYAN}CONTRIBUTING.md${NC}         - Contributor guide"
echo -e "  ${CYAN}https://github.com/SecVulnHub/SecV${NC}\n"

if [ $TIER -eq 1 ]; then
    echo -e "${YELLOW}💡 Tip: Upgrade to Standard tier for full scanning features:${NC}"
    echo -e "   ${CYAN}pip3 install scapy python-nmap --user${NC}\n"
fi

if [ $TIER -eq 2 ]; then
    echo -e "${YELLOW}💡 Tip: Upgrade to Full tier for HTTP detection:${NC}"
    echo -e "   ${CYAN}pip3 install requests beautifulsoup4 --user${NC}\n"
fi

echo -e "${GREEN}Happy Hacking! 🔒${NC}\n"
