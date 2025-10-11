#!/usr/bin/env bash
#
# SecV Installation Script v2.4 - Go Loader Edition
# Complete installation with Go binary compilation
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SECV_BIN="$SCRIPT_DIR/secV"
MAIN_GO="$SCRIPT_DIR/main.go"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"
VERSION="2.4.0"

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

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
║   SecV Installer v2.4 - Go Loader Edition                        ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] Starting SecV installation...${NC}\n"

# ============================================================================
# Detect System Information
# ============================================================================

echo -e "${YELLOW}[1/11] Detecting system information...${NC}"
DISTRO=$(detect_distro)
echo -e "${GREEN}[✓] Detected distribution: ${DISTRO}${NC}"

if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="macos"
    echo -e "${GREEN}[✓] Operating system: macOS${NC}"
elif [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "linux" ]]; then
    OS_TYPE="linux"
    echo -e "${GREEN}[✓] Operating system: Linux${NC}"
else
    OS_TYPE="unknown"
    echo -e "${YELLOW}[!] Unknown operating system: $OSTYPE${NC}"
fi
echo

# ============================================================================
# Check Python 3.8+
# ============================================================================

echo -e "${YELLOW}[2/11] Checking Python installation...${NC}"

if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        echo -e "${GREEN}[✓] Python $PYTHON_VERSION detected${NC}"
    else
        echo -e "${RED}[✗] Python 3.8+ required (found $PYTHON_VERSION)${NC}"
        echo -e "${YELLOW}[!] Please install Python 3.8 or later${NC}"
        exit 1
    fi
else
    echo -e "${RED}[✗] Python 3 not found${NC}"
    echo -e "${YELLOW}[!] Install Python 3.8+ first:${NC}"
    echo -e "    ${DIM}Ubuntu/Debian: sudo apt install python3 python3-pip${NC}"
    echo -e "    ${DIM}Arch: sudo pacman -S python python-pip${NC}"
    echo -e "    ${DIM}macOS: brew install python3${NC}"
    exit 1
fi
echo

# ============================================================================
# Check Go Compiler
# ============================================================================

echo -e "${YELLOW}[3/11] Checking Go compiler...${NC}"

if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}[✓] Go compiler detected: ${GO_VERSION}${NC}"
    HAS_GO=true
else
    echo -e "${YELLOW}[!] Go compiler not found${NC}"
    echo -e "${DIM}    Go is required to compile the SecV binary${NC}"
    echo -e "${DIM}    Install instructions:${NC}"
    echo -e "${DIM}    - Arch: sudo pacman -S go${NC}"
    echo -e "${DIM}    - Ubuntu/Debian: sudo apt install golang-go${NC}"
    echo -e "${DIM}    - macOS: brew install go${NC}"
    echo -e "${DIM}    - Or download from: https://go.dev/dl/${NC}"
    
    read -p "Continue without Go? SecV won't be compiled. [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    HAS_GO=false
fi
echo

# ============================================================================
# Check/Install pip
# ============================================================================

echo -e "${YELLOW}[4/11] Checking pip installation...${NC}"

if ! python3 -m pip --version &> /dev/null; then
    echo -e "${YELLOW}[!] pip not found, attempting to install...${NC}"
    
    case "$DISTRO" in
        ubuntu|debian|kali|parrot)
            sudo apt-get update
            sudo apt-get install -y python3-pip
            ;;
        arch|archcraft|manjaro)
            sudo pacman -Sy --noconfirm python-pip
            ;;
        fedora|rhel|centos)
            sudo dnf install -y python3-pip
            ;;
        *)
            echo -e "${RED}[✗] Cannot auto-install pip for $DISTRO${NC}"
            echo -e "${YELLOW}Please install pip manually and re-run installer${NC}"
            exit 1
            ;;
    esac
fi

if python3 -m pip --version &> /dev/null; then
    PIP_VERSION=$(python3 -m pip --version | awk '{print $2}')
    echo -e "${GREEN}[✓] pip ${PIP_VERSION} installed${NC}"
else
    echo -e "${RED}[✗] pip installation failed${NC}"
    exit 1
fi
echo

# ============================================================================
# Select Installation Tier
# ============================================================================

echo -e "${YELLOW}[5/11] Select installation tier...${NC}"
echo
echo -e "${BOLD}Choose your installation tier:${NC}"
echo -e "  ${GREEN}1)${NC} Basic     - Core only (~5MB)"
echo -e "     ${DIM}Dependencies: cmd2, rich${NC}"
echo
echo -e "  ${CYAN}2)${NC} Standard  - Core + scanning (~50MB) ${BOLD}[Recommended]${NC}"
echo -e "     ${DIM}Dependencies: Basic + scapy, python-nmap${NC}"
echo
echo -e "  ${MAGENTA}3)${NC} Full      - All features (~100MB)"
echo -e "     ${DIM}Dependencies: Everything in requirements.txt${NC}"
echo
echo -e "  ${YELLOW}4)${NC} Elite     - Full + masscan"
echo -e "     ${DIM}Dependencies: Full + masscan binary${NC}"
echo

read -p "Enter choice [1-4] (default: 2): " TIER_CHOICE
TIER_CHOICE=${TIER_CHOICE:-2}

case "$TIER_CHOICE" in
    1)
        INSTALL_TIER="basic"
        echo -e "${GREEN}[✓] Selected: Basic tier${NC}"
        ;;
    2)
        INSTALL_TIER="standard"
        echo -e "${GREEN}[✓] Selected: Standard tier (Recommended)${NC}"
        ;;
    3)
        INSTALL_TIER="full"
        echo -e "${GREEN}[✓] Selected: Full tier${NC}"
        ;;
    4)
        INSTALL_TIER="elite"
        echo -e "${GREEN}[✓] Selected: Elite tier${NC}"
        ;;
    *)
        echo -e "${YELLOW}[!] Invalid choice, defaulting to Standard${NC}"
        INSTALL_TIER="standard"
        ;;
esac
echo

# ============================================================================
# Install Python Dependencies
# ============================================================================

echo -e "${YELLOW}[6/11] Installing Python dependencies...${NC}"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo -e "${RED}[✗] requirements.txt not found!${NC}"
    exit 1
fi

# Create temporary requirements file based on tier
TEMP_REQ=$(mktemp)

case "$INSTALL_TIER" in
    basic)
        echo "cmd2>=2.4.3" >> "$TEMP_REQ"
        echo "rich>=13.0.0" >> "$TEMP_REQ"
        echo "argcomplete>=3.0.0" >> "$TEMP_REQ"
        ;;
    standard)
        echo "cmd2>=2.4.3" >> "$TEMP_REQ"
        echo "rich>=13.0.0" >> "$TEMP_REQ"
        echo "argcomplete>=3.0.0" >> "$TEMP_REQ"
        echo "scapy>=2.5.0" >> "$TEMP_REQ"
        echo "python-nmap>=0.7.1" >> "$TEMP_REQ"
        ;;
    full|elite)
        cp "$REQUIREMENTS_FILE" "$TEMP_REQ"
        ;;
esac

# Try different pip installation methods
PIP_SUCCESS=false

echo -e "${CYAN}[*] Attempting pip install (method 1: --user)...${NC}"
if python3 -m pip install --user -r "$TEMP_REQ" &> /dev/null; then
    PIP_SUCCESS=true
    echo -e "${GREEN}[✓] Dependencies installed (--user)${NC}"
fi

if [ "$PIP_SUCCESS" = false ]; then
    echo -e "${CYAN}[*] Attempting pip install (method 2: --user --break-system-packages)...${NC}"
    if python3 -m pip install --user --break-system-packages -r "$TEMP_REQ" &> /dev/null; then
        PIP_SUCCESS=true
        echo -e "${GREEN}[✓] Dependencies installed (--user --break-system-packages)${NC}"
    fi
fi

if [ "$PIP_SUCCESS" = false ]; then
    echo -e "${CYAN}[*] Attempting pip install (method 3: --break-system-packages)...${NC}"
    if python3 -m pip install --break-system-packages -r "$TEMP_REQ" &> /dev/null; then
        PIP_SUCCESS=true
        echo -e "${GREEN}[✓] Dependencies installed (--break-system-packages)${NC}"
    fi
fi

if [ "$PIP_SUCCESS" = false ]; then
    echo -e "${YELLOW}[!] User installation failed, trying with sudo...${NC}"
    if sudo python3 -m pip install --break-system-packages -r "$TEMP_REQ"; then
        PIP_SUCCESS=true
        echo -e "${GREEN}[✓] Dependencies installed (sudo)${NC}"
    fi
fi

rm -f "$TEMP_REQ"

if [ "$PIP_SUCCESS" = false ]; then
    echo -e "${RED}[✗] Failed to install Python dependencies${NC}"
    echo -e "${YELLOW}[!] Try manually: pip3 install -r requirements.txt --user${NC}"
    exit 1
fi
echo

# ============================================================================
# Install Elite Tier Components
# ============================================================================

if [ "$INSTALL_TIER" = "elite" ]; then
    echo -e "${YELLOW}[7/11] Installing Elite tier components...${NC}"
    
    if command -v masscan &> /dev/null; then
        echo -e "${GREEN}[✓] masscan already installed${NC}"
    else
        echo -e "${CYAN}[*] Installing masscan...${NC}"
        
        case "$DISTRO" in
            ubuntu|debian|kali|parrot)
                sudo apt-get install -y masscan
                ;;
            arch|archcraft|manjaro)
                sudo pacman -S --noconfirm masscan
                ;;
            fedora|rhel|centos)
                sudo dnf install -y masscan
                ;;
            *)
                echo -e "${YELLOW}[!] Cannot auto-install masscan for $DISTRO${NC}"
                echo -e "${DIM}    Install manually: https://github.com/robertdavidgraham/masscan${NC}"
                ;;
        esac
        
        if command -v masscan &> /dev/null; then
            echo -e "${GREEN}[✓] masscan installed${NC}"
        else
            echo -e "${YELLOW}[!] masscan installation failed (optional)${NC}"
        fi
    fi
    echo
else
    echo -e "${YELLOW}[7/11] Skipping Elite tier components...${NC}"
    echo -e "${DIM}    Selected tier: $INSTALL_TIER${NC}"
    echo
fi

# ============================================================================
# Compile Go Binary
# ============================================================================

echo -e "${YELLOW}[8/11] Compiling SecV binary...${NC}"

if [ "$HAS_GO" = true ]; then
    if [ ! -f "$MAIN_GO" ]; then
        echo -e "${RED}[✗] main.go not found!${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}[*] Compiling Go binary (this may take a minute)...${NC}"
    
    cd "$SCRIPT_DIR"
    if go build -ldflags="-s -w" -o secV main.go; then
        chmod +x secV
        BINARY_SIZE=$(du -h secV | cut -f1)
        echo -e "${GREEN}[✓] Binary compiled successfully (${BINARY_SIZE})${NC}"
    else
        echo -e "${RED}[✗] Compilation failed${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}[!] Skipping compilation (Go not available)${NC}"
    echo -e "${DIM}    You won't be able to run SecV without the binary${NC}"
fi
echo

# ============================================================================
# Create Tools Directory
# ============================================================================

echo -e "${YELLOW}[9/11] Setting up directory structure...${NC}"

TOOLS_DIR="$SCRIPT_DIR/tools"
CACHE_DIR="$SCRIPT_DIR/.cache"

mkdir -p "$TOOLS_DIR"
mkdir -p "$CACHE_DIR"

echo -e "${GREEN}[✓] Directories created${NC}"
echo

# ============================================================================
# Set Permissions
# ============================================================================

echo -e "${YELLOW}[10/11] Setting permissions...${NC}"

chmod +x "$SCRIPT_DIR/secV" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/install.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/uninstall.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/update.py" 2>/dev/null || true

echo -e "${GREEN}[✓] Permissions set${NC}"
echo

# ============================================================================
# System-Wide Installation (Optional)
# ============================================================================

echo -e "${YELLOW}[11/11] System-wide installation...${NC}"

read -p "Install SecV system-wide to /usr/local/bin? [Y/n]: " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    if [ -f "$SECV_BIN" ]; then
        sudo ln -sf "$SECV_BIN" /usr/local/bin/secV
        echo -e "${GREEN}[✓] SecV installed to /usr/local/bin/secV${NC}"
        echo -e "${DIM}    You can now run 'secV' from anywhere${NC}"
    else
        echo -e "${YELLOW}[!] Binary not found, skipping system-wide install${NC}"
    fi
else
    echo -e "${CYAN}[*] Skipped system-wide installation${NC}"
    echo -e "${DIM}    Run with: ./secV${NC}"
fi
echo

# ============================================================================
# Installation Complete
# ============================================================================

echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║                   Installation Complete! ✓                        ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo

echo -e "${BOLD}SecV v${VERSION} - Go Loader Edition${NC}"
echo -e "${DIM}Installation tier: ${INSTALL_TIER}${NC}"
echo

echo -e "${CYAN}${BOLD}Quick Start:${NC}"
if [ -L "/usr/local/bin/secV" ]; then
    echo -e "  ${GREEN}secV${NC}                    # Start SecV (system-wide)"
else
    echo -e "  ${GREEN}./secV${NC}                  # Start SecV (local)"
fi
echo -e "  ${GREEN}secV > help${NC}              # Show commands"
echo -e "  ${GREEN}secV > show modules${NC}      # List all modules"
echo -e "  ${GREEN}secV > use portscan${NC}      # Load a module"
echo

echo -e "${CYAN}${BOLD}Documentation:${NC}"
echo -e "  ${DIM}README.md${NC}               - Project overview"
echo -e "  ${DIM}INSTALL.md${NC}              - Installation guide"
echo -e "  ${DIM}CONTRIBUTING.md${NC}         - Contribution guidelines"
echo

echo -e "${CYAN}${BOLD}Update System:${NC}"
echo -e "  ${GREEN}secV > update${NC}           # Check for updates (in SecV shell)"
echo -e "  ${GREEN}python3 update.py${NC}       # Manual update check"
echo

echo -e "${YELLOW}${BOLD}⚠️  Ethical Use Reminder:${NC}"
echo -e "${DIM}SecV is for authorized security testing only.${NC}"
echo -e "${DIM}Always obtain proper authorization before testing.${NC}"
echo

echo -e "${BOLD}${CYAN}Ready to hack! Start SecV now:${NC}"
if [ -L "/usr/local/bin/secV" ]; then
    echo -e "  ${GREEN}${BOLD}secV${NC}"
else
    echo -e "  ${GREEN}${BOLD}./secV${NC}"
fi
echo
