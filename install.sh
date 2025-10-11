#!/usr/bin/env bash
#
# SecV Installation Script v2.4
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
║   SecV Installer v2.4                                            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] Starting SecV installation...${NC}\n"

# ============================================================================
# Detect System Information
# ============================================================================

echo -e "${YELLOW}[1/12] Detecting system information...${NC}"
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

echo -e "${YELLOW}[2/12] Checking Python installation...${NC}"

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

# Ensure curl and unzip are available (needed for fallback installations)
if ! command -v curl &> /dev/null || ! command -v unzip &> /dev/null; then
    echo -e "${YELLOW}[!] Installing required utilities (curl, unzip)...${NC}"
    case "$DISTRO" in
        ubuntu|debian|kali|parrot|linuxmint|pop)
            sudo apt-get install -y curl unzip
            ;;
        arch|archcraft|manjaro)
            sudo pacman -S --noconfirm --needed curl unzip
            ;;
        fedora|rhel|centos|rocky|alma)
            sudo dnf install -y curl unzip
            ;;
        alpine)
            sudo apk add curl unzip
            ;;
        opensuse*|sles)
            sudo zypper install -y curl unzip
            ;;
        *)
            if ! command -v curl &> /dev/null; then
                echo -e "${RED}[✗] curl not found - please install manually${NC}"
                exit 1
            fi
            if ! command -v unzip &> /dev/null; then
                echo -e "${RED}[✗] unzip not found - please install manually${NC}"
                exit 1
            fi
            ;;
    esac
fi

# Check for Java (required for Android RE tools)
if ! command -v java &> /dev/null; then
    echo -e "${YELLOW}[!] Java not found, installing...${NC}"
    case "$DISTRO" in
        ubuntu|debian|kali|parrot|linuxmint|pop)
            sudo apt-get install -y default-jre
            ;;
        arch|archcraft|manjaro)
            sudo pacman -S --noconfirm --needed jre-openjdk
            ;;
        fedora|rhel|centos|rocky|alma)
            sudo dnf install -y java-latest-openjdk
            ;;
        alpine)
            sudo apk add openjdk11-jre
            ;;
        opensuse*|sles)
            sudo zypper install -y java-11-openjdk
            ;;
        *)
            echo -e "${YELLOW}[!] Please install Java Runtime Environment manually${NC}"
            ;;
    esac
    
    if command -v java &> /dev/null; then
        JAVA_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')
        echo -e "${GREEN}[✓] Java ${JAVA_VERSION} installed${NC}"
    else
        echo -e "${YELLOW}[!] Java installation may be incomplete${NC}"
    fi
else
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')
    echo -e "${GREEN}[✓] Java ${JAVA_VERSION} detected${NC}"
fi

echo

# ============================================================================
# Check/Install Android RE Tools
# ============================================================================

echo -e "${YELLOW}[3/12] Checking Android RE tools...${NC}"

MISSING_TOOLS=()

if ! command -v aapt &> /dev/null; then
    MISSING_TOOLS+=("aapt")
fi

if ! command -v apktool &> /dev/null; then
    MISSING_TOOLS+=("apktool")
fi

if ! command -v jadx &> /dev/null; then
    MISSING_TOOLS+=("jadx")
fi

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    echo -e "${GREEN}[✓] All Android RE tools installed${NC}"
    echo -e "${DIM}    aapt:    $(command -v aapt)${NC}"
    echo -e "${DIM}    apktool: $(command -v apktool)${NC}"
    echo -e "${DIM}    jadx:    $(command -v jadx)${NC}"
else
    echo -e "${YELLOW}[!] Missing tools: ${MISSING_TOOLS[*]}${NC}"
    echo -e "${CYAN}[*] Attempting to install Android RE tools...${NC}"
    
    INSTALL_METHOD=""
    
    case "$DISTRO" in
        arch|archcraft|manjaro)
            INSTALL_METHOD="arch"
            # Install jadx from official repos
            if ! command -v jadx &> /dev/null; then
                sudo pacman -Sy --noconfirm --needed jadx
            fi
            
            # Check for AUR helper
            AUR_HELPER=""
            if command -v yay &> /dev/null; then
                AUR_HELPER="yay"
            elif command -v paru &> /dev/null; then
                AUR_HELPER="paru"
            elif command -v trizen &> /dev/null; then
                AUR_HELPER="trizen"
            fi
            
            if [ -n "$AUR_HELPER" ]; then
                echo -e "${CYAN}[*] Using AUR helper: $AUR_HELPER${NC}"
                
                # Install apktool from AUR
                if ! command -v apktool &> /dev/null; then
                    $AUR_HELPER -S --noconfirm --needed android-apktool-bin
                fi
                
                # Install aapt from AUR
                if ! command -v aapt &> /dev/null; then
                    $AUR_HELPER -S --noconfirm --needed android-sdk-build-tools
                fi
            else
                echo -e "${RED}[✗] No AUR helper found (yay, paru, trizen)${NC}"
                INSTALL_METHOD="fallback"
            fi
            ;;
            
        ubuntu|debian|kali|parrot|linuxmint|pop)
            INSTALL_METHOD="debian"
            sudo apt-get update
            sudo apt-get install -y aapt apktool jadx 2>/dev/null || INSTALL_METHOD="fallback"
            ;;
            
        alpine)
            INSTALL_METHOD="alpine"
            # Enable testing repo for android-apktool
            if ! grep -q "testing" /etc/apk/repositories; then
                echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" | sudo tee -a /etc/apk/repositories
            fi
            sudo apk update
            sudo apk add android-tools android-apktool jadx 2>/dev/null || INSTALL_METHOD="fallback"
            ;;
            
        opensuse*|sles)
            INSTALL_METHOD="opensuse"
            # Try zypper first
            sudo zypper refresh
            sudo zypper install -y android-tools apktool jadx 2>/dev/null || INSTALL_METHOD="snap_fallback"
            ;;
            
        fedora|rhel|centos|rocky|alma)
            INSTALL_METHOD="redhat"
            # Try EPEL first for RHEL-based
            if [[ "$DISTRO" =~ ^(rhel|centos|rocky|alma)$ ]]; then
                sudo dnf install -y epel-release 2>/dev/null || true
            fi
            sudo dnf install -y android-tools apktool jadx 2>/dev/null || INSTALL_METHOD="snap_fallback"
            ;;
            
        gentoo)
            INSTALL_METHOD="gentoo"
            sudo emerge --ask=n dev-util/android-tools dev-util/apktool dev-java/jadx 2>/dev/null || INSTALL_METHOD="fallback"
            ;;
            
        void)
            INSTALL_METHOD="void"
            sudo xbps-install -Sy android-tools apktool jadx 2>/dev/null || INSTALL_METHOD="fallback"
            ;;
            
        *)
            INSTALL_METHOD="fallback"
            ;;
    esac
    
    # Snap fallback for distros that support it
    if [ "$INSTALL_METHOD" = "snap_fallback" ]; then
        if command -v snap &> /dev/null; then
            echo -e "${CYAN}[*] Trying Snap packages...${NC}"
            if ! command -v apktool &> /dev/null; then
                sudo snap install apktool 2>/dev/null || true
            fi
            if ! command -v jadx &> /dev/null; then
                sudo snap install jadx 2>/dev/null || true
            fi
            # aapt not available as snap, will use fallback
        fi
        INSTALL_METHOD="fallback"
    fi
    
    # Universal fallback - download pre-built binaries
    if [ "$INSTALL_METHOD" = "fallback" ]; then
        echo -e "${CYAN}[*] Using universal binary installation method...${NC}"
        
        TOOLS_BIN_DIR="$SCRIPT_DIR/tools/bin"
        mkdir -p "$TOOLS_BIN_DIR"
        
        # Install apktool
        if ! command -v apktool &> /dev/null; then
            echo -e "${CYAN}[*] Downloading apktool...${NC}"
            cd "$TOOLS_BIN_DIR"
            curl -LO https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
            curl -LO https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
            mv apktool_2.9.3.jar apktool.jar
            chmod +x apktool
            sudo ln -sf "$TOOLS_BIN_DIR/apktool" /usr/local/bin/apktool
            cd "$SCRIPT_DIR"
        fi
        
        # Install jadx
        if ! command -v jadx &> /dev/null; then
            echo -e "${CYAN}[*] Downloading jadx...${NC}"
            cd "$TOOLS_BIN_DIR"
            JADX_VERSION="1.5.0"
            curl -LO "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
            unzip -q "jadx-${JADX_VERSION}.zip" -d jadx
            chmod +x jadx/bin/jadx jadx/bin/jadx-gui
            sudo ln -sf "$TOOLS_BIN_DIR/jadx/bin/jadx" /usr/local/bin/jadx
            sudo ln -sf "$TOOLS_BIN_DIR/jadx/bin/jadx-gui" /usr/local/bin/jadx-gui
            rm "jadx-${JADX_VERSION}.zip"
            cd "$SCRIPT_DIR"
        fi
        
        # Install aapt (from Android SDK build-tools)
        if ! command -v aapt &> /dev/null; then
            echo -e "${CYAN}[*] Downloading aapt...${NC}"
            cd "$TOOLS_BIN_DIR"
            AAPT_VERSION="35.0.2"
            curl -LO "https://dl.google.com/android/repository/build-tools_r${AAPT_VERSION}-linux.zip"
            unzip -q "build-tools_r${AAPT_VERSION}-linux.zip" -d build-tools
            chmod +x build-tools/android-*/aapt
            sudo ln -sf "$TOOLS_BIN_DIR/build-tools/android-"*/aapt /usr/local/bin/aapt
            rm "build-tools_r${AAPT_VERSION}-linux.zip"
            cd "$SCRIPT_DIR"
        fi
    fi
    
    # Verify installation
    echo -e "${CYAN}[*] Verifying installation...${NC}"
    INSTALL_SUCCESS=true
    
    if ! command -v aapt &> /dev/null; then
        echo -e "${RED}[✗] aapt installation failed${NC}"
        INSTALL_SUCCESS=false
    fi
    if ! command -v apktool &> /dev/null; then
        echo -e "${RED}[✗] apktool installation failed${NC}"
        INSTALL_SUCCESS=false
    fi
    if ! command -v jadx &> /dev/null; then
        echo -e "${RED}[✗] jadx installation failed${NC}"
        INSTALL_SUCCESS=false
    fi
    
    if [ "$INSTALL_SUCCESS" = true ]; then
        echo -e "${GREEN}[✓] Android RE tools installed successfully${NC}"
        if [ "$INSTALL_METHOD" = "fallback" ]; then
            echo -e "${DIM}    Installed to: $TOOLS_BIN_DIR${NC}"
        fi
    else
        echo -e "${RED}[✗] Some tools failed to install${NC}"
        echo -e "${YELLOW}[!] Manual installation required:${NC}"
        echo -e "${DIM}    - aapt:    https://developer.android.com/studio/releases/build-tools${NC}"
        echo -e "${DIM}    - apktool: https://apktool.org${NC}"
        echo -e "${DIM}    - jadx:    https://github.com/skylot/jadx/releases${NC}"
        exit 1
    fi
fi
echo

# ============================================================================
# Check Go Compiler
# ============================================================================

echo -e "${YELLOW}[4/12] Checking Go compiler...${NC}"

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

echo -e "${YELLOW}[5/12] Checking pip installation...${NC}"

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
# Installation Configuration
# ============================================================================

echo -e "${YELLOW}[6/12] Configuring installation...${NC}"
echo -e "${GREEN}[✓] Installing full suite with all dependencies${NC}"
echo

# ============================================================================
# Install Python Dependencies
# ============================================================================

echo -e "${YELLOW}[7/12] Installing Python dependencies...${NC}"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo -e "${RED}[✗] requirements.txt not found!${NC}"
    exit 1
fi

# Use full requirements file
TEMP_REQ=$(mktemp)
cp "$REQUIREMENTS_FILE" "$TEMP_REQ"

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
# Install Elite Components (masscan)
# ============================================================================

echo -e "${YELLOW}[8/12] Installing masscan...${NC}"

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

# ============================================================================
# Compile Go Binary
# ============================================================================

echo -e "${YELLOW}[9/12] Compiling SecV binary...${NC}"

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

echo -e "${YELLOW}[10/12] Setting up directory structure...${NC}"

TOOLS_DIR="$SCRIPT_DIR/tools"
CACHE_DIR="$SCRIPT_DIR/.cache"

mkdir -p "$TOOLS_DIR"
mkdir -p "$CACHE_DIR"

echo -e "${GREEN}[✓] Directories created${NC}"
echo

# ============================================================================
# Set Permissions
# ============================================================================

echo -e "${YELLOW}[11/12] Setting permissions...${NC}"

chmod +x "$SCRIPT_DIR/secV" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/install.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/uninstall.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/update.py" 2>/dev/null || true

echo -e "${GREEN}[✓] Permissions set${NC}"
echo

# ============================================================================
# System-Wide Installation (Optional)
# ============================================================================

echo -e "${YELLOW}[12/12] System-wide installation...${NC}"

read -p "Install SecV system-wide to /usr/local/bin? [y/N]: " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "$SECV_BIN" ]; then
        sudo ln -sf "$SECV_BIN" /usr/local/bin/secV
        echo -e "${GREEN}[✓] SecV installed to /usr/local/bin/secV${NC}"
        echo -e "${DIM}    You can now run 'secV' from anywhere${NC}"
        SYSTEM_WIDE=true
    else
        echo -e "${YELLOW}[!] Binary not found, skipping system-wide install${NC}"
        SYSTEM_WIDE=false
    fi
else
    echo -e "${CYAN}[*] Skipped system-wide installation${NC}"
    echo -e "${DIM}    Run with: ./secV${NC}"
    SYSTEM_WIDE=false
fi
echo

# ============================================================================
# Installation Complete
# ============================================================================

echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║                   Installation Complete! ✓                        ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo

echo -e "${BOLD}SecV v${VERSION}${NC}"
echo

echo -e "${CYAN}${BOLD}Quick Start:${NC}"
if [ "$SYSTEM_WIDE" = true ]; then
    echo -e "  ${GREEN}secV${NC}                    # Start SecV"
else
    echo -e "  ${GREEN}./secV${NC}                  # Start SecV"
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
if [ "$SYSTEM_WIDE" = true ]; then
    echo -e "  ${GREEN}${BOLD}secV${NC}"
else
    echo -e "  ${GREEN}${BOLD}./secV${NC}"
fi
echo
