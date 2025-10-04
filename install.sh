#!/usr/bin/env bash
#
# SecV Installation Script
# Installs dependencies and optionally deploys SecV system-wide
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
║   SecV Installer - The Polyglot Security Platform                ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SECV_BIN="$SCRIPT_DIR/secV"

echo -e "${BLUE}[*] Starting SecV installation...${NC}\n"

# Check if Python 3 is installed
echo -e "${YELLOW}[1/5] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed!${NC}"
    echo -e "${YELLOW}    Please install Python 3.8 or later and try again.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo -e "${GREEN}[✓] Python $PYTHON_VERSION found${NC}\n"

# Check if pip is installed
echo -e "${YELLOW}[2/5] Checking pip installation...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip3 is not installed!${NC}"
    echo -e "${YELLOW}    Installing pip...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y python3-pip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        python3 -m ensurepip --upgrade
    else
        echo -e "${RED}[!] Unable to install pip automatically. Please install manually.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[✓] pip3 found${NC}\n"

# Install Python dependencies
echo -e "${YELLOW}[3/5] Installing Python dependencies...${NC}"
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    pip3 install -r "$SCRIPT_DIR/requirements.txt" --user
else
    echo -e "${CYAN}    Installing cmd2 and rich...${NC}"
    pip3 install cmd2 rich --user
fi
echo -e "${GREEN}[✓] Dependencies installed${NC}\n"

# Make SecV executable
echo -e "${YELLOW}[4/5] Setting executable permissions...${NC}"
chmod +x "$SECV_BIN"
echo -e "${GREEN}[✓] SecV is now executable${NC}\n"

# Test local execution
echo -e "${YELLOW}[5/5] Testing local installation...${NC}"
if [ -x "$SECV_BIN" ]; then
    echo -e "${GREEN}[✓] SecV can be run with: ./secV${NC}\n"
else
    echo -e "${RED}[!] Failed to make SecV executable${NC}"
    exit 1
fi

# Ask about system-wide installation
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}║   System-Wide Installation                                        ║${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${YELLOW}Would you like to install SecV system-wide?${NC}"
echo -e "${BLUE}This will allow you to run 'secV' from anywhere on your system.${NC}"
echo -e "${BLUE}Installation location: /usr/local/bin/secV${NC}\n"

read -p "Install system-wide? [y/N]: " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n${YELLOW}Installing system-wide (requires sudo)...${NC}"
    
    # Create symlink in /usr/local/bin
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
        
        # Add to shell profile if not already present
        SHELL_RC=""
        if [ -n "$ZSH_VERSION" ]; then
            SHELL_RC="$HOME/.zshrc"
        elif [ -n "$BASH_VERSION" ]; then
            SHELL_RC="$HOME/.bashrc"
        fi
        
        if [ -n "$SHELL_RC" ] && [ -f "$SHELL_RC" ]; then
            if ! grep -q "secV completion" "$SHELL_RC" 2>/dev/null; then
                echo -e "${YELLOW}Would you like to enable shell completion? [y/N]:${NC}"
                read -p "" -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    echo -e "\n# SecV completion" >> "$SHELL_RC"
                    echo "eval \"\$(register-python-argcomplete secV)\"" >> "$SHELL_RC" 2>/dev/null || true
                    echo -e "${GREEN}[✓] Shell completion enabled${NC}"
                    echo -e "${YELLOW}    Run 'source $SHELL_RC' or restart your shell${NC}"
                fi
            fi
        fi
    else
        echo -e "${RED}[!] Failed to install system-wide${NC}"
        echo -e "${YELLOW}    You can still run SecV with: ./secV${NC}"
    fi
else
    echo -e "\n${BLUE}[i] Local installation complete.${NC}"
    echo -e "${BLUE}    Run SecV with: ./secV${NC}"
    echo -e "${BLUE}    Or run this installer again to install system-wide.${NC}"
fi

# Create tools directory if it doesn't exist
if [ ! -d "$SCRIPT_DIR/tools" ]; then
    echo -e "\n${YELLOW}Creating tools directory...${NC}"
    mkdir -p "$SCRIPT_DIR/tools"
    echo -e "${GREEN}[✓] Tools directory created${NC}"
fi

# Installation summary
echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}║   Installation Complete!                                          ║${NC}"
echo -e "${CYAN}║                                                                   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}✓ SecV is ready to use!${NC}\n"

echo -e "${BLUE}Quick Start:${NC}"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "  ${YELLOW}secV${NC}                    # Start SecV shell"
else
    echo -e "  ${YELLOW}./secV${NC}                  # Start SecV shell"
fi
echo -e "  ${YELLOW}show modules${NC}            # List available modules"
echo -e "  ${YELLOW}use <module>${NC}            # Load a module"
echo -e "  ${YELLOW}run${NC}                     # Execute module"
echo -e "  ${YELLOW}help${NC}                    # Show all commands\n"

echo -e "${BLUE}Documentation:${NC}"
echo -e "  ${CYAN}https://github.com/SecVulnHub/SecV${NC}\n"

echo -e "${GREEN}Happy Hacking! 🔒${NC}\n"
