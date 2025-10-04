#!/usr/bin/env bash
#
# SecV Uninstallation Script
# Removes system-wide SecV installation
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║   SecV Uninstaller                                                ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

INSTALL_PATH="/usr/local/bin/secV"

if [ -L "$INSTALL_PATH" ] || [ -f "$INSTALL_PATH" ]; then
    echo -e "${YELLOW}Found system-wide installation at: $INSTALL_PATH${NC}"
    read -p "Remove system-wide installation? [y/N]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -f "$INSTALL_PATH"
        echo -e "${GREEN}[✓] System-wide installation removed${NC}"
        echo -e "${YELLOW}[i] Local files in $(pwd) are preserved${NC}"
        echo -e "${YELLOW}[i] You can still run: ./secV${NC}"
    else
        echo -e "${YELLOW}[i] Uninstallation cancelled${NC}"
    fi
else
    echo -e "${YELLOW}[i] No system-wide installation found${NC}"
    echo -e "${YELLOW}[i] SecV is only installed locally${NC}"
fi

echo -e "\n${CYAN}To completely remove SecV, delete this directory:${NC}"
echo -e "${YELLOW}rm -rf $(pwd)${NC}\n"
