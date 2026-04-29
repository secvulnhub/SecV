#!/usr/bin/env bash
#
# SecV uninstall
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

INSTALL_PATH="/usr/local/bin/secV"

echo -e "${CYAN}secV uninstall${NC}\n"

if [ -L "$INSTALL_PATH" ] || [ -f "$INSTALL_PATH" ]; then
    echo -e "${YELLOW}found: $INSTALL_PATH${NC}"
    read -p "remove system-wide install? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -f "$INSTALL_PATH"
        echo -e "${GREEN}[✓] removed${NC}"
        echo -e "${DIM}local files in $(pwd) are unchanged${NC}"
    else
        echo -e "${DIM}cancelled${NC}"
    fi
else
    echo -e "${DIM}no system-wide install found${NC}"
fi

echo -e "\n${DIM}to fully remove: rm -rf $(pwd)${NC}\n"
