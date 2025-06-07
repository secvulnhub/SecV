#!/usr/bin/env bash
#MACSPOOF version 0.0.1 ~ by 0xbv1 LINUX MODULE
echo "Welcome to MACPOOF $USER"
echo "Detected OS: $(uname -s)"

# Function to detect the operating system and set appropriate commands
detect_os() {
    case "$(uname -s)" in
        Linux*)     
            OS_TYPE="Linux"
            # Linux uses 'ip' command (modern) or 'ifconfig' (legacy)
            if command -v ip &> /d]ev/null; then
                LIST_CMD="ip link show"
                CHANGE_CMD="ip link set dev"
            elif command -v ifconfig &> /dev/null; then
                LIST_CMD="ifconfig -a"
                CHANGE_CMD="ifconfig"
            else
                echo "Error: Neither 'ip' nor 'ifconfig' found. Cannot proceed."
                exit 1
            fi
            ;;
        Darwin*)    
            OS_TYPE="macOS"
            # macOS uses ifconfig
            LIST_CMD="ifconfig -a"
            CHANGE_CMD="ifconfig"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS_TYPE="Windows"
            echo "Warning: Windows detected. This bash script has limited functionality on Windows."
            echo "Consider using the PowerShell version instead."
            ;;
        FreeBSD*|OpenBSD*|NetBSD*)
            OS_TYPE="BSD"
            LIST_CMD="ifconfig -a"
            CHANGE_CMD="ifconfig"
            ;;
        *)
            OS_TYPE="Unknown"
            echo "Unknown operating system. Attempting to use standard commands..."
            LIST_CMD="ifconfig -a"
            CHANGE_CMD="ifconfig"
            ;;
    esac
}

# Function to validate MAC address format
# This regex works across all bash implementations
validate_mac() {
    local mac="$1"
    # Convert to lowercase for consistent checking
    mac=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
    
    # MAC address regex: 6 pairs of hex digits separated by colons
    # Using POSIX character classes for maximum compatibility
    if [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
        return 0  # Valid
    elif [[ $mac =~ ^([0-9a-f]{2}-){5}[0-9a-f]{2}$ ]]; then
        # Also accept dash-separated format and convert to colon format
        echo "Converting dash format to colon format..."
        echo "$mac" | tr '-' ':'
        return 0
    else
        return 1  # Invalid
    fi
}

# Function to validate interface name based on OS
validate_interface() {
    local interface="$1"
    
    case "$OS_TYPE" in
        Linux)
            # Check if interface exists using ip or ifconfig
            if command -v ip &> /dev/null; then
                ip link show "$interface" &>/dev/null
            else
                ifconfig "$interface" &>/dev/null
            fi
            ;;
        macOS|BSD)
            # Use ifconfig to check interface existence
            ifconfig "$interface" &>/dev/null
            ;;
        *)
            # Generic check - try ifconfig
            ifconfig "$interface" &>/dev/null 2>&1
            ;;
    esac
}

# Function to list available interfaces
list_interfaces() {
    echo "Available network interfaces:"
    case "$OS_TYPE" in
        Linux)
            if command -v ip &> /dev/null; then
                ip -o link show | awk -F': ' '{print $2}' | grep -v lo
            else
                ifconfig -a | grep -E '^[a-zA-Z0-9]' | awk '{print $1}' | sed 's/://'
            fi
            ;;
        macOS|BSD)
            ifconfig -l
            ;;
        *)
            ifconfig -a | grep -E '^[a-zA-Z0-9]' | awk '{print $1}' | sed 's/://'
            ;;
    esac
}

# Function to get current MAC address
get_current_mac() {
    local interface="$1"
    
    case "$OS_TYPE" in
        Linux)
            if command -v ip &> /dev/null; then
                ip link show "$interface" | awk '/ether/ {print $2}'
            else
                ifconfig "$interface" | awk '/ether|HWaddr/ {print $2}'
            fi
            ;;
        macOS)
            ifconfig "$interface" | awk '/ether/ {print $2}'
            ;;
        BSD)
            ifconfig "$interface" | awk '/ether/ {print $2}'
            ;;
        *)
            ifconfig "$interface" | grep -i 'ether\|hwaddr' | awk '{print $2}' | head -1
            ;;
    esac
}

# Function to change MAC address
change_mac_address() {
    local interface="$1"
    local new_mac="$2"
    
    echo "Bringing interface down..."
    case "$OS_TYPE" in
        Linux)
            if command -v ip &> /dev/null; then
                sudo ip link set dev "$interface" down
                sudo ip link set dev "$interface" address "$new_mac"
                sudo ip link set dev "$interface" up
            else
                sudo ifconfig "$interface" down
                sudo ifconfig "$interface" hw ether "$new_mac"
                sudo ifconfig "$interface" up
            fi
            ;;
        macOS)
            # macOS requires a different approach
            sudo ifconfig "$interface" ether "$new_mac"
            ;;
        BSD)
            sudo ifconfig "$interface" down
            sudo ifconfig "$interface" ether "$new_mac"
            sudo ifconfig "$interface" up
            ;;
        *)
            echo "Attempting generic MAC change..."
            sudo ifconfig "$interface" down
            sudo ifconfig "$interface" hw ether "$new_mac" 2>/dev/null || \
            sudo ifconfig "$interface" ether "$new_mac"
            sudo ifconfig "$interface" up
            ;;
    esac
}

# Main script execution starts here
detect_os
echo "Operating System: $OS_TYPE"

# Check for root privileges
if [[ $EUID -ne 0 ]] && [[ "$OS_TYPE" != "Windows" ]]; then
    echo "Warning: This script typically requires root privileges."
    echo "You may need to run with sudo or as root."
    read -p "Continue anyway? (y/N): " continue_choice
    if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Show available interfaces
echo ""
list_interfaces
echo ""

# Get interface with validation
while true; do
    read -p "Input INTERFACE needed to modify > " IF
    if validate_interface "$IF"; then
        echo "Interface $IF found."
        CURRENT_MAC=$(get_current_mac "$IF")
        echo "Current MAC address: $CURRENT_MAC"
        break
    else
        echo "Error: Interface '$IF' not found."
        echo "Please check available interfaces above."
    fi
done

# Get MAC address with validation
while true; do
    read -p "Input dummy MACADDRESS preferred (or 'random' for random MAC) > " MC
    
    if [[ "$MC" == "random" ]]; then
        # Generate a random MAC address
        # First byte: set bit 1 (locally administered) and clear bit 0 (unicast)
        MC=$(printf "02:%02x:%02x:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
        echo "Generated random MAC: $MC"
        break
    elif NORMALIZED_MAC=$(validate_mac "$MC"); then
        if [[ -n "$NORMALIZED_MAC" ]]; then
            MC="$NORMALIZED_MAC"  # Use normalized version if conversion happened
        fi
        echo "MAC address format is valid: $MC"
        break
    else
        echo "Error: Invalid MAC address format."
        echo "Please use format like aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff"
        echo "Or type 'random' for a random MAC address."
    fi
done

# Confirm the change
echo ""
echo "Ready to change MAC address:"
echo "  Interface: $IF"
echo "  From: $CURRENT_MAC"
echo "  To: $MC"
echo ""
read -p "Proceed with MAC address change? (y/N): " confirm

if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo "Changing MAC address..."
    if change_mac_address "$IF" "$MC"; then
        echo "MAC address change completed!"
        NEW_MAC=$(get_current_mac "$IF")
        echo "New MAC address: $NEW_MAC"
        
        # Verify the change
        if [[ "$NEW_MAC" == "$MC" ]]; then
            echo "✓ MAC address successfully changed!"
        else
            echo "⚠ Warning: MAC address may not have changed as expected."
            echo "This could be due to hardware limitations or driver restrictions."
        fi
    else
        echo "✗ Error: Failed to change MAC address."
        echo "This could be due to:"
        echo "  - Insufficient privileges"
        echo "  - Hardware/driver limitations"
        echo "  - Interface in use by active connections"
    fi
else
    echo "MAC address change cancelled."
fi

echo ""
echo "MACPOOF session completed."
