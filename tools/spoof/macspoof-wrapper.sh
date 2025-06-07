#!/bin/bash

# macspoof-wrapper.sh - Intelligent MAC spoofing wrapper for SecV
# This script reads JSON input from stdin and executes the appropriate
# macspoof binary based on the target platform or auto-detection

# Function to log messages to stderr (so they don't interfere with JSON output)
log_message() {
    echo "[MacSpoof] $1" >&2
}

# Function to detect the operating system
detect_platform() {
    local os_name=$(uname -s)
    case "$os_name" in
        Linux*)     echo "linux";;
        Darwin*)    echo "macos";;
        CYGWIN*|MINGW*|MSYS*) echo "windows";;
        *)          echo "unknown";;
    esac
}

# Function to validate MAC address format
validate_mac_address() {
    local mac="$1"
    if [[ $mac =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to get current MAC address of an interface
get_current_mac() {
    local interface="$1"
    local platform="$2"
    
    case "$platform" in
        "linux")
            if command -v ip &> /dev/null; then
                ip link show "$interface" 2>/dev/null | awk '/ether/ {print $2}'
            elif command -v ifconfig &> /dev/null; then
                ifconfig "$interface" 2>/dev/null | awk '/ether/ {print $2}'
            fi
            ;;
        "macos")
            ifconfig "$interface" 2>/dev/null | awk '/ether/ {print $2}'
            ;;
        "windows")
            # For Windows, this would typically use PowerShell
            # We'll call our PowerShell script to get the current MAC
            powershell.exe -File "./macspoof.ps1" -Action "get" -Interface "$interface" 2>/dev/null | grep "CurrentMAC" | cut -d':' -f2 | tr -d ' '
            ;;
    esac
}

# Function to execute the appropriate macspoof tool
execute_macspoof() {
    local interface="$1"
    local new_mac="$2"
    local platform="$3"
    local script_dir="$(dirname "$0")"
    
    case "$platform" in
        "linux")
            if [[ -x "$script_dir/macspoof-linux" ]]; then
                log_message "Using Linux binary"
                "$script_dir/macspoof-linux" "$interface" "$new_mac"
            elif [[ -x "$script_dir/macspoof.sh" ]]; then
                log_message "Using shell script"
                bash "$script_dir/macspoof.sh" "$interface" "$new_mac"
            else
                return 1
            fi
            ;;
        "macos")
            if [[ -x "$script_dir/macspoof.sh" ]]; then
                log_message "Using shell script for macOS"
                bash "$script_dir/macspoof.sh" "$interface" "$new_mac"
            else
                return 1
            fi
            ;;
        "windows")
            if [[ -x "$script_dir/macspoof.exe" ]] || [[ -f "$script_dir/macspoof" ]]; then
                log_message "Using Windows binary"
                "$script_dir/macspoof" "$interface" "$new_mac" 2>/dev/null || "$script_dir/macspoof.exe" "$interface" "$new_mac"
            elif [[ -f "$script_dir/macspoof.ps1" ]]; then
                log_message "Using PowerShell script"
                powershell.exe -ExecutionPolicy Bypass -File "$script_dir/macspoof.ps1" -Interface "$interface" -NewMAC "$new_mac"
            else
                return 1
            fi
            ;;
        *)
            log_message "Unsupported platform: $platform"
            return 1
            ;;
    esac
}

# Main execution starts here
main() {
    # Read JSON input from stdin (this is how SecV passes data to modules)
    local input_json=$(cat)
    
    # Parse the JSON to extract required parameters
    # Using basic JSON parsing with jq if available, or simple grep/sed as fallback
    if command -v jq &> /dev/null; then
        local target=$(echo "$input_json" | jq -r '.target // empty')
        local interface=$(echo "$input_json" | jq -r '.parameters.interface // empty')
        local new_mac=$(echo "$input_json" | jq -r '.parameters.mac_address // empty')
        local platform=$(echo "$input_json" | jq -r '.parameters.platform // empty')
    else
        # Fallback parsing without jq (less robust but functional)
        local target=$(echo "$input_json" | grep -o '"target"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
        local interface=$(echo "$input_json" | grep -o '"interface"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
        local new_mac=$(echo "$input_json" | grep -o '"mac_address"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
        local platform=$(echo "$input_json" | grep -o '"platform"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
    fi
    
    # Auto-detect platform if not specified
    if [[ -z "$platform" ]]; then
        platform=$(detect_platform)
        log_message "Auto-detected platform: $platform"
    fi
    
    # Validate required parameters
    if [[ -z "$interface" ]]; then
        echo '{"success": false, "errors": ["Interface parameter is required"], "data": null}'
        exit 1
    fi
    
    if [[ -z "$new_mac" ]]; then
        echo '{"success": false, "errors": ["MAC address parameter is required"], "data": null}'
        exit 1
    fi
    
    # Validate MAC address format
    if ! validate_mac_address "$new_mac"; then
        echo '{"success": false, "errors": ["Invalid MAC address format. Use XX:XX:XX:XX:XX:XX"], "data": null}'
        exit 1
    fi
    
    log_message "Starting MAC address change for interface: $interface"
    log_message "Target MAC: $new_mac"
    log_message "Platform: $platform"
    
    # Get current MAC address before change
    local old_mac=$(get_current_mac "$interface" "$platform")
    if [[ -z "$old_mac" ]]; then
        echo '{"success": false, "errors": ["Could not retrieve current MAC address. Interface may not exist."], "data": null}'
        exit 1
    fi
    
    log_message "Current MAC: $old_mac"
    
    # Check if MAC is already set to the desired value
    if [[ "$old_mac" == "$new_mac" ]]; then
        echo "{\"success\": true, \"errors\": [], \"data\": {\"old_mac\": \"$old_mac\", \"new_mac\": \"$new_mac\", \"interface\": \"$interface\", \"message\": \"MAC address already set to desired value\"}}"
        exit 0
    fi
    
    # Execute the MAC spoofing
    if execute_macspoof "$interface" "$new_mac" "$platform"; then
        # Verify the change was successful
        sleep 1  # Give the system a moment to apply the change
        local current_mac=$(get_current_mac "$interface" "$platform")
        
        if [[ "$current_mac" == "$new_mac" ]]; then
            log_message "MAC address successfully changed"
            echo "{\"success\": true, \"errors\": [], \"data\": {\"old_mac\": \"$old_mac\", \"new_mac\": \"$current_mac\", \"interface\": \"$interface\", \"message\": \"MAC address successfully changed\"}}"
        else
            log_message "MAC address change may have failed - verification shows: $current_mac"
            echo "{\"success\": false, \"errors\": [\"MAC address change verification failed\"], \"data\": {\"old_mac\": \"$old_mac\", \"attempted_mac\": \"$new_mac\", \"current_mac\": \"$current_mac\", \"interface\": \"$interface\"}}"
        fi
    else
        log_message "MAC spoofing command failed"
        echo "{\"success\": false, \"errors\": [\"MAC spoofing command execution failed\"], \"data\": {\"old_mac\": \"$old_mac\", \"interface\": \"$interface\"}}"
        exit 1
    fi
}

# Check if we're being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
