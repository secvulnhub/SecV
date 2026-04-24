# MAC Address Spoofer v2.0

**Category:** Network  
**Author:** 0xb0rn3 (oxbv1)  
**Platform:** Linux (iproute2)  
**Privileges:** Root/Sudo Required

---

## Overview

Automated MAC address spoofer with background daemon support. Changes MAC addresses at configurable intervals using locally-administered OUI prefix (02:00:00) to minimize network conflicts. Each interface runs an independent background process with state tracking for graceful management.

## Features

- **Per-Interface Daemons** - Each interface gets its own background process
- **State Persistence** - Tracks original MACs and PIDs for proper restoration
- **Locally-Administered MACs** - Uses 02:00:00 prefix to avoid vendor conflicts
- **Multi-Interface Support** - Single, multiple, or all UP interfaces
- **Dry Run Mode** - Test without making changes
- **Configurable Interval** - Adjust MAC rotation speed (0.1-60 seconds)
- **Status Monitoring** - Check running spoofers and their state
- **Automatic Restoration** - Original MACs restored when stopping

## Installation

### Prerequisites

```bash
# Linux with iproute2 (ip command)
apt-get install iproute2  # Debian/Ubuntu
yum install iproute       # RHEL/CentOS

# Python 3.6+
python3 --version

# Root privileges
sudo -v
```

### Setup

```bash
# Module is already installed with SecV
# No additional dependencies required
```

## Quick Start

### Basic Usage

```bash
# Start SecV with root privileges
sudo secV

# Load the module
secV > use mac_spoof

# Spoof a single interface
secV (mac_spoof) > set iface wlan0
secV (mac_spoof) > run target

# Check status
secV (mac_spoof) > set action status
secV (mac_spoof) > run target

# Stop spoofer (restores original MAC)
secV (mac_spoof) > set action stop
secV (mac_spoof) > run target
```

## Parameters

### iface
**Type:** String  
**Required:** No (if all_up is true)  
**Default:** None

Interface name or comma-separated list of interfaces.

**Examples:**
```bash
set iface wlan0           # Single interface
set iface eth0,wlan0      # Multiple interfaces
```

### all_up
**Type:** Boolean  
**Required:** No  
**Default:** false

Select all non-loopback interfaces currently UP.

**Examples:**
```bash
set all_up true           # Use all UP interfaces
set all_up false          # Manual interface selection
```

### action
**Type:** String  
**Required:** No  
**Default:** start

Operation to perform: start, stop, or status.

**Examples:**
```bash
set action start          # Start spoofer daemon
set action stop           # Stop and restore MAC
set action status         # Check spoofer status
```

### dry_run
**Type:** Boolean  
**Required:** No  
**Default:** false

Preview actions without making changes.

**Examples:**
```bash
set dry_run true          # Test without changes
set dry_run false         # Execute normally
```

### interval
**Type:** Number  
**Required:** No  
**Default:** 0.5

Seconds between MAC address changes.

**Examples:**
```bash
set interval 0.5          # Fast rotation (default)
set interval 5.0          # Slower, more stable
set interval 1.0          # Moderate speed
```

## Usage Examples

### Example 1: Basic Interface Spoofing

Start MAC spoofing on a wireless interface:

```bash
sudo secV
secV > use mac_spoof
secV (mac_spoof) > set iface wlan0
secV (mac_spoof) > run target
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "action": "start",
    "results": {
      "wlan0": {
        "success": true,
        "message": "Started spoofer for wlan0",
        "pid": 12345,
        "original_mac": "aa:bb:cc:dd:ee:ff",
        "interval": 0.5
      }
    }
  }
}
```

### Example 2: Multiple Interfaces

Spoof multiple interfaces simultaneously:

```bash
secV (mac_spoof) > set iface eth0,wlan0
secV (mac_spoof) > run target
```

### Example 3: All UP Interfaces

Automatically spoof all active interfaces:

```bash
secV (mac_spoof) > set all_up true
secV (mac_spoof) > run target
```

### Example 4: Check Status

Monitor running spoofers:

```bash
secV (mac_spoof) > set action status
secV (mac_spoof) > set all_up true
secV (mac_spoof) > run target
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "action": "status",
    "results": {
      "wlan0": {
        "interface": "wlan0",
        "running": true,
        "pid": 12345,
        "original_mac": "aa:bb:cc:dd:ee:ff",
        "current_mac": "02:00:00:1a:2b:3c",
        "uptime_seconds": 120
      }
    }
  }
}
```

### Example 5: Stop and Restore

Stop spoofer and restore original MAC:

```bash
secV (mac_spoof) > set iface wlan0
secV (mac_spoof) > set action stop
secV (mac_spoof) > run target
```

**Expected Output:**
```json
{
  "success": true,
  "data": {
    "action": "stop",
    "results": {
      "wlan0": {
        "success": true,
        "message": "Stopped spoofer for wlan0",
        "restored_mac": "aa:bb:cc:dd:ee:ff"
      }
    }
  }
}
```

### Example 6: Dry Run Testing

Test configuration without making changes:

```bash
secV (mac_spoof) > set iface wlan0
secV (mac_spoof) > set dry_run true
secV (mac_spoof) > run target
```

### Example 7: Slower Rotation

Use slower MAC changes for better stability:

```bash
secV (mac_spoof) > set iface wlan0
secV (mac_spoof) > set interval 5.0
secV (mac_spoof) > run target
```

## Technical Details

### MAC Address Format

Generated MACs use locally-administered format:
- **First octet:** `02` (locally administered, unicast)
- **Second/third octets:** `00:00` (consistent prefix)
- **Last three octets:** Random (XX:XX:XX)

**Example:** `02:00:00:1a:2b:3c`

### State Management

State files are stored in: `~/.secv/mac_spoof/`

**State file format:**
```json
{
  "interface": "wlan0",
  "pid": 12345,
  "original_mac": "aa:bb:cc:dd:ee:ff",
  "started": 1696512345.678
}
```

### Process Management

Each spoofer runs as a detached background daemon:
1. Fork process
2. Detach from terminal (setsid)
3. Redirect stdout/stderr to /dev/null
4. Enter infinite MAC rotation loop
5. Handle termination signals

### MAC Change Process

For each rotation:
1. Bring interface down (`ip link set <iface> down`)
2. Change MAC address (`ip link set <iface> address <mac>`)
3. Bring interface up (`ip link set <iface> up`)
4. Wait for interval duration
5. Repeat

## Important Warnings

### Network Impact

- **Active Connections Lost:** Changing MAC breaks TCP connections, DHCP leases, WiFi associations
- **Network Instability:** Rapid changes may confuse network equipment
- **Driver Compatibility:** Some drivers don't handle frequent MAC changes well

### Security Considerations

- **Root Access Required:** Must run SecV with sudo
- **Detection Risk:** May trigger IDS/IPS alerts
- **Legal Requirements:** Only use in authorized environments
- **Audit Trail:** State files track spoofer activity

### Best Practices

1. **Test First:** Use dry_run mode before executing
2. **Slower is Better:** Use intervals of 5+ seconds for stability
3. **Monitor Status:** Regularly check spoofer status
4. **Clean Shutdown:** Always stop spoofers before system shutdown
5. **Lab Only:** Use in isolated lab environments

## Troubleshooting

### Common Issues

**Error: Root privileges required**
```bash
# Solution: Run SecV with sudo
sudo secV
```

**Error: No interfaces specified**
```bash
# Solution: Set iface parameter or enable all_up
secV (mac_spoof) > set iface wlan0
# OR
secV (mac_spoof) > set all_up true
```

**Interface goes down after spoofing**
```bash
# Some drivers require manual bring-up
sudo ip link set wlan0 up
```

**Spoofer process dies unexpectedly**
```bash
# Check system logs
dmesg | tail -20
journalctl -n 50

# Increase interval for stability
secV (mac_spoof) > set interval 5.0
```

### Checking Logs

```bash
# View kernel messages
dmesg | grep -i "mac\|eth\|wlan"

# Check network interface logs
journalctl -u NetworkManager

# Monitor MAC changes in real-time
watch -n 1 'ip link show wlan0 | grep link/ether'
```

### Manual Cleanup

If spoofer crashes or state becomes corrupted:

```bash
# Kill all spoofer processes
pkill -f "mac_spoof.py"

# Remove state files
rm -rf ~/.secv/mac_spoof/*.json

# Manually restore MAC (if needed)
sudo ip link set wlan0 down
sudo ip link set wlan0 address AA:BB:CC:DD:EE:FF
sudo ip link set wlan0 up
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✓ Supported | Requires iproute2 |
| macOS | ✗ Not supported | Different interface management |
| Windows | ✗ Not supported | Different network stack |

## Dependencies

- **Python:** 3.6 or later (stdlib only)
- **iproute2:** ip command for interface management
- **Root:** sudo/root privileges required

## Performance

- **CPU Impact:** Minimal (~0.1% per interface)
- **Memory:** ~5MB per spoofer process
- **Network Overhead:** Brief disconnection per MAC change (~100ms)

## Security Notes

### Anonymity Considerations

While MAC spoofing provides some anonymity:
- **Limited Scope:** Only affects local network layer
- **Other Identifiers:** IP, hostname, traffic patterns remain
- **Timing Analysis:** MAC change patterns may be detectable
- **Application Layer:** Higher protocols can leak identity

### Detection Methods

Network administrators may detect MAC spoofing via:
- Frequent ARP cache changes
- MAC address OUI mismatches
- Rapid DHCP requests
- Switch port security violations
- Wireless association patterns

## License

Part of SecV - MIT License

## Contributing

Improvements welcome! Submit PRs to the SecV repository.

## Support

- **Issues:** GitHub Issues
- **Documentation:** SecV Wiki
- **Community:** SecV Discussions

---

**Remember:** Only use this tool in authorized lab environments or with explicit permission. Unauthorized MAC spoofing may violate network policies and laws.
