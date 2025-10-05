# Advanced Port Scanner Module v3.0

High-performance Python port scanner for SecV with CIDR support, stealth capabilities, and multi-method scanning.

## Installation

### Quick Setup

```bash
cd ~/SecV/tools/scanning/portscan
chmod +x portscan.py

# Test basic functionality
echo '{"target":"127.0.0.1","params":{"ports":"22,80,443"}}' | python3 portscan.py
```

### Installation Tiers

**Basic (No Dependencies)**
```bash
# Works out of the box with Python stdlib
# Features: TCP connect scan, service detection
./secV
secV ➤ use portscan
secV (portscan) ➤ run 192.168.1.1
```

**Standard (Recommended)**
```bash
# Install scapy for SYN scanning
pip3 install scapy --user --break-system-packages

# Features: + SYN stealth scan, ICMP ping sweep
sudo ./secV  # Requires root for SYN scan
secV ➤ use portscan
secV (portscan) ➤ set scan_type syn
secV (portscan) ➤ set stealth true
secV (portscan) ➤ run 192.168.1.0/24
```

**Full (All Features)**
```bash
# Install all optional dependencies
pip3 install scapy requests dnspython --user --break-system-packages

# Features: + HTTP detection, DNS resolution
```

## Quick Start Guide

### 1. Basic Scan
```bash
secV ➤ use portscan
secV (portscan) ➤ run 192.168.1.1
# Scans top 20 most common ports
```

### 2. Scan Entire Subnet
```bash
secV (portscan) ➤ set ports web
secV (portscan) ➤ run 192.168.1.0/24
# Scans all hosts in subnet for web ports
```

### 3. Fast Aggressive Scan
```bash
secV (portscan) ➤ set ports top-100
secV (portscan) ➤ set threads 200
secV (portscan) ➤ set timeout 0.5
secV (portscan) ➤ run 10.0.0.1-254
# Fast scan of IP range
```

### 4. Stealth SYN Scan (Requires Root)
```bash
sudo secV
secV ➤ use portscan
secV (portscan) ➤ set scan_type syn
secV (portscan) ➤ set stealth true
secV (portscan) ➤ set ping_sweep true
secV (portscan) ➤ run 192.168.1.0/24
```

## Target Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.1` | Scan one host |
| CIDR | `192.168.1.0/24` | Scan subnet (254 hosts) |
| Range | `192.168.1.1-50` | Scan IP range |
| Multiple | `192.168.1.1,192.168.1.10,10.0.0.1` | Comma-separated |
| Hostname | `example.com` | Domain name |

## Port Specifications

### Presets
- `top-20` - 20 most common ports (fastest)
- `top-100` - Top 100 ports
- `top-1000` - Top 1000 ports
- `web` - Web services (80,443,8080,8443,etc)
- `database` - Database ports (3306,5432,27017,etc)
- `mail` - Mail servers (25,110,143,587,etc)
- `common` - Most commonly used ports
- `all` - All 65535 ports (very slow!)

### Custom Formats
- Single: `80` or `22,80,443`
- Range: `1-1000` or `8000-9000`
- Mixed: `22,80,443,8000-9000`

## Scan Types

### TCP Connect (Default)
```bash
set scan_type connect
```
- Works everywhere (no special privileges)
- Most compatible
- Slightly slower than SYN
- Leaves connection logs

### SYN Stealth (Advanced)
```bash
set scan_type syn
```
- Requires: scapy + root/sudo
- Faster than connect
- Less detectable (doesn't complete handshake)
- May bypass some firewalls

### UDP Scan
```bash
set scan_type udp
```
- Scans UDP ports
- Much slower than TCP
- Results often inconclusive (open|filtered)
- Good for DNS, DHCP, SNMP

## Performance Tuning

### Local Network (Fast)
```bash
set threads 200
set timeout 0.5
set ports top-100
```

### Internet Hosts (Balanced)
```bash
set threads 100
set timeout 2.0
set ports common
```

### Large Subnets (Efficient)
```bash
set ping_sweep true
set threads 150
set timeout 1.0
```

### All Ports (Comprehensive)
```bash
set ports all
set threads 500
set timeout 0.3
# Expect 10-30 minutes per host
```

## Features

### Service Detection
Automatically identifies services running on open ports:
- HTTP/HTTPS servers with version
- SSH with version
- FTP, SMTP, MySQL, PostgreSQL
- And more...

```bash
set service_detect true
```

### Banner Grabbing
Captures service banners for analysis:
```json
{
  "port": 22,
  "service": "ssh",
  "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
}
```

### Stealth Features
- SYN scanning (half-open connections)
- Custom source ports
- ICMP ping sweep for host discovery
- Randomized port order

## Examples

### Example 1: Quick Network Discovery
```bash
secV ➤ use portscan
secV (portscan) ➤ set ports common
secV (portscan) ➤ set ping_sweep true
secV (portscan) ➤ run 192.168.1.0/24
```

### Example 2: Web Server Audit
```bash
secV (portscan) ➤ set ports web
secV (portscan) ➤ set service_detect true
secV (portscan) ➤ set threads 50
secV (portscan) ➤ run company.com
```

### Example 3: Database Server Scan
```bash
secV (portscan) ➤ set ports database
secV (portscan) ➤ set verbose true
secV (portscan) ➤ run 10.0.0.50
```

### Example 4: Stealth Penetration Test
```bash
# Requires root
sudo secV
secV ➤ use portscan
secV (portscan) ➤ set scan_type syn
secV (portscan) ➤ set stealth true
secV (portscan) ➤ set source_port 53
secV (portscan) ➤ set ping_sweep true
secV (portscan) ➤ run 192.168.100.0/24
```

## Output Format

```json
{
  "success": true,
  "data": {
    "scan_info": {
      "version": "3.0.0",
      "scan_type": "connect",
      "duration": "45.23s",
      "threads": 100
    },
    "statistics": {
      "total_ports_scanned": 5080,
      "open_ports": 23,
      "closed_ports": 5050,
      "filtered_ports": 7
    },
    "results": [
      {
        "host": "192.168.1.1",
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH_8.2p1",
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "response_time": 0.023,
        "scan_method": "connect"
      }
    ]
  }
}
```

## Troubleshooting

### "Permission denied" for SYN scan
```bash
# Solution: Run with sudo
sudo secV
```

### "Scapy not available"
```bash
# Solution: Install scapy
pip3 install scapy --user --break-system-packages
```

### Slow scans
```bash
# Solution: Increase threads, lower timeout
set threads 200
set timeout 0.5
```

### No open ports found
```bash
# Solution: Try different scan type or increase timeout
set scan_type syn
set timeout 2.0
```

### Firewall blocking scans
```bash
# Solution: Use stealth mode
set stealth true
set source_port 53
```

## Legal & Ethical Use

**⚠️ AUTHORIZATION REQUIRED**

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security audits of your own systems
- ✅ Network administration tasks
- ✅ Educational purposes on isolated networks

**NEVER use this tool to:**
- ❌ Scan networks without explicit written permission
- ❌ Attack or harm systems
- ❌ Violate computer fraud laws
- ❌ Bypass security measures maliciously

**Unauthorized port scanning may violate:**
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in your jurisdiction

**Always:**
1. Obtain written authorization
2. Follow rules of engagement
3. Document your testing scope
4. Report findings responsibly

## Advanced Usage

### Scripting Example
```python
import subprocess
import json

config = {
    "target": "192.168.1.0/24",
    "params": {
        "ports": "top-100",
        "threads": 150,
        "service_detect": True
    }
}

result = subprocess.run(
    ["python3", "portscan.py"],
    input=json.dumps(config),
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)
print(f"Found {data['data']['statistics']['open_ports']} open ports")
```

### Integration with Other Tools
```bash
# Export results to file
secV (portscan) ➤ run 192.168.1.0/24 > scan_results.json

# Chain with vulnerability scanner
secV ➤ use portscan
secV (portscan) ➤ run 192.168.1.10
secV (portscan) ➤ back
secV ➤ use vuln-scan
secV (vuln-scan) ➤ run 192.168.1.10
```

## Performance Benchmarks

| Scenario | Threads | Time | Notes |
|----------|---------|------|-------|
| Single host, top-20 | 50 | ~2s | Quick check |
| Single host, top-1000 | 100 | ~15s | Standard scan |
| /24 subnet, common ports | 150 | ~2min | With ping sweep |
| Single host, all ports | 500 | ~8min | Comprehensive |

## Comparison with Other Tools

| Feature | SecV portscan | nmap | masscan |
|---------|--------------|------|---------|
| Installation | pip install | apt install | compile |
| SYN scan | ✅ | ✅ | ✅ |
| Service detection | ✅ | ✅ | ❌ |
| UDP scan | ✅ | ✅ | ❌ |
| CIDR support | ✅ | ✅ | ✅ |
| JSON output | ✅ | ✅ (xml) | ✅ |
| Speed | Fast | Medium | Fastest |
| Stealth | ✅ | ✅ | ❌ |

## Contributing

Found a bug or want to add a feature?
1. Fork the SecV repository
2. Create a feature branch
3. Add your changes to `tools/scanning/portscan/`
4. Test thoroughly
5. Submit a pull request

## Support

- **Documentation**: See inline help with `help module`
- **Issues**: GitHub Issues
- **Community**: GitHub Discussions

## License

MIT License - See LICENSE file

## Credits

- **Author**: SecVulnHub Team
- **Contributors**: SecV Community
- **Inspired by**: nmap, masscan, unicornscan

---

**Version**: 3.0.0  
**Last Updated**: 2025-10-05  
**Compatibility**: Python 3.8+, Linux/macOS/Windows
