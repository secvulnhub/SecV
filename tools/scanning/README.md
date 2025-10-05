# PortScan - Advanced Multi-Engine Network Scanner

**Version:** 2.0.0  
**Author:** SecVulnHub Team  
**Category:** Scanning  
**Status:** Production Ready

---

## Overview

PortScan is a comprehensive, extensible port scanning module that intelligently selects the best available scanning method based on installed dependencies. It features multiple scan engines, service detection, banner grabbing, and graceful fallback when optional dependencies are missing.

### Key Features

✅ **Multi-Engine Support**
- TCP Connect Scan (always available)
- SYN Stealth Scan (requires scapy + root)
- Nmap Integration (requires python-nmap)

✅ **Advanced Detection**
- Service name and version detection
- Banner grabbing for 20+ services
- HTTP technology detection (WordPress, React, Angular, etc.)
- SSL/TLS certificate analysis

✅ **Performance**
- Concurrent scanning (up to 50 threads)
- Optimized port range handling
- Response time measurement
- Timeout management

✅ **Intelligent Fallback**
- Works with stdlib only (Basic tier)
- Gracefully handles missing dependencies
- Auto-selects best available engine

---

## Installation Tiers

### Basic (Always Works)
```bash
# No additional dependencies required
# Uses TCP connect scan only
```
**Capabilities:** Basic port scanning, service detection, banner grabbing

### Standard (Recommended)
```bash
pip3 install scapy
```
**Adds:** SYN stealth scanning (requires root privileges)

### Full
```bash
pip3 install scapy requests
```
**Adds:** HTTP technology detection, enhanced web service analysis

### Complete
```bash
pip3 install scapy requests python-nmap
```
**Adds:** Full nmap integration with comprehensive scanning options

---

## Quick Start

### Basic Usage

```bash
# Load module
secV > use portscan

# Scan with defaults (top 20 ports)
secV (portscan) > run example.com

# Get help
secV (portscan) > help module
```

### Common Scenarios

**1. Quick Reconnaissance**
```bash
secV > use portscan
secV (portscan) > run target.com
# Scans top 20 most common ports
```

**2. Web Server Assessment**
```bash
secV (portscan) > set ports web
secV (portscan) > run example.com
# Scans: 80, 443, 8000, 8080, 8443, 8888
```

**3. Database Server Scan**
```bash
secV (portscan) > set ports db
secV (portscan) > run 192.168.1.100
# Scans: 1433, 3306, 5432, 27017, 6379, 9200
```

**4. Comprehensive Network Scan**
```bash
secV (portscan) > set ports top-1000
secV (portscan) > set timeout 0.5
secV (portscan) > run 10.0.0.50
```

**5. Stealth SYN Scan** (requires root + scapy)
```bash
sudo ./secV
secV > use portscan
secV (portscan) > set engine syn
secV (portscan) > set ports 1-1000
secV (portscan) > run target.local
```

---

## Parameters

### ports
**Type:** string  
**Default:** `top-20`  
**Description:** Port specification

**Pre-defined Sets:**
- `top-20` - Top 20 most common ports (fastest)
- `top-100` - Top 100 ports
- `top-1000` - Top 1000 ports
- `common` - 20 most commonly used ports
- `web` - Web ports (80, 443, 8080, 8443, 8888)
- `db` - Database ports (MySQL, PostgreSQL, MongoDB, Redis, etc.)
- `all` - All 65535 ports (very slow!)

**Custom Formats:**
- Range: `1-1000`, `8000-9000`
- List: `80,443,8080,8443`
- Mixed: `80,443,8000-9000,22`

**Examples:**
```bash
set ports top-100
set ports 1-1000
set ports 80,443,8080,8443
set ports 22,80,443,8000-9000
```

### engine
**Type:** string  
**Default:** `auto`  
**Description:** Scan engine to use

**Options:**
- `auto` - Automatically select best available (recommended)
- `connect` - TCP connect scan (always works)
- `syn` - SYN stealth scan (requires scapy + root)
- `nmap` - Nmap integration (requires python-nmap)

**Examples:**
```bash
set engine auto        # Let PortScan choose
set engine connect     # Force connect scan
set engine syn         # Use SYN scan (needs root)
set engine nmap        # Use nmap backend
```

### timeout
**Type:** float  
**Default:** `1.0`  
**Range:** `0.1 - 10.0`  
**Description:** Timeout per port in seconds

Lower values = faster scans but may miss slower responses  
Higher values = more accurate but slower scans

**Examples:**
```bash
set timeout 0.5    # Fast scan for live hosts
set timeout 1.0    # Balanced (default)
set timeout 3.0    # Thorough scan
```

### detect_http
**Type:** boolean  
**Default:** `true`  
**Description:** Enable HTTP technology detection

When enabled, web ports (80, 443, 8080, etc.) are analyzed for:
- Server software and versions
- Web frameworks (WordPress, Joomla, React, Angular)
- Technologies in use
- HTTP headers

**Examples:**
```bash
set detect_http true   # Enable (default)
set detect_http false  # Disable for faster scans
```

---

## Output Format

### Success Response

```json
{
  "success": true,
  "data": {
    "target": "example.com",
    "scan_method": "ConnectScanEngine",
    "ports_scanned": 20,
    "ports_open": 3,
    "scan_duration": 2.45,
    "results": [
      {
        "port": 22,
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH_8.2",
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4",
        "protocol": "tcp",
        "response_time": 0.123
      },
      {
        "port": 80,
        "state": "open",
        "service": "http",
        "version": "nginx/1.18.0",
        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
        "protocol": "tcp",
        "response_time": 0.098
      }
    ],
    "capabilities": {
      "connect": true,
      "syn": false,
      "nmap": false,
      "http_tech": true,
      "banner_grab": true
    }
  },
  "errors": []
}
```

### Port Result Fields

- **port** (int) - Port number
- **state** (string) - Port state: `open`, `closed`, or `filtered`
- **service** (string) - Service name (e.g., `http`, `ssh`, `mysql`)
- **version** (string) - Service version if detected
- **banner** (string) - Service banner (first 200 chars)
- **protocol** (string) - Protocol (usually `tcp`)
- **response_time** (float) - Response time in seconds

---

## Architecture

### Scan Engine Selection Flow

```
User runs scan
    ↓
Check engine parameter
    ↓
engine == 'nmap' && HAS_NMAP? → Use NmapScanEngine
    ↓
engine == 'syn' && HAS_SCAPY? → Use SYNScanEngine
    ↓                            ↓ (if no root)
    ↓                            Fall back to ConnectScanEngine
    ↓
engine == 'auto'? → Select best available
    ↓
Use ConnectScanEngine (always works)
```

### Service Detection Pipeline

```
Port found open
    ↓
Get common service name from port number
    ↓
Attempt banner grabbing (with appropriate probe)
    ↓
Parse version from banner
    ↓
If web port && detect_http enabled → Detect HTTP technologies
    ↓
Return enriched result
```

---

## Service Fingerprints

PortScan includes fingerprints for 20+ common services:

| Port | Service | Detection Method |
|------|---------|------------------|
| 21 | FTP | Banner + AUTH probe |
| 22 | SSH | Banner parse |
| 25 | SMTP | EHLO probe |
| 53 | DNS | Service name |
| 80/8080 | HTTP | GET request + headers |
| 110 | POP3 | Banner |
| 143 | IMAP | Banner |
| 443/8443 | HTTPS | TLS handshake + GET |
| 445 | SMB | Service name |
| 3306 | MySQL | Protocol detection |
| 3389 | RDP | Service name |
| 5432 | PostgreSQL | Service name |
| 5900 | VNC | Banner |
| 6379 | Redis | Protocol probe |
| 8080 | HTTP-Proxy | GET request |
| 27017 | MongoDB | Service name |

---

## Performance Tuning

### Fast Scanning

```bash
# Minimize ports
set ports top-20

# Reduce timeout
set timeout 0.5

# Disable HTTP detection
set detect_http false

# Run
run target.com
```
**Result:** ~2-5 second scans

### Thorough Scanning

```bash
# More ports
set ports top-1000

# Longer timeout
set timeout 2.0

# Enable all features
set detect_http true

# Use SYN if available (faster than connect for many ports)
set engine syn

# Run
run target.com
```
**Result:** More comprehensive but slower

### Parallel Scanning

Use SecV's workflow system for multiple targets:

```bash
secV > workflow add use portscan
secV > workflow add set ports common
secV > workflow add run 192.168.1.1
secV > workflow add run 192.168.1.2
secV > workflow add run 192.168.1.3
secV > workflow run
```

---

## Troubleshooting

### "Module requires scapy for SYN scanning"

**Solution:**
```bash
pip3 install scapy
```

On Linux, you may also need:
```bash
sudo apt install libpcap-dev
```

### "Permission denied" when using SYN scan

**Solution:** SYN scanning requires raw socket access:
```bash
sudo ./secV
# Then use portscan with engine=syn
```

### Slow scanning

**Causes & Solutions:**

1. **Too many ports:**
   ```bash
   set ports top-100  # Instead of top-1000
   ```

2. **Timeout too high:**
   ```bash
   set timeout 0.5  # Reduce from default 1.0
   ```

3. **HTTP detection overhead:**
   ```bash
   set detect_http false
   ```

4. **Network latency:** Use SYN scan if available (faster):
   ```bash
   set engine syn
   ```

### No results / all ports closed

**Possible causes:**
- Firewall blocking scans
- Host is down (try ping first)
- Network connectivity issues
- Timeout too low for slow networks

**Solutions:**
```bash
# Increase timeout
set timeout 3.0

# Try different engine
set engine nmap

# Verify connectivity
ping target.com
```

---

## Examples

### Example 1: Web Application Assessment

```bash
secV > use portscan
secV (portscan) > set ports web
secV (portscan) > set detect_http true
secV (portscan) > run webapp.example.com

# Output will show:
# - Open web ports
# - Server software (Apache, nginx, etc.)
# - Frameworks (WordPress, React, etc.)
# - TLS/SSL info
```

### Example 2: Internal Network Discovery

```bash
secV > use portscan
secV (portscan) > set ports common
secV (portscan) > set timeout 0.5
secV (portscan) > run 192.168.1.50

# Fast scan of common services on internal network
```

### Example 3: Comprehensive Server Audit

```bash
sudo ./secV
secV > use portscan
secV (portscan) > set engine syn
secV (portscan) > set ports top-1000
secV (portscan) > set timeout 1.0
secV (portscan) > run production-server.local

# Thorough scan using stealth SYN method
```

### Example 4: Database Server Check

```bash
secV > use portscan
secV (portscan) > set ports db
secV (portscan) > run db-server.company.local

# Scans all common database ports:
# MySQL, PostgreSQL, MongoDB, Redis, etc.
```

---

## Development

### Adding New Service Fingerprints

Edit `portscan.py` and add to `ServiceFingerprinter.COMMON_SERVICES`:

```python
COMMON_SERVICES = {
    # ... existing services ...
    9200: "elasticsearch",
    9300: "elasticsearch-cluster",
}
```

And add probes if needed:

```python
SERVICE_PROBES = {
    # ... existing probes ...
    9200: b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
}
```

### Adding New Scan Engines

Create a new class inheriting from `ScanEngine`:

```python
class CustomScanEngine(ScanEngine):
    def scan(self) -> List[PortResult]:
        # Your scanning logic
        pass
```

Register in `PortScanner._select_engine()`.

---

## Security Considerations

### Ethical Use Only

PortScan is designed for **authorized security testing only**. Always:
- ✅ Obtain written authorization before scanning
- ✅ Respect scope limitations
- ✅ Follow responsible disclosure
- ✅ Comply with local laws

### Stealth Considerations

- **Connect Scan:** Leaves full connection logs
- **SYN Scan:** More stealthy, incomplete handshake
- **Nmap:** Depends on nmap arguments used

### Rate Limiting

Be mindful of scan rate to avoid:
- Triggering IDS/IPS systems
- Causing network congestion
- DoS effects on target

Adjust with `timeout` and consider adding delays between scans.

---

## FAQ

**Q: Why does SYN scan need root?**  
A: SYN scanning uses raw sockets which require elevated privileges to create and send custom TCP packets.

**Q: Can I scan IPv6 addresses?**  
A: Currently only IPv4 is supported. IPv6 support is planned for future versions.

**Q: How do I scan UDP ports?**  
A: UDP scanning is not yet implemented. Use nmap directly for UDP scans.

**Q: What's the fastest way to scan?**  
A: Use `ports=top-20`, `timeout=0.5`, `detect_http=false`, and `engine=syn` (if root available).

**Q: Can I export results?**  
A: Results are in JSON format. Pipe to file or use SecV's reporting modules.

---

## Changelog

### Version 2.0.0 (Current)
- Complete rewrite with multi-engine architecture
- Added SYN and nmap scan engine support
- Enhanced service detection with 20+ fingerprints
- HTTP technology detection
- Concurrent scanning with thread pool
- Pre-defined port sets (top-20, web, db, etc.)
- Graceful dependency handling
- Comprehensive help system integration

### Version 1.0.0
- Initial release
- Basic TCP connect scanning
- Simple service detection

---

## Contributing

Contributions welcome! Areas for improvement:

- [ ] IPv6 support
- [ ] UDP scanning
- [ ] OS fingerprinting
- [ ] More service fingerprints
- [ ] Custom scan profiles
- [ ] Result caching
- [ ] Progress indicators

See [CONTRIBUTING.md](../../../CONTRIBUTING.md) for guidelines.

---

## License

MIT License - See LICENSE file

---

## Support

- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Documentation:** This README + module help
- **Examples:** See `examples/` directory

---

## Credits

**Author:** SecVulnHub Team  
**Maintainers:** 0xbv1, 0xb0rn3

Special thanks to:
- nmap project for inspiration
- scapy developers
- SecV community contributors

---

**Remember:** Always scan responsibly and ethically! 🔒
