#!/usr/bin/env python3
"""
PortScan - Advanced Multi-Engine Network Scanner
Author: SecVulnHub Team
Version: 2.0.0

A comprehensive, extensible port scanning module with multiple scan engines,
service detection, and intelligent fallback mechanisms.
"""

import json
import sys
import socket
import struct
import time
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict

# Optional dependency detection
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    nmap = None

try:
    from scapy.all import sr1, IP, TCP, ICMP, conf
    conf.verb = 0  # Suppress scapy output
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None


@dataclass
class PortResult:
    """Represents a single port scan result"""
    port: int
    state: str  # open, closed, filtered
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    protocol: str = "tcp"
    response_time: float = 0.0
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ServiceFingerprinter:
    """Enhanced service detection and fingerprinting"""
    
    COMMON_SERVICES = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 80: "http", 110: "pop3",
        143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http-proxy", 8443: "https-alt", 27017: "mongodb"
    }
    
    SERVICE_PROBES = {
        80: b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        443: b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        21: b"USER anonymous\r\n",
        22: b"\r\n",
        25: b"EHLO scanner\r\n",
        3306: b"\x00\x00\x00\x0a",  # MySQL handshake
    }
    
    @staticmethod
    def get_service_name(port: int) -> str:
        """Get common service name for port"""
        return ServiceFingerprinter.COMMON_SERVICES.get(port, f"port-{port}")
    
    @staticmethod
    def grab_banner(host: str, port: int, timeout: float = 2.0) -> Tuple[str, str]:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send probe if available
            probe = ServiceFingerprinter.SERVICE_PROBES.get(port)
            if probe:
                sock.send(probe.replace(b"{}", host.encode()))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Parse version from banner
            version = ServiceFingerprinter._parse_version(banner)
            return banner[:200], version  # Limit banner length
            
        except Exception:
            return "", ""
    
    @staticmethod
    def _parse_version(banner: str) -> str:
        """Extract version information from banner"""
        # Common patterns
        patterns = [
            r'SSH-[\d\.]+-(OpenSSH_[\d\.]+)',
            r'Apache/([\d\.]+)',
            r'nginx/([\d\.]+)',
            r'MySQL ([\d\.]+)',
            r'Version ([\d\.]+)',
        ]
        
        import re
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return ""
    
    @staticmethod
    def detect_http_tech(host: str, port: int) -> Dict[str, Any]:
        """Detect HTTP technologies if available"""
        if not HAS_REQUESTS:
            return {}
        
        try:
            url = f"http://{host}:{port}" if port != 443 else f"https://{host}:{port}"
            resp = requests.get(url, timeout=3, verify=False, allow_redirects=False)
            
            tech = {
                'server': resp.headers.get('Server', ''),
                'powered_by': resp.headers.get('X-Powered-By', ''),
                'framework': '',
                'status': resp.status_code
            }
            
            # Detect frameworks from headers/content
            content = resp.text[:5000]
            if 'wp-content' in content or 'wordpress' in content.lower():
                tech['framework'] = 'WordPress'
            elif 'joomla' in content.lower():
                tech['framework'] = 'Joomla'
            elif '__next' in content or 'nextjs' in content.lower():
                tech['framework'] = 'Next.js'
            elif 'react' in content.lower() or '_react' in content:
                tech['framework'] = 'React'
            
            return tech
            
        except Exception:
            return {}


class ScanEngine:
    """Base class for scan engines"""
    
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.results: List[PortResult] = []
    
    def scan(self) -> List[PortResult]:
        """Execute scan - override in subclasses"""
        raise NotImplementedError


class ConnectScanEngine(ScanEngine):
    """TCP Connect scan - most compatible, no privileges required"""
    
    def scan(self) -> List[PortResult]:
        """Perform TCP connect scan"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)
        
        return self.results
    
    def _scan_port(self, port: int) -> Optional[PortResult]:
        """Scan single port with TCP connect"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            response_time = time.time() - start_time
            sock.close()
            
            if result == 0:
                service = ServiceFingerprinter.get_service_name(port)
                banner, version = ServiceFingerprinter.grab_banner(
                    self.target, port, self.timeout
                )
                
                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    version=version,
                    banner=banner,
                    response_time=response_time
                )
        except Exception:
            pass
        
        return None


class SYNScanEngine(ScanEngine):
    """SYN scan using Scapy - stealthy, requires root"""
    
    def scan(self) -> List[PortResult]:
        """Perform SYN scan"""
        if not HAS_SCAPY:
            raise RuntimeError("Scapy required for SYN scanning")
        
        for port in self.ports:
            result = self._syn_scan_port(port)
            if result:
                self.results.append(result)
        
        return self.results
    
    def _syn_scan_port(self, port: int) -> Optional[PortResult]:
        """SYN scan single port"""
        try:
            start_time = time.time()
            
            # Send SYN packet
            syn_packet = IP(dst=self.target)/TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            response_time = time.time() - start_time
            
            if response is None:
                return None  # Filtered or no response
            
            if response.haslayer(TCP):
                if response[TCP].flags == "SA":  # SYN-ACK
                    # Send RST to close connection
                    rst = IP(dst=self.target)/TCP(dport=port, flags="R")
                    sr1(rst, timeout=0.1, verbose=0)
                    
                    service = ServiceFingerprinter.get_service_name(port)
                    return PortResult(
                        port=port,
                        state="open",
                        service=service,
                        response_time=response_time
                    )
                elif response[TCP].flags == "RA":  # RST-ACK
                    return PortResult(
                        port=port,
                        state="closed",
                        response_time=response_time
                    )
        except Exception:
            pass
        
        return None


class NmapScanEngine(ScanEngine):
    """Nmap integration - comprehensive scanning"""
    
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0, 
                 scan_type: str = "-sV"):
        super().__init__(target, ports, timeout)
        self.scan_type = scan_type
    
    def scan(self) -> List[PortResult]:
        """Perform nmap scan"""
        if not HAS_NMAP:
            raise RuntimeError("python-nmap required for nmap scanning")
        
        nm = nmap.PortScanner()
        port_range = self._format_port_range()
        
        try:
            nm.scan(self.target, port_range, arguments=self.scan_type)
            
            if self.target in nm.all_hosts():
                for proto in nm[self.target].all_protocols():
                    for port in nm[self.target][proto].keys():
                        port_info = nm[self.target][proto][port]
                        
                        result = PortResult(
                            port=port,
                            state=port_info['state'],
                            service=port_info.get('name', 'unknown'),
                            version=port_info.get('version', ''),
                            protocol=proto
                        )
                        self.results.append(result)
        except Exception as e:
            print(f"Nmap scan error: {e}", file=sys.stderr)
        
        return self.results
    
    def _format_port_range(self) -> str:
        """Format ports for nmap"""
        if not self.ports:
            return "1-1000"
        
        # Optimize consecutive ports
        ports_sorted = sorted(self.ports)
        ranges = []
        start = ports_sorted[0]
        end = start
        
        for port in ports_sorted[1:]:
            if port == end + 1:
                end = port
            else:
                ranges.append(f"{start}-{end}" if start != end else str(start))
                start = end = port
        
        ranges.append(f"{start}-{end}" if start != end else str(start))
        return ",".join(ranges)


class PortScanner:
    """Main scanner orchestrator"""
    
    # Pre-defined port sets
    PORT_SETS = {
        'top-20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                   993, 995, 1723, 3306, 3389, 5900, 8080],
        'top-100': list(range(1, 101)),
        'top-1000': list(range(1, 1001)),
        'all': list(range(1, 65536)),
        'web': [80, 443, 8000, 8080, 8443, 8888],
        'db': [1433, 3306, 5432, 27017, 6379, 9200],
        'common': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]
    }
    
    def __init__(self, target: str, params: Dict[str, Any]):
        self.target = target
        self.params = params
        self.capabilities = self._detect_capabilities()
        
    def _detect_capabilities(self) -> Dict[str, bool]:
        """Detect available scanning capabilities"""
        caps = {
            'connect': True,  # Always available
            'syn': HAS_SCAPY,
            'nmap': HAS_NMAP,
            'http_tech': HAS_REQUESTS,
            'banner_grab': True
        }
        return caps
    
    def scan(self) -> Dict[str, Any]:
        """Execute scan with best available method"""
        # Parse ports
        ports = self._parse_ports()
        if not ports:
            return self._error("No valid ports specified")
        
        # Select scan engine
        engine = self._select_engine(ports)
        
        # Inform user of scanning method
        scan_method = engine.__class__.__name__
        print(f"INFO: Using {scan_method} for {len(ports)} ports", file=sys.stderr)
        
        # Execute scan
        start_time = time.time()
        results = engine.scan()
        scan_duration = time.time() - start_time
        
        # Enhance results with additional info
        open_ports = [r for r in results if r.state == "open"]
        
        # HTTP technology detection for web ports
        if self.capabilities['http_tech'] and self.params.get('detect_http', True):
            for result in open_ports:
                if result.port in [80, 443, 8080, 8443]:
                    tech = ServiceFingerprinter.detect_http_tech(
                        self.target, result.port
                    )
                    if tech:
                        result.version = tech.get('server', result.version)
        
        return {
            'target': self.target,
            'scan_method': scan_method,
            'ports_scanned': len(ports),
            'ports_open': len(open_ports),
            'scan_duration': round(scan_duration, 2),
            'results': [r.to_dict() for r in results],
            'capabilities': self.capabilities
        }
    
    def _parse_ports(self) -> List[int]:
        """Parse port specification"""
        port_spec = self.params.get('ports', 'top-20')
        
        # Pre-defined sets
        if port_spec in self.PORT_SETS:
            return self.PORT_SETS[port_spec]
        
        # Custom range or list
        ports = []
        for part in str(port_spec).split(','):
            part = part.strip()
            
            if '-' in part:
                # Range: 1-100
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    continue
            else:
                # Single port
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    
    def _select_engine(self, ports: List[int]) -> ScanEngine:
        """Select best available scan engine"""
        engine_pref = self.params.get('engine', 'auto')
        timeout = float(self.params.get('timeout', 1.0))
        
        if engine_pref == 'nmap' and self.capabilities['nmap']:
            return NmapScanEngine(self.target, ports, timeout)
        
        if engine_pref == 'syn' and self.capabilities['syn']:
            try:
                return SYNScanEngine(self.target, ports, timeout)
            except PermissionError:
                print("WARN: SYN scan requires root, falling back to connect", 
                      file=sys.stderr)
        
        # Default to connect scan
        return ConnectScanEngine(self.target, ports, timeout)
    
    def _error(self, message: str) -> Dict[str, Any]:
        """Generate error response"""
        return {
            'success': False,
            'error': message,
            'target': self.target
        }


def show_help():
    """Display module help"""
    help_text = """
╔═══════════════════════════════════════════════════════════════════╗
║                    PortScan Module Help                           ║
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  Advanced multi-engine network port scanner with service detection,
  banner grabbing, and intelligent fallback mechanisms.

CAPABILITIES (Auto-Detected):
  ✓ Connect Scan   - TCP connect (always available)
  """ + ("✓" if HAS_SCAPY else "✗") + """ SYN Scan      - Stealth SYN scan (requires scapy & root)
  """ + ("✓" if HAS_NMAP else "✗") + """ Nmap Scan     - Full nmap integration
  """ + ("✓" if HAS_REQUESTS else "✗") + """ HTTP Tech     - Web technology detection
  ✓ Banner Grab   - Service version detection

PARAMETERS:
  ports           Port specification (required)
                  Formats:
                    - Preset: top-20, top-100, top-1000, common, web, db
                    - Range: 1-100, 8000-9000
                    - List: 80,443,8080
                    - Mixed: 80,443,8000-9000
  
  engine          Scan engine (default: auto)
                  Options: auto, connect, syn, nmap
  
  timeout         Timeout per port in seconds (default: 1.0)
  
  detect_http     Enable HTTP tech detection (default: true)

USAGE EXAMPLES:

1. Quick Scan (Top 20 Ports):
   secV > use portscan
   secV (portscan) > run example.com

2. Common Ports:
   secV (portscan) > set ports common
   secV (portscan) > run 192.168.1.1

3. Custom Port Range:
   secV (portscan) > set ports 1-1000
   secV (portscan) > run target.local

4. Specific Ports:
   secV (portscan) > set ports 80,443,8080,8443
   secV (portscan) > run example.com

5. SYN Scan (Stealth):
   secV (portscan) > set engine syn
   secV (portscan) > run 192.168.1.1
   Note: Requires root privileges

6. Nmap Integration:
   secV (portscan) > set engine nmap
   secV (portscan) > run example.com

7. Fast Web Scan:
   secV (portscan) > set ports web
   secV (portscan) > set timeout 0.5
   secV (portscan) > run example.com

INSTALLATION TIERS:
  Basic    : Connect scan only (stdlib)
  Standard : + SYN scan (requires: pip install scapy)
  Full     : + HTTP detection (requires: pip install requests)
  Complete : + Nmap (requires: pip install python-nmap)

TIPS:
  • Use 'top-20' for quick reconnaissance
  • Use 'syn' engine for stealth (requires root)
  • Lower timeout for faster scans of online hosts
  • Combine with other modules for vulnerability assessment

OUTPUT:
  • State: open, closed, filtered
  • Service name and version (when available)
  • Response times
  • HTTP technologies (for web ports)
  • Service banners

AUTHOR: SecVulnHub Team
VERSION: 2.0.0
"""
    print(help_text)


def main():
    """Main entry point"""
    # Check if help requested
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        show_help()
        sys.exit(0)
    
    try:
        # Read execution context
        context = json.loads(sys.stdin.read())
        target = context.get('target')
        params = context.get('params', {})
        
        if not target:
            result = {
                'success': False,
                'data': None,
                'errors': ['No target specified']
            }
        else:
            # Execute scan
            scanner = PortScanner(target, params)
            scan_data = scanner.scan()
            
            result = {
                'success': True,
                'data': scan_data,
                'errors': []
            }
    
    except json.JSONDecodeError as e:
        result = {
            'success': False,
            'data': None,
            'errors': [f'Invalid JSON input: {str(e)}']
        }
    except Exception as e:
        result = {
            'success': False,
            'data': None,
            'errors': [f'Scan error: {str(e)}']
        }
    
    # Output result
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
