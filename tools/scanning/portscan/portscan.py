#!/usr/bin/env python3
"""
SecV Advanced Port Scanner v3.0
High-performance network scanner with stealth capabilities

Author: SecVulnHub Team
License: MIT
WARNING: For authorized security testing only
"""

import socket
import json
import sys
import time
import threading
import queue
import ipaddress
import random
import struct
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
import re

# Optional imports with graceful degradation
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    scapy = None

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# Constants
VERSION = "3.0.0"
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100
MAX_THREADS = 500

# Port presets
PORT_PRESETS = {
    'top-20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    'top-100': list(range(1, 101)),
    'top-1000': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995] + list(range(1, 1001)),
    'web': [80, 443, 8000, 8008, 8080, 8088, 8443, 8888],
    'database': [1433, 1521, 3306, 5432, 27017, 27018, 6379, 9200],
    'mail': [25, 110, 143, 465, 587, 993, 995],
    'common': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080],
    'all': list(range(1, 65536))
}

# Service fingerprints
SERVICE_SIGNATURES = {
    22: {'name': 'ssh', 'pattern': rb'SSH-'},
    21: {'name': 'ftp', 'pattern': rb'220.*FTP'},
    25: {'name': 'smtp', 'pattern': rb'220.*SMTP'},
    80: {'name': 'http', 'pattern': rb'HTTP/'},
    443: {'name': 'https', 'pattern': rb'HTTP/'},
    3306: {'name': 'mysql', 'pattern': rb'\x00\x00\x00\x0a'},
    5432: {'name': 'postgresql', 'pattern': rb'PostgreSQL'},
    6379: {'name': 'redis', 'pattern': rb'\+PONG'},
    27017: {'name': 'mongodb', 'pattern': rb'MongoDB'},
}


@dataclass
class ScanResult:
    """Structured scan result"""
    host: str
    port: int
    protocol: str
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    response_time: float = 0.0
    timestamp: str = ""
    ttl: int = 0
    scan_method: str = "connect"
    
    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v}


class PortScanner:
    """Advanced port scanner with multiple scan techniques"""
    
    def __init__(self, config: dict):
        self.config = config
        self.results: List[ScanResult] = []
        self.results_lock = threading.Lock()
        self.stats = {
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'start_time': time.time()
        }
        
        # Parse configuration
        self.timeout = config.get('timeout', DEFAULT_TIMEOUT)
        self.threads = min(config.get('threads', DEFAULT_THREADS), MAX_THREADS)
        self.verbose = config.get('verbose', False)
        self.service_detect = config.get('service_detect', True)
        self.stealth = config.get('stealth', False)
        self.scan_type = config.get('scan_type', 'connect')
        self.source_port = config.get('source_port', 0)
        
    def log(self, message: str, level: str = "INFO"):
        """Thread-safe logging"""
        if self.verbose or level == "ERROR":
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {level}: {message}", file=sys.stderr)
    
    def parse_targets(self, target_str: str) -> List[str]:
        """Parse target specification (IPs, CIDR, ranges)"""
        targets = []
        
        for target in target_str.split(','):
            target = target.strip()
            
            # CIDR notation
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    targets.extend([str(ip) for ip in network.hosts()])
                    self.log(f"Parsed CIDR {target}: {network.num_addresses} hosts")
                except ValueError as e:
                    self.log(f"Invalid CIDR {target}: {e}", "ERROR")
            
            # IP range (192.168.1.1-254)
            elif '-' in target and '.' in target:
                try:
                    base, range_part = target.rsplit('.', 1)
                    if '-' in range_part:
                        start, end = map(int, range_part.split('-'))
                        for i in range(start, end + 1):
                            targets.append(f"{base}.{i}")
                        self.log(f"Parsed range {target}: {end - start + 1} hosts")
                except ValueError as e:
                    self.log(f"Invalid range {target}: {e}", "ERROR")
            
            # Single host
            else:
                targets.append(target)
        
        return list(set(targets))  # Remove duplicates
    
    def parse_ports(self, port_str: str) -> List[int]:
        """Parse port specification"""
        ports = set()
        
        # Check for presets
        if port_str in PORT_PRESETS:
            return PORT_PRESETS[port_str]
        
        # Parse custom port specification
        for part in port_str.split(','):
            part = part.strip()
            
            # Port range
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                except ValueError:
                    self.log(f"Invalid port range: {part}", "ERROR")
            
            # Single port
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except ValueError:
                    self.log(f"Invalid port: {part}", "ERROR")
        
        return sorted(list(ports))
    
    def tcp_connect_scan(self, host: str, port: int) -> ScanResult:
        """Standard TCP connect scan"""
        start_time = time.time()
        result = ScanResult(
            host=host,
            port=port,
            protocol="tcp",
            state="closed",
            scan_method="connect",
            timestamp=datetime.now().isoformat()
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        # Use custom source port if specified (for stealth)
        if self.source_port:
            try:
                sock.bind(('', self.source_port))
            except:
                pass
        
        try:
            sock.connect((host, port))
            result.state = "open"
            result.response_time = time.time() - start_time
            
            # Service detection
            if self.service_detect:
                self.detect_service(sock, result)
            
            sock.close()
            
        except socket.timeout:
            result.state = "filtered"
        except socket.error:
            result.state = "closed"
        finally:
            sock.close()
        
        return result
    
    def syn_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """SYN stealth scan using scapy"""
        if not HAS_SCAPY:
            self.log("Scapy not available, falling back to connect scan", "WARN")
            return self.tcp_connect_scan(host, port)
        
        start_time = time.time()
        result = ScanResult(
            host=host,
            port=port,
            protocol="tcp",
            state="closed",
            scan_method="syn",
            timestamp=datetime.now().isoformat()
        )
        
        try:
            # Random source port for stealth
            src_port = random.randint(1024, 65535) if not self.source_port else self.source_port
            
            # Craft SYN packet
            ip_layer = IP(dst=host)
            tcp_layer = TCP(sport=src_port, dport=port, flags="S", seq=random.randint(1000, 9000))
            packet = ip_layer / tcp_layer
            
            # Send packet and wait for response
            response = scapy.sr1(packet, timeout=self.timeout, verbose=0)
            
            if response:
                result.response_time = time.time() - start_time
                result.ttl = response.ttl if hasattr(response, 'ttl') else 0
                
                # Check response flags
                if response.haslayer(TCP):
                    tcp_flags = response[TCP].flags
                    if tcp_flags == 0x12:  # SYN-ACK
                        result.state = "open"
                        # Send RST to close connection (stealth)
                        rst = IP(dst=host) / TCP(sport=src_port, dport=port, flags="R", seq=response[TCP].ack)
                        scapy.send(rst, verbose=0)
                    elif tcp_flags == 0x14:  # RST-ACK
                        result.state = "closed"
                elif response.haslayer(ICMP):
                    result.state = "filtered"
            else:
                result.state = "filtered"
                
        except Exception as e:
            self.log(f"SYN scan error for {host}:{port}: {e}", "ERROR")
            result.state = "error"
        
        return result
    
    def udp_scan(self, host: str, port: int) -> ScanResult:
        """UDP scan"""
        start_time = time.time()
        result = ScanResult(
            host=host,
            port=port,
            protocol="udp",
            state="open|filtered",
            scan_method="udp",
            timestamp=datetime.now().isoformat()
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            # Send UDP probe
            sock.sendto(b'\x00', (host, port))
            
            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                result.state = "open"
                result.banner = data[:100].decode('utf-8', errors='ignore')
                result.response_time = time.time() - start_time
            except socket.timeout:
                result.state = "open|filtered"
                
        except socket.error as e:
            # ICMP port unreachable means closed
            if "unreachable" in str(e).lower():
                result.state = "closed"
        finally:
            sock.close()
        
        return result
    
    def detect_service(self, sock: socket.socket, result: ScanResult):
        """Detect service and grab banner"""
        try:
            # Check signature database
            if result.port in SERVICE_SIGNATURES:
                result.service = SERVICE_SIGNATURES[result.port]['name']
            
            # Try to grab banner
            sock.settimeout(2.0)
            
            # Send probe based on common ports
            if result.port in [80, 8080, 8000, 8008, 8888]:
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            elif result.port in [443, 8443]:
                result.service = "https"
                return
            elif result.port == 22:
                pass  # SSH sends banner first
            elif result.port == 21:
                pass  # FTP sends banner first
            elif result.port == 25:
                pass  # SMTP sends banner first
            else:
                # Try generic probe
                sock.sendall(b"\r\n")
            
            # Receive response
            try:
                banner = sock.recv(1024)
                if banner:
                    result.banner = banner[:200].decode('utf-8', errors='ignore').strip()
                    
                    # Detect service from banner
                    banner_lower = result.banner.lower()
                    if 'http' in banner_lower:
                        result.service = "http"
                        # Extract server version
                        if 'server:' in banner_lower:
                            match = re.search(r'server:\s*([^\r\n]+)', banner_lower)
                            if match:
                                result.version = match.group(1).strip()
                    elif 'ssh' in result.banner:
                        result.service = "ssh"
                        match = re.search(r'SSH-[\d.]+-(\S+)', result.banner)
                        if match:
                            result.version = match.group(1)
                    elif 'ftp' in banner_lower:
                        result.service = "ftp"
                    elif 'smtp' in banner_lower:
                        result.service = "smtp"
                    elif 'mysql' in banner_lower:
                        result.service = "mysql"
                    elif 'postgresql' in banner_lower:
                        result.service = "postgresql"
                        
            except socket.timeout:
                pass
                
        except Exception as e:
            self.log(f"Service detection error: {e}", "DEBUG")
    
    def ping_sweep(self, hosts: List[str]) -> List[str]:
        """ICMP ping sweep to find live hosts"""
        if not HAS_SCAPY:
            self.log("Scapy not available, skipping ping sweep", "WARN")
            return hosts
        
        live_hosts = []
        self.log(f"Ping sweep: checking {len(hosts)} hosts...")
        
        def ping_host(host):
            try:
                packet = IP(dst=host) / ICMP()
                response = scapy.sr1(packet, timeout=1, verbose=0)
                if response:
                    return host
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, host): host for host in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
        
        self.log(f"Ping sweep: {len(live_hosts)} hosts alive")
        return live_hosts if live_hosts else hosts
    
    def scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        """Scan single port using configured method"""
        self.stats['total_ports'] += 1
        
        # Select scan method
        if self.scan_type == 'syn' and HAS_SCAPY:
            result = self.syn_scan(host, port)
        elif self.scan_type == 'udp':
            result = self.udp_scan(host, port)
        else:
            result = self.tcp_connect_scan(host, port)
        
        # Update statistics
        if result:
            if result.state == "open":
                self.stats['open_ports'] += 1
            elif result.state == "closed":
                self.stats['closed_ports'] += 1
            elif result.state == "filtered":
                self.stats['filtered_ports'] += 1
            
            with self.results_lock:
                self.results.append(result)
            
            # Log open ports immediately
            if result.state == "open" and self.verbose:
                service_info = f" [{result.service}]" if result.service != "unknown" else ""
                self.log(f"OPEN: {host}:{port}{service_info}")
        
        return result
    
    def scan(self, targets: List[str], ports: List[int]):
        """Main scan orchestration"""
        self.log(f"Starting scan: {len(targets)} hosts, {len(ports)} ports")
        self.log(f"Scan type: {self.scan_type}, Threads: {self.threads}")
        
        # Ping sweep if in stealth mode
        if self.stealth and HAS_SCAPY:
            targets = self.ping_sweep(targets)
        
        # Create scan tasks
        tasks = [(host, port) for host in targets for port in ports]
        total_tasks = len(tasks)
        completed = 0
        
        self.log(f"Total scan tasks: {total_tasks}")
        
        # Execute scans with thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): (host, port) 
                      for host, port in tasks}
            
            for future in as_completed(futures):
                completed += 1
                if completed % 100 == 0 or completed == total_tasks:
                    progress = (completed / total_tasks) * 100
                    self.log(f"Progress: {completed}/{total_tasks} ({progress:.1f}%)")
                
                try:
                    future.result()
                except Exception as e:
                    host, port = futures[future]
                    self.log(f"Scan error {host}:{port}: {e}", "ERROR")
    
    def get_results(self) -> dict:
        """Get formatted results"""
        duration = time.time() - self.stats['start_time']
        
        return {
            "success": True,
            "data": {
                "scan_info": {
                    "version": VERSION,
                    "scan_type": self.scan_type,
                    "duration": f"{duration:.2f}s",
                    "threads": self.threads
                },
                "statistics": {
                    "total_ports_scanned": self.stats['total_ports'],
                    "open_ports": self.stats['open_ports'],
                    "closed_ports": self.stats['closed_ports'],
                    "filtered_ports": self.stats['filtered_ports']
                },
                "results": [r.to_dict() for r in self.results if r.state == "open"]
            },
            "errors": []
        }


def main():
    """Main entry point"""
    try:
        # Read context from SecV
        context = json.loads(sys.stdin.read())
        target = context.get('target', '')
        params = context.get('params', {})
        
        # Build configuration
        config = {
            'timeout': float(params.get('timeout', DEFAULT_TIMEOUT)),
            'threads': int(params.get('threads', DEFAULT_THREADS)),
            'verbose': params.get('verbose', False),
            'service_detect': params.get('service_detect', True),
            'stealth': params.get('stealth', False),
            'scan_type': params.get('scan_type', 'connect'),
            'source_port': int(params.get('source_port', 0)),
            'ping_sweep': params.get('ping_sweep', False)
        }
        
        # Initialize scanner
        scanner = PortScanner(config)
        
        # Parse targets
        targets = scanner.parse_targets(target)
        if not targets:
            result = {
                "success": False,
                "data": None,
                "errors": ["No valid targets specified"]
            }
            print(json.dumps(result))
            return
        
        # Parse ports
        port_spec = params.get('ports', 'top-20')
        ports = scanner.parse_ports(port_spec)
        if not ports:
            result = {
                "success": False,
                "data": None,
                "errors": ["No valid ports specified"]
            }
            print(json.dumps(result))
            return
        
        # Execute scan
        scanner.scan(targets, ports)
        
        # Return results
        result = scanner.get_results()
        print(json.dumps(result, indent=2))
        
    except KeyboardInterrupt:
        result = {
            "success": False,
            "data": None,
            "errors": ["Scan interrupted by user"]
        }
        print(json.dumps(result))
        sys.exit(1)
        
    except Exception as e:
        result = {
            "success": False,
            "data": None,
            "errors": [f"Scan error: {str(e)}"]
        }
        print(json.dumps(result))
        sys.exit(1)


if __name__ == '__main__':
    main()
