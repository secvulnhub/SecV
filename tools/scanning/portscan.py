#!/usr/bin/env python3
"""
PortScan - Advanced Network Discovery and Port Analysis Module
Pure Python implementation with enterprise-grade features
Author: 0xbv1 | 0xb0rn3
No external scanners - 100% native implementation with masscan-speed techniques
"""

import json
import sys
import socket
import struct
import time
import re
import ssl
import select
import threading
import asyncio
import random
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
import ipaddress
import urllib.parse
import base64
import hashlib

# Try to import optional high-performance libraries
try:
    import python_nmap
    HAS_PYTHON_NMAP = True
except ImportError:
    HAS_PYTHON_NMAP = False

try:
    import masscan
    HAS_MASSCAN = True
except ImportError:
    HAS_MASSCAN = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class ServiceFingerprint:
    """Service detection fingerprint"""
    name: str
    ports: List[int]
    protocol: str
    probe: Optional[bytes] = None
    patterns: List[str] = field(default_factory=list)
    requires_tls: bool = False
    alpn_protocols: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.compiled_patterns = [re.compile(p.encode() if isinstance(p, str) else p) 
                                  for p in self.patterns]


@dataclass
class PortResult:
    """Enhanced port scan result"""
    host: str
    ip: str
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: int = 0
    confidence: int = 0
    
    # Device information
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    os_family: Optional[str] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    
    # TLS/SSL information
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_common_name: Optional[str] = None
    tls_san: List[str] = field(default_factory=list)
    tls_issuer: Optional[str] = None
    tls_valid_from: Optional[str] = None
    tls_valid_to: Optional[str] = None
    
    # HTTP information
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None
    http_technologies: List[str] = field(default_factory=list)
    
    # Advanced fingerprinting
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    tcp_options: List[str] = field(default_factory=list)
    
    # Scanner metadata
    scan_method: str = "connect"
    
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class MasscanStyleScanner:
    """Masscan-inspired fast asynchronous scanner"""
    
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()
    
    async def scan_port_async(self, ip: str, port: int) -> Optional[Dict]:
        """Asynchronous port scan"""
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return {'ip': ip, 'port': port, 'state': 'open'}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
    
    async def scan_range_async(self, ip: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports asynchronously (masscan-style)"""
        tasks = [self.scan_port_async(ip, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
    
    def scan_range(self, ip: str, ports: List[int]) -> List[Dict]:
        """Synchronous wrapper for async scanning"""
        return asyncio.run(self.scan_range_async(ip, ports))


class NmapStyleScanner:
    """Python-nmap integration for advanced scanning"""
    
    def __init__(self):
        self.available = HAS_PYTHON_NMAP
        if self.available:
            self.scanner = python_nmap.PortScanner()
    
    def scan(self, target: str, ports: str, arguments: str = "-sV -sC") -> Dict:
        """Execute nmap-style scan with service detection"""
        if not self.available:
            return {}
        
        try:
            self.scanner.scan(target, ports, arguments=arguments)
            results = []
            
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    ports_data = self.scanner[host][proto]
                    for port, data in ports_data.items():
                        result = {
                            'host': host,
                            'port': port,
                            'protocol': proto,
                            'state': data.get('state', 'unknown'),
                            'service': data.get('name', 'unknown'),
                            'version': data.get('version', ''),
                            'product': data.get('product', ''),
                            'extrainfo': data.get('extrainfo', ''),
                            'cpe': data.get('cpe', ''),
                        }
                        results.append(result)
            
            return {'results': results}
        except Exception:
            return {}


class ScapyScanner:
    """Scapy-based low-level packet scanner"""
    
    def __init__(self):
        self.available = HAS_SCAPY
    
    def syn_scan(self, target: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """SYN scan using raw packets"""
        if not self.available:
            return None
        
        try:
            # Create SYN packet
            ip = scapy.IP(dst=target)
            syn = scapy.TCP(dport=port, flags='S')
            packet = ip/syn
            
            # Send and receive
            response = scapy.sr1(packet, timeout=timeout, verbose=0)
            
            if response is None:
                return 'filtered'
            elif response.haslayer(scapy.TCP):
                if response.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst = scapy.TCP(dport=port, flags='R')
                    scapy.send(ip/rst, verbose=0)
                    return 'open'
                elif response.getlayer(scapy.TCP).flags == 0x14:  # RST-ACK
                    return 'closed'
            
            return 'filtered'
        except Exception:
            return None
    
    def os_fingerprint(self, target: str) -> Optional[Dict]:
        """Basic OS fingerprinting using TTL and window size"""
        if not self.available:
            return None
        
        try:
            # Send ICMP echo request
            packet = scapy.IP(dst=target)/scapy.ICMP()
            response = scapy.sr1(packet, timeout=2, verbose=0)
            
            if response:
                ttl = response.ttl
                
                # TTL-based OS guessing
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                    os_family = "Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                    os_family = "Windows"
                else:
                    os_guess = "Unknown"
                    os_family = "Unknown"
                
                return {
                    'os_guess': os_guess,
                    'os_family': os_family,
                    'ttl': ttl
                }
        except Exception:
            return None


class ServiceDetector:
    """Advanced service detection engine"""
    
    def __init__(self):
        self.fingerprints = self._load_fingerprints()
        self.timeout = 5
        
    def _load_fingerprints(self) -> List[ServiceFingerprint]:
        """Load service fingerprints for detection"""
        fingerprints = []
        
        # HTTP/HTTPS
        fingerprints.append(ServiceFingerprint(
            name="http",
            ports=[80, 8080, 8000, 8081, 8090, 8888, 3000, 5000],
            protocol="tcp",
            probe=b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            patterns=[
                b"HTTP/\\d\\.\\d (\\d+)",
                b"Server: ([^\\r\\n]+)",
            ]
        ))
        
        fingerprints.append(ServiceFingerprint(
            name="https",
            ports=[443, 8443, 8834, 9443],
            protocol="tcp",
            requires_tls=True,
            alpn_protocols=["http/1.1", "h2"],
            probe=b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            patterns=[
                b"HTTP/\\d\\.\\d (\\d+)",
                b"Server: ([^\\r\\n]+)",
            ]
        ))
        
        # SSH
        fingerprints.append(ServiceFingerprint(
            name="ssh",
            ports=[22, 2222, 2200],
            protocol="tcp",
            patterns=[
                b"SSH-([\\d\\.]+)-([^\\r\\n]+)",
                b"OpenSSH[_\\s]([\\d\\.p]+)",
            ]
        ))
        
        # FTP
        fingerprints.append(ServiceFingerprint(
            name="ftp",
            ports=[21, 2121],
            protocol="tcp",
            patterns=[
                b"220[- ](.+?)\\r\\n",
                b"FTP.*?([\\d\\.]+)",
            ]
        ))
        
        # SMTP
        fingerprints.append(ServiceFingerprint(
            name="smtp",
            ports=[25, 587, 465],
            protocol="tcp",
            probe=b"EHLO scanner\r\n",
            patterns=[
                b"220[- ](.+?)\\r\\n",
                b"Postfix",
                b"Exim",
                b"Sendmail",
            ]
        ))
        
        # MySQL
        fingerprints.append(ServiceFingerprint(
            name="mysql",
            ports=[3306, 3307],
            protocol="tcp",
            patterns=[
                b"\\x00([\\d\\.]+)\\x00",
                b"mysql",
            ]
        ))
        
        # PostgreSQL
        fingerprints.append(ServiceFingerprint(
            name="postgresql",
            ports=[5432, 5433],
            protocol="tcp",
            patterns=[
                b"PostgreSQL",
            ]
        ))
        
        # MongoDB
        fingerprints.append(ServiceFingerprint(
            name="mongodb",
            ports=[27017, 27018, 27019],
            protocol="tcp",
            patterns=[
                b"MongoDB",
            ]
        ))
        
        # Redis
        fingerprints.append(ServiceFingerprint(
            name="redis",
            ports=[6379],
            protocol="tcp",
            probe=b"PING\r\n",
            patterns=[
                b"\\+PONG",
                b"redis_version:([\\d\\.]+)",
            ]
        ))
        
        # Elasticsearch
        fingerprints.append(ServiceFingerprint(
            name="elasticsearch",
            ports=[9200, 9300],
            protocol="tcp",
            probe=b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
            patterns=[
                b'"version"\\s*:\\s*{[^}]*"number"\\s*:\\s*"([^"]+)"',
                b"elasticsearch",
            ]
        ))
        
        # RDP
        fingerprints.append(ServiceFingerprint(
            name="rdp",
            ports=[3389],
            protocol="tcp",
            patterns=[
                b"\\x03\\x00\\x00",
                b"mstshash",
            ]
        ))
        
        # VNC
        fingerprints.append(ServiceFingerprint(
            name="vnc",
            ports=[5900, 5901, 5902],
            protocol="tcp",
            patterns=[
                b"RFB (\\d+\\.\\d+)",
            ]
        ))
        
        # Telnet
        fingerprints.append(ServiceFingerprint(
            name="telnet",
            ports=[23],
            protocol="tcp",
            patterns=[
                b"\\xff\\xfd",
                b"login:",
                b"Username:",
            ]
        ))
        
        # DNS
        fingerprints.append(ServiceFingerprint(
            name="dns",
            ports=[53],
            protocol="tcp",
            patterns=[
                b"\\x00\\x00\\x00\\x00",
            ]
        ))
        
        # LDAP
        fingerprints.append(ServiceFingerprint(
            name="ldap",
            ports=[389, 636],
            protocol="tcp",
            patterns=[
                b"\\x30",
                b"objectClass",
            ]
        ))
        
        # SMB
        fingerprints.append(ServiceFingerprint(
            name="smb",
            ports=[139, 445],
            protocol="tcp",
            patterns=[
                b"\\xffSMB",
                b"\\xfeSMB",
            ]
        ))
        
        # SNMP
        fingerprints.append(ServiceFingerprint(
            name="snmp",
            ports=[161],
            protocol="udp",
            patterns=[
                b"\\x30",
            ]
        ))
        
        return fingerprints
    
    def detect(self, host: str, port: int, protocol: str = "tcp") -> Tuple[Optional[str], Optional[str], Optional[str], int]:
        """
        Detect service on a port
        Returns: (service_name, version, banner, confidence)
        """
        # Find matching fingerprints
        matching = [fp for fp in self.fingerprints 
                   if fp.protocol == protocol and (not fp.ports or port in fp.ports)]
        
        if not matching:
            # Try generic detection
            return self._generic_detection(host, port, protocol)
        
        # Try each fingerprint
        for fingerprint in matching:
            try:
                result = self._probe_service(host, port, fingerprint)
                if result:
                    return result
            except Exception:
                continue
        
        return None, None, None, 0
    
    def _probe_service(self, host: str, port: int, fp: ServiceFingerprint) -> Optional[Tuple]:
        """Probe a service with a specific fingerprint"""
        try:
            # Create connection
            if fp.requires_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_alpn_protocols(fp.alpn_protocols if fp.alpn_protocols else ["http/1.1"])
                
                sock = socket.create_connection((host, port), timeout=self.timeout)
                conn = context.wrap_socket(sock, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=self.timeout)
            
            try:
                # Send probe if specified
                if fp.probe:
                    probe_data = fp.probe
                    if b'%s' in probe_data:
                        probe_data = probe_data.replace(b'%s', host.encode())
                    conn.sendall(probe_data)
                
                # Read response
                conn.settimeout(self.timeout)
                response = b''
                try:
                    while len(response) < 4096:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                        time.sleep(0.01)
                except socket.timeout:
                    pass
                
                # Match patterns
                version = None
                confidence = 50
                
                for pattern in fp.compiled_patterns:
                    match = pattern.search(response)
                    if match:
                        confidence = 90
                        if match.groups():
                            version = match.group(1).decode('utf-8', errors='ignore')
                        break
                
                banner = response[:500].decode('utf-8', errors='ignore').strip()
                
                return fp.name, version, banner, confidence
                
            finally:
                conn.close()
                
        except Exception:
            return None
    
    def _generic_detection(self, host: str, port: int, protocol: str) -> Tuple:
        """Generic service detection based on banner grabbing"""
        try:
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.settimeout(self.timeout)
            
            # Try to read banner
            try:
                banner = conn.recv(1024).decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                banner = ""
            
            conn.close()
            
            if banner:
                # Analyze banner for clues
                service = self._analyze_banner(banner, port)
                return service, None, banner, 30
            
            return "unknown", None, None, 10
            
        except Exception:
            return None, None, None, 0
    
    def _analyze_banner(self, banner: str, port: int) -> str:
        """Analyze banner content to guess service"""
        banner_lower = banner.lower()
        
        if 'http' in banner_lower or 'html' in banner_lower:
            return 'http'
        elif 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower or 'mail' in banner_lower:
            return 'smtp'
        elif 'mysql' in banner_lower:
            return 'mysql'
        elif 'postgres' in banner_lower:
            return 'postgresql'
        elif 'redis' in banner_lower:
            return 'redis'
        
        # Port-based fallback
        common_ports = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp',
            25: 'smtp', 3306: 'mysql', 5432: 'postgresql',
            6379: 'redis', 27017: 'mongodb', 9200: 'elasticsearch',
            3389: 'rdp', 5900: 'vnc', 23: 'telnet'
        }
        
        return common_ports.get(port, 'unknown')


class TLSProber:
    """TLS/SSL certificate and configuration prober"""
    
    def probe(self, host: str, port: int) -> Dict[str, Any]:
        """Probe TLS/SSL configuration"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1", "h2"])
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    alpn = ssock.selected_alpn_protocol()
                    
                    tls_info = {
                        'version': version,
                        'cipher': cipher[0] if cipher else None,
                        'alpn_protocol': alpn,
                        'common_name': None,
                        'san': [],
                        'issuer': None,
                        'valid_from': None,
                        'valid_to': None
                    }
                    
                    if cert:
                        # Extract subject
                        for field in cert.get('subject', []):
                            for key, value in field:
                                if key == 'commonName':
                                    tls_info['common_name'] = value
                        
                        # Extract issuer
                        for field in cert.get('issuer', []):
                            for key, value in field:
                                if key == 'organizationName':
                                    tls_info['issuer'] = value
                                    break
                        
                        # Extract SAN
                        for ext in cert.get('subjectAltName', []):
                            if ext[0] == 'DNS':
                                tls_info['san'].append(ext[1])
                        
                        # Extract validity dates
                        tls_info['valid_from'] = cert.get('notBefore')
                        tls_info['valid_to'] = cert.get('notAfter')
                    
                    return tls_info
        except Exception:
            return {}


class HTTPProber:
    """HTTP/HTTPS service prober"""
    
    def probe(self, host: str, port: int, use_tls: bool = False) -> Dict[str, Any]:
        """Probe HTTP service for detailed information"""
        try:
            scheme = 'https' if use_tls else 'http'
            
            # Create connection
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=5)
                conn = context.wrap_socket(sock, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=5)
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Scanner/1.0\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode())
            
            # Read response
            response = b''
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 100000:  # 100KB limit
                        break
                except socket.timeout:
                    break
            
            conn.close()
            
            # Parse response
            response_str = response.decode('utf-8', errors='ignore')
            headers_end = response_str.find('\r\n\r\n')
            if headers_end == -1:
                headers_end = response_str.find('\n\n')
            
            if headers_end > 0:
                headers_section = response_str[:headers_end]
                body = response_str[headers_end:]
            else:
                headers_section = response_str
                body = ""
            
            # Extract status code
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', headers_section)
            status_code = int(status_match.group(1)) if status_match else None
            
            # Extract headers
            headers = {}
            for line in headers_section.split('\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract title
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else None
            
            # Detect technologies
            technologies = self._detect_technologies(headers, body)
            
            return {
                'status_code': status_code,
                'server': headers.get('server'),
                'title': title,
                'technologies': technologies,
                'headers': dict(list(headers.items())[:20])  # Limit headers
            }
            
        except Exception:
            return {}
    
    def _detect_technologies(self, headers: Dict, body: str) -> List[str]:
        """Detect web technologies from headers and body"""
        techs = []
        
        # Server header
        server = headers.get('server', '').lower()
        if 'apache' in server:
            techs.append('Apache')
        elif 'nginx' in server:
            techs.append('Nginx')
        elif 'iis' in server:
            techs.append('IIS')
        
        # X-Powered-By
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            techs.append('PHP')
        elif 'asp.net' in powered_by:
            techs.append('ASP.NET')
        
        # Body analysis
        body_lower = body.lower()
        if 'wordpress' in body_lower or 'wp-content' in body_lower:
            techs.append('WordPress')
        if 'joomla' in body_lower:
            techs.append('Joomla')
        if 'drupal' in body_lower:
            techs.append('Drupal')
        if 'jquery' in body_lower:
            techs.append('jQuery')
        if 'react' in body_lower or 'reactjs' in body_lower:
            techs.append('React')
        if 'angular' in body_lower:
            techs.append('Angular')
        if 'vue' in body_lower:
            techs.append('Vue.js')
        
        return techs


class DeviceFingerprinter:
    """Device and OS fingerprinting"""
    
    def __init__(self):
        self.mac_vendors = self._load_mac_vendors()
    
    def _load_mac_vendors(self) -> Dict[str, str]:
        """Load MAC vendor database"""
        return {
            "00:00:0C": "Cisco Systems",
            "00:05:85": "Juniper Networks",
            "00:0B:86": "HP Enterprise",
            "00:06:5B": "Dell Inc",
            "00:15:6D": "Ubiquiti",
            "00:0C:42": "MikroTik",
            "00:09:0F": "Fortinet",
            "00:1B:17": "Palo Alto Networks",
            "00:09:5B": "NETGEAR",
            "00:05:5F": "D-Link",
            "00:03:2F": "Linksys",
            "00:02:B3": "Intel Corporation",
            "00:E0:4C": "Realtek",
            "00:05:69": "VMware",
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:15:5D": "Microsoft",
            "00:03:93": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "24:0A:C4": "Espressif (ESP32/ESP8266)",
        }
    
    def guess_os(self, service_info: Dict[str, Any], ttl: Optional[int] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Guess operating system from service information
        Returns: (os_guess, os_family)
        """
        services = service_info.get('services', [])
        
        # TTL-based detection
        if ttl:
            if ttl <= 64:
                os_family = "Unix"
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_family = "Windows"
                os_guess = "Windows"
            else:
                os_family = "Unknown"
                os_guess = "Unknown"
        else:
            os_family = None
            os_guess = None
        
        # Windows indicators
        windows_services = ['microsoft-ds', 'netbios-ssn', 'rdp', 'winrm', 'msrpc']
        if any(s in str(services).lower() for s in windows_services):
            return "Windows Server", "Windows"
        
        # Linux indicators
        linux_services = ['ssh', 'apache', 'nginx']
        if any(s in str(services).lower() for s in linux_services):
            # Check for specific distros
            banners = str(service_info.get('banners', [])).lower()
            if 'ubuntu' in banners:
                return "Linux (Ubuntu)", "Unix"
            elif 'debian' in banners:
                return "Linux (Debian)", "Unix"
            elif 'centos' in banners or 'rhel' in banners:
                return "Linux (RHEL/CentOS)", "Unix"
            return "Linux", "Unix"
        
        return os_guess, os_family
    
    def lookup_mac_vendor(self, mac: str) -> Optional[str]:
        """Lookup MAC address vendor"""
        if not mac or len(mac) < 8:
            return None
        
        prefix = mac[:8].upper()
        return self.mac_vendors.get(prefix)


class AdvancedPortScanner:
    """Main scanning engine with multiple backends"""
    
    def __init__(self, target: str, params: Dict[str, Any]):
        self.target = target
        self.params = params
        
        # Configuration
        self.scan_type = params.get('scan_type', 'connect')
        self.scan_method = params.get('scan_method', 'auto')
        self.ports = self._parse_ports(params.get('ports', 'top-100'))
        self.timeout = params.get('timeout', 2000) / 1000.0
        self.max_threads = params.get('concurrency', 50)
        self.service_detection = params.get('service_detection', True)
        self.os_detection = params.get('os_detection', False)
        self.aggressive = params.get('aggressive', False)
        self.use_masscan_speed = params.get('use_masscan_speed', False)
        
        # Initialize components
        self.service_detector = ServiceDetector()
        self.tls_prober = TLSProber()
        self.http_prober = HTTPProber()
        self.device_fingerprinter = DeviceFingerprinter()
        self.masscan_scanner = MasscanStyleScanner(timeout=self.timeout)
        self.nmap_scanner = NmapStyleScanner() if HAS_PYTHON_NMAP else None
        self.scapy_scanner = ScapyScanner() if HAS_SCAPY else None
        
        # Results#!/usr/bin/env python3
"""
PortScan - Advanced Network Discovery and Port Analysis Module
Pure Python implementation with enterprise-grade features
No external scanners - 100% native implementation
"""

import json
import sys
import socket
import struct
import time
import re
import ssl
import select
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
import ipaddress
import urllib.parse
import base64
import hashlib


@dataclass
class ServiceFingerprint:
    """Service detection fingerprint"""
    name: str
    ports: List[int]
    protocol: str
    probe: Optional[bytes] = None
    patterns: List[str] = field(default_factory=list)
    requires_tls: bool = False
    alpn_protocols: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.compiled_patterns = [re.compile(p.encode() if isinstance(p, str) else p) 
                                  for p in self.patterns]


@dataclass
class PortResult:
    """Enhanced port scan result"""
    host: str
    ip: str
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: int = 0
    confidence: int = 0
    
    # Device information
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    
    # TLS/SSL information
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_common_name: Optional[str] = None
    tls_san: List[str] = field(default_factory=list)
    tls_issuer: Optional[str] = None
    tls_valid_from: Optional[str] = None
    tls_valid_to: Optional[str] = None
    
    # HTTP information
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None
    http_technologies: List[str] = field(default_factory=list)
    
    # Advanced fingerprinting
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    tcp_options: List[str] = field(default_factory=list)
    
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ServiceDetector:
    """Advanced service detection engine"""
    
    def __init__(self):
        self.fingerprints = self._load_fingerprints()
        self.timeout = 5
        
    def _load_fingerprints(self) -> List[ServiceFingerprint]:
        """Load service fingerprints for detection"""
        fingerprints = []
        
        # HTTP/HTTPS
        fingerprints.append(ServiceFingerprint(
            name="http",
            ports=[80, 8080, 8000, 8081, 8090, 8888, 3000, 5000],
            protocol="tcp",
            probe=b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            patterns=[
                b"HTTP/\\d\\.\\d (\\d+)",
                b"Server: ([^\\r\\n]+)",
            ]
        ))
        
        fingerprints.append(ServiceFingerprint(
            name="https",
            ports=[443, 8443, 8834, 9443],
            protocol="tcp",
            requires_tls=True,
            alpn_protocols=["http/1.1", "h2"],
            probe=b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            patterns=[
                b"HTTP/\\d\\.\\d (\\d+)",
                b"Server: ([^\\r\\n]+)",
            ]
        ))
        
        # SSH
        fingerprints.append(ServiceFingerprint(
            name="ssh",
            ports=[22, 2222, 2200],
            protocol="tcp",
            patterns=[
                b"SSH-([\\d\\.]+)-([^\\r\\n]+)",
                b"OpenSSH[_\\s]([\\d\\.p]+)",
            ]
        ))
        
        # FTP
        fingerprints.append(ServiceFingerprint(
            name="ftp",
            ports=[21, 2121],
            protocol="tcp",
            patterns=[
                b"220[- ](.+?)\\r\\n",
                b"FTP.*?([\\d\\.]+)",
            ]
        ))
        
        # SMTP
        fingerprints.append(ServiceFingerprint(
            name="smtp",
            ports=[25, 587, 465],
            protocol="tcp",
            probe=b"EHLO scanner\r\n",
            patterns=[
                b"220[- ](.+?)\\r\\n",
                b"Postfix",
                b"Exim",
                b"Sendmail",
            ]
        ))
        
        # MySQL
        fingerprints.append(ServiceFingerprint(
            name="mysql",
            ports=[3306, 3307],
            protocol="tcp",
            patterns=[
                b"\\x00([\\d\\.]+)\\x00",
                b"mysql",
            ]
        ))
        
        # PostgreSQL
        fingerprints.append(ServiceFingerprint(
            name="postgresql",
            ports=[5432, 5433],
            protocol="tcp",
            patterns=[
                b"PostgreSQL",
            ]
        ))
        
        # MongoDB
        fingerprints.append(ServiceFingerprint(
            name="mongodb",
            ports=[27017, 27018, 27019],
            protocol="tcp",
            patterns=[
                b"MongoDB",
            ]
        ))
        
        # Redis
        fingerprints.append(ServiceFingerprint(
            name="redis",
            ports=[6379],
            protocol="tcp",
            probe=b"PING\r\n",
            patterns=[
                b"\\+PONG",
                b"redis_version:([\\d\\.]+)",
            ]
        ))
        
        # Elasticsearch
        fingerprints.append(ServiceFingerprint(
            name="elasticsearch",
            ports=[9200, 9300],
            protocol="tcp",
            probe=b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
            patterns=[
                b'"version"\\s*:\\s*{[^}]*"number"\\s*:\\s*"([^"]+)"',
                b"elasticsearch",
            ]
        ))
        
        # RDP
        fingerprints.append(ServiceFingerprint(
            name="rdp",
            ports=[3389],
            protocol="tcp",
            patterns=[
                b"\\x03\\x00\\x00",
                b"mstshash",
            ]
        ))
        
        # VNC
        fingerprints.append(ServiceFingerprint(
            name="vnc",
            ports=[5900, 5901, 5902],
            protocol="tcp",
            patterns=[
                b"RFB (\\d+\\.\\d+)",
            ]
        ))
        
        # Telnet
        fingerprints.append(ServiceFingerprint(
            name="telnet",
            ports=[23],
            protocol="tcp",
            patterns=[
                b"\\xff\\xfd",
                b"login:",
                b"Username:",
            ]
        ))
        
        # DNS
        fingerprints.append(ServiceFingerprint(
            name="dns",
            ports=[53],
            protocol="tcp",
            patterns=[
                b"\\x00\\x00\\x00\\x00",
            ]
        ))
        
        # LDAP
        fingerprints.append(ServiceFingerprint(
            name="ldap",
            ports=[389, 636],
            protocol="tcp",
            patterns=[
                b"\\x30",
                b"objectClass",
            ]
        ))
        
        # SMB
        fingerprints.append(ServiceFingerprint(
            name="smb",
            ports=[139, 445],
            protocol="tcp",
            patterns=[
                b"\\xffSMB",
                b"\\xfeSMB",
            ]
        ))
        
        # SNMP
        fingerprints.append(ServiceFingerprint(
            name="snmp",
            ports=[161],
            protocol="udp",
            patterns=[
                b"\\x30",
            ]
        ))
        
        return fingerprints
    
    def detect(self, host: str, port: int, protocol: str = "tcp") -> Tuple[Optional[str], Optional[str], Optional[str], int]:
        """
        Detect service on a port
        Returns: (service_name, version, banner, confidence)
        """
        # Find matching fingerprints
        matching = [fp for fp in self.fingerprints 
                   if fp.protocol == protocol and (not fp.ports or port in fp.ports)]
        
        if not matching:
            # Try generic detection
            return self._generic_detection(host, port, protocol)
        
        # Try each fingerprint
        for fingerprint in matching:
            try:
                result = self._probe_service(host, port, fingerprint)
                if result:
                    return result
            except Exception:
                continue
        
        return None, None, None, 0
    
    def _probe_service(self, host: str, port: int, fp: ServiceFingerprint) -> Optional[Tuple]:
        """Probe a service with a specific fingerprint"""
        try:
            # Create connection
            if fp.requires_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_alpn_protocols(fp.alpn_protocols if fp.alpn_protocols else ["http/1.1"])
                
                sock = socket.create_connection((host, port), timeout=self.timeout)
                conn = context.wrap_socket(sock, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=self.timeout)
            
            try:
                # Send probe if specified
                if fp.probe:
                    probe_data = fp.probe
                    if b'%s' in probe_data:
                        probe_data = probe_data.replace(b'%s', host.encode())
                    conn.sendall(probe_data)
                
                # Read response
                conn.settimeout(self.timeout)
                response = b''
                try:
                    while len(response) < 4096:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                        time.sleep(0.01)
                except socket.timeout:
                    pass
                
                # Match patterns
                version = None
                confidence = 50
                
                for pattern in fp.compiled_patterns:
                    match = pattern.search(response)
                    if match:
                        confidence = 90
                        if match.groups():
                            version = match.group(1).decode('utf-8', errors='ignore')
                        break
                
                banner = response[:500].decode('utf-8', errors='ignore').strip()
                
                return fp.name, version, banner, confidence
                
            finally:
                conn.close()
                
        except Exception:
            return None
    
    def _generic_detection(self, host: str, port: int, protocol: str) -> Tuple:
        """Generic service detection based on banner grabbing"""
        try:
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.settimeout(self.timeout)
            
            # Try to read banner
            try:
                banner = conn.recv(1024).decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                banner = ""
            
            conn.close()
            
            if banner:
                # Analyze banner for clues
                service = self._analyze_banner(banner, port)
                return service, None, banner, 30
            
            return "unknown", None, None, 10
            
        except Exception:
            return None, None, None, 0
    
    def _analyze_banner(self, banner: str, port: int) -> str:
        """Analyze banner content to guess service"""
        banner_lower = banner.lower()
        
        if 'http' in banner_lower or 'html' in banner_lower:
            return 'http'
        elif 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower or 'mail' in banner_lower:
            return 'smtp'
        elif 'mysql' in banner_lower:
            return 'mysql'
        elif 'postgres' in banner_lower:
            return 'postgresql'
        elif 'redis' in banner_lower:
            return 'redis'
        
        # Port-based fallback
        common_ports = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp',
            25: 'smtp', 3306: 'mysql', 5432: 'postgresql',
            6379: 'redis', 27017: 'mongodb', 9200: 'elasticsearch',
            3389: 'rdp', 5900: 'vnc', 23: 'telnet'
        }
        
        return common_ports.get(port, 'unknown')


class TLSProber:
    """TLS/SSL certificate and configuration prober"""
    
    def probe(self, host: str, port: int) -> Dict[str, Any]:
        """Probe TLS/SSL configuration"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1", "h2"])
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    alpn = ssock.selected_alpn_protocol()
                    
                    tls_info = {
                        'version': version,
                        'cipher': cipher[0] if cipher else None,
                        'alpn_protocol': alpn,
                        'common_name': None,
                        'san': [],
                        'issuer': None,
                        'valid_from': None,
                        'valid_to': None
                    }
                    
                    if cert:
                        # Extract subject
                        for field in cert.get('subject', []):
                            for key, value in field:
                                if key == 'commonName':
                                    tls_info['common_name'] = value
                        
                        # Extract issuer
                        for field in cert.get('issuer', []):
                            for key, value in field:
                                if key == 'organizationName':
                                    tls_info['issuer'] = value
                                    break
                        
                        # Extract SAN
                        for ext in cert.get('subjectAltName', []):
                            if ext[0] == 'DNS':
                                tls_info['san'].append(ext[1])
                        
                        # Extract validity dates
                        tls_info['valid_from'] = cert.get('notBefore')
                        tls_info['valid_to'] = cert.get('notAfter')
                    
                    return tls_info
        except Exception:
            return {}


class HTTPProber:
    """HTTP/HTTPS service prober"""
    
    def probe(self, host: str, port: int, use_tls: bool = False) -> Dict[str, Any]:
        """Probe HTTP service for detailed information"""
        try:
            scheme = 'https' if use_tls else 'http'
            
            # Create connection
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=5)
                conn = context.wrap_socket(sock, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=5)
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Scanner/1.0\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode())
            
            # Read response
            response = b''
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 100000:  # 100KB limit
                        break
                except socket.timeout:
                    break
            
            conn.close()
            
            # Parse response
            response_str = response.decode('utf-8', errors='ignore')
            headers_end = response_str.find('\r\n\r\n')
            if headers_end == -1:
                headers_end = response_str.find('\n\n')
            
            if headers_end > 0:
                headers_section = response_str[:headers_end]
                body = response_str[headers_end:]
            else:
                headers_section = response_str
                body = ""
            
            # Extract status code
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', headers_section)
            status_code = int(status_match.group(1)) if status_match else None
            
            # Extract headers
            headers = {}
            for line in headers_section.split('\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract title
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else None
            
            # Detect technologies
            technologies = self._detect_technologies(headers, body)
            
            return {
                'status_code': status_code,
                'server': headers.get('server'),
                'title': title,
                'technologies': technologies,
                'headers': dict(list(headers.items())[:20])  # Limit headers
            }
            
        except Exception:
            return {}
    
    def _detect_technologies(self, headers: Dict, body: str) -> List[str]:
        """Detect web technologies from headers and body"""
        techs = []
        
        # Server header
        server = headers.get('server', '').lower()
        if 'apache' in server:
            techs.append('Apache')
        elif 'nginx' in server:
            techs.append('Nginx')
        elif 'iis' in server:
            techs.append('IIS')
        
        # X-Powered-By
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            techs.append('PHP')
        elif 'asp.net' in powered_by:
            techs.append('ASP.NET')
        
        # Body analysis
        body_lower = body.lower()
        if 'wordpress' in body_lower or 'wp-content' in body_lower:
            techs.append('WordPress')
        if 'joomla' in body_lower:
            techs.append('Joomla')
        if 'drupal' in body_lower:
            techs.append('Drupal')
        if 'jquery' in body_lower:
            techs.append('jQuery')
        if 'react' in body_lower or 'reactjs' in body_lower:
            techs.append('React')
        if 'angular' in body_lower:
            techs.append('Angular')
        if 'vue' in body_lower:
            techs.append('Vue.js')
        
        return techs


class DeviceFingerprinter:
    """Device and OS fingerprinting"""
    
    def __init__(self):
        self.mac_vendors = self._load_mac_vendors()
    
    def _load_mac_vendors(self) -> Dict[str, str]:
        """Load MAC vendor database"""
        return {
            "00:00:0C": "Cisco Systems",
            "00:05:85": "Juniper Networks",
            "00:0B:86": "HP Enterprise",
            "00:06:5B": "Dell Inc",
            "00:15:6D": "Ubiquiti",
            "00:0C:42": "MikroTik",
            "00:09:0F": "Fortinet",
            "00:1B:17": "Palo Alto Networks",
            "00:09:5B": "NETGEAR",
            "00:05:5F": "D-Link",
            "00:03:2F": "Linksys",
            "00:02:B3": "Intel Corporation",
            "00:E0:4C": "Realtek",
            "00:05:69": "VMware",
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:15:5D": "Microsoft",
            "00:03:93": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "24:0A:C4": "Espressif (ESP32/ESP8266)",
        }
    
    def guess_os(self, service_info: Dict[str, Any]) -> Optional[str]:
        """Guess operating system from service information"""
        services = service_info.get('services', [])
        
        # Windows indicators
        windows_services = ['microsoft-ds', 'netbios-ssn', 'rdp', 'winrm', 'msrpc']
        if any(s in str(services).lower() for s in windows_services):
            return "Windows"
        
        # Linux indicators
        linux_services = ['ssh', 'apache', 'nginx']
        if any(s in str(services).lower() for s in linux_services):
            # Check for specific distros
            banners = str(service_info.get('banners', [])).lower()
            if 'ubuntu' in banners:
                return "Linux (Ubuntu)"
            elif 'debian' in banners:
                return "Linux (Debian)"
            elif 'centos' in banners or 'rhel' in banners:
                return "Linux (RHEL/CentOS)"
            return "Linux"
        
        return None
    
    def lookup_mac_vendor(self, mac: str) -> Optional[str]:
        """Lookup MAC address vendor"""
        if not mac or len(mac) < 8:
            return None
        
        prefix = mac[:8].upper()
        return self.mac_vendors.get(prefix)


class AdvancedPortScanner:
    """Main scanning engine"""
    
    def __init__(self, target: str, params: Dict[str, Any]):
        self.target = target
        self.params = params
        
        # Configuration
        self.scan_type = params.get('scan_type', 'connect')
        self.ports = self._parse_ports(params.get('ports', 'top-100'))
        self.timeout = params.get('timeout', 2000) / 1000.0  # Convert ms to seconds
        self.max_threads = params.get('concurrency', 50)
        self.service_detection = params.get('service_detection', True)
        self.os_detection = params.get('os_detection', False)
        self.aggressive = params.get('aggressive', False)
        
        # Initialize components
        self.service_detector = ServiceDetector()
        self.tls_prober = TLSProber()
        self.http_prober = HTTPProber()
        self.device_fingerprinter = DeviceFingerprinter()
        
        # Results storage
        self.results = []
        self.lock = threading.Lock()
        
        # Determine best scanning method
        self._select_scan_method()
    
    def _select_scan_method(self):
        """Select the best available scanning method"""
        if self.scan_method == 'auto':
            # Auto-select based on available libraries
            if self.use_masscan_speed and self.masscan_scanner:
                self.scan_method = 'masscan'
            elif self.nmap_scanner and self.nmap_scanner.available and self.aggressive:
                self.scan_method = 'nmap'
            elif self.scapy_scanner and self.scapy_scanner.available and self.scan_type == 'syn':
                self.scan_method = 'scapy'
            else:
                self.scan_method = 'connect'
        
        # Log selected method
        method_info = {
            'connect': 'TCP Connect (Pure Python)',
            'masscan': 'Async Fast Scan (Masscan-style)',
            'nmap': 'Python-Nmap Integration',
            'scapy': 'Raw Packet Scan (Scapy)'
        }
        self.selected_method = method_info.get(self.scan_method, 'TCP Connect')
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification"""
        if port_spec == 'top-100':
            return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                   1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000, 1433, 1521, 1434,
                   5432, 6379, 27017, 3000, 5000, 8000, 8081, 9200, 11211, 50000,
                   2049, 2181, 5060, 5672, 6000, 7000, 9000, 9090, 15672, 49152,
                   20, 69, 161, 162, 389, 636, 873, 1080, 1194, 1433, 1521, 2082,
                   2083, 2086, 2087, 2095, 2096, 2222, 3128, 4443, 4444, 5061, 5222,
                   5269, 5555, 5601, 5672, 5984, 6667, 7001, 7002, 8009, 8089, 8180,
                   8443, 8834, 9001, 9043, 9080, 9090, 9443, 10000, 10443, 27017]
        
        elif port_spec == 'top-1000':
            return list(range(1, 1001))
        
        # Parse custom port specification
        ports = []
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    
    def scan(self) -> Dict[str, Any]:
        """Execute port scan"""
        start_time = time.time()
        
        # Resolve target
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            return {
                "success": False,
                "error": f"Failed to resolve hostname: {self.target}"
            }
        
        # Execute scan based on selected method
        if self.scan_method == 'masscan' and self.use_masscan_speed:
            self._scan_masscan_style(ip)
        elif self.scan_method == 'nmap' and self.nmap_scanner:
            self._scan_nmap_style(ip)
        elif self.scan_method == 'scapy' and self.scapy_scanner:
            self._scan_scapy_style(ip)
        else:
            self._scan_connect_style(ip)
        
        # OS detection
        os_guess = None
        os_family = None
        if self.os_detection and self.results:
            if self.scapy_scanner and self.scapy_scanner.available:
                os_info = self.scapy_scanner.os_fingerprint(ip)
                if os_info:
                    os_guess = os_info.get('os_guess')
                    os_family = os_info.get('os_family')
            
            if not os_guess:
                service_info = {
                    'services': [r.service for r in self.results],
                    'banners': [r.banner for r in self.results if r.banner]
                }
                os_guess, os_family = self.device_fingerprinter.guess_os(service_info)
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return {
            "success": True,
            "target": self.target,
            "ip": ip,
            "scan_type": self.scan_type,
            "scan_method": self.selected_method,
            "ports_scanned": len(self.ports),
            "open_ports": len(self.results),
            "os_guess": os_guess,
            "os_family": os_family,
            "results": [asdict(r) for r in self.results],
            "execution_time_ms": execution_time
        }
    
    def _scan_masscan_style(self, ip: str):
        """Fast asynchronous scanning (masscan-inspired)"""
        open_ports = self.masscan_scanner.scan_range(ip, self.ports)
        
        for port_info in open_ports:
            result = self._create_port_result(
                self.target, ip, port_info['port'], 'tcp', 'open', 'masscan'
            )
            
            if self.service_detection:
                self._enhance_with_service_detection(result)
            
            with self.lock:
                self.results.append(result)
    
    def _scan_nmap_style(self, ip: str):
        """Scan using python-nmap library"""
        port_str = ','.join(map(str, self.ports))
        args = "-sV" if self.service_detection else "-sT"
        
        nmap_results = self.nmap_scanner.scan(ip, port_str, args)
        
        if nmap_results and 'results' in nmap_results:
            for port_data in nmap_results['results']:
                result = self._create_port_result(
                    self.target, ip, port_data['port'], 
                    port_data['protocol'], port_data['state'], 'nmap'
                )
                result.service = port_data.get('service')
                result.version = port_data.get('version')
                
                if self.service_detection:
                    self._enhance_with_service_detection(result)
                
                with self.lock:
                    self.results.append(result)
    
    def _scan_scapy_style(self, ip: str):
        """Scan using scapy for raw packet manipulation"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port_scapy, ip, port): port
                for port in self.ports
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result and result.state == 'open':
                    with self.lock:
                        self.results.append(result)
    
    def _scan_connect_style(self, ip: str):
        """Standard TCP connect scan"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port_connect, ip, port): port
                for port in self.ports
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result and result.state == 'open':
                    with self.lock:
                        self.results.append(result)
    
    def _scan_port_scapy(self, ip: str, port: int) -> Optional[PortResult]:
        """Scan single port using scapy"""
        if not self.scapy_scanner:
            return None
        
        state = self.scapy_scanner.syn_scan(ip, port, self.timeout)
        if state != 'open':
            return None
        
        result = self._create_port_result(self.target, ip, port, 'tcp', state, 'scapy')
        
        if self.service_detection:
            self._enhance_with_service_detection(result)
        
        return result
    
    def _scan_port_connect(self, ip: str, port: int) -> Optional[PortResult]:
        """Scan single port using TCP connect"""
        start = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((ip, port))
            sock.close()
            
            if result_code != 0:
                return None
            
            response_time = int((time.time() - start) * 1000)
            
            result = self._create_port_result(self.target, ip, port, 'tcp', 'open', 'connect')
            result.response_time_ms = response_time
            
            if self.service_detection:
                self._enhance_with_service_detection(result)
            
            return result
            
        except Exception:
            return None
    
    def _create_port_result(self, host: str, ip: str, port: int, 
                           protocol: str, state: str, method: str) -> PortResult:
        """Create a PortResult object"""
        return PortResult(
            host=host,
            ip=ip,
            port=port,
            protocol=protocol,
            state=state,
            scan_method=method
        )
    
    def _enhance_with_service_detection(self, result: PortResult):
        """Enhance result with service detection"""
        service, version, banner, confidence = self.service_detector.detect(
            result.ip, result.port
        )
        
        result.service = service
        result.version = version
        result.banner = banner
        result.confidence = confidence
        
        # TLS probing for HTTPS ports
        if result.service == 'https' or result.port in [443, 8443, 8834, 9443]:
            tls_info = self.tls_prober.probe(result.ip, result.port)
            if tls_info:
                result.tls_version = tls_info.get('version')
                result.tls_cipher = tls_info.get('cipher')
                result.tls_common_name = tls_info.get('common_name')
                result.tls_san = tls_info.get('san', [])
                result.tls_issuer = tls_info.get('issuer')
                result.tls_valid_from = tls_info.get('valid_from')
                result.tls_valid_to = tls_info.get('valid_to')
        
        # HTTP probing
        if result.service in ['http', 'https'] or result.port in [80, 443, 8080, 8443]:
            http_info = self.http_prober.probe(
                result.ip, result.port, 
                use_tls=(result.service == 'https' or result.port in [443, 8443])
            )
            if http_info:
                result.http_status = http_info.get('status_code')
                result.http_server = http_info.get('server')
                result.http_title = http_info.get('title')
                result.http_technologies = http_info.get('technologies', [])


def main():
    """Main execution function"""
    try:
        # Read execution context from stdin
        context = json.loads(sys.stdin.read())
        target = context['target']
        params = context.get('params', {})
        
        # Create scanner instance
        scanner = AdvancedPortScanner(target, params)
        
        # Execute scan
        scan_results = scanner.scan()
        
        if not scan_results.get('success'):
            result = {
                "success": False,
                "data": None,
                "errors": [scan_results.get('error', 'Scan failed')]
            }
        else:
            # Format results
            formatted = format_results(scan_results)
            
            result = {
                "success": True,
                "data": {
                    "results": scan_results,
                    "summary": formatted
                },
                "errors": []
            }
        
    except Exception as e:
        result = {
            "success": False,
            "data": None,
            "errors": [f"Scanner error: {str(e)}"]
        }
    
    # Output result as JSON
    print(json.dumps(result, indent=2))


def format_results(scan_data: Dict[str, Any]) -> str:
    """Format scan results as human-readable summary"""
    lines = []
    
    lines.append("=" * 70)
    lines.append(f"PortScan Results - Advanced Network Discovery")
    lines.append(f"Author: 0xbv1 | 0xb0rn3")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Target: {scan_data['target']}")
    lines.append(f"IP Address: {scan_data['ip']}")
    lines.append(f"Scan Method: {scan_data['scan_method']}")
    lines.append(f"Scan Type: {scan_data['scan_type'].upper()}")
    lines.append(f"Ports Scanned: {scan_data['ports_scanned']}")
    lines.append(f"Open Ports Found: {scan_data['open_ports']}")
    lines.append(f"Execution Time: {scan_data['execution_time_ms']}ms")
    
    if scan_data.get('os_guess'):
        lines.append(f"OS Detection: {scan_data['os_guess']}")
        if scan_data.get('os_family'):
            lines.append(f"OS Family: {scan_data['os_family']}")
    
    lines.append("")
    lines.append("=" * 70)
    lines.append("")
    
    if not scan_data['results']:
        lines.append("No open ports found.")
        return "\n".join(lines)
    
    lines.append("OPEN PORTS:")
    lines.append("")
    
    for port_result in scan_data['results']:
        port = port_result['port']
        service = port_result.get('service', 'unknown')
        version = port_result.get('version', '')
        
        port_line = f"  {port}/tcp"
        service_line = f"{service}"
        if version:
            service_line += f" {version}"
        
        lines.append(f"{port_line:15} {service_line}")
        
        # Show scan method
        scan_method = port_result.get('scan_method', 'connect')
        lines.append(f"    Method: {scan_method}")
        
        # Show response time
        resp_time = port_result.get('response_time_ms', 0)
        if resp_time:
            lines.append(f"    Response Time: {resp_time}ms")
        
        # Show confidence
        if port_result.get('confidence'):
            lines.append(f"    Detection Confidence: {port_result['confidence']}%")
        
        # Show TLS information
        if port_result.get('tls_version'):
            lines.append(f"    TLS Version: {port_result['tls_version']}")
            lines.append(f"    TLS Cipher: {port_result['tls_cipher']}")
            
            if port_result.get('tls_common_name'):
                lines.append(f"    Certificate CN: {port_result['tls_common_name']}")
            
            if port_result.get('tls_issuer'):
                lines.append(f"    Certificate Issuer: {port_result['tls_issuer']}")
            
            if port_result.get('tls_san'):
                san_list = ', '.join(port_result['tls_san'][:5])
                lines.append(f"    SAN: {san_list}")
        
        # Show HTTP information
        if port_result.get('http_status'):
            lines.append(f"    HTTP Status: {port_result['http_status']}")
            
            if port_result.get('http_server'):
                lines.append(f"    Server: {port_result['http_server']}")
            
            if port_result.get('http_title'):
                title = port_result['http_title'][:60]
                lines.append(f"    Title: {title}")
            
            if port_result.get('http_technologies'):
                techs = ', '.join(port_result['http_technologies'])
                lines.append(f"    Technologies: {techs}")
        
        # Show device information
        if port_result.get('device_type'):
            lines.append(f"    Device Type: {port_result['device_type']}")
        
        if port_result.get('mac_vendor'):
            lines.append(f"    Vendor: {port_result['mac_vendor']}")
        
        # Show banner snippet
        if port_result.get('banner'):
            banner = port_result['banner'][:100].replace('\n', ' ').replace('\r', '')
            lines.append(f"    Banner: {banner}")
        
        lines.append("")
    
    lines.append("=" * 70)
    lines.append("Scan completed successfully")
    lines.append("=" * 70)
    
    return "\n".join(lines)


if __name__ == '__main__':
    main()
        """Parse port specification"""
        if port_spec == 'top-100':
            return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                   1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000, 1433, 1521, 1434,
                   5432, 6379, 27017, 3000, 5000, 8000, 8081, 9200, 11211, 50000,
                   2049, 2181, 5060, 5672, 6000, 7000, 9000, 9090, 15672, 49152,
                   20, 69, 161, 162, 389, 636, 873, 1080, 1194, 1433, 1521, 2082,
                   2083, 2086, 2087, 2095, 2096, 2222, 3128, 4443, 4444, 5061, 5222,
                   5269, 5555, 5601, 5672, 5984, 6667, 7001, 7002, 8009, 8089, 8180,
                   8443, 8834, 9001, 9043, 9080, 9090, 9443, 10000, 10443, 27017]
        
        elif port_spec == 'top-1000':
            # Would implement full top 1000 list
            return list(range(1, 1001))
        
        # Parse custom port specification
        ports = []
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    
    def scan(self) -> Dict[str, Any]:
        """Execute port scan"""
        start_time = time.time()
        
        # Resolve target
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            return {
                "success": False,
                "error": f"Failed to resolve hostname: {self.target}"
            }
        
        # Scan ports
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, self.target, ip, port): port
                for port in self.ports
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result and result.state == 'open':
                    with self.lock:
                        self.results.append(result)
        
        # Post-processing
        if self.os_detection and self.results:
            os_guess = self._guess_os()
        else:
            os_guess = None
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return {
            "success": True,
            "target": self.target,
            "ip": ip,
            "scan_type": self.scan_type,
            "ports_scanned": len(self.ports),
            "open_ports": len(self.results),
            "os_guess": os_guess,
            "results": [asdict(r) for r in self.results],
            "execution_time_ms": execution_time
        }
    
    def _scan_port(self, host: str, ip: str, port: int) -> Optional[PortResult]:
        """Scan a single port"""
        start = time.time()
        
        try:
            # TCP Connect scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((ip, port))
            sock.close()
            
            if result_code != 0:
                return None
            
            response_time = int((time.time() - start) * 1000)
            
            # Port is open - create result
            result = PortResult(
                host=host,
                ip=ip,
                port=port,
                protocol="tcp",
                state="open",
                response_time_ms=response_time
            )
            
            # Service detection
            if self.service_detection:
                service, version, banner, confidence = self.service_detector.detect(ip, port)
                result.service = service
                result.version = version
                result.banner = banner
                result.confidence = confidence
                
                # TLS probing for HTTPS ports
                if service == 'https' or port in [443, 8443, 8834, 9443]:
                    tls_info = self.tls_prober.probe(ip, port)
                    if tls_info:
                        result.tls_version = tls_info.get('version')
                        result.tls_cipher = tls_info.get('cipher')
                        result.tls_common_name = tls_info.get('common_name')
                        result.tls_san = tls_info.get('san', [])
                        result.tls_issuer = tls_info.get('issuer')
                        result.tls_valid_from = tls_info.get('valid_from')
                        result.tls_valid_to = tls_info.get('valid_to')
                
                # HTTP probing
                if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                    http_info = self.http_prober.probe(ip, port, use_tls=(service == 'https' or port in [443, 8443]))
                    if http_info:
                        result.http_status = http_info.get('status_code')
                        result.http_server = http_info.get('server')
                        result.http_title = http_info.get('title')
                        result.http_technologies = http_info.get('technologies', [])
            
            return result
            
        except Exception:
            return None
    
    def _guess_os(self) -> Optional[str]:
        """Guess operating system from scan results"""
        service_info = {
            'services': [r.service for r in self.results],
            'banners': [r.banner for r in self.results if r.banner]
        }
        return self.device_fingerprinter.guess_os(service_info)


def main():
    """Main execution function"""
    try:
        # Read execution context from stdin
        context = json.loads(sys.stdin.read())
        target = context['target']
        params = context.get('params', {})
        
        # Create scanner instance
        scanner = AdvancedPortScanner(target, params)
        
        # Execute scan
        scan_results = scanner.scan()
        
        if not scan_results.get('success'):
            result = {
                "success": False,
                "data": None,
                "errors": [scan_results.get('error', 'Scan failed')]
            }
        else:
            # Format results
            formatted = format_results(scan_results)
            
            result = {
                "success": True,
                "data": {
                    "results": scan_results,
                    "summary": formatted
                },
                "errors": []
            }
        
    except Exception as e:
        result = {
            "success": False,
            "data": None,
            "errors": [f"Scanner error: {str(e)}"]
        }
    
    # Output result as JSON
    print(json.dumps(result, indent=2))


def format_results(scan_data: Dict[str, Any]) -> str:
    """Format scan results as human-readable summary"""
    lines = []
    
    lines.append(f"Network Scan Results for {scan_data['target']}")
    lines.append(f"IP Address: {scan_data['ip']}")
    lines.append(f"Scan Type: {scan_data['scan_type'].upper()}")
    lines.append(f"Ports Scanned: {scan_data['ports_scanned']}")
    lines.append(f"Open Ports Found: {scan_data['open_ports']}")
    lines.append(f"Execution Time: {scan_data['execution_time_ms']}ms")
    
    if scan_data.get('os_guess'):
        lines.append(f"OS Guess: {scan_data['os_guess']}")
    
    lines.append("")
    lines.append("=" * 70)
    lines.append("")
    
    if not scan_data['results']:
        lines.append("No open ports found.")
        return "\n".join(lines)
    
    lines.append("OPEN PORTS:")
    lines.append("")
    
    for port_result in scan_data['results']:
        port = port_result['port']
        service = port_result.get('service', 'unknown')
        version = port_result.get('version', '')
        
        port_line = f"  {port}/tcp"
        service_line = f"{service}"
        if version:
            service_line += f" {version}"
        
        lines.append(f"{port_line:15} {service_line}")
        
        # Show response time
        resp_time = port_result.get('response_time_ms', 0)
        lines.append(f"    Response Time: {resp_time}ms")
        
        # Show confidence if available
        if port_result.get('confidence'):
            lines.append(f"    Detection Confidence: {port_result['confidence']}%")
        
        # Show TLS information
        if port_result.get('tls_version'):
            lines.append(f"    TLS Version: {port_result['tls_version']}")
            lines.append(f"    TLS Cipher: {port_result['tls_cipher']}")
            
            if port_result.get('tls_common_name'):
                lines.append(f"    Certificate CN: {port_result['tls_common_name']}")
            
            if port_result.get('tls_issuer'):
                lines.append(f"    Certificate Issuer: {port_result['tls_issuer']}")
            
            if port_result.get('tls_san'):
                san_list = ', '.join(port_result['tls_san'][:5])
                lines.append(f"    SAN: {san_list}")
        
        # Show HTTP information
        if port_result.get('http_status'):
            lines.append(f"    HTTP Status: {port_result['http_status']}")
            
            if port_result.get('http_server'):
                lines.append(f"    Server: {port_result['http_server']}")
            
            if port_result.get('http_title'):
                title = port_result['http_title'][:60]
                lines.append(f"    Title: {title}")
            
            if port_result.get('http_technologies'):
                techs = ', '.join(port_result['http_technologies'])
                lines.append(f"    Technologies: {techs}")
        
        # Show device information
        if port_result.get('device_type'):
            lines.append(f"    Device Type: {port_result['device_type']}")
        
        if port_result.get('mac_vendor'):
            lines.append(f"    Vendor: {port_result['mac_vendor']}")
        
        # Show banner snippet
        if port_result.get('banner'):
            banner = port_result['banner'][:100].replace('\n', ' ').replace('\r', '')
            lines.append(f"    Banner: {banner}")
        
        lines.append("")
    
    return "\n".join(lines)


if __name__ == '__main__':
    main()
