#!/usr/bin/env python3
"""
Network Reconnaissance Module for SecV v1.0
Author: 0xb0rn3 | github.com/0xb0rn3

Concurrent multi-engine network profiling:
  nmap, masscan, rustscan, arp-scan, Shodan, DNS, WHOIS, ASN
  — all running simultaneously for maximum speed.
"""

import json
import sys
import os
import subprocess
import socket
import time
import re
import shutil
import ipaddress
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

# NVD real-time CVE enrichment (optional)
_NVD_AVAILABLE = False
try:
    _nvd_dir = Path(__file__).parent.parent.parent / "mobile"
    if str(_nvd_dir) not in sys.path:
        sys.path.insert(0, str(_nvd_dir))
    from nvd_lookup import lookup_cve, search_cves_by_keyword
    _NVD_AVAILABLE = True
except ImportError:
    def lookup_cve(cve_id, api_key=""):  # type: ignore
        return None
    def search_cves_by_keyword(kw, results=5, api_key=""):  # type: ignore
        return []

# ============================================================================
# CAPABILITY DETECTION
# ============================================================================

CAPS: Dict[str, Any] = {
    'nmap':         bool(shutil.which('nmap')),
    'masscan':      bool(shutil.which('masscan')),
    'rustscan':     bool(shutil.which('rustscan')),
    'arp_scan':     bool(shutil.which('arp-scan')),
    'fping':        bool(shutil.which('fping')),
    'whois':        bool(shutil.which('whois')),
    'root':         os.geteuid() == 0,
    'gobuster':     bool(shutil.which('gobuster')),
    'ffuf':         bool(shutil.which('ffuf')),
    'whatweb':      bool(shutil.which('whatweb')),
    'nikto':        bool(shutil.which('nikto')),
    'searchsploit': bool(shutil.which('searchsploit')),
    'xsltproc':     bool(shutil.which('xsltproc')),
    'proxychains4': bool(shutil.which('proxychains4')),
    'nmblookup':    bool(shutil.which('nmblookup')),
    'enum4linux':   bool(shutil.which('enum4linux')),
    'smbclient':    bool(shutil.which('smbclient')),
    'snmpwalk':     bool(shutil.which('snmpwalk')),
    'curl':         bool(shutil.which('curl')),
}

try:
    import scapy.all as _scapy
    from scapy.layers.inet import IP, ICMP, TCP
    from scapy.layers.l2 import ARP, Ether
    CAPS['scapy'] = True
except (ImportError, Exception):
    CAPS['scapy'] = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    CAPS['requests'] = True
except ImportError:
    CAPS['requests'] = False

try:
    import dns.resolver
    import dns.reversename
    CAPS['dns'] = True
except ImportError:
    CAPS['dns'] = False

try:
    import shodan as _shodan_mod
    CAPS['shodan_lib'] = True
except ImportError:
    CAPS['shodan_lib'] = False

try:
    import mmh3 as _mmh3
    CAPS['mmh3'] = True
except ImportError:
    _mmh3 = None  # type: ignore
    CAPS['mmh3'] = False

# ============================================================================
# OUI VENDOR DATABASE
# ============================================================================

OUI_DB: Dict[str, str] = {
    # Hypervisors / virtual
    '00:00:0c': 'Cisco',         '00:50:56': 'VMware',         '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',    '52:54:00': 'QEMU/KVM',       '00:16:3e': 'Xen',
    '02:42:ac': 'Docker',        '00:15:5d': 'Microsoft (Hyper-V)',
    # Raspberry Pi / Arduino / IoT
    'b8:27:eb': 'Raspberry Pi',  'dc:a6:32': 'Raspberry Pi',   'e4:5f:01': 'Raspberry Pi',
    '28:cd:c1': 'Raspberry Pi',  '2c:cf:67': 'Raspberry Pi',   'd8:3a:dd': 'Raspberry Pi',
    '70:ff:76': 'Arduino',       'a4:cf:12': 'Espressif (IoT)','24:0a:c4': 'Espressif (IoT)',
    '3c:5a:b4': 'Google',        '54:60:09': 'Google',
    # Apple — iPhone, iPad, Mac, AirPods
    'fc:aa:14': 'Apple',  '3c:22:fb': 'Apple',  'a4:c3:f0': 'Apple',
    '88:a9:b7': 'Apple',  '04:34:f6': 'Apple',  '00:17:f2': 'Apple',
    'ac:bc:32': 'Apple',  'f4:f1:5a': 'Apple',  '8c:85:90': 'Apple',
    '78:fd:94': 'Apple',  'a8:51:ab': 'Apple',  '18:af:61': 'Apple',
    'f0:99:bf': 'Apple',  '28:cf:e9': 'Apple',  '9c:f3:87': 'Apple',
    'd0:03:4b': 'Apple',  '40:98:ad': 'Apple',  'b8:8d:12': 'Apple',
    '60:03:08': 'Apple',  'bc:92:6b': 'Apple',  '04:52:f3': 'Apple',
    '70:ec:e4': 'Apple',  'a4:b1:97': 'Apple',  '14:7d:da': 'Apple',
    '00:03:93': 'Apple',  'ac:87:a3': 'Apple',  '3c:d0:f8': 'Apple',
    '68:fb:7e': 'Apple',  '20:c9:d0': 'Apple',  'f0:b4:79': 'Apple',
    # Samsung
    '00:1a:4b': 'Samsung', '40:b0:76': 'Samsung', 'c4:57:6e': 'Samsung',
    'b4:3a:28': 'Samsung', '78:52:1a': 'Samsung', '98:52:b1': 'Samsung',
    '00:07:ab': 'Samsung', 'a4:23:05': 'Samsung', 'f8:77:b8': 'Samsung',
    # Intel / networking silicon
    '00:1b:21': 'Intel',   '00:23:14': 'Intel',   '8c:8d:28': 'Intel',
    '00:02:b3': 'Intel',   '8c:ec:4b': 'Intel',   'a4:c3:f0': 'Intel',
    '00:02:c9': 'Mellanox','00:0e:1e': 'QLogic',
    '00:0a:f7': 'Broadcom','00:10:18': 'Broadcom',
    # Enterprise network / security vendors
    '00:23:24': 'Fortinet',  '00:09:0f': 'Fortinet',  '00:0d:ed': 'Fortinet',
    '00:18:18': 'Juniper',   '2c:21:72': 'Juniper',   '00:05:85': 'Juniper',
    '00:1e:13': 'MikroTik',  '4c:5e:0c': 'MikroTik',  '00:0c:42': 'MikroTik',
    '00:1d:c0': 'Palo Alto', '1b:17:00': 'Palo Alto',
    '00:1c:73': 'Arista',    '74:83:ef': 'Arista',
    '00:15:6d': 'Ubiquiti',  '04:18:d6': 'Ubiquiti',  '24:a4:3c': 'Ubiquiti',
    '00:09:5b': 'NETGEAR',   '20:4e:7f': 'NETGEAR',   'a0:21:b7': 'NETGEAR',
    '00:26:82': 'TP-Link',   'f4:f2:6d': 'TP-Link',   '50:c7:bf': 'TP-Link',
    '00:50:ba': 'D-Link',    '14:d6:4d': 'D-Link',    '00:05:5f': 'D-Link',
    '00:18:f3': 'ASUS',      '04:92:26': 'ASUS',      '00:1a:92': 'ASUS',
    '00:1e:e5': 'Linksys',   '00:03:2f': 'Linksys',
    '00:0d:3a': 'Microsoft', '00:12:5a': 'Microsoft',
    '00:21:5a': 'HP',        '3c:d9:2b': 'HP',        '00:0b:86': 'HP Enterprise',
    '00:14:22': 'Dell',      'f8:db:88': 'Dell',       '00:1a:a0': 'Dell',
    '00:0f:1f': 'IBM',       '00:1a:64': 'IBM',        '00:02:55': 'IBM',
    'ac:1f:6b': 'Supermicro','0c:c4:7a': 'Supermicro','00:25:90': 'Supermicro',
    '00:23:7d': 'Cisco',     '58:97:bd': 'Cisco',      '00:1b:54': 'Cisco',
    '00:e0:4c': 'Realtek',   '00:01:80': 'ASUS',       '00:01:64': 'Lenovo',
    '00:01:24': 'Acer',
}

# Apple/iOS-specific port signatures
APPLE_PORTS: Dict[int, str] = {
    62078: 'ios-lockdownd',  # iOS lockdown daemon — definitive iOS/macOS indicator
    5000:  'airplay',        # AirPlay receiver
    7000:  'airplay-video',  # AirPlay video
    49152: 'apple-bonjour',  # Bonjour/mDNS dynamic port
    3689:  'daap',           # iTunes music sharing (DAAP)
    5353:  'mdns',           # mDNS / Bonjour
    548:   'afp',            # Apple Filing Protocol
    88:    'kerberos',       # Kerberos (common on macOS)
}

def lookup_mac_vendor(mac: str) -> str:
    if not mac:
        return ''
    norm = mac.lower()
    for prefix, vendor in OUI_DB.items():
        if norm.startswith(prefix):
            return vendor
    return ''

# ============================================================================
# CVE DATABASE
# ============================================================================

CVE_DB: Dict[str, List[Dict]] = {
    'ssh': [
        {'id': 'CVE-2023-38408', 'cvss': 9.8, 'desc': 'openssh-agent remote code execution',  'affects_max': '9.3p1'},
        {'id': 'CVE-2021-41617', 'cvss': 7.0, 'desc': 'sshd privilege escalation',            'affects_max': '8.7'},
        {'id': 'CVE-2018-15473', 'cvss': 5.3, 'desc': 'OpenSSH username enumeration',         'affects_max': '7.6'},
        {'id': 'CVE-2016-20012', 'cvss': 5.3, 'desc': 'OpenSSH username enumeration < 8.9',   'affects_max': '8.8'},
    ],
    'openssh': [
        {'id': 'CVE-2023-38408', 'cvss': 9.8, 'desc': 'ssh-agent remote code execution',      'affects_max': '9.3p1'},
        {'id': 'CVE-2021-41617', 'cvss': 7.0, 'desc': 'Privilege escalation in sshd',         'affects_max': '8.7'},
        {'id': 'CVE-2018-15473', 'cvss': 5.3, 'desc': 'Username enumeration side-channel',    'affects_max': '7.6'},
    ],
    'apache': [
        {'id': 'CVE-2021-41773', 'cvss': 9.8, 'desc': 'Path traversal + RCE (2.4.49)',         'affects_min': '2.4.49', 'affects_max': '2.4.49'},
        {'id': 'CVE-2021-42013', 'cvss': 9.8, 'desc': 'Path traversal + RCE (2.4.49-2.4.50)', 'affects_min': '2.4.49', 'affects_max': '2.4.50'},
        {'id': 'CVE-2022-31813', 'cvss': 9.8, 'desc': 'mod_proxy header smuggling',            'affects_max': '2.4.54'},
        {'id': 'CVE-2021-40438', 'cvss': 9.0, 'desc': 'mod_proxy SSRF',                        'affects_max': '2.4.48'},
        {'id': 'CVE-2017-7679',  'cvss': 9.8, 'desc': 'mod_mime buffer overread',              'affects_max': '2.4.25'},
    ],
    'nginx': [
        {'id': 'CVE-2021-23017', 'cvss': 7.7, 'desc': 'One-byte overwrite in DNS resolver',   'affects_max': '1.21.0'},
        {'id': 'CVE-2019-9511',  'cvss': 7.5, 'desc': 'HTTP/2 Data Dribble DoS',              'affects_max': '1.17.2'},
        {'id': 'CVE-2013-4547',  'cvss': 7.5, 'desc': 'Null byte in URI processing',          'affects_max': '1.5.6'},
    ],
    'http': [
        {'id': 'CVE-2021-41773', 'cvss': 9.8, 'desc': 'Apache 2.4.49 path traversal (if Apache)'},
    ],
    'https': [
        {'id': 'CVE-2014-0160', 'cvss': 7.5, 'desc': 'OpenSSL Heartbleed (if old OpenSSL)'},
        {'id': 'CVE-2022-0778', 'cvss': 7.5, 'desc': 'OpenSSL BN_mod_sqrt() infinite loop'},
    ],
    'mysql': [
        {'id': 'CVE-2012-2122',  'cvss': 7.5, 'desc': 'Authentication bypass via timing',     'affects_max': '5.5.23'},
        {'id': 'CVE-2021-2471',  'cvss': 7.5, 'desc': 'Multiple MySQL < 8.0.27 vulns',        'affects_max': '8.0.26'},
        {'id': 'CVE-2020-14765', 'cvss': 6.5, 'desc': 'InnoDB denial of service',             'affects_max': '8.0.20'},
    ],
    'postgresql': [
        {'id': 'CVE-2019-10164', 'cvss': 8.8, 'desc': 'Stack overflow via security-definer',  'affects_max': '11.2'},
        {'id': 'CVE-2022-1552',  'cvss': 8.8, 'desc': 'Autovacuum privilege escalation',      'affects_max': '14.2'},
        {'id': 'CVE-2023-2454',  'cvss': 7.2, 'desc': 'Row security policy bypass',           'affects_max': '15.2'},
    ],
    'redis': [
        {'id': 'CVE-2022-0543',  'cvss': 10.0, 'desc': 'Lua sandbox escape (Debian/Ubuntu)',  'affects_max': '6.0.16'},
        {'id': 'CVE-2021-32625', 'cvss': 7.5,  'desc': 'Integer overflow in GETDEL',          'affects_max': '6.2.4'},
        {'id': 'CVE-2020-14147', 'cvss': 7.5,  'desc': 'Integer overflow in ziplistResize',   'affects_max': '6.0.11'},
    ],
    'mongodb': [
        {'id': 'CVE-2021-32030', 'cvss': 7.5, 'desc': 'Improper authentication in SCRAM'},
        {'id': 'CVE-2019-2389', 'cvss': 6.5, 'desc': 'Secondary crash with RBAC'},
    ],
    'elasticsearch': [
        {'id': 'CVE-2021-22145', 'cvss': 6.5, 'desc': 'Memory disclosure via error message'},
        {'id': 'CVE-2020-7020', 'cvss': 7.5, 'desc': 'Improper URL validation'},
    ],
    'ftp': [
        {'id': 'CVE-2015-3306', 'cvss': 10.0, 'desc': 'ProFTPD mod_copy arbitrary cmd exec',  'affects_max': '1.3.5'},
        {'id': 'CVE-2011-2523', 'cvss': 10.0, 'desc': 'vsftpd 2.3.4 backdoor',               'affects_min': '2.3.4', 'affects_max': '2.3.4'},
    ],
    'smb': [
        {'id': 'CVE-2017-0144', 'cvss': 9.3, 'desc': 'EternalBlue SMB RCE (WannaCry)'},
        {'id': 'CVE-2020-0796', 'cvss': 10.0, 'desc': 'SMBGhost SMBv3 RCE'},
        {'id': 'CVE-2021-36942', 'cvss': 7.5, 'desc': 'PetitPotam NTLM relay'},
    ],
    'microsoft-ds': [
        {'id': 'CVE-2017-0144', 'cvss': 9.3, 'desc': 'EternalBlue SMB RCE (WannaCry)'},
        {'id': 'CVE-2020-0796', 'cvss': 10.0, 'desc': 'SMBGhost RCE (SMBv3.1.1)'},
    ],
    'ms-wbt-server': [
        {'id': 'CVE-2019-0708', 'cvss': 9.8, 'desc': 'BlueKeep RDP pre-auth RCE'},
        {'id': 'CVE-2020-0609', 'cvss': 9.8, 'desc': 'Windows RDS Gateway pre-auth RCE'},
    ],
    'rdp': [
        {'id': 'CVE-2019-0708', 'cvss': 9.8, 'desc': 'BlueKeep RDP pre-auth RCE'},
        {'id': 'CVE-2012-0002', 'cvss': 9.3, 'desc': 'MS12-020 RDP DoS/potential RCE'},
    ],
    'vnc': [
        {'id': 'CVE-2019-15681', 'cvss': 7.5, 'desc': 'LibVNCServer memory disclosure'},
        {'id': 'CVE-2018-7550', 'cvss': 8.8, 'desc': 'VNC memory corruption'},
    ],
    'telnet': [
        {'id': 'CVE-2011-4862', 'cvss': 10.0, 'desc': 'telnetd encryption key overflow'},
    ],
    'tomcat': [
        {'id': 'CVE-2020-1938', 'cvss': 9.8, 'desc': 'Ghostcat AJP file read/include'},
        {'id': 'CVE-2019-0232', 'cvss': 8.1, 'desc': 'CGI Servlet RCE on Windows'},
        {'id': 'CVE-2021-33037', 'cvss': 5.3, 'desc': 'HTTP request smuggling'},
    ],
    'memcached': [
        {'id': 'CVE-2013-7290', 'cvss': 7.5, 'desc': 'Remote DoS via SASL authentication'},
    ],
    'docker': [
        {'id': 'CVE-2019-5736', 'cvss': 8.6, 'desc': 'runc container escape'},
        {'id': 'CVE-2020-15257', 'cvss': 5.2, 'desc': 'containerd host network namespace escape'},
    ],
    'mqtt': [
        {'id': 'CVE-2023-28366', 'cvss': 7.5, 'desc': 'Mosquitto MQTT broker memory corruption via malformed packets'},
        {'id': 'MQTT-NO-AUTH',   'cvss': 9.1, 'desc': 'MQTT broker allows unauthenticated connections'},
    ],
    'modbus': [
        {'id': 'MODBUS-NO-AUTH', 'cvss': 9.8, 'desc': 'Modbus TCP has no authentication — unauthenticated ICS read/write possible'},
    ],
    'bacnet': [
        {'id': 'BACNET-NO-AUTH', 'cvss': 9.8, 'desc': 'BACnet/IP allows unauthenticated read/write to building automation systems'},
    ],
    'dnp3': [
        {'id': 'DNP3-NO-AUTH',   'cvss': 9.8, 'desc': 'DNP3 lacks authentication — unauthenticated SCADA control possible'},
    ],
    's7comm': [
        {'id': 'CVE-2019-13945', 'cvss': 7.5, 'desc': 'Siemens S7 SIMATIC improper input validation'},
        {'id': 'CVE-2019-10929', 'cvss': 7.5, 'desc': 'Siemens S7-300/400 buffer over-read via crafted packets'},
        {'id': 'CVE-2014-2908',  'cvss': 9.0, 'desc': 'Siemens S7 PLC remote crash via Metasploit module'},
    ],
    'niagara-fox': [
        {'id': 'CVE-2021-33558', 'cvss': 7.5, 'desc': 'Tridium Niagara Fox protocol information disclosure'},
        {'id': 'CVE-2012-3007',  'cvss': 7.8, 'desc': 'Tridium Niagara AX path traversal / arbitrary file read'},
    ],
    'rtsp': [
        {'id': 'RTSP-NO-AUTH',   'cvss': 7.5, 'desc': 'RTSP stream accessible without authentication — camera feed exposed'},
    ],
    'coap': [
        {'id': 'COAP-NO-AUTH',   'cvss': 7.5, 'desc': 'CoAP (UDP/5683) has no authentication by default — IoT command injection risk'},
    ],
    'hikvision': [
        {'id': 'CVE-2021-36260', 'cvss': 9.8, 'desc': 'Hikvision unauthenticated RCE via web API (CVSS 9.8)'},
        {'id': 'CVE-2022-28171', 'cvss': 9.8, 'desc': 'Hikvision authentication bypass in web panel'},
    ],
    'dahua': [
        {'id': 'CVE-2021-33044', 'cvss': 9.8, 'desc': 'Dahua authentication bypass via identity authentication bypass'},
        {'id': 'CVE-2021-33045', 'cvss': 9.8, 'desc': 'Dahua smart IP cameras authentication bypass'},
    ],
}

# Version-specific CVE lookups — exact service+version string → CVE IDs
# Source: NVD + r3cond0g vulnDB; keyed as "product version" lowercase
VERSIONED_CVE_DB: Dict[str, List[str]] = {
    'apache 2.4.44':  ['CVE-2020-9490'],
    'apache 2.4.48':  ['CVE-2019-17567'],
    'apache 2.4.49':  ['CVE-2021-41773', 'CVE-2021-42013'],
    'apache 2.4.50':  ['CVE-2021-41524', 'CVE-2021-42013'],
    'apache 2.4.53':  ['CVE-2022-22719', 'CVE-2022-22721'],
    'apache 2.4.54':  ['CVE-2022-26377', 'CVE-2022-28330', 'CVE-2022-28614'],
    'openssh 7.9':    ['CVE-2019-6110', 'CVE-2019-6111'],
    'openssh 8.5':    ['CVE-2021-28041'],
    'openssh 9.2':    ['CVE-2023-25136'],
    'nginx 1.6.1':    ['CVE-2014-3556'],
    'nginx 1.6.2':    ['CVE-2014-3616'],
    'nginx 1.9.10':   ['CVE-2016-0742', 'CVE-2016-0746'],
    'mysql 5.7.31':   ['CVE-2018-2562'],
    'mysql 8.0.22':   ['CVE-2020-2578', 'CVE-2020-2621'],
    'mysql 5.5':      ['CVE-2012-2122'],
    'php 7.4.28':     ['CVE-2021-21708'],
    'php 8.0.30':     ['CVE-2023-3824'],
    'php 8.1':        ['CVE-2023-3823'],
    'openssl 1.0.1':  ['CVE-2014-0160'],  # Heartbleed
    'openssl 1.0.2':  ['CVE-2016-0800'],  # DROWN
    'openssl 1.1.1':  ['CVE-2022-0778'],
    'postgresql 15.4':['CVE-2023-39418'],
    'proftpd 1.3.5':  ['CVE-2015-3306'],
    'vsftpd 2.3.4':   ['CVE-2011-2523'],
    'tomcat 9.0':     ['CVE-2020-1938'],  # Ghostcat
    'tomcat 10.0':    ['CVE-2021-33037'],
    'redis 6.0':      ['CVE-2022-0543'],
    'samba 4':        ['CVE-2021-44142'],
    'samba 3':        ['CVE-2017-7494'],  # SambaCry
    'log4j 2.':       ['CVE-2021-44228', 'CVE-2021-45046'],  # Log4Shell
    'spring 5.3':     ['CVE-2022-22965'],  # Spring4Shell
    'exchange 2013':  ['CVE-2021-26855', 'CVE-2021-27065'],  # ProxyLogon
    'exchange 2016':  ['CVE-2021-26855', 'CVE-2021-26857'],
    'exchange 2019':  ['CVE-2021-26855'],
}

# Service → CPE vendor/product for improved CVE correlation
SERVICE_TO_CPE: Dict[str, Dict[str, str]] = {
    'http':          {'vendor': 'apache',     'product': 'http_server'},
    'https':         {'vendor': 'apache',     'product': 'http_server'},
    'nginx':         {'vendor': 'nginx',      'product': 'nginx'},
    'ssh':           {'vendor': 'openbsd',    'product': 'openssh'},
    'openssh':       {'vendor': 'openbsd',    'product': 'openssh'},
    'ftp':           {'vendor': 'proftpd',    'product': 'proftpd'},
    'mysql':         {'vendor': 'oracle',     'product': 'mysql'},
    'mariadb':       {'vendor': 'mariadb',    'product': 'mariadb'},
    'postgresql':    {'vendor': 'postgresql', 'product': 'postgresql'},
    'redis':         {'vendor': 'redis',      'product': 'redis'},
    'mongodb':       {'vendor': 'mongodb',    'product': 'mongodb'},
    'smtp':          {'vendor': 'postfix',    'product': 'postfix'},
    'rdp':           {'vendor': 'microsoft',  'product': 'remote_desktop_services'},
    'ms-wbt-server': {'vendor': 'microsoft',  'product': 'remote_desktop_services'},
    'microsoft-ds':  {'vendor': 'microsoft',  'product': 'windows'},
    'netbios-ssn':   {'vendor': 'microsoft',  'product': 'windows'},
    'smb':           {'vendor': 'microsoft',  'product': 'windows'},
    'ldap':          {'vendor': 'openldap',   'product': 'openldap'},
    'vnc':           {'vendor': 'realvnc',    'product': 'vnc'},
    'telnet':        {'vendor': 'gnu',        'product': 'inetutils'},
    'snmp':          {'vendor': 'net-snmp',   'product': 'net-snmp'},
    'tomcat':        {'vendor': 'apache',     'product': 'tomcat'},
    'iis':           {'vendor': 'microsoft',  'product': 'iis'},
    'oracle':        {'vendor': 'oracle',     'product': 'database'},
    'mssql':         {'vendor': 'microsoft',  'product': 'sql_server'},
    'ms-sql-s':      {'vendor': 'microsoft',  'product': 'sql_server'},
    'elasticsearch': {'vendor': 'elastic',    'product': 'elasticsearch'},
    'docker':        {'vendor': 'docker',     'product': 'engine'},
}


def _parse_ver(v: str) -> tuple:
    """Parse version string to comparable numeric tuple. '9.3p2' → (9,3,2)."""
    v = re.sub(r'p(\d+)', r'.\1', v.strip().lower())
    parts = []
    for seg in re.split(r'[.\-_]', v):
        m = re.match(r'^(\d+)', seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _ver_in_range(detected: str, affects_min: str = '', affects_max: str = '') -> bool:
    """Return True if detected version falls within [affects_min, affects_max] (inclusive).
    Unknown detected version conservatively returns True (assume affected)."""
    if not detected:
        return True
    d = _parse_ver(detected)
    if affects_min:
        m = _parse_ver(affects_min)
        maxl = max(len(d), len(m))
        if (d + (0,) * (maxl - len(d))) < (m + (0,) * (maxl - len(m))):
            return False  # detected < affects_min
    if affects_max:
        m = _parse_ver(affects_max)
        maxl = max(len(d), len(m))
        if (d + (0,) * (maxl - len(d))) > (m + (0,) * (maxl - len(m))):
            return False  # detected > affects_max (patched)
    return True


def correlate_cves(service: str, product: str = '', version: str = '') -> List[Dict]:
    """Map detected service/product/version to relevant CVEs, deduped by CVE ID.
    Version range fields affects_min/affects_max prevent false positives on patched versions."""
    seen_ids: Set[str] = set()
    findings: List[Dict] = []
    lookup_str = (service + ' ' + product).lower()

    # Service-based lookup with version-range filtering
    for key, cves in CVE_DB.items():
        if key in lookup_str:
            for cve in cves:
                cve_id = cve.get('id', '')
                if not cve_id or cve_id in seen_ids:
                    continue
                if version and (cve.get('affects_max') or cve.get('affects_min')):
                    if not _ver_in_range(version, cve.get('affects_min', ''), cve.get('affects_max', '')):
                        continue
                seen_ids.add(cve_id)
                findings.append(cve)

    # Version-specific lookup — exact prefix match on "product version" key
    if version:
        ver_key = f'{(product or service).lower()} {version.lower()}'
        # Normalize: convert p-suffix so 'openssh 9.3p2' becomes 'openssh 9.3.2'
        ver_key_norm = re.sub(r'p(\d+)', r'.\1', ver_key)
        for pattern, cve_ids in VERSIONED_CVE_DB.items():
            pat_norm = re.sub(r'p(\d+)', r'.\1', pattern)
            # Match only if the version component starts with the pattern version
            # and the next char (if any) is a separator — prevents '9.3' matching '9.31'
            if re.match(r'^' + re.escape(pat_norm) + r'([.\-_ ]|$)', ver_key_norm):
                for cve_id in cve_ids:
                    if cve_id not in seen_ids:
                        seen_ids.add(cve_id)
                        findings.append({'id': cve_id, 'cvss': 7.5,
                                         'desc': f'Known vulnerability in {product or service} {version}',
                                         'version_specific': True})

    return sorted(findings, key=lambda c: -c.get('cvss', 0))[:8]

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ServiceInfo:
    port: int
    protocol: str = 'tcp'
    state: str = 'open'
    service: str = ''
    product: str = ''
    version: str = ''
    banner: str = ''
    http_title: str = ''
    http_server: str = ''
    http_status: int = 0
    http_technologies: List[str] = field(default_factory=list)
    http_security_headers: Dict[str, str] = field(default_factory=dict)
    http_missing_headers: List[str] = field(default_factory=list)
    http_cookies: List[Dict] = field(default_factory=list)
    http_redirect_chain: List[str] = field(default_factory=list)
    tls_subject: str = ''
    tls_issuer: str = ''
    tls_expiry: str = ''
    tls_not_before: str = ''
    tls_sig_algo: str = ''
    tls_sans: List[str] = field(default_factory=list)
    cves: List[Dict] = field(default_factory=list)
    nmap_scripts: Dict[str, str] = field(default_factory=dict)
    response_ms: float = 0.0
    confidence: int = 0
    sources: List[str] = field(default_factory=list)

@dataclass
class HostProfile:
    ip: str
    state: str = 'up'
    hostname: str = ''
    mac: str = ''
    mac_vendor: str = ''
    os_family: str = ''
    os_version: str = ''
    os_confidence: int = 0
    device_type: str = ''
    device_category: str = ''  # camera | router | nas | iot | ics | surveillance | unknown
    ttl: int = 0
    latency_ms: float = 0.0
    services: List[ServiceInfo] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    reverse_dns: str = ''
    whois_org: str = ''
    asn: str = ''
    asn_org: str = ''
    country: str = ''
    city: str = ''
    shodan: Dict = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = 'LOW'
    scan_sources: List[str] = field(default_factory=list)

# ============================================================================
# NMAP RUNNER
# ============================================================================

class NmapRunner:

    @staticmethod
    def available() -> bool:
        return CAPS['nmap']

    @staticmethod
    def host_discovery(target_list: List[str], timeout: int = 60,
                       extra_flags: Optional[List[str]] = None,
                       proxy_prefix: Optional[List[str]] = None) -> Set[str]:
        """Fast nmap ping sweep"""
        if not CAPS['nmap']:
            return set()
        try:
            base = (proxy_prefix or []) + ['nmap', '-sn', '-T4', '--open', '-oX', '-']
            if CAPS['root']:
                base += ['-PE']
            cmd = base + (extra_flags or []) + target_list[:256]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return NmapRunner._parse_alive_xml(proc.stdout)
        except Exception:
            return set()

    @staticmethod
    def port_scan(target: str, ports: str = 'top-1000', timeout: int = 120,
                  extra_flags: Optional[List[str]] = None,
                  proxy_prefix: Optional[List[str]] = None,
                  xml_out: str = '') -> Dict:
        """nmap port scan with service detection"""
        if not CAPS['nmap']:
            return {}
        port_arg = NmapRunner._port_preset(ports)
        cmd = (proxy_prefix or []) + ['nmap', '-sV', '--version-intensity', '5', '-T4', '--open']
        if port_arg.startswith('--'):
            parts = port_arg.split()
            cmd += [parts[0], parts[1]] if len(parts) > 1 else [parts[0]]
        else:
            cmd += ['-p', port_arg]
        if CAPS['root']:
            cmd += ['-sS', '-O']
        else:
            cmd += ['-sT']
        cmd += (extra_flags or [])
        if xml_out:
            cmd += ['-oA', xml_out, '-oX', xml_out + '.xml']
        else:
            cmd += ['-oX', '-']
        cmd.append(target)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            xml_data = Path(xml_out + '.xml').read_text() if xml_out else proc.stdout
            return NmapRunner._parse_xml(xml_data)
        except Exception:
            return {}

    @staticmethod
    def targeted_scan(target: str, ports: List[int],
                      run_scripts: bool = False, timeout: int = 180,
                      extra_flags: Optional[List[str]] = None,
                      proxy_prefix: Optional[List[str]] = None,
                      nse_profile: str = '',
                      xml_out: str = '') -> Dict:
        """Focused nmap scan on specific ports"""
        if not CAPS['nmap'] or not ports:
            return {}
        port_str = ','.join(str(p) for p in sorted(set(ports)))
        cmd = (proxy_prefix or []) + ['nmap', '-sV', '--version-intensity', '7', '-T4',
               '-p', port_str]
        if CAPS['root']:
            cmd += ['-sS']
        else:
            cmd += ['-sT']
        if run_scripts:
            scripts = nse_profile or 'default,vuln'
            cmd += ['--script', scripts]
        cmd += (extra_flags or [])
        if xml_out:
            cmd += ['-oA', xml_out, '-oX', xml_out + '.xml']
        else:
            cmd += ['-oX', '-']
        cmd.append(target)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            xml_data = Path(xml_out + '.xml').read_text() if xml_out else proc.stdout
            return NmapRunner._parse_xml(xml_data)
        except Exception:
            return {}

    @staticmethod
    def _port_preset(ports: str) -> str:
        presets = {
            'quick':    '21,22,23,25,53,80,443,445,3389,62078',
            'top-20':   '21,22,23,25,53,80,110,443,445,1723,3306,3389,5900,8080,62078',
            'top-100':  '--top-ports 100',
            'top-1000': '--top-ports 1000',
            'web':      '80,443,8000,8001,8008,8080,8081,8088,8090,8091,8443,8888,9000,9090,9200,3000,4000,5000',
            'database': '1433,1434,1521,3306,5432,6379,9042,9200,11211,27017,28015,50070',
            'common':   '21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,3306,3389,5432,6379,8080,27017,62078',
            'ios':      '62078,5000,7000,548,3689,49152,88,5353',
            'iot':      '80,443,1883,8883,5683,5353,8080,8443,5000',
            'camera':   '80,443,554,8000,8080,8443,37777,34567,3702',
            'router':   '80,443,8080,8443,22,23,7547,8291',
            'nas':      '80,443,5000,5001,9000,445,139,22',
            'ics':      '80,443,502,20000,102,47808,1911,161,22',
            'device':   '80,443,554,1883,8883,5683,5353,8000,8080,8443,37777,34567,3702,7547,8291,5000,5001,9000,502,20000,102,47808,1911',
            'all':      '1-65535',
        }
        return presets.get(ports, ports)

    @staticmethod
    def _parse_alive_xml(xml_data: str) -> Set[str]:
        hosts: Set[str] = set()
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    addr = host.find('.//address[@addrtype="ipv4"]')
                    if addr is not None:
                        hosts.add(addr.get('addr', ''))
        except Exception:
            pass
        return hosts

    @staticmethod
    def _parse_xml(xml_data: str) -> Dict:
        """Parse nmap XML into structured result dict keyed by IP"""
        result: Dict = {}
        if not xml_data.strip():
            return result
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError:
            return result

        for host_elem in root.findall('.//host'):
            status = host_elem.find('status')
            if status is None or status.get('state') != 'up':
                continue

            addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
            ip = addr_elem.get('addr', '')

            host_data: Dict = {
                'ip': ip, 'mac': '', 'mac_vendor': '',
                'hostname': '', 'os': {}, 'services': [],
            }

            mac_elem = host_elem.find('.//address[@addrtype="mac"]')
            if mac_elem is not None:
                host_data['mac'] = mac_elem.get('addr', '')
                host_data['mac_vendor'] = (mac_elem.get('vendor', '')
                                           or lookup_mac_vendor(host_data['mac']))

            hn = (host_elem.find('.//hostname[@type="user"]')
                  or host_elem.find('.//hostname'))
            if hn is not None:
                host_data['hostname'] = hn.get('name', '')

            os_match = host_elem.find('.//osmatch')
            if os_match is not None:
                osclass = os_match.find('osclass')
                host_data['os'] = {
                    'name':     os_match.get('name', ''),
                    'accuracy': int(os_match.get('accuracy', 0)),
                    'family':   osclass.get('osfamily', '') if osclass is not None else '',
                    'version':  osclass.get('osgen', '') if osclass is not None else '',
                }

            for port_elem in host_elem.findall('.//port'):
                state_elem = port_elem.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue
                svc_elem = port_elem.find('service')
                svc: Dict = {
                    'port':     int(port_elem.get('portid', 0)),
                    'protocol': port_elem.get('protocol', 'tcp'),
                    'state':    'open',
                    'service':  svc_elem.get('name', '') if svc_elem is not None else '',
                    'product':  svc_elem.get('product', '') if svc_elem is not None else '',
                    'version':  svc_elem.get('version', '') if svc_elem is not None else '',
                    'banner':   svc_elem.get('extrainfo', '') if svc_elem is not None else '',
                    'scripts':  {},
                }
                for script in port_elem.findall('script'):
                    svc['scripts'][script.get('id', '')] = script.get('output', '')[:512]
                svc['cves'] = correlate_cves(svc['service'], svc['product'], svc['version'])
                host_data['services'].append(svc)

            result[ip] = host_data
        return result


# ============================================================================
# MASSCAN RUNNER
# ============================================================================

class MasscanRunner:

    @staticmethod
    def available() -> bool:
        return CAPS['masscan'] and CAPS['root']

    @staticmethod
    def scan(targets: str, ports: str = 'top-1000',
             rate: int = 1000, timeout: int = 120) -> Dict[str, Set[int]]:
        """Masscan discovery, returns {ip: set_of_ports}"""
        if not MasscanRunner.available():
            return {}
        port_arg = MasscanRunner._port_arg(ports)
        try:
            cmd = ['masscan', targets, '-p', port_arg,
                   '--rate', str(rate), '--open', '-oJ', '-', '--wait', '2']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return MasscanRunner._parse_json(proc.stdout)
        except Exception:
            return {}

    @staticmethod
    def _port_arg(ports: str) -> str:
        presets = {
            'quick':    '21,22,23,25,53,80,443,445,3389,62078',
            'top-20':   '21,22,23,25,53,80,110,443,445,1723,3306,3389,62078',
            'top-100':  '1-1024,3306,3389,5432,5900,6379,8080,8443,27017,62078',
            'top-1000': '1-1024,1080,1433,1521,3306,3389,5432,5900,6379,8000-8100,8443,9200,27017,62078',
            'web':      '80,443,8000,8080,8443,8888,9000,9090,3000,5000',
            'database': '1433,1521,3306,5432,6379,9200,11211,27017',
            'common':   '21,22,23,25,53,80,110,135,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,6379,8080,27017,62078',
            'ios':      '62078,5000,7000,548,3689,49152,88,5353',
            'iot':      '80,443,1883,8883,5683,5353,8080,8443,5000',
            'camera':   '80,443,554,8000,8080,8443,37777,34567,3702',
            'router':   '80,443,8080,8443,22,23,7547,8291',
            'nas':      '80,443,5000,5001,9000,445,139,22',
            'ics':      '80,443,502,20000,102,47808,1911,161,22',
            'device':   '80,443,554,1883,8883,5683,5353,8000,8080,8443,37777,34567,3702,7547,8291,5000,5001,9000,502,20000,102,47808,1911',
            'all':      '0-65535',
        }
        return presets.get(ports, ports)

    @staticmethod
    def _parse_json(data: str) -> Dict[str, Set[int]]:
        result: Dict[str, Set[int]] = {}
        for line in data.strip().split('\n'):
            line = line.strip().rstrip(',')
            if not line or line in ('[', ']', '{', '}'):
                continue
            try:
                entry = json.loads(line)
                ip = entry.get('ip', '')
                ports_info = entry.get('ports', [{}])
                port = int(ports_info[0].get('port', 0)) if ports_info else 0
                if ip and port:
                    result.setdefault(ip, set()).add(port)
            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                continue
        return result


# ============================================================================
# RUSTSCAN RUNNER
# ============================================================================

class RustscanRunner:

    @staticmethod
    def available() -> bool:
        return CAPS['rustscan']

    @staticmethod
    def scan(target: str, batch_size: int = 4096, timeout: int = 120) -> Set[int]:
        """Rustscan fast port discovery, returns set of open ports"""
        if not CAPS['rustscan']:
            return set()
        try:
            cmd = ['rustscan', '-a', target, '-b', str(batch_size),
                   '--timeout', '1500', '--tries', '1',
                   '--', '-sV', '-oX', '-']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            nmap_data = NmapRunner._parse_xml(proc.stdout)
            found: Set[int] = set()
            for hd in nmap_data.values():
                for svc in hd.get('services', []):
                    found.add(svc['port'])
            return found
        except Exception:
            return set()


# ============================================================================
# ARP SCANNER
# ============================================================================

class ArpScanner:

    @staticmethod
    def scan(subnet: str, interface: Optional[str] = None,
             timeout: int = 30) -> Dict[str, str]:
        """ARP host discovery, returns {ip: mac}"""
        result: Dict[str, str] = {}

        if CAPS['arp_scan'] and CAPS['root']:
            result = ArpScanner._binary_scan(interface, timeout)

        if not result and CAPS['scapy'] and CAPS['root']:
            result = ArpScanner._scapy_scan(subnet, timeout)

        return result

    @staticmethod
    def _binary_scan(interface: Optional[str], timeout: int) -> Dict[str, str]:
        try:
            cmd = ['arp-scan', '--localnet', '--ignoredups']
            if interface:
                cmd += ['-I', interface]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            result: Dict[str, str] = {}
            for line in proc.stdout.split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0].strip()):
                    result[parts[0].strip()] = parts[1].strip()
            return result
        except Exception:
            return {}

    @staticmethod
    def _scapy_scan(subnet: str, timeout: int) -> Dict[str, str]:
        try:
            pkt = _scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / _scapy.ARP(pdst=subnet)
            answered, _ = _scapy.srp(pkt, timeout=min(timeout, 5), verbose=False)
            return {recv.psrc: recv.hwsrc for _, recv in answered}
        except Exception:
            return {}


# ============================================================================
# BANNER GRABBER
# ============================================================================

_BANNER_PROBES: Dict[int, bytes] = {
    21:    b'',
    22:    b'',
    25:    b'EHLO secv-scan\r\n',
    80:    b'GET / HTTP/1.0\r\nHost: secv\r\n\r\n',
    110:   b'',
    143:   b'',
    554:   b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: secv-netrecon\r\n\r\n',
    1883:  b'\x10\x16\x00\x04MQTT\x04\x02\x00\x3c\x00\x0asecv-probe',
    6379:  b'PING\r\n',
    11211: b'stats\r\n',
}

def banner_grab(ip: str, port: int, timeout: float = 3.0) -> Tuple[str, float]:
    t0 = time.time()
    banner = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        probe = _BANNER_PROBES.get(port, b'\r\n')
        if probe:
            sock.send(probe)
        raw = sock.recv(1024)
        banner = raw.decode('utf-8', errors='replace').strip()[:256]
        sock.close()
    except Exception:
        pass
    return banner, (time.time() - t0) * 1000


# ============================================================================
# HTTP PROBER
# ============================================================================

_HTTP_TECH: Dict[str, List[str]] = {
    'WordPress':    [r'wp-content', r'wp-includes', r'WordPress'],
    'Joomla':       [r'Joomla', r'/components/com_'],
    'Drupal':       [r'Drupal', r'/sites/default/'],
    'Django':       [r'csrfmiddlewaretoken', r'Django'],
    'Flask':        [r'Werkzeug', r'Flask'],
    'Laravel':      [r'laravel_session', r'Laravel'],
    'Spring':       [r'X-Application-Context', r'Spring'],
    'Express':      [r'X-Powered-By: Express'],
    'React':        [r'__REACT_DEVTOOLS', r'_react'],
    'Angular':      [r'ng-version', r'angular\.js'],
    'Vue.js':       [r'Vue\.js', r'__vue__'],
    'jQuery':       [r'jquery\.min\.js', r'jQuery'],
    'Bootstrap':    [r'bootstrap\.min\.css', r'bootstrap\.min\.js'],
    'PHP':          [r'X-Powered-By: PHP', r'\.php\b'],
    'ASP.NET':      [r'X-Powered-By: ASP\.NET', r'__VIEWSTATE'],
    'Apache':       [r'Apache', r'httpd'],
    'Nginx':        [r'nginx'],
    'IIS':          [r'Microsoft-IIS'],
    'Tomcat':       [r'Apache Tomcat', r'Coyote'],
    'Cloudflare':   [r'CF-RAY', r'cf-cache-status'],
    'Grafana':      [r'Grafana', r'grafana'],
    'Jenkins':      [r'Jenkins', r'hudson'],
    'Kubernetes':   [r'Kubernetes', r'k8s'],
    'Elasticsearch':[r'Elasticsearch', r'"cluster_name"'],
}

_SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
]


def http_probe(ip: str, port: int, timeout: float = 5.0) -> Dict:
    if not CAPS['requests']:
        return {}
    scheme = 'https' if port in (443, 8443, 9443) else 'http'
    url = f'{scheme}://{ip}:{port}/'
    result: Dict = {
        'status': 0, 'title': '', 'server': '', 'technologies': [],
        'tls_subject': '', 'tls_issuer': '', 'tls_expiry': '',
        'tls_sans': [], 'tls_sig_algo': '', 'tls_not_before': '',
        'security_headers': {}, 'missing_security_headers': [],
        'cookies': [], 'redirect_chain': [],
    }
    try:
        import requests as _req
        resp = _req.get(url, timeout=timeout, verify=False, allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0 (SecV netrecon/2.0)'})
        result['status'] = resp.status_code
        result['server'] = resp.headers.get('Server', '')

        # Redirect chain
        if resp.history:
            result['redirect_chain'] = [r.url for r in resp.history] + [resp.url]

        title_m = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.IGNORECASE)
        if title_m:
            result['title'] = title_m.group(1).strip()[:120]

        haystack = resp.text[:50000] + str(dict(resp.headers))
        for tech, patterns in _HTTP_TECH.items():
            for pat in patterns:
                if re.search(pat, haystack, re.IGNORECASE):
                    result['technologies'].append(tech)
                    break

        # Security headers audit
        for hdr in _SECURITY_HEADERS:
            val = resp.headers.get(hdr, '')
            if val:
                result['security_headers'][hdr] = val
            else:
                result['missing_security_headers'].append(hdr)

        # Cookie security analysis
        for cookie in resp.cookies:
            result['cookies'].append({
                'name':     cookie.name,
                'secure':   cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie._rest).lower(),
                'samesite': cookie._rest.get('SameSite', '') if hasattr(cookie, '_rest') else '',
                'domain':   cookie.domain or '',
            })

        if scheme == 'https':
            try:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                with ctx.wrap_socket(socket.socket(), server_hostname=ip) as s:
                    s.settimeout(3)
                    s.connect((ip, port))
                    cert = s.getpeercert()
                    if cert:
                        subj   = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        result['tls_subject']    = subj.get('commonName', '')
                        result['tls_issuer']     = issuer.get('organizationName', '')
                        result['tls_expiry']     = cert.get('notAfter', '')
                        result['tls_not_before'] = cert.get('notBefore', '')
                        result['tls_sig_algo']   = cert.get('signatureAlgorithm', '')
                        # Subject Alternative Names
                        sans = []
                        for rtype, val in cert.get('subjectAltName', []):
                            if rtype == 'DNS':
                                sans.append(val)
                        result['tls_sans'] = sans[:20]
            except Exception:
                pass
    except Exception:
        pass
    return result


# ============================================================================
# NETBIOS / SMB ENUMERATION
# ============================================================================

def netbios_lookup(ip: str, timeout: int = 8) -> Dict:
    """Query NetBIOS name table via nmblookup; fallback banner grab port 139"""
    result: Dict = {'name': '', 'workgroup': '', 'mac': '', 'shares': [], 'users': []}
    if CAPS.get('nmblookup'):
        try:
            proc = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=timeout,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                m = re.match(r'^\s*(\S+)\s+<([0-9a-fA-F]{2})>\s+-\s+[BMH]\s+', line)
                if m:
                    name, ntype = m.group(1), m.group(2)
                    if ntype == '00' and not result['name']:
                        result['name'] = name.strip()
                    elif ntype == '1e':
                        result['workgroup'] = name.strip()
                mac_m = re.search(r'MAC Address = ([0-9A-F:]{17})', line, re.IGNORECASE)
                if mac_m:
                    result['mac'] = mac_m.group(1)
        except Exception:
            pass

    if CAPS.get('smbclient') and result['name']:
        try:
            proc = subprocess.run(
                ['smbclient', '-L', ip, '-N', '--no-pass'],
                capture_output=True, text=True, timeout=timeout,
            )
            for line in proc.stdout.splitlines():
                if re.match(r'^\s+\S+\s+(Disk|IPC)', line, re.IGNORECASE):
                    share = line.split()[0].strip()
                    if share and share not in result['shares']:
                        result['shares'].append(share)
        except Exception:
            pass

    return result


def snmp_probe(ip: str, communities: Optional[List[str]] = None,
               timeout: int = 5) -> Dict:
    """Test SNMP community strings via snmpwalk; returns sysDescr if accessible"""
    result: Dict = {'community': '', 'sysdescr': '', 'sysname': ''}
    if not CAPS.get('snmpwalk'):
        return result
    for community in (communities or ['public', 'private', 'manager', 'community']):
        try:
            proc = subprocess.run(
                ['snmpwalk', '-v2c', '-c', community, '-t', '2', ip,
                 'SNMPv2-MIB::sysDescr.0'],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and 'STRING:' in proc.stdout:
                result['community'] = community
                m = re.search(r'STRING:\s*(.+)', proc.stdout)
                if m:
                    result['sysdescr'] = m.group(1).strip()[:200]
                break
        except Exception:
            pass
    return result


# ============================================================================
# PASSIVE RECON
# ============================================================================

class PassiveRecon:

    @staticmethod
    def dns_lookup(target: str) -> Dict:
        result: Dict = {'forward': {}, 'mx': [], 'ns': [], 'txt': []}
        if CAPS['dns']:
            try:
                import dns.resolver as _r
                import dns.reversename as _rn
                res = _r.Resolver()
                res.timeout = 3
                res.lifetime = 5
                for rtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'):
                    try:
                        ans = res.resolve(target, rtype)
                        if rtype == 'MX':
                            result['mx'] = [str(r.exchange).rstrip('.') for r in ans]
                        elif rtype == 'NS':
                            result['ns'] = [str(r).rstrip('.') for r in ans]
                        elif rtype == 'TXT':
                            result['txt'] = [str(r) for r in ans]
                        else:
                            result['forward'][rtype] = [str(r) for r in ans]
                    except Exception:
                        pass
            except Exception:
                pass
        else:
            try:
                ips = socket.getaddrinfo(target, None)
                result['forward']['A'] = list({addr[4][0] for addr in ips})
            except Exception:
                pass
        return result

    @staticmethod
    def reverse_dns(ip: str) -> str:
        try:
            if CAPS['dns']:
                import dns.resolver as _r
                import dns.reversename as _rn
                rev = _rn.from_address(ip)
                ans = _r.resolve(rev, 'PTR')
                return str(ans[0]).rstrip('.')
        except Exception:
            pass
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ''

    @staticmethod
    def asn_lookup(ip: str) -> Dict:
        result: Dict = {'asn': '', 'org': '', 'country': '', 'city': ''}
        try:
            if ipaddress.ip_address(ip).is_private:
                result['org'] = 'Private Network'
                return result
        except Exception:
            pass
        if not CAPS['requests']:
            return result
        try:
            import requests as _req
            resp = _req.get(f'https://ipinfo.io/{ip}/json',
                           timeout=5, headers={'User-Agent': 'SecV/1.0'})
            if resp.status_code == 200:
                data = resp.json()
                raw_org = data.get('org', '')
                parts = raw_org.split(' ', 1) if raw_org else ['', '']
                result['asn'] = parts[0]
                result['org'] = parts[1] if len(parts) > 1 else ''
                result['country'] = data.get('country', '')
                result['city'] = data.get('city', '')
        except Exception:
            pass
        return result

    @staticmethod
    def whois_lookup(ip: str) -> str:
        if not CAPS['whois']:
            return ''
        try:
            if ipaddress.ip_address(ip).is_private:
                return 'Private Network'
        except Exception:
            pass
        try:
            proc = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
            for line in proc.stdout.split('\n'):
                if re.match(r'(OrgName|org-name|netname|descr):', line, re.IGNORECASE):
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return ''


# ============================================================================
# SHODAN CLIENT
# ============================================================================

class ShodanClient:

    def __init__(self, api_key: str):
        self.key = api_key
        self._client = None
        if api_key and CAPS.get('shodan_lib'):
            try:
                self._client = _shodan_mod.Shodan(api_key)
            except Exception:
                pass

    def lookup(self, ip: str) -> Dict:
        if not self.key:
            return {}
        try:
            if ipaddress.ip_address(ip).is_private:
                return {}
        except Exception:
            pass

        if self._client:
            try:
                host = self._client.host(ip)
                return {
                    'ports':       host.get('ports', []),
                    'vulns':       list(host.get('vulns', {}).keys()),
                    'os':          host.get('os', ''),
                    'org':         host.get('org', ''),
                    'hostnames':   host.get('hostnames', []),
                    'tags':        host.get('tags', []),
                    'last_update': host.get('last_update', ''),
                }
            except Exception:
                pass

        if CAPS['requests']:
            try:
                import requests as _req
                resp = _req.get(f'https://api.shodan.io/shodan/host/{ip}',
                               params={'key': self.key}, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        'ports':       data.get('ports', []),
                        'vulns':       list(data.get('vulns', {}).keys()),
                        'os':          data.get('os', ''),
                        'org':         data.get('org', ''),
                        'hostnames':   data.get('hostnames', []),
                        'tags':        data.get('tags', []),
                        'last_update': data.get('last_update', ''),
                    }
            except Exception:
                pass
        return {}


# ============================================================================
# WHATWEB RUNNER
# ============================================================================

class WhatwebRunner:

    @staticmethod
    def available() -> bool:
        return CAPS.get('whatweb', False)

    @staticmethod
    def scan(url: str, timeout: int = 30,
             evasion: bool = False,
             proxy_prefix: Optional[List[str]] = None) -> Dict:
        """Run whatweb against a URL, return parsed tech/plugin data"""
        if not WhatwebRunner.available():
            return {}
        try:
            cmd = (proxy_prefix or []) + [
                'whatweb', '--log-json=-', '--no-errors', '-q', url
            ]
            if evasion:
                cmd += ['--user-agent', _pick_ua(), '--throttle', '500']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            results: Dict = {'url': url, 'technologies': [], 'plugins': {}}
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if isinstance(entry, list):
                        entry = entry[0] if entry else {}
                    plugins = entry.get('plugins', {})
                    for name, data in plugins.items():
                        if name in ('Status', 'RedirectLocation', 'IP', 'RequestConfig'):
                            continue
                        results['technologies'].append(name)
                        detail = {}
                        if 'string' in data:
                            detail['version'] = data['string'][0] if data['string'] else ''
                        results['plugins'][name] = detail
                except (json.JSONDecodeError, KeyError, IndexError):
                    pass
            results['technologies'] = list(dict.fromkeys(results['technologies']))
            return results
        except Exception:
            return {}


# ============================================================================
# GOBUSTER / FFUF RUNNER
# ============================================================================

_DEFAULT_WORDLISTS = [
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
]

def _find_wordlist(custom: str = '') -> str:
    if custom and Path(custom).is_file():
        return custom
    for wl in _DEFAULT_WORDLISTS:
        if Path(wl).is_file():
            return wl
    return ''


class GobusterRunner:

    @staticmethod
    def available() -> bool:
        return CAPS.get('gobuster', False)

    @staticmethod
    def scan(url: str, wordlist: str = '', threads: int = 50,
             timeout: int = 120, evasion: bool = False,
             proxy_prefix: Optional[List[str]] = None,
             output_file: str = '') -> List[str]:
        """Directory brute-force, returns list of found paths"""
        wl = _find_wordlist(wordlist)
        if not GobusterRunner.available() or not wl:
            return []
        if evasion:
            threads = min(threads, 5)   # slow down to avoid detection
        try:
            cmd = (proxy_prefix or []) + [
                'gobuster', 'dir',
                '-u', url,
                '-w', wl,
                '-t', str(threads),
                '-k', '-q',
                '--no-error',
            ]
            if evasion:
                cmd += ['--useragent', _pick_ua(), '--delay', '500ms']
            if output_file:
                cmd += ['-o', output_file]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            found = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and line.startswith('/'):
                    found.append(line.split()[0])
            return found
        except Exception:
            return []


class FfufRunner:

    @staticmethod
    def available() -> bool:
        return CAPS.get('ffuf', False)

    @staticmethod
    def scan(url: str, wordlist: str = '', threads: int = 50,
             timeout: int = 120, evasion: bool = False,
             proxy_prefix: Optional[List[str]] = None,
             output_file: str = '') -> List[str]:
        """ffuf directory brute-force, returns list of found paths"""
        wl = _find_wordlist(wordlist)
        if not FfufRunner.available() or not wl:
            return []
        if evasion:
            threads = min(threads, 5)
        fuzz_url = url.rstrip('/') + '/FUZZ'
        try:
            cmd = (proxy_prefix or []) + [
                'ffuf',
                '-u', fuzz_url,
                '-w', wl,
                '-t', str(threads),
                '-mc', 'all',
                '-fc', '404',
                '-s',
            ]
            if evasion:
                cmd += ['-H', f'User-Agent: {_pick_ua()}', '-p', '0.5']
            if output_file:
                cmd += ['-o', output_file, '-of', 'json']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            found = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith('['):
                    # plain output: path [Status: 200, ...]
                    m = re.match(r'^(/\S*)', line)
                    if m:
                        found.append(m.group(1))
            return found
        except Exception:
            return []


# ============================================================================
# NIKTO RUNNER
# ============================================================================

# Evasion technique numbers for nikto -evasion flag
_NIKTO_EVASION_TECHNIQUES = '1,2,5,7'   # encoding + path tricks; avoids 6/8 (break responses)

# Shared list of generic browser UAs — used by all web tools in evasion mode
_EVASION_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36',
]

def _pick_ua() -> str:
    import random
    return random.choice(_EVASION_USER_AGENTS)


class NiktoRunner:

    @staticmethod
    def available() -> bool:
        return CAPS.get('nikto', False)

    @staticmethod
    def scan(url: str, timeout: int = 120,
             evasion: bool = False,
             proxy_prefix: Optional[List[str]] = None,
             output_file: str = '') -> Dict:
        """
        Run nikto web vulnerability scanner against url.
        Returns dict with 'findings' (list of dicts) and 'raw' output.
        """
        if not NiktoRunner.available():
            return {}
        try:
            cmd = (proxy_prefix or []) + [
                'nikto', '-host', url, '-nointeractive', '-Format', 'csv',
                '-output', '-',
            ]
            if evasion:
                cmd += [
                    '-evasion', _NIKTO_EVASION_TECHNIQUES,
                    '-useragent', _pick_ua(),
                ]
                # Add proxy if proxychains not wrapping (nikto -useproxy)
                # Rate limit via nikto's own -Pause flag
                cmd += ['-Pause', '1']
            if output_file:
                cmd += ['-output', output_file, '-Format', 'csv']

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            findings: List[Dict] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # CSV: hostname,ip,port,nikto_id,osvdb,method,uri,message
                parts = line.split(',', 7)
                if len(parts) >= 8:
                    findings.append({
                        'host':    parts[0],
                        'ip':      parts[1],
                        'port':    parts[2],
                        'id':      parts[3],
                        'osvdb':   parts[4],
                        'method':  parts[5],
                        'uri':     parts[6],
                        'message': parts[7],
                    })
                elif len(parts) >= 4 and 'OSVDB' in line:
                    findings.append({'message': line})
            return {'findings': findings, 'raw': proc.stdout[:4096]}
        except subprocess.TimeoutExpired:
            return {'findings': [], 'raw': 'timeout'}
        except Exception:
            return {}


# ============================================================================
# SEARCHSPLOIT RUNNER
# ============================================================================

class SearchsploitRunner:

    @staticmethod
    def available() -> bool:
        return CAPS.get('searchsploit', False)

    @staticmethod
    def search_nmap_xml(xml_path: str) -> List[Dict]:
        """Run searchsploit --nmap against XML scan file"""
        if not SearchsploitRunner.available() or not Path(xml_path).is_file():
            return []
        try:
            proc = subprocess.run(
                ['searchsploit', '--nmap', xml_path, '--colour=false'],
                capture_output=True, text=True, timeout=60,
            )
            return SearchsploitRunner._parse_output(proc.stdout)
        except Exception:
            return []

    @staticmethod
    def search_service(service: str, version: str = '') -> List[Dict]:
        """Search exploitdb by service name + optional version"""
        if not SearchsploitRunner.available() or not service:
            return []
        query = f'{service} {version}'.strip()
        try:
            proc = subprocess.run(
                ['searchsploit', '--colour=false', query],
                capture_output=True, text=True, timeout=30,
            )
            return SearchsploitRunner._parse_output(proc.stdout)
        except Exception:
            return []

    @staticmethod
    def _parse_output(raw: str) -> List[Dict]:
        results: List[Dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith('-') or line.startswith('Exploit') or line.startswith('Shellcode'):
                continue
            # lines look like: Title                                                 | path/to/exploit.py
            if '|' not in line:
                continue
            parts = line.split('|', 1)
            if len(parts) == 2:
                title = parts[0].strip()
                path  = parts[1].strip()
                if title and path and 'No Results' not in title:
                    results.append({'title': title, 'path': path})
        return results


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

_TIMEOUT_TABLE = {
    'quick':   {'discovery': 45, 'masscan': 30, 'rustscan': 30,
                'nmap_svc': 60, 'profile': 90, 'per_tool': 20},
    'normal':  {'discovery': 90, 'masscan': 60, 'rustscan': 60,
                'nmap_svc': 120, 'profile': 180, 'per_tool': 30},
    'deep':    {'discovery': 150, 'masscan': 120, 'rustscan': 120,
                'nmap_svc': 300, 'profile': 360, 'per_tool': 60},
    'stealth': {'discovery': 360, 'masscan': 300, 'rustscan': 120,
                'nmap_svc': 300, 'profile': 600, 'per_tool': 60},
    'evasion': {'discovery': 480, 'masscan': 300, 'rustscan': 120,
                'nmap_svc': 480, 'profile': 720, 'per_tool': 90},
}

_HIGH_RISK_PORTS = {23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017,
                    1883, 554, 37777, 34567, 8000}
_CRITICAL_PORTS  = {21, 502, 20000, 102, 47808, 1911}  # FTP + ICS/SCADA protocols
_WEB_PORTS       = {80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 3000, 5000}
_PORT_NAMES: Dict[int, str] = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 102: 's7comm', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
    139: 'netbios-ssn', 143: 'imap', 389: 'ldap', 443: 'https',
    445: 'microsoft-ds', 465: 'smtps', 502: 'modbus', 554: 'rtsp',
    587: 'submission', 636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
    1433: 'ms-sql-s', 1521: 'oracle', 1723: 'pptp', 1883: 'mqtt', 1911: 'niagara-fox',
    3306: 'mysql', 3389: 'ms-wbt-server', 3702: 'onvif-wsd',
    5000: 'synology-dsm', 5001: 'synology-dsm-ssl', 5432: 'postgresql',
    5683: 'coap', 5900: 'vnc', 5984: 'couchdb', 6379: 'redis',
    7547: 'tr-069', 8000: 'hikvision-http', 8080: 'http-proxy',
    8291: 'winbox', 8443: 'https-alt', 8883: 'mqtt-tls',
    9000: 'http', 9200: 'elasticsearch', 9900: 'nis', 11211: 'memcached',
    20000: 'dnp3', 27017: 'mongodb', 34567: 'dvr-http',
    37777: 'dahua-dvr', 47808: 'bacnet',
}

# ============================================================================
# IoT / DEVICE DETECTION CONSTANTS
# ============================================================================

_IOT_PORTS    = {1883, 8883, 5683, 5353}
_CAMERA_PORTS = {554, 8000, 37777, 34567, 3702}
_ROUTER_PORTS = {7547, 8291}
_NAS_PORTS    = {5000, 5001, 9000}
_ICS_PORTS    = {502, 20000, 102, 47808, 1911}
_DEVICE_PORTS = _IOT_PORTS | _CAMERA_PORTS | _ROUTER_PORTS | _NAS_PORTS | _ICS_PORTS

# Camera identification — favicon mmh3 hashes (from Shodan research + Vader)
CAMERA_FAVICON_HASHES: Dict[int, str] = {
    -256948040:  'Axis Camera',
    -808923751:  'Hikvision',
    -1132729927: 'D-Link Camera',
    1523019567:  'Panasonic Camera',
    -1320218906: 'Foscam',
    -874498984:  'Vivotek',
    1996458771:  'TP-Link Camera',
    -685785856:  'Logitech Circle',
    -823700596:  'NETGEAR Arlo',
    -1843219879: 'Samsung SmartCam',
    -1042281985: 'Sony Camera',
    -1702085052: 'Dahua',
    -1217267760: 'Amcrest',
    1699742818:  'Toshiba Camera',
    -1543082388: 'Sricam',
    1977756667:  'Reolink',
    -649861016:  'Zmodo',
}

# Camera HTTP server signatures
CAMERA_SERVER_SIGS: List[str] = [
    'boa', 'goahead', 'uc-httpd', 'thttpd', 'webs', 'app-webs',
    'hikvision-webs', 'dahua', 'mini_httpd', 'netwave', 'ip camera',
]

# Camera WWW-Authenticate realm patterns (lowercase)
CAMERA_AUTH_SIGS: List[str] = [
    'basic realm="ip camera"', 'basic realm="login"',
    'basic realm="webcam"', 'basic realm="network camera"',
    'basic realm="ipc"', 'basic realm="isapi"',
]

# Camera page title / HTML body keywords
CAMERA_HTML_SIGS: List[str] = [
    'ip camera', 'network camera', 'webcam', 'live view',
    'hikvision', 'dahua', 'foscam', 'onvif', 'surveillance',
    'ptz control', 'video stream', 'ipcamera',
]

# Flock Safety / LPR surveillance camera MAC prefixes (from flock-back)
FLOCK_MAC_PREFIXES: List[str] = [
    '58:8e:81', 'cc:cc:cc', 'ec:1b:bd', '90:35:ea', '04:0d:84',
    'f0:82:c0', '1c:34:f1', '38:5b:44', '94:34:69', 'b4:e3:f9',
    '70:c9:4e', '3c:91:80', 'd8:f3:bc', '80:30:49', '14:5a:fc',
    '74:4c:a1', '08:3a:88', '9c:2f:9d', '94:08:53', 'e4:aa:ea',
]

# ICS protocol → CVE key mapping
_ICS_PORT_SERVICE: Dict[int, str] = {
    502:   'modbus',
    20000: 'dnp3',
    102:   's7comm',
    47808: 'bacnet',
    1911:  'niagara-fox',
}


class NetRecon:
    """Concurrent multi-engine network reconnaissance"""

    def __init__(self, context: Dict):
        self.target  = context.get('target', '')
        self.params  = context.get('params', {})
        # Parse comma/plus/pipe-separated modes for concurrent feature chaining
        raw_mode = self.params.get('mode', 'normal').lower()
        self.modes: Set[str] = set(re.split(r'[,+|]', raw_mode))
        self.mode  = raw_mode  # kept for display and backward compat

        self.ports   = self.params.get('ports', 'top-1000')
        self.threads = int(self.params.get('threads', 20))
        self.rate    = int(self.params.get('rate', 1000))
        self.timeout = int(self.params.get('timeout', 5))
        self.os_det  = self._bool(self.params.get('os_detection', False))
        self.scripts = self._bool(self.params.get('vuln_scripts', False))
        self.passive = self._bool(self.params.get('passive_only', False))
        self.iface   = self.params.get('interface', '')
        self.exclude: Set[str] = set(
            x.strip() for x in self.params.get('exclude', '').split(',') if x.strip()
        )
        self.shodan_key  = self.params.get('shodan_key', '')
        self.nvd_api_key = self.params.get('nvd_api_key', os.environ.get('NVD_API_KEY', ''))

        # Evasion / anonymity params
        self.evasion       = self._bool(self.params.get('evasion', False))
        self.decoys        = int(self.params.get('decoys', 5))
        self.mtu           = int(self.params.get('mtu', 8))
        self.source_port   = int(self.params.get('source_port', 53))
        self.data_length   = int(self.params.get('data_length', 32))
        self.use_proxychains = self._bool(self.params.get('proxychains', False))
        self.nse_profile   = self.params.get('nse_profile', '')

        # Output / post-processing params
        self.web_enum      = self._bool(self.params.get('web_enum', True))
        self.web_wordlist  = self.params.get('web_wordlist', '')
        self.do_searchsploit = self._bool(self.params.get('searchsploit', False))
        self.output_dir    = self.params.get('output_dir', '')

        # Union all mode feature flags — each mode layer stacks onto the others
        # 'full' = all features: deep + stealth + evasion
        if 'quick' in self.modes:
            self.ports = self.params.get('ports', 'quick')
        if 'deep' in self.modes or 'full' in self.modes:
            self.scripts = True
            self.os_det  = True
            if 'ports' not in self.params:
                self.ports = 'top-1000'
        if 'stealth' in self.modes or 'full' in self.modes:
            self.rate    = min(self.rate, 200)
            self.timeout = max(self.timeout, 10)
        if 'evasion' in self.modes or 'full' in self.modes:
            self.evasion = True
            self.rate    = min(self.rate, 100)
            self.timeout = max(self.timeout, 15)
            if not self.nse_profile:
                self.nse_profile = 'banner,firewalk'
        if 'full' in self.modes:
            self.scripts = True
            self.os_det  = True
            self.web_enum = True

        self.shodan  = ShodanClient(self.shodan_key)
        self.errors: List[str] = []
        self._start  = datetime.now()

    # ------------------------------------------------------------------

    def _warn_sudo(self) -> None:
        """Print warnings to stderr when root is needed but not present."""
        if CAPS['root']:
            return
        needs_root = []
        if MasscanRunner.available():
            needs_root.append('masscan (SYN scan)')
        if CAPS['arp_scan']:
            needs_root.append('arp-scan (ARP host discovery)')
        if self.os_det:
            needs_root.append('nmap OS detection (-O flag)')
        if self.modes & {'syn', 'stealth', 'full'}:
            needs_root.append(f'mode={self.mode} (raw SYN packets)')
        if needs_root:
            print('[!] WARNING: not running as root — some features will be degraded or skipped:',
                  file=sys.stderr)
            for item in needs_root:
                print(f'    - {item}', file=sys.stderr)
            print('[!] Re-run with sudo for full capability.', file=sys.stderr)

    def execute(self) -> Dict:
        if not self.target:
            return {'success': False, 'errors': ['No target specified']}

        self._warn_sudo()
        t0 = time.time()
        engines: List[str] = []

        try:
            target_ips, target_str = self._parse_target(self.target)
            if not target_ips:
                return {'success': False, 'errors': ['Target could not be resolved']}

            # ── PHASE 1 ── Concurrent host discovery ──────────────────────
            print(f'[*] Phase 1: Concurrent discovery ({len(target_ips)} potential hosts)...',
                  file=sys.stderr)

            alive: Dict[str, Set[int]] = {}
            arp_map: Dict[str, str]    = {}

            with ThreadPoolExecutor(max_workers=10) as ex:
                fut_map: Dict = {}

                if MasscanRunner.available() and not self.passive:
                    fut_map[ex.submit(MasscanRunner.scan, target_str, self.ports,
                                      self.rate, self._t('masscan'))] = 'masscan'
                    engines.append('masscan')

                if RustscanRunner.available() and not self.passive and len(target_ips) <= 20:
                    for ip in list(target_ips)[:20]:
                        fut_map[ex.submit(RustscanRunner.scan, ip, 4096,
                                          self._t('rustscan'))] = f'rs:{ip}'
                    if 'rustscan' not in engines:
                        engines.append('rustscan')

                if self._is_local(target_str):
                    fut_map[ex.submit(ArpScanner.scan, target_str,
                                      self.iface or None, 30)] = 'arp'
                    engines.append('arp')

                if NmapRunner.available() and not self.passive:
                    fut_map[ex.submit(NmapRunner.host_discovery,
                                      list(target_ips)[:256], 60,
                                      self._evasion_flags(),
                                      self._proxy_prefix())] = 'nmap_disc'
                    if 'nmap' not in engines:
                        engines.append('nmap')

                for fut in as_completed(fut_map, timeout=self._t('discovery')):
                    tag = fut_map[fut]
                    try:
                        r = fut.result()
                        if tag == 'masscan' and isinstance(r, dict):
                            for ip, ports in r.items():
                                if ip not in self.exclude:
                                    alive.setdefault(ip, set()).update(ports)

                        elif tag.startswith('rs:'):
                            ip = tag[3:]
                            if isinstance(r, set) and r:
                                alive.setdefault(ip, set()).update(r)

                        elif tag == 'arp' and isinstance(r, dict):
                            for ip, mac in r.items():
                                if ip not in self.exclude:
                                    arp_map[ip] = mac
                                    alive.setdefault(ip, set())

                        elif tag == 'nmap_disc' and isinstance(r, set):
                            for ip in r:
                                if ip not in self.exclude:
                                    alive.setdefault(ip, set())
                    except Exception as e:
                        self.errors.append(f'{tag}: {e}')

            # Fallback: pure TCP if nothing found
            if not alive and not self.passive:
                print('[*] Falling back to TCP connect scan...', file=sys.stderr)
                alive = self._tcp_fallback(list(target_ips)[:64])
                engines.append('tcp_connect')

            if not alive:
                alive = {ip: set() for ip in target_ips if ip not in self.exclude}

            print(f'[*] Found {len(alive)} alive hosts', file=sys.stderr)

            # ── PHASE 2 ── Concurrent per-host deep profiling ─────────────
            print(f'[*] Phase 2: Concurrent deep profiling ({len(alive)} hosts)...',
                  file=sys.stderr)

            profiles: List[HostProfile] = []

            with ThreadPoolExecutor(max_workers=min(self.threads, max(1, len(alive)))) as ex:
                pf = {
                    ex.submit(self._profile_host, ip, ports, arp_map.get(ip, '')): ip
                    for ip, ports in alive.items()
                }
                for fut in as_completed(pf, timeout=self._t('profile')):
                    ip = pf[fut]
                    try:
                        p = fut.result()
                        if p:
                            profiles.append(p)
                    except Exception as e:
                        self.errors.append(f'profile {ip}: {e}')

            profiles.sort(key=lambda h: [int(x) for x in h.ip.split('.') if x.isdigit()])

            # ── PHASE 3 ── Web enumeration (gobuster/ffuf + whatweb) ──────
            if self.web_enum and not self.passive:
                print('[*] Phase 3: Web enumeration...', file=sys.stderr)
                self._run_web_enum(profiles)

            # ── PHASE 4 ── Exploit mapping ────────────────────────────────
            if self.do_searchsploit:
                print('[*] Phase 4: Searchsploit mapping...', file=sys.stderr)
                self._run_searchsploit(profiles)

            duration = time.time() - t0

            # ── PHASE 5 ── Output generation ──────────────────────────────
            output_artifacts: Dict = {}
            if self.output_dir:
                print('[*] Phase 5: Generating outputs...', file=sys.stderr)
                output_artifacts = self._generate_outputs(profiles, target_str)

            # NVD CVE enrichment: collect all CVE IDs across all hosts/services
            if _NVD_AVAILABLE:
                all_cve_ids: Set[str] = set()
                for h in profiles:
                    for svc in h.services:
                        for cve in svc.cves:
                            cid = cve.get('id', '')
                            if cid:
                                all_cve_ids.add(cid)
                if all_cve_ids:
                    print(f'[*] Enriching {len(all_cve_ids)} CVEs from NVD API...',
                          file=sys.stderr)
                    nvd_cache: Dict[str, Dict] = {}
                    for cve_id in list(all_cve_ids)[:20]:  # cap at 20 to respect rate limit
                        result = lookup_cve(cve_id, self.nvd_api_key)
                        if result:
                            nvd_cache[cve_id] = result
                    # Patch CVE entries in place
                    for h in profiles:
                        for svc in h.services:
                            for cve in svc.cves:
                                cid = cve.get('id', '')
                                if cid in nvd_cache:
                                    nd = nvd_cache[cid]
                                    cve['cvss']    = nd.get('cvss_v3', cve.get('cvss', 0))
                                    cve['desc']    = nd.get('description', cve.get('desc', ''))
                                    cve['severity']= nd.get('severity', '')
                                    cve['published']= nd.get('published', '')
                                    cve['nvd_live'] = True

            return {
                'success': True,
                'data': {
                    'target':           self.target,
                    'scan_start':       self._start.isoformat(),
                    'scan_duration':    round(duration, 2),
                    'hosts_discovered': len(profiles),
                    'engines_used':     engines,
                    'capabilities':     {k: v for k, v in CAPS.items()},
                    'hosts':            [asdict(h) for h in profiles],
                    'summary':          self._summary(profiles, duration, engines),
                    'outputs':          output_artifacts,
                },
                'errors': self.errors,
            }

        except Exception as e:
            return {'success': False, 'errors': [f'Scan failed: {e}']}

    # ------------------------------------------------------------------

    def _profile_host(self, ip: str, initial_ports: Set[int], mac: str = '') -> Optional[HostProfile]:
        """Profile a single host concurrently with all available tools"""
        profile = HostProfile(ip=ip, mac=mac, mac_vendor=lookup_mac_vendor(mac))
        if mac:
            profile.scan_sources.append('arp')

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs: Dict[str, Any] = {}

            if NmapRunner.available() and not self.passive:
                ef = self._evasion_flags()
                pp = self._proxy_prefix()
                nse = self.nse_profile if self.nse_profile else ''
                if initial_ports:
                    futs['nmap'] = ex.submit(NmapRunner.targeted_scan, ip,
                                             list(initial_ports), self.scripts,
                                             self._t('nmap_svc'), ef, pp, nse)
                else:
                    futs['nmap'] = ex.submit(NmapRunner.port_scan, ip,
                                             self.ports, self._t('nmap_svc'), ef, pp)

            futs['rdns']  = ex.submit(PassiveRecon.reverse_dns, ip)
            futs['dns']   = ex.submit(PassiveRecon.dns_lookup, ip)
            futs['asn']   = ex.submit(PassiveRecon.asn_lookup, ip)
            if CAPS['whois']:
                futs['whois'] = ex.submit(PassiveRecon.whois_lookup, ip)
            if self.shodan_key:
                futs['shodan'] = ex.submit(self.shodan.lookup, ip)

            for name, fut in futs.items():
                try:
                    self._merge(profile, name, fut.result(timeout=self._t('per_tool')))
                except Exception as e:
                    self.errors.append(f'{ip}/{name}: {e}')

        # Filter tcpwrapped — port is open but service identification failed; keep as unknown
        for svc in profile.services:
            if svc.service == 'tcpwrapped':
                svc.service = ''
                svc.banner  = 'tcpwrapped'

        # HTTP analysis on web ports — concurrent
        open_ports = {s.port for s in profile.services}
        web = open_ports & _WEB_PORTS
        if web and CAPS['requests'] and not self.passive:
            with ThreadPoolExecutor(max_workers=max(1, len(web))) as ex:
                hf = {ex.submit(http_probe, ip, p, 5.0): p for p in web}
                for fut in as_completed(hf, timeout=25):
                    self._merge_http(profile, hf[fut], fut.result() or {})

        # whatweb fingerprinting on web ports
        if web and WhatwebRunner.available() and not self.passive:
            pp = self._proxy_prefix()
            for port in list(web)[:4]:
                scheme = 'https' if port in (443, 8443, 9443) else 'http'
                url = f'{scheme}://{ip}:{port}/'
                ww = WhatwebRunner.scan(url, timeout=20, proxy_prefix=pp,
                                        evasion=self.evasion)
                if ww.get('technologies'):
                    svc = next((s for s in profile.services if s.port == port), None)
                    if svc:
                        for tech in ww['technologies']:
                            if tech not in svc.http_technologies:
                                svc.http_technologies.append(tech)
                        if 'whatweb' not in svc.sources:
                            svc.sources.append('whatweb')

        # Banner grab fallback if nmap gave nothing
        if not profile.services and initial_ports and not self.passive:
            if self.evasion:
                _BANNER_PROBES[554] = (
                    f'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {_pick_ua()}\r\n\r\n'
                ).encode()
            for port in sorted(initial_ports)[:20]:
                bnr, ms = banner_grab(ip, port, float(self.timeout))
                svc = ServiceInfo(port=port, state='open', banner=bnr, response_ms=ms,
                                  sources=['banner_grab'])
                svc.service = self._guess_service(port, bnr)
                svc.cves    = correlate_cves(svc.service, '', '')
                profile.services.append(svc)

        # Apple / iOS device fingerprinting
        open_ports = {s.port for s in profile.services}
        apple_hits = {p: APPLE_PORTS[p] for p in open_ports if p in APPLE_PORTS}
        if apple_hits or (profile.mac_vendor and 'Apple' in profile.mac_vendor):
            if 62078 in apple_hits:
                # lockdownd is exclusive to iPhone/iPad/iPod
                if not profile.os_family:
                    profile.os_family = 'iOS'
                if not profile.device_type:
                    profile.device_type = 'iPhone/iPad'
            elif not profile.device_type:
                profile.device_type = 'Apple device'
            # Annotate the lockdownd service if nmap missed it
            if 62078 in apple_hits and not any(s.port == 62078 for s in profile.services):
                profile.services.append(ServiceInfo(
                    port=62078, service='ios-lockdownd',
                    product='Apple iOS lockdown daemon', state='open',
                    sources=['apple_detect'],
                ))
        # NetBIOS / SMB enumeration for port 139/445
        open_ports = {s.port for s in profile.services}
        if open_ports & {139, 445} and not self.passive:
            nb = netbios_lookup(ip)
            if nb.get('name'):
                if not profile.hostname:
                    profile.hostname = nb['name']
                if not profile.mac and nb.get('mac'):
                    profile.mac = nb['mac']
                    profile.mac_vendor = lookup_mac_vendor(profile.mac)
                for svc in profile.services:
                    if svc.port in (139, 445):
                        if nb.get('shares'):
                            svc.__dict__['smb_shares'] = nb['shares']
                        if 'netbios' not in svc.sources:
                            svc.sources.append('netbios')

        # SNMP enumeration for port 161
        if 161 in open_ports and not self.passive:
            sr = snmp_probe(ip)
            if sr.get('community'):
                for svc in profile.services:
                    if svc.port == 161:
                        svc.__dict__['snmp_community'] = sr['community']
                        svc.__dict__['snmp_sysdescr']  = sr.get('sysdescr', '')
                        if not svc.banner:
                            svc.banner = sr.get('sysdescr', '')
                        if 'snmp' not in svc.sources:
                            svc.sources.append('snmp')
                profile.vulnerabilities.append({
                    'id': 'SNMP-DEFAULT-COMMUNITY',
                    'severity': 'HIGH',
                    'desc': f"SNMP community string '{sr['community']}' is guessable",
                })

        # mDNS/Bonjour probe — avahi-browse reveals hostname + service type
        if shutil.which('avahi-browse') and not self.passive:
            try:
                res = subprocess.run(
                    ['avahi-browse', '-r', '-t', '-p', '_services._dns-sd._udp'],
                    capture_output=True, text=True, timeout=8,
                )
                for line in res.stdout.splitlines():
                    if profile.ip in line or (profile.hostname and profile.hostname in line):
                        m = re.search(r'hostname=\[([^\]]+)\]', line)
                        if m and not profile.hostname:
                            profile.hostname = m.group(1).rstrip('.')
                        if 'iPhone' in line or 'iPad' in line:
                            if not profile.device_type:
                                profile.device_type = 'iPhone/iPad'
                            if not profile.os_family:
                                profile.os_family = 'iOS'
            except Exception:
                pass

        # IoT / Camera / Router / NAS / ICS / Surveillance device classification
        self._detect_device_category(profile)

        # Active IoT protocol probes on device-specific ports
        if not self.passive:
            open_ports = {s.port for s in profile.services}

            # MQTT — test if broker accepts unauthenticated connections
            if 1883 in open_ports:
                mqtt = self._probe_mqtt(ip)
                for svc in profile.services:
                    if svc.port == 1883:
                        if mqtt.get('connack'):
                            svc.banner = svc.banner or 'MQTT CONNACK received'
                        if mqtt.get('no_auth'):
                            svc.__dict__['mqtt_no_auth'] = True
                            profile.vulnerabilities.append({
                                'id': 'MQTT-NO-AUTH',
                                'severity': 'CRITICAL',
                                'desc': 'MQTT broker accepts unauthenticated connections — full broker access possible',
                            })

            # RTSP — check if stream is accessible without auth
            if 554 in open_ports:
                rtsp = self._probe_rtsp(ip, 554)
                for svc in profile.services:
                    if svc.port == 554:
                        if rtsp.get('banner') and not svc.banner:
                            svc.banner = rtsp['banner'][:120]
                        if rtsp.get('server') and not svc.http_server:
                            svc.http_server = rtsp['server']
                        if rtsp.get('no_auth'):
                            profile.vulnerabilities.append({
                                'id': 'RTSP-NO-AUTH',
                                'severity': 'HIGH',
                                'desc': 'RTSP camera stream is accessible without any authentication',
                            })

            # Camera favicon hash fingerprinting — identify model/vendor
            if profile.device_category == 'camera' or (open_ports & _CAMERA_PORTS):
                for port in sorted(open_ports & {80, 443, 8080, 8443, 8000})[:3]:
                    model = self._fingerprint_camera_favicon(ip, port)
                    if model:
                        if not profile.device_type:
                            profile.device_type = model
                        break

        profile.risk_score, profile.risk_level = self._risk(profile)
        return profile

    # ------------------------------------------------------------------

    def _merge(self, p: HostProfile, src: str, data: Any):
        if not data:
            return

        if src == 'nmap':
            hd = data.get(p.ip) or (next(iter(data.values())) if data else {})
            if not hd:
                return
            if not p.mac and hd.get('mac'):
                p.mac        = hd['mac']
                p.mac_vendor = hd.get('mac_vendor', '') or lookup_mac_vendor(p.mac)
            if not p.hostname:
                p.hostname = hd.get('hostname', '')
            os = hd.get('os', {})
            if os.get('name') and not p.os_family:
                p.os_family    = os.get('family', '') or os.get('name', '')
                p.os_version   = os.get('version', '')
                p.os_confidence = os.get('accuracy', 0)
            for sd in hd.get('services', []):
                existing = next((s for s in p.services if s.port == sd['port']), None)
                if existing:
                    if sd.get('service') and not existing.service:
                        existing.service = sd['service']
                    if sd.get('version') and not existing.version:
                        existing.version = sd['version']
                    if sd.get('cves') and not existing.cves:
                        existing.cves = sd['cves']
                    if 'nmap' not in existing.sources:
                        existing.sources.append('nmap')
                else:
                    svc = ServiceInfo(
                        port=sd['port'], protocol=sd.get('protocol', 'tcp'),
                        state='open', service=sd.get('service', ''),
                        product=sd.get('product', ''), version=sd.get('version', ''),
                        banner=sd.get('banner', ''), cves=sd.get('cves', []),
                        nmap_scripts=sd.get('scripts', {}), sources=['nmap'],
                    )
                    p.services.append(svc)
            if 'nmap' not in p.scan_sources:
                p.scan_sources.append('nmap')

        elif src == 'rdns':
            if data:
                p.reverse_dns = str(data)
                if not p.hostname:
                    p.hostname = p.reverse_dns

        elif src == 'dns':
            if isinstance(data, dict):
                p.dns_records = data.get('forward', {})

        elif src == 'asn':
            if isinstance(data, dict):
                p.asn     = data.get('asn', '')
                p.asn_org = data.get('org', '')
                p.country = data.get('country', '')
                p.city    = data.get('city', '')

        elif src == 'whois':
            p.whois_org = str(data) if data else ''

        elif src == 'shodan':
            if isinstance(data, dict):
                p.shodan = data
                our = {s.port for s in p.services}
                for sp in data.get('ports', []):
                    if sp not in our:
                        p.services.append(ServiceInfo(port=sp, sources=['shodan']))

    def _merge_http(self, p: HostProfile, port: int, data: Dict):
        if not data:
            return
        svc = next((s for s in p.services if s.port == port), None)
        if not svc:
            svc = ServiceInfo(port=port,
                              service='https' if port in (443, 8443) else 'http')
            p.services.append(svc)
        svc.http_status          = data.get('status', 0)
        svc.http_title           = data.get('title', '')
        svc.http_server          = data.get('server', '')
        svc.http_technologies    = data.get('technologies', [])
        svc.http_security_headers= data.get('security_headers', {})
        svc.http_missing_headers = data.get('missing_security_headers', [])
        svc.http_cookies         = data.get('cookies', [])
        svc.http_redirect_chain  = data.get('redirect_chain', [])
        svc.tls_subject          = data.get('tls_subject', '')
        svc.tls_issuer           = data.get('tls_issuer', '')
        svc.tls_expiry           = data.get('tls_expiry', '')
        svc.tls_not_before       = data.get('tls_not_before', '')
        svc.tls_sig_algo         = data.get('tls_sig_algo', '')
        svc.tls_sans             = data.get('tls_sans', [])
        if 'http' not in svc.sources:
            svc.sources.append('http')

    def _risk(self, p: HostProfile) -> Tuple[int, str]:
        score = 0
        for svc in p.services:
            if svc.port in _CRITICAL_PORTS:
                score += 20
            elif svc.port in _HIGH_RISK_PORTS:
                score += 10
            else:
                score += 2
            for cve in svc.cves:
                c = cve.get('cvss', 0)
                score += 25 if c >= 9.0 else 15 if c >= 7.0 else 5 if c >= 4.0 else 0
        if any(s.port == 23 for s in p.services):
            score += 30
        # Device category risk boosts
        if p.device_category == 'ics':
            score += 40  # ICS exposed on network is always critical
        elif p.device_category == 'camera':
            score += 15  # IP cameras are high-value targets
        elif p.device_category == 'router':
            score += 10
        # Vulnerability-level boosts
        crit_vulns = [v for v in p.vulnerabilities if v.get('severity') == 'CRITICAL']
        score += len(crit_vulns) * 15
        score = min(score, 100)
        level = ('CRITICAL' if score >= 75 else 'HIGH' if score >= 50
                 else 'MEDIUM' if score >= 25 else 'LOW')
        return score, level

    def _summary(self, hosts: List[HostProfile], dur: float, engines: List[str]) -> Dict:
        svcs = [s for h in hosts for s in h.services]
        cves = [c for s in svcs for c in s.cves]
        svc_cnt: Dict[str, int] = {}
        for s in svcs:
            k = s.service or f'port/{s.port}'
            svc_cnt[k] = svc_cnt.get(k, 0) + 1
        os_dist: Dict[str, int] = {}
        for h in hosts:
            k = h.os_family or 'Unknown'
            os_dist[k] = os_dist.get(k, 0) + 1
        risk_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for h in hosts:
            risk_dist[h.risk_level] = risk_dist.get(h.risk_level, 0) + 1
        return {
            'scan_duration':   round(dur, 2),
            'hosts_alive':     len(hosts),
            'total_open_ports': len(svcs),
            'top_services':    sorted(svc_cnt.items(), key=lambda x: -x[1])[:15],
            'os_distribution': os_dist,
            'risk_distribution': risk_dist,
            'vulnerabilities': {
                'critical': len([c for c in cves if c.get('cvss', 0) >= 9.0]),
                'high':     len([c for c in cves if 7.0 <= c.get('cvss', 0) < 9.0]),
                'medium':   len([c for c in cves if 4.0 <= c.get('cvss', 0) < 7.0]),
                'total':    len(cves),
                'top_cves': list({c['id'] for c in sorted(cves, key=lambda x: -x.get('cvss', 0))[:10]}),
            },
            'high_risk_hosts': [h.ip for h in hosts if h.risk_level in ('CRITICAL', 'HIGH')],
            'shodan_enriched': len([h for h in hosts if h.shodan]),
            'engines_used':    engines,
        }

    # ------------------------------------------------------------------
    # EVASION + PROXY HELPERS
    # ------------------------------------------------------------------

    def _evasion_flags(self) -> List[str]:
        """Return nmap evasion flags when evasion mode is active"""
        if not self.evasion:
            return []
        flags = ['-f', f'--mtu', str(self.mtu), '-n', '-Pn']
        if self.decoys > 0:
            flags += ['-D', f'RND:{self.decoys}']
        if self.source_port > 0:
            flags += ['-g', str(self.source_port)]
        if self.data_length > 0:
            flags += ['--data-length', str(self.data_length)]
        return flags

    def _proxy_prefix(self) -> List[str]:
        """Return proxychains prefix when requested and available"""
        if self.use_proxychains and CAPS.get('proxychains4'):
            return ['proxychains4', '-q']
        return []

    # ------------------------------------------------------------------
    # IoT / DEVICE DETECTION
    # ------------------------------------------------------------------

    def _detect_device_category(self, profile: HostProfile):
        """Classify host into device category based on open ports and HTTP signatures"""
        open_ports = {s.port for s in profile.services}

        # ICS/SCADA — highest priority, always flag critical
        ics_hit = open_ports & _ICS_PORTS
        if ics_hit:
            profile.device_category = 'ics'
            for port in ics_hit:
                proto = _ICS_PORT_SERVICE.get(port, 'ics')
                svc = next((s for s in profile.services if s.port == port), None)
                if svc and not svc.service:
                    svc.service = proto
                ics_cves = correlate_cves(proto)
                if svc:
                    existing_ids = {c['id'] for c in svc.cves}
                    for c in ics_cves:
                        if c['id'] not in existing_ids:
                            svc.cves.append(c)
                profile.vulnerabilities.append({
                    'id': f'ICS-EXPOSED-{proto.upper()}',
                    'severity': 'CRITICAL',
                    'desc': (f'{proto.upper()} port {port} is exposed — '
                             f'unauthenticated ICS/SCADA access possible'),
                })
            return

        # IP Camera — port match + HTTP signature confirm
        if open_ports & ({554} | _CAMERA_PORTS):
            if self._is_camera(profile) or (open_ports & {554, 37777, 34567, 3702}):
                profile.device_category = 'camera'
                cam_cves = correlate_cves('rtsp')
                if 554 in open_ports:
                    svc = next((s for s in profile.services if s.port == 554), None)
                    if svc:
                        existing_ids = {c['id'] for c in svc.cves}
                        for c in cam_cves:
                            if c['id'] not in existing_ids:
                                svc.cves.append(c)
                return

        # Router — TR-069 or Winbox are definitive router ports
        if open_ports & _ROUTER_PORTS:
            profile.device_category = 'router'
            return

        # NAS — Synology DSM ports
        if open_ports & _NAS_PORTS:
            profile.device_category = 'nas'
            return

        # IoT — MQTT/CoAP
        if open_ports & _IOT_PORTS:
            profile.device_category = 'iot'
            if 1883 in open_ports:
                mqtt_cves = correlate_cves('mqtt')
                svc = next((s for s in profile.services if s.port == 1883), None)
                if svc:
                    existing_ids = {c['id'] for c in svc.cves}
                    for c in mqtt_cves:
                        if c['id'] not in existing_ids:
                            svc.cves.append(c)
            return

        # Flock Safety / LPR surveillance camera by MAC OUI (from flock-back)
        if profile.mac:
            mac_l = profile.mac.lower()
            for prefix in FLOCK_MAC_PREFIXES:
                if mac_l.startswith(prefix.lower()):
                    profile.device_category = 'surveillance'
                    if not profile.device_type:
                        profile.device_type = 'Flock Safety LPR Camera'
                    profile.vulnerabilities.append({
                        'id': 'SURVEILLANCE-LPR-DETECTED',
                        'severity': 'INFO',
                        'desc': 'MAC OUI matches Flock Safety / LPR surveillance camera network',
                    })
                    return

    def _is_camera(self, profile: HostProfile) -> bool:
        """Check HTTP server/title/auth signatures to confirm IP camera"""
        for svc in profile.services:
            server = svc.http_server.lower()
            title  = svc.http_title.lower()
            if any(sig in server for sig in CAMERA_SERVER_SIGS):
                return True
            if any(sig in title for sig in CAMERA_HTML_SIGS):
                return True
        return False

    def _fingerprint_camera_favicon(self, ip: str, port: int) -> str:
        """Fetch /favicon.ico and mmh3-hash it to identify camera model/vendor"""
        if not CAPS.get('mmh3') or not CAPS.get('requests') or _mmh3 is None:
            return ''
        try:
            import requests as _req, base64 as _b64
            scheme = 'https' if port in (443, 8443) else 'http'
            resp = _req.get(f'{scheme}://{ip}:{port}/favicon.ico',
                            timeout=4, verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 (SecV netrecon)'})
            if resp.status_code == 200 and resp.content:
                h = _mmh3.hash(_b64.encodebytes(resp.content))
                return CAMERA_FAVICON_HASHES.get(h, '')
        except Exception:
            pass
        return ''

    def _probe_mqtt(self, ip: str) -> Dict:
        """Send MQTT CONNECT packet and check CONNACK response"""
        result: Dict = {'connack': False, 'no_auth': False}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((ip, 1883))
            # MQTT v3.1.1 CONNECT, clean session, keepalive 60, client-id "secv-probe"
            connect_pkt = b'\x10\x16\x00\x04MQTT\x04\x02\x00\x3c\x00\x0asecv-probe'
            s.send(connect_pkt)
            raw = s.recv(4)
            s.close()
            if len(raw) >= 4 and raw[0] == 0x20:  # CONNACK packet type
                result['connack'] = True
                result['no_auth'] = (raw[3] == 0x00)  # return code 0 = accepted without auth
        except Exception:
            pass
        return result

    def _probe_rtsp(self, ip: str, port: int = 554) -> Dict:
        """Send RTSP OPTIONS and parse response for auth/server info"""
        result: Dict = {'banner': '', 'no_auth': False, 'server': ''}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((ip, port))
            ua = _pick_ua() if self.evasion else 'secv-netrecon'
            s.send(f'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {ua}\r\n\r\n'.encode())
            raw = s.recv(512)
            s.close()
            resp = raw.decode('utf-8', errors='replace')
            result['banner'] = resp[:200]
            m = re.search(r'Server:\s*(.+)', resp, re.IGNORECASE)
            if m:
                result['server'] = m.group(1).strip()
            result['no_auth'] = 'RTSP/1.0 200' in resp
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------
    # WEB ENUMERATION
    # ------------------------------------------------------------------

    def _run_web_enum(self, profiles: List[HostProfile]):
        """Run gobuster/ffuf + nikto + whatweb on all discovered web services"""
        pp = self._proxy_prefix()
        wl = self.web_wordlist
        ev = self.evasion

        for host in profiles:
            for svc in host.services:
                if svc.port not in _WEB_PORTS:
                    continue
                scheme = 'https' if svc.port in (443, 8443, 9443) else 'http'
                url = f'{scheme}://{host.ip}:{svc.port}'

                out_base = ''
                if self.output_dir:
                    safe_ip = host.ip.replace('.', '_')
                    out_base = str(Path(self.output_dir) / f'web_{safe_ip}_{svc.port}')

                # Gobuster first, ffuf as fallback
                found: List[str] = []
                if GobusterRunner.available():
                    found = GobusterRunner.scan(
                        url, wl, threads=50, timeout=120,
                        evasion=ev,
                        proxy_prefix=pp,
                        output_file=out_base + '_gobuster.txt' if out_base else '',
                    )
                elif FfufRunner.available():
                    found = FfufRunner.scan(
                        url, wl, threads=50, timeout=120,
                        evasion=ev,
                        proxy_prefix=pp,
                        output_file=out_base + '_ffuf.json' if out_base else '',
                    )

                if found:
                    if not hasattr(svc, 'web_paths'):
                        svc.__dict__['web_paths'] = found
                    if 'web_enum' not in svc.sources:
                        svc.sources.append('web_enum')

                # Nikto vulnerability scan
                if NiktoRunner.available() and not self.passive:
                    nikto_out = out_base + '_nikto.txt' if out_base else ''
                    nk = NiktoRunner.scan(url, timeout=300, evasion=ev,
                                          proxy_prefix=pp, output_file=nikto_out)
                    if nk.get('findings'):
                        svc.__dict__.setdefault('nikto_findings', []).extend(nk['findings'])
                        if 'nikto' not in svc.sources:
                            svc.sources.append('nikto')

                # WhatWeb fingerprint
                if WhatwebRunner.available() and not self.passive:
                    ww = WhatwebRunner.scan(url, timeout=20, proxy_prefix=pp, evasion=ev)
                    if ww.get('technologies'):
                        for tech in ww['technologies']:
                            if tech not in svc.http_technologies:
                                svc.http_technologies.append(tech)
                        if 'whatweb' not in svc.sources:
                            svc.sources.append('whatweb')

    # ------------------------------------------------------------------
    # SEARCHSPLOIT
    # ------------------------------------------------------------------

    def _run_searchsploit(self, profiles: List[HostProfile]):
        """Map discovered services to ExploitDB entries via searchsploit"""
        if not SearchsploitRunner.available():
            return

        # Try XML-based search first if we have an output dir
        xml_file = ''
        if self.output_dir:
            xml_file = str(Path(self.output_dir) / 'scan.xml')

        if xml_file and Path(xml_file).is_file():
            exploits = SearchsploitRunner.search_nmap_xml(xml_file)
            if exploits:
                for host in profiles:
                    if not hasattr(host, 'exploits'):
                        host.__dict__['exploits'] = []
                    host.__dict__['exploits'].extend(exploits)
            return

        # Per-service fallback
        seen: Set[str] = set()
        for host in profiles:
            if not hasattr(host, 'exploits'):
                host.__dict__['exploits'] = []
            for svc in host.services:
                key = f'{svc.service}:{svc.version}'
                if key in seen or not svc.service:
                    continue
                seen.add(key)
                results = SearchsploitRunner.search_service(svc.service, svc.version)
                if results:
                    host.__dict__['exploits'].extend(results[:5])
                    if not hasattr(svc, 'exploits'):
                        svc.__dict__['exploits'] = results[:5]

    # ------------------------------------------------------------------
    # OUTPUT GENERATION
    # ------------------------------------------------------------------

    def _generate_outputs(self, profiles: List[HostProfile], target_str: str) -> Dict:
        """Generate HTML report, nmap XML, MSF RC file in output_dir"""
        out = Path(self.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = str(out / f'netrecon_{ts}')
        artifacts: Dict = {}

        # Run a combined nmap scan for file output (XML → HTML via xsltproc)
        if NmapRunner.available() and not self.passive:
            ef = self._evasion_flags()
            pp = self._proxy_prefix()
            live_ips = [h.ip for h in profiles]
            if live_ips:
                print(f'[*] Generating XML scan for {len(live_ips)} hosts...', file=sys.stderr)
                cmd = (pp) + ['nmap', '-sV', '--version-intensity', '5', '-T4',
                               '-oA', base, '--open', '-p',
                               ','.join(str(s.port) for h in profiles
                                        for s in h.services if s.port)[:2048]
                               or 'top-1000']
                if CAPS['root']:
                    cmd += ['-sS']
                else:
                    cmd += ['-sT']
                cmd += ef + live_ips[:64]
                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    xml_file = base + '.xml'
                    artifacts['nmap_xml'] = xml_file

                    # HTML report via xsltproc
                    if CAPS.get('xsltproc') and Path(xml_file).is_file():
                        html_file = base + '.html'
                        subprocess.run(
                            ['xsltproc', xml_file, '-o', html_file],
                            capture_output=True, timeout=30,
                        )
                        if Path(html_file).is_file():
                            artifacts['html_report'] = html_file

                    # Searchsploit on the XML
                    if self.do_searchsploit and CAPS.get('searchsploit'):
                        exploits = SearchsploitRunner.search_nmap_xml(base + '.xml')
                        if exploits:
                            ss_file = base + '_exploits.txt'
                            with open(ss_file, 'w') as f:
                                for e in exploits:
                                    f.write(f"{e['title']} | {e['path']}\n")
                            artifacts['searchsploit'] = ss_file
                except Exception as e:
                    self.errors.append(f'output_scan: {e}')

        # Metasploit RC file
        rc_file = base + '_msf.rc'
        ws_name = f'netrecon_{ts}'
        xml_path = artifacts.get('nmap_xml', '')
        with open(rc_file, 'w') as f:
            f.write(f'spool {base}_msf_console.log\n')
            f.write(f'workspace -a {ws_name}\n')
            if xml_path and Path(xml_path).is_file():
                f.write(f'db_import {xml_path}\n')
            f.write('hosts\nservices\nvulns\n\n')
            f.write('# --- Suggested attack vectors ---\n')
            for host in profiles:
                for svc in host.services:
                    for cve in getattr(svc, 'cves', []):
                        if cve.get('cvss', 0) >= 7.0:
                            f.write(f'# {host.ip}:{svc.port} {svc.service} — {cve["id"]} (CVSS {cve["cvss"]})\n')
            f.write('\n# --- Handler template ---\n')
            f.write('# use exploit/multi/handler\n')
            f.write('# set PAYLOAD windows/x64/meterpreter/reverse_tcp\n')
            f.write('# set LHOST <YOUR_IP>\n# set LPORT 4444\n')
            f.write('# set ExitOnSession false\n# exploit -j\n')
        artifacts['msf_rc'] = rc_file

        return artifacts

    # ------------------------------------------------------------------

    def _parse_target(self, target: str) -> Tuple[Set[str], str]:
        ips: Set[str] = set()
        target = target.strip()

        if ',' in target:
            for t in target.split(','):
                sub, _ = self._parse_target(t.strip())
                ips.update(sub)
            return ips, target

        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 1024 and self.mode != 'deep':
                hosts = hosts[:1024]
            return {str(h) for h in hosts}, str(net)
        except ValueError:
            pass

        m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', target)
        if m:
            prefix, s, e = m.group(1), int(m.group(2)), int(m.group(3))
            return {f'{prefix}{i}' for i in range(s, min(e + 1, 256))}, target

        try:
            ipaddress.ip_address(target)
            return {target}, target
        except ValueError:
            pass

        try:
            resolved = socket.gethostbyname(target)
            return {resolved}, resolved
        except Exception as e:
            self.errors.append(f'Cannot resolve {target}: {e}')
        return ips, target

    def _is_local(self, target_str: str) -> bool:
        try:
            return ipaddress.ip_network(target_str, strict=False).is_private
        except Exception:
            try:
                return ipaddress.ip_address(target_str).is_private
            except Exception:
                return False

    def _tcp_fallback(self, ips: List[str]) -> Dict[str, Set[int]]:
        common = [21,22,23,25,53,80,110,143,389,443,445,993,995,
                  1433,1521,3306,3389,5432,5900,6379,8080,8443,27017]
        result: Dict[str, Set[int]] = {}
        lock = threading.Lock()

        def probe(ip: str):
            found: Set[int] = set()
            for port in common:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    if s.connect_ex((ip, port)) == 0:
                        found.add(port)
                    s.close()
                except Exception:
                    pass
            if found:
                with lock:
                    result[ip] = found

        with ThreadPoolExecutor(max_workers=min(50, len(ips))) as ex:
            list(ex.map(probe, ips))
        return result

    def _guess_service(self, port: int, banner: str = '') -> str:
        if banner:
            bl = banner.lower()
            for kw, svc in [('ssh','ssh'),('ftp','ftp'),('smtp','smtp'),
                             ('http','http'),('mysql','mysql'),('mariadb','mysql'),
                             ('redis','redis'),('mongo','mongodb')]:
                if kw in bl:
                    return svc
        return _PORT_NAMES.get(port, 'unknown')

    def _bool(self, v: Any) -> bool:
        if isinstance(v, bool): return v
        return str(v).lower() in ('true', '1', 'yes', 'on')

    def _t(self, phase: str) -> int:
        # For chained modes, use the most permissive timeout (max across all active modes)
        base = max(
            (_TIMEOUT_TABLE.get(m, _TIMEOUT_TABLE['normal']).get(phase, 60) for m in self.modes),
            default=60
        )
        return base


# ============================================================================
# HELP
# ============================================================================

def show_help():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║  Network Recon Module v2.0 — Multi-Engine Profiler + Evasion      ║
║  github.com/0xb0rn3                                               ║
╚═══════════════════════════════════════════════════════════════════╝

Concurrent scanning: nmap, masscan, rustscan, arp-scan, Shodan,
gobuster/ffuf, whatweb, searchsploit — all in one pass.

SCAN MODES:
  quick    Fast, top ports only, minimal service detection
  normal   Balanced, top-1000 ports, full service/HTTP detection  [default]
  deep     All ports, vuln scripts, OS fingerprinting
  stealth  Low-rate scanning for IDS evasion (rate≤200, timeout≥10)
  evasion  Full IDS/FW bypass: packet frags, decoys, source-port spoof
  full     Everything: deep + stealth + evasion + web enum

  Modes can be chained with comma/plus for feature union:
    mode=deep,stealth   → deep port scan at stealth rate
    mode=full           → all features combined
    mode=evasion+stealth → double-layer evasion

TOOLS (all concurrent):
  nmap          Service/version/OS/script detection
  masscan       Ultra-fast port discovery  [requires root]
  rustscan      Fast port discovery wrapper
  arp-scan      Local MAC + host discovery  [requires root]
  whatweb       Web tech fingerprinting (CMS, framework, server)
  gobuster/ffuf Web directory brute-force on discovered HTTP ports
  searchsploit  ExploitDB mapping per service/version
  Shodan        External threat intelligence  [requires API key]
  ipinfo.io     ASN / country / org lookup
  DNS/WHOIS     Forward, reverse, MX, NS, TXT records
  NetBIOS/SMB   NetBIOS name + share enumeration (ports 139/445)
  SNMP          Community string brute-force (port 161)

IoT / DEVICE DETECTION (automatic):
  camera        RTSP probe (554), favicon mmh3 hash (17 camera models), HTTP server/title sigs
  iot           MQTT CONNECT probe (1883), CoAP (5683), mDNS (5353)
  router        TR-069 (7547), MikroTik Winbox (8291) detection
  nas           Synology DSM (5000/5001) detection
  ics           Modbus (502), DNP3 (20000), Siemens S7 (102), BACnet (47808), Niagara Fox (1911)
  surveillance  Flock Safety / LPR camera MAC OUI fingerprinting

PARAMETERS:
  mode            quick | normal | deep | stealth | evasion | full  (default: normal)
                  Chain modes with comma/plus: deep,stealth or full
  ports           quick | top-20 | top-100 | top-1000 | web | database | common
                  iot | camera | router | nas | ics | device | all
                  or custom: 80,443,8080-8090                (default: top-1000)
  threads         Concurrent host threads                    (default: 20)
  rate            Masscan pps                                (default: 1000)
  timeout         Per-host base timeout (s)                  (default: 5)
  os_detection    true | false                               (default: false)
  vuln_scripts    Run nmap vuln NSE scripts                  (default: false)
  nse_profile     Custom NSE script list (e.g. vuln,exploit,auth,brute)
  shodan_key      Shodan API key
  interface       NIC for ARP scan
  exclude         Comma-separated IPs to skip
  passive_only    DNS/WHOIS/Shodan only, no active scan

EVASION / ANONYMITY:
  evasion         true | false — enable all IDS/FW bypass flags  (default: false)
  decoys          Number of RND decoys (e.g. 10)                 (default: 5)
  mtu             Packet fragment MTU (e.g. 8, 16, 24)           (default: 8)
  source_port     Source port spoof (e.g. 53 for DNS camouflage)  (default: 53)
  data_length     Append random padding bytes                     (default: 32)
  proxychains     true | false — wrap nmap with proxychains4      (default: false)

WEB / EXPLOIT OUTPUT:
  web_enum        true | false — run gobuster/ffuf on web ports   (default: true)
  web_wordlist    Path to wordlist for gobuster/ffuf
  searchsploit    true | false — run searchsploit per service     (default: false)
  output_dir      Directory to save: nmap XML, HTML report, MSF RC, gobuster results

TARGETS:
  192.168.1.1          Single IP
  192.168.1.0/24       CIDR network
  192.168.1.1-50       IP range
  example.com          Hostname (resolved)
  10.0.0.1,10.0.0.2    Multiple targets

EXAMPLES:
  use netrecon; set mode normal; run 192.168.1.0/24
  use netrecon; set mode deep; set shodan_key KEY; run 10.0.0.1
  use netrecon; set mode evasion; set proxychains true; run 10.10.10.5
  use netrecon; set evasion true; set decoys 10; set mtu 16; run 10.10.10.0/24
  use netrecon; set searchsploit true; set output_dir /tmp/scan; run 192.168.1.1
  use netrecon; set ports web; set vuln_scripts true; set web_enum true; run example.com
  use netrecon; set ports iot; run 192.168.1.0/24     # MQTT/CoAP/mDNS sweep
  use netrecon; set ports camera; run 192.168.1.0/24  # IP camera sweep (RTSP, Hikvision, Dahua)
  use netrecon; set ports ics; run 10.0.0.0/24        # ICS/SCADA sweep (Modbus, DNP3, BACnet, S7)
  use netrecon; set ports device; run 192.168.1.0/24  # Full device sweep (all IoT categories)

OUTPUT (JSON):
  hosts[]         Per-host: IP, MAC, vendor, hostname, OS, services, risk
  device_category camera | router | nas | iot | ics | surveillance | (empty)
  device_type     Specific model if identified (e.g. "Hikvision", "Dahua", "Reolink")
  services[]      Per-service: port, service, version, banner, HTTP title,
                  technologies (whatweb), web_paths (gobuster), TLS, CVEs
                  mqtt_no_auth, snmp_community, smb_shares (when applicable)
  vulnerabilities[] Host-level findings: ICS exposure, MQTT no-auth, RTSP no-auth, SNMP defaults
  shodan{}        Shodan data per host (vulns, ports, tags, org)
  dns_records{}   Forward/reverse/MX/NS/TXT
  asn/country     ASN, org, country, city
  risk_score      0-100 per host with level: LOW/MEDIUM/HIGH/CRITICAL
                  ICS hosts get +40 base score, cameras +15
  summary{}       Total hosts, services, OS dist, CVE stats, high-risk hosts
  outputs{}       Paths to: html_report, nmap_xml, msf_rc, searchsploit results

REQUIREMENTS:
  Minimum:  Python 3.8+ (TCP connect fallback always works)
  Standard: nmap
  Enhanced: masscan nmap arp-scan whatweb gobuster   [+ run as root for SYN scan]
  Evasion:  proxychains4 + configured proxy chain
  IoT/Cam:  pip3 install mmh3   (favicon hash fingerprinting, optional)
  Full:     + pip3 install scapy dnspython requests shodan mmh3
            + apt install ffuf searchsploit gobuster whatweb xsltproc
""")


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('--help', '-h', 'help'):
        show_help()
        sys.exit(0)
    try:
        data = json.loads(sys.stdin.read())
        result = NetRecon(data).execute()
        print(json.dumps(result, indent=2, default=str))
    except json.JSONDecodeError as e:
        print(json.dumps({'success': False, 'errors': [f'Invalid JSON input: {e}']}))
        sys.exit(1)
    except KeyboardInterrupt:
        print(json.dumps({'success': False, 'errors': ['Interrupted']}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({'success': False, 'errors': [f'Fatal: {e}']}))
        sys.exit(1)


if __name__ == '__main__':
    main()
