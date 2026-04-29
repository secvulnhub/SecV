#!/usr/bin/env python3
"""
wifi_monitor — LAN host discovery, port scanning, CVE lookup, and threat detection.
secV interface: reads {"target": "...", "params": {...}} from stdin, writes JSON to stdout.
"""
import asyncio
import socket
import ssl
import json
import sys
import os
import time
import ipaddress
import threading
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.ERROR)

# Optional deps
try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# ── helpers ──────────────────────────────────────────────────────────────────

def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).lower() in ('1', 'true', 'yes', 'on')


def _parse_ports(s: str) -> List[int]:
    s = (s or '').strip()
    if not s or s == 'default':
        return [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
                8080, 8443, 27017]
    ports = []
    for part in s.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _expand_cidr(target: str) -> List[str]:
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]

# ── ARP discovery ─────────────────────────────────────────────────────────────

def _arp_scan(cidr: str, timeout: float = 3.0) -> Dict[str, str]:
    """Returns {ip: mac} for live hosts via ARP. Falls back silently when scapy unavailable."""
    if not HAS_SCAPY:
        return {}
    try:
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=cidr)
        answered, _ = srp(pkt, timeout=timeout, verbose=False, retry=1)
        return {rcv.psrc: rcv.hwsrc for _, rcv in answered}
    except Exception:
        return {}


def _tcp_ping(ips: List[str], ports=(80, 443, 22, 445), timeout: float = 1.0) -> Set[str]:
    """TCP connect to common ports; returns set of responsive IPs."""
    alive: Set[str] = set()
    lock = threading.Lock()

    def probe(ip: str):
        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        alive.add(ip)
                    s.close()
                    return
                s.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=min(100, len(ips))) as ex:
        list(ex.map(probe, ips))
    return alive

# ── CVE lookup ────────────────────────────────────────────────────────────────

_cve_cache: Dict[str, Any] = {}

async def _lookup_cves(session, keyword: str) -> List[str]:
    if not HAS_AIOHTTP or not keyword or len(keyword) < 3:
        return []
    cached = _cve_cache.get(keyword)
    if cached and datetime.now() - cached['ts'] < timedelta(hours=24):
        return cached['cves']
    try:
        async with session.get(
            f'https://cve.circl.lu/api/search/{keyword}',
            timeout=aiohttp.ClientTimeout(total=4)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if isinstance(data, list):
                    cves = [item['id'] for item in data[:3] if 'id' in item]
                    _cve_cache[keyword] = {'cves': cves, 'ts': datetime.now()}
                    return cves
    except Exception:
        pass
    return []


def _banner_keyword(banner: str) -> str:
    if not banner or banner in ('N/A', 'Open (Silent)'):
        return ''
    b = banner.lower()
    if b.startswith('ssh-'):
        return 'openssh'
    if 'server:' in b:
        prod = banner.split('|')[0].replace('Server:', '').strip()
        return prod.split('/')[0].split(' ')[0][:15]
    if 'tls' in b and 'alpn' in b:
        return 'openssl'
    return ''

# ── Port prober ───────────────────────────────────────────────────────────────

async def _probe_port(ip: str, port: int, hostname: str, session) -> Optional[Dict]:
    result = {
        'port': port, 'status': 'filtered',
        'service': 'unknown', 'banner': 'N/A', 'cves': []
    }
    try:
        result['service'] = socket.getservbyport(port, 'tcp')
    except OSError:
        pass

    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2.0
        )
        result['status'] = 'open'
        result['banner'] = 'Open (Silent)'

        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname),
                    timeout=3.0
                )
                writer.write(f'GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                raw = data.decode('utf-8', errors='ignore')
                if 'Server:' in raw:
                    srv = [l for l in raw.split('\r\n') if l.lower().startswith('server:')]
                    result['banner'] = f'HTTPS | {srv[0].strip()}' if srv else 'HTTPS'
                else:
                    result['banner'] = 'HTTPS'
                result['service'] = 'https'
            except Exception:
                result['banner'] = 'HTTPS (TLS)'
        elif port in (80, 8080):
            try:
                writer.write(f'GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                raw = data.decode('utf-8', errors='ignore')
                if 'Server:' in raw:
                    srv = [l for l in raw.split('\r\n') if l.lower().startswith('server:')]
                    result['banner'] = srv[0].strip() if srv else 'HTTP'
                else:
                    result['banner'] = 'HTTP'
                result['service'] = 'http'
            except Exception:
                result['banner'] = 'HTTP'
        else:
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=1.5)
                raw = data.decode('utf-8', errors='ignore').strip()
                if raw:
                    result['banner'] = raw.split('\n')[0][:150]
                    if raw.startswith('SSH-'):
                        result['service'] = 'ssh'
            except asyncio.TimeoutError:
                pass

    except ConnectionRefusedError:
        result['status'] = 'closed'
        return None
    except asyncio.TimeoutError:
        result['status'] = 'timeout'
        return None
    except OSError:
        return None
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    if result['status'] == 'open':
        kw = _banner_keyword(result['banner'])
        if kw and session:
            result['cves'] = await _lookup_cves(session, kw)

    return result


async def _scan_host(ip: str, ports: List[int], hostname: str, max_concurrency: int = 100) -> List[Dict]:
    session = None
    if HAS_AIOHTTP:
        session = aiohttp.ClientSession()

    sem = asyncio.Semaphore(max_concurrency)
    results = []

    async def bounded(port):
        async with sem:
            return await _probe_port(ip, port, hostname, session)

    tasks = [bounded(p) for p in ports]
    done = await asyncio.gather(*tasks, return_exceptions=True)
    for r in done:
        if isinstance(r, dict):
            results.append(r)

    if session:
        await session.close()
    return sorted(results, key=lambda x: x['port'])

# ── Device fingerprinting ─────────────────────────────────────────────────────

def _fingerprint(open_ports: List[Dict]) -> Dict:
    ports = {r['port'] for r in open_ports}
    banners = ' '.join(r.get('banner', '') for r in open_ports).lower()
    info = {'device_type': 'Unknown', 'os': 'Unknown', 'risks': []}

    if {80, 443}.intersection(ports) and ('camera' in banners or 'dvr' in banners):
        info['device_type'] = 'IoT Camera / DVR'
        info['risks'].append('Exposed IoT device')
    elif {53, 80}.issubset(ports) and ('router' in banners or 'mikrotik' in banners or 'openwrt' in banners):
        info['device_type'] = 'Router / Gateway'
    elif {21, 22, 445}.intersection(ports) and ('synology' in banners or 'qnap' in banners):
        info['device_type'] = 'NAS Device'
    elif {3306, 5432, 27017, 1433}.intersection(ports):
        info['device_type'] = 'Database Server'
        info['risks'].append('Exposed database port')
    elif {80, 443}.issubset(ports):
        info['device_type'] = 'Web Server'
    elif 22 in ports:
        info['device_type'] = 'Linux Host'

    if 3389 in ports or 445 in ports:
        info['os'] = 'Windows'
    elif 22 in ports or 'ubuntu' in banners or 'debian' in banners:
        info['os'] = 'Linux/Unix'

    if 23 in ports:
        info['risks'].append('Telnet — cleartext protocol')
    if 21 in ports:
        info['risks'].append('FTP — cleartext protocol')
    if 'openssh 4' in banners or 'openssh 5' in banners:
        info['risks'].append('End-of-life SSH version')

    return info

# ── Threat detection ──────────────────────────────────────────────────────────

def _threat_summary(hosts: List[Dict]) -> List[str]:
    threats = []
    exposed_db = [h['ip'] for h in hosts
                  if any(p['port'] in (3306, 5432, 27017, 6379, 1433) for p in h.get('open_ports', []))]
    if exposed_db:
        threats.append(f'Exposed database service on: {", ".join(exposed_db)}')

    telnet_hosts = [h['ip'] for h in hosts
                    if any(p['port'] == 23 for p in h.get('open_ports', []))]
    if telnet_hosts:
        threats.append(f'Telnet (cleartext) enabled on: {", ".join(telnet_hosts)}')

    return threats

# ── Main ──────────────────────────────────────────────────────────────────────

async def _run(context: Dict) -> Dict:
    target = context.get('target', '')
    params = context.get('params', {})

    mode = params.get('mode', 'scan')
    ports_param = params.get('ports', 'default')
    port_scan = _bool(params.get('port_scan', True))
    cve_lookup = _bool(params.get('cve_lookup', True))
    timeout = float(params.get('timeout', 3.0))
    concurrency = int(params.get('concurrency', 100))

    if not target:
        return {'error': 'target is required (IP, CIDR, or hostname)'}

    result = {
        'target': target,
        'scan_time': datetime.now().isoformat(),
        'mode': mode,
        'hosts': [],
        'threats': [],
        'summary': {}
    }

    # ── Host discovery ────────────────────────────────────────────────────────
    ips = _expand_cidr(target)
    print(f'[*] Discovering hosts in {target} ({len(ips)} addresses)...', file=sys.stderr)

    arp_map = {}
    alive_ips: Set[str] = set()

    if len(ips) > 1:
        arp_map = _arp_scan(target, timeout=timeout)
        alive_ips = set(arp_map.keys())
        print(f'[*] ARP: {len(alive_ips)} hosts', file=sys.stderr)

    if not alive_ips:
        alive_ips = _tcp_ping(ips[:128], timeout=min(timeout, 1.5))
        print(f'[*] TCP ping: {len(alive_ips)} hosts', file=sys.stderr)

    if not alive_ips:
        # Single-target mode — scan the target directly even if ping fails
        if len(ips) == 1:
            alive_ips = set(ips)
        else:
            result['summary'] = {'hosts_found': 0, 'message': 'No responding hosts detected'}
            return result

    print(f'[*] Found {len(alive_ips)} alive hosts', file=sys.stderr)

    # ── Per-host scanning ─────────────────────────────────────────────────────
    ports = _parse_ports(ports_param)

    for ip in sorted(alive_ips):
        host_entry: Dict[str, Any] = {
            'ip': ip,
            'mac': arp_map.get(ip, ''),
            'hostname': '',
            'open_ports': [],
            'fingerprint': {},
        }

        try:
            host_entry['hostname'] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        if port_scan:
            hostname = host_entry['hostname'] or ip
            print(f'[*] Scanning {ip} ({len(ports)} ports)...', file=sys.stderr)
            open_ports = await _scan_host(ip, ports, hostname, concurrency)
            host_entry['open_ports'] = open_ports
            host_entry['fingerprint'] = _fingerprint(open_ports)

        result['hosts'].append(host_entry)

    result['threats'] = _threat_summary(result['hosts'])

    total_open = sum(len(h['open_ports']) for h in result['hosts'])
    all_cves = [c for h in result['hosts']
                for p in h['open_ports'] for c in p.get('cves', [])]

    result['summary'] = {
        'hosts_found': len(result['hosts']),
        'total_open_ports': total_open,
        'threats_detected': len(result['threats']),
        'unique_cves': len(set(all_cves)),
        'cve_list': list(set(all_cves)),
    }

    return result


def main():
    raw = sys.stdin.read()
    try:
        context = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON input: {e}'}))
        sys.exit(1)

    result = asyncio.run(_run(context))
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
