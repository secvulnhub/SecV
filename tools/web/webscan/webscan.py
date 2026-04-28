#!/usr/bin/env python3
"""
webscan — Web vulnerability scanner covering SQLi, XSS, CSRF, IDOR, 403 bypass,
security headers, framework CVEs (Jira, AEM, Confluence), file upload, open redirect.
secV interface: reads {"target": "...", "params": {...}} from stdin, writes JSON to stdout.
"""
import sys
import json
import time
import re
import socket
import urllib.parse
from typing import Dict, List, Optional, Any

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── helpers ───────────────────────────────────────────────────────────────────

def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).lower() in ('1', 'true', 'yes', 'on')


def _get(session, url: str, timeout: float = 8, **kwargs):
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=True, **kwargs)
    except Exception:
        return None


def _post(session, url: str, data=None, timeout: float = 8, **kwargs):
    try:
        return session.post(url, data=data, timeout=timeout, verify=False, allow_redirects=True, **kwargs)
    except Exception:
        return None


def _normalize(target: str) -> str:
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return target.rstrip('/')

# ── security headers ──────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': None,
    'Content-Security-Policy': None,
    'Strict-Transport-Security': None,
    'X-XSS-Protection': None,
    'Referrer-Policy': None,
    'Permissions-Policy': None,
}


def check_security_headers(resp) -> Dict:
    findings = {'missing': [], 'present': [], 'misconfigured': []}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for hdr, expected in SECURITY_HEADERS.items():
        key = hdr.lower()
        if key in headers:
            findings['present'].append(hdr)
            if expected and expected.lower() not in headers[key].lower():
                findings['misconfigured'].append(f'{hdr}: expected "{expected}", got "{headers[key]}"')
        else:
            findings['missing'].append(hdr)
    return findings

# ── SQL injection ─────────────────────────────────────────────────────────────

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed",
    r"sqlite3\.operationalerror",
    r"odbc sql server driver",
    r"microsoft sql native client error",
    r"ora-\d{5}:",
    r"supplied argument is not a valid mysql",
]

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "1 AND 1=1", "1 AND 1=2"]

TIME_SQLI = {
    "mysql":  "' AND SLEEP(3)-- -",
    "pgsql":  "' OR pg_sleep(3)-- -",
    "mssql":  "'; WAITFOR DELAY '0:0:3'--",
}


def check_sqli(session, url: str, params: dict) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))
    if not base_params:
        return findings

    for param in list(base_params.keys()):
        # Error-based
        for payload in SQLI_PAYLOADS:
            test_params = base_params.copy()
            test_params[param] = payload
            resp = _get(session, url.split('?')[0], params=test_params)
            if resp:
                body = resp.text.lower()
                for pat in SQLI_ERROR_PATTERNS:
                    if re.search(pat, body, re.IGNORECASE):
                        findings.append({
                            'type': 'sqli_error',
                            'severity': 'HIGH',
                            'param': param,
                            'payload': payload,
                            'evidence': pat,
                            'url': url,
                        })
                        break

        # Time-based blind
        for db, payload in TIME_SQLI.items():
            test_params = base_params.copy()
            test_params[param] = payload
            t0 = time.time()
            resp = _get(session, url.split('?')[0], params=test_params, timeout=10)
            elapsed = time.time() - t0
            if resp and elapsed >= 2.8:
                findings.append({
                    'type': 'sqli_time_blind',
                    'severity': 'HIGH',
                    'param': param,
                    'db': db,
                    'elapsed': round(elapsed, 2),
                    'url': url,
                })

    return findings

# ── Reflected XSS ─────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]


def check_xss(session, url: str) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))
    if not base_params:
        return findings

    for param in list(base_params.keys()):
        for payload in XSS_PAYLOADS:
            test_params = base_params.copy()
            test_params[param] = payload
            resp = _get(session, url.split('?')[0], params=test_params)
            if resp and payload in resp.text:
                findings.append({
                    'type': 'reflected_xss',
                    'severity': 'HIGH',
                    'param': param,
                    'payload': payload,
                    'url': url,
                })
                break

    return findings

# ── CSRF check ────────────────────────────────────────────────────────────────

CSRF_TOKEN_PATTERNS = [
    r'<input[^>]+name=["\']?(_token|csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\']?',
    r'<meta[^>]+name=["\']?csrf-token["\']?',
]


def check_csrf(session, url: str) -> List[Dict]:
    findings = []
    resp = _get(session, url)
    if not resp:
        return findings

    body = resp.text
    has_form = '<form' in body.lower() and 'method' in body.lower()
    if not has_form:
        return findings

    has_token = any(re.search(pat, body, re.IGNORECASE) for pat in CSRF_TOKEN_PATTERNS)
    if not has_token:
        findings.append({
            'type': 'csrf_missing_token',
            'severity': 'MEDIUM',
            'note': 'Form found without detectable CSRF token',
            'url': url,
        })

    return findings

# ── 403 bypass ────────────────────────────────────────────────────────────────

BYPASS_HEADERS = [
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
    {'Referer': 'https://example.com/admin'},
]

BYPASS_PATH_TRICKS = [
    '/%2f', '/./', '/..;/', '/%20', '//']


def check_403_bypass(session, base_url: str, path: str) -> List[Dict]:
    findings = []
    full_url = base_url + path
    resp = _get(session, full_url)
    if not resp or resp.status_code != 403:
        return findings

    # Header bypass
    for headers in BYPASS_HEADERS:
        r = _get(session, full_url, headers=headers)
        if r and r.status_code == 200:
            findings.append({
                'type': '403_bypass_header',
                'severity': 'HIGH',
                'bypass_header': list(headers.keys())[0],
                'url': full_url,
            })

    # Path manipulation
    for trick in BYPASS_PATH_TRICKS:
        test_url = base_url + trick + path.lstrip('/')
        r = _get(session, test_url)
        if r and r.status_code == 200:
            findings.append({
                'type': '403_bypass_path',
                'severity': 'HIGH',
                'bypass_path': test_url,
                'url': full_url,
            })

    return findings

# ── Open redirect ─────────────────────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '/\\evil.com',
    'https:evil.com',
]

REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'returnUrl', 'redirect_uri',
                   'callback', 'goto', 'redir', 'destination', 'target', 'to']


def check_open_redirect(session, base_url: str) -> List[Dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    existing = dict(urllib.parse.parse_qsl(parsed.query))

    test_params = list(existing.keys()) or REDIRECT_PARAMS[:5]
    for param in test_params:
        for payload in REDIRECT_PAYLOADS:
            params = existing.copy()
            params[param] = payload
            resp = _get(session, base_url.split('?')[0], params=params, timeout=5)
            if resp:
                final = resp.url
                if 'evil.com' in final:
                    findings.append({
                        'type': 'open_redirect',
                        'severity': 'MEDIUM',
                        'param': param,
                        'redirected_to': final,
                        'url': base_url,
                    })
                    break
    return findings

# ── Framework CVE checks ──────────────────────────────────────────────────────

JIRA_PATHS = [
    ('/rest/api/2/mypermissions', 'CVE-check: Jira unauthenticated permissions'),
    ('/secure/ContactAdministrators!default.jspa', 'CVE-2019-11581: Jira SSTI'),
    ('/plugins/servlet/Wallboard/', 'CVE-2018-20824: Jira XSS'),
    ('/plugins/servlet/gadgets/makeRequest', 'CVE-2019-8451: Jira SSRF'),
    ('/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true', 'CVE-2019-8449: Jira user info disclosure'),
    ('/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml', 'CVE-2019-8442: Jira info disclosure'),
    ('/secure/QueryComponent!Default.jspa', 'CVE-2020-14179: Jira info disclosure'),
    ('/_/;/WEB-INF/web.xml', 'CVE-2021-26086: Jira file read'),
]

AEM_PATHS = [
    ('/bin/querybuilder.json/a.html', 'CVE-2016-0957: AEM dispatcher bypass'),
    ('/bin/querybuilder.json;%0aa.css', 'CVE-2016-0957: AEM dispatcher bypass (encoded)'),
    ('/content/../libs/foundation/components/login', 'AEM login bypass attempt'),
    ('/etc.json', 'AEM /etc exposure'),
]

CONFLUENCE_PATHS = [
    ('/login.action', 'Confluence login page'),
    ('/pages/viewpage.action?pageId=1', 'Confluence anonymous access check'),
]


def check_framework_cves(session, base_url: str) -> List[Dict]:
    findings = []

    # Detect framework from response headers / body
    resp = _get(session, base_url)
    if not resp:
        return findings

    headers_str = str(resp.headers).lower()
    body = resp.text.lower()

    is_jira = 'jira' in body or 'atlassian' in headers_str
    is_aem = 'aem' in body or 'cq5' in body or 'granite' in body
    is_confluence = 'confluence' in body

    paths_to_check = []
    if is_jira:
        paths_to_check.extend([(p, note, 'jira') for p, note in JIRA_PATHS])
    if is_aem:
        paths_to_check.extend([(p, note, 'aem') for p, note in AEM_PATHS])
    if is_confluence:
        paths_to_check.extend([(p, note, 'confluence') for p, note in CONFLUENCE_PATHS])

    # Always probe a few Jira paths regardless (in case detection fails)
    if not is_jira:
        paths_to_check.extend([(p, note, 'jira') for p, note in JIRA_PATHS[:3]])

    for path, note, framework in paths_to_check:
        r = _get(session, base_url + path, timeout=6)
        if r and r.status_code in (200, 201, 301, 302):
            findings.append({
                'type': 'framework_cve',
                'severity': 'MEDIUM',
                'framework': framework,
                'path': path,
                'status_code': r.status_code,
                'note': note,
                'url': base_url + path,
            })

    return findings

# ── File upload detection ─────────────────────────────────────────────────────

UPLOAD_PATHS = ['/upload', '/file/upload', '/api/upload', '/media/upload',
                '/uploads', '/attachments', '/import']


def check_file_upload(session, base_url: str) -> List[Dict]:
    findings = []
    resp = _get(session, base_url)
    if resp:
        body = resp.text
        # Detect upload forms
        upload_forms = re.findall(r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>', body, re.IGNORECASE)
        if upload_forms:
            findings.append({
                'type': 'upload_form_detected',
                'severity': 'INFO',
                'count': len(upload_forms),
                'note': 'File upload form found — check for unrestricted upload',
                'url': base_url,
            })

    for path in UPLOAD_PATHS:
        r = _get(session, base_url + path, timeout=5)
        if r and r.status_code in (200, 201, 405):
            findings.append({
                'type': 'upload_endpoint',
                'severity': 'INFO',
                'path': path,
                'status_code': r.status_code,
                'url': base_url + path,
            })

    return findings

# ── Rate limit check ──────────────────────────────────────────────────────────

def check_rate_limit(session, url: str, attempts: int = 10) -> List[Dict]:
    findings = []
    codes = []
    for _ in range(attempts):
        r = _get(session, url, timeout=5)
        if r:
            codes.append(r.status_code)
        time.sleep(0.1)

    if codes and 429 not in codes and all(c < 400 for c in codes):
        findings.append({
            'type': 'missing_rate_limit',
            'severity': 'LOW',
            'note': f'No rate limiting detected after {attempts} requests',
            'url': url,
        })
    return findings

# ── Main ──────────────────────────────────────────────────────────────────────

def run(context: Dict) -> Dict:
    if not HAS_REQUESTS:
        return {'error': 'requests library required: pip3 install requests'}

    target = context.get('target', '')
    params = context.get('params', {})

    if not target:
        return {'error': 'target URL is required'}

    base_url = _normalize(target)

    checks = {
        'headers':         _bool(params.get('headers', True)),
        'sqli':            _bool(params.get('sqli', True)),
        'xss':             _bool(params.get('xss', True)),
        'csrf':            _bool(params.get('csrf', True)),
        'bypass_403':      _bool(params.get('bypass_403', False)),
        'open_redirect':   _bool(params.get('open_redirect', True)),
        'framework_cves':  _bool(params.get('framework_cves', True)),
        'file_upload':     _bool(params.get('file_upload', True)),
        'rate_limit':      _bool(params.get('rate_limit', False)),
    }

    bypass_path  = params.get('bypass_path', '/admin')
    extra_url    = params.get('url', base_url)  # URL with params for SQLi/XSS
    user_agent   = params.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
    cookies      = params.get('cookies', '')
    headers_param = params.get('headers_str', '')

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})
    if cookies:
        for kv in cookies.split(';'):
            kv = kv.strip()
            if '=' in kv:
                k, v = kv.split('=', 1)
                session.cookies.set(k.strip(), v.strip())
    if headers_param:
        for kv in headers_param.split(';'):
            kv = kv.strip()
            if ':' in kv:
                k, v = kv.split(':', 1)
                session.headers[k.strip()] = v.strip()

    result: Dict[str, Any] = {
        'target': base_url,
        'scan_url': extra_url,
        'findings': [],
        'summary': {},
    }

    print(f'[*] Scanning {base_url}...', file=sys.stderr)

    if checks['headers']:
        print('[*] Checking security headers...', file=sys.stderr)
        resp = _get(session, base_url)
        if resp:
            hdr = check_security_headers(resp)
            if hdr['missing']:
                result['findings'].append({
                    'type': 'security_headers',
                    'severity': 'LOW',
                    'missing': hdr['missing'],
                    'present': hdr['present'],
                    'misconfigured': hdr['misconfigured'],
                })

    if checks['sqli'] and '?' in extra_url:
        print('[*] Testing SQL injection...', file=sys.stderr)
        result['findings'].extend(check_sqli(session, extra_url, params))

    if checks['xss'] and '?' in extra_url:
        print('[*] Testing reflected XSS...', file=sys.stderr)
        result['findings'].extend(check_xss(session, extra_url))

    if checks['csrf']:
        print('[*] Checking CSRF tokens...', file=sys.stderr)
        result['findings'].extend(check_csrf(session, base_url))

    if checks['bypass_403']:
        print(f'[*] Testing 403 bypass on {bypass_path}...', file=sys.stderr)
        result['findings'].extend(check_403_bypass(session, base_url, bypass_path))

    if checks['open_redirect']:
        print('[*] Testing open redirect...', file=sys.stderr)
        result['findings'].extend(check_open_redirect(session, extra_url))

    if checks['framework_cves']:
        print('[*] Checking framework CVEs (Jira/AEM/Confluence)...', file=sys.stderr)
        result['findings'].extend(check_framework_cves(session, base_url))

    if checks['file_upload']:
        print('[*] Detecting file upload endpoints...', file=sys.stderr)
        result['findings'].extend(check_file_upload(session, base_url))

    if checks['rate_limit']:
        print('[*] Testing rate limiting...', file=sys.stderr)
        result['findings'].extend(check_rate_limit(session, base_url))

    # Summary
    by_severity: Dict[str, int] = {}
    for f in result['findings']:
        sev = f.get('severity', 'INFO')
        by_severity[sev] = by_severity.get(sev, 0) + 1

    result['summary'] = {
        'total_findings': len(result['findings']),
        'by_severity': by_severity,
        'checks_run': [k for k, v in checks.items() if v],
    }

    return result


def main():
    raw = sys.stdin.read()
    try:
        context = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON input: {e}'}))
        sys.exit(1)

    result = run(context)
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
