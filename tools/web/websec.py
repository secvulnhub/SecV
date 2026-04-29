#!/usr/bin/env python3
"""
WebSec - Web Security Research & OSINT Tool v1.0
For SecV Platform | Author: SecVulnHub Team
Category: Web Security Research

A Burp Suite-style terminal tool for security researchers and bug bounty hunters.
Every operation includes educational context so users learn as they work.

⚠️  FOR AUTHORIZED TESTING AND SECURITY RESEARCH ONLY ⚠️
"""

import json
import sys
import socket
import subprocess
import re
import time
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
║   Web Security Research & OSINT Tool v1.0                           ║
║   For Bug Bounty Hunters & Security Researchers                     ║
╚══════════════════════════════════════════════════════════════════════╝{NC}
"""

def learn(text: str):
    """Print educational context."""
    print(f"\n{B}[LEARN]{NC} {DIM}{text}{NC}", file=sys.stderr)

def info(text: str):
    print(f"{C}[*]{NC} {text}", file=sys.stderr)

def ok(text: str):
    print(f"{G}[+]{NC} {text}", file=sys.stderr)

def warn(text: str):
    print(f"{Y}[!]{NC} {text}", file=sys.stderr)

def bad(text: str):
    print(f"{R}[-]{NC} {text}", file=sys.stderr)

def section(title: str):
    print(f"\n{BOLD}{Y}{'─'*60}{NC}", file=sys.stderr)
    print(f"{BOLD}{W} {title}{NC}", file=sys.stderr)
    print(f"{BOLD}{Y}{'─'*60}{NC}", file=sys.stderr)

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
        "learn": "HSTS is a browser instruction. Once a browser sees this header, it will REFUSE to connect over HTTP for the specified time period."
    },
    "missing_csp": {
        "name": "Missing Content Security Policy (CSP)",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "CSP controls what resources browsers can load, protecting against XSS and data injection.",
        "impact": "Cross-Site Scripting (XSS) attacks have higher success rate",
        "fix": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "learn": "Without CSP, if an attacker injects JavaScript into your page, the browser will happily run it. CSP is a whitelist of trusted sources."
    },
    "missing_xframe": {
        "name": "Missing X-Frame-Options",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Without this header, the site can be embedded in iframes on attacker-controlled pages.",
        "impact": "Clickjacking attacks - tricking users into clicking invisible buttons",
        "fix": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
        "learn": "Clickjacking: imagine an attacker overlays an invisible iframe of your bank's 'confirm transfer' button over a 'Win a Prize!' button. Users think they're clicking one thing but actually clicking your button."
    },
    "missing_xcontent": {
        "name": "Missing X-Content-Type-Options",
        "severity": "LOW",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Without this header, browsers may 'sniff' content types and execute files as different types than intended.",
        "impact": "MIME-type confusion attacks, script execution from unexpected sources",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "learn": "Old browsers tried to be 'helpful' by guessing file types. If a server says a file is text/plain but it looks like HTML, the browser would render it as HTML - including any scripts inside."
    },
    "server_version_disclosure": {
        "name": "Server Version Disclosure",
        "severity": "LOW",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The server is revealing its software name and version, helping attackers identify vulnerabilities.",
        "impact": "Reconnaissance - attacker knows exactly what CVEs to look for",
        "fix": "Configure server to suppress or genericize the Server header",
        "learn": "Information disclosure is step 1 in most attacks. Knowing 'Apache 2.4.49' immediately tells an attacker to try CVE-2021-41773 (path traversal). Remove this gift to attackers."
    },
    "cors_wildcard": {
        "name": "CORS Wildcard Origin",
        "severity": "HIGH",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Access-Control-Allow-Origin: * allows any website to make cross-origin requests with your API's responses.",
        "impact": "Any malicious website can read your API responses if the user is logged in",
        "fix": "Restrict to specific trusted origins: Access-Control-Allow-Origin: https://yourdomain.com",
        "learn": "CORS is a browser security feature. Browsers block cross-origin requests by default. The server tells browsers which origins are allowed. * means 'everyone is allowed' - dangerous for authenticated APIs."
    },
    "cors_reflect_origin": {
        "name": "CORS Reflects Arbitrary Origin",
        "severity": "HIGH",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The server echoes back any Origin header sent, granting access to any website.",
        "impact": "Cross-Origin attacks, credential theft from authenticated users",
        "fix": "Maintain an explicit whitelist of trusted origins",
        "learn": "Some developers think 'I'll just allow whatever Origin is sent' to avoid CORS errors. This completely breaks the same-origin policy and is equivalent to Access-Control-Allow-Origin: *."
    },
    "insecure_cookie": {
        "name": "Cookie Missing Secure Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-614",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Session cookies without the Secure flag can be sent over unencrypted HTTP connections.",
        "impact": "Session hijacking via network sniffing on HTTP connections",
        "fix": "Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict",
        "learn": "The Secure flag tells the browser: only send this cookie over HTTPS. Without it, if a user visits http:// (not https://), their session cookie travels in plaintext - readable by anyone on the network."
    },
    "cookie_no_httponly": {
        "name": "Cookie Missing HttpOnly Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-1004",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Cookies without HttpOnly can be read by JavaScript, making XSS attacks more damaging.",
        "impact": "Session theft via XSS - document.cookie exposes the session token",
        "fix": "Set-Cookie: session=xxx; HttpOnly",
        "learn": "HttpOnly cookies cannot be accessed via document.cookie in JavaScript. Even if an XSS attack injects malicious JS, it cannot steal HttpOnly cookies. Always set this on session tokens."
    },
    "cookie_no_samesite": {
        "name": "Cookie Missing SameSite Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
        "impact": "Cross-Site Request Forgery (CSRF) - attackers can make requests on behalf of authenticated users",
        "fix": "Set-Cookie: session=xxx; SameSite=Strict (or Lax for less restrictive)",
        "learn": "SameSite=Strict means: don't send this cookie when navigating from another site. This breaks CSRF attacks because the attacker's form submission won't include the victim's cookies."
    },
    "sqli_error": {
        "name": "SQL Injection - Error Based",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "User input is directly interpolated into SQL queries, and database errors are visible.",
        "impact": "Data exfiltration, authentication bypass, in some cases remote code execution",
        "fix": "Use parameterized queries/prepared statements. NEVER concatenate user input into SQL.",
        "learn": "SQL injection is when user input changes the structure of a query. ' OR '1'='1 as a password can make the query: WHERE pass='' OR '1'='1' which is always true. Modern ORMs prevent this automatically."
    },
    "xss_reflected": {
        "name": "Reflected XSS",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "User-supplied input is reflected in the response without proper encoding.",
        "impact": "Session theft, phishing, malware delivery, defacement",
        "fix": "HTML-encode all user input when rendering. Use modern frameworks that auto-escape. Implement CSP.",
        "learn": "Reflected XSS: attacker sends victim a link with ?search=<script>steal()</script>. The server puts this in the page, browser runs it. The attacker never touches the server - the victim's browser does all the work."
    },
    "open_redirect": {
        "name": "Open Redirect",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "The application redirects to user-supplied URLs without validation.",
        "impact": "Phishing - users trust your domain, get redirected to malicious site. Can be used in OAuth flows to steal tokens.",
        "fix": "Validate redirect URLs against a whitelist of allowed destinations",
        "learn": "Open redirects are often chained with other attacks. 'Login at bank.com/login?next=evil.com' - user sees trusted bank.com domain, but gets redirected to evil.com after authentication where attacker harvests credentials."
    },
    "directory_listing": {
        "name": "Directory Listing Enabled",
        "severity": "MEDIUM",
        "cwe": "CWE-548",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The web server shows directory contents when no index file exists.",
        "impact": "Exposes file structure, source code, backups, configuration files",
        "fix": "Disable directory listing in web server config (Options -Indexes for Apache)",
        "learn": "Directory listing exposes your app's internal structure. Attackers look for .git directories (source code), backup files (.bak, .old), and config files that shouldn't be public."
    },
    "outdated_libs": {
        "name": "Outdated JavaScript Libraries",
        "severity": "MEDIUM",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "description": "The application uses JavaScript libraries with known vulnerabilities.",
        "impact": "Depends on specific CVEs in the detected version",
        "fix": "Update to latest stable versions. Use automated dependency checking (npm audit, Dependabot)",
        "learn": "Old jQuery versions had XSS vulnerabilities. Old Bootstrap had open redirects. Attackers scan sites for these fingerprints specifically. The OWASP Dependency-Check tool automates this detection."
    },
    "weak_ssl": {
        "name": "Weak SSL/TLS Configuration",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "The server supports deprecated TLS versions or weak cipher suites.",
        "impact": "BEAST, POODLE, DROWN, SWEET32 and other protocol-level attacks",
        "fix": "Disable TLS 1.0/1.1, disable weak ciphers (RC4, DES, 3DES, MD5), use TLS 1.2+ with strong ciphers",
        "learn": "TLS versions are like lock versions. TLS 1.0 is like a 30-year-old padlock - researchers have found ways to open it. TLS 1.3 is the latest, most secure version. Many compliance frameworks now require minimum TLS 1.2."
    },
    "path_traversal": {
        "name": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "User input can navigate outside the intended directory using ../ sequences.",
        "impact": "Read arbitrary files including /etc/passwd, application config, source code",
        "fix": "Validate and sanitize file paths. Use realpath() to resolve and verify paths stay within allowed directory.",
        "learn": "../../etc/passwd goes up two directories then into /etc/passwd. If your app serves files like /files/[user_input], an attacker can use ../../etc/passwd to read system files. Always use a path join + starts-with check."
    },
    "sensitive_files_exposed": {
        "name": "Sensitive Files Accessible",
        "severity": "HIGH",
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Common sensitive files are publicly accessible (git, env, config files).",
        "impact": "Source code exposure, API key leakage, database credentials exposure",
        "fix": "Block access to .git, .env, config files in web server configuration",
        "learn": "Developers often forget to exclude .git folders from web roots, exposing their entire source code history. .env files contain API keys and database passwords. These are #1 findings in bug bounty programs."
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
    "' AND SLEEP(0)--",  # Safe - sleep(0) won't delay but tests syntax
    "1 ORDER BY 1--",
    "1 UNION SELECT NULL--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
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
    r"ORA-[0-9]{5}",       # Oracle
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
]

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

        self.findings: List[Dict] = []
        self.info_findings: List[Dict] = []
        self.errors: List[str] = []

        # Parse target URL
        self.url, self.host, self.scheme, self.port = self._parse_target(target)

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

    def _request(self, url: str, method: str = "GET", headers: dict = None,
                  data: str = None, allow_redirects: bool = True,
                  timeout: float = None) -> Optional[Dict]:
        """Make an HTTP request, using requests if available, else urllib."""
        timeout = timeout or self.timeout
        default_headers = {
            "User-Agent": "Mozilla/5.0 (SecV WebSec Research Tool)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            default_headers.update(headers)

        try:
            if CAPS["requests"]:
                resp = requests.request(
                    method, url,
                    headers=default_headers,
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
                # Fallback to urllib
                req = urllib.request.Request(url, headers=default_headers, method=method)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "bytes": body.encode(),
                        "url": resp.url,
                        "redirected": resp.url != url,
                    }
        except Exception as e:
            return None

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
                "learn": v["learn"],
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
        section("WEB OSINT RECONNAISSANCE")
        learn("OSINT stands for Open Source Intelligence. We collect information that's publicly available "
              "without touching the target directly. Think of it as checking someone's public social media "
              "before knocking on their door. DNS records, SSL certs, and WHOIS are all public data.")

        results = {}

        # --- DNS Records ---
        section("DNS Records")
        learn("DNS (Domain Name System) maps domain names to IP addresses. Different record types reveal "
              "different info: A=IPv4, AAAA=IPv6, MX=mail servers, NS=nameservers, TXT=various config "
              "(SPF/DKIM for email auth, verification tokens). MX records tell you what email provider "
              "they use. NS records reveal what DNS provider they use.")
        
        dns_results = self._dns_lookup()
        results["dns"] = dns_results

        # --- WHOIS ---
        section("WHOIS Information")
        learn("WHOIS is a public registry of who owns a domain. It reveals registrar, registration date, "
              "expiry date, and sometimes contact info. Expiry dates matter - many 'hacks' are just "
              "expired domains being registered by attackers. A recently registered domain mimicking "
              "a brand is often a phishing indicator.")
        
        whois_result = self._whois_lookup()
        results["whois"] = whois_result

        # --- SSL Certificate ---
        section("SSL/TLS Certificate")
        learn("SSL certificates bind a domain to a public key. They reveal: who issued the cert (CA), "
              "what domains it covers (SANs can reveal subdomains!), expiry date, and whether it's "
              "using modern crypto. Certificate Transparency logs are public - you can find all certs "
              "ever issued for a domain at crt.sh")
        
        ssl_result = self._ssl_inspect()
        results["ssl"] = ssl_result

        # --- Robots.txt & Sitemap ---
        section("Robots.txt & Sitemap")
        learn("robots.txt tells search engine bots which URLs NOT to crawl. Ironically, this is a perfect "
              "map of what the site wants to hide! /admin, /internal, /backup are common entries. "
              "The Disallow lines are a treasure map for security researchers.")
        
        results["robots_sitemap"] = self._fetch_robots_sitemap()

        # --- HTTP Headers ---
        section("HTTP Response Headers")
        learn("HTTP headers are metadata sent with every response. Security headers tell the browser how "
              "to behave (block iframes, enforce HTTPS, allow scripts only from trusted sources). "
              "Missing security headers are some of the most common bug bounty findings.")
        
        results["headers"] = self._headers_audit()

        # --- Technology Detection ---
        section("Technology Stack Detection")
        learn("Every web framework, CMS, and library leaves fingerprints in the HTML, CSS, JS, and HTTP "
              "headers. Knowing the tech stack lets you look up known CVEs specifically for those versions. "
              "This is the reconnaissance that precedes targeted exploitation.")
        
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
                    # Fallback: use system dig/nslookup
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

        # Check for interesting TXT records
        if "TXT" in records:
            for txt in records["TXT"]:
                if "spf" in txt.lower():
                    info(f"SPF Record found: {txt[:80]}")
                    learn("SPF (Sender Policy Framework) lists authorized mail servers. If too permissive "
                          "(e.g., ~all instead of -all), attackers can spoof emails from this domain.")
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

            # Extract key fields
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
            warn("Tip: Try manually at https://whois.domaintools.com or https://lookup.icann.org")

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
                            info(f"Subject Alternative Names (subdomains/domains on same cert):")
                            for san in result["san"][:20]:
                                info(f"  → {san}")
                            learn("SANs are goldmine for bug bounty! Other domains on the same cert often "
                                  "belong to the same company. Check each one - dev/staging/internal "
                                  "environments are often less hardened than production.")

                        # Check for weak TLS
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

        # Suggest crt.sh
        info(f"Certificate Transparency logs: https://crt.sh/?q={self.host}")
        learn("crt.sh indexes all SSL certificates issued for a domain. Because CAs must publicly log certs, "
              "you can find subdomains that were never intended to be discovered - internal.company.com, "
              "dev.company.com, staging.company.com etc.")
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
                        for path in disallowed[:20]:
                            info(f"  → {path.strip()}")
                        learn("Each 'Disallow' line is a hidden page the site doesn't want Google indexing. "
                              "These are often admin panels, internal tools, or sensitive directories.")
                
                if name == "security_txt":
                    info("Security.txt found - this site has a vulnerability disclosure policy")
                    learn("security.txt (RFC 9116) is how responsible companies tell researchers "
                          "where and how to report vulnerabilities. Always check this before testing - "
                          "it defines scope and responsible disclosure requirements.")
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

        # Security headers to check
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

        # Check referrer policy
        if "referrer-policy" in headers:
            ok(f"Referrer-Policy: {headers['referrer-policy']}")
        else:
            warn("MISSING: Referrer-Policy")
            learn("Without Referrer-Policy, your site's URLs get included in the HTTP Referer header "
                  "when users click links to other sites. If your URLs contain tokens or sensitive IDs "
                  "(e.g., /reset-password?token=xxx), those leak to third-party sites.")

        # Check permissions policy
        if "permissions-policy" in headers:
            ok(f"Permissions-Policy: {headers['permissions-policy'][:60]}")
        
        # Server header - version disclosure
        if "server" in headers:
            server = headers["server"]
            info(f"Server header: {server}")
            # Check if version disclosed
            if any(char.isdigit() for char in server):
                self._add_finding("server_version_disclosure",
                    evidence=f"Server: {server}")
                warn(f"Version disclosed in Server header: {server}")

        # X-Powered-By
        if "x-powered-by" in headers:
            powered = headers["x-powered-by"]
            warn(f"X-Powered-By disclosed: {powered}")
            self._add_finding("server_version_disclosure",
                detail=f"Tech stack disclosed via X-Powered-By header",
                evidence=f"X-Powered-By: {powered}")
            learn("X-Powered-By tells attackers exactly what framework you're using. "
                  "PHP versions, ASP.NET versions, Express versions - all exploitable if outdated.")

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

        if detected:
            learn(f"Detected {len(detected)} technologies. For each one, search: "
                  f"'[technology] CVE 2024' or check https://www.cvedetails.com. "
                  f"Check if detected versions are current at https://www.npmjs.com/advisories")

        # Check for version numbers in common libs
        jquery_match = re.search(r"jquery[/-]([\d.]+)(?:\.min)?\.js", full_text, re.IGNORECASE)
        if jquery_match:
            version = jquery_match.group(1)
            info(f"jQuery version: {version}")
            parts = [int(x) for x in version.split(".")[:2] if x.isdigit()]
            if parts and (parts[0] < 3 or (parts[0] == 3 and len(parts) > 1 and parts[1] < 6)):
                self._add_finding("outdated_libs",
                    detail=f"jQuery {version} has known XSS vulnerabilities",
                    evidence=f"Detected jQuery version: {version}")
                warn(f"Potentially outdated jQuery: {version} - check for XSS CVEs")

        return {"detected": list(detected.keys())}

    # =========================================================================
    # OPERATION: DIRECTORY/FILE DISCOVERY
    # =========================================================================

    def op_dirs(self) -> Dict:
        """Discover directories and sensitive files."""
        section("DIRECTORY & FILE DISCOVERY")
        learn("Directory brute-forcing tries common paths that developers often forget to protect. "
              "We're looking for admin panels, backup files, source code, and configuration files "
              "that shouldn't be publicly accessible. This is like trying every door in a building "
              "to find which ones are unlocked.")

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
                    color = G if status == 200 else Y

                    # Highlight interesting files
                    is_interesting = any(x in path for x in [
                        ".env", ".git", "config", "backup", "admin",
                        "phpinfo", "debug", ".sql", "swagger", "graphql"
                    ])

                    if is_interesting:
                        bad(f"[{status}] {path} ← INTERESTING!")
                        interesting.append(result)
                        
                        if ".git" in path:
                            self._add_finding("sensitive_files_exposed",
                                detail="Git repository exposed - full source code may be accessible",
                                evidence=f"HTTP {status} at {result['url']}",
                                url=result["url"])
                            learn("An exposed .git directory means an attacker can run "
                                  "'git clone' tricks to download your entire source code, "
                                  "including all history. API keys, passwords in old commits - all exposed.")
                        elif ".env" in path:
                            self._add_finding("sensitive_files_exposed",
                                detail=".env file accessible - likely contains API keys and passwords",
                                evidence=f"HTTP {status} at {result['url']}",
                                url=result["url"])
                        elif "swagger" in path or "graphql" in path:
                            info(f"API documentation found: {result['url']}")
                            learn("API documentation (Swagger/OpenAPI) lists every endpoint, parameter, "
                                  "and data type. This is the blueprint for testing the API. "
                                  "Always check if authentication is required to view it.")
                    else:
                        info(f"[{status}] {path}")

                    found.append(result)

        info(f"\nFound {len(found)} accessible paths, {len(interesting)} interesting")
        return {"found": found, "interesting": interesting}

    # =========================================================================
    # OPERATION: SECURITY HEADERS AUDIT
    # =========================================================================

    def op_headers(self) -> Dict:
        """Detailed security headers analysis."""
        section("SECURITY HEADERS AUDIT")
        learn("HTTP security headers are instructions browsers follow to protect users. They're free to "
              "implement and have a massive security impact. Missing headers are low-effort, high-impact "
              "findings in bug bounty programs. Tools like securityheaders.com grade sites on these.")
        return self._headers_audit()

    # =========================================================================
    # OPERATION: CORS TESTING
    # =========================================================================

    def op_cors(self) -> Dict:
        """Test for CORS misconfigurations."""
        section("CORS MISCONFIGURATION TESTING")
        learn("CORS (Cross-Origin Resource Sharing) allows websites to request data from other domains. "
              "Misconfigurations let attacker-controlled sites access your API on behalf of logged-in users. "
              "Imagine: you visit evil.com, it silently calls bank.com/api/balance using your session cookie "
              "and sends the result to the attacker. CORS misconfigs are consistently high-paying bug bounty findings.")

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
                warn(f"Wildcard CORS: Origin={origin} → ACAO={acao}")
                self._add_finding("cors_wildcard",
                    detail="Access-Control-Allow-Origin: * allows all origins",
                    evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}")
                results["wildcard"] = True

            elif acao == origin and origin != f"https://{self.host}":
                if acac.lower() == "true":
                    bad(f"REFLECTED CORS with credentials: Origin={origin} → ACAO={acao}, ACAC={acac}")
                    self._add_finding("cors_reflect_origin",
                        detail="Server reflects arbitrary Origin and allows credentials - Critical CORS bypass",
                        evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}\nResponse ACAC: {acac}",
                        severity_override="CRITICAL")
                    learn("CORS reflection + credentials = account takeover. Attacker can make authenticated "
                          "API calls from their site and read the responses. This is often rated Critical "
                          "in bug bounty programs, especially on financial/healthcare applications.")
                else:
                    warn(f"Reflected CORS (no credentials): Origin={origin} → ACAO={acao}")
                    self._add_finding("cors_reflect_origin",
                        detail="Server reflects arbitrary Origin header",
                        evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}")
                results.setdefault("reflected", []).append(origin)
            else:
                info(f"Origin: {origin} → ACAO: {acao or 'not set'}")

        return results

    # =========================================================================
    # OPERATION: COOKIE AUDIT
    # =========================================================================

    def op_cookies(self) -> Dict:
        """Audit cookie security attributes."""
        section("COOKIE SECURITY AUDIT")
        learn("Cookies store session tokens - the keys to a user's account. Three flags protect them: "
              "Secure (only send over HTTPS), HttpOnly (JavaScript can't read it), SameSite (don't "
              "send cross-site). Missing flags are like leaving your house keys in an unlocked mailbox.")

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

            ok(f"  Secure: {'✓' if secure else '✗'}")
            ok(f"  HttpOnly: {'✓' if httponly else '✗'}")
            ok(f"  SameSite: {samesite or '✗ NOT SET'}")

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
        """Test for SQL injection vulnerabilities."""
        section("SQL INJECTION DETECTION")
        learn("SQL injection occurs when user input is embedded directly into SQL queries. "
              "We test by sending characters that 'break' SQL syntax (quotes, semicolons) "
              "and watching for database error messages. If we get MySQL errors back, the input "
              "is going directly into a query. We only use safe, non-destructive payloads here.")

        warn("Testing with error-based detection only. No blind/time-based tests to avoid server load.")
        warn("Always get written authorization before running SQLi tests.")

        results = {"vulnerable": [], "tested": 0}
        test_url = self.params.get("test_url", self.url)

        # Get the page first to find forms and parameters
        resp = self._request(test_url)
        if not resp:
            return results

        test_points = []

        # Extract URL parameters
        parsed = urllib.parse.urlparse(test_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param_name, values in params.items():
                test_points.append(("GET", param_name, test_url))
                info(f"Found GET parameter: {param_name}")

        # Extract form fields
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
                        info(f"Found form field: {name} [{method}] → {action}")

        if not test_points:
            info("No parameters found to test. Use test_url param with a URL containing ?param=value")
            learn("SQLi needs a place to inject. Look for URLs like: /search?q=test, "
                  "/product?id=1, /user?name=john. These parameter values might go into SQL queries.")
            return results

        # Test each point
        for method, param, url in test_points:
            for payload in SQLI_PAYLOADS[:5]:  # Test with first 5 safe payloads
                results["tested"] += 1

                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params_dict = urllib.parse.parse_qs(parsed.query)
                    params_dict[param] = [payload]
                    new_query = urllib.parse.urlencode(params_dict, doseq=True)
                    test_target = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    resp = self._request(test_target, timeout=8.0)
                else:
                    resp = self._request(url, method="POST",
                                        data=urllib.parse.urlencode({param: payload}))

                if not resp:
                    continue

                body = resp["body"]
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
                            "pattern": pattern
                        })
                        learn(f"The payload '{payload}' caused a database error. This means the input "
                              f"went directly into a SQL query. To confirm, you'd use sqlmap with "
                              f"authorization: sqlmap -u '{url}' --dbs")
                        break

        if not results["vulnerable"]:
            ok(f"No obvious SQLi found in {results['tested']} tests (error-based only)")
            info("For thorough testing, use SQLMap with authorization on a test environment")

        return results

    # =========================================================================
    # OPERATION: XSS DETECTION
    # =========================================================================

    def op_xss(self) -> Dict:
        """Test for reflected XSS vulnerabilities."""
        section("CROSS-SITE SCRIPTING (XSS) DETECTION")
        learn("XSS (Cross-Site Scripting) injects malicious JavaScript into web pages viewed by other users. "
              "Reflected XSS: attacker sends victim a link, the link's payload reflects in the page, "
              "browser executes it. We test by injecting markers and checking if they appear unescaped "
              "in the response. We use unique markers to avoid false positives.")

        warn("Testing for reflected XSS only. Stored XSS requires manual review.")

        results = {"vulnerable": [], "tested": 0}
        test_url = self.params.get("test_url", self.url)

        # Use a unique marker to identify reflection
        marker = f"WSEC{int(time.time())}"
        safe_marker = f"{marker}<b>test</b>"

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
            for payload in XSS_PAYLOADS[:3]:
                full_payload = f"{marker}{payload}"
                results["tested"] += 1

                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    pdict = urllib.parse.parse_qs(parsed.query)
                    pdict[param] = [full_payload]
                    new_q = urllib.parse.urlencode(pdict, doseq=True)
                    target = urllib.parse.urlunparse(parsed._replace(query=new_q))
                    resp = self._request(target)
                else:
                    resp = self._request(url, method="POST",
                                        data=urllib.parse.urlencode({param: full_payload}))

                if not resp:
                    continue

                body = resp["body"]
                # Check if payload reflects unencoded
                if marker in body:
                    # Check if < > are encoded
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
                        learn("The payload reflected without HTML encoding. To confirm, manually test in "
                              "a browser. If alert(1) pops, it's confirmed XSS. Report with reproduction "
                              "steps and a harmless alert() PoC. Do NOT use payloads that steal data.")
                    else:
                        ok(f"  {param}: Input reflected but HTML-encoded (safe)")
                else:
                    info(f"  {param}: Payload not reflected (payload: {payload[:20]})")

        return results

    # =========================================================================
    # OPERATION: WEB SPIDER
    # =========================================================================

    def op_spider(self) -> Dict:
        """Spider/crawl the target website."""
        section("WEB SPIDER / CRAWLER")
        learn("Spidering follows links to map the structure of a website. We collect all discovered URLs, "
              "forms, and JavaScript endpoints. This gives us a complete picture of the application's "
              "attack surface. Every form is a potential injection point. Every URL is a potential "
              "access control issue. Knowing the full site map is step 1 in any web pentest.")

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

            # Find links
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

            # Find forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                fields = [inp.get("name", "") for inp in form.find_all(["input", "textarea", "select"])]
                form_data = {"action": urllib.parse.urljoin(url, action),
                             "method": method, "fields": fields, "source_url": url}
                found["forms"].append(form_data)
                info(f"  → Form: {method} {form_data['action']} | Fields: {fields[:5]}")

            # Find JS files
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_src = urllib.parse.urljoin(url, src)
                if full_src not in found["js_files"]:
                    found["js_files"].append(full_src)

        ok(f"Spider complete: {len(found['urls'])} pages, {len(found['forms'])} forms, "
           f"{len(found['js_files'])} JS files, {len(found['external'])} external links")

        if found["js_files"]:
            learn("JavaScript files often contain API endpoints, hardcoded tokens, internal domain names, "
                  "and developer comments. Download and search them: grep -r 'api_key\\|token\\|password\\|secret' *.js")

        return found

    # =========================================================================
    # OPERATION: GOOGLE DORKS
    # =========================================================================

    def op_dork(self) -> Dict:
        """Generate Google dork queries for OSINT."""
        section("GOOGLE DORK GENERATOR")
        learn("Google dorks use advanced search operators to find information that's technically public "
              "but not meant to be easily found. They reveal exposed files, login pages, vulnerable "
              "parameters, and sensitive documents. Use these on Google, Bing, or Shodan. "
              "Always note: finding public data via search engines is not hacking. Accessing systems "
              "you're not authorized for IS. Know the difference.")

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

        learn("Wayback Machine (web.archive.org) stores old versions of websites. "
              "Old versions often have: previously exposed API keys in JS files, "
              "removed but cached admin pages, old subdomains that still resolve. "
              "This is a goldmine for OSINT and bug bounty reconnaissance.")

        return {"dorks": dorks}

    # =========================================================================
    # OPERATION: SSL FULL ANALYSIS
    # =========================================================================

    def op_ssl(self) -> Dict:
        """Full SSL/TLS analysis."""
        section("SSL/TLS DEEP ANALYSIS")
        learn("SSL/TLS protects data in transit. Misconfigurations here affect ALL users silently. "
              "TLS version matters: TLS 1.0/1.1 are deprecated. Weak ciphers can be attacked "
              "with tools like BEAST, POODLE. Certificate issues cause browser warnings. "
              "Use SSLLabs (ssllabs.com/ssltest) for definitive grading.")

        ssl_result = self._ssl_inspect()
        info(f"\nFor comprehensive TLS testing: https://www.ssllabs.com/ssltest/analyze.html?d={self.host}")
        
        # Test HTTP → HTTPS redirect
        if self.scheme == "https":
            http_url = f"http://{self.host}:{self.port if self.port != 443 else 80}"
            resp = self._request(http_url, allow_redirects=False, timeout=5.0)
            if resp:
                if resp["status"] in (301, 302, 307, 308):
                    location = resp["headers"].get("location", "")
                    if "https" in location:
                        ok(f"HTTP → HTTPS redirect: {resp['status']} to {location[:60]}")
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
        learn("A WAF (Web Application Firewall) sits in front of web apps and blocks malicious traffic. "
              "Knowing if one exists changes your testing approach. WAFs look for attack signatures "
              "in requests. We probe with obviously malicious-looking requests and analyze the response. "
              "Cloudflare returns 1020, ModSecurity returns 403 with specific messages, AWS WAF returns 403.")

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

        # Normal request baseline
        baseline = self._request(self.url)
        baseline_status = baseline["status"] if baseline else 0

        # Send attack-like request
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
            info("No WAF signature detected. Site may be unprotected or using a custom WAF.")
            info("Check for rate limiting by sending many requests quickly.")

        if waf_active:
            learn("With a WAF, direct injection payloads will be blocked. Bug bounty hunters use techniques "
                  "like encoding, case variation, comments (/**/, %20, %09), and split payloads to bypass "
                  "signature-based WAFs. Understanding the WAF vendor helps find known bypasses.")

        return {"detected": detected_waf, "waf_active": waf_active}

    # =========================================================================
    # OPERATION: VULNERABILITY SUMMARY / FULL SCAN
    # =========================================================================

    def op_full(self) -> Dict:
        """Run complete security assessment."""
        section("FULL WEB SECURITY ASSESSMENT")
        learn("We'll run a complete assessment covering OSINT, headers, cookies, CORS, common files, "
              "WAF detection, and SSL analysis. Each section teaches you what we're looking for and why. "
              "Take notes on findings - a good report includes: description, impact, reproduction steps, fix.")

        results = {}
        results["recon"] = self.op_recon()
        results["cookies"] = self.op_cookies()
        results["cors"] = self.op_cors()
        results["dirs"] = self.op_dirs()
        results["waf"] = self.op_waf()
        results["ssl"] = self.op_ssl()

        return results

    # =========================================================================
    # OPERATION: KNOWN VULNERABILITY LIBRARY
    # =========================================================================

    def op_vulnlib(self) -> Dict:
        """Display the built-in vulnerability knowledge base."""
        section("VULNERABILITY KNOWLEDGE BASE")
        learn("This library covers the OWASP Top 10 and common web vulnerabilities. "
              "Use it to understand what you're looking for and how to report findings. "
              "Each vulnerability includes: description, impact, fix, and learning context.")

        for key, vuln in VULN_DB.items():
            sev = vuln["severity"]
            color = self._severity_color(sev)
            print(f"\n{color}{BOLD}[{sev}] {vuln['name']}{NC}", file=sys.stderr)
            print(f"  {DIM}CWE: {vuln['cwe']} | {vuln['owasp']}{NC}", file=sys.stderr)
            print(f"  Description: {vuln['description']}", file=sys.stderr)
            print(f"  {R}Impact: {vuln['impact']}{NC}", file=sys.stderr)
            print(f"  {G}Fix: {vuln['fix']}{NC}", file=sys.stderr)
            print(f"  {B}[LEARN] {vuln['learn']}{NC}", file=sys.stderr)

        return {"total_vulns": len(VULN_DB), "categories": list(VULN_DB.keys())}

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
            "vulnlib": self.op_vulnlib,
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
                if f.get("learn"):
                    print(f"  {B}[LEARN] {f['learn']}{NC}", file=sys.stderr)

            counts = {}
            for f in sorted_findings:
                s = f.get("severity", "INFO")
                counts[s] = counts.get(s, 0) + 1

            print(f"\n{BOLD}Total: {len(sorted_findings)} findings{NC}", file=sys.stderr)
            for sev, count in counts.items():
                color = self._severity_color(sev)
                print(f"  {color}{sev}: {count}{NC}", file=sys.stderr)

            learn("When writing your bug bounty report: 1) Describe the vulnerability clearly, "
                  "2) Show step-by-step reproduction, 3) Explain the real-world impact, "
                  "4) Suggest a specific fix. Programs pay more for clear, actionable reports. "
                  "Always follow the program's disclosure policy and scope.")
        else:
            ok("No critical findings detected in this run")
            info("Manual testing is always needed for logic flaws, authentication issues, and business logic bugs")

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
# HELP SYSTEM
# ============================================================================

def show_help():
    print(banner())
    print(f"""
{BOLD}{Y}OPERATIONS:{NC}

  {G}recon{NC}     → Full web OSINT (DNS, WHOIS, SSL, robots, headers, tech stack)
             Ideal starting point. Non-intrusive intelligence gathering.

  {G}headers{NC}   → HTTP security headers audit
             Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options

  {G}cors{NC}      → CORS misconfiguration testing
             Tests if arbitrary origins can access the API

  {G}cookies{NC}   → Cookie security flag audit
             Checks Secure, HttpOnly, SameSite flags

  {G}dirs{NC}      → Directory and sensitive file discovery
             Brute-forces common paths (admin, .env, .git, backups, APIs)

  {G}sqli{NC}      → SQL injection detection (error-based)
             Requires test_url parameter with ?param=value

  {G}xss{NC}       → Reflected XSS detection
             Requires test_url parameter with ?param=value

  {G}spider{NC}    → Web crawler / site mapper
             Discovers all pages, forms, and JS files

  {G}dork{NC}      → Google dork generator for OSINT
             Generates search queries for finding sensitive data

  {G}ssl{NC}       → SSL/TLS deep analysis
             Checks TLS version, ciphers, cert validity, HTTP→HTTPS redirect

  {G}waf{NC}       → WAF detection
             Identifies Cloudflare, ModSecurity, AWS WAF, Akamai, etc.

  {G}full{NC}      → Complete assessment (runs all non-intrusive operations)

  {G}vulnlib{NC}   → Browse the vulnerability knowledge base with explanations

{BOLD}{Y}PARAMETERS:{NC}
  operation      Operation to run (see above)
  test_url       URL with parameters for sqli/xss testing
  threads        Concurrent threads for discovery (default: 10)
  timeout        Request timeout in seconds (default: 10)
  max_pages      Max pages for spider (default: 50)
  wordlist_file  Path to custom wordlist for dirs operation
  verbose        Show verbose output (true/false)

{BOLD}{Y}EXAMPLES:{NC}

  {C}use websec{NC}
  {C}set operation recon{NC}
  {C}run https://example.com{NC}

  {C}set operation dirs{NC}
  {C}run https://example.com{NC}

  {C}set operation sqli{NC}
  {C}set test_url https://example.com/search?q=test{NC}
  {C}run https://example.com{NC}

  {C}set operation full{NC}
  {C}run https://target.com{NC}

{BOLD}{R}⚠  LEGAL DISCLAIMER:{NC}
  Only test systems you own or have explicit written authorization to test.
  Unauthorized testing is illegal under the CFAA, Computer Misuse Act, and similar laws.
  Always read and follow bug bounty program rules and scope before testing.

{BOLD}{Y}LEARNING RESOURCES:{NC}
  PortSwigger Web Security Academy: https://portswigger.net/web-security (FREE)
  OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
  HackTheBox: https://www.hackthebox.com
  Bug Bounty Platforms: HackerOne, Bugcrowd, Intigriti
""")

# ============================================================================
# MAIN
# ============================================================================

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h", "help"):
        show_help()
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
        print(json.dumps(result, indent=2, default=str))
    except KeyboardInterrupt:
        print(json.dumps({"success": False, "errors": ["Interrupted by user"]}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"success": False, "errors": [str(e)]}))
        sys.exit(1)


if __name__ == "__main__":
    main()
