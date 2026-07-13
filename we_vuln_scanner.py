"""
Web Vulnerability Scanner
=========================
Scans websites for common security vulnerabilities and generates a detailed report.

Usage:
    python web_vuln_scanner.py -u https://example.com
    python web_vuln_scanner.py -u https://example.com -o report.html --depth 2
    python web_vuln_scanner.py --help

Checks performed:
    - Missing/weak HTTP security headers
    - SSL/TLS configuration issues
    - Open redirects
    - Reflected XSS (basic detection)
    - SQL Injection probing (error-based, basic)
    - Directory listing exposure
    - Sensitive file/path exposure (.env, .git, backup files, admin panels)
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - Server/technology information disclosure
    - CORS misconfiguration
    - Clickjacking (X-Frame-Options / CSP frame-ancestors)
    - Form analysis (CSRF token presence)

Disclaimer:
    Only scan systems you own or have explicit written permission to test.
    Unauthorized scanning may be illegal.
"""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' library not found. Install it with: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("[!] 'beautifulsoup4' not found. Some checks will be limited. Install: pip install beautifulsoup4")


# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    title: str
    description: str
    url: str
    evidence: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    start_time: str = ""
    end_time: str = ""
    findings: list = field(default_factory=list)
    scanned_urls: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "recommendation": "Define a strict Content-Security-Policy to mitigate XSS and data injection."
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "recommendation": "Add a Permissions-Policy header to restrict browser feature access."
    },
}

SENSITIVE_PATHS = [
    # Version control
    ("/.git/HEAD",              "CRITICAL", "Git repository exposed"),
    ("/.git/config",            "CRITICAL", "Git config exposed"),
    ("/.svn/entries",           "HIGH",     "SVN repository exposed"),
    # Environment / config
    ("/.env",                   "CRITICAL", "Environment file exposed"),
    ("/.env.local",             "CRITICAL", "Environment file exposed"),
    ("/.env.production",        "CRITICAL", "Environment file exposed"),
    ("/config.php",             "HIGH",     "PHP config file exposed"),
    ("/wp-config.php",          "CRITICAL", "WordPress config exposed"),
    ("/configuration.php",      "HIGH",     "CMS config file exposed"),
    ("/config.yml",             "HIGH",     "YAML config exposed"),
    ("/config.yaml",            "HIGH",     "YAML config exposed"),
    ("/database.yml",           "HIGH",     "Database config exposed"),
    # Backups
    ("/backup.zip",             "HIGH",     "Backup archive exposed"),
    ("/backup.tar.gz",          "HIGH",     "Backup archive exposed"),
    ("/db_backup.sql",          "CRITICAL", "Database backup exposed"),
    ("/dump.sql",               "CRITICAL", "Database dump exposed"),
    ("/website.zip",            "HIGH",     "Website backup exposed"),
    # Admin panels
    ("/admin",                  "MEDIUM",   "Admin panel found"),
    ("/admin/",                 "MEDIUM",   "Admin panel found"),
    ("/administrator",          "MEDIUM",   "Admin panel found"),
    ("/wp-admin",               "MEDIUM",   "WordPress admin found"),
    ("/phpmyadmin",             "HIGH",     "phpMyAdmin exposed"),
    ("/pma",                    "HIGH",     "phpMyAdmin exposed"),
    ("/adminer.php",            "HIGH",     "Adminer DB tool exposed"),
    # Logs
    ("/error.log",              "HIGH",     "Error log exposed"),
    ("/access.log",             "HIGH",     "Access log exposed"),
    ("/debug.log",              "MEDIUM",   "Debug log exposed"),
    # Other
    ("/server-status",          "MEDIUM",   "Apache server-status exposed"),
    ("/server-info",            "MEDIUM",   "Apache server-info exposed"),
    ("/robots.txt",             "INFO",     "robots.txt found (check for hidden paths)"),
    ("/sitemap.xml",            "INFO",     "sitemap.xml found"),
    ("/.htpasswd",              "CRITICAL", ".htpasswd file exposed"),
    ("/.htaccess",              "MEDIUM",   ".htaccess file exposed"),
    ("/crossdomain.xml",        "LOW",      "crossdomain.xml found"),
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "1' AND SLEEP(0)--",
    "1; DROP TABLE users--",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"pg_query\(\)",
    r"sqlite3?.*error",
    r"syntax error.*sql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

REDIRECT_PARAMS = ["redirect", "redirect_to", "redirect_url", "return", "return_url",
                   "returnUrl", "next", "url", "goto", "target", "link", "forward"]


# ─────────────────────────────────────────────
# HTTP Helper
# ─────────────────────────────────────────────

class Requester:
    def __init__(self, timeout=10, delay=0.3, verify_ssl=True, proxies=None, user_agent=None):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (compatible; VulnScanner/1.0; +https://github.com/)"
            )
        })
        if proxies:
            self.session.proxies = proxies

    def get(self, url, params=None, allow_redirects=True, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            return self.session.get(url, params=params, timeout=self.timeout,
                                    allow_redirects=allow_redirects, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url, data=None, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            return self.session.post(url, data=data, timeout=self.timeout, **kwargs)
        except requests.RequestException:
            return None


# ─────────────────────────────────────────────
# Individual Check Modules
# ─────────────────────────────────────────────

def check_security_headers(url: str, resp: requests.Response, result: ScanResult):
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            result.findings.append(Finding(
                severity=meta["severity"],
                category="Security Headers",
                title=f"Missing header: {header}",
                description=f"The HTTP response does not include the '{header}' security header.",
                url=url,
                evidence=f"Header absent from response",
                recommendation=meta["recommendation"],
            ))

    # Check HSTS max-age value if present
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age=(\d+)", hsts)
        if match and int(match.group(1)) < 31536000:
            result.findings.append(Finding(
                severity="LOW",
                category="Security Headers",
                title="HSTS max-age too short",
                description="The HSTS max-age is less than 1 year (31536000 seconds).",
                url=url,
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Set max-age to at least 31536000.",
            ))


def check_information_disclosure(url: str, resp: requests.Response, result: ScanResult):
    headers_to_check = ["server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version", "x-generator", "x-drupal-cache"]
    for h in headers_to_check:
        val = resp.headers.get(h)
        if val:
            result.findings.append(Finding(
                severity="LOW",
                category="Information Disclosure",
                title=f"Server technology disclosed via '{h}' header",
                description=f"The response reveals technology/version information.",
                url=url,
                evidence=f"{h}: {val}",
                recommendation=f"Remove or sanitize the '{h}' response header to avoid fingerprinting.",
            ))


def check_ssl(target_url: str, result: ScanResult):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme != "https":
        result.findings.append(Finding(
            severity="HIGH",
            category="SSL/TLS",
            title="Site does not use HTTPS",
            description="The target is served over plain HTTP. All data is transmitted unencrypted.",
            url=target_url,
            recommendation="Migrate to HTTPS and redirect all HTTP traffic.",
        ))
        return

    host = parsed.netloc.split(":")[0]
    port = int(parsed.port or 443)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Check expiry
                expire_str = cert.get("notAfter", "")
                if expire_str:
                    expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_dt - datetime.utcnow()).days
                    if days_left < 0:
                        result.findings.append(Finding(
                            severity="CRITICAL",
                            category="SSL/TLS",
                            title="SSL certificate has expired",
                            description=f"The SSL certificate expired {abs(days_left)} days ago.",
                            url=target_url,
                            evidence=f"notAfter: {expire_str}",
                            recommendation="Renew the SSL certificate immediately.",
                        ))
                    elif days_left < 30:
                        result.findings.append(Finding(
                            severity="HIGH",
                            category="SSL/TLS",
                            title="SSL certificate expiring soon",
                            description=f"The SSL certificate expires in {days_left} days.",
                            url=target_url,
                            evidence=f"notAfter: {expire_str}",
                            recommendation="Renew the SSL certificate before it expires.",
                        ))

                # Weak cipher
                if cipher and cipher[0]:
                    if any(w in cipher[0].upper() for w in ["RC4", "DES", "NULL", "EXPORT", "MD5"]):
                        result.findings.append(Finding(
                            severity="HIGH",
                            category="SSL/TLS",
                            title=f"Weak cipher suite in use: {cipher[0]}",
                            description="The server is using a known-weak cipher suite.",
                            url=target_url,
                            evidence=f"Cipher: {cipher}",
                            recommendation="Disable weak ciphers and use TLS 1.2+ with strong suites.",
                        ))

    except ssl.SSLCertVerificationError as e:
        result.findings.append(Finding(
            severity="HIGH",
            category="SSL/TLS",
            title="SSL certificate validation failed",
            description="The server's SSL certificate could not be verified.",
            url=target_url,
            evidence=str(e),
            recommendation="Install a valid, trusted SSL certificate.",
        ))
    except Exception:
        pass  # SSL check not possible, skip silently


def check_cookies(url: str, resp: requests.Response, result: ScanResult):
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        samesite = cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            issues.append("missing SameSite attribute")
        elif samesite.lower() == "none" and not cookie.secure:
            issues.append("SameSite=None without Secure flag")

        if issues:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Cookie Security",
                title=f"Insecure cookie: {cookie.name}",
                description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}.",
                url=url,
                evidence=f"Cookie: {cookie.name}={cookie.value[:10]}... | Issues: {', '.join(issues)}",
                recommendation="Set Secure, HttpOnly, and SameSite=Strict (or Lax) on all cookies.",
            ))


def check_cors(url: str, requester: Requester, result: ScanResult):
    evil_origin = "https://evil.com"
    resp = requester.get(url, headers={"Origin": evil_origin})
    if resp is None:
        return
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        result.findings.append(Finding(
            severity="HIGH",
            category="CORS",
            title="CORS wildcard with credentials allowed",
            description="The server allows any origin AND credentials — this is a dangerous misconfiguration.",
            url=url,
            evidence=f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
            recommendation="Never combine Access-Control-Allow-Origin: * with credentials. Whitelist specific trusted origins.",
        ))
    elif acao == evil_origin:
        sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
        result.findings.append(Finding(
            severity=sev,
            category="CORS",
            title="CORS policy reflects arbitrary origin",
            description=f"The server reflects untrusted origins in Access-Control-Allow-Origin.",
            url=url,
            evidence=f"Sent Origin: {evil_origin} | Got: Access-Control-Allow-Origin: {acao}",
            recommendation="Validate and whitelist allowed origins. Do not reflect arbitrary values.",
        ))


def check_clickjacking(url: str, resp: requests.Response, result: ScanResult):
    xfo = resp.headers.get("X-Frame-Options", "")
    csp = resp.headers.get("Content-Security-Policy", "")
    has_frame_protection = (
        xfo.upper() in ("DENY", "SAMEORIGIN") or
        "frame-ancestors" in csp.lower()
    )
    if not has_frame_protection:
        result.findings.append(Finding(
            severity="MEDIUM",
            category="Clickjacking",
            title="Page can be embedded in an iframe (clickjacking risk)",
            description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
            url=url,
            recommendation="Set X-Frame-Options: DENY or add 'frame-ancestors' to your CSP.",
        ))


def check_sensitive_paths(base_url: str, requester: Requester, result: ScanResult):
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    def probe(path_info):
        path, severity, label = path_info
        url = base + path
        resp = requester.get(url, allow_redirects=False)
        if resp is not None and resp.status_code in (200, 206):
            result.findings.append(Finding(
                severity=severity,
                category="Sensitive File/Path Exposure",
                title=label,
                description=f"The path '{path}' is publicly accessible.",
                url=url,
                evidence=f"HTTP {resp.status_code} | Content-Length: {len(resp.content)} bytes",
                recommendation=f"Restrict access to '{path}' or remove the file from the server.",
            ))
            result.scanned_urls.append(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        ex.map(probe, SENSITIVE_PATHS)


def check_directory_listing(base_url: str, requester: Requester, result: ScanResult):
    test_paths = ["/images/", "/uploads/", "/static/", "/assets/", "/files/", "/backup/"]
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in test_paths:
        url = base + path
        resp = requester.get(url)
        if resp and resp.status_code == 200:
            lower = resp.text.lower()
            if "index of" in lower or "parent directory" in lower:
                result.findings.append(Finding(
                    severity="MEDIUM",
                    category="Directory Listing",
                    title=f"Directory listing enabled at {path}",
                    description="The web server is configured to list directory contents.",
                    url=url,
                    evidence=f"Response contains 'Index of' or 'Parent Directory'",
                    recommendation="Disable directory listing in your web server configuration.",
                ))


def check_xss(url: str, requester: Requester, result: ScanResult):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            resp = requester.get(url, params=test_params)
            if resp and payload in resp.text:
                result.findings.append(Finding(
                    severity="HIGH",
                    category="Cross-Site Scripting (XSS)",
                    title=f"Potential reflected XSS in parameter: {param}",
                    description=(
                        f"The parameter '{param}' reflects the payload unescaped in the response, "
                        "indicating a potential reflected XSS vulnerability."
                    ),
                    url=url,
                    evidence=f"Payload: {payload} | Parameter: {param}",
                    recommendation="Encode all user-supplied output. Use a Content-Security-Policy. Validate input server-side.",
                ))
                break  # One finding per param is enough


def check_sqli(url: str, requester: Requester, result: ScanResult):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = test_params[param] + payload
            resp = requester.get(url, params=test_params)
            if resp:
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        result.findings.append(Finding(
                            severity="CRITICAL",
                            category="SQL Injection",
                            title=f"Potential SQL Injection in parameter: {param}",
                            description=(
                                f"The parameter '{param}' triggered a SQL error message when injected "
                                "with a malicious payload. This strongly suggests SQL injection."
                            ),
                            url=url,
                            evidence=f"Payload: {payload} | DB error pattern matched: {pattern}",
                            recommendation=(
                                "Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL strings."
                            ),
                        ))
                        break


def check_open_redirect(url: str, requester: Requester, result: ScanResult):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    redirect_params_found = [p for p in params if p.lower() in REDIRECT_PARAMS]
    for param in redirect_params_found:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            resp = requester.get(url, params=test_params, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    result.findings.append(Finding(
                        severity="HIGH",
                        category="Open Redirect",
                        title=f"Open redirect via parameter: {param}",
                        description=f"The parameter '{param}' allows redirecting users to arbitrary external URLs.",
                        url=url,
                        evidence=f"Payload: {payload} | Location: {location}",
                        recommendation="Validate and whitelist redirect destinations. Reject external URLs.",
                    ))
                    break


def check_forms_csrf(url: str, resp: requests.Response, result: ScanResult):
    if not BS4_AVAILABLE:
        return
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return

    forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")
    for form in forms:
        inputs = form.find_all("input")
        has_csrf = any(
            (i.get("name", "").lower() in ("csrf_token", "csrftoken", "_token",
                                            "authenticity_token", "__requestverificationtoken")
             or i.get("type", "").lower() == "hidden")
            for i in inputs
        )
        if not has_csrf:
            action = form.get("action", url)
            result.findings.append(Finding(
                severity="MEDIUM",
                category="CSRF",
                title="POST form without apparent CSRF token",
                description="A POST form was found with no visible CSRF protection token.",
                url=url,
                evidence=f"Form action: {action}",
                recommendation="Add a CSRF token to all state-changing forms and validate it server-side.",
            ))


def crawl_links(url: str, resp: requests.Response, base_url: str) -> list:
    """Extract same-origin links from a page."""
    if not BS4_AVAILABLE:
        return []
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return []

    parsed_base = urllib.parse.urlparse(base_url)
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full = urllib.parse.urljoin(url, href)
        parsed = urllib.parse.urlparse(full)
        if parsed.netloc == parsed_base.netloc and parsed.scheme in ("http", "https"):
            links.add(full)
    return list(links)


# ─────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────

class Scanner:
    def __init__(self, target: str, depth: int = 1, timeout: int = 10,
                 delay: float = 0.3, verify_ssl: bool = True, threads: int = 5,
                 proxy: str = None, user_agent: str = None):
        self.target = target.rstrip("/")
        self.depth = depth
        self.threads = threads
        self.result = ScanResult(target=self.target)
        proxies = {"http": proxy, "https": proxy} if proxy else None
        self.req = Requester(timeout=timeout, delay=delay, verify_ssl=verify_ssl,
                             proxies=proxies, user_agent=user_agent)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{ts}] {msg}")

    def run(self) -> ScanResult:
        self.result.start_time = datetime.now().isoformat()
        print(f"\n{'='*60}")
        print(f"  Web Vulnerability Scanner")
        print(f"  Target : {self.target}")
        print(f"  Depth  : {self.depth}")
        print(f"  Time   : {self.result.start_time}")
        print(f"{'='*60}\n")

        # SSL check (global)
        self.log("Checking SSL/TLS configuration...")
        check_ssl(self.target, self.result)

        # Sensitive path scan (global, once per host)
        self.log("Scanning for sensitive paths and files...")
        check_sensitive_paths(self.target, self.req, self.result)

        # Directory listing
        self.log("Checking for directory listing...")
        check_directory_listing(self.target, self.req, self.result)

        # CORS check
        self.log("Checking CORS policy...")
        check_cors(self.target, self.req, self.result)

        # Crawl & per-page checks
        visited = set()
        queue = [self.target]

        for current_depth in range(self.depth):
            next_queue = []
            for url in queue:
                if url in visited:
                    continue
                visited.add(url)
                self.result.scanned_urls.append(url)
                self.log(f"Scanning page: {url}")

                resp = self.req.get(url)
                if resp is None:
                    self.result.errors.append(f"Could not reach: {url}")
                    continue

                check_security_headers(url, resp, self.result)
                check_information_disclosure(url, resp, self.result)
                check_cookies(url, resp, self.result)
                check_clickjacking(url, resp, self.result)
                check_xss(url, self.req, self.result)
                check_sqli(url, self.req, self.result)
                check_open_redirect(url, self.req, self.result)
                check_forms_csrf(url, resp, self.result)

                # Queue links for next depth
                if current_depth < self.depth - 1:
                    links = crawl_links(url, resp, self.target)
                    next_queue.extend(links)

            queue = list(set(next_queue) - visited)

        self.result.end_time = datetime.now().isoformat()
        return self.result


# ─────────────────────────────────────────────
# Report Generation
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#3498db",
    "INFO":     "#95a5a6",
}

SEVERITY_BG = {
    "CRITICAL": "#fdecea",
    "HIGH":     "#fef5ec",
    "MEDIUM":   "#fefde7",
    "LOW":      "#ebf5fb",
    "INFO":     "#f8f9f9",
}


def generate_html_report(result: ScanResult, output_path: str):
    findings_sorted = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    counts = defaultdict(int)
    for f in result.findings:
        counts[f.severity] += 1

    finding_rows = ""
    for i, f in enumerate(findings_sorted, 1):
        color = SEVERITY_COLORS.get(f.severity, "#999")
        bg = SEVERITY_BG.get(f.severity, "#fff")
        finding_rows += f"""
        <div class="finding" style="border-left: 4px solid {color}; background:{bg};">
          <div class="finding-header">
            <span class="badge" style="background:{color};">{f.severity}</span>
            <span class="finding-title">{f.title}</span>
            <span class="category-tag">{f.category}</span>
          </div>
          <div class="finding-body">
            <p><strong>URL:</strong> <code>{f.url}</code></p>
            <p><strong>Description:</strong> {f.description}</p>
            {"<p><strong>Evidence:</strong> <code>" + f.evidence + "</code></p>" if f.evidence else ""}
            {"<p><strong>Recommendation:</strong> " + f.recommendation + "</p>" if f.recommendation else ""}
          </div>
        </div>"""

    scanned_list = "".join(f"<li><code>{u}</code></li>" for u in result.scanned_urls)
    error_list = "".join(f"<li>{e}</li>" for e in result.errors) or "<li>None</li>"

    summary_bars = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        summary_bars += f"""
        <div class="summary-item">
          <span class="summary-label" style="color:{color}">{sev}</span>
          <div class="summary-bar-wrap">
            <div class="summary-bar" style="width:{min(c*30, 300)}px; background:{color};"></div>
            <span class="summary-count">{c}</span>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Scan Report — {result.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f6f8; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #1a252f 0%, #2c3e50 100%); color: white; padding: 40px 60px; }}
  .header h1 {{ font-size: 2rem; font-weight: 700; letter-spacing: -0.5px; }}
  .header .subtitle {{ opacity: 0.75; margin-top: 6px; font-size: 0.95rem; }}
  .container {{ max-width: 1100px; margin: 40px auto; padding: 0 20px; }}
  .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 28px; overflow: hidden; }}
  .card-title {{ font-size: 1.1rem; font-weight: 600; padding: 18px 24px; border-bottom: 1px solid #eee; color: #34495e; }}
  .card-body {{ padding: 24px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }}
  .meta-item label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; color: #7f8c8d; }}
  .meta-item p {{ font-size: 0.95rem; font-weight: 500; margin-top: 4px; word-break: break-all; }}
  .summary-item {{ display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }}
  .summary-label {{ width: 75px; font-weight: 700; font-size: 0.85rem; }}
  .summary-bar-wrap {{ display: flex; align-items: center; gap: 8px; }}
  .summary-bar {{ height: 16px; border-radius: 3px; transition: width 0.4s; }}
  .summary-count {{ font-weight: 600; font-size: 0.9rem; }}
  .finding {{ border-radius: 6px; margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; padding: 12px 16px; flex-wrap: wrap; }}
  .badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; color: white; }}
  .finding-title {{ font-weight: 600; font-size: 0.97rem; flex: 1; }}
  .category-tag {{ font-size: 0.78rem; color: #7f8c8d; border: 1px solid #ddd; padding: 2px 8px; border-radius: 12px; }}
  .finding-body {{ padding: 12px 16px 16px; font-size: 0.9rem; line-height: 1.7; }}
  .finding-body p {{ margin-bottom: 6px; }}
  code {{ background: rgba(0,0,0,0.06); padding: 1px 5px; border-radius: 3px; font-family: monospace; font-size: 0.85em; word-break: break-all; }}
  ul {{ padding-left: 20px; line-height: 2; }}
  .no-findings {{ text-align: center; padding: 40px; color: #27ae60; font-size: 1.1rem; font-weight: 600; }}
  .footer {{ text-align: center; padding: 30px; color: #7f8c8d; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔒 Vulnerability Scan Report</h1>
  <div class="subtitle">Generated by Web Vulnerability Scanner &mdash; For authorized testing only</div>
</div>
<div class="container">

  <div class="card">
    <div class="card-title">📋 Scan Summary</div>
    <div class="card-body">
      <div class="meta-grid">
        <div class="meta-item"><label>Target</label><p>{result.target}</p></div>
        <div class="meta-item"><label>Started</label><p>{result.start_time}</p></div>
        <div class="meta-item"><label>Finished</label><p>{result.end_time}</p></div>
        <div class="meta-item"><label>Pages Scanned</label><p>{len(result.scanned_urls)}</p></div>
        <div class="meta-item"><label>Total Findings</label><p>{len(result.findings)}</p></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">📊 Findings by Severity</div>
    <div class="card-body">{summary_bars}</div>
  </div>

  <div class="card">
    <div class="card-title">🔍 Findings ({len(result.findings)})</div>
    <div class="card-body">
      {"".join([finding_rows]) if findings_sorted else '<div class="no-findings">✅ No vulnerabilities detected!</div>'}
    </div>
  </div>

  <div class="card">
    <div class="card-title">🌐 Scanned URLs</div>
    <div class="card-body"><ul>{scanned_list}</ul></div>
  </div>

  <div class="card">
    <div class="card-title">⚠️ Errors</div>
    <div class="card-body"><ul>{error_list}</ul></div>
  </div>

</div>
<div class="footer">
  ⚠️ This tool is for authorized security testing only. Unauthorized scanning is illegal.<br>
  Web Vulnerability Scanner &mdash; {datetime.now().year}
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  [✓] HTML report saved: {output_path}")


def generate_json_report(result: ScanResult, output_path: str):
    data = {
        "target": result.target,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "scanned_urls": result.scanned_urls,
        "errors": result.errors,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "url": f.url,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
        ],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"  [✓] JSON report saved: {output_path}")


def print_console_report(result: ScanResult):
    COLORS = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[33m",
        "LOW":      "\033[94m",
        "INFO":     "\033[37m",
        "RESET":    "\033[0m",
        "BOLD":     "\033[1m",
        "GREEN":    "\033[92m",
    }

    print(f"\n{COLORS['BOLD']}{'─'*60}")
    print(f"  SCAN RESULTS — {result.target}")
    print(f"{'─'*60}{COLORS['RESET']}\n")

    findings_sorted = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    if not findings_sorted:
        print(f"  {COLORS['GREEN']}✅ No vulnerabilities found!{COLORS['RESET']}\n")
    else:
        for f in findings_sorted:
            c = COLORS.get(f.severity, "")
            print(f"  {c}[{f.severity}]{COLORS['RESET']} {f.title}")
            print(f"         Category : {f.category}")
            print(f"         URL      : {f.url}")
            if f.evidence:
                print(f"         Evidence : {f.evidence}")
            if f.recommendation:
                print(f"         Fix      : {f.recommendation}")
            print()

    counts = defaultdict(int)
    for f in result.findings:
        counts[f.severity] += 1

    print(f"  {COLORS['BOLD']}Summary:{COLORS['RESET']}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        col = COLORS.get(sev, "")
        print(f"    {col}{sev:10}{COLORS['RESET']} : {c}")

    print(f"\n  Pages scanned : {len(result.scanned_urls)}")
    print(f"  Duration      : {result.start_time} → {result.end_time}")


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — scan a website for common security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_vuln_scanner.py -u https://example.com
  python web_vuln_scanner.py -u https://example.com --depth 2 -o report.html
  python web_vuln_scanner.py -u https://example.com --json results.json --no-ssl-verify
  python web_vuln_scanner.py -u https://example.com --delay 1.0 --timeout 15

⚠️  Only scan systems you own or have explicit written permission to test.
        """
    )

    parser.add_argument("-u", "--url",      required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output",   default="scan_report.html", help="HTML report output path (default: scan_report.html)")
    parser.add_argument("--json",           default=None,  help="Also save a JSON report to this path")
    parser.add_argument("--depth",          type=int, default=1, help="Crawl depth (default: 1, max recommended: 3)")
    parser.add_argument("--timeout",        type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay",          type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--threads",        type=int, default=5, help="Concurrent threads for path scanning (default: 5)")
    parser.add_argument("--no-ssl-verify",  action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--proxy",          default=None, help="HTTP/S proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent",     default=None, help="Custom User-Agent string")

    args = parser.parse_args()

    # Ensure URL has scheme
    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    scanner = Scanner(
        target=args.url,
        depth=args.depth,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not args.no_ssl_verify,
        threads=args.threads,
        proxy=args.proxy,
        user_agent=args.user_agent,
    )

    result = scanner.run()
    print_console_report(result)
    generate_html_report(result, args.output)
    if args.json:
        generate_json_report(result, args.json)


if __name__ == "__main__":
    main()
