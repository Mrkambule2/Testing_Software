#!/usr/bin/env python3
"""
VulnCheck Lite - Defensive Website Security Scanner
===================================================
Runs from a USB drive. PIN-protected. Performs ONLY passive/read-only
GET requests (headers, TLS info, public file checks) - no attacks,
no brute force, no destructive actions.

Usage:  python scan_tool.py   (or double-click run.bat)
Report: vuln_report_YYYYMMDD_HHMMSS.txt in the same folder
"""

import sys
import os
import re
import ssl
import json
import socket
import urllib.request
import urllib.error
import urllib.parse
import http.client
import concurrent.futures
import ipaddress
import subprocess
import random
import time
from datetime import datetime

CORRECT_PIN = "0012246060086"
TIMEOUT = 8
USER_AGENT = "VulnCheck-Lite/1.0 (defensive security audit)"

# Sensitive paths checked with read-only GET requests.
# Finding these exposed is a common, serious misconfiguration.
SENSITIVE_PATHS = [
    # Version control / repo leaks
    "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore",
    "/.svn/entries", "/.hg/hgrc", "/.bzr/README",
    # Env / config / credentials
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup",
    "/.npmrc", "/.pypirc", "/.netrc", "/.htpasswd", "/.htaccess",
    "/config.php", "/config.php~", "/config.php.bak", "/config.yml", "/config.yaml",
    "/config.json", "/config.js", "/appsettings.json", "/web.config",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.swp",
    "/wp-config.bak", "/wp-config.txt", "/settings.py",
    # Database dumps / backups
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
    "/dump.sql", "/mysql.sql", "/site.sql", "/data.sql", "/db_backup.sql",
    "/backup/", "/backups/", "/old/", "/test/",
    # Info / status / admin panels
    "/server-status", "/server-info", "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/administrator/", "/adminer.php", "/phpmyadmin/", "/pma/",
    "/wp-admin/", "/wp-login.php", "/user/login",
    # API docs / debug
    "/api-docs", "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/api/swagger.json", "/graphql", "/graphiql", "/actuator", "/actuator/env",
    "/actuator/health", "/actuator/heapdump", "/trace", "/debug/", "/elmah.axd",
    # Cloud / infra
    "/.dockerenv", "/docker-compose.yml", "/Dockerfile", "/.aws/credentials",
    "/.ssh/id_rsa", "/id_rsa", "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Common misc
    "/.DS_Store", "/Thumbs.db", "/package.json", "/composer.json", "/yarn.lock",
    "/package-lock.json", "/README.md", "/CHANGELOG.md",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/humans.txt", "/ads.txt", "/app-ads.txt",
]

# Directories checked for enabled directory listing.
EXTRA_DIRS = ["/assets/", "/images/", "/img/", "/uploads/", "/files/", "/static/",
              "/backup/", "/backups/", "/admin/", "/test/", "/old/", "/tmp/", "/logs/"]

MAX_LINKED_FILES = 15

# Ports checked with a single TCP connect each (no login attempts).
DB_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8443: "HTTPS-alt", 8888: "HTTP-alt2", 9000: "Portainer?", 9090: "Prometheus?",
    9200: "Elasticsearch", 9300: "ES-transport", 11211: "Memcached", 27017: "MongoDB",
}

# Extended port list for IP/device targets: all well-known ports (1-1024)
# plus common high ports. Used automatically when target is an IP address.
_EXTRA_PORT_NAMES = {
    53: "DNS", 80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-sub", 873: "Rsync", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1434: "MSSQL-UDP?",
    1723: "PPTP", 1900: "UPnP", 2049: "NFS", 2376: "Docker-TLS",
    3000: "Dev-HTTP", 3128: "Squid-proxy", 3260: "iSCSI", 4444: "Metasploit?",
    5000: "Dev-HTTP2", 5060: "SIP", 5353: "mDNS", 5555: "ADB?",
    5672: "RabbitMQ", 5901: "VNC2", 5984: "CouchDB", 6000: "X11",
    6667: "IRC", 7001: "WebLogic", 8008: "HTTP-alt3", 8009: "AJP",
    8081: "HTTP-alt4", 8086: "Docker", 8088: "HTTP-alt5", 8089: "Splunk?",
    8090: "HTTP-alt6", 8444: "HTTPS-alt2", 8880: "HTTP-alt7", 9001: "Portainer/Hyper-V",
    9042: "Cassandra", 9091: "Prometheus-alt", 9100: "Printer/JetDirect",
    9418: "Git", 9999: "Unknown-svc", 10000: "Webmin", 11211: "Memcached",
    15672: "RabbitMQ-mgmt", 18080: "HTTP-alt8", 27018: "MongoDB2",
    27019: "MongoDB3", 28017: "MongoDB-web", 50000: "SAP/DB2?",
    50070: "Hadoop-Namenode", 61616: "ActiveMQ", 61613: "ActiveMQ-stomp",
}
EXTENDED_PORTS = dict(DB_PORTS)
for _p in range(1, 1025):
    EXTENDED_PORTS.setdefault(_p, _EXTRA_PORT_NAMES.get(_p, "svc" + str(_p)))
for _p, _n in _EXTRA_PORT_NAMES.items():
    EXTENDED_PORTS.setdefault(_p, _n)


def is_ip_target(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except (ValueError, AttributeError):
        return False

# Security headers that should be present
RECOMMENDED_HEADERS = {
    "strict-transport-security": "HSTS - forces HTTPS, prevents downgrade attacks",
    "content-security-policy": "CSP - mitigates XSS",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "Prevents MIME-sniffing",
    "referrer-policy": "Controls referrer leakage",
    "permissions-policy": "Restricts browser features",
}

SECURITY_RE = [
    (r"BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY", "private key material"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}", "GitHub token"),
    (r"glpat-[0-9A-Za-z_\-]{20}", "GitLab token"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token"),
    (r"[sr]k_live_[0-9A-Za-z]{16,}", "Stripe live key"),
    (r"SG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}", "SendGrid API key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT token"),
    (r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)['\"\s]*[:=]['\"\s]*[0-9A-Za-z_\-]{16,}", "hardcoded API key/token"),
    (r"(?i)password\s*[:=]['\"\s]*[^'\"\s]{6,}", "hardcoded password"),
    (r"(?i)secret\s*[:=]['\"\s]*[^'\"\s]{6,}", "secret value"),
    (r"aws_access_key_id", "AWS access key"),
    (r"-----BEGIN CERTIFICATE-----", "certificate block"),
    (r"(mongodb(\+srv)?|mysql|postgres(ql)?|redis|mssql|sqlserver)://[^/\s'\"]+:[^@\s'\"]+@", "database connection string with credentials"),
]


def banner():
    print("=" * 64)
    print("  VulnCheck Lite - Defensive Website Security Scanner")
    print("  Read-only audit. No attacks, no destructive actions.")
    print("=" * 64)


class Progress:
    """Green ASCII progress bar (0-100%)."""
    WIDTH = 40

    def __init__(self, total):
        self.total = max(1, total)
        self.done = 0
        self.use_color = sys.stdout.isatty()

    def update(self, label=""):
        self.done += 1
        pct = min(100, int(self.done / self.total * 100))
        filled = int(self.WIDTH * pct / 100)
        bar = "\u2588" * filled + "\u2591" * (self.WIDTH - filled)
        if self.use_color:
            sys.stdout.write(f"\r\x1b[92m|{bar}|\x1b[0m {pct:3d}%  {label[:45]}")
        else:
            sys.stdout.write(f"\r|{bar}| {pct:3d}%  {label[:45]}")
        sys.stdout.flush()

    def finish(self):
        if self.use_color:
            sys.stdout.write(f"\r\x1b[92m|{'\u2588' * self.WIDTH}|\x1b[0m 100%  done\n")
        else:
            sys.stdout.write(f"\r|{'\u2588' * self.WIDTH}| 100%  done\n")
        sys.stdout.flush()


def add_finding(findings, severity, message, detail=""):
    if detail:
        message = f"{message} - {detail}"
    findings.append((severity, message))


def check_pin():
    pin = input("\nEnter PIN to continue: ").strip()
    if pin != CORRECT_PIN:
        print("\n[!] Incorrect PIN. Access denied.")
        sys.exit(1)
    print("[+] PIN accepted.\n")


def normalize_url(raw):
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", "")), parsed


def get_opener():
    ctx = ssl.create_default_context()
    # We are auditing, not attacking - accept any cert so we can still report on it.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def fetch(url, opener, method="GET", max_bytes=200_000):
    """Single read-only request. Returns (status, headers, body_bytes) or raises."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    with opener.open(req, timeout=TIMEOUT) as resp:
        body = resp.read(max_bytes)
        return resp.status, dict(resp.headers.items()), body


def check_tls(parsed, findings, info):
    """TLS version and cipher used by the server."""
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme != "https":
        add_finding(findings,"HIGH", "Site served over plain HTTP - traffic (incl. credentials) can be intercepted.")
        return
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                cert = ssock.getpeercert(binary_form=False)
                info.append(f"TLS version : {version}")
                info.append(f"Cipher       : {cipher[0]} ({cipher[2]} bits)" if cipher else "Cipher       : unknown")
                if cipher and cipher[2] and cipher[2] < 128:
                    add_finding(findings,"HIGH", f"Weak cipher in use: {cipher[0]} ({cipher[2]}-bit).")
                if version in ("SSLv3", "TLSv1", "TLSv1.1"):
                    add_finding(findings,"HIGH", f"Deprecated TLS version in use: {version}.")
    except Exception as e:
        info.append(f"TLS check failed: {e}")


def check_cert_validity(parsed):
    """Check certificate validity period (dates only, read-only)."""
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "unknown")
                return f"Certificate expires: {not_after}"
    except Exception as e:
        return f"Certificate check failed: {e} (possibly self-signed or invalid)"


def scan_headers(url, opener, findings, info):
    try:
        status, headers, body = fetch(url, opener)
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers.items()), e.read(200_000)
    except Exception as e:
        add_finding(findings,"HIGH", f"Could not reach target: {e}")
        return None, None, None

    info.append(f"HTTP status  : {status}")
    server = headers.get("Server") or headers.get("server")
    if server:
        info.append(f"Server banner: {server}")
        add_finding(findings,"LOW", f"Server version disclosed via header: {server} (helps attackers fingerprint the stack).")
    powered = headers.get("X-Powered-By")
    if powered:
        add_finding(findings,"LOW", f"Technology disclosed via X-Powered-By: {powered}")

    h_lower = {k.lower(): v for k, v in headers.items()}
    for hdr, desc in RECOMMENDED_HEADERS.items():
        if hdr not in h_lower:
            add_finding(findings,"MEDIUM", f"Missing security header '{hdr}' - {desc}")

    # HSTS specifics
    hsts = h_lower.get("strict-transport-security")
    if hsts and "max-age" in hsts.lower():
        try:
            max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
            if max_age < 15552000:
                add_finding(findings,"LOW", f"HSTS max-age is only {max_age}s (recommended >= 15552000 / 6 months).")
        except ValueError:
            pass

    # Cookies
    cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for c in cookies:
        cl = c.lower()
        if "secure" not in cl:
            add_finding(findings,"MEDIUM", "Cookie set without 'Secure' flag - can be sent over HTTP.")
        if "httponly" not in cl:
            add_finding(findings,"MEDIUM", "Cookie set without 'HttpOnly' flag - readable by JavaScript (XSS risk).")
        if "samesite" not in cl:
            add_finding(findings,"LOW", "Cookie set without 'SameSite' attribute - CSRF risk.")
        break  # one representative finding is enough

    return status, headers, body


TEXT_FILE_PATHS = ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
                   "/.well-known/security.txt", "/humans.txt", "/ads.txt", "/app-ads.txt")

# Paths that almost always indicate a real exposure if they return 200.
HIGH_VALUE_PATHS = {
    "/.git/HEAD", "/.git/config", "/.git/index", "/.env", "/.env.local",
    "/.env.production", "/.env.backup", "/.svn/entries", "/.hg/hgrc",
    "/.npmrc", "/.pypirc", "/.netrc", "/.htpasswd", "/config.php",
    "/config.php~", "/config.php.bak", "/config.yml", "/config.yaml",
    "/config.json", "/appsettings.json", "/web.config",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.bak",
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
    "/dump.sql", "/mysql.sql", "/data.sql", "/db_backup.sql",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/adminer.php", "/phpmyadmin/", "/pma/", "/actuator", "/actuator/env",
    "/actuator/heapdump", "/elmah.axd", "/.dockerenv", "/docker-compose.yml",
    "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa",
}


def scan_sensitive_paths(base_url, opener, findings, info, progress,
                         homepage_body=b"", dbfp=None):
    """Probe SENSITIVE_PATHS in parallel (read-only GET), update progress per path."""
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    def probe(path):
        url = root + path
        try:
            status, headers, body = fetch(url, opener, max_bytes=100_000)
            return path, status, body
        except urllib.error.HTTPError as e:
            body = b""
            if e.code == 200:
                try:
                    body = e.read(100_000)
                except Exception:
                    pass
            return path, e.code, body
        except Exception:
            return path, None, b""

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(probe, p): p for p in SENSITIVE_PATHS}
        for fut in concurrent.futures.as_completed(futures):
            path, status, body = fut.result()
            try:
                if status == 200 and body:
                    # SPA/catch-all fallback: identical body to homepage = not a real file
                    if homepage_body and body == homepage_body[:len(body)]:
                        pass
                    else:
                        content = body[:50_000].decode("utf-8", errors="ignore")
                        if dbfp is not None:
                            dbfp.update(find_db_fingerprints(content))
                        # Skip custom 404/soft-404 pages that return 200 with HTML
                        looks_html = "<html" in content[:300].lower() or "<!doctype" in content[:300].lower()
                        if looks_html and path not in TEXT_FILE_PATHS and not path.endswith("/"):
                            pass  # likely a SPA fallback page, not the real file
                        else:
                            is_sensitive = path in HIGH_VALUE_PATHS
                            severity = "HIGH" if is_sensitive else "INFO"
                            add_finding(findings, severity,
                                        f"Publicly accessible: {path} (HTTP {status})"
                                        + (" - SENSITIVE FILE EXPOSED!" if is_sensitive else ""))
                            # Scan body for leaked secrets
                            for pattern, label in SECURITY_RE:
                                if re.search(pattern, content, re.IGNORECASE):
                                    add_finding(findings, "CRITICAL",
                                                f"Possible {label} found in response of {path} - review and rotate!")
                                    break
                elif status in (401, 403):
                    pass  # protected - good, no finding needed
            finally:
                progress.update(f"path {path}")


def extract_links(html, base):
    """Same-origin .js/.css/.json/.map/html links from a page."""
    links = []
    for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html, re.I):
        u = urllib.parse.urljoin(base, m.group(1))
        p = urllib.parse.urlsplit(u)
        if p.netloc == urllib.parse.urlsplit(base).netloc and \
           re.search(r"\.(js|mjs|css|json|map|html?|txt)(\?|$)", p.path, re.I):
            links.append(u.split("#")[0])
    seen, out = set(), []
    for l in links:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out


def scan_linked_files(base_url, opener, homepage_body, links, findings, info, progress):
    """Fetch public JS/CSS/JSON/HTML files and scan them for leaked secrets."""
    items = [(base_url, homepage_body)] + [(u, None) for u in links]
    email_set = set()
    secrets_hit = 0
    db_string_hits = 0
    public_chunks = []
    for url, cached in items:
        label = urllib.parse.urlsplit(url).path or "/"
        try:
            if cached is not None:
                status, headers, body = 200, {}, cached
            else:
                status, headers, body = fetch(url, opener, max_bytes=1_000_000)
        except Exception:
            progress.update(f"file {label}")
            continue
        try:
            if status == 200 and body:
                # SPA fallback returns homepage HTML for missing files - skip those
                if cached is None and homepage_body and \
                        body == homepage_body[:len(body)]:
                    pass
                else:
                    text = body[:500_000].decode("utf-8", errors="ignore")
                    public_chunks.append(text)
                    if label.lower().split("?")[0].endswith(".map"):
                        add_finding(findings, "LOW",
                                    f"JavaScript source map publicly accessible: {url}",
                                    "Source maps can reveal original source code - confirm this is intentional.")
                    for pattern, plabel in SECURITY_RE:
                        m = re.search(pattern, text, re.IGNORECASE)
                        if m:
                            snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 50):m.end() + 50])[:180]
                            add_finding(findings, "CRITICAL",
                                        f"Possible {plabel} exposed in public file: {url}")
                            info.append(f"      context: {snippet}")
                            secrets_hit += 1
                            if "database connection" in plabel.lower():
                                db_string_hits += 1
                            break
                    email_set.update(re.findall(
                        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
        finally:
            progress.update(f"file {label}")
    info.append(f"Public file scan: {len(items)} page(s)/file(s) checked, "
                f"{secrets_hit} secret pattern hit(s).")
    if email_set:
        sample = ", ".join(sorted(email_set)[:5])
        info.append(f"Email addresses visible in public files: {len(email_set)} (e.g. {sample})")
    return {"text": "".join(public_chunks)[:1_000_000],
            "secret_hits": secrets_hit,
            "db_string_hits": db_string_hits}


def check_cors(base_url, opener, findings, info, progress):
    """Send Origin header and inspect Access-Control-* response (read-only GET)."""
    parsed = urllib.parse.urlparse(base_url)
    url = f"{parsed.scheme}://{parsed.netloc}/"
    evil = "https://cors-probe.example.com"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT, "Origin": evil})
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        except urllib.error.HTTPError as e:
            acao = e.headers.get("Access-Control-Allow-Origin", "") if e.headers else ""
            acac = e.headers.get("Access-Control-Allow-Credentials", "") if e.headers else ""
    except Exception:
        progress.update("CORS check")
        return
    if acao == "*":
        add_finding(findings, "MEDIUM",
                    "CORS allows ANY origin (Access-Control-Allow-Origin: *)",
                    "Any website can read this site's responses through visitors' browsers.")
    elif evil in acao and acac.lower() == "true":
        add_finding(findings, "HIGH",
                    "CORS reflects arbitrary origin WITH credentials allowed",
                    "A malicious site could make authenticated cross-origin requests as your users.")
    progress.update("CORS check")


def check_http_methods(base_url, opener, findings, info, progress):
    """OPTIONS request to see advertised HTTP methods (read-only)."""
    try:
        req = urllib.request.Request(base_url, method="OPTIONS",
                                     headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                allow = resp.headers.get("Allow", "") or resp.headers.get("allow", "")
                status = resp.status
        except urllib.error.HTTPError as e:
            allow = e.headers.get("Allow", "") if e.headers else ""
            status = e.code
    except Exception:
        progress.update("HTTP methods")
        return
    info.append(f"HTTP OPTIONS -> {status}" + (f", Allow: {allow}" if allow else ""))
    if re.search(r"(?i)\b(PUT|DELETE|TRACE|CONNECT)\b", allow):
        add_finding(findings, "MEDIUM",
                    f"Risky HTTP methods advertised: {allow}",
                    "PUT/DELETE/TRACE can enable data tampering or cross-site tracing if accepted.")
    progress.update("HTTP methods")


def scan_dir_listing(base_url, opener, findings, info, progress):
    """Check common directories for enabled directory listing."""
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for d in EXTRA_DIRS:
        try:
            status, headers, body = fetch(root + d, opener, max_bytes=60_000)
        except urllib.error.HTTPError as e:
            status, body = e.code, b""
        except Exception:
            progress.update(f"dir {d}")
            continue
        try:
            if status == 200 and body:
                text = body[:30_000].decode("utf-8", errors="ignore")
                low = text.lower()
                if ("index of /" in low or "parent directory" in low or
                        re.search(r"<title>\s*index of", low)):
                    add_finding(findings, "MEDIUM",
                                f"Directory listing enabled: {root}{d}",
                                "Anyone can browse file names in this directory.")
        finally:
            progress.update(f"dir {d}")


# SQL error strings that indicate a database error leaked to the client.
SQL_ERROR_RE = [
    r"you have an error in your sql syntax", r"mysql_fetch", r"mysql_.*error",
    r"warning.*mysql", r"check the manual that corresponds to your mysql",
    r"postgresql.*error", r"pg_query", r"unterminated quoted string",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"microsoft ole db.*sql", r"odbc.*driver", r"jdbc.*sql",
    r"sqlite.*error", r"sqlite3?\.?:", r"ora-\d{4,5}", r"oracle.*error",
    r"sqlstate\[", r"supplied argument is not a valid mysql",
    r"conversion failed when converting", r"nvarchar", r"varchar.*value",
    r"mongo.*error", r"redis.*error", r"couchdb", r"elasticsearch.*error",
    r"sequelize", r"knex.*error", r"typeorm", r"prisma.*error",
    r"syntax error at or near", r"unexpected token.*sql",
]


# Database fingerprint patterns - extract DB name + version from leaked content.
DB_FP_RES = [
    ("MariaDB", r"(?i)mariadb[^\n]{0,40}?(\d+\.\d+(?:\.\d+)?)"),
    ("MySQL", r"(?i)mysql[^\n]{0,40}?(\d+\.\d+(?:\.\d+)?)"),
    ("PostgreSQL", r"(?i)postgresql?\s+(\d+(?:\.\d+)*)"),
    ("Microsoft SQL Server", r"(?i)(?:microsoft sql server|sqlserver)[^\n]{0,40}?(\d{2,4}(?:\.\d+)?)"),
    ("SQLite", r"(?i)sqlite3?[^\n]{0,30}?(\d+\.\d+(?:\.\d+)?)"),
    ("Oracle", r"(?i)oracle[^\n]{0,30}?(\d+(?:\.\d+){1,2})"),
    ("MongoDB", r"(?i)mongodb[^\n]{0,40}?(\d+\.\d+(?:\.\d+)?)"),
    ("Redis", r"(?i)redis[_ /-]?version[:\s]+(\d+\.\d+(?:\.\d+)?)"),
    ("phpMyAdmin", r"(?i)phpmyadmin\s+(\d+\.\d+(?:\.\d+)?)"),
    ("Adminer", r"(?i)adminer\s+(\d+\.\d+(?:\.\d+)?)"),
    ("Elasticsearch", r"(?i)elasticsearch[^\n]{0,40}?(\d+\.\d+(?:\.\d+)?)"),
]


def find_db_fingerprints(text):
    """Return ['MySQL 8.0.36', ...] style fingerprints found in text."""
    found = []
    for name, pat in DB_FP_RES:
        m = re.search(pat, text)
        if m:
            ver = next((g for g in m.groups() if g), None)
            found.append(f"{name} {ver}" if ver else name)
    return found


def http_raw(url, method="GET", data=None, opener=None, ctype=None):
    """Raw HTTP request for probes. Returns (status, body_bytes, headers_dict)."""
    opener = opener or get_opener()
    headers = {"User-Agent": USER_AGENT}
    body = None
    if data is not None:
        body = data.encode("utf-8", errors="replace")
        headers["Content-Type"] = ctype or "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(200_000), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        try:
            b = e.read(200_000)
        except Exception:
            b = b""
        return e.code, b, dict(e.headers.items()) if e.headers else {}
    except Exception:
        return None, b"", {}


def _norm_body(b):
    return re.sub(rb"\s+", b"", b[:80_000])


def discover_attack_surface(base_url, homepage_html, public_text):
    """Find forms, query-param URLs and API endpoints. No requests made."""
    parsed = urllib.parse.urlparse(base_url)
    netloc = parsed.netloc
    candidates = []   # {"url","method","params","source"}
    apis = set()
    corpus = (homepage_html or "") + "\n" + (public_text or "")

    # HTML forms
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", homepage_html or "",
                         re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        am = re.search(r"action\s*=\s*[\"']?([^\"'\s>]+)", attrs, re.I)
        mm = re.search(r"method\s*=\s*[\"']?(\w+)", attrs, re.I)
        action = urllib.parse.urljoin(base_url, am.group(1) if am else base_url)
        method = (mm.group(1).upper() if mm else "GET")
        p = urllib.parse.urlsplit(action)
        if p.netloc != netloc or p.scheme not in ("http", "https"):
            continue
        params = []
        for inp in re.findall(r"<input\b[^>]*>", inner, re.I):
            nm = re.search(r"name\s*=\s*[\"']([^\"']+)", inp, re.I)
            tp = re.search(r"type\s*=\s*[\"']([^\"']+)", inp, re.I)
            if not nm:
                continue
            t = (tp.group(1).lower() if tp else "text")
            if t in ("submit", "button", "image", "reset", "file"):
                continue
            val = re.search(r"value\s*=\s*[\"']([^\"']*)", inp, re.I)
            params.append((nm.group(1), val.group(1) if val else ""))
        for nm in re.findall(r"<(?:select|textarea)\b[^>]*name\s*=\s*[\"']([^\"']+)",
                             inner, re.I):
            params.append((nm, "test"))
        if params:
            candidates.append({"url": action.split("#")[0], "method": method,
                               "params": params[:4], "source": "form"})

    # URLs with query strings (links + JS strings)
    for m in re.finditer(r"[\"'(]([^\"'()\s<>]*\?[^\"'()\s<>]*=[^\"'()\s<>]*)",
                         corpus):
        u = urllib.parse.urljoin(base_url, m.group(1))
        p = urllib.parse.urlsplit(u)
        if p.netloc != netloc or p.scheme not in ("http", "https"):
            continue
        if re.search(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|map|txt|xml)(\?|$)",
                     p.path, re.I):
            continue
        pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        if pairs:
            candidates.append({"url": u.split("#")[0], "method": "GET",
                               "params": pairs[:4], "source": "query-url"})

    # API endpoints referenced in JS/HTML
    api_pats = [
        r"[\"'`](/api/[^\"'`\s]+)[\"'`]",
        r"[\"'`](/v\d+/[^\"'`\s]+)[\"'`]",
        r"[\"'`](/graphql[^\"'`\s]*)[\"'`]",
        r"[\"'`](/(?:rest|service|services|gateway)/[^\"'`\s]+)[\"'`]",
        r"(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]",
        r"\burl\s*:\s*[\"'`]([^\"'`]+)[\"'`]",
    ]
    for pat in api_pats:
        for m in re.finditer(pat, corpus):
            u = urllib.parse.urljoin(base_url, m.group(1))
            p = urllib.parse.urlsplit(u)
            if p.netloc == netloc and p.scheme in ("http", "https") and \
               not re.search(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|map|txt)(\?|$)",
                             p.path, re.I):
                apis.add(u.split("#")[0])

    # Dedupe candidates by url+method
    seen, uniq = set(), []
    for c in candidates:
        key = (c["url"], c["method"])
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq[:25], sorted(apis)[:40]


def probe_sqli(cand, opener, findings, info, progress, dbfp=None):
    """Non-destructive SQLi indicators: error-based, boolean-based, UNION (NULLs only).
    Returns 'error' | 'boolean' | 'union' | None."""
    url, method = cand["url"], cand["method"]
    params = [(k, v) for k, v in cand["params"]][:4]
    if not params:
        return None
    parts = urllib.parse.urlsplit(url)
    clean = f"{parts.scheme}://{parts.netloc}{parts.path}"

    def request(pairs):
        if method == "GET":
            return http_raw(clean + "?" + urllib.parse.urlencode(pairs),
                            "GET", None, opener)
        return http_raw(clean, "POST", urllib.parse.urlencode(pairs), opener)

    label = parts.path + (("?" + parts.query[:40]) if parts.query else "")

    base_pairs = list(params)
    first = params[0][0]

    def with_first(newval):
        return [(k, newval if k == first else v) for k, v in base_pairs]

    base_val = dict(base_pairs).get(first, "")

    # 1) baseline
    bs, bb, _ = request(base_pairs)
    progress.update(f"sqli baseline {label[:30]}")
    if bs is None:
        return None

    # 2) single-quote error probe
    qs, qb, _ = request(with_first(base_val + "'"))
    progress.update(f"sqli quote {label[:30]}")
    qtext = qb.decode("utf-8", errors="ignore")
    if dbfp is not None:
        dbfp.update(find_db_fingerprints(qtext))
    sql_err = any(re.search(p, qtext, re.I) for p in SQL_ERROR_RE)
    if sql_err or (qs is not None and qs >= 500 and qs != bs):
        add_finding(findings, "HIGH",
                    f"Possible ERROR-BASED SQL injection at {method} {label} - "
                    "a single quote triggered a database/server error. "
                    "Verify manually (e.g. sqlmap) - do NOT exploit.")
        info.append(f"      SQLi probe: DB error signature in response of {label}")
        result = "error"
    else:
        result = None

    # 3) boolean differential: ' OR '1'='1  vs  ' OR '1'='2
    ts, tb, _ = request(with_first(base_val + "' OR '1'='1"))
    progress.update(f"sqli bool-true {label[:30]}")
    fs, fb, _ = request(with_first(base_val + "' OR '1'='2"))
    progress.update(f"sqli bool-false {label[:30]}")
    if ts and fs:
        tn, fn = _norm_body(tb), _norm_body(fb)
        bn = _norm_body(bb)
        # true/false responses differ from each other AND from baseline
        if tn != fn:
            import difflib
            ratio = difflib.SequenceMatcher(None, tn[:50_000], fn[:50_000]).quick_ratio()
            if ratio < 0.98:
                if result is None:
                    add_finding(findings, "MEDIUM",
                                f"Possible BOOLEAN-BASED SQL injection at {method} {label} - "
                                "'OR 1=1' vs 'OR 1=2' produced different responses. "
                                "Verify manually.")
                    info.append(f"      SQLi probe: boolean differential at {label}")
                    result = "boolean"

    # 4) UNION column-count probe (NULLs only - extracts NO data) if indicator found
    if result in ("error", "boolean"):
        progress.total += 8  # reserve slots for up to 8 UNION attempts
        for n in range(1, 9):
            nulls = ",".join(["NULL"] * n)
            payload = base_val + f"' UNION SELECT {nulls}-- -"
            us, ub, _ = request(with_first(payload))
            progress.update(f"sqli union {n}col {label[:26]}")
            if us is None:
                continue
            utext = ub.decode("utf-8", errors="ignore")
            if dbfp is not None:
                dbfp.update(find_db_fingerprints(utext))
            still_err = any(re.search(p, utext, re.I) for p in SQL_ERROR_RE)
            if not still_err and _norm_body(ub) != _norm_body(qb):
                add_finding(findings, "HIGH",
                            f"Possible UNION-BASED SQL injection at {method} {label} "
                            f"(~{n} columns) - UNION probe with NULL columns returned "
                            "a different, error-free response. VERIFY MANUALLY with "
                            "sqlmap before reporting as confirmed.")
                info.append(f"      SQLi probe: UNION ~{n} columns at {label}")
                return "union"
    return result


REDIRECT_PARAMS = {"url", "next", "redirect", "return", "returnto", "return_url",
                   "continue", "target", "dest", "destination", "goto", "go",
                   "link", "rurl", "redir", "callback", "redirect_uri",
                   "redirecturl", "forward", "out", "view"}
XSS_PROBE = 'd3v1nxss<>"'
SSTI_PROBE = "${7*7}"
OPEN_REDIRECT_TARGET = "https://probe.invalid/devin-check"


def _vtuple(v):
    parts = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def probe_client_side(cand, opener, findings, info, progress):
    """Non-destructive XSS reflection, SSTI and open-redirect probes."""
    url, method = cand["url"], cand["method"]
    params = cand["params"][:4]
    if not params:
        return
    parts = urllib.parse.urlsplit(url)
    clean = f"{parts.scheme}://{parts.netloc}{parts.path}"
    first = params[0][0]
    base_val = dict(params).get(first, "") or "test"
    label = parts.path + (("?" + parts.query[:40]) if parts.query else "")

    def req(newval):
        pairs = [(k, newval if k == first else v) for k, v in params]
        if method == "GET":
            return http_raw(clean + "?" + urllib.parse.urlencode(pairs),
                            "GET", None, opener)
        return http_raw(clean, "POST", urllib.parse.urlencode(pairs), opener)

    # 1) Reflected XSS: does input come back unencoded?
    st, body, _ = req(base_val + XSS_PROBE)
    progress.update(f"xss probe {label[:26]}")
    if st and body and XSS_PROBE.encode() in body:
        add_finding(findings, "MEDIUM",
                    f"Possible reflected XSS at {method} {label} - "
                    "input is reflected unencoded. Verify manually.")
        info.append(f"      XSS probe: unencoded reflection at {label}")

    # 2) SSTI: ${7*7} should evaluate to 49 if template injection exists
    st, body, _ = req(base_val + SSTI_PROBE)
    progress.update(f"ssti probe {label[:26]}")
    if st and body:
        text = body.decode("utf-8", errors="ignore")
        if "49" in text and SSTI_PROBE not in text:
            add_finding(findings, "MEDIUM",
                        f"Possible SERVER-SIDE TEMPLATE INJECTION at {method} {label} - "
                        "${7*7} appears to have evaluated. Verify manually.")
            info.append(f"      SSTI probe: possible evaluation at {label}")

    # 3) Open redirect: only for redirect-looking parameter names
    if first.lower() in REDIRECT_PARAMS:
        st, body, hdrs = req(OPEN_REDIRECT_TARGET)
        progress.update(f"redirect probe {label[:24]}")
        loc = ""
        for k, v in hdrs.items():
            if k.lower() == "location":
                loc = v
        if st and 300 <= st < 400 and "probe.invalid" in loc:
            add_finding(findings, "HIGH",
                        f"OPEN REDIRECT at {method} {label} - "
                        "parameter controls redirect target. Phishing risk.")


def check_legacy_tls(host, findings, info, progress):
    """Try TLS 1.0 / 1.1 handshakes - they should be refused."""
    if not host:
        progress.update("legacy TLS check")
        return
    for label, maxv in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                        ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = maxv
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    add_finding(findings, "HIGH",
                                f"Server accepts deprecated {label}",
                                "Disable TLS < 1.2 - these protocols have known attacks.")
                    info.append(f"Legacy TLS: {label} handshake SUCCEEDED (should be disabled)")
        except Exception:
            pass
    progress.update("legacy TLS check")


def check_graphql(base_url, opener, findings, info, progress):
    """Probe common GraphQL endpoints for enabled introspection."""
    root = base_url.rstrip("/")
    for path in ("/graphql", "/api/graphql", "/graphql/", "/v1/graphql", "/gql"):
        url = root + path
        st, body, _ = http_raw(url, "POST",
                               '{"query":"{__schema{queryType{name}}}"}',
                               opener, ctype="application/json")
        progress.update(f"graphql {path}")
        if st == 200 and body:
            text = body[:20_000].decode("utf-8", errors="ignore")
            if "__schema" in text or '"data"' in text:
                add_finding(findings, "HIGH",
                            f"GraphQL endpoint at {path} responds - "
                            "introspection appears enabled",
                            "Full schema disclosure helps attackers map the API. "
                            "Disable introspection in production.")
                info.append(f"GraphQL: {url} returned schema data")
                return
        if st in (404, 405, None):
            continue


def check_api_auth(apis, base_url, opener, findings, info, progress):
    """GET-probe discovered API endpoints - flag ones returning data unauthenticated."""
    examined = 0
    for api in apis:
        if examined >= 10:
            break
        examined += 1
        path = urllib.parse.urlsplit(api).path.lower()
        if re.search(r"(login|signin|auth|token|health|status|favicon)", path):
            progress.update(f"api auth (skip) {path[:24]}")
            continue
        st, body, hdrs = http_raw(api, "GET", None, opener)
        progress.update(f"api auth {path[:28]}")
        if st == 200 and body:
            head = body[:200].lstrip()
            ctype = ""
            for k, v in hdrs.items():
                if k.lower() == "content-type":
                    ctype = v.lower()
            if head.startswith((b"{", b"[")) or "json" in ctype:
                add_finding(findings, "INFO",
                            f"API endpoint returns data without authentication: {api}",
                            "Confirm this data is intended to be public.")


def check_subdomain_takeover(base_url, opener, findings, info, progress,
                             homepage_body=b""):
    """Fetch a random path - hosting-platform 404 pages can mean dangling DNS."""
    import random
    rand = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                   for _ in range(10))
    url = base_url.rstrip("/") + "/" + rand
    st, body, _ = http_raw(url, "GET", None, opener, )
    progress.update("dangling deploy check")
    if st is None or not body:
        return
    if homepage_body and body == homepage_body[:len(body)]:
        return  # SPA fallback - normal
    text = body[:30_000].decode("utf-8", errors="ignore").lower()
    markers = [
        ("netlify", "Netlify"),
        ("github pages", "GitHub Pages"),
        ("heroku", "Heroku"),
        ("surge.sh", "Surge"),
        ("readthedocs", "Read the Docs"),
        ("azurewebsites", "Azure"),
        ("cloudfront", "CloudFront"),
    ]
    for key, name in markers:
        if key in text and ("not found" in text or "no such" in text or
                            "doesn't exist" in text or "project not found" in text):
            add_finding(findings, "MEDIUM",
                        f"Possible DANGLING DEPLOYMENT / subdomain takeover risk "
                        f"({name} not-found page at random path)",
                        "DNS points to a hosting platform but no site is deployed. "
                        "An attacker could claim this subdomain.")
            return


def check_content_issues(base_url, homepage_html, public_text, is_https,
                         findings, info, progress):
    """Offline analysis of already-fetched content: mixed content, comments,
    password autocomplete, CSRF tokens, 3rd-party scripts, JS lib versions,
    internal infrastructure references."""
    progress.update("content analysis")
    netloc = urllib.parse.urlsplit(base_url).netloc

    # Mixed content (HTTPS page loading http:// resources)
    if is_https:
        mixed = set(re.findall(
            r'(?:src|href)\s*=\s*["\']http://[^"\'>\s]+', homepage_html, re.I))
        if mixed:
            add_finding(findings, "LOW",
                        f"{len(mixed)} mixed-content http:// resource(s) on HTTPS page",
                        "; ".join(sorted(mixed)[:5]))

    # Suspicious HTML comments (dev notes, credentials hints)
    for m in re.finditer(r"<!--(.*?)-->", homepage_html, re.I | re.S):
        c = m.group(1)
        if re.search(r"(?i)(todo|fixme|password|secret|api[_-]?key|debug|hack|xxx|internal)", c):
            add_finding(findings, "LOW", "Suspicious HTML comment in page source",
                        re.sub(r"\s+", " ", c).strip()[:140])
            break

    # Password fields without autocomplete attribute
    pwd_tags = [t for t in re.findall(r"<input\b[^>]*>", homepage_html, re.I)
                if re.search(r"type\s*=\s*[\"']?password", t, re.I)
                and not re.search(r"autocomplete\s*=", t, re.I)]
    if pwd_tags:
        add_finding(findings, "LOW",
                    f"{len(pwd_tags)} password field(s) missing autocomplete attribute",
                    "Use autocomplete='current-password'/'new-password' appropriately.")

    # POST forms without a visible CSRF/token field
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", homepage_html, re.I | re.S):
        attrs, inner = m.groups()
        mm = re.search(r"method\s*=\s*[\"']?(\w+)", attrs, re.I)
        if mm and mm.group(1).upper() == "POST" and \
                not re.search(r"(?i)name\s*=\s*[\"']?[^\"'>\s]*(csrf|token|authenticity|_token)", inner):
            add_finding(findings, "MEDIUM",
                        "POST form has no visible CSRF token field",
                        "If no token is added by JS, the form may be CSRF-able.")
            break

    # Third-party scripts (supply-chain visibility)
    third = set()
    for src in re.findall(r"<script\b[^>]*src\s*=\s*[\"']([^\"']+)", homepage_html, re.I):
        u = urllib.parse.urljoin(base_url, src)
        if urllib.parse.urlsplit(u).netloc != netloc:
            third.add(urllib.parse.urlsplit(u).netloc)
    if third:
        info.append("Third-party script hosts: " + ", ".join(sorted(third)[:10]))

    # JS library versions (known-vulnerable/EOL detection)
    corpus = (homepage_html or "") + "\n" + (public_text or "")
    libs = {}
    for name, pat in [
        ("jQuery", r"jquery[-.](\d+\.\d+\.\d+)"),
        ("AngularJS", r"angular(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)|AngularJS v(\d+\.\d+\.\d+)"),
        ("Bootstrap", r"bootstrap[-.](\d+\.\d+\.\d+)"),
        ("Lodash", r"lodash[-.](\d+\.\d+\.\d+)"),
        ("Vue.js", r"vue(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)|vue@(?:dist/)?(\d+\.\d+\.\d+)"),
        ("React", r"react(?:\.production\.min)?\.js|react@(?:umd/)?(\d+\.\d+\.\d+)"),
    ]:
        m = re.search(pat, corpus, re.I)
        if m:
            libs[name] = next((g for g in m.groups() if g), "unknown")
    for name, ver in libs.items():
        info.append(f"JS library detected: {name} {ver}")
    jq = libs.get("jQuery")
    if jq and _vtuple(jq) < (3, 5, 0):
        add_finding(findings, "MEDIUM",
                    f"jQuery {jq} detected - versions < 3.5.0 have known XSS CVEs",
                    "Upgrade jQuery to >= 3.7.1.")
    aj = libs.get("AngularJS")
    if aj and _vtuple(aj)[0] == 1:
        add_finding(findings, "MEDIUM",
                    f"AngularJS {aj} detected - AngularJS 1.x is END-OF-LIFE",
                    "No security patches since Dec 2021 - migrate to modern framework.")
    ld = libs.get("Lodash")
    if ld and _vtuple(ld) < (4, 17, 21):
        add_finding(findings, "MEDIUM",
                    f"Lodash {ld} detected - versions < 4.17.21 have known CVEs",
                    "Upgrade to lodash >= 4.17.21.")
    bs = libs.get("Bootstrap")
    if bs and _vtuple(bs)[0] < 4:
        add_finding(findings, "LOW",
                    f"Bootstrap {bs} detected - major version is old/EOL",
                    "Consider upgrading to a supported Bootstrap version.")

    # Internal infrastructure references in public files
    for m in re.finditer(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
            r"[a-z0-9][a-z0-9-]*(?:\.internal|\.local|\.corp|\.lan)\b)",
            corpus, re.I):
        add_finding(findings, "LOW",
                    "Internal infrastructure reference exposed in public files",
                    f"Found: {m.group(0)} - reveals internal network naming.")
        break

    # DOM-XSS sinks: dangerous JS functions in public code
    sinks = len(re.findall(
        r"innerHTML|outerHTML|document\.write|eval\s*\(|new Function|"
        r"setTimeout\s*\(\s*['\"]|location\.href\s*=[^;]{0,60}(location|search|hash)",
        corpus))
    if sinks:
        add_finding(findings, "LOW",
                    f"{sinks} potential DOM-XSS sink(s) in public JS/HTML "
                    "(innerHTML/eval/document.write/location)",
                    "Review whether user input reaches these sinks unencoded.")


def _dns_txt(name):
    """Query DNS TXT records via nslookup (best-effort, cross-platform)."""
    for args in (["nslookup", "-type=TXT", name],
                 ["nslookup", name]):
        try:
            out = subprocess.check_output(args, timeout=10,
                                          stderr=subprocess.DEVNULL)
            return out.decode("utf-8", errors="ignore")
        except Exception:
            continue
    return ""


def check_phishing_surface(base_url, homepage_html, findings, info, progress):
    """Anti-phishing checks: SPF/DMARC DNS records + forms posting credentials
    to external domains."""
    netloc = urllib.parse.urlsplit(base_url).netloc
    domain = netloc.split(":")[0]
    domain = domain[4:] if domain.startswith("www.") else domain
    try:
        ipaddress.ip_address(domain.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False

    # 1) SPF / DMARC - can attackers spoof email as this domain?
    if is_ip:
        info.append("DNS email-auth check skipped (target is an IP address)")
        progress.update("spf/dmarc check")
    else:
        try:
            spf_out = _dns_txt(domain)
            spf_ok = "v=spf1" in spf_out.lower()
            dmarc_out = _dns_txt("_dmarc." + domain)
            dmarc_ok = "v=dmarc1" in dmarc_out.lower()
            if spf_ok:
                info.append("DNS: SPF record present (good)")
            else:
                add_finding(findings, "MEDIUM",
                            f"No SPF record found for {domain}",
                            "Anyone can send email appearing to come from this domain - phishing risk.")
            if dmarc_ok:
                info.append("DNS: DMARC record present (good)")
            elif spf_ok:
                add_finding(findings, "LOW",
                            f"No DMARC record for {domain}",
                            "Spoofed emails won't be rejected/quarantined.")
            else:
                add_finding(findings, "MEDIUM",
                            f"No DMARC record for {domain}",
                            "No policy telling receivers to reject spoofed mail - phishing risk.")
        except Exception as e:
            info.append(f"DNS email-auth check skipped: {e}")
        progress.update("spf/dmarc check")

    # 2) Forms submitting to a DIFFERENT domain - credentials may leave site
    ext = set()
    for m in re.finditer(r"<form\b([^>]*)>", homepage_html or "", re.I):
        am = re.search(r"action\s*=\s*[\"']?([^\"'\s>]+)", m.group(1), re.I)
        if not am:
            continue
        u = urllib.parse.urljoin(base_url, am.group(1))
        h = urllib.parse.urlsplit(u).netloc
        if h and h != netloc:
            ext.add(h)
    if ext:
        add_finding(findings, "HIGH",
                    "Form(s) submit data to EXTERNAL domain(s): " +
                    ", ".join(sorted(ext)[:5]),
                    "User credentials/data may be sent to a third party - verify this is intentional.")
    progress.update("external form check")


def check_suspicious_scripts(base_url, public_text, homepage_html,
                             findings, info, progress):
    """Scan public files for crypto-miners, obfuscated code, suspicious iframes."""
    corpus = (public_text or "") + "\n" + (homepage_html or "")
    patterns = [
        ("crypto miner (coinhive/cryptonight)",
         r"(?i)(coinhive|cryptonight|coin-hive|miner\.start|crypto-?loot|"
         r"webminer|deepminer)"),
        ("obfuscated script (eval/atob/unescape)",
         r"eval\s*\(\s*atob|document\.write\s*\(\s*unescape|"
         r"eval\s*\(\s*function|unescape\s*\(\s*['\"]%u"),
        ("javascript: URI in markup",
         r"(?i)(href|src|action)\s*=\s*[\"']\s*javascript\s*:"),
        ("known malicious-domain pattern",
         r"(?i)(\.top/|\.xyz/|\.buzz/|freebitco|claim-?reward|"
         r"verify-?your-?account|wallet-?sync)"),
    ]
    hits = 0
    for label, pat in patterns:
        m = re.search(pat, corpus)
        if m:
            hits += 1
            sev = "HIGH" if "miner" in label else "MEDIUM"
            ctx = re.sub(r"\s+", " ", corpus[max(0, m.start() - 40):m.end() + 40])[:160]
            add_finding(findings, sev,
                        f"Suspicious script pattern in public files: {label}",
                        f"Context: {ctx}")
    # External iframes can load malicious/trackers content
    netloc = urllib.parse.urlsplit(base_url).netloc
    ext_iframes = set()
    for src in re.findall(r"<iframe\b[^>]*src\s*=\s*[\"']([^\"']+)",
                          homepage_html or "", re.I):
        h = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, src)).netloc
        if h and h != netloc:
            ext_iframes.add(h)
    if ext_iframes:
        info.append("External iframe hosts: " + ", ".join(sorted(ext_iframes)[:8]))
        add_finding(findings, "LOW",
                    "External iframe(s) embedded: " +", ".join(sorted(ext_iframes)[:5]),
                    "Third-party frames can serve malicious content or track users - verify trusted.")
    progress.update("suspicious script scan")
    info.append(f"Suspicious script patterns found: {hits}")


# Well-known factory default credentials - tiny list, NOT brute force.
# Used only on device/IP targets to detect unchanged default passwords.
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "admin123"), ("admin", ""), ("root", "root"),
    ("root", "admin"), ("user", "user"), ("admin", "12345"),
    ("support", "support"),
]


def check_ping(host, findings, info, progress):
    """Quick ICMP ping - tells user if the device is even alive."""
    if not host or not is_ip_target(host):
        progress.update("ping (skipped - not IP)")
        return
    try:
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "-w", "2000", host]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", host]
        out = subprocess.check_output(cmd, timeout=6,
                                      stderr=subprocess.DEVNULL).decode("latin-1", "ignore")
        if "ttl=" in out.lower():
            info.append(f"Device {host} responds to ping (alive)")
        else:
            info.append(f"Device {host} does NOT respond to ping "
                        "(may be off, wrong IP, or ICMP blocked)")
    except Exception as e:
        info.append(f"Ping check failed for {host}: {e}")
    progress.update("ping")


def _find_login_form(html, base_url):
    """Locate a login form: returns dict(action, method, user_field, pass_field)."""
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S):
        attrs, inner = m.groups()
        if not re.search(r"type\s*=\s*[\"']?password", inner, re.I):
            continue
        ufield = pfield = None
        for inp in re.findall(r"<input\b[^>]*>", inner, re.I):
            nm = re.search(r"name\s*=\s*[\"']([^\"']+)", inp, re.I)
            tp = re.search(r"type\s*=\s*[\"']?([^\"'\s>]*)", inp, re.I)
            if not nm:
                continue
            name, t = nm.group(1), (tp.group(1).lower() if tp else "text")
            if t in ("password", "passwd") or re.search(r"(?i)pass", name):
                pfield = name
            elif (ufield is None and t not in
                  ("hidden", "submit", "button", "checkbox", "radio", "password")
                  and re.search(r"(?i)(user|login|name|email|account|uid|uname)", name)):
                ufield = name
        if ufield and pfield:
            am = re.search(r"action\s*=\s*[\"']?([^\"'\s>]+)", attrs, re.I)
            mm = re.search(r"method\s*=\s*[\"']?(\w+)", attrs, re.I)
            action = urllib.parse.urljoin(base_url, am.group(1) if am else base_url)
            p = urllib.parse.urlsplit(action)
            if p.netloc == urllib.parse.urlsplit(base_url).netloc and \
               p.scheme in ("http", "https"):
                return {"action": action.split("#")[0],
                        "method": (mm.group(1).upper() if mm else "POST"),
                        "user_field": ufield, "pass_field": pfield}
    return None


def _no_redirect_opener():
    """Opener that does NOT follow redirects - needed to detect login success."""
    class _NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        _NR(), urllib.request.HTTPSHandler(context=ctx))


def check_default_credentials(base_url, opener, homepage_html, findings,
                              info, progress):
    """Device mode: try ~10 factory-default credential pairs against the
    device's own login form. Defensive check for unchanged default passwords.
    NOT brute force - stops on first success."""
    form = _find_login_form(homepage_html, base_url)
    if not form:
        # Login form may be on a sub-page - probe common login locations
        for path in ("/login", "/login.html", "/admin", "/admin/",
                     "/index.html", "/home.html", "/ui", "/web"):
            st, b, _ = http_raw(base_url.rstrip("/") + path, "GET", None, opener)
            progress.update(f"login page {path}")
            if st == 200 and b:
                form = _find_login_form(b.decode("utf-8", errors="ignore"),
                                        base_url.rstrip("/") + path)
                if form:
                    break
    if not form:
        info.append("No login form detected - default credential check skipped")
        progress.update("no login form")
        return
    info.append(f"Login form found ({form['method']} {form['action']}) - "
                "testing factory default credentials")
    opener = _no_redirect_opener()  # see 302 redirects = login success

    parts = urllib.parse.urlsplit(form["action"])
    clean = f"{parts.scheme}://{parts.netloc}{parts.path}"

    def attempt(user, pw):
        pairs = [(form["user_field"], user), (form["pass_field"], pw)]
        if form["method"] == "GET":
            return http_raw(clean + "?" + urllib.parse.urlencode(pairs),
                            "GET", None, opener)
        return http_raw(clean, "POST", urllib.parse.urlencode(pairs), opener)

    # Baseline (empty creds) for comparison
    bs, bb, bh = attempt("", "")
    progress.update("baseline login attempt")
    base_len = len(bb or b"")

    for user, pw in DEFAULT_CREDS:
        st, body, hdrs = attempt(user, pw)
        progress.update(f"default cred {user}:***")
        if st is None:
            continue
        loc = ""
        for k, v in hdrs.items():
            if k.lower() == "location":
                loc = v.lower()
        redirected = st in (301, 302, 303, 307, 308) and "login" not in loc
        has_cookie = any(k.lower() == "set-cookie" for k in hdrs)
        body_diff = base_len > 0 and body is not None and \
            abs(len(body) - base_len) > 0.5 * base_len
        if redirected or (has_cookie and body_diff):
            add_finding(findings, "CRITICAL",
                        f"WEAK PASSWORD - device login accepts DEFAULT credentials "
                        f"'{user}':***",
                        "Factory default password still active - change it "
                        "immediately to a strong unique password.")
            info.append(f"      DEFAULT CREDS WORK: {user} / {pw or '(blank)'}")
            return
        time.sleep(0.3)

    info.append("No factory default credentials worked - good sign. "
                "(Actual password strength cannot be checked externally.)")


def check_idor(apis, base_url, opener, findings, info, progress):
    """Light IDOR probe: numeric-ID API endpoints fetched with two different
    IDs - flags if both return distinct data without authentication."""
    cands = []
    for api in apis:
        p = urllib.parse.urlsplit(api).path
        if re.search(r"/\d+(/|$)", p):
            cands.append(api)
    for api in cands[:3]:
        parts = urllib.parse.urlsplit(api)
        m = re.search(r"/(\d+)(/|$)", parts.path)
        if not m:
            continue
        n = int(m.group(1))
        progress.update(f"idor {parts.path[:30]}")
        bodies = []
        for newid in (n, n + 1):
            newpath = re.sub(r"/\d+", f"/{newid}", parts.path, count=1)
            u = f"{parts.scheme}://{parts.netloc}{newpath}"
            if parts.query:
                u += "?" + parts.query
            st, body, _ = http_raw(u, "GET", None, opener)
            if st == 200 and body and body[:1] in (b"{", b"["):
                bodies.append(body[:5_000])
        if len(bodies) == 2 and bodies[0] != bodies[1]:
            add_finding(findings, "MEDIUM",
                        f"Potential IDOR at {api} - sequential object IDs "
                        "return different data without authentication",
                        "Verify server-side authorization checks every object ID.")


# ---------------------------------------------------------------------------
# Category risk scoring + PDF report (0 = secure, 100 = fully vulnerable)
# ---------------------------------------------------------------------------
CATEGORIES = [
    ("SQL Injection (and similar injection attacks)", "SQLI",
     "Use parameterized queries / prepared statements for ALL database access. "
     "Never concatenate user input into SQL. Verify with sqlmap."),
    ("Broken Authentication / Session Management Flaws", "AUTH",
     "Enforce HTTPS everywhere, Secure+HttpOnly+SameSite cookies, strong "
     "session IDs, lockout/rate-limiting on login."),
    ("Sensitive Data Exposure / Misconfiguration", "DATA",
     "Remove publicly exposed files, rotate any leaked secrets, disable "
     "server version disclosure, encrypt data at rest."),
    ("Cross-Site Scripting (XSS) and related client-side attacks", "XSS",
     "Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; "
     "encode all output; use modern frameworks' auto-escaping."),
    ("IDOR / Broken Access Control", "IDOR",
     "Enforce authorization server-side on EVERY object/request; restrict "
     "CORS; disable directory listing."),
    ("API and Backend Vulnerabilities", "API",
     "Authenticate & authorize every API endpoint, disable public API docs "
     "in production, add rate limiting, validate all input."),
    ("Man-in-the-Middle (MitM) / Network Interception", "MITM",
     "Force HTTPS with HSTS, TLS 1.2+, valid certificate, no mixed content."),
    ("Supply-Chain / Third-Party Component Attacks", "SUPPLY",
     "Pin dependencies, use Subresource Integrity for CDN scripts, remove "
     "exposed manifests/source maps, monitor dependencies for CVEs."),
    ("Social Engineering / Phishing", "SOCIAL",
     "Security awareness training, phishing simulations, strong password "
     "policy, MFA. (Not externally testable - process control.)"),
    ("Malware, Ransomware, or Insider Threats", "MALWARE",
     "EDR/antivirus, patching, least-privilege access, backups, insider-"
     "threat policy. (Not externally testable - internal control.)"),
]


def score_categories(findings, homepage_html=""):
    """Map findings to the 10 risk categories. Returns {key: (score, notes)}."""
    scores = {k: 0 for _, k, _ in CATEGORIES}
    notes = {k: [] for _, k, _ in CATEGORIES}

    def bump(key, pts, note):
        scores[key] = min(100, scores[key] + pts)
        if note and note not in notes[key]:
            notes[key].append(note)

    for sev, msg in findings:
        ml = msg.lower()
        if "error-based sql injection" in ml:
            bump("SQLI", 45, "error-based SQLi indicator")
        if "boolean-based sql injection" in ml:
            bump("SQLI", 30, "boolean-based SQLi indicator")
        if "union-based sql injection" in ml:
            bump("SQLI", 55, "UNION-based SQLi indicator")
        if "database connection string" in ml:
            bump("SQLI", 15, "DB credentials exposed")
            bump("DATA", 15, "DB credentials in public file")
        if "cookie" in ml and ("missing flags" in ml or "without" in ml):
            bump("AUTH", 12, "insecure cookie flags")
        if "plain http" in ml:
            bump("AUTH", 10, "site on plain HTTP")
            bump("MITM", 20, "no HTTPS enforcement")
        if re.search(r"publicly accessible: /(wp-login|user/login|administrator|admin/)", ml):
            bump("AUTH", 8, "login/admin panel reachable")
        if sev == "CRITICAL" and ("exposed in public file" in ml or "secret" in ml):
            bump("DATA", 40, "secret/credential exposed publicly")
        if sev == "HIGH" and ("sensitive file exposed" in ml or
                              "publicly accessible" in ml):
            bump("DATA", 25, "sensitive file publicly accessible")
        if ".sql" in ml and "publicly accessible" in ml:
            bump("DATA", 10, "SQL dump possibly exposed")
        if "server version disclosed" in ml or "x-powered-by" in ml:
            bump("DATA", 5, "technology/version disclosure")
        if "source map" in ml:
            bump("DATA", 5, "source map exposed")
            bump("SUPPLY", 5, "source map exposed")
        if "content-security-policy" in ml:
            bump("XSS", 15, "CSP missing")
        if "x-frame-options" in ml:
            bump("XSS", 10, "clickjacking protection missing")
        if "x-content-type-options" in ml:
            bump("XSS", 5, "MIME-sniffing possible")
        if "referrer-policy" in ml:
            bump("XSS", 5, "referrer policy missing")
        if "permissions-policy" in ml:
            bump("XSS", 3, "permissions policy missing")
        if "directory listing" in ml:
            bump("IDOR", 15, "directory listing enabled")
        if "cors" in ml and "any origin" in ml:
            bump("IDOR", 15, "CORS allows any origin")
        if "cors" in ml and "credentials" in ml:
            bump("IDOR", 35, "CORS reflects origin with credentials")
        if "risky http methods" in ml:
            bump("IDOR", 10, "risky HTTP methods enabled")
        if "phpmyadmin" in ml or "/pma/" in ml:
            bump("IDOR", 20, "DB admin panel exposed")
        if "actuator" in ml:
            bump("API", 20, "Spring Actuator exposed")
        if "swagger" in ml or "api-docs" in ml or "openapi" in ml:
            bump("API", 15, "API documentation publicly exposed")
        if "server-status" in ml or "server-info" in ml:
            bump("API", 10, "server status page exposed")
        if "graphql" in ml:
            bump("API", 10, "GraphQL endpoint exposed")
        if "strict-transport-security" in ml:
            bump("MITM", 15, "HSTS missing")
        if "deprecated tls" in ml or "weak cipher" in ml:
            bump("MITM", 30, "weak TLS version/cipher")
        if "certificate" in ml and ("expired" in ml or "fail" in ml or
                                    "verification" in ml):
            bump("MITM", 50, "TLS certificate problem")
        if re.search(r"publicly accessible: /(package\.json|composer\.json|"
                     r"yarn\.lock|package-lock\.json)", ml):
            bump("SUPPLY", 8, "dependency manifest exposed")
        # --- social engineering / phishing surface ---
        if "spf" in ml or "dmarc" in ml:
            bump("SOCIAL", 25, "email spoofing possible (missing SPF/DMARC)")
        if "external domain" in ml and "form" in ml:
            bump("SOCIAL", 35, "form submits credentials to external domain")
        if "open redirect" in ml:
            bump("SOCIAL", 15, "open redirect enables phishing links")
        # --- malware / insider-threat surface ---
        if "miner" in ml or "obfuscat" in ml or "suspicious script" in ml:
            bump("MALWARE", 40, "crypto-miner/obfuscated/suspicious script")
        if "external iframe" in ml:
            bump("MALWARE", 10, "external iframe can serve malicious content")
        # --- XSS / DOM ---
        if "dom-xss" in ml or "dom xss" in ml:
            bump("XSS", 10, "DOM-XSS sinks in public JS")
        # --- IDOR / access control ---
        if "idor" in ml or "sequential object" in ml:
            bump("IDOR", 30, "sequential object IDs accessible")

    # SRI check: <script src=...> without integrity attribute
    if homepage_html:
        tags = re.findall(r"<script\b[^>]*>", homepage_html, re.I)
        ext = [t for t in tags if re.search(r"\bsrc\s*=", t, re.I)]
        no_sri = [t for t in ext if not re.search(r"\bintegrity\s*=", t, re.I)]
        if no_sri:
            bump("SUPPLY", min(20, 5 * len(no_sri)),
                 f"{len(no_sri)} script(s) without SRI integrity hash")

    return {k: (min(100, scores[k]), notes[k][:4]) for _, k, _ in CATEGORIES}


def _pdf_safe(s):
    return s.encode("ascii", "replace").decode("ascii")


def write_pdf(path, rows):
    """Minimal dependency-free PDF writer.
    rows: list of (bold:bool, size:int, text:str). ~50 lines per page."""
    per_page = 50
    pages = [rows[i:i + per_page] for i in range(0, len(rows), per_page)] or [[]]
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        ("<< /Type /Pages /Kids [" +
         " ".join(f"{4 + i * 2} 0 R" for i in range(len(pages))) +
         f"] /Count {len(pages)} >>").encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    for prows in pages:
        parts = ["BT"]
        for i, (bold, size, text) in enumerate(prows):
            font = "/F2" if bold else "/F1"
            esc = (_pdf_safe(text)[:110]
                   .replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)"))
            if i == 0:
                parts.append(f"{font} {size} Tf 50 780 Td {size + 4} TL")
            else:
                parts.append(f"{font} {size} Tf {size + 4} TL")
            parts.append(f"({esc}) Tj")
            parts.append("T*")
        parts.append("ET")
        stream = "\n".join(parts).encode("latin-1", "replace")
        page_num = len(objs) + 1      # next object number = page
        cont_num = len(objs) + 2      # following object = content stream
        objs.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            + f"/Contents {cont_num} 0 R >>".encode())
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) +
                    stream + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF").encode()
    with open(path, "wb") as f:
        f.write(bytes(out))


def scan_db_ports(host, findings, info, progress, dbfp=None, ports=None):
    """TCP-connect scan of common service/DB ports. No login attempts."""
    ports = ports or DB_PORTS
    if not host:
        progress.update("port scan (skipped)")
        return

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((host, p))
            return p
        except Exception:
            return None
        finally:
            s.close()

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(probe, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = fut.result()
            if p:
                open_ports.append(p)
            progress.update(f"port {futures[fut]}")
    open_ports.sort()
    info.append(f"Open ports on {host}: " +
                (", ".join(f"{p}({ports[p]})" for p in open_ports) if open_ports else "none of the scanned ports"))

    db_like = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 2375}
    for p in open_ports:
        name = ports[p]
        if p in (6379, 9200, 11211, 27017, 2375):
            add_finding(findings, "CRITICAL",
                        f"{name} (port {p}) exposed to the internet",
                        "Unauthenticated-access-prone service reachable publicly - firewall it and require auth.")
        elif p in db_like:
            add_finding(findings, "HIGH",
                        f"{name} (port {p}) exposed to the internet",
                        "Database port reachable publicly - restrict via firewall/VPN and strong credentials.")
        elif p == 23:
            add_finding(findings, "HIGH", "Telnet (23) open",
                        "Telnet sends credentials unencrypted - disable or replace with SSH.")
        elif p == 21:
            add_finding(findings, "MEDIUM", "FTP (21) open",
                        "FTP transmits credentials in clear text - prefer SFTP/FTPS.")
        elif p == 445:
            add_finding(findings, "MEDIUM", "SMB (445) exposed",
                        "Ensure SMB is not reachable from untrusted networks.")
        elif p == 3389:
            add_finding(findings, "MEDIUM", "RDP (3389) exposed",
                        "Restrict via VPN/IP allowlist; enable NLA and strong passwords.")

    # Banner grab on DB ports only - some DBs (e.g. MySQL) send a version
    # string in their greeting packet. Read-only: we send nothing.
    DB_BANNER_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 2375, 9300}
    if dbfp is not None:
        for p in open_ports:
            if p not in DB_BANNER_PORTS:
                continue
            try:
                s = socket.create_connection((host, p), timeout=3)
                s.settimeout(2)
                try:
                    data = s.recv(512)
                except socket.timeout:
                    data = b""
                s.close()
                if data:
                    txt = data.decode("latin-1", "ignore")
                    fps = find_db_fingerprints(txt)
                    vers = re.findall(r"\d+\.\d+(?:\.\d+){0,2}", txt)
                    if fps:
                        dbfp.update(fps)
                    elif vers:
                        dbfp.add(f"{ports[p]} {vers[0]} (port {p} banner)")
                    else:
                        printable = re.sub(r"[^\x20-\x7e]", " ", txt).strip()[:60]
                        if printable:
                            dbfp.add(f"{ports[p]} service banner on {p}: {printable}")
            except Exception:
                pass
    return open_ports


def run_scan(target):
    findings = []   # (severity, message)
    info = []
    opener = get_opener()
    base_url, parsed = normalize_url(target)
    host = parsed.hostname
    ip_mode = is_ip_target(host) if host else False
    homepage_html = ""
    dbfp = set()   # database fingerprints detected from leaked content/banners

    print(f"\n[*] Scanning: {base_url}")
    print("[*] Mode: read-only audit + non-destructive SQLi indicator probes\n")

    info.append(f"Target        : {base_url}")
    info.append(f"Scan started  : {datetime.now().isoformat(timespec='seconds')}")
    try:
        info.append(f"Host resolves : {socket.gethostbyname(host) if host else 'n/a'}")
    except Exception:
        info.append(f"Host resolves : FAILED ({host})")

    print("[*] Progress (each test shows its own bar):")

    # Per-test scoring: 0 = secure / no issues found, 100 = vulnerable
    test_results = []   # (name, score, finding_count, note)
    status = headers = body = None
    surface = {"text": "", "secret_hits": 0, "db_string_hits": 0}
    candidates, apis, sqli_results, open_ports, links = [], [], [], [], []
    _PTS = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 12, "LOW": 5}

    def run_test(name, total, fn, note=""):
        p = Progress(total)
        before = len(findings)
        try:
            fn(p)
        except Exception as e:
            info.append(f"Test '{name}' error: {e}")
        finally:
            p.finish()
        new = findings[before:]
        sc = min(100, sum(_PTS.get(s, 0) for s, _ in new))
        test_results.append((name, sc, len(new), note))

    # 1) Reachability / headers / cookies
    def t_headers(p):
        nonlocal status, headers, body
        status, headers, body = scan_headers(base_url, opener, findings, info)
        p.update("headers & cookies")
    run_test("HTTP headers & cookies", 1, t_headers)

    if status is not None:
        # 2) TLS version & cipher
        if parsed.scheme == "https":
            def t_tls(p):
                check_tls(parsed, findings, info)
                p.update("TLS version & cipher")
            run_test("TLS version & cipher", 1, t_tls)

            # 3) Certificate validity
            def t_cert(p):
                info.append(check_cert_validity(parsed))
                p.update("certificate validity")
            run_test("TLS certificate validity", 1, t_cert)
        else:
            run_test("TLS version & cipher", 1,
                     lambda p: p.update("skipped - HTTP"), "skipped")
            run_test("TLS certificate validity", 1,
                     lambda p: p.update("skipped - HTTP"), "skipped")

        # Pre-compute linked files
        homepage_html = body.decode("utf-8", errors="ignore") if body else ""
        dbfp.update(find_db_fingerprints(homepage_html))
        links = extract_links(homepage_html, base_url)[:MAX_LINKED_FILES]

        # 4) Sensitive paths (~90 probes, parallel)
        def t_paths(p):
            scan_sensitive_paths(base_url, opener, findings, info, p, body, dbfp)
        run_test("Sensitive file exposure (90+ paths)", len(SENSITIVE_PATHS), t_paths)

        # 5) Public JS/CSS/JSON files - secret leakage scan
        def t_files(p):
            nonlocal surface
            surface = scan_linked_files(base_url, opener, body, links,
                                        findings, info, p)
            if surface is None:
                surface = {"text": "", "secret_hits": 0, "db_string_hits": 0}
        run_test("Public file & secret scan", 1 + len(links), t_files)
        dbfp.update(find_db_fingerprints(surface["text"]))

        # Attack surface discovery (instant, no requests)
        candidates, apis = discover_attack_surface(base_url, homepage_html,
                                                   surface["text"])
        info.append(f"Attack surface: {len(candidates)} input(s) with parameters, "
                    f"{len(apis)} API endpoint(s) discovered")
        for a in apis[:15]:
            info.append(f"      API endpoint: {a}")
        if len(apis) > 15:
            info.append(f"      ... and {len(apis) - 15} more API endpoint(s)")

        # 6) SQL injection indicators
        def t_sqli(p):
            nonlocal sqli_results
            sqli_results = []
            for cand in candidates:
                r = probe_sqli(cand, opener, findings, info, p, dbfp)
                if r:
                    sqli_results.append(r)
        run_test("SQL injection probes (error/boolean/UNION)",
                 max(1, len(candidates) * 4), t_sqli)

        # 7) XSS / SSTI / open-redirect probes
        def t_client(p):
            for cand in candidates:
                probe_client_side(cand, opener, findings, info, p)
        run_test("XSS / SSTI / open-redirect probes",
                 max(1, len(candidates) * 3), t_client)

        # 8) CORS / HTTP methods / directory listing
        run_test("CORS configuration", 1,
                 lambda p: check_cors(base_url, opener, findings, info, p))
        run_test("HTTP methods (OPTIONS)", 1,
                 lambda p: check_http_methods(base_url, opener, findings, info, p))
        run_test("Directory listing check", len(EXTRA_DIRS),
                 lambda p: scan_dir_listing(base_url, opener, findings, info, p))

        # 9) Deep checks
        run_test("Legacy TLS 1.0/1.1 check", 1,
                 lambda p: check_legacy_tls(
                     host if parsed.scheme == "https" else "",
                     findings, info, p))
        run_test("GraphQL introspection", 5,
                 lambda p: check_graphql(base_url, opener, findings, info, p))
        run_test("API authentication probe", min(len(apis), 10) or 1,
                 lambda p: check_api_auth(apis, base_url, opener, findings, info, p))
        run_test("Dangling deploy / subdomain takeover", 1,
                 lambda p: check_subdomain_takeover(
                     base_url, opener, findings, info, p, body))
        run_test("Content analysis (mixed/comments/forms/JS libs)", 1,
                 lambda p: check_content_issues(
                     base_url, homepage_html, surface["text"],
                     parsed.scheme == "https", findings, info, p))

        # 10) Phishing surface: SPF/DMARC + external form actions
        run_test("Phishing surface (SPF/DMARC/external forms)", 2,
                 lambda p: check_phishing_surface(
                     base_url, homepage_html, findings, info, p))

        # 11) Suspicious scripts: miners, obfuscation, iframes
        run_test("Suspicious script scan (miners/obfuscation)", 1,
                 lambda p: check_suspicious_scripts(
                     base_url, surface["text"], homepage_html,
                     findings, info, p))

        # 12) IDOR probe on numeric-ID API endpoints
        run_test("IDOR probe (numeric object IDs)", 3,
                 lambda p: check_idor(apis, base_url, opener, findings, info, p))

        # 13) robots.txt + sitemap.xml review
        def t_robots(p):
            for fname in ("robots.txt", "sitemap.xml", "sitemap_index.xml"):
                p.update(fname)
                try:
                    r_status, _, r_body = fetch(base_url.rstrip("/") + "/" + fname,
                                                opener, max_bytes=300_000)
                except Exception:
                    continue
                if r_status != 200 or not r_body:
                    continue
                text = r_body.decode("utf-8", errors="ignore")
                if fname == "robots.txt":
                    entries = re.findall(r"(?im)^\s*disallow\s*:\s*(\S+)", text)
                else:
                    entries = re.findall(r"<loc>\s*([^<]+?)\s*</loc>", text)
                sensitive = [e for e in entries
                             if re.search(r"(?i)(admin|backup|config|\.sql|\.env|private|"
                                          r"secret|api|test|dev|staging|debug|tmp|temp|"
                                          r"log|upload|download)", e)]
                if sensitive:
                    add_finding(findings, "LOW",
                                f"{fname} reveals potentially sensitive paths ({len(sensitive)})",
                                "; ".join(sensitive[:10]) +
                                (" ..." if len(sensitive) > 10 else ""))
                info.append(f"{fname}: {len(entries)} path(s) listed")
        run_test("robots.txt & sitemap review", 3, t_robots)

        # 14) Software fingerprinting via headers (informational)
        def t_fp(p):
            for h in ("X-AspNet-Version", "X-Generator", "X-Drupal-Cache", "Via"):
                for k, v in (headers or {}).items():
                    if k.lower() == h.lower():
                        info.append(f"Fingerprint    : {k}: {v}")
            p.update("fingerprints")
        run_test("Software fingerprinting", 1, t_fp)
    else:
        print("[!] Site unreachable - skipping web checks, running port scan only.")
        test_results.append(("Web application checks", 0, 0, "skipped - unreachable"))

    # 14b) Device checks - run even if web unreachable (ping still works)
    run_test("Device ping check", 1,
             lambda p: check_ping(host, findings, info, p))

    def t_creds(p):
        if not ip_mode:
            p.update("skipped - not a device/IP target")
            return
        check_default_credentials(base_url, opener, homepage_html,
                                  findings, info, p)
    run_test("Default credential check (device login)",
             len(DEFAULT_CREDS) + 9, t_creds,
             "" if ip_mode else "skipped")

    # 15) Port scan - extended (~1089 ports) for IP/device targets,
    #     common ports only for domain targets
    port_map = EXTENDED_PORTS if ip_mode else DB_PORTS
    port_test_name = (f"Port scan ({len(port_map)} ports - device mode)"
                      if ip_mode else "Port scan & service/DB banners")

    def t_ports(p):
        nonlocal open_ports
        open_ports = scan_db_ports(host, findings, info, p, dbfp,
                                   ports=port_map) or []
    run_test(port_test_name, len(port_map), t_ports)

    # Report detected database technologies
    if dbfp:
        for fp in sorted(dbfp):
            info.append(f"Database fingerprint: {fp}")
        add_finding(findings, "INFO",
                    "Database technology detected: " + ", ".join(sorted(dbfp)[:6]),
                    "Fingerprinted from error messages, page content or port "
                    "banner. Verify the version is still supported/patched.")

    # HTTP -> HTTPS redirect note for plain-HTTP targets
    if parsed.scheme == "http":
        add_finding(findings, "MEDIUM",
                    "Site available over plain HTTP without forced HTTPS redirect.")

    # ---- Verdict & database posture ----
    sev_count = {}
    for sev, _ in findings:
        sev_count[sev] = sev_count.get(sev, 0) + 1
    sqli_hit = any("sql injection" in m.lower() for _, m in findings)

    if sev_count.get("CRITICAL"):
        verdict = ("VULNERABLE - CRITICAL issues found. "
                   "Fix all CRITICAL findings immediately.")
    elif sev_count.get("HIGH"):
        verdict = ("AT RISK - HIGH severity issues found. "
                   "Address HIGH findings before launch.")
    elif sqli_hit or sev_count.get("MEDIUM"):
        verdict = ("POTENTIALLY VULNERABLE - MEDIUM findings present. "
                   "Manually verify injection indicators (e.g. with sqlmap).")
    else:
        verdict = ("No obvious vulnerabilities detected by external checks. "
                   "This does NOT guarantee security - internal testing still needed.")

    db_like_ports = [p for p in open_ports
                     if p in (3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 2375)]
    surface = locals().get("surface") or {}
    sqli_results = locals().get("sqli_results") or []
    if surface.get("db_string_hits"):
        db_posture = ("DATABASE: NOT SECURE - connection strings with credentials "
                      "are exposed in public files. Rotate credentials NOW.")
    elif sqli_results:
        db_posture = ("DATABASE: AT RISK - SQL injection indicators detected. "
                      "Inputs reach the database layer unsafely (verify manually).")
    elif db_like_ports:
        db_posture = ("DATABASE: AT RISK - database service port(s) exposed: " +
                      ", ".join(map(str, db_like_ports)) +
                      ". Restrict via firewall/VPN.")
    else:
        db_posture = ("DATABASE: no external exposure detected. "
                      "Internal credentials/config still need review.")
    if dbfp:
        db_posture += (" Detected technology: " +
                       ", ".join(sorted(dbfp)[:4]) +
                       " - confirm version is supported and patched.")

    # ---- Output ----
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f[0], 5))
    cat_scores = score_categories(findings, homepage_html)

    print("\n" + "=" * 64)
    print("  SECURITY VERDICT")
    print("=" * 64)
    print(f"  {verdict}")
    print(f"  {db_posture}")
    counts_str = ", ".join(f"{k}={v}" for k, v in
                           sorted(sev_count.items(), key=lambda x: order.get(x[0], 9)))
    print(f"  Findings: {counts_str or 'none'}")

    print("\n" + "=" * 64)
    print("  FINDINGS")
    print("=" * 64)
    if not findings:
        print("  No issues detected by the passive checks.")
    for sev, msg in findings:
        print(f"  [{sev:8}] {msg}")

    print("\n" + "=" * 64)
    print("  INFO")
    print("=" * 64)
    for line in info:
        print(f"  {line}")

    print("\n" + "=" * 64)
    print("  CATEGORY RISK SCORES  (0 = secure, 100 = fully vulnerable)")
    print("=" * 64)
    for i, (name, key, _fix) in enumerate(CATEGORIES, 1):
        sc, nt = cat_scores[key]
        note = ("  <- " + "; ".join(nt)) if nt else ""
        print(f"  {i:2d}. {name[:54]:<54} {sc:3d}/100{note}")

    print("\n" + "=" * 64)
    print("  TEST RESULTS  (0 = secure / no issues, 100 = vulnerable)")
    print("=" * 64)
    worst = 0
    for name, sc, cnt, note in test_results:
        worst = max(worst, sc)
        tag = f" [{note}]" if note else ""
        print(f"  {name[:52]:<52} {sc:3d}/100  ({cnt} finding(s)){tag}")
    print(f"  {'OVERALL - worst test score':<52} {worst:3d}/100")

    # Write report file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"vuln_report_{ts}.txt"
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_name)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("VulnCheck Lite - Defensive Security Audit Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target : {base_url}\n")
        f.write(f"Date   : {datetime.now().isoformat(timespec='seconds')}\n")
        f.write("Mode   : Read-only audit (GET/HEAD/OPTIONS + TCP connect + "
                "non-destructive SQLi indicator probes)\n\n")
        f.write("SECURITY VERDICT\n" + "-" * 60 + "\n")
        f.write(f"{verdict}\n{db_posture}\n")
        f.write("Findings: " + (counts_str or "none") + "\n\n")
        f.write("TEST RESULTS  (0 = secure / no issues, 100 = vulnerable)\n"
                + "-" * 60 + "\n")
        for name, sc, cnt, note in test_results:
            tag = f" [{note}]" if note else ""
            f.write(f"{name[:50]:<50} {sc:3d}/100  ({cnt} finding(s)){tag}\n")
        f.write("\nFINDINGS\n" + "-" * 60 + "\n")
        for sev, msg in findings:
            f.write(f"[{sev:8}] {msg}\n")
        f.write("\nINFO\n" + "-" * 60 + "\n")
        for line in info:
            f.write(line + "\n")
        f.write("\nRECOMMENDATIONS\n" + "-" * 60 + "\n")
        f.write("- Remove or restrict access to any exposed sensitive files (.env, .git, backups).\n")
        f.write("- Add missing security headers (CSP, HSTS, X-Frame-Options, etc.).\n")
        f.write("- Set Secure + HttpOnly + SameSite on all cookies.\n")
        f.write("- Disable server version disclosure (Server / X-Powered-By headers).\n")
        f.write("- Upgrade to TLS 1.2+ and strong ciphers (>=128-bit).\n")
        f.write("- If secrets were found in responses, rotate them immediately.\n")
        f.write("- If SQL injection indicators were found: use parameterized queries / "
                "prepared statements for ALL database access, and verify with sqlmap.\n")
        f.write("- Restrict database ports (3306/5432/27017/6379/9200...) via firewall/VPN.\n")
        f.write("- Review discovered API endpoints for missing authentication/rate limiting.\n")

    # ---- PDF report ----
    pdf_rows = [
        (True, 16, "Security Assessment Report"),
        (False, 10, f"Target : {base_url}"),
        (False, 10, f"Date   : {datetime.now().isoformat(timespec='seconds')}"),
        (True, 11, "SECURITY VERDICT"),
        (False, 10, verdict),
        (False, 10, db_posture),
        (False, 10, f"Findings: {counts_str or 'none'}"),
        (False, 8, ""),
        (True, 12, "CATEGORY RISK SCORES  (0 = secure, 100 = fully vulnerable)"),
    ]
    for i, (name, key, fix) in enumerate(CATEGORIES, 1):
        sc, nt = cat_scores[key]
        pdf_rows.append((False, 10, f"{i:2d}. {name}"))
        pdf_rows.append((True, 11, f"     Score: {sc}/100"))
        if nt:
            pdf_rows.append((False, 9, "     Indicators: " + "; ".join(nt)))
        if sc > 0:
            pdf_rows.append((False, 9, "     Fix: " + fix))
    pdf_rows += [(False, 8, ""),
                 (True, 12, "TEST RESULTS  (0 = secure / no issues, 100 = vulnerable)")]
    worst = 0
    for name, sc, cnt, note in test_results:
        worst = max(worst, sc)
        tag = f" [{note}]" if note else ""
        pdf_rows.append((False, 9,
                         f"{name[:48]:<48} {sc:3d}/100  ({cnt} finding(s)){tag}"))
    pdf_rows.append((True, 10, f"OVERALL - worst test score: {worst}/100"))
    pdf_rows += [(False, 8, ""), (True, 12, "FINDINGS")]
    for sev, msg in findings[:80]:
        pdf_rows.append((False, 9, f"[{sev}] {msg}"))
    if len(findings) > 80:
        pdf_rows.append((False, 9,
                         f"... and {len(findings) - 80} more (see .txt report)"))
    risky = sorted(((cat_scores[key][0], name, fix)
                    for name, key, fix in CATEGORIES if cat_scores[key][0] > 0),
                   reverse=True)
    pdf_rows += [(False, 8, ""), (True, 12, "TOP FIXES (by risk score)")]
    if risky:
        for sc, name, fix in risky:
            pdf_rows.append((False, 9, f"- [{sc}/100] {name}: {fix}"))
    else:
        pdf_rows.append((False, 9, "No high-risk categories detected."))

    pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            f"vuln_report_{ts}.pdf")
    try:
        write_pdf(pdf_path, pdf_rows)
        print(f"[+] PDF report saved: {pdf_path}")
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")

    print(f"\n[+] Report saved: {report_path}")


def main():
    banner()
    check_pin()
    print("Enter the website URL to audit (e.g. example.com):")
    target = input("> ").strip()
    if not target:
        print("No target entered. Exiting.")
        sys.exit(0)
    try:
        run_scan(target)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()
