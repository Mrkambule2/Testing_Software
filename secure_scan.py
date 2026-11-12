"""
Authorized Security Exposure Scanner (read-only)
==================================================
Runs from USB. PIN-gated. Designed for authorized testers only.

What it does (all GET/HEAD requests, no exploitation, no writes to target):
  * HTTP security header review
  * TLS certificate summary (expiry, issuer, weak protocol flags)
  * Checks for accidentally exposed sensitive files (.env, .git, backups, config, etc.)
  * Scans public HTML/JS for leaked secrets (API keys, tokens, private keys, passwords)
  * Cookie flag review
  * Plain HTTP -> HTTPS redirect check
  * Optional: port scan of common ports (TCP connect only) + exposed service banners

It NEVER attempts login, brute force, injection, or file upload.
It only reports findings to help the team strengthen security.

Usage:  python secure_scan.py  (or double-click RUN_SCAN.bat)
Python 3.9+ required, standard library only (no pip install needed).
"""

import concurrent.futures
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PIN = "0012246060086"
REQUEST_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "10"))   # seconds per request
MAX_BODY_BYTES = int(os.environ.get("SCAN_MAX_BODY", str(2_000_000)))
MAX_FILES_TO_SCAN = int(os.environ.get("SCAN_MAX_FILES", "60"))  # HTML/JS files to scan
USER_AGENT = "AuthorizedExposureScanner/1.0 (security assessment; read-only)"

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/hgrc",
    "/config.php", "/config.yml", "/config.yaml", "/config.json", "/settings.py",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.swp", "/wp-config.bak",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/backup.sql", "/db.sql", "/database.sql", "/dump.sql", "/backup.zip", "/backup.tar.gz",
    "/admin/", "/administrator/", "/phpmyadmin/", "/adminer.php", "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/api/swagger.json", "/swagger.json", "/openapi.json", "/api-docs",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/package.json", "/composer.json", "/yarn.lock", "/package-lock.json",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/phpinfo.php", "/info.php", "/test.php", "/debug/", "/trace",
    "/.DS_Store", "/Thumbs.db",
    "/docker-compose.yml", "/Dockerfile", "/.docker/config.json",
    "/.npmrc", "/.pypirc", "/.aws/credentials",
]

# name, regex, severity, description
SECRET_PATTERNS = [
    ("AWS Access Key ID",        r"\bAKIA[0-9A-Z]{16}\b", "HIGH"),
    ("AWS Secret Key (context)", r"(?i)aws.{0,20}secret.{0,5}['\"]([A-Za-z0-9/+=]{40})['\"]", "HIGH"),
    ("Google API Key",           r"\bAIza[0-9A-Za-z_\-]{35}\b", "HIGH"),
    ("Google OAuth Client ID",   r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "MEDIUM"),
    ("GitHub Token",             r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b", "HIGH"),
    ("GitLab Token",             r"\bglpat-[0-9A-Za-z_\-]{20}\b", "HIGH"),
    ("Slack Token",              r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "HIGH"),
    ("Stripe Live Key",          r"\b[sr]k_live_[0-9A-Za-z]{16,}\b", "HIGH"),
    ("Twilio API Key",           r"\bSK[0-9a-f]{32}\b", "MEDIUM"),
    ("SendGrid API Key",         r"\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b", "HIGH"),
    ("JWT",                      r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "MEDIUM"),
    ("Private Key Block",        r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----", "CRITICAL"),
    ("Generic API Key assignment", r"(?i)['\"]?(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"][0-9A-Za-z_\-]{16,}['\"]", "MEDIUM"),
    ("Hardcoded password",       r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", "MEDIUM"),
    ("Database Connection String", r"(?i)(mongodb(\+srv)?|mysql|postgres(ql)?|redis)://[^\s'\"]+:[^\s'\"]+@", "HIGH"),
    ("Bearer Token",             r"(?i)bearer\s+[0-9A-Za-z_\-\.]{20,}", "MEDIUM"),
    ("Email address",            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "INFO"),
]

EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS missing - browsers can be downgraded to HTTP",
    "content-security-policy": "CSP missing - increases XSS impact",
    "x-frame-options": "Clickjacking protection missing (use X-Frame-Options or CSP frame-ancestors)",
    "x-content-type-options": "X-Content-Type-Options missing - MIME sniffing possible",
    "referrer-policy": "Referrer-Policy missing - URLs may leak to third parties",
    "permissions-policy": "Permissions-Policy missing - camera/mic/geolocation not restricted",
}
SECURE_COOKIE_FLAGS = ["secure", "httponly", "samesite"]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 2049, 2375, 3000, 3306, 3389, 4444, 5000, 5432, 5601,
                5900, 6379, 8000, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
                11211, 27017, 27018, 50000]

BANNER_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3",
                143: "IMAP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
                27017: "MongoDB", 2375: "Docker API", 8080: "HTTP-alt", 8443: "HTTPS-alt"}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def banner(text=""):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def _read_secret(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    print(prompt, end="", flush=True)
    return sys.stdin.readline().strip()


def verify_pin():
    for attempt in range(3):
        pin = _read_secret("Enter access PIN: ")
        if pin == PIN:
            print("Access granted.\n")
            return True
        remaining = 2 - attempt
        print(f"Incorrect PIN. {remaining} attempt(s) left." if remaining else "Access denied.")
    return False


def confirm_authorization(target):
    print("\n" + "!" * 78)
    print("AUTHORIZED TESTING ONLY")
    print("!" * 78)
    print(f"Target: {target}")
    print("This tool performs READ-ONLY checks (GET/HEAD requests, TCP connect)")
    print("against systems you are authorized to test. It does not exploit,")
    print("crack, modify, or damage anything.")
    ans = input("\nType 'I AM AUTHORIZED' to continue: ").strip()
    return ans == "I AM AUTHORIZED"


def normalize_target(raw):
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlsplit(raw)
    if not parsed.hostname:
        return None
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}://{parsed.hostname}{port}", parsed.hostname


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(follow_redirects=True):
    handlers = [] if follow_redirects else [NoRedirect()]
    handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return urllib.request.build_opener(*handlers)


def http_get(url, method="GET", max_bytes=MAX_BODY_BYTES, opener=None):
    """Returns dict(status, headers, body_bytes, final_url, error). Never raises."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT,
                                                              "Accept": "*/*"})
    opener = opener or make_opener()
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read(max_bytes)
            return {"status": resp.status, "headers": dict(resp.headers.items()),
                    "body": body, "final_url": resp.geturl(), "error": None}
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(max_bytes)
        except Exception:
            pass
        return {"status": e.code, "headers": dict(e.headers.items()) if e.headers else {},
                "body": body, "final_url": url, "error": str(e.reason)}
    except Exception as e:
        return {"status": None, "headers": {}, "body": b"", "final_url": url, "error": str(e)}


def head_ok(url):
    r = http_get(url, method="HEAD", max_bytes=0)
    if r["status"] is not None:
        return r["status"]
    return http_get(url, method="GET", max_bytes=0)["status"]


def severity(sev):
    return sev in ("CRITICAL", "HIGH")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
class Findings:
    def __init__(self):
        self.items = []

    def add(self, category, sev, title, detail, evidence=""):
        ev = evidence.strip().replace("\n", " ")
        if len(ev) > 200:
            ev = ev[:197] + "..."
        self.items.append({"category": category, "severity": sev, "title": title,
                           "detail": detail, "evidence": ev})

    def summary(self):
        counts = {}
        for i in self.items:
            counts[i["severity"]] = counts.get(i["severity"], 0) + 1
        return counts


def check_redirect(base, host, findings):
    http_url = f"http://{host}/"
    r = http_get(http_url, max_bytes=0, opener=make_opener(follow_redirects=False))
    if r["status"] is None:
        findings.add("HTTPS", "MEDIUM", "HTTP not reachable", f"http://{host}/ did not respond: {r['error']}")
        return
    loc = r["headers"].get("Location", "")
    if 300 <= (r["status"] or 0) < 400 and loc.lower().startswith("https://"):
        findings.add("HTTPS", "INFO", "HTTP redirects to HTTPS", f"{http_url} -> {loc}")
    elif r["status"] == 200:
        findings.add("HTTPS", "MEDIUM", "Site served over plain HTTP",
                     "No redirect to HTTPS. Credentials/data can be sent in clear text.")
    else:
        findings.add("HTTPS", "LOW", f"HTTP returns {r['status']}", f"No HTTPS redirect observed at {http_url}")


def check_headers(base, findings):
    r = http_get(base + "/", max_bytes=0)
    if r["status"] is None:
        findings.add("Headers", "HIGH", "Site unreachable", f"{base}: {r['error']}")
        return None
    headers = {k.lower(): v for k, v in r["headers"].items()}
    for h, desc in EXPECTED_HEADERS.items():
        if h not in headers:
            findings.add("Headers", "MEDIUM", f"Missing header: {h}", desc)
    server = headers.get("server", "")
    if server:
        findings.add("Headers", "INFO", f"Server header disclosed: {server}",
                     "Version info can help attackers target known vulnerabilities.")
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.add("Headers", "LOW", f"X-Powered-By disclosed: {powered}", "Reveals backend technology.")
    if "set-cookie" in headers or "Set-Cookie" in r["headers"]:
        raw = r["headers"].get("Set-Cookie") or r["headers"].get("set-cookie") or ""
        cookies = [c.strip() for c in raw.split("\n") if c.strip()]
        if not cookies:
            # headers dict may have collapsed multiple cookies
            cookies = [v for k, v in r["headers"].items() if k.lower() == "set-cookie"]
        for c in cookies[:10]:
            name = c.split("=", 1)[0]
            flags = {f for f in SECURE_COOKIE_FLAGS if re.search(rf"(?i)(^|;\s*){f}\b", c)}
            missing = [f for f in SECURE_COOKIE_FLAGS if f not in flags]
            if missing:
                findings.add("Cookies", "MEDIUM", f"Cookie '{name}' missing flags: {', '.join(missing).upper()}",
                             f"Cookie: {c[:150]}")
    return r


def check_tls(host, findings):
    if not host:
        return
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
        not_after = cert.get("notAfter")
        if not_after:
            exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days = (exp - dt.datetime.now(dt.timezone.utc)).days
            if days < 0:
                findings.add("TLS", "CRITICAL", "TLS certificate EXPIRED", f"Expired {abs(days)} days ago ({not_after}).")
            elif days < 30:
                findings.add("TLS", "HIGH", f"TLS certificate expires in {days} days", not_after)
            else:
                findings.add("TLS", "INFO", f"TLS certificate valid until {not_after}", cert.get("subject", [[("?", "?")]])[0][0][1])
        san = cert.get("subjectAltName", [])
        findings.add("TLS", "INFO", f"TLS protocol: {proto}, cipher: {cipher[0] if cipher else '?'}",
                     f"SANs: {len(san)} name(s)")
        if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.add("TLS", "HIGH", f"Deprecated TLS protocol in use: {proto}", "Support TLS 1.2+ only.")
    except ssl.SSLCertVerificationError as e:
        findings.add("TLS", "CRITICAL", "TLS certificate verification FAILED", str(e))
    except Exception as e:
        findings.add("TLS", "LOW", "TLS check skipped", str(e))


def check_sensitive_paths(base, findings):
    def probe(path):
        url = base + path
        r = http_get(url, max_bytes=4096)
        return path, r

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for fut in concurrent.futures.as_completed([ex.submit(probe, p) for p in SENSITIVE_PATHS]):
            results.append(fut.result())
            time.sleep(0.05)

    for path, r in sorted(results, key=lambda x: x[0]):
        if r["status"] is None:
            continue
        body = r["body"].decode("utf-8", errors="replace")
        low = body[:500].lower()
        # Filter out soft-404s
        if r["status"] == 200 and any(x in low for x in ("not found", "page not found", "404", "does not exist")) and len(body) < 800:
            continue
        interesting = path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
        if r["status"] == 200 and (interesting or path not in ("/admin/", "/administrator/", "/phpmyadmin/", "/debug/")):
            sev = "HIGH" if any(k in path for k in (".env", ".git", ".sql", "backup", "config", "credential", "htpasswd", ".npmrc", ".pypirc", ".aws")) else "MEDIUM"
            if "actuator/heapdump" in path or "server-status" in path or "phpinfo" in path:
                sev = "HIGH"
            findings.add("Exposed Files", sev, f"Publicly accessible: {path}",
                         f"HTTP {r['status']}, {len(r['body'])} bytes returned. Review whether this should be public.",
                         body[:300])
        elif r["status"] in (401, 403):
            findings.add("Exposed Files", "INFO", f"Protected (good): {path}", f"HTTP {r['status']} - access denied.")

    # robots.txt disallowed paths of interest
    robots = http_get(base + "/robots.txt", max_bytes=100_000)
    if robots["status"] == 200:
        text = robots["body"].decode("utf-8", errors="replace")
        disallowed = re.findall(r"(?im)^\s*disallow:\s*(\S+)", text)
        sensitive = [d for d in disallowed if re.search(r"(?i)(admin|backup|config|\.sql|\.env|private|secret|api|test|dev|staging|debug|tmp|temp|log)", d)]
        if sensitive:
            findings.add("Info Disclosure", "LOW", "robots.txt reveals sensitive paths",
                         "; ".join(sensitive[:15]), text[:500])


def extract_links(base, html, limit=30):
    links = set()
    for m in re.finditer(r'''(?:src|href)=["']([^"']+)["']''', html, re.I):
        u = urllib.parse.urljoin(base, m.group(1))
        p = urllib.parse.urlsplit(u)
        if p.netloc == urllib.parse.urlsplit(base).netloc and re.search(r"\.(js|mjs|css|json|html?)(\?|$)", p.path, re.I):
            links.add(u.split("#")[0])
    return sorted(links)[:limit]


def scan_secrets(base, findings):
    start = http_get(base + "/", max_bytes=MAX_BODY_BYTES)
    pages = [start]
    html = start["body"].decode("utf-8", errors="replace") if start["body"] else ""
    for link in extract_links(base, html):
        if len(pages) >= MAX_FILES_TO_SCAN:
            break
        r = http_get(link, max_bytes=MAX_BODY_BYTES)
        if r["status"] == 200 and r["body"]:
            pages.append(r)
            # also grab JS-referenced chunks one level deep for HTML pages
            if re.search(r"\.html?$", urllib.parse.urlsplit(link).path, re.I):
                sub_html = r["body"].decode("utf-8", errors="replace")
                for sub in extract_links(base, sub_html, limit=10):
                    if len(pages) >= MAX_FILES_TO_SCAN:
                        break
                    s = http_get(sub, max_bytes=MAX_BODY_BYTES)
                    if s["status"] == 200 and s["body"]:
                        pages.append(s)

    seen = set()
    for r in pages:
        url = r["final_url"]
        text = r["body"].decode("utf-8", errors="replace")
        for name, pattern, sev in SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                match = m.group(0)
                # Skip obvious placeholders/examples
                if re.search(r"(?i)(your[_-]|example|sample|xxx|placeholder|<|>|\*|changeme|dummy|test[_-]?key)", match):
                    continue
                # Redact long secrets in report
                redacted = match if len(match) <= 12 else match[:6] + "..." + match[-4:]
                fp = hashlib.sha1((url + name + redacted).encode()).hexdigest()[:10]
                if fp in seen:
                    continue
                seen.add(fp)
                findings.add("Secrets in Public Files", sev, f"{name} found in {url}",
                             f"Possible {name} exposed. Verify and rotate if real. Snippet: {redacted}")

    # inline source maps / .git exposure via common files
    for extra in ("/.git/HEAD", "/.env", "/config.json", "/appsettings.json", "/api/config"):
        r = http_get(base + extra, max_bytes=200_000)
        if r["status"] == 200 and r["body"]:
            text = r["body"].decode("utf-8", errors="replace")
            for name, pattern, sev in SECRET_PATTERNS:
                for m in re.finditer(pattern, text):
                    match = m.group(0)
                    if re.search(r"(?i)(your[_-]|example|sample|xxx|placeholder|<|>|\*|changeme)", match):
                        continue
                    redacted = match if len(match) <= 12 else match[:6] + "..." + match[-4:]
                    findings.add("Secrets in Public Files", sev, f"{name} found in {base + extra}",
                                 f"Snippet: {redacted}")


def port_scan(host, findings, ports=COMMON_PORTS):
    open_ports = []

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(probe, ports):
            if res:
                open_ports.append(res)

    findings.add("Network", "INFO", f"{len(open_ports)} common ports open on {host}",
                 ", ".join(map(str, sorted(open_ports))) or "none")

    # Banner grab only for known-risk services (single connection, no brute force)
    for p in sorted(open_ports):
        if p in (22, 21, 23, 25, 110, 143):
            try:
                s = socket.create_connection((host, p), timeout=3)
                s.settimeout(3)
                try:
                    s.sendall(b"\r\n")
                except Exception:
                    pass
                banner_data = s.recv(256).decode("utf-8", errors="replace").strip()
                s.close()
                if banner_data:
                    svc = BANNER_PORTS.get(p, str(p))
                    sev = "HIGH" if p in (23, 21, 110, 143) else "LOW"
                    findings.add("Network", sev, f"{svc} banner on port {p}",
                                 banner_data[:160], banner_data[:200])
            except Exception:
                pass

    risky = {6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached", 2375: "Docker"}
    for p, name in risky.items():
        if p in open_ports:
            findings.add("Network", "CRITICAL", f"{name} exposed on port {p}",
                         "Database/cache service reachable from network. Ensure it is firewalled and requires auth.")
    if 3389 in open_ports:
        findings.add("Network", "MEDIUM", "RDP (3389) exposed", "Restrict via VPN/IP allowlist; ensure NLA and strong passwords.")
    if 23 in open_ports:
        findings.add("Network", "HIGH", "Telnet (23) open", "Telnet is unencrypted. Disable or replace with SSH.")


def check_mixed_content(base, findings):
    if not base.startswith("https"):
        return
    r = http_get(base + "/", max_bytes=MAX_BODY_BYTES)
    if not r["body"]:
        return
    text = r["body"].decode("utf-8", errors="replace")
    insecure = re.findall(r'''(?:src|href)\s*=\s*["']http://[^"']+["']''', text, re.I)
    if insecure:
        findings.add("HTTPS", "LOW", f"{len(insecure)} mixed-content (http://) references on HTTPS page",
                     "; ".join(insecure[:5]))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_findings(findings):
    banner("FINDINGS SUMMARY")
    counts = findings.summary()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(f"  {sev:<9}: {counts.get(sev, 0)}")
    print()
    order = {s: i for i, s in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))}
    for f in sorted(findings.items, key=lambda x: (order[x["severity"]], x["category"])):
        print(f"[{f['severity']:<8}] ({f['category']}) {f['title']}")
        print(f"           {f['detail']}")
        if f["evidence"]:
            print(f"           Evidence: {f['evidence']}")
        print()


def save_report(findings, target, outdir):
    os.makedirs(outdir, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    path = os.path.join(outdir, f"scan_report_{safe}_{ts}.txt")
    counts = findings.summary()
    lines = [
        "AUTHORIZED SECURITY EXPOSURE SCAN REPORT",
        "=" * 60,
        f"Target:     {target}",
        f"Date (UTC): {dt.datetime.now(dt.timezone.utc).isoformat()}Z",
        f"Tool:       secure_scan.py v1.0 (read-only)",
        "Findings:   " + ", ".join(f"{k}={v}" for k, v in counts.items()),
        "",
        "NOTE: This report lists publicly observable information only. No",
        "exploitation, brute force, or modification was performed.",
        "",
    ]
    order = {s: i for i, s in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))}
    for f in sorted(findings.items, key=lambda x: (order[x["severity"]], x["category"])):
        lines += [f"[{f['severity']}] ({f['category']}) {f['title']}",
                  f"    {f['detail']}"]
        if f["evidence"]:
            lines.append(f"    Evidence: {f['evidence']}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    banner("AUTHORIZED SECURITY EXPOSURE SCANNER")
    print("Read-only checks for authorized testing. No cracking or destruction.")

    if not verify_pin():
        sys.exit(1)

    raw = input("\nEnter website URL or software host/IP to scan: ").strip()
    norm = normalize_target(raw)
    if not norm:
        print("Invalid target.")
        sys.exit(1)
    base, host = norm
    if base.endswith("/"):
        base = base[:-1]

    # Resolve host once to avoid repeated DNS lookups and reject malformed input
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        try:
            socket.getaddrinfo(host, None)
        except socket.gaierror:
            print(f"Could not resolve host: {host}")
            sys.exit(1)

    if not confirm_authorization(f"{base} (host: {host})"):
        print("Cancelled.")
        sys.exit(0)

    run_ports = input("\nRun port scan of common ports? [y/N]: ").strip().lower() == "y"

    findings = Findings()
    t0 = time.time()

    banner(f"1/6 HTTPS redirect & headers  ->  {base}")
    r = check_headers(base, findings)
    check_redirect(base, host, findings)

    banner(f"2/6 TLS certificate  ->  {host}:443")
    check_tls(host, findings)

    banner("3/6 Sensitive file exposure checks")
    check_sensitive_paths(base, findings)

    banner("4/6 Secret leakage scan (HTML/JS/config)")
    scan_secrets(base, findings)

    banner("5/6 Mixed content check")
    check_mixed_content(base, findings)

    if run_ports:
        banner(f"6/6 Port scan (common ports)  ->  {host}")
        port_scan(host, findings)
    else:
        banner("6/6 Port scan skipped")

    elapsed = time.time() - t0
    banner(f"SCAN COMPLETE in {elapsed:.1f}s")
    print_findings(findings)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(script_dir, "reports")
    path = save_report(findings, raw, report_dir)
    print(f"\nReport saved to: {path}")

    counts = findings.summary()
    if counts.get("CRITICAL") or counts.get("HIGH"):
        print("\nACTION REQUIRED: Critical/High findings need remediation.")
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(130)
