"""Website security checks (Stage 3). Real HTTP requests, conservative rate limits.

Only run against assets approved by the ScopeManager. Every check returns a finding
dict: title, severity, confidence, category, evidence, impact, remediation.
'potential' is used whenever a check cannot prove exploitability.
"""
import re
import socket
import ssl
import time
import urllib.request
import urllib.error

from datetime import date

USER_AGENT = "DerycodeCyberSecurity/1.0 (authorized assessment)"
MIN_INTERVAL = 0.4  # seconds between requests — conservative by default

SECURITY_HEADERS = [
    ("strict-transport-security", "high", "No HTTP Strict Transport Security (HSTS)."),
    ("content-security-policy", "medium", "No Content-Security-Policy header."),
    ("x-content-type-options", "low", "No X-Content-Type-Options: nosniff."),
    ("x-frame-options", "medium", "No clickjacking protection (X-Frame-Options / CSP frame-ancestors)."),
    ("referrer-policy", "low", "No Referrer-Policy header."),
]

BACKUP_PATHS = ["/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql", "/site.zip",
                "/.env", "/config.php.bak", "/config.bak", "/web.config.bak",
                "/database.sql", "/backup/"]

INFO_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

MIXED_RE = re.compile(r'(?:src|href)\s*=\s*["\']http://', re.I)


class _Limiter:
    def __init__(self):
        self._last = 0.0

    def wait(self):
        delta = time.time() - self._last
        if delta < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - delta)
        self._last = time.time()


def fetch(url, timeout=10, method="GET", data=None, cancel=None):
    """Single safe request. Raises urllib errors to the caller; checks cancel flag."""
    if cancel is not None and cancel.is_set():
        raise InterruptedError("scan cancelled")
    lim = _Limiter()
    lim.wait()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        body = r.read(2_000_000)  # cap body read
        return r.status, dict(r.headers), body


def _finding(title, severity, confidence, category, evidence, impact, remediation):
    return {"title": title, "severity": severity, "confidence": confidence,
            "category": category, "evidence": evidence[:2000],
            "impact": impact, "remediation": remediation}


def check_website(url, cancel=None):
    """Run all website checks. Returns list of finding dicts (may be empty)."""
    findings = []
    url = url if url.startswith("http") else "https://" + url
    base = url.rstrip("/")

    # 1. HTTPS availability
    try:
        status, headers, body = fetch(base, cancel=cancel)
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers), b""
    except Exception as e:
        return [_finding(f"Target unreachable: {type(e).__name__}", "informational",
                        "confirmed", "availability", str(e),
                        "Assessment could not proceed.",
                        "Verify the URL and network, then rerun.")]

    if not base.startswith("https://"):
        findings.append(_finding("HTTPS not used for initial request", "high", "confirmed",
                                "transport", f"Requested URL used plain HTTP: {base}",
                                "Traffic can be intercepted or modified.",
                                "Redirect all HTTP to HTTPS and enable HSTS."))

    # 2. TLS certificate validity
    host = urllib.request.urlparse(base).hostname
    if base.startswith("https://"):
        try:
            import datetime
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    not_after = tls.getpeercert()["notAfter"]
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 21:
                findings.append(_finding(f"TLS certificate expires in {max(days_left,0)} days",
                                         "low" if days_left > 0 else "critical", "confirmed",
                                         "tls", f"cert expires {not_after}",
                                         "Expired or soon-expiring certificates break security and trust.",
                                         "Renew the certificate before expiry."))
        except Exception:
            findings.append(_finding("TLS certificate check failed", "low", "potential",
                                     "tls", f"Could not validate certificate for {host}",
                                     "Certificate may be missing, expired or self-signed.",
                                     "Install a valid certificate (e.g. Let's Encrypt)."))

    # 3. Security headers
    lower = {k.lower(): v for k, v in headers.items()}
    for header, sev, msg in SECURITY_HEADERS:
        if header not in lower:
            findings.append(_finding(msg, sev, "potential", "headers",
                                      f"response for {base} lacks '{header}'",
                                      "Missing hardening header increases attack surface.",
                                      f"Add the '{header}' response header."))

    # 4. Cookie security attributes
    for name, value in headers.items():
        if name.lower() == "set-cookie":
            attrs = value.lower()
            missing = [a for a in ("secure", "httponly") if a not in attrs]
            if missing:
                sev = "high" if "httponly" in missing else "medium"
                findings.append(_finding(
                    f"Cookie without {'/'.join(missing)}", sev, "confirmed", "cookies",
                    value[:200], "Cookie may be stolen via XSS or plaintext interception.",
                    f"Set the {', '.join(missing)} attribute on all cookies."))

    # 5. Mixed content
    try:
        text = body.decode("utf-8", "ignore")
        n = len(MIXED_RE.findall(text))
        if n and base.startswith("https://"):
            findings.append(_finding(f"Mixed content: {n} insecure subresource reference(s)",
                                    "medium", "confirmed", "transport",
                                    MIXED_RE.search(text).group(0) if n else "",
                                    "Page loads resources over plain HTTP.",
                                    "Serve all subresources over HTTPS."))
    except Exception:
        pass

    # 6. Exposed backup/config files & directory listing (bounded probe)
    for path in BACKUP_PATHS:
        if cancel is not None and cancel.is_set():
            raise InterruptedError("scan cancelled")
        try:
            s, h, b = fetch(base + path, cancel=cancel)
            if s == 200 and len(b) > 0:
                head = b[:200].lstrip().lower()
                ctype = (h.get("Content-Type") or "").lower()
                # SPA catch-all: server returns the app shell (HTML) for every
                # path. That is NOT the requested file — downgrade, never confirm.
                if head.startswith((b"<!doctype", b"<html")) or "text/html" in ctype:
                    continue
                if path in ("/.env",):
                    sev, conf = "critical", "confirmed"
                elif path.endswith((".sql", ".zip", ".tar.gz",)):
                    sev, conf = "critical", "confirmed"
                else:
                    sev, conf = "high", "potential"
                findings.append(_finding(
                    f"Publicly accessible sensitive file: {path}", sev, conf, "exposure",
                    f"GET {base}{path} returned HTTP {s}, {len(b)} bytes",
                    "Backups and config files often contain credentials or data.",
                    "Remove the file from the web root and restrict access."))
        except urllib.error.HTTPError:
            continue
        except InterruptedError:
            raise
        except Exception:
            continue

    # 7. Directory listing
    try:
        s, h, b = fetch(base + "/", cancel=cancel)
        if re.search(rb"<title>Index of", b, re.I):
            findings.append(_finding("Directory listing enabled", "medium", "confirmed",
                                    "misconfig", "Server generated a directory index.",
                                    "Exposes file names and structure.",
                                    "Disable directory listing (Options -Indexes)."))
    except Exception:
        pass

    # 8. Information disclosure
    for hname in INFO_HEADERS:
        if hname in lower:
            findings.append(_finding(f"Server technology disclosed in '{hname}' header",
                                    "informational", "confirmed", "disclosure",
                                    f"{hname}: {lower[hname]}",
                                    "Helps attackers target known weaknesses.",
                                    "Suppress version/technology headers."))

    return findings
