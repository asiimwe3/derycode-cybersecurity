"""API security checks (Stage 3) — bounded, authorized-only.

Inventory + auth-boundary + error-exposure checks. Where a check cannot prove
exploitability it is recorded as 'potential'.
"""
import json
import re
import urllib.error

from secscan.website_checks import fetch

COMMON_API_PATHS = ["/api", "/api/v1", "/v1", "/api/health", "/api/users",
                   "/api/config", "/api/debug", "/swagger.json", "/openapi.json",
                   "/api-docs"]

ERROR_MARKERS = [b"Traceback (most recent call last)", b"at java.base/", b"Warning:",
                 b"stack trace", b"debug_backtrace", b"System.Exception"]


def _finding(title, severity, confidence, evidence, impact, remediation):
    return {"title": title, "severity": severity, "confidence": confidence,
            "category": "api", "evidence": evidence[:1500],
            "impact": impact, "remediation": remediation}


def check_api(base_url, cancel=None, extra_paths=None):
    findings = []
    base = base_url.rstrip("/")
    discovered = []

    # 1. Endpoint inventory (bounded probe of common paths + any user-supplied ones)
    paths = COMMON_API_PATHS + list(extra_paths or [])
    for p in paths:
        if cancel is not None and cancel.is_set():
            raise InterruptedError("scan cancelled")
        try:
            s, h, b = fetch(base + p, cancel=cancel)
            ct = (h.get("Content-Type") or "")
            if s == 200 and ("json" in ct.lower() or b.startswith(b"{") or b.startswith(b"[")):
                discovered.append(p)
                # 2. Authentication requirement: anonymous 200 with data may be an issue
                looks_sensitive = re.search(rb'"(email|token|phone|secret|password|key)"',
                                            b, re.I)
                if looks_sensitive:
                    findings.append(_finding(
                        f"API returns sensitive-looking data without authentication: {p}",
                        "high", "potential",
                        f"Anonymous GET {base}{p} -> 200, keys matched: {looks_sensitive.group(1)!r}",
                        "Unauthenticated users may read sensitive records.",
                        "Require authentication and validate object-level authorization."))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                continue  # properly protected — good
        except InterruptedError:
            raise
        except Exception:
            continue

    # 3. OpenAPI/Swagger exposure
    for doc in ("/swagger.json", "/openapi.json", "/api-docs"):
        try:
            s, h, b = fetch(base + doc, cancel=cancel)
            if s == 200:
                findings.append(_finding(
                    f"API documentation publicly accessible: {doc}", "medium", "potential",
                    f"Anonymous GET {base}{doc} -> 200 ({len(b)} bytes)",
                    "Full endpoint map exposed to attackers.",
                    "Restructure or protect API documentation in production."))
        except Exception:
            continue

    # 4. Unsafe error messages
    try:
        s, h, b = fetch(base + "/api/nonexistent-probe-xyz", cancel=cancel)
        for marker in ERROR_MARKERS:
            if marker.lower() in b.lower():
                findings.append(_finding(
                    "API returns verbose/unsafe error output", "medium", "potential",
                    f"404-probe response contained {marker!r}",
                    "Stack traces reveal framework versions, paths and logic.",
                    "Return generic errors; disable debug output in production."))
                break
    except Exception:
        pass

    if not discovered:
        findings.append(_finding("No JSON API endpoints found on common paths",
                                 "informational", "confirmed",
                                 "Probed common API paths; none returned JSON.",
                                 "", "If an API exists, provide its endpoint list for review."))
    findings.append({"title": f"API endpoint inventory: {len(discovered)} discovered",
                    "severity": "informational", "confidence": "confirmed",
                    "category": "api-inventory",
                    "evidence": json.dumps(discovered)[:1500],
                    "impact": "", "remediation": ""})
    return findings
