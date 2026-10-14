"""Source code security audit (Stage 3). Local only — code never leaves the machine."""
import os
import re

MAX_FILE = 1_000_000          # skip files larger than 1 MB
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist",
             "build", ".idea", ".vscode", "site-packages"}
TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".php", ".rb",
            ".go", ".cs", ".c", ".cpp", ".h", ".sh", ".ps1", ".env", ".yml",
            ".yaml", ".json", ".xml", ".sql", ".ini", ".conf", ".properties"}

import functools  # noqa
PATTERNS = [
    (r"-----BEGIN (RSA |EC |PGP |OPENSSH )?PRIVATE KEY-----", "critical", "confirmed",
     "Private key committed to source",
     "Anyone with repository access can use the key. Remove it, rotate, and purge history."),
    (r"AKIA[0-9A-Z]{16}", "critical", "confirmed",
     "AWS access key committed to source",
     "Leaked cloud credentials. Revoke the key immediately and rotate."),
    (r"AIza[0-9A-Za-z_\-]{35}", "high", "potential",
     "Google API key committed to source",
     "Verify the key's restrictions; rotate if unrestricted."),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"\\s]{6,}['\"]", "high", "potential",
     "Hardcoded password in source",
     "Move the secret to an environment variable or secret manager."),
    (r"(?i)(secret|api[_-]?key|token)\s*[=:]\s*['\"][A-Za-z0-9+/_\-]{16,}['\"]",
     "high", "potential", "Hardcoded secret/API key in source",
     "Move the secret to an environment variable or secret manager."),
]
SQLI_RE = re.compile(
    r"""(?i)\b(execute|executemany|query)\s*\(\s*f?['"].*\b(select|insert|update|delete|drop)\b.*(['"]\s*\+|['"]\s*%|\.format\(|\{)""")
XSS_RE = re.compile(r"""(?i)(innerHTML|document\.write)\s*[=(]\s*[^'"]*['"`]?\s*(?:\+|window\.|location|params|req\.|\$\{)""")
SHELL_RE = re.compile(r"""(?i)(shell\s*=\s*True|os\.system\s*\(|eval\s*\(|pickle\.loads\s*\()""")
INSECURE_FS_RE = re.compile(r"""(?i)(chmod\s*777|tempfile\.mktemp\(|open\s*\([^)]*['"]w['"][^)]*\.\.)""")


def _finding(title, severity, confidence, category, evidence, impact, remediation):
    return {"title": title, "severity": severity, "confidence": confidence,
            "category": category, "evidence": evidence[:600],
            "impact": impact, "remediation": remediation}


def _mask(text):
    """Keep evidence useful but never reproduce a full secret."""
    if len(text) <= 12:
        return text
    return text[:6] + "…MASKED…" + text[-4:]


def audit_source(path, cancel=None):
    findings = []
    seen = set()
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if cancel is not None and cancel.is_set():
                raise InterruptedError("scan cancelled")
            fp = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            if ext not in TEXT_EXT:
                continue
            try:
                if os.path.getsize(fp) > MAX_FILE:
                    continue
                text = open(fp, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(fp, path)
            for lineno, line in enumerate(text.splitlines(), 1):
                for rx, sev, conf, title, fix in PATTERNS:
                    m = re.search(rx, line)
                    if m:
                        key = (title, rel)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(_finding(
                            f"{title} ({rel}:{lineno})", sev, conf, "secrets",
                            f"{rel}:{lineno}: {_mask(m.group(0))}", "", fix))
                if SQLI_RE.search(line):
                    findings.append(_finding(
                        f"SQL injection risk in {rel}:{lineno}", "high", "potential",
                        "sql-injection", f"{rel}:{lineno}: {_mask(line.strip())}",
                        "Untrusted input concatenated into a query can alter database actions.",
                        "Use parameterized queries."))
                if XSS_RE.search(line):
                    findings.append(_finding(
                        f"Cross-site scripting risk in {rel}:{lineno}", "high", "potential",
                        "xss", f"{rel}:{lineno}: {_mask(line.strip())}",
                        "Unencoded input written to the DOM executes attacker script.",
                        "Encode output; use safe DOM APIs."))
                if SHELL_RE.search(line):
                    findings.append(_finding(
                        f"Dangerous dynamic execution in {rel}:{lineno}", "high", "potential",
                        "dangerous-exec", f"{rel}:{lineno}: {_mask(line.strip())}",
                        "Shell injection / arbitrary code execution risk.",
                        "Avoid shell=True and eval; validate all inputs."))
                if INSECURE_FS_RE.search(line):
                    findings.append(_finding(
                        f"Insecure file handling in {rel}:{lineno}", "medium", "potential",
                        "file-security", f"{rel}:{lineno}: {_mask(line.strip())}",
                        "World-writable files or unsafe temp paths can be abused.",
                        "Use restrictive permissions and tempfile.mkstemp."))
    return findings
