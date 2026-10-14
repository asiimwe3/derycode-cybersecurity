"""Windows Security event log reader (Stage 5). Read-only via wevtutil."""
import re
import subprocess
import sys


def requires_windows():
    return sys.platform != "win32"


def failed_logins(limit=20):
    """EventID 4625 (failed logon). Returns [{time, source, detail}]."""
    if requires_windows():
        return None  # caller must present 'requires_windows'
    cmd = ["wevtutil", "qe", "Security",
           "/q:*[System[(EventID=4625)]]", f"/c:{limit}", "/rd:true", "/f:text"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception:
        return []
    out = []
    for block in r.stdout.split("Event["):
        ip = re.search(r"IpAddress:\s*(\S+)", block)
        t = re.search(r"Date:\s*([0-9\-:T.]+)", block)
        if t:
            out.append({"time": t.group(1),
                        "source": ip.group(1) if ip else "local",
                        "detail": "failed logon (4625)"})
    return out


def record_failed_logins(db):
    """Store observed failed logins as events (source for the brute-force rule)."""
    if requires_windows():
        db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                   "VALUES ('audit_note','informational','local',"
                   "'Failed-logon monitoring requires Windows.')")
        return 0
    rows = failed_logins() or []
    for r in rows:
        db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                   "VALUES ('failed_login','low',?,?)", (r["source"], r["detail"]))
    return len(rows)
