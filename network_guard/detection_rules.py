"""Detection rules (Stage 5). Every rule reports what it can actually observe,
and states 'potential' when activity is merely unusual — never automatically malicious.
Inputs: recorded security events, netstat connection snapshots, traffic deltas.
"""
import ipaddress


def rule_repeated_failed_auth(db, window_minutes=15, threshold=5):
    """Windows Security log 4625 events, if the host is Windows and readable."""
    rows = db.query(
        "SELECT source, COUNT(*) n FROM security_events WHERE event_type = 'failed_login' "
        "AND created_at >= datetime('now', ?) GROUP BY source HAVING n >= ?",
        (f'-{window_minutes} minutes', threshold))
    for r in rows:
        db.execute("INSERT INTO security_events (event_type, severity, source, message, details_json) "
                   "VALUES ('auth_bruteforce_suspected','high',?,?,?)",
                   (r["source"], f"{r['n']} failed logins in {window_minutes} minutes — "
                    "possible brute force; investigate before assuming an attack.",
                    __import__("json").dumps({"count": r["n"]})))


def rule_admin_service_access(db, protected_ports=(3389, 22, 3306, 5900)):
    """Remote connections aimed at administrative services (from netstat data)."""
    conns = db.query("SELECT source, message FROM security_events "
                     "WHERE event_type = 'connection'")
    admin = [(c["source"], c["message"]) for c in conns
             if any(f":{p}" in (c["message"] or "") for p in protected_ports)]
    for src, detail in admin:
        db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                   "VALUES ('admin_service_access','high',?,?)",
                   (src, f"Connection to administrative service observed: {detail}. "
                         "Verify it is an authorized administrator."))


def rule_malicious_destinations(db):
    """Compare recorded remote endpoints against the flagged-destination list."""
    flagged = db.query("SELECT value FROM settings WHERE key LIKE 'flagged_dest%'")
    flagged = [f["value"] for f in flagged]
    if not flagged:
        return 0
    hits = 0
    for c in db.query("SELECT source, message FROM security_events "
                      "WHERE event_type = 'connection'"):
        remote = c["message"] or ""
        for bad in flagged:
            if bad and bad in remote:
                db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                           "VALUES ('malicious_destination_suspected','high',?,?)",
                           (c["source"], f"Connection matches flagged destination {bad}."))
                hits += 1
    return hits


def rule_traffic_spike(db, deltas, threshold_mb=200):
    """Flag unexpected traffic spikes from snapshot deltas (bytes)."""
    for iface, (rx, tx) in (deltas or {}).items():
        total_mb = (rx + tx) / (1024 * 1024)
        if total_mb > threshold_mb:
            db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                       "VALUES ('traffic_spike','medium','local',?)",
                       (f"{iface}: {total_mb:.0f} MB in window — unusual volume; "
                        "confirm it is expected activity.",))


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def run_all(db, deltas=None):
    """Run every rule against recorded data. Returns number of new alerts raised."""
    before = db.scalar("SELECT COUNT(*) FROM security_events WHERE severity IN ('high','critical')")
    rule_repeated_failed_auth(db)
    rule_admin_service_access(db)
    rule_malicious_destinations(db)
    rule_traffic_spike(db, deltas)
    after = db.scalar("SELECT COUNT(*) FROM security_events WHERE severity IN ('high','critical')")
    return after - before
