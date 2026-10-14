"""Device discovery (Stage 5) — read-only, for networks the admin has approved.

Uses the OS ARP table (no raw packets), optional bounded ping sweep of an
explicitly approved subnet, hostname resolution, and records new devices.
"""
import ipaddress
import re
import socket
import subprocess
import threading

WIN = False
try:
    import sys
    WIN = sys.platform == "win32"
except Exception:
    pass


def arp_table():
    """Parse the system ARP table -> list of dicts {ip, mac, iface}."""
    rows = []
    if WIN:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:\-]{17})\s+(\S+)\s*(\S*)", line)
            if m and m.group(2) != "ff:ff:ff:ff:ff:ff":
                rows.append({"ip": m.group(1), "mac": m.group(2).lower().replace("-", ":"),
                             "iface": m.group(4) or ""})
    else:
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True,
                                  timeout=20).stdout
        except Exception:
            out = subprocess.run(["arp", "-n"], capture_output=True, text=True,
                                  timeout=20).stdout
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", line)
            if m:
                rows.append({"ip": m.group(1), "mac": m.group(2), "iface": ""})
    return rows


def resolve_hostname(ip, timeout=2):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError):
        return ""


def ping(ip):
    """Bounded single ping. Returns True if host answers."""
    flag = "-n" if WIN else "-c"
    timeout = "-w" if WIN else "-W"
    tval = "1500" if WIN else "2"
    cmd = ["ping", flag, "1", timeout, tval, str(ip)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        return (r.returncode == 0 or "TTL=" in r.stdout or "ttl=" in r.stdout.lower())
    except Exception:
        return False


def ping_sweep(cidr, max_hosts=64, cancel=None, progress=None):
    """Threaded sweep of an EXPLICITLY approved subnet. Caps at max_hosts."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()][:max_hosts]
    alive = []
    lock = threading.Lock()

    def worker(ip):
        if cancel is not None and cancel.is_set():
            return
        if ping(ip):
            with lock:
                alive.append(ip)
                if progress:
                    progress(len(alive), ip)

    threads = [threading.Thread(target=worker, args=(ip,), daemon=True) for ip in hosts]
    for t in threads[:32]:
        t.start()
        t.join()          # conservative: at most 32 concurrent pings
    return alive


def sync_devices(db, discovered, source="arp"):
    """Upsert devices; flag brand-new ones and record a security event."""
    new_devices = []
    for dev in discovered:
        ip, mac = dev["ip"], dev.get("mac", "")
        existing = db.query_one("SELECT id FROM network_devices WHERE ip = ? AND mac = ?",
                                 (ip, mac))
        if existing:
            db.execute("UPDATE network_devices SET last_seen = datetime('now') WHERE id = ?",
                       (existing["id"],))
        else:
            db.execute("INSERT OR IGNORE INTO network_devices (ip, mac, notes) VALUES (?,?,?)",
                       (ip, mac, f"first seen via {source}"))
            did = db.query_one("SELECT id FROM network_devices WHERE ip = ? AND mac = ?",
                               (ip, mac))
            if did:
                new_devices.append((did["id"], ip))
    for did, ip in new_devices:
        db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                   "VALUES ('new_device','low',?, 'New device appeared on the network')", (ip,))
    return new_devices
