"""Traffic monitoring + connection snapshots (Stage 5). Read-only.

Interface counters: /proc/net/dev on Linux, `netstat -e` on Windows. Both are
documented system interfaces; no packet capture, no content inspection.
Active connections come from `netstat -ano` — metadata only, never payloads.
"""
import re
import subprocess
import sys
import time


def interface_counters():
    """Returns {iface: (rx_bytes, tx_bytes)} or {'_unsupported': reason}."""
    counters = {}
    if sys.platform != "win32":
        try:
            for line in open("/proc/net/dev"):
                m = re.match(r"\s*(\S+):\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)", line)
                if m:
                    counters[m.group(1)] = (int(m.group(2)), int(m.group(3)))
            if counters:
                return counters
        except OSError:
            pass
    try:
        out = subprocess.run(["netstat", "-e"], capture_output=True, text=True,
                              timeout=20).stdout
        for line in out.splitlines():
            nums = re.findall(r"(\d{4,})", line)
            if len(nums) >= 2 and re.match(r"\s*[\d,]+\s+[\d,]+", line):
                rx = int(nums[0].replace(",", ""))
                tx = int(nums[1].replace(",", ""))
                counters.setdefault("aggregate", (rx, tx))
        return counters or {"_unsupported": "interface counters unavailable on this system"}
    except Exception as e:
        return {"_unsupported": f"interface counters unavailable: {type(e).__name__}"}


def traffic_delta(first, second, iface=None):
    """Bytes transferred between two interface_counters() snapshots."""
    keys = [iface] if iface else [k for k in first if k in second and not k.startswith("_")]
    deltas = {}
    for k in keys:
        r = second[k][0] - first[k][0]
        t = second[k][1] - first[k][1]
        deltas[k] = (max(r, 0), max(t, 0))
    return deltas


def active_connections():
    """Active TCP connections -> [{local, remote, state, pid}]. Metadata only."""
    conns = []
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             timeout=20).stdout
    except Exception:
        try:
            out = subprocess.run(["ss", "-tunp"], capture_output=True, text=True,
                                  timeout=20).stdout
        except Exception:
            return conns
    for line in out.splitlines():
        m = re.match(r"\s*(?:TCP)?\s*([\d.]+:\d+)\s+([\d.]+:\d+)\s+(\S+)\s*(\d+)?", line)
        if m:
            conns.append({"local": m.group(1), "remote": m.group(2),
                          "state": m.group(3).lower(), "pid": m.group(4) or ""})
    return conns


def record_snapshot(db):
    """Store a traffic snapshot as informational event; returns counters."""
    counters = interface_counters()
    db.execute("INSERT INTO security_events (event_type, severity, source, message, details_json) "
               "VALUES ('traffic_snapshot','informational','local','Traffic snapshot recorded',?)",
               (__import__("json").dumps({k: v for k, v in list(counters.items())[:8]}),))
    return counters
