"""Firewall integration (Stage 7) — read-only by default.

Windows: netsh advfirewall. Linux: ufw/iptables. Disruptive actions REQUIRE
explicit admin confirmation from the UI AND elevated OS privileges; the caller
must pass confirm=True, which the UI only sets after a confirmation dialog.
"""
import os
import subprocess
import sys


def is_elevated():
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        return r.returncode, r.stdout or r.stderr
    except Exception as e:
        return 1, f"command failed: {type(e).__name__}"


def status():
    """Read-only firewall configuration review."""
    if sys.platform == "win32":
        code, out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    else:
        code, out = _run(["ufw", "status", "verbose"])
        if code != 0:
            code, out = _run(["iptables", "-L", "-n", "--line-numbers"])
        if code != 0:
            return "unsupported", ("Firewall status could not be read on this system. "
                                    "On Windows this uses 'netsh advfirewall'.")
    return ("ok" if code == 0 else "error"), out


def add_block_rule(ip, confirm=False, name="Derycode-Block"):
    """Block a verified malicious destination. Refuses without confirmation."""
    if not confirm:
        return False, "Administrator confirmation required — refusing to change firewall."
    if not is_elevated():
        return False, ("Elevated (administrator) privileges are required to modify the "
                       "firewall. Rerun the app as administrator.")
    if sys.platform == "win32":
        code, out = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                          f"name={name}-{ip}", "dir=out", "action=block",
                          f"remoteip={ip}", "enable=yes"])
    else:
        code, out = _run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
    return code == 0, out
