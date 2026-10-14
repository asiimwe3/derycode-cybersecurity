"""Windows computer security audit (Stage 5). Read-only, documented interfaces.

Uses PowerShell/CIM and netsh via subprocess. On non-Windows systems every check
reports 'requires_windows' — the app never fakes a Windows audit result.
"""
import subprocess
import sys


def _ps(cmd, timeout=25):
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip() if r.returncode == 0 else None


def requires_windows():
    return sys.platform != "win32"


def audit_system():
    """Returns dict of real checks (or explicit 'requires_windows' markers)."""
    result = {}
    if requires_windows():
        for key in ("os", "defender", "firewall", "services", "admins",
                    "software", "updates"):
            result[key] = {"status": "requires_windows",
                           "detail": "This module runs on Windows only."}
        return result

    result["os"] = {"detail": _ps("Get-CimInstance Win32_OperatingSystem | "
                                  "Select-Object Caption,Version,LastBootUpTime | "
                                  "ConvertTo-Json")}
    result["updates"] = {"detail": _ps("(Get-HotFix | Sort-Object InstalledOn -Descending "
                                       "| Select-Object -First 5 | ConvertTo-Json)")}
    result["defender"] = {"detail": _ps("Get-MpComputerStatus | "
                                        "Select-Object AMServiceEnabled, "
                                        "RealTimeProtectionEnabled, "
                                        "AntivirusSignatureLastUpdated | ConvertTo-Json")}
    result["firewall"] = {"detail": _ps("netsh advfirewall show allprofiles state")}
    result["services"] = {"detail": _ps("Get-Service | Where-Object "
                                       "{$_.Status -eq 'Running'} | Measure-Object | "
                                       "Select-Object Count | ConvertTo-Json")}
    result["admins"] = {"detail": _ps("Get-LocalGroupMember Administrators | "
                                      "Select-Object Name | ConvertTo-Json")}
    result["software"] = {"detail": _ps("(Get-ItemProperty HKLM:\\Software\\"
                                        "Microsoft\\Windows\\CurrentVersion\\"
                                        "Uninstall\\* | Select-Object DisplayName, "
                                        "DisplayVersion | ConvertTo-Json)")}
    return result


def findings_from(audit):
    """Turn audit output into honest finding dicts."""
    findings = []
    if audit.get("os", {}).get("status") == "requires_windows":
        return [{"title": "Windows security audit requires Windows",
                 "severity": "informational", "confidence": "confirmed",
                 "category": "host-audit",
                 "evidence": "Module skipped: not running on Windows.",
                 "impact": "", "remediation": "Run on the Windows host to audit it."}]
    import json as _json

    def _try_load(v):
        try:
            return _json.loads(v)
        except Exception:
            return v

    defender = _try_load((audit.get("defender") or {}).get("detail") or "")
    if isinstance(defender, dict):
        if defender.get("RealTimeProtectionEnabled") is False:
            findings.append({"title": "Real-time antivirus protection disabled",
                             "severity": "critical", "confidence": "confirmed",
                             "category": "host-audit", "evidence": str(defender),
                             "impact": "Malware is not blocked in real time.",
                             "remediation": "Enable real-time protection."})
        sig = defender.get("AntivirusSignatureLastUpdated")
        if sig:
            findings.append({"title": f"Antivirus signatures last updated: {sig}",
                             "severity": "informational", "confidence": "confirmed",
                             "category": "host-audit", "evidence": str(defender),
                             "impact": "", "remediation": "Keep signatures current."})
    fw = (audit.get("firewall") or {}).get("detail") or ""
    if "OFF" in fw.upper():
        findings.append({"title": "Windows Firewall disabled for at least one profile",
                         "severity": "high", "confidence": "confirmed",
                         "category": "host-audit", "evidence": fw[:500],
                         "impact": "Host is directly exposed to network attacks.",
                         "remediation": "Enable the firewall on all profiles."})
    admins = _try_load((audit.get("admins") or {}).get("detail") or "")
    if isinstance(admins, list) and len(admins) > 3:
        findings.append({"title": f"{len(admins)} local administrator accounts",
                         "severity": "low", "confidence": "potential",
                         "category": "host-audit",
                         "evidence": ", ".join(str(a.get("Name", a)) for a in admins)[:500],
                         "impact": "More privileged accounts increase attack surface.",
                         "remediation": "Review and remove unneeded administrators."})
    return findings
