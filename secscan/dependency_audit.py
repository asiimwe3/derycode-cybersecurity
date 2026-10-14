"""Dependency audit (Stage 4).

Works offline against a bundled advisory snapshot; optionally refreshes from the
OSV API only when the user has given explicit consent in Settings. If the online
lookup is unavailable, reports clearly that intelligence could not be refreshed.
"""
import json
import re
import urllib.request

# Offline advisory snapshot: widely-known CVEs for common packages.
# Each entry: package, affected range string, CVE, severity, patched version, ref.
ADVISORIES = [
    ("requests", "<2.31.0", "CVE-2023-32681", "medium", "2.31.0",
     "https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q"),
    ("django", "<4.2.8", "CVE-2023-46695", "high", "4.2.8",
     "https://docs.djangoproject.com/en/stable/releases/security/"),
    ("pillow", "<10.3.0", "CVE-2023-50252", "high", "10.3.0",
     "https://osv.dev/vulnerability/GHSA-3f63-hfp8-52jq"),
    ("pyyaml", "<5.4", "CVE-2020-14343", "critical", "5.4",
     "https://osv.dev/vulnerability/GHSA-8q2v-4v8x-82j5"),
    ("cryptography", "<42.0.4", "CVE-2024-26130", "high", "42.0.4",
     "https://osv.dev/vulnerability/GHSA-h4gh-ggpy-cng2"),
    ("urllib3", "<1.26.17", "CVE-2023-43804", "high", "1.26.17",
     "https://osv.dev/vulnerability/GHSA-g5mx-j8w2-6jx8"),
    ("flask", "<2.2.5", "CVE-2023-30861", "medium", "2.2.5",
     "https://osv.dev/vulnerability/GHSA-4ffj-3g6q-h758"),
    ("jinja2", "<3.1.3", "CVE-2024-22195", "medium", "3.1.3",
     "https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95"),
    ("werkzeug", "<2.3.8", "CVE-2023-46136", "medium", "2.3.8",
     "https://osv.dev/vulnerability/GHSA-447j-wfjg-9hvp"),
    ("setuptools", "<65.5.1", "CVE-2022-40897", "high", "65.5.1",
     "https://osv.dev/vulnerability/GHSA-hcpj-75p5-h336"),
    ("aiohttp", "<3.9.4", "CVE-2024-30251", "high", "3.9.4",
     "https://osv.dev/vulnerability/GHSA-4c8r-74qp-hFR2"),
]

VER_RE = re.compile(r"[vV]?(\d+(?:\.\d+)*)")


def _version_tuple(v):
    m = VER_RE.search(v or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)


def _in_range(installed, rng):
    """Supports '<x.y.z' style ranges used in the snapshot."""
    rng = rng.strip()
    if rng.startswith("<="):
        return _version_tuple(installed) <= _version_tuple(rng[2:])
    if rng.startswith("<"):
        return _version_tuple(installed) < _version_tuple(rng[1:])
    return False


def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=~><!]*\s*(.*)$", line)
        if m:
            out.append((m.group(1).lower().replace("_", "-"), m.group(2).strip()))
    return out


def parse_package_json(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = {}
    deps.update(data.get("dependencies") or {})
    deps.update(data.get("devDependencies") or {})
    return [(k.lower(), v.lstrip("^~>=")) for k, v in deps.items()]


def _lookup_osv(package, version, timeout=10):
    """Optional online refresh (only called with user consent). Returns advisory dicts."""
    payload = json.dumps({"package": {"name": package, "ecosystem": "PyPI"},
                          "version": version}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    return data.get("vulns", [])


def audit_manifest(manifest_path, allow_online=False):
    """Returns (findings, notes). findings use the standard finding-dict shape."""
    findings, notes = [], []
    path = manifest_path.lower()
    try:
        text = open(manifest_path, encoding="utf-8", errors="ignore").read()
    except OSError as e:
        return [], [f"Could not read manifest: {e}"]
    if path.endswith("package.json"):
        deps = parse_package_json(text)
        ecosystem = "npm"
    else:
        deps = parse_requirements(text)
        ecosystem = "PyPI"

    for name, version in deps:
        for pkg, rng, cve, sev, patched, ref in ADVISORIES:
            if pkg == name and version and _in_range(version, rng):
                findings.append({
                    "title": f"Vulnerable dependency: {name} {version}",
                    "severity": sev, "confidence": "confirmed", "category": "dependency",
                    "evidence": f"{name} {version} affected by {rng} ({cve})",
                    "impact": f"Known vulnerability {cve} in {name} {version}.",
                    "remediation": f"Upgrade {name} to {patched} or later. Ref: {ref}"})
        if allow_online:
            try:
                for v in _lookup_osv(name, version or "0"):
                    findings.append({
                        "title": f"OSV: {name} {version} — {v.get('id', 'unknown')}",
                        "severity": "medium", "confidence": "potential",
                        "category": "dependency",
                        "evidence": json.dumps(v.get("summary", ""))[:300],
                        "impact": v.get("summary", ""),
                        "remediation": "Upgrade per the advisory."})
            except Exception as e:
                notes.append(f"OSV lookup failed for {name}: {type(e).__name__}; "
                             f"dependency intelligence could not be refreshed online.")
    if not allow_online:
        notes.append("Offline advisory snapshot used. Enable 'online dependency lookup' "
                     "in Settings to refresh intelligence from the OSV database.")
    return findings, notes
