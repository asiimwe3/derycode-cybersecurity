"""Scan engine (Stage 3): authorization gate, progress, cancellation, audit."""
import threading

from core.scope_manager import UnauthorizedTargetError
from secscan import website_checks, api_checks, source_code_audit, dependency_audit

MODULES = {
    "website_checks": ("Website security checks",
                       lambda db, asset, cancel: website_checks.check_website(asset["target"], cancel)),
    "api_checks": ("API security checks",
                   lambda db, asset, cancel: api_checks.check_api(asset["target"], cancel)),
    "source_code_audit": ("Source code audit",
                          lambda db, asset, cancel: source_code_audit.audit_source(asset["target"], cancel)),
    "dependency_audit": ("Dependency audit",
                         lambda db, asset, cancel: dependency_audit.audit_manifest(asset["target"], False)[0]),
}


class ScanRunner:
    """Runs selected modules against an authorized asset. Blocking; call in a worker."""

    def __init__(self, db, scope, asset_id, modules, progress=None):
        self.db = db
        self.scope = scope
        self.asset_id = asset_id
        self.modules = [m for m in modules if m in MODULES]
        self.progress = progress or (lambda pct, msg: None)
        self.cancel = threading.Event()

    def run(self):
        asset = self.scope.assert_authorized(self.asset_id)  # gate — raises if unauthorized
        self.db.audit("scan.start", target=asset["target"],
                      details={"modules": self.modules})
        self.db.execute(
            "INSERT INTO scans (asset_id, module, status) VALUES (?,?, 'running')",
            (self.asset_id, "+".join(self.modules)))
        scan_id = self.db.scalar("SELECT MAX(id) FROM scans")
        total = max(len(self.modules), 1)
        results, failed = [], []
        for i, key in enumerate(self.modules):
            if self.cancel.is_set():
                break
            label, fn = MODULES[key]
            self.progress(int(i * 100 / total), f"Running {label}…")
            try:
                findings = fn(self.db, asset, self.cancel)
                for f in findings:
                    self.db.execute(
                        "INSERT INTO findings (scan_id, title, severity, confidence, category, "
                        "evidence, impact, remediation) VALUES (?,?,?,?,?,?,?,?)",
                        (scan_id, f["title"], f["severity"], f["confidence"],
                         f.get("category", ""), f.get("evidence", ""),
                         f.get("impact", ""), f.get("remediation", "")))
                results.extend(findings)
            except InterruptedError:
                break
            except Exception as e:  # one module failing never kills the scan
                failed.append(f"{key}: {type(e).__name__}")
        cancelled = self.cancel.is_set()
        status = "cancelled" if cancelled else ("completed" if not failed else "completed")
        self.db.execute("UPDATE scans SET status = ?, finished_at = datetime('now') "
                        "WHERE id = ?", (status, scan_id))
        self.db.audit("scan.end", target=asset["target"],
                      details={"scan_id": scan_id, "status": status,
                               "findings": len(results), "module_errors": failed})
        self.progress(100, "Scan finished." if not cancelled else "Scan cancelled.")
        return {"scan_id": scan_id, "status": status, "findings": results,
                "module_errors": failed, "asset": asset}
