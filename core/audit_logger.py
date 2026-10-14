"""Audit logger — routes application events to the audit table and console."""
import json
import time


class AuditLogger:
    """Thin wrapper so modules log consistently (DB audit + console + optional file)."""

    def __init__(self, db, console=None):
        self.db = db
        self.console = console

    def log(self, action, user_id=None, target="", details=None, kind="info"):
        details = details or {}
        self.db.audit(action, user_id=user_id, target=target, details=details)
        if self.console is not None:
            self.console.log(f"AUDIT {action} target={target} {json.dumps(details)[:80]}", kind)
