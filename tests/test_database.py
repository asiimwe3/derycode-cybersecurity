"""Stage 1 tests: schema, CRUD, stats, backup, demo fixtures."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.database import Database, hash_password, verify_password


def fresh_db(tmp_path):
    return Database(tmp_path / "test.db")


def test_schema_migrates_idempotently(tmp_path):
    db = fresh_db(tmp_path)
    first = db.migrate()          # already applied in __init__ -> no-op
    assert first is False
    db.close()
    db2 = Database(tmp_path / "test.db")   # reopen same file
    assert db2.scalar("SELECT COUNT(*) FROM settings") >= 0
    db2.close()


def test_password_hashing_roundtrip():
    salt, digest = hash_password("S3cret-pass!")
    assert "S3cret-pass!" not in digest and salt not in digest
    assert verify_password("S3cret-pass!", salt, digest)
    assert not verify_password("wrong", salt, digest)


def test_authentication_and_wrong_password(tmp_path):
    db = fresh_db(tmp_path)
    db.create_user("admin", "hunter2hunter2")
    assert db.authenticate("admin", "hunter2hunter2") is not None
    assert db.authenticate("admin", "nope") is None
    assert db.authenticate("ghost", "x") is None      # unknown user, constant-work
    db.close()


def test_assets_scans_findings_and_stats(tmp_path):
    db = fresh_db(tmp_path)
    db.execute("INSERT INTO assets (name, asset_type, target, authorization_status) "
               "VALUES ('Demo site','website','https://demo.test','approved')")
    aid = db.scalar("SELECT id FROM assets")
    db.execute("INSERT INTO scans (asset_id, module, status, finished_at) "
               "VALUES (?, 'website_checks', 'completed', datetime('now'))", (aid,))
    sid = db.scalar("SELECT MAX(id) FROM scans WHERE asset_id = ?", (aid,))
    for sev, conf in [("critical", "confirmed"), ("high", "potential")]:
        db.execute("INSERT INTO findings (scan_id, title, severity, confidence) "
                   "VALUES (?, 't', ?, ?)", (sid, sev, conf))
    s = db.dashboard_stats()
    assert s["assets"] == 1
    assert s["scans_completed"] == 1
    assert s["findings_confirmed"] == 1
    assert s["findings_potential"] == 1
    assert s["critical_high"] == 2
    assert s["severity_breakdown"]["critical"] == 1
    assert s["demo_mode"] is False
    db.close()


def test_backup_creates_working_copy(tmp_path):
    db = fresh_db(tmp_path)
    db.execute("INSERT INTO assets (name, asset_type, target) VALUES ('x','website','https://x.test')")
    dest = db.backup(tmp_path / "backups")
    assert dest.exists()
    check = Database(dest)
    assert check.scalar("SELECT COUNT(*) FROM assets") == 1
    check.close()
    db.close()


def test_audit_log_written(tmp_path):
    db = fresh_db(tmp_path)
    db.audit("test.action", user_id=None, target="t1", details={"k": 1})
    row = db.query_one("SELECT action, target, details_json FROM audit_logs")
    assert row["action"] == "test.action" and '"k": 1' in row["details_json"]
    db.close()
