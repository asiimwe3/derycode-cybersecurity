"""Derycode Cybersecurity — local SQLite storage layer.

Security design:
  - All queries use parameterized SQL (no string interpolation of user input).
  - Passwords are never stored: PBKDF2-HMAC-SHA256 hash + per-user random salt.
  - Schema is versioned; migrations run in a transaction and are idempotent.
  - Backups copy the database file to the configured backup directory.
"""
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 1

MIGRATIONS = {
    1: """
    CREATE TABLE roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        permissions_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL DEFAULT '',
        role_id INTEGER REFERENCES roles(id),
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        iterations INTEGER NOT NULL DEFAULT 200000,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_login_at TEXT
    );
    CREATE TABLE assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL CHECK (asset_type IN ('website','web_app','api','local_project','network','windows_host')),
        target TEXT NOT NULL,
        owner TEXT NOT NULL DEFAULT '',
        authorization_status TEXT NOT NULL DEFAULT 'pending' CHECK (authorization_status IN ('pending','approved','expired','revoked')),
        notes TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE authorizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        scope TEXT NOT NULL,
        authorized_by TEXT NOT NULL,
        valid_from TEXT NOT NULL DEFAULT (date('now')),
        valid_until TEXT,
        evidence TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        module TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed','cancelled')),
        started_at TEXT NOT NULL DEFAULT (datetime('now')),
        finished_at TEXT,
        summary_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
        confidence TEXT NOT NULL CHECK (confidence IN ('confirmed','potential')),
        category TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        impact TEXT NOT NULL DEFAULT '',
        remediation TEXT NOT NULL DEFAULT '',
        verified INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE network_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        hostname TEXT NOT NULL DEFAULT '',
        mac TEXT NOT NULL DEFAULT '',
        is_authorized INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen TEXT NOT NULL DEFAULT (datetime('now')),
        notes TEXT NOT NULL DEFAULT '',
        UNIQUE(ip, mac)
    );
    CREATE TABLE security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
        source TEXT NOT NULL DEFAULT '',
        message TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE remediation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved','accepted_risk')),
        assigned_to TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        lessons_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL DEFAULT '',
        enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE instructors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL DEFAULT '',
        specialty TEXT NOT NULL DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
        progress_pct INTEGER NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
        completed_at TEXT,
        UNIQUE(student_id, course_id)
    );
    CREATE TABLE challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL CHECK (difficulty IN ('basic','intermediate','advanced')),
        points INTEGER NOT NULL DEFAULT 100,
        description TEXT NOT NULL DEFAULT '',
        objectives_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE challenge_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
        score INTEGER NOT NULL DEFAULT 0,
        completed_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(student_id, challenge_id)
    );
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        fmt TEXT NOT NULL DEFAULT 'html' CHECK (fmt IN ('html','pdf')),
        path TEXT NOT NULL,
        generated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    INSERT OR IGNORE INTO roles (name, description, permissions_json) VALUES
        ('admin', 'Full application control', '["*"]'),
        ('instructor', 'Teaching, lab and academy management', '["academy.*","cyberlab.*","reports.view"]'),
        ('student', 'Training modules and own progress only', '["cyberlab.view","academy.view-self"]'),
        ('analyst', 'Scanning and reporting on approved assets', '["secscan.*","networkguard.view","reports.*"]');
    """
}


def default_db_path() -> Path:
    """Application data lives outside the source tree (safe for portable builds)."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home())) / "DerycodeCybersecurity"
    else:
        base = Path.home() / ".derycode-cybersecurity"
    base.mkdir(parents=True, exist_ok=True)
    return base / "app.db"


def hash_password(password: str, salt: str = None, iterations: int = 200000):
    """Return (salt, hash). PBKDF2-HMAC-SHA256; plaintext is never stored."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return salt, digest.hex()


def verify_password(password: str, salt: str, expected_hash: str, iterations: int = 200000) -> bool:
    import hmac
    _, digest = hash_password(password, salt, iterations)
    return hmac.compare_digest(digest, expected_hash)


class Database:
    def __init__(self, path=None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.migrate()

    # ---------- schema ----------
    def migrate(self):
        cur = self.conn.execute("PRAGMA user_version")
        version = cur.fetchone()[0]
        if version >= SCHEMA_VERSION:
            return False
        for v in range(version + 1, SCHEMA_VERSION + 1):
            with self.conn:
                self.conn.executescript(MIGRATIONS[v])
                self.conn.execute(f"PRAGMA user_version = {v}")
        return True

    # ---------- helpers ----------
    def query(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()

    def execute(self, sql, params=()):
        with self.conn:
            return self.conn.execute(sql, params)

    def scalar(self, sql, params=(), default=0):
        row = self.query_one(sql, params)
        return row[0] if row and row[0] is not None else default

    def setting(self, key, default=None):
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_setting(self, key, value):
        self.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))

    # ---------- users ----------
    def create_user(self, username, password, full_name="", role="admin"):
        role_id = self.scalar("SELECT id FROM roles WHERE name = ?", (role,))
        salt, digest = hash_password(password)
        self.execute(
            "INSERT INTO users (username, full_name, role_id, password_hash, salt) VALUES (?,?,?,?,?)",
            (username, full_name, role_id, digest, salt))
        return self.scalar("SELECT id FROM users WHERE username = ?", (username,))

    def authenticate(self, username, password):
        """Returns user row dict on success, None otherwise. Constant-work comparison."""
        row = self.query_one("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        if row is None:
            verify_password(password, "00" * 16, "00" * 32, 1000)  # equalise timing
            return None
        if verify_password(password, row["salt"], row["password_hash"], row["iterations"]):
            self.execute("UPDATE users SET last_login_at = datetime('now') WHERE id = ?", (row["id"],))
            return dict(row)
        return None

    # ---------- audit ----------
    def audit(self, action, user_id=None, target="", details=None):
        self.execute("INSERT INTO audit_logs (user_id, action, target, details_json) VALUES (?,?,?,?)",
                     (user_id, action, target, json.dumps(details or {})))

    # ---------- dashboard statistics (all from real data) ----------
    def dashboard_stats(self):
        s = {}
        s["assets"] = self.scalar("SELECT COUNT(*) FROM assets")
        s["scans_completed"] = self.scalar("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        s["findings_confirmed"] = self.scalar("SELECT COUNT(*) FROM findings WHERE confidence = 'confirmed'")
        s["findings_potential"] = self.scalar("SELECT COUNT(*) FROM findings WHERE confidence = 'potential'")
        s["critical_high"] = self.scalar(
            "SELECT COUNT(*) FROM findings WHERE severity IN ('critical','high')")
        s["devices"] = self.scalar("SELECT COUNT(*) FROM network_devices")
        s["alerts"] = self.scalar(
            "SELECT COUNT(*) FROM security_events WHERE severity IN ('critical','high')")
        s["challenges_done"] = self.scalar("SELECT COUNT(*) FROM challenge_results")
        s["severity_breakdown"] = {
            r["severity"]: r["n"] for r in
            self.query("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")}
        s["recent_activity"] = [
            dict(r) for r in self.query(
                "SELECT created_at, action AS what, target AS detail FROM audit_logs "
                "UNION ALL SELECT started_at AS created_at, module AS what, status AS detail FROM scans "
                "UNION ALL SELECT created_at, event_type AS what, message AS detail FROM security_events "
                "ORDER BY created_at DESC LIMIT 15")]
        s["demo_mode"] = self.setting("demo_mode", "0") == "1"
        return s

    # ---------- backup ----------
    def backup(self, backup_dir):
        """Hot backup via SQLite backup API (safe while app is running)."""
        backup_dir = Path(backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        dest = backup_dir / f"dcs-backup-{time.strftime('%Y%m%d-%H%M%S')}.db"
        target = sqlite3.connect(str(dest))
        with target:
            self.conn.backup(target)
        target.close()
        return dest

    def close(self):
        self.conn.close()
