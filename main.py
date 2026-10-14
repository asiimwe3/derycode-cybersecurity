"""Derycode Cybersecurity — entry point.

Usage:
  python main.py                 normal start (real, empty database)
  python main.py --demo-seed     seed clearly-labelled demonstration data (evaluation/testing)
  python main.py --create-admin <user> <password>   bootstrap a first admin account
"""
import argparse
import sys

from PySide6.QtWidgets import QApplication

from core.database import Database, default_db_path
from ui.main_window import MainWindow
from ui.theme import STYLESHEET

DEMO_NOTE = ("Demo data is clearly labelled in every table row; "
             "demo records never represent real findings.")


def seed_demo(db):
    """Safe demonstration fixtures — labelled as demo, used for evaluation and tests."""
    db.set_setting("demo_mode", "1")
    db.audit("demo.seed", target="demo fixtures", details={"note": DEMO_NOTE})
    db.execute("INSERT OR IGNORE INTO assets (name, asset_type, target, owner, authorization_status, notes) "
               "VALUES ('Derycode Academy Test Server [DEMO]', 'website', 'https://demo.derycode.test', "
               "'Derycode Organization', 'approved', 'demo fixture')")
    asset_id = db.scalar("SELECT id FROM assets WHERE target = 'https://demo.derycode.test'")
    for module, n_findings in [("website_checks", 3), ("source_code_audit", 2), ("api_checks", 1)]:
        db.execute("INSERT INTO scans (asset_id, module, status, finished_at) VALUES (?,?,?,datetime('now'))",
                   (asset_id, module, "completed"))
        scan_id = db.scalar("SELECT MAX(id) FROM scans WHERE asset_id = ? AND module = ?", (asset_id, module))
        demo_findings = [
            ("Missing Content-Security-Policy [DEMO]", "medium", "confirmed"),
            ("TLS certificate expires in 21 days [DEMO]", "low", "confirmed"),
            ("Outdated jQuery 3.4.1 [DEMO]", "medium", "potential"),
            ("Hardcoded test API key in config.py [DEMO]", "critical", "confirmed"),
            ("Reflected input possible in search form [DEMO]", "high", "potential"),
            ("Verbose error messages from API [DEMO]", "low", "confirmed"),
            ("Admin endpoint accessible without auth [DEMO]", "critical", "confirmed"),
        ][:n_findings]
        for title, sev, conf in demo_findings:
            db.execute("INSERT INTO findings (scan_id, title, severity, confidence) VALUES (?,?,?,?)",
                        (scan_id, title, sev, conf))
    for ip, mac, note in [("192.168.10.2", "aa:bb:cc:00:00:02", "cafe workstation [DEMO]"),
                          ("192.168.10.3", "aa:bb:cc:00:00:03", "cafe workstation [DEMO]"),
                          ("192.168.10.254", "aa:bb:cc:00:00:ff", "cafe router [DEMO]")]:
        db.execute("INSERT OR IGNORE INTO network_devices (ip, mac, is_authorized, notes) VALUES (?,?,1,?)",
                   (ip, mac, note))
    db.execute("INSERT INTO security_events (event_type, severity, source, message) VALUES "
               "('repeated_failed_logins','high','192.168.10.9 [DEMO]','12 failed SSH attempts in 5 minutes')")


def main():
    parser = argparse.ArgumentParser(description="Derycode Cybersecurity")
    parser.add_argument("--db", default=str(default_db_path()), help="database file path")
    parser.add_argument("--demo-seed", action="store_true",
                        help="seed clearly-labelled demonstration data for evaluation/testing")
    parser.add_argument("--create-admin", nargs=2, metavar=("USER", "PASSWORD"))
    args = parser.parse_args()

    db = Database(args.db)
    if args.create_admin:
        uid = db.create_user(args.create_admin[0], args.create_admin[1], role="admin",
                             full_name="Administrator")
        db.audit("user.create_admin", user_id=uid, target=args.create_admin[0])
        print(f"Admin '{args.create_admin[0]}' created.")
        db.close()
        return
    if args.demo_seed:
        seed_demo(db)

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    window = MainWindow(db)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
