"""GUI tests run headless with QT_QPA_PLATFORM=offscreen."""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication
from core.database import Database
from ui.main_window import MainWindow
from core.permissions import load_user


def admin(db, tmp=None):
    db.create_user("tester", "password123", role="admin")
    return load_user(db, "tester", "password123")


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_shell_and_dashboard(qapp, tmp_path):
    db = Database(tmp_path / "gui.db")
    user = admin(db)
    win = MainWindow(db, user)
    assert win.windowTitle().startswith("DERYCODE CYBERSECURITY")
    assert win.stack.count() >= 10         # all sections have views
    for key in win._nav_buttons:
        if key in win.allowed:
            win.switch(key)
    win.switch("overview")
    dash = win.views["overview"]
    assert dash.card_assets._value.text() == "0"
    db.close()


def test_dashboard_reflects_real_data(qapp, tmp_path):
    db = Database(tmp_path / "gui2.db")
    db.execute("INSERT INTO assets (name, asset_type, target) VALUES ('a','website','https://a.test')")
    db.execute("INSERT INTO security_events (event_type, severity, source, message) "
               "VALUES ('e','high','s','m')")
    win = MainWindow(db, admin(db))
    win.switch("overview")
    dash = win.views["overview"]
    assert dash.card_assets._value.text() == "1"
    assert dash.card_alerts._value.text() == "1"
    assert dash.demo_badge.isHidden()
    db.close()


def test_demo_seed_flags_badge(qapp, tmp_path):
    from main import seed_demo
    db = Database(tmp_path / "gui3.db")
    seed_demo(db)
    win = MainWindow(db, admin(db))
    win.switch("overview")
    assert not win.views["overview"].demo_badge.isHidden()
    db.close()
