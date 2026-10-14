"""Application shell: sidebar navigation, console dock, honest status LED.

Every section now hosts a real view; access is gated by role permissions.
"""
import sys

from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (QApplication, QDockWidget, QHBoxLayout, QLabel,
                               QMainWindow, QMessageBox, QPushButton,
                               QScrollArea, QStackedWidget, QStatusBar,
                               QVBoxLayout, QWidget)

from ui.dashboard import DashboardView
from ui.theme import MUTED, NEON, STYLESHEET
from ui.widgets import Console, ModulePlaceholder, StatusLed

SECTIONS = [
    # (key, label, permission, stage-note shown only if a view cannot load)
    ("overview", "Overview", "dashboard.view", 1),
    ("secscan", "SecScan", "secscan.view", 3),
    ("networkguard", "Network Guard", "networkguard.view", 5),
    ("cyberlab", "CyberLab", "cyberlab.view", 6),
    ("academy", "Academy", "academy.view", 6),
    ("reports", "Vulnerability Reports", "reports.view", 4),
    ("events", "Security Events", "networkguard.view", 5),
    ("inventory", "Device Inventory", "networkguard.view", 5),
    ("settings", "Settings", "settings.view", 2),
    ("audit", "Audit Logs", "audit.view", 2),
]

VIEW_BUILDERS = {}


class MainWindow(QMainWindow):
    def __init__(self, db, user, app_name="DERYCODE CYBERSECURITY"):
        super().__init__()
        self.db = db
        self.user = user
        self.setWindowTitle(f"{app_name} — Build. Learn. Test. Defend.")
        self.resize(1280, 800)
        self.setMinimumSize(QSize(1024, 640))

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- sidebar ----
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)
        sbar = QVBoxLayout(sidebar)
        sbar.setContentsMargins(10, 6, 10, 12)
        sbar.setSpacing(2)
        brand = QLabel("DERYCODE")
        brand.setObjectName("Brand")
        tag = QLabel("CYBERSECURITY")
        tag.setObjectName("BrandTag")
        sbar.addWidget(brand)
        sbar.addWidget(tag)
        self._nav_buttons = {}
        from core.permissions import user_can
        self.allowed = set()
        for key, label, perm, stage in SECTIONS:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            if user_can(self.user, perm):
                btn.clicked.connect(lambda _, k=key: self.switch(k))
                self.allowed.add(key)
            else:
                btn.setEnabled(False)
                btn.setToolTip("Your role does not grant access to this module.")
            sbar.addWidget(btn)
            self._nav_buttons[key] = btn
        sbar.addStretch(1)
        who = QLabel(f"{user['username']} · {user.get('role', 'user')}")
        who.setObjectName("Muted")
        sbar.addWidget(who)
        root.addWidget(sidebar)

        # ---- pages ----
        self.console = Console()
        self.stack = QStackedWidget()
        self.views = {}
        self._build_views()
        root.addWidget(self.stack, 1)

        # ---- console dock ----
        dock = QDockWidget("OPERATIONS CONSOLE", self)
        dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetClosable)
        dock.setWidget(self.console)
        self.addDockWidget(Qt.BottomDockWidgetArea, dock)
        self.console.log(f"signed in as {user['username']} ({user.get('role')})", "ok")
        self.console.log(f"database: {db.path}", "ok")

        # ---- status bar ----
        status = QStatusBar()
        self.led = StatusLed()
        status.addWidget(self.led)
        self.status_ready = QLabel("READY")
        status.addWidget(self.status_ready)
        status.addPermanentWidget(QLabel(f"db: {db.path.name}"))
        self.setStatusBar(status)
        self.set_busy(False)

        first = next((k for k, *_ in SECTIONS if k in self.allowed), None)
        if first:
            self.switch(first)
        else:
            QMessageBox.warning(self, "No access",
                                 "Your role has no accessible modules. Contact an admin.")

    def _build_views(self):
        from ui.dashboard import DashboardView  # noqa
        from core.permissions import user_can

        def add(key, widget):
            self.views[key] = widget
            self.stack.addWidget(widget)

        add("overview", DashboardView(self.db, self.console))

        if "secscan" in self.allowed:
            from ui.secscan_view import SecScanView
            add("secscan", SecScanView(self.db, self.user, self.console, self))
        if "networkguard" in self.allowed:
            from ui.network_views import (NetworkGuardView, DeviceInventoryView,
                                          SecurityEventsView)
            add("networkguard", NetworkGuardView(self.db, self.user, self.console, self))
            add("inventory", DeviceInventoryView(self.db, self.user, self.console, self))
            add("events", SecurityEventsView(self.db, self.user, self.console, self))
        if "cyberlab" in self.allowed:
            from ui.cyberlab_view import CyberLabView
            add("cyberlab", CyberLabView(self.db, self.user, self.console, self))
        if "academy" in self.allowed:
            from ui.academy_view import AcademyView
            add("academy", AcademyView(self.db, self.user, self.console, self))
        if "reports" in self.allowed:
            from ui.admin_views import ReportsView
            add("reports", ReportsView(self.db, self.user, self.console, self))
        if "settings" in self.allowed:
            from ui.admin_views import SettingsView
            add("settings", SettingsView(self.db, self.user, self.console, self))
        if "audit" in self.allowed:
            from ui.admin_views import AuditView
            add("audit", AuditView(self.db, self.user, self.console, self))

        # pad the stack so section indexes align even when some views are missing
        order = [s[0] for s in SECTIONS]
        final = []
        for key in order:
            if key in self.views:
                final.append(key)
        self._ordered = final

    def set_busy(self, busy, label="OPERATION IN PROGRESS"):
        """Only true operations may animate the LED."""
        self.led.set_busy(busy)
        self.status_ready.setText(label if busy else "READY")
        self.status_ready.setStyleSheet(f"color: {NEON if busy else MUTED}; font-weight: 700;")

    def switch(self, key):
        for k, btn in self._nav_buttons.items():
            btn.setChecked(k == key)
        if key in self.views:
            self.stack.setCurrentWidget(self.views[key])
            view = self.views[key]
            if hasattr(view, "refresh"):
                try:
                    view.refresh()
                except Exception as e:
                    self.console.log(f"refresh error in {key}: {type(e).__name__}", "err")

    def closeEvent(self, event):
        self.db.close()
        super().closeEvent(event)
