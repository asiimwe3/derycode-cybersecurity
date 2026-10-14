"""Application shell: sidebar navigation, console dock, honest status LED."""
import sys

from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (QApplication, QDockWidget, QHBoxLayout, QLabel,
                               QMainWindow, QPushButton, QScrollArea,
                               QStackedWidget, QStatusBar, QVBoxLayout, QWidget)

from ui.dashboard import DashboardView
from ui.theme import MUTED, NEON, PANEL, STYLESHEET
from ui.widgets import Console, ModulePlaceholder, StatusLed

SECTIONS = [
    # (key, label, stage, plan shown on the placeholder page)
    ("overview", "Overview", 1, "Live operational statistics drawn from the local database."),
    ("secscan", "SecScan", 3, "Website, application, API, source-code and dependency security checks "
                              "on assets you are authorized to test."),
    ("networkguard", "Network Guard", 5, "Device discovery and traffic monitoring for the "
                                        "authorized café network; read-only by default."),
    ("cyberlab", "CyberLab", 6, "Hands-on ethical hacking challenges with scoring and isolated "
                                "local targets."),
    ("academy", "Academy", 6, "Students, instructors, the 10-course curriculum, progress and "
                              "certificates."),
    ("reports", "Vulnerability Reports", 4, "HTML/PDF assessment reports with findings, severity, "
                                            "evidence and remediation."),
    ("events", "Security Events", 5, "Recorded network and host security events with alert "
                                     "management."),
    ("inventory", "Device Inventory", 5, "Discovered devices, authorization state and history."),
    ("settings", "Settings", 2, "Users, roles, permissions, asset authorization and application "
                                "configuration."),
    ("audit", "Audit Logs", 2, "Immutable local trail of every action performed in the app."),
]


class MainWindow(QMainWindow):
    def __init__(self, db, app_name="DERYCODE CYBERSECURITY"):
        super().__init__()
        self.db = db
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
        for key, label, stage, plan in SECTIONS:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, k=key: self.switch(k))
            sbar.addWidget(btn)
            self._nav_buttons[key] = btn
        sbar.addStretch(1)
        footer = QLabel("Derycode Organization")
        footer.setObjectName("Muted")
        sbar.addWidget(footer)
        root.addWidget(sidebar)

        # ---- stacked pages ----
        self.console = Console()
        self.stack = QStackedWidget()
        self.views = {}
        self.views["overview"] = DashboardView(db, self.console)
        self.stack.addWidget(self.views["overview"])
        for key, label, stage, plan in SECTIONS[1:]:
            page = QScrollArea()
            page.setWidgetResizable(True)
            page.setWidget(ModulePlaceholder(label, stage, plan))
            self.stack.addWidget(page)
        root.addWidget(self.stack, 1)

        # ---- console dock ----
        dock = QDockWidget("OPERATIONS CONSOLE", self)
        dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetClosable)
        dock.setWidget(self.console)
        self.addDockWidget(Qt.BottomDockWidgetArea, dock)
        self.console.log(f"{app_name} started — database: {db.path}", "ok")

        # ---- status bar ----
        status = QStatusBar()
        self.led = StatusLed()
        status.addWidget(self.led)
        self.status_ready = QLabel("READY")
        status.addWidget(self.status_ready)
        status.addPermanentWidget(QLabel(f"db: {db.path.name}"))
        self.setStatusBar(status)
        self.set_busy(False)

        self.switch("overview")

    def set_busy(self, busy, label="OPERATION IN PROGRESS"):
        """Only true operations may animate the LED."""
        self.led.set_busy(busy)
        self.status_ready.setText(label if busy else "READY")
        self.status_ready.setStyleSheet(f"color: {NEON if busy else MUTED}; font-weight: 700;")

    def switch(self, key):
        for k, btn in self._nav_buttons.items():
            btn.setChecked(k == key)
        self.stack.setCurrentIndex([s[0] for s in SECTIONS].index(key))
        if key == "overview":
            self.views["overview"].refresh()

    def closeEvent(self, event):
        self.db.close()
        super().closeEvent(event)
