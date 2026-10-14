"""Settings, Audit Logs and Reports views (Stage 2/4 UI)."""
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QHBoxLayout, QHeaderView,
                                QLabel, QLineEdit, QMessageBox, QPushButton,
                                QTableWidget, QTableWidgetItem, QVBoxLayout,
                                QWidget, QFormLayout, QGroupBox, QComboBox)

from core.database import Database
from core.permissions import user_can


class SettingsView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.user, self.console, self.window = db, user, console, window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("SETTINGS"))
        self.note = QLabel("")
        self.note.setStyleSheet("color:#ff2e4d;")
        lay.addWidget(self.note)

        user_box = QGroupBox("Users and roles")
        ul = QFormLayout(user_box)
        self.new_user = QLineEdit()
        self.new_pass = QLineEdit(); self.new_pass.setEchoMode(QLineEdit.Password)
        self.new_role = QComboBox()
        self.new_role.addItems(["analyst", "instructor", "student", "admin"])
        add_btn = QPushButton("Create user")
        add_btn.clicked.connect(self.create_user)
        ul.addRow("Username", self.new_user)
        ul.addRow("Password (8+ chars)", self.new_pass)
        ul.addRow("Role", self.new_role)
        ul.addRow("", add_btn)
        lay.addWidget(user_box)

        app_box = QGroupBox("Application")
        al = QFormLayout(app_box)
        self.osv_check = QCheckBox("Allow online dependency lookups (OSV API) — sends "
                                   "package names/versions only, never source code")
        self.osv_check.setChecked(db.setting("allow_online_deps", "0") == "1")
        self.osv_check.toggled.connect(self._toggle_osv)
        backup_btn = QPushButton("Back up database now")
        backup_btn.clicked.connect(self.backup)
        al.addRow(self.osv_check)
        al.addRow("", backup_btn)
        lay.addWidget(app_box)
        lay.addStretch(1)

    def _toggle_osv(self, on):
        self.db.set_setting("allow_online_deps", "1" if on else "0")
        self.db.audit("settings.online_deps", target=str(on))

    def create_user(self):
        if not user_can(self.user, "settings.users"):
            self.note.setText("Your role cannot create users.")
            return
        u, p = self.new_user.text().strip(), self.new_pass.text()
        if not u or len(p) < 8:
            self.note.setText("Username required; password must be 8+ characters.")
            return
        uid = self.db.create_user(u, p, role=self.new_role.currentText())
        self.db.audit("user.create", user_id=self.user["id"], target=u,
                       details={"role": self.new_role.currentText()})
        self.console.log(f"user created: {u} ({self.new_role.currentText()})", "ok")
        self.new_user.clear(); self.new_pass.clear()
        self.note.setText("")

    def backup(self):
        dest = self.db.backup((self.db.path.parent / "backups"))
        QMessageBox.information(self, "Backup", f"Database backed up to:\n{dest}")


class AuditView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("AUDIT LOGS — EVERY ACTION RECORDED"))
        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search actions…")
        self.search.textChanged.connect(self.refresh)
        row.addWidget(self.search)
        lay.addLayout(row)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Action", "Target", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, 1)

    def refresh(self):
        q = self.search.text().strip() if hasattr(self, "search") else ""
        if q:
            rows = self.db.query("SELECT * FROM audit_logs WHERE action LIKE ? "
                                 "ORDER BY id DESC LIMIT 500", (f"%{q}%",))
        else:
            rows = self.db.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500")
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, v in enumerate([r["created_at"], r["action"], r["target"],
                                   r["details_json"]]):
                self.table.setItem(i, j, QTableWidgetItem(str(v)[:200]))


class ReportsView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.console = db, console
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("VULNERABILITY REPORTS"))
        note = QLabel("Reports contain only what scans actually recorded.")
        note.setStyleSheet("color:#7d8a7d;")
        lay.addWidget(note)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Scan", "Title", "Format", "Path"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        open_btn = QPushButton("Open selected report")
        open_btn.clicked.connect(self.open_report)
        pdf_btn = QPushButton("Export last scan as PDF")
        pdf_btn.clicked.connect(self.export_pdf)
        row.addWidget(open_btn)
        row.addWidget(pdf_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.refresh()

    def refresh(self):
        rows = self.db.query("SELECT * FROM reports ORDER BY id DESC LIMIT 200")
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, v in enumerate([r["id"], r["scan_id"], r["title"], r["fmt"],
                                   r["path"]]):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))

    def open_report(self):
        row = self.table.currentRow()
        if row < 0:
            return
        path = self.table.item(row, 4).text()
        import os, subprocess, sys
        if not os.path.exists(path):
            QMessageBox.information(self, "Reports", "File moved or deleted.")
            return
        if sys.platform == "win32":
            os.startfile(path)  # noqa
        else:
            subprocess.run(["xdg-open", path], capture_output=True)

    def export_pdf(self):
        scan = self.db.query_one("SELECT MAX(id) id FROM scans WHERE status = 'completed'")
        if not scan or not scan["id"]:
            QMessageBox.information(self, "Reports", "Run a scan first.")
            return
        out = QFileDialog.getSaveFileName(self, "Save PDF", "assessment-report.pdf",
                                          "PDF (*.pdf)")[0]
        if not out:
            return
        from reports.report_generator import generate_pdf
        path = generate_pdf(self.db, scan["id"],
                            out.rsplit("/", 1)[0] if "/" in out else ".")
        self.console.log(f"PDF report generated: {path}", "ok")
        self.refresh()
