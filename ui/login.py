"""Login dialog (Stage 2). First run creates the initial admin account."""
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFormLayout, QLabel,
                               QLineEdit, QVBoxLayout)

from core.database import Database
from core.permissions import load_user, user_can


class LoginDialog(QDialog):
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.user = None
        self.setWindowTitle("DERYCODE CYBERSECURITY — Sign in")
        self.setFixedWidth(380)
        lay = QVBoxLayout(self)
        brand = QLabel("DERYCODE CYBERSECURITY")
        brand.setStyleSheet("color:#39ff14;font-weight:800;letter-spacing:2px;")
        tag = QLabel("Build. Learn. Test. Defend.")
        tag.setStyleSheet("color:#7d8a7d;")
        lay.addWidget(brand)
        lay.addWidget(tag)
        self.form = QFormLayout()
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.form.addRow("Username", self.user_edit)
        self.form.addRow("Password", self.pass_edit)
        lay.addLayout(self.form)
        self.error = QLabel("")
        self.error.setStyleSheet("color:#ff2e4d;")
        lay.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

        first_run = db.scalar("SELECT COUNT(*) FROM users") == 0
        if first_run:
            self.setWindowTitle("First run — create the administrator account")
            self.form.insertRow(0, QLabel("No users exist yet. Create the admin account:"))
            self.full_edit = QLineEdit()
            self.pass2_edit = QLineEdit()
            self.pass2_edit.setEchoMode(QLineEdit.Password)
            self.form.addRow("Full name", self.full_edit)
            self.form.addRow("Repeat password", self.pass2_edit)
            self._mode = "create"
        else:
            self._mode = "login"

    def _submit(self):
        u, p = self.user_edit.text().strip(), self.pass_edit.text()
        if self._mode == "create":
            if not u or len(p) < 8:
                self.error.setText("Username required; password must be 8+ characters.")
                return
            if p != self.pass2_edit.text():
                self.error.setText("Passwords do not match.")
                return
            uid = self.db.create_user(u, p, full_name=self.full_edit.text().strip(),
                                      role="admin")
            self.db.audit("user.first_admin_created", user_id=uid, target=u)
            self.user = load_user(self.db, u, p)
        else:
            self.user = load_user(self.db, u, p)
            if self.user is None:
                self.error.setText("Invalid username or password.")
                self.user_edit.setFocus()
                return
            self.db.audit("user.login", user_id=self.user["id"], target=u)
        self.accept()

    @staticmethod
    def authenticate(db):
        """Show dialog until success or quit. Returns user dict or None."""
        while True:
            dlg = LoginDialog(db)
            if dlg.exec() == QDialog.Accepted and dlg.user:
                return dlg.user
            return None
