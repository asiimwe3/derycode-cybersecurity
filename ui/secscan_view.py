"""SecScan view (Stage 3 UI): register + authorize assets, run modules, see findings."""
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
                                QHeaderView, QInputDialog, QLabel, QLineEdit,
                                QMessageBox, QProgressBar, QPushButton,
                                QScrollArea, QTableWidget, QTableWidgetItem,
                                QVBoxLayout, QWidget, QCheckBox, QGroupBox)

from core.scope_manager import ScopeManager, UnauthorizedTargetError
from core.permissions import user_can
from secscan.engine import ScanRunner, MODULES
from ui.theme import SEVERITY_COLORS


class ScanWorker(QThread):
    progress_sig = Signal(int, str)
    done_sig = Signal(object)

    def __init__(self, runner):
        super().__init__()
        self.runner = runner

    def run(self):
        try:
            self.runner.progress = lambda pct, msg: self.progress_sig.emit(pct, msg)
            self.done_sig.emit({"ok": True, "result": self.runner.run()})
        except UnauthorizedTargetError as e:
            self.done_sig.emit({"ok": False, "error": str(e)})
        except Exception as e:
            self.done_sig.emit({"ok": False, "error": f"{type(e).__name__}: {e}"})


class SecScanView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.user, self.console, self.window = db, user, console, window
        self.scope = ScopeManager(db)
        self.worker = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)

        title = QLabel("DERYCODE SECSCAN — AUTHORIZED SECURITY ASSESSMENT")
        title.setObjectName("SectionTitle")
        lay.addWidget(title)
        note = QLabel("Only assets with recorded authorization can be scanned. "
                      "Potential findings are labelled, never confirmed without evidence.")
        note.setStyleSheet("color:#7d8a7d;")
        lay.addWidget(note)

        # ---- register + authorize ----
        reg_box = QGroupBox("Register and authorize an asset")
        reg_lay = QFormLayout(reg_box)
        self.name_edit = QLineEdit()
        self.type_combo = QComboBox()
        self.type_combo.addItems(["website", "web_app", "api", "local_project"])
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("https://your-site.example  OR  C:\\path\\to\\project")
        self.reg_btn = QPushButton("Register asset")
        self.reg_btn.clicked.connect(self.register_asset)
        reg_lay.addRow("Asset name", self.name_edit)
        reg_lay.addRow("Type", self.type_combo)
        reg_lay.addRow("Target", self.target_edit)
        reg_lay.addRow("", self.reg_btn)
        lay.addWidget(reg_box)

        # ---- scan controls ----
        scan_box = QGroupBox("Run a scan")
        scan_lay = QFormLayout(scan_box)
        self.asset_combo = QComboBox()
        self.module_checks = {}
        for key, (label, _fn) in MODULES.items():
            cb = QCheckBox(label)
            self.module_checks[key] = cb
        self.start_btn = QPushButton("START SCAN")
        self.start_btn.setStyleSheet("font-weight:800;")
        self.start_btn.clicked.connect(self.start_scan)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.status_label = QLabel("Idle.")
        scan_lay.addRow("Authorized asset", self.asset_combo)
        for key in MODULES:
            scan_lay.addRow("", self.module_checks[key])
        scan_lay.addRow("", self.start_btn)
        scan_lay.addRow("", self.cancel_btn)
        scan_lay.addRow("Progress", self.progress)
        scan_lay.addRow("Status", self.status_label)
        lay.addWidget(scan_box)

        # ---- findings table ----
        lay.addWidget(QLabel("FINDINGS FROM THIS SESSION"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severity", "Confidence", "Title",
                                              "Evidence", "Remediation"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, 1)

        self.report_btn = QPushButton("Generate report for last scan")
        self.report_btn.clicked.connect(self.generate_report)
        lay.addWidget(self.report_btn)
        self.refresh()

    def refresh(self):
        self.asset_combo.clear()
        for row in self.db.query("SELECT id, name FROM assets WHERE "
                                 "authorization_status = 'approved' ORDER BY id"):
            self.asset_combo.addItem(f"#{row['id']} {row['name']}", row["id"])

    def register_asset(self):
        name, target = self.name_edit.text().strip(), self.target_edit.text().strip()
        if not name or not target:
            QMessageBox.warning(self, "Missing data", "Asset name and target are required.")
            return
        asset_id = self.scope.register_asset(name, self.type_combo.currentText(),
                                             target, owner=self.user.get("full_name", ""))
        scope, ok = QInputDialog.getText(
            self, "Authorization required",
            f"Record the authorized scope for '{name}'.\n"
            "Example: 'Written permission from owner, valid 30 days for this target only.'")
        if not ok or not scope.strip():
            QMessageBox.information(self, "Pending", "Asset saved as PENDING — it cannot "
                                     "be scanned until authorization is recorded.")
            self.refresh()
            return
        self.scope.authorize_asset(asset_id, scope.strip(),
                                   authorized_by=self.user["username"])
        QMessageBox.information(self, "Authorized", "Asset registered and authorized.")
        self.name_edit.clear(); self.target_edit.clear()
        self.refresh()

    def start_scan(self):
        if self.asset_combo.count() == 0:
            QMessageBox.warning(self, "No assets", "Register and authorize an asset first.")
            return
        asset_id = self.asset_combo.currentData()
        modules = [k for k, cb in self.module_checks.items() if cb.isChecked()]
        if not modules:
            QMessageBox.warning(self, "No modules", "Select at least one module.")
            return
        asset = self.db.query_one("SELECT name FROM assets WHERE id = ?", (asset_id,))
        confirm = QMessageBox.question(
            self, "Confirm scan",
            f"Start scan of '{asset['name']}' with: {', '.join(modules)}?\n"
            "Active probes are sent to the authorized target only.",
            QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        runner = ScanRunner(self.db, self.scope, asset_id, modules)
        self.worker = ScanWorker(runner)
        self.worker.progress_sig.connect(self._progress)
        self.worker.done_sig.connect(self._done)
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.window.set_busy(True, "SCAN RUNNING")
        self.console.log(f"scan started on asset #{asset_id} modules={modules}", "ok")
        self.worker.start()

    def cancel_scan(self):
        if self.worker and self.worker.runner:
            self.worker.runner.cancel.set()
            self.status_label.setText("Cancelling…")

    def _progress(self, pct, msg):
        self.progress.setValue(pct)
        self.status_label.setText(msg)

    def _done(self, payload):
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.window.set_busy(False)
        if not payload.get("ok"):
            self.status_label.setText("Scan failed.")
            self.console.log(f"scan error: {payload.get('error')}", "err")
            QMessageBox.critical(self, "Scan failed", payload.get("error", "Unknown error"))
            return
        r = payload["result"]
        self.status_label.setText(f"{r['status']}: {len(r['findings'])} finding(s).")
        self.console.log(f"scan {r['status']}: {len(r['findings'])} findings", "warn"
                         if r["module_errors"] else "ok")
        self.table.setRowCount(len(r["findings"]))
        for i, f in enumerate(r["findings"]):
            self.table.setItem(i, 0, QTableWidgetItem(f["severity"].upper()))
            self.table.setItem(i, 1, QTableWidgetItem(f["confidence"]))
            self.table.setItem(i, 2, QTableWidgetItem(f["title"]))
            self.table.setItem(i, 3, QTableWidgetItem(f.get("evidence", "")[:300]))
            self.table.setItem(i, 4, QTableWidgetItem(f.get("remediation", "")[:300]))
        self.refresh()

    def generate_report(self):
        scan = self.db.query_one("SELECT MAX(id) id FROM scans WHERE asset_id IS NOT NULL")
        if not scan or not scan["id"]:
            QMessageBox.information(self, "No scans", "Run a scan first.")
            return
        out = QFileDialog.getSaveFileName(self, "Save report", "assessment-report.html",
                                          "HTML (*.html)")[0]
        if not out:
            return
        from reports.report_generator import generate_html
        path = generate_html(self.db, scan["id"], out.rsplit("/", 1)[0]
                             if "/" in out else ".")
        QMessageBox.information(self, "Report", f"Report saved:\n{path}")
