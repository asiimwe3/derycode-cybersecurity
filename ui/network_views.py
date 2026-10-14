"""Network Guard, Device Inventory and Security Events views (Stage 5 UI)."""
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QHeaderView, QInputDialog,
                                QLabel, QMessageBox, QPushButton, QTableWidget,
                                QTableWidgetItem, QVBoxLayout, QWidget)

from network_guard import device_discovery, detection_rules, traffic_monitor
from network_guard.firewall_integration import status as fw_status, add_block_rule
from windows_security.event_log_reader import requires_windows, record_failed_logins
from core.permissions import user_can


def _table(headers, stretch_last=True):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    if stretch_last:
        t.horizontalHeader().setSectionResizeMode(len(headers) - 1, QHeaderView.Stretch)
    return t


class NetworkGuardView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.user, self.console, self.window = db, user, console, window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        title = QLabel("NETWORK GUARD — AUTHORIZED CAFÉ NETWORK MONITORING")
        title.setObjectName("SectionTitle")
        lay.addWidget(title)
        note = QLabel("Read-only monitoring by default. Unusual activity is flagged for "
                      "investigation — never automatically judged malicious. No customer "
                      "communications or passwords are ever intercepted.")
        note.setStyleSheet("color:#7d8a7d;")
        lay.addWidget(note)

        row = QHBoxLayout()
        self.discover_btn = QPushButton("Refresh devices (ARP table, read-only)")
        self.discover_btn.clicked.connect(self.discover)
        self.rules_btn = QPushButton("Run detection rules")
        self.rules_btn.clicked.connect(self.run_rules)
        self.fw_btn = QPushButton("Review firewall configuration")
        self.fw_btn.clicked.connect(self.review_firewall)
        row.addWidget(self.discover_btn)
        row.addWidget(self.rules_btn)
        row.addWidget(self.fw_btn)
        lay.addLayout(row)

        lay.addWidget(QLabel("TRAFFIC SNAPSHOT (interface counters, bytes)"))
        self.counter_label = QLabel("No snapshot recorded this session.")
        self.counter_label.setStyleSheet("color:#9aa5a0;")
        lay.addWidget(self.counter_label)
        self.snap_btn = QPushButton("Take traffic snapshot")
        self.snap_btn.clicked.connect(self.snapshot)
        lay.addWidget(self.snap_btn)

        lay.addWidget(QLabel("FIREWALL CONFIGURATION"))
        self.fw_text = QLabel("Not loaded.")
        self.fw_text.setWordWrap(True)
        self.fw_text.setStyleSheet("color:#9aa5a0;")
        lay.addWidget(self.fw_text)

        self.block_btn = QPushButton("Block a verified malicious destination (admin only)")
        self.block_btn.clicked.connect(self.block_destination)
        lay.addWidget(self.block_btn)
        lay.addStretch(1)

    def discover(self):
        self.window.set_busy(True, "DISCOVERING")
        rows = device_discovery.arp_table()
        new = device_discovery.sync_devices(self.db, rows, source="arp")
        self.window.set_busy(False)
        self.console.log(f"device discovery: {len(rows)} ARP entries, {len(new)} new", "ok")
        QMessageBox.information(self, "Devices",
                                f"Found {len(rows)} devices in the ARP table. "
                                f"New: {len(new)} (logged as security events).")

    def run_rules(self):
        raised = detection_rules.run_all(self.db)
        if not requires_windows():
            record_failed_logins(self.db)
        self.console.log(f"detection rules ran: {raised} new alert(s)", "warn" if raised else "ok")
        QMessageBox.information(self, "Rules", f"Detection rules executed. "
                                f"{raised} new alert(s) raised for investigation.")

    def snapshot(self):
        counters = traffic_monitor.record_snapshot(self.db)
        pretty = ", ".join(f"{k}: {v[0]//1048576}MB in/{v[1]//1048576}MB out"
                          for k, v in list(counters.items())[:4])
        self.counter_label.setText(pretty or "Counters unavailable on this system.")
        self.console.log("traffic snapshot recorded", "ok")

    def review_firewall(self):
        state, out = fw_status()
        self.fw_text.setText(out[:4000] if state == "ok" else
                             f"Firewall review: {out}")
        self.console.log(f"firewall status: {state}", "ok")

    def block_destination(self):
        if not user_can(self.user, "networkguard.block"):
            QMessageBox.warning(self, "Permission denied",
                                 "Your role cannot change network protection settings.")
            return
        ip, ok = QInputDialog.getText(self, "Block destination",
                                      "IP of the VERIFIED malicious destination:")
        if not ok or not ip.strip():
            return
        confirm = QMessageBox.question(
            self, "Confirm disruptive action",
            f"Block all outbound traffic to {ip}?\nThis requires elevated privileges "
            "and confirmation.", QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        ok2, msg = add_block_rule(ip.strip(), confirm=True)
        if ok2:
            self.db.audit("firewall.block", target=ip, details={"by": self.user["username"]})
            self.console.log(f"firewall rule added: block {ip}", "warn")
        QMessageBox.information(self, "Firewall", msg if not ok2 else
                                f"Blocked {ip}.")


class DeviceInventoryView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.console = db, console
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("DEVICE INVENTORY"))
        self.table = _table(["IP", "MAC", "Hostname", "Authorized", "First seen",
                             "Last seen"])
        lay.addWidget(self.table, 1)
        btn = QPushButton("Toggle authorization for selected device")
        btn.clicked.connect(self.toggle_auth)
        lay.addWidget(btn)

    def refresh(self):
        rows = self.db.query("SELECT * FROM network_devices ORDER BY last_seen DESC")
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            host = device_discovery.resolve_hostname(r["ip"])
            for j, v in enumerate([r["ip"], r["mac"], host,
                                   "yes" if r["is_authorized"] else "NO",
                                   r["first_seen"], r["last_seen"]]):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))

    def toggle_auth(self):
        row = self.table.currentRow()
        if row < 0:
            return
        dev_id = self.db.query_one(
            "SELECT id FROM network_devices WHERE ip = ?",
            (self.table.item(row, 0).text(),))["id"]
        self.db.execute("UPDATE network_devices SET is_authorized = "
                        "1 - is_authorized WHERE id = ?", (dev_id,))
        self.db.audit("device.toggle_auth", target=str(dev_id))
        self.refresh()


class SecurityEventsView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("SECURITY EVENTS"))
        row = QHBoxLayout()
        self.filter = QComboBox()
        self.filter.addItems(["all", "critical", "high", "medium", "low", "informational"])
        self.filter.currentTextChanged.connect(self.refresh)
        btn = QPushButton("Refresh")
        btn.clicked.connect(self.refresh)
        row.addWidget(QLabel("Severity filter:"))
        row.addWidget(self.filter)
        row.addWidget(btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.table = _table(["Time", "Type", "Severity", "Source", "Message"])
        lay.addWidget(self.table, 1)

    def refresh(self):
        sev = self.filter.currentText() if hasattr(self, "filter") else "all"
        if sev == "all":
            rows = self.db.query("SELECT * FROM security_events ORDER BY id DESC LIMIT 500")
        else:
            rows = self.db.query("SELECT * FROM security_events WHERE severity = ? "
                                 "ORDER BY id DESC LIMIT 500", (sev,))
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, v in enumerate([r["created_at"], r["event_type"], r["severity"],
                                   r["source"], r["message"]]):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))
