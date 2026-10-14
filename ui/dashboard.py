"""Main dashboard — every number comes from a live database query."""
from PySide6.QtWidgets import (QFrame, QGridLayout, QHBoxLayout, QHeaderView,
                                QLabel, QTableWidget, QTableWidgetItem,
                                QVBoxLayout, QWidget)

from ui.theme import (MUTED, NEON, SEVERITY_COLORS)
from ui.widgets import SeverityBarChart, StatCard


class DashboardView(QWidget):
    def __init__(self, db, console):
        super().__init__()
        self.db = db
        self.console = console
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.setSpacing(12)

        head = QHBoxLayout()
        title = QLabel("OPERATIONS OVERVIEW")
        title.setObjectName("SectionTitle")
        self.demo_badge = QLabel("DEMO DATA — SEEDED FOR EVALUATION, NOT REAL FINDINGS")
        self.demo_badge.setStyleSheet(
            f"color: {SEVERITY_COLORS['medium']}; border: 1px solid {SEVERITY_COLORS['medium']};"
            "border-radius: 4px; padding: 3px 8px; font-size: 11px; font-weight: 700;")
        self.demo_badge.hide()
        head.addWidget(title)
        head.addStretch(1)
        head.addWidget(self.demo_badge)
        lay.addLayout(head)

        grid = QGridLayout()
        grid.setSpacing(10)
        self.card_assets = StatCard("Registered assets", subtitle="targets in inventory")
        self.card_scans = StatCard("Completed scans", subtitle="all modules")
        self.card_conf = StatCard("Confirmed vulnerabilities", accent=SEVERITY_COLORS["critical"],
                                  subtitle="verified evidence")
        self.card_pot = StatCard("Potential findings", accent=SEVERITY_COLORS["medium"],
                                 subtitle="need verification")
        self.card_crit = StatCard("Critical / high", accent=SEVERITY_COLORS["high"],
                                  subtitle="severity findings")
        self.card_dev = StatCard("Network devices", subtitle="seen on monitored networks")
        self.card_alerts = StatCard("Security alerts", accent=SEVERITY_COLORS["critical"],
                                    subtitle="critical & high events")
        self.card_labs = StatCard("Challenges completed", accent=NEON,
                                  subtitle="CyberLab + Academy")
        for i, card in enumerate([self.card_assets, self.card_scans, self.card_conf,
                                  self.card_pot, self.card_crit, self.card_dev,
                                  self.card_alerts, self.card_labs]):
            grid.addWidget(card, i // 4, i % 4)
        lay.addLayout(grid)

        mid = QHBoxLayout()
        chart_panel = QFrame()
        chart_panel.setObjectName("Card")
        chart_lay = QVBoxLayout(chart_panel)
        chart_lay.setContentsMargins(12, 8, 12, 8)
        chart_title = QLabel("FINDINGS BY SEVERITY")
        chart_title.setObjectName("CardTitle")
        self.chart = SeverityBarChart({})
        chart_lay.addWidget(chart_title)
        chart_lay.addWidget(self.chart)
        mid.addWidget(chart_panel, 1)

        act_panel = QFrame()
        act_panel.setObjectName("Card")
        act_lay = QVBoxLayout(act_panel)
        act_lay.setContentsMargins(12, 8, 12, 8)
        act_title = QLabel("RECENT SYSTEM ACTIVITY")
        act_title.setObjectName("CardTitle")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["TIME", "EVENT", "DETAIL"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        act_lay.addWidget(act_title)
        act_lay.addWidget(self.table)
        mid.addWidget(act_panel, 2)
        lay.addLayout(mid, 1)

        self.refresh()

    def refresh(self):
        s = self.db.dashboard_stats()
        self.card_assets.set_value(s["assets"])
        self.card_scans.set_value(s["scans_completed"])
        self.card_conf.set_value(s["findings_confirmed"])
        self.card_pot.set_value(s["findings_potential"])
        self.card_crit.set_value(s["critical_high"])
        self.card_dev.set_value(s["devices"])
        self.card_alerts.set_value(s["alerts"])
        self.card_labs.set_value(s["challenges_done"])
        self.chart.set_breakdown(s["severity_breakdown"])
        self.demo_badge.setVisible(s["demo_mode"])

        rows = s["recent_activity"]
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(r["created_at"]))
            self.table.setItem(i, 1, QTableWidgetItem(str(r["what"])))
            item = QTableWidgetItem(str(r["detail"])[:120])
            item.setToolTip(str(r["detail"]))
            self.table.setItem(i, 2, item)
        self.console.log(f"dashboard refreshed: {s['assets']} assets, "
                         f"{s['findings_confirmed'] + s['findings_potential']} findings", "ok")
