"""CyberLab view (Stage 6 UI): local lab, challenges, scoring, history."""
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget)

from cyberlab import challenges as CH, scoring
from cyberlab.lab_server import LabServer


class CyberLabView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.user, self.console, self.window = db, user, console, window
        self.lab = LabServer()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("DERYCODE CYBERLAB — ETHICAL HACKING PRACTICE"))
        note = QLabel("The lab is a deliberately vulnerable app served ONLY on "
                      "127.0.0.1 — an authorized, isolated target. Training modules never "
                      "touch public systems or café customers.")
        note.setStyleSheet("color:#7d8a7d;")
        lay.addWidget(note)

        row = QHBoxLayout()
        self.start_btn = QPushButton("Start lab")
        self.start_btn.clicked.connect(self.start_lab)
        self.stop_btn = QPushButton("Stop lab")
        self.stop_btn.clicked.connect(lambda: (self.lab.stop(),
                                                self.url_label.setText("lab stopped"),
                                                self.console.log("lab stopped")))
        self.reset_btn = QPushButton("Reset lab")
        self.reset_btn.clicked.connect(self.reset_lab)
        row.addWidget(self.start_btn)
        row.addWidget(self.stop_btn)
        row.addWidget(self.reset_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.url_label = QLabel("Lab not running.")
        self.url_label.setStyleSheet("color:#39ff14;")
        lay.addWidget(self.url_label)

        student_row = QHBoxLayout()
        student_row.addWidget(QLabel("Practicing as:"))
        self.student_combo = QComboBox()
        student_row.addWidget(self.student_combo)
        lay.addLayout(student_row)

        lay.addWidget(QLabel("CHALLENGES"))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Code", "Title", "Category", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.cellClicked.connect(self.show_challenge)
        lay.addWidget(self.table, 1)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(170)
        lay.addWidget(self.detail)
        ans_row = QHBoxLayout()
        self.answer = QLineEdit()
        self.answer.setPlaceholderText("Enter flag or answer…")
        self.submit = QPushButton("Verify answer")
        self.submit.clicked.connect(self.submit_answer)
        self.hint_btn = QPushButton("Hint")
        self.hint_btn.clicked.connect(self.show_hint)
        ans_row.addWidget(self.answer, 1)
        ans_row.addWidget(self.hint_btn)
        ans_row.addWidget(self.submit)
        lay.addLayout(ans_row)
        self.score_label = QLabel("")
        self.score_label.setStyleSheet("color:#39ff14;font-weight:700;")
        lay.addWidget(self.score_label)
        self.current = None
        self.refresh()

    def start_lab(self):
        url = self.lab.start()
        self.url_label.setText(f"Lab running at {url} (local only)")
        self.console.log(f"lab started at {url}", "ok")

    def reset_lab(self):
        url = self.lab.reset()
        self.url_label.setText(f"Lab reset and running at {url}")
        self.console.log("lab reset", "ok")

    def _student_id(self):
        if self.student_combo.count() == 0:
            return None
        return self.student_combo.currentData()

    def refresh(self):
        self.student_combo.clear()
        for s in self.db.query("SELECT id, full_name FROM students ORDER BY full_name"):
            self.student_combo.addItem(f"#{s['id']} {s['full_name']}", s["id"])
        rows = self.db.query("SELECT * FROM challenges ORDER BY id")
        sid = self._student_id()
        done = set()
        if sid:
            done = {r["challenge_id"] for r in self.db.query(
                "SELECT challenge_id FROM challenge_results WHERE student_id = ?", (sid,))}
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            status = "COMPLETE" if r["id"] in done else "open"
            for j, v in enumerate([r["code"], r["title"], r["category"], status]):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))
        if sid:
            s = scoring.student_score(self.db, sid)
            self.score_label.setText(f"Score: {s['total']} points · "
                                     f"{len(s['completed'])}/{len(CH.CHALLENGES)} challenges")
        else:
            self.score_label.setText("No students registered — add students in Academy.")

    def show_challenge(self, row, _col):
        code = self.table.item(row, 0).text()
        self.current = next(c for c in CH.CHALLENGES if c["code"] == code)
        self.detail.setHtml(
            f"<b>{self.current['title']}</b> ({self.current['code']}, "
            f"{self.current['points']} pts, {self.current['difficulty']})<br>"
            f"{self.current['description']}<br><br>"
            f"<b>Mission:</b> {self.current['instructions']}<br>"
            f"<b>Learn:</b> {self.current['objectives'][0]}")

    def show_hint(self):
        if not self.current:
            return
        QMessageBox.information(self, "Hint", self.current["hints"][0])

    def submit_answer(self):
        sid = self._student_id()
        if not sid or not self.current:
            QMessageBox.warning(self, "CyberLab", "Select a student and a challenge.")
            return
        answer = self.answer.text().strip()
        live = self.current["code"] == "NET-01" and self.lab.running()
        result = scoring.record_attempt(self.db, sid, self.current["code"],
                                        answer, live=live)
        self.console.log(f"lab attempt {self.current['code']} -> "
                         f"{'OK' if result['ok'] else 'failed'}", "ok" if result["ok"] else "warn")
        QMessageBox.information(self, "Result", result["message"])
        self.answer.clear()
        self.refresh()
