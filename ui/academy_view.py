"""Academy view (Stage 6 UI): students, courses, quizzes, certificates, export."""
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QHeaderView, QInputDialog,
                               QLabel, QLineEdit, QMessageBox, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget, QFileDialog, QRadioButton, QButtonGroup,
                               QScrollArea, QFrame, QGridLayout, QSpinBox)

from academy import course_manager, student_manager, certificates


class AcademyView(QWidget):
    def __init__(self, db, user, console, window):
        super().__init__()
        self.db, self.user, self.console, self.window = db, user, console, window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.addWidget(QLabel("DERYCODE ACADEMY — TRAINING MANAGEMENT"))
        note = QLabel("Certificates reflect only completion recorded in this application "
                      "and imply no external accreditation.")
        note.setStyleSheet("color:#7d8a7d;")
        lay.addWidget(note)

        add_row = QHBoxLayout()
        name_edit = QLineEdit(); name_edit.setPlaceholderText("New student full name")
        add_btn = QPushButton("Add student")
        add_btn.clicked.connect(lambda: self.add_student(name_edit.text()))
        ins_edit = QLineEdit(); ins_edit.setPlaceholderText("New instructor name")
        ins_btn = QPushButton("Add instructor")
        ins_btn.clicked.connect(lambda: self.add_instructor(ins_edit.text()))
        add_row.addWidget(name_edit, 1)
        add_row.addWidget(add_btn)
        add_row.addWidget(ins_edit, 1)
        add_row.addWidget(ins_btn)
        lay.addLayout(add_row)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Student", "Courses", "Completed",
                                              "Lab points", "Challenges"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        lay.addWidget(self.table, 1)

        course_row = QHBoxLayout()
        course_row.addWidget(QLabel("Course:"))
        self.course_combo = QComboBox()
        course_row.addWidget(self.course_combo)
        enroll_btn = QPushButton("Enroll selected student")
        enroll_btn.clicked.connect(self.enroll)
        quiz_btn = QPushButton("Take quiz as selected student")
        quiz_btn.clicked.connect(self.take_quiz)
        cert_btn = QPushButton("Generate certificate")
        cert_btn.clicked.connect(self.generate_cert)
        course_row.addWidget(enroll_btn)
        course_row.addWidget(quiz_btn)
        course_row.addWidget(cert_btn)
        course_row.addStretch(1)
        lay.addLayout(course_row)

        export_btn = QPushButton("Export student records (CSV)")
        export_btn.clicked.connect(self.export_csv)
        lay.addWidget(export_btn)
        self.refresh()

    def refresh(self):
        rows = student_manager.students_with_progress(self.db)
        self.table.setRowCount(len(rows))
        for i, s in enumerate(rows):
            for j, v in enumerate([s["id"], s["full_name"], s["courses"],
                                   s["completed"], s["lab_points"], s["challenges_done"]]):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))
        self.course_combo.clear()
        for c in self.db.query("SELECT id, code, title FROM courses ORDER BY code"):
            self.course_combo.addItem(f"{c['code']} {c['title']}", c["id"])

    def _selected_student(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Academy", "Select a student row first.")
            return None
        return int(self.table.item(row, 0).text())

    def add_student(self, name):
        name = name.strip()
        if not name:
            QMessageBox.warning(self, "Academy", "Enter the student's name.")
            return
        student_manager.add_student(self.db, name)
        self.console.log(f"student added: {name}", "ok")
        self.refresh()

    def add_instructor(self, name):
        name = name.strip()
        if not name:
            QMessageBox.warning(self, "Academy", "Enter the instructor's name.")
            return
        student_manager.add_instructor(self.db, name)
        self.console.log(f"instructor added: {name}", "ok")

    def enroll(self):
        sid = self._selected_student()
        if sid:
            student_manager.enroll(self.db, sid, self.course_combo.currentData())
            self.refresh()

    def take_quiz(self):
        sid = self._selected_student()
        if not sid:
            return
        course = course_manager.get_course(self.db, self.db.query_one(
            "SELECT code FROM courses WHERE id = ?",
            (self.course_combo.currentData(),))["code"])
        quiz = course["quiz"]
        answers = []
        for q in quiz:
            choice, ok = QInputDialog.getItem(
                self, f"Quiz — {course['title']}", q["q"], q["a"], 0, False)
            if not ok:
                return
            answers.append(q["a"].index(choice))
        result = course_manager.grade_quiz(self.db, quiz, answers)
        student_manager.record_quiz(self.db, sid, self.course_combo.currentData(), result)
        self.console.log(f"quiz result: {result['score']}/{result['total']}", "ok")
        verdict = ("PASSED — course marked complete." if result["passed"]
                   else "Keep studying; 70% passes the course.")
        QMessageBox.information(
            self, "Quiz result",
            f"Score: {result['score']}/{result['total']} ({result['pct']}%)\n{verdict}")
        self.refresh()

    def generate_cert(self):
        sid = self._selected_student()
        if not sid:
            return
        out = QFileDialog.getSaveFileName(self, "Save certificate",
                                          "certificate.html", "HTML (*.html)")[0]
        if not out:
            return
        path = certificates.generate(self.db, sid, self.course_combo.currentData(),
                                     out.rsplit("/", 1)[0] if "/" in out else ".")
        if path is None:
            QMessageBox.warning(self, "Certificate",
                                "Course not completed yet — certificates only reflect "
                                "actual completion.")
            return
        QMessageBox.information(self, "Certificate", f"Certificate saved:\n{path}")

    def export_csv(self):
        out = QFileDialog.getSaveFileName(self, "Export CSV", "academy-records.csv",
                                          "CSV (*.csv)")[0]
        if out:
            student_manager.export_csv(self.db, out)
            QMessageBox.information(self, "Export", f"Saved:\n{out}")
