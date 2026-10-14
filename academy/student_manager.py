"""Academy student manager (Stage 6) + CSV export."""
import csv
import os


def add_student(db, full_name, email=""):
    db.execute("INSERT INTO students (full_name, email) VALUES (?,?)", (full_name, email))
    sid = db.scalar("SELECT MAX(id) FROM students")
    db.audit("academy.student_add", target=full_name)
    return sid


def add_instructor(db, full_name, email="", specialty=""):
    db.execute("INSERT INTO instructors (full_name, email, specialty) VALUES (?,?,?)",
               (full_name, email, specialty))
    return db.scalar("SELECT MAX(id) FROM instructors")


def enroll(db, student_id, course_id):
    db.execute("INSERT OR IGNORE INTO enrollments (student_id, course_id) VALUES (?,?)",
               (student_id, course_id))
    db.audit("academy.enroll", target=f"student={student_id} course={course_id}")


def set_progress(db, student_id, course_id, pct, completed=False):
    done_clause = "datetime('now')" if completed else "completed_at"
    db.execute(
        f"UPDATE enrollments SET progress_pct = ?, completed_at = {done_clause} "
        "WHERE student_id = ? AND course_id = ?", (pct, student_id, course_id))


def record_quiz(db, student_id, course_id, result):
    """Store quiz result; completion only when passed and progress reaches 100."""
    db.execute("UPDATE enrollments SET progress_pct = MAX(progress_pct, ?) "
               "WHERE student_id = ? AND course_id = ?",
               (result["pct"], student_id, course_id))
    if result["passed"]:
        db.execute("UPDATE enrollments SET progress_pct = 100, completed_at = "
                   "datetime('now') WHERE student_id = ? AND course_id = ?",
                   (student_id, course_id))
        db.audit("academy.course_completed",
                 target=f"student={student_id} course={course_id}",
                 details={"pct": result["pct"]})


def students_with_progress(db):
    rows = db.query(
        "SELECT s.id, s.full_name, s.email, COUNT(DISTINCT e.course_id) courses, "
        "SUM(CASE WHEN e.completed_at IS NOT NULL THEN 1 ELSE 0 END) completed, "
        "COALESCE((SELECT SUM(cr.score) FROM challenge_results cr "
        "WHERE cr.student_id = s.id), 0) lab_points, "
        "COALESCE((SELECT COUNT(*) FROM challenge_results cr "
        "WHERE cr.student_id = s.id), 0) challenges_done "
        "FROM students s LEFT JOIN enrollments e ON e.student_id = s.id "
        "GROUP BY s.id ORDER BY s.full_name")
    return [dict(r) for r in rows]


def export_csv(db, out_path):
    """Export student records + course reports to CSV."""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["student_id", "full_name", "email", "enrolled_courses",
                    "courses_completed", "lab_points", "challenges_done"])
        for s in students_with_progress(db):
            w.writerow([s["id"], s["full_name"], s["email"], s["courses"],
                        s["completed"], s["lab_points"], s["challenges_done"]])
    db.audit("academy.export_csv", target=out_path)
    return out_path
