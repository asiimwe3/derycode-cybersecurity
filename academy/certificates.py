"""Certificate generation (Stage 6). Certificates state only what is true:
completion of a Derycode Academy course in this application. No external
accreditation is claimed.
"""
import os
import time

CERT_TEMPLATE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Certificate</title>
<style>body{{font-family:'Georgia',serif;background:#fff;color:#111;margin:0}}
.cert{{border:6px double #2a3a2a;margin:40px auto;padding:48px;max-width:820px;text-align:center}}
h1{{letter-spacing:4px;color:#14351f;margin-bottom:4px}} .name{{font-size:34px;margin:26px 0}}
.meta{{color:#555;font-size:14px}} .badge{{display:inline-block;background:#14351f;
color:#fff;padding:6px 14px;border-radius:999px;font-size:12px;letter-spacing:2px}}</style>
</head><body><div class="cert">
<div class="badge">DERYCODE ACADEMY</div>
<h1>CERTIFICATE OF COURSE COMPLETION</h1>
<p class="meta">This certifies that</p>
<div class="name">{student_name}</div>
<p class="meta">has successfully completed the course</p>
<div style="font-size:22px;font-weight:bold">{course_title}</div>
<p class="meta">{course_code} · Derycode Academy — Derycode Cybersecurity application<br>
Completed on {completed} · Score {score_pct}%<br>
Issued {issued} · Record ID {record_id}</p>
<p class="meta" style="margin-top:26px">This certificate reflects completion recorded in the
Derycode Cybersecurity application and implies no external accreditation.</p>
</div></body></html>"""


def generate(db, student_id, course_id, out_dir, score_pct=100):
    student = db.query_one("SELECT full_name FROM students WHERE id = ?", (student_id,))
    course = db.query_one("SELECT code, title FROM courses WHERE id = ?", (course_id,))
    enroll = db.query_one("SELECT completed_at FROM enrollments WHERE student_id = ? "
                          "AND course_id = ?", (student_id, course_id))
    if not student or not course or not enroll or not enroll["completed_at"]:
        return None  # never certify an incomplete course
    os.makedirs(out_dir, exist_ok=True)
    safe = "".join(c for c in student["full_name"] if c.isalnum() or c in " _-")
    out = os.path.join(out_dir,
                       f"certificate-{course['code']}-{safe.strip().replace(' ', '_')}.html")
    page = CERT_TEMPLATE.format(
        student_name=student["full_name"], course_title=course["title"],
        course_code=course["code"], completed=enroll["completed_at"],
        score_pct=score_pct, issued=time.strftime("%Y-%m-%d"),
        record_id=f"DCS-CERT-{student_id:03d}-{course_id:03d}")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    db.audit("academy.certificate", target=out)
    return out
