"""CyberLab scoring (Stage 6). Points only for genuinely verified completions."""
from cyberlab import challenges as CH


def student_score(db, student_id):
    rows = db.query(
        "SELECT cr.score, c.code, c.title, cr.completed_at FROM challenge_results cr "
        "JOIN challenges c ON c.id = cr.challenge_id WHERE cr.student_id = ? "
        "ORDER BY cr.completed_at DESC", (student_id,))
    total = sum(r["score"] for r in rows)
    return {"total": total, "completed": rows,
            "max": sum(c["points"] for c in CH.CHALLENGES)}


def record_attempt(db, student_id, challenge_code, answer, live=False):
    """Verify an answer; award points and store history ONLY on success."""
    ch = next((c for c in CH.CHALLENGES if c["code"] == challenge_code), None)
    if ch is None:
        return {"ok": False, "message": "Unknown challenge."}
    ok = CH.verify_live(ch, answer) if live else CH.verify(ch, answer)
    if not ok:
        db.audit("lab.attempt_failed", target=challenge_code,
                 details={"student": student_id})
        return {"ok": False, "message": "Not correct — try again (hints available)."}
    ch_id = db.scalar("SELECT id FROM challenges WHERE code = ?", (challenge_code,))
    db.execute(
        "INSERT INTO challenge_results (student_id, challenge_id, score) VALUES (?,?,?) "
        "ON CONFLICT(student_id, challenge_id) DO NOTHING", (student_id, ch_id, ch["points"]))
    db.audit("lab.challenge_completed", target=challenge_code,
             details={"student": student_id, "points": ch["points"]})
    return {"ok": True, "message": f"Correct! +{ch['points']} points.", "points": ch["points"]}


def history(db, student_id):
    return [dict(r) for r in db.query(
        "SELECT c.code, c.title, cr.score, cr.completed_at FROM challenge_results cr "
        "JOIN challenges c ON c.id = cr.challenge_id WHERE cr.student_id = ? "
        "ORDER BY cr.completed_at DESC", (student_id,))]
