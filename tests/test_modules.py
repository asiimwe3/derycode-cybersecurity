"""Stage 2-6 tests: scope, scans, lab, reports, academy, permissions."""
import http.server
import json
import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest


@pytest.fixture
def db(tmp_path):
    from core.database import Database
    d = Database(tmp_path / "t.db")
    yield d
    d.close()


def make_user(db, role="admin"):
    db.create_user("u_" + role, "password123", role=role)
    from core.permissions import load_user
    return load_user(db, "u_" + role, "password123")


# ---------- Stage 2: scope + permissions ----------
def test_unauthorized_scan_rejected(db, tmp_path):
    from core.scope_manager import ScopeManager, UnauthorizedTargetError
    sm = ScopeManager(db)
    aid = sm.register_asset("My site", "website", "https://mine.test")
    runner_mod = __import__("secscan.engine", fromlist=["ScanRunner"])
    runner = runner_mod.ScanRunner(db, sm, aid, ["website_checks"])
    with pytest.raises(UnauthorizedTargetError):
        runner.run()
    sm.authorize_asset(aid, "owner permission", authorized_by="owner")
    assert sm.is_authorized(aid) is True


def test_permissions_gating(db):
    admin = make_user(db, "admin")
    student = make_user(db, "student")
    from core.permissions import user_can
    assert user_can(admin, "secscan.run")
    assert not user_can(student, "secscan.run")
    assert user_can(student, "cyberlab.view")


# ---------- Stage 3: website checks against a real local mock target ----------
class MockHandler(http.server.BaseHTTPRequestHandler):
    headers_out = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        for k, v in self.headers_out.items():
            self.send_header(k, v)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"abc")


@pytest.fixture
def mock_site():
    MockHandler.headers_out = {"Server": "Apache/2.4.29 (Ubuntu)",
                               "Set-Cookie": "sid=abc; Path=/"}
    httpd = http.server.HTTPServer(("127.0.0.1", 0), MockHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_website_checks_find_real_issues(mock_site):
    from secscan.website_checks import check_website
    findings = check_website(mock_site)
    titles = " | ".join(f["title"] for f in findings)
    assert "No HTTP Strict Transport Security" in titles       # header missing
    assert "Cookie without secure/httponly" in titles          # insecure cookie
    assert "Server technology disclosed" in titles          # info disclosure
    assert all(f["confidence"] in ("confirmed", "potential") for f in findings)


def test_source_audit_detects_secrets(tmp_path):
    from secscan.source_code_audit import audit_source
    src = tmp_path / "app"
    src.mkdir()
    (src / "config.py").write_text(
        'password = "hunter2hunter2"\nAPI_KEY = "sk-1234567890abcdefghij"\n')
    (src / "db.py").write_text(
        'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n')
    (src / "page.js").write_text("element.innerHTML = location.hash;\n")
    findings = audit_source(str(src))
    joined = " | ".join(f["title"] for f in findings)
    assert "Hardcoded password" in joined
    assert "SQL injection risk" in joined
    assert "Cross-site scripting risk" in joined
    # secrets must be masked in evidence
    for f in findings:
        assert "hunter2hunter2" not in f["evidence"]


def test_dependency_audit_offline(tmp_path):
    from secscan.dependency_audit import audit_manifest
    man = tmp_path / "req-test.txt"
    man.write_text("requests==2.28.0\npyyaml==5.3.1\nflask==3.0.0\n")
    findings, notes = audit_manifest(str(man), allow_online=False)
    titles = " | ".join(f["title"] for f in findings)
    assert "requests 2.28.0" in titles and "CVE-2023-32681" in findings[0]["evidence"]
    assert "pyyaml" in titles
    assert any("offline" in n.lower() for n in notes)


# ---------- Stage 4: reports ----------
def test_html_report_contains_only_real_findings(db, tmp_path):
    db.execute("INSERT INTO assets (name, asset_type, target, authorization_status) "
               "VALUES ('t','website','https://t.test','approved')")
    aid = db.scalar("SELECT id FROM assets")
    db.execute("INSERT INTO authorizations (asset_id, scope, authorized_by) "
               "VALUES (?, 'test scope', 'tester')", (aid,))
    db.execute("INSERT INTO scans (asset_id, module, status, finished_at) "
               "VALUES (?, 'website_checks', 'completed', datetime('now'))", (aid,))
    sid = db.scalar("SELECT MAX(id) FROM scans")
    db.execute("INSERT INTO findings (scan_id, title, severity, confidence, evidence) "
               "VALUES (?,?,?,?, 'real evidence line')",
               (sid, "Real finding", "high", "confirmed"))
    from reports.report_generator import generate_html
    out = generate_html(db, sid, str(tmp_path))
    html_text = open(out, encoding="utf-8").read()
    assert "Real finding" in html_text
    assert "real evidence line" in html_text
    assert "test scope" in html_text
    assert db.scalar("SELECT COUNT(*) FROM reports") == 1


# ---------- Stage 5: network + detection (parse-level) ----------
def test_detection_rules_raise_alerts(db):
    for _ in range(6):
        db.execute("INSERT INTO security_events (event_type, severity, source, message) "
                   "VALUES ('failed_login','low','203.0.113.9','failed logon')")
    from network_guard.detection_rules import run_all
    raised = run_all(db)
    assert raised >= 1
    bruteforce = db.query_one("SELECT COUNT(*) n FROM security_events "
                              "WHERE event_type = 'auth_bruteforce_suspected'")
    assert bruteforce["n"] == 1


def test_traffic_delta_math():
    from network_guard.traffic_monitor import traffic_delta
    first = {"eth0": (1000, 500)}
    second = {"eth0": (3000, 2500)}
    assert traffic_delta(first, second) == {"eth0": (2000, 2000)}


def test_firewall_refuses_without_confirmation():
    from network_guard.firewall_integration import add_block_rule
    ok, msg = add_block_rule("192.0.2.1", confirm=False)
    assert ok is False and "confirmation" in msg.lower()


# ---------- Stage 6: lab + scoring + academy ----------
def test_lab_sqli_and_verification(db):
    from cyberlab import challenges as CH, scoring
    from cyberlab.lab_server import LabServer
    server = LabServer(port=0)
    server.port = 8781
    url = server.start()
    try:
        import urllib.request
        with urllib.request.urlopen(url + "/api/items?category=%27%20OR%201%3D1%20--",
                                    timeout=5) as r:
            body = r.read().decode()
        assert "DCS{" in body and "or_one_equals_one" in body
        ch = next(c for c in CH.CHALLENGES if c["code"] == "SQLI-01")
        assert CH.verify(ch, "DCS{or_one_equals_one}") is True
        assert CH.verify(ch, "wrong") is False
    finally:
        server.stop()
    CH.seed(db)
    db.execute("INSERT INTO students (full_name) VALUES ('Lab Tester')")
    sid = db.scalar("SELECT id FROM students")
    result = scoring.record_attempt(db, sid, "SQLI-01", "DCS{or_one_equals_one}")
    assert result["ok"] is True
    bad = scoring.record_attempt(db, sid, "IDOR-01", "nope")
    assert bad["ok"] is False
    assert db.scalar("SELECT COUNT(*) FROM challenge_results") == 1  # failed not stored


def test_academy_quiz_and_certificate(db, tmp_path):
    from academy import course_manager, student_manager, certificates
    course_manager.seed(db)
    sid = student_manager.add_student(db, "Cert Student")
    courses = db.query("SELECT id, code FROM courses ORDER BY id")
    cid = courses[0]["id"]
    student_manager.enroll(db, sid, cid)
    quiz = course_manager.get_course(db, courses[0]["code"])["quiz"]
    answers = [q["correct"] for q in quiz]     # perfect score
    result = course_manager.grade_quiz(db, quiz, answers)
    assert result["passed"] is True
    student_manager.record_quiz(db, sid, cid, result)
    path = certificates.generate(db, sid, cid, str(tmp_path))
    assert path and os.path.exists(path)
    assert "no external accreditation" in open(path).read()
    # incomplete course must NOT certify
    sid2 = student_manager.add_student(db, "Incomplete")
    assert certificates.generate(db, sid2, cid, str(tmp_path)) is None
    out = student_manager.export_csv(db, str(tmp_path / "academy-export.csv"))
    assert "Cert Student" in open(out).read()


# ---------- Regression: SQLite used from a worker thread (user-reported crash) ----------
def test_database_usable_from_worker_thread(db):
    """Scans run in QThread workers; the DB is created on the main thread."""
    import threading
    errors, results = [], []

    def worker(n):
        try:
            db.execute("INSERT INTO assets (name, asset_type, target) VALUES (?,?,?)",
                       (f"t{n}", "website", f"https://t{n}.example"))
            results.append(db.scalar("SELECT COUNT(*) FROM assets"))
        except Exception as e:                      # ProgrammingError before the fix
            errors.append(repr(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    assert db.scalar("SELECT COUNT(*) FROM assets") == 8


def test_full_scan_runs_in_thread(db, mock_site):
    """End-to-end: asset registered on main thread, real scan run from a worker thread."""
    from core.scope_manager import ScopeManager
    from secscan.engine import ScanRunner
    sm = ScopeManager(db)
    aid = sm.register_asset("mock", "website", mock_site)
    sm.authorize_asset(aid, "own test target", authorized_by="owner")
    out = {}

    def run():
        try:
            out["result"] = ScanRunner(db, sm, aid, ["website_checks"]).run()
        except Exception as e:                       # pre-fix: ProgrammingError
            out["err"] = repr(e)

    t = threading.Thread(target=run)
    t.start()
    t.join(90)
    assert "err" not in out, out.get("err")
    assert db.scalar("SELECT COUNT(*) FROM scans WHERE status = 'completed'") >= 1
    assert db.scalar("SELECT COUNT(*) FROM findings") > 0


def test_spa_catchall_not_reported_as_exposed_files(db, monkeypatch):
    """Sites that return index.html for every path must NOT be flagged as
    exposing /backup.zip, /.env etc. (regression: false-positive criticals)."""
    import secscan.website_checks as wc

    class SpaHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<!DOCTYPE html><html><body>app shell</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), SpaHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        findings = wc.check_website(f"http://127.0.0.1:{httpd.server_address[1]}")
    finally:
        httpd.shutdown()
    exposed = [f for f in findings if "Publicly accessible sensitive file" in f["title"]]
    assert exposed == [], exposed
