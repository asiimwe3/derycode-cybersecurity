"""CyberLab challenges (Stage 6) — missions, hints, verification, remediation.

Verification is done locally against the lab server or fixture data. Flags are
never stored in plaintext in the database: answers are hashed (sha256 + salt).
"""
import hashlib
import json
import urllib.request

from cyberlab.lab_server import FLAGS

HINT = "hint"
ANSWER = "answer"

CHALLENGES = [
    {"code": "NET-01", "title": "Find the lab service", "category": "Networking",
     "difficulty": "basic", "points": 50,
     "description": "Connect to the local lab server and report its HTTP status for '/'.",
     "objectives": ["Understand ports and HTTP status codes"],
     "instructions": "Start the lab, then answer: what numeric HTTP status does GET / "
                     "return? (Check the lab URL in your browser or a proxy.)",
     "hints": ["Open http://127.0.0.1:8777/ — the browser shows the page (200)."],
     "verify": "status_200", "flag_text": "200",
     "explanation": "HTTP 200 means the service is up. Port scanning is the first step "
                    "of any authorized assessment.",
     "remediation": "Know which services you expose, and close the ones you don't need."},
    {"code": "AUTH-01", "title": "Weak credentials", "category": "Authentication",
     "difficulty": "basic", "points": 75,
     "description": "Log in to /login using weak default-style credentials.",
     "objectives": ["Recognize why weak passwords are dangerous"],
     "instructions": "Try common weak combinations on the lab login form. "
                     "The flag appears after a successful login. Submit the flag.",
     "hints": ["Try admin / 123456"],
     "verify": "flag", "flag_text": FLAGS["auth"],
     "explanation": "Guessable passwords let anyone in. Credential lists make this instant.",
     "remediation": "Enforce strong passwords, rate-limit logins, offer 2FA."},
    {"code": "XSS-01", "title": "Reflected XSS", "category": "Web vulnerabilities",
     "difficulty": "intermediate", "points": 100,
     "description": "The /search page reflects input without encoding.",
     "objectives": ["Understand cross-site scripting"],
     "instructions": "Visit /search?q=<script>alert(1)</script> — the app reveals the "
                     "flag when it 'executes' script input. Submit the flag.",
     "hints": ["The reflected term is printed raw into the HTML."],
     "verify": "flag", "flag_text": FLAGS["xss"],
     "explanation": "Unencoded reflection lets attacker script run in victims' browsers: "
                    "session theft, defacement, keylogging.",
     "remediation": "Encode output for the right context; use a CSP as a second layer."},
    {"code": "SQLI-01", "title": "SQL injection on the API", "category": "Web vulnerabilities",
     "difficulty": "intermediate", "points": 100,
     "description": "/api/items?category= filters with string concatenation.",
     "objectives": ["Understand SQL injection concepts"],
     "instructions": "Make the API return the hidden 'secret' item. The item's name "
                     "contains the flag. Submit the flag.",
     "hints": ["Try category=' OR 1=1 --"],
     "verify": "flag", "flag_text": FLAGS["sqli"],
     "explanation": "Concatenating input into SQL lets attackers read or change data.",
     "remediation": "Parameterized queries only; least-privilege DB accounts."},
    {"code": "IDOR-01", "title": "Broken access control", "category": "Access control",
     "difficulty": "intermediate", "points": 100,
     "description": "Note IDs are viewable by anyone.",
     "objectives": ["Understand IDOR / object-level authorization"],
     "instructions": "Find the instructor note that contains the flag (it is not "
                     "linked from your guide). Submit the flag.",
     "hints": ["If /notes/1 works, what about /notes/2?"],
     "verify": "flag", "flag_text": FLAGS["idor"],
     "explanation": "The server never checks that the requester owns the object.",
     "remediation": "Check ownership/authorization on every object request."},
    {"code": "LOG-01", "title": "Log analysis", "category": "Log analysis",
     "difficulty": "basic", "points": 75,
     "description": "Read /logs and identify the attacker's IP address.",
     "objectives": ["Read authentication logs", "Spot brute-force patterns"],
     "instructions": "One IP is repeatedly failing logins. Submit that IP address.",
     "hints": ["Count FAIL lines per IP."],
     "verify": "ip", "flag_text": "198.51.100.77",
     "explanation": "Repeated failures from one source is the classic brute-force signature.",
     "remediation": "Rate-limit, lock accounts, alert on repeated failures."},
    {"code": "IR-01", "title": "Incident response order", "category": "Incident response",
     "difficulty": "basic", "points": 50,
     "description": "Put the IR phases in the right order.",
     "objectives": ["Know the standard incident-response phases"],
     "instructions": "Submit the correct order using first letters, e.g. 'CPDER' "
                     "(Containment, Preparation, Detection, Eradication, Recovery).",
     "hints": ["Prepare before you detect; contain before you eradicate."],
     "verify": "ir_order", "flag_text": "PDCE R".replace(" ", ""),
     "explanation": "Preparation, Detection, Containment, Eradication, Recovery (+ lessons).",
     "remediation": "Rehearse the process; document each incident."},
    {"code": "LNX-01", "title": "File permission audit", "category": "Linux security",
     "difficulty": "basic", "points": 75,
     "description": "Given a directory listing, find the dangerous permission.",
     "objectives": ["Read ls -l output", "Spot world-writable files"],
     "instructions": "Listing: '-rwxr-xr-x root root run.sh' / '-rw-rw-rw- root root "
                     "run.sh' / 'drwx------ root root .ssh'. Submit which entry is "
                     "dangerous: 'file', 'dir', or 'other'.",
     "hints": ["World-writable files can be replaced by any user."],
     "verify": "perm_choice", "flag_text": "file",
     "explanation": "A world-writable executable runs with whatever user executes it — "
                    "anyone can swap it.",
     "remediation": "Use least privilege: remove group/world write on executables."},
]

IR_CORRECT = "PDCE R".replace(" ", "")


def _norm(text):
    return (text or "").strip().lower()


def _hash(answer):
    return hashlib.sha256(("dcs-lab-salt::" + _norm(answer)).encode()).hexdigest()


def verify(challenge, answer):
    """Local verification. Returns True/False — never reveals the flag."""
    kind = challenge["verify"]
    a = _norm(answer)
    if kind == "flag":
        return a == _norm(challenge["flag_text"])
    if kind == "status_200":
        return a == "200"
    if kind == "ip":
        return a == _norm(challenge["flag_text"])
    if kind == "ir_order":
        return a.replace(" ", "") == IR_CORRECT.lower()
    if kind == "perm_choice":
        return a == "file"
    return False


def verify_live(challenge, answer):
    """For HTTP challenges: optionally confirm against the live lab."""
    if challenge["code"] == "NET-01":
        try:
            with urllib.request.urlopen("http://127.0.0.1:8777/", timeout=5) as r:
                return str(r.status) == _norm(answer)
        except Exception:
            return False
    return verify(challenge, answer)


def seed(db):
    """Insert challenge definitions (idempotent). Flags are stored hashed."""
    for c in CHALLENGES:
        db.execute(
            "INSERT OR IGNORE INTO challenges (code, title, category, difficulty, points, "
            "description, objectives_json) VALUES (?,?,?,?,?,?,?)",
            (c["code"], c["title"], c["category"], c["difficulty"], c["points"],
             c["description"], json.dumps(c["objectives"])))
        ch_id = db.scalar("SELECT id FROM challenges WHERE code = ?", (c["code"],))
        # answer hash kept in settings namespaced by challenge id (not the plaintext flag)
        db.set_setting(f"lab_answer_{ch_id}", _hash(c["flag_text"]))
    return len(CHALLENGES)
