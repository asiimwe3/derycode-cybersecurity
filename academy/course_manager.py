"""Academy course manager (Stage 6) — the 10-course Derycode curriculum."""
import json

COURSES = [
    ("CS-101", "Cybersecurity Fundamentals",
     "CIA triad, threats, risk, defense in depth, security mindset.",
     ["What security is and why it matters", "The CIA triad", "Threats, risks and "
      "vulnerabilities", "Defense in depth", "Security policies and hygiene"],
     [{"q": "Which element of the CIA triad ensures data is not altered without "
            "authorization?", "a": ["Integrity", "Availability", "Confidentiality"], "correct": 0},
      {"q": "Defense in depth means…", "a": ["One very strong control",
                                             "Multiple overlapping controls",
                                             "Encryption only"], "correct": 1},
      {"q": "A weakness that can be exploited is called a…", "a": ["Threat", "Risk",
                                                                   "Vulnerability"], "correct": 2}]),
    ("NET-201", "Computer Networking",
     "TCP/IP, ports, routing, subnetting and common protocols.",
     ["The TCP/IP model", "IP addressing and subnetting", "Ports and services",
      "DNS, DHCP, NAT", "Reading packet flows"],
     [{"q": "HTTPS normally uses port…", "a": ["80", "443", "22"], "correct": 1},
      {"q": "A private Class C range is…", "a": ["10.0.0.0/8", "172.16.0.0/12",
                                                 "192.168.0.0/16"], "correct": 2},
      {"q": "Which protocol resolves names to IPs?", "a": ["DHCP", "DNS", "ARP"], "correct": 1}]),
    ("LNX-201", "Linux for Ethical Hackers",
     "Shell survival, permissions, services, logs and hardening.",
     ["Command-line basics", "Users, groups and permissions", "Processes and services",
      "Log files and audit", "Hardening essentials"],
     [{"q": "Which permission means 'read and execute but not write'?", "a": ["rwx",
                                                                              "r-x", "-wx"], "correct": 1},
      {"q": "Logs live mainly in…", "a": ["/var/log", "/etc/log", "/tmp/logs"], "correct": 0},
      {"q": "The sticky bit is useful on…", "a": ["/etc", "/tmp", "/root"], "correct": 1}]),
    ("WIN-201", "Windows Security",
     "Windows accounts, services, Defender, event logs and hardening.",
     ["Users, groups and UAC", "Services and scheduled tasks", "Defender and firewall",
      "Security event logs", "Group Policy basics"],
     [{"q": "Event ID 4625 means…", "a": ["Failed logon", "Successful logon",
                                          "Service start"], "correct": 0},
      {"q": "UAC prompts exist to…", "a": ["Slow you down", "Limit privilege escalation",
                                           "Encrypt files"], "correct": 1},
      {"q": "Which interface shows firewall state?", "a": ["netsh advfirewall", "ping",
                                                           "tracert"], "correct": 0}]),
    ("DEF-301", "Network Defense",
     "Monitoring, detection rules, firewalls and segmentation.",
     ["Defensive monitoring", "Detection rules and alerts", "Firewall design",
      "Network segmentation", "Incident triage"],
     [{"q": "Repeated failed logins from one IP is a classic…", "a": ["Brute-force "
                                                                      "signature", "DNS "
                                                                      "tunnel", "Port "
                                                                      "scan"], "correct": 0},
      {"q": "Segmenting café clients from business systems is…", "a": ["Optional",
       "A core defense", "Only for banks"], "correct": 1},
      {"q": "An 'unusual but authorized' activity should be…", "a": ["Blocked "
       "immediately", "Investigated before judging", "Ignored"], "correct": 1}]),
    ("WEB-301", "Web Application Security",
     "XSS, SQLi, CSRF, authentication and session security.",
     ["The OWASP mindset", "XSS in depth", "SQL injection", "CSRF and sessions",
      "Secure auth patterns"],
     [{"q": "Parameterized queries prevent…", "a": ["XSS", "SQL injection", "CSRF"], "correct": 1},
      {"q": "HttpOnly on a cookie protects against…", "a": ["Script reading the cookie",
                                                            "XSS reflection", "SQLi"], "correct": 0},
      {"q": "Encoding output prevents…", "a": ["XSS", "CSRF", "SSRF"], "correct": 0}]),
    ("API-301", "API Security",
     "Authentication, authorization boundaries, error handling, rate limiting.",
     ["API authentication", "Object-level authorization", "Error and data exposure",
      "Rate limiting", "API inventory and documentation"],
     [{"q": "A 200 response to an anonymous request for other users' data indicates…",
       "a": ["Good caching", "Broken access control", "Rate limiting"], "correct": 1},
      {"q": "Verbose stack traces in API responses…", "a": ["Help debugging in prod",
       "Leak implementation details", "Are required by REST"], "correct": 1},
      {"q": "Which is a stateless token standard?", "a": ["JWT", "PHPSESSID", "Kerberos"],
       "correct": 0}]),
    ("PEN-401", "Ethical Penetration Testing",
     "Authorized testing methodology, scoping, reporting and law.",
     ["Rules of engagement and scope", "Recon and enumeration", "Safe exploitation",
      "Post-assessment and remediation", "Writing professional reports"],
     [{"q": "Written authorization is…", "a": ["Nice to have", "Legally required "
                                                "before testing", "Only for banks"], "correct": 1},
      {"q": "A finding you cannot verify is…", "a": ["Confirmed", "Potential — needs "
       "verification", "Ignored"], "correct": 1},
      {"q": "The best report finding includes…", "a": ["Just the CVE", "Evidence, impact "
       "and remediation", "A screenshot only"], "correct": 1}]),
    ("FOR-401", "Digital Forensics",
     "Evidence handling, acquisition, chain of custody, analysis.",
     ["Forensic principles", "Order of volatility", "Acquiring images and logs",
      "Chain of custody", "Analysis basics"],
     [{"q": "Collecting data in order of volatility means…", "a": ["RAM before disk",
       "Disk before RAM", "Random order"], "correct": 0},
      {"q": "Chain of custody records…", "a": ["Who handled evidence and when",
                                               "Password hashes", "Firewall rules"], "correct": 0},
      {"q": "The first forensic rule is…", "a": ["Search everything", "Do not alter "
       "the evidence", "Reboot the machine"], "correct": 1}]),
    ("IRP-401", "Incident Response",
     "Preparation, detection, containment, eradication, recovery.",
     ["IR lifecycle", "Detection and triage", "Containment strategies",
      "Eradication and recovery", "Lessons learned"],
     [{"q": "The first IR phase is…", "a": ["Containment", "Preparation", "Recovery"],
       "correct": 1},
      {"q": "Containment aims to…", "a": ["Delete evidence", "Stop the spread/impact",
                                          "Patch servers"], "correct": 1},
      {"q": "Lessons learned happens…", "a": ["During containment", "Before the "
       "incident", "After recovery"], "correct": 2}]),
]


def seed(db):
    """Create courses + quizzes (idempotent). Quizzes stored as settings JSON."""
    for code, title, desc, lessons, quiz in COURSES:
        db.execute(
            "INSERT OR IGNORE INTO courses (code, title, description, lessons_count) "
            "VALUES (?,?,?,?)", (code, title, desc, len(lessons)))
        db.set_setting(f"course_lessons_{code}", json.dumps(lessons))
        db.set_setting(f"course_quiz_{code}", json.dumps(quiz))
    db.audit("academy.seed", target="courses", details={"count": len(COURSES)})
    return len(COURSES)


def get_course(db, code):
    row = db.query_one("SELECT * FROM courses WHERE code = ?", (code,))
    if not row:
        return None
    return {**dict(row),
            "lessons": json.loads(db.setting(f"course_lessons_{code}", "[]")),
            "quiz": json.loads(db.setting(f"course_quiz_{code}", "[]"))}


def grade_quiz(db, quiz, answers):
    """answers = list of chosen indexes. Returns score + per-question results."""
    results, score = [], 0
    for i, q in enumerate(quiz):
        chosen = answers[i] if i < len(answers) else -1
        ok = chosen == q["correct"]
        score += 1 if ok else 0
        results.append({"question": q["q"], "chosen": chosen,
                        "correct_index": q["correct"], "ok": ok})
    pct = int(100 * score / max(len(quiz), 1))
    return {"score": score, "total": len(quiz), "pct": pct, "results": results,
            "passed": pct >= 70}
