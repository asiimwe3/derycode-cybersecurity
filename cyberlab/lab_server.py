"""CyberLab local lab server (Stage 6).

A deliberately vulnerable mini web app served ONLY on 127.0.0.1 — the authorized
training target. Students find flags planted in the flaws. No external system is
ever touched by training modules.
"""
import html
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Flags students must extract through the flaws.
FLAGS = {
    "auth": "DCS{weak_passwords_fall}",
    "sqli": "DCS{or_one_equals_one}",
    "xss": "DCS{unencoded_reflection}",
    "idor": "DCS{broken_access_control}",
    "log": "DCS{read_the_logs}",
}

USERS = {"admin": "123456", "student": "student123"}   # deliberately weak
ITEMS = [
    {"id": 1, "name": "Cables (6m)", "category": "network"},
    {"id": 2, "name": "USB hub", "category": "hardware"},
    {"id": 3, "name": f"Flag item: {FLAGS['sqli']}", "category": "secret"},
]
NOTES = {
    1: ("Lab guide", "Use the flaws in this app to find all five flags."),
    2: ("Instructor note", f"The IDOR flag is {FLAGS['idor']}"),
    3: ("Passwords", "admin / 123456 (weak on purpose)"),
}
LOG_LINES = [
    "2026-01-05 09:12:44 login OK user=admin ip=127.0.0.1",
    "2026-01-05 09:14:02 login FAIL user=root ip=127.0.0.1",
    "2026-01-05 09:14:05 login FAIL user=root ip=198.51.100.77",
    "2026-01-05 09:14:06 login FAIL user=oracle ip=198.51.100.77",
    "2026-01-05 09:14:08 login FAIL user=test ip=198.51.100.77",
    "2026-01-05 09:14:10 login FAIL user=guest ip=198.51.100.77",
]

PAGE = """<html><head><title>DCS Practice Shop</title></head>
<body style="font-family:monospace;background:#111;color:#cfc">
<h2>DCS Practice Shop (vulnerable training app)</h2>
<p><a href="/">home</a> | <a href="/login">login</a> | <a href="/search">search</a> |
<a href="/api/items">api</a> | <a href="/logs">logs</a> | <a href="/notes/1">notes</a></p>
%s</body></html>"""


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, body, code=200, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}

        if u.path == "/":
            return self._send(PAGE % "<p>Welcome. Everything here is intentionally "
                                      "insecure — find the flags.</p>")
        if u.path == "/login":
            return self._send(PAGE % """<form method="POST" action="/login">
              user <input name="u"> pass <input name="p" type="password">
              <button>Log in</button></form>""")
        if u.path == "/search":
            term = q.get("q", "")
            # FLAW: reflected without encoding (XSS) and flags a magic term
            body = (f"<p>Search results for: {term}</p>"
                    "<p>1. HDMI cable<br>2. Cat6 cable<br>3. SATA cable</p>")
            if "<script" in term.lower():
                body = f"<p>Search results for: {term}</p><p>{FLAGS['xss']}</p>"
            return self._send(PAGE % body)
        if u.path == "/api/items":
            cat = q.get("category", "")
            # FLAW: fake SQL filter — classic ' OR 1=1 -- bypass
            if cat:
                if re.search(r"(\bor\b|\bunion\b|--|#)", cat, re.I):
                    return self._send(json.dumps(ITEMS), ctype="application/json")
                return self._send(json.dumps([]), ctype="application/json")
            return self._send(json.dumps([i for i in ITEMS
                                          if i["category"] != "secret"]),
                              ctype="application/json")
        if u.path == "/logs":
            return self._send(PAGE % "<pre>" + "\n".join(LOG_LINES) + "</pre>"
                              "<p>The log-analysis flag is hidden in the pattern: "
                              f"<!-- {FLAGS['log']} --></p>")
        if u.path.startswith("/notes/"):
            # FLAW: no access control on note IDs (IDOR)
            nid = u.path.split("/")[2]
            if nid.isdigit() and int(nid) in NOTES:
                return self._send(PAGE % f"<p>{html.escape(str(NOTES[int(nid)]))}</p>")
            return self._send(PAGE % "<p>not found</p>", 404)
        return self._send(PAGE % "<p>404</p>", 404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode())
            user, pwd = data.get("u", [""])[0], data.get("p", [""])[0]
            if USERS.get(user) == pwd:
                return self._send(PAGE % f"<p>Logged in as {user}.</p>"
                                  f"<p>{FLAGS['auth']}</p>")
            return self._send(PAGE % "<p>Invalid credentials.</p>", 401)
        return self._send(PAGE % "<p>404</p>", 404)


class LabServer:
    """Start/stop/reset the local lab. Binds to 127.0.0.1 only."""

    def __init__(self, port=8777):
        self.port = port
        self._httpd = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def running(self):
        return self._httpd is not None

    def start(self):
        if self.running():
            return self.url
        self._httpd = HTTPServer(("127.0.0.1", self.port), LabHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None
            self._thread = None

    def reset(self):
        """Lab is stateless; a restart fully resets it."""
        self.stop()
        return self.start()
