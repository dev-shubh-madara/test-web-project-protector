"""DefaultMart - an INTENTIONALLY VULNERABLE demo shop (CipherBloom Test Lab).

LOCALHOST ONLY. Every user, password and key in here is fake.
It refuses to bind to anything except 127.0.0.1 and must never be deployed.
"""
import argparse
import html
import json
import os
import re
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import config

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(ROOT, "db.sqlite3")

# A "misconfigured static handler": these private files are served to anyone.
LEAKS = {
    "/.env": (".env", "text/plain"),
    "/.env.local": (".env.local", "text/plain"),
    "/.git/config": ("leaky/git_config", "text/plain"),
    "/.git/HEAD": ("leaky/git_HEAD", "text/plain"),
    "/.aws/credentials": ("leaky/aws_credentials", "text/plain"),
    "/docker-compose.yml": ("docker-compose.yml", "text/plain"),
    "/backup.zip": ("leaky/backup.zip", "application/zip"),
    "/db.sqlite3": ("db.sqlite3", "application/octet-stream"),
    "/.DS_Store": ("leaky/DS_Store", "application/octet-stream"),
}
MIME = {".js": "application/javascript", ".css": "text/css", ".svg": "image/svg+xml"}

CSS = """
*{box-sizing:border-box}body{margin:0;min-height:100vh;color:#f2eeff;font:16px/1.6 system-ui,Segoe UI,Roboto,sans-serif;
background:radial-gradient(60% 50% at 15% 10%,#7c4dff55,transparent),radial-gradient(50% 50% at 90% 20%,#ff4fd855,transparent),
radial-gradient(50% 50% at 50% 100%,#17c8ff33,transparent),#07040f}
.warn{background:linear-gradient(90deg,#ff3b6b,#ff8a3d);color:#14001f;text-align:center;font-weight:800;padding:9px 12px;letter-spacing:.4px}
main{max-width:980px;margin:0 auto;padding:36px 18px 70px}h1{font-size:clamp(34px,6vw,58px);margin:10px 0;letter-spacing:-1.5px}
h1 span{background:linear-gradient(90deg,#ff4fd8,#8b5cff,#36e2ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.glass{background:linear-gradient(160deg,#ffffff18,#ffffff08);border:1px solid #ffffff24;border-radius:20px;padding:22px;
backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 20px 60px -25px #000}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;margin-top:22px}
input,button{font:inherit;border-radius:12px;border:1px solid #ffffff2a;background:#0006;color:#fff;padding:11px 13px;width:100%;margin:6px 0}
button{background:linear-gradient(110deg,#7c4dff,#ff4fd8);border:0;font-weight:800;cursor:pointer}
a{color:#7fe9ff}code{background:#0007;padding:2px 7px;border-radius:7px}.dim{color:#a69cc8}
.products{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:22px}
.p{padding:16px;border-radius:16px;border:1px solid #ffffff22;background:#ffffff0c}.p b{display:block}
pre{white-space:pre-wrap;background:#0008;padding:14px;border-radius:12px;overflow:auto}
"""


def page(title, body):
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>%s</title><style>%s</style></head><body>"
        "<div class='warn'>INTENTIONALLY VULNERABLE DEMO &middot; LOCALHOST ONLY &middot; ALL DATA IS FAKE</div>"
        "<main>%s</main><script src='/static/app.js'></script></body></html>" % (title, CSS, body)
    )


HOME = """
<p class='dim'>CipherBloom Test Lab</p>
<h1>Default<span>Mart</span></h1>
<p class='dim'>A fake online shop full of mistakes on purpose, so you can watch CipherBloom Guardian find them.</p>
<div class='grid'>
  <form class='glass' action='/search' method='get'><b>Search products</b>
    <input name='q' placeholder='try: phone'><button>Search</button></form>
  <form class='glass' action='/login' method='post'><b>Admin login</b>
    <input name='user' placeholder='user'><input name='password' type='password' placeholder='password'><button>Sign in</button></form>
</div>
<div class='products'>
  <div class='p'><b>Neon Keyboard</b><span class='dim'>Rs 2,499</span></div>
  <div class='p'><b>Glass Mouse</b><span class='dim'>Rs 1,299</span></div>
  <div class='p'><b>Bloom Headset</b><span class='dim'>Rs 3,999</span></div>
  <div class='p'><b>Cipher Webcam</b><span class='dim'>Rs 2,199</span></div>
</div>
<div class='glass' style='margin-top:22px'><b>Open API</b>
  <p class='dim'>No login needed:</p>
  <p><a href='/api/users'>/api/users</a> &middot; <a href='/api/user?id=1'>/api/user?id=1</a> &middot;
  <a href='/api/calc?expr=6*7'>/api/calc?expr=6*7</a> &middot; <a href='/docs'>/docs</a></p>
  <p id='results' class='dim'></p></div>
"""


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "Apache/2.4.7 (Ubuntu)"  # version disclosure on purpose

    def log_message(self, fmt, *args):
        sys.stderr.write("[lab] %s\n" % (fmt % args))

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookies=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/5.4.0")
        origin = self.headers.get("Origin")
        if origin:  # trusts ANY website, and allows cookies: on purpose
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, data):
        self._send(code, json.dumps(data, indent=2), "application/json")

    def _file(self, rel, ctype):
        with open(os.path.join(ROOT, rel), "rb") as fh:
            self._send(200, fh.read(), ctype)

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        if path in LEAKS:
            return self._file(*LEAKS[path])
        if path == "/":
            return self._send(200, page("DefaultMart", HOME),
                              cookies=["visitor_id=1001; Path=/", "session=guest-session; Path=/"])
        if path == "/search":
            q = qs.get("q", [""])[0]
            # reflected XSS on purpose: the text is not escaped
            return self._send(200, page("Search", "<h2>Results for: %s</h2><p class='dim'>No products found.</p>"
                                                  "<p><a href='/'>Back</a></p>" % q))
        if path == "/api/users":
            con = sqlite3.connect(DB_PATH)
            rows = con.execute("SELECT id, name, email, role FROM users").fetchall()
            con.close()
            return self._json(200, [dict(zip(("id", "name", "email", "role"), r)) for r in rows])
        if path == "/api/user":
            uid = qs.get("id", ["1"])[0]
            con = sqlite3.connect(DB_PATH)
            try:  # SQL injection on purpose (read-only fake data)
                rows = con.execute("SELECT id, name, email, role FROM users WHERE id = " + uid).fetchall()
                return self._json(200, [dict(zip(("id", "name", "email", "role"), r)) for r in rows])
            except Exception as exc:
                return self._json(500, {"error": str(exc), "hint": "SELECT ... WHERE id = " + uid})
            finally:
                con.close()
        if path == "/api/calc":
            expr = qs.get("expr", ["1+1"])[0]
            # eval on purpose, but hardened (digits/operators only, no **) so this demo cannot run code
            if not re.fullmatch(r"[0-9+\-*/(). ]{1,40}", expr) or "**" in expr:
                return self._json(400, {"error": "only simple arithmetic is allowed in this demo"})
            try:
                return self._json(200, {"expr": expr, "result": eval(expr, {"__builtins__": {}}, {})})
            except Exception as exc:
                return self._json(400, {"error": str(exc)})
        if path == "/docs":
            return self._send(200, page("API docs", "<h2>Swagger UI (demo)</h2><p class='dim'>openapi: 3.0.0 &middot; "
                                                    "<a href='/openapi.json'>openapi.json</a></p>"))
        if path == "/openapi.json":
            return self._json(200, {"openapi": "3.0.0", "info": {"title": "DefaultMart API"},
                                    "paths": {"/api/users": {}, "/api/user": {}, "/api/calc": {}}})
        if path == "/console":
            return self._send(200, page("Console", "<h2>Interactive Console</h2><p class='dim'>(simulated, runs nothing)</p>"))
        if path.startswith("/static/"):
            name = os.path.normpath(path[len("/static/"):])
            full = os.path.join(ROOT, "static", name)
            if not name.startswith("..") and not os.path.isabs(name) and os.path.isfile(full):
                return self._file(os.path.join("static", name), MIME.get(os.path.splitext(name)[1], "text/plain"))
        # simulated debug page: a fake stack trace for unknown routes
        trace = ("Traceback (most recent call last):\n  File \"/srv/defaultmart/server.py\", line 88, in do_GET\n"
                 "    handler = ROUTES[path]\nKeyError: %r\n\nDEBUG = %s" % (path, config.DEBUG))
        return self._send(404, page("Not found", "<h2>Server error</h2><pre>%s</pre>" % html.escape(trace)))

    def do_POST(self):
        parsed = urlparse(self.path)
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        if parsed.path == "/login":
            user, password = form.get("user", [""])[0], form.get("password", [""])[0]
            if user == config.ADMIN_USER and password == config.ADMIN_PASS:  # no rate limit, weak password
                return self._send(200, page("Welcome", "<h2>Welcome back, admin</h2><p><a href='/'>Home</a></p>"),
                                  cookies=["session=admin-session-token; Path=/"])
            return self._send(401, page("Login", "<h2>Wrong user or password</h2><p><a href='/'>Try again</a></p>"))
        return self._send(404, page("Not found", "<h2>Not found</h2>"))


def main():
    ap = argparse.ArgumentParser(description="DefaultMart - intentionally vulnerable demo (localhost only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("Refusing to bind to %s. This demo is intentionally vulnerable and runs on localhost only." % args.host)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("DefaultMart (INTENTIONALLY VULNERABLE) on http://127.0.0.1:%d  - localhost only, all data is fake" % args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
