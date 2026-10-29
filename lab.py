#!/usr/bin/env python3
"""CipherBloom Test Lab - an intentionally vulnerable demo shop to test CipherBloom Guardian.

    python lab.py build        create ./target (fake secrets, syntax errors, leaky files)
    python lab.py serve        run the demo shop on http://127.0.0.1:8000 (localhost only)
    python lab.py scoreboard   build, run the shop, scan it with CipherBloom and show what it caught
    python lab.py clean        delete ./target

Everything is FAKE. The fake keys are generated on your computer at build time, so they are never
stored in this Git repo. Never deploy the generated site: it is vulnerable on purpose.
"""
import argparse
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import string
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
TARGET = HERE / "target"
RENAMES = {"dot_env": ".env", "dot_env_local": ".env.local", "dot_gitignore": ".gitignore"}

DIGITS = string.digits
UPPER = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "_-"


def rnd(rng, n, alphabet=ALNUM):
    """Random string whose first and last characters are letters/digits (so token regexes match cleanly)."""
    edges = [c for c in alphabet if c.isalnum()]
    body = "".join(rng.choice(alphabet) for _ in range(n - 2))
    return rng.choice(edges) + body + rng.choice(edges)


def make_tokens(seed):
    r = random.Random(seed)
    t = {
        "AWS_KEY": "AKIA" + rnd(r, 16, UPPER),
        "AWS_KEY2": "AKIA" + rnd(r, 16, UPPER),
        "AWS_SECRET": rnd(r, 40),
        "GH_TOKEN": "ghp_" + rnd(r, 36),
        "TG_TOKEN": rnd(r, 10, DIGITS) + ":" + rnd(r, 35, B64),
        "GOOGLE_KEY": "AIza" + rnd(r, 35, B64),
        "SLACK_TOKEN": "xoxb-" + rnd(r, 12, DIGITS) + "-" + rnd(r, 24),
        "STRIPE_KEY": "sk_live_" + rnd(r, 24),
        "AI_KEY": "sk-proj-" + rnd(r, 48, B64),
        "DISCORD_TOKEN": "M" + rnd(r, 24, B64) + "." + rnd(r, 6, B64) + "." + rnd(r, 27, B64),
        "DB_URL": "postgres://admin:" + rnd(r, 14) + "@db.internal:5432/defaultmart",
        "GENERIC_SECRET": rnd(r, 32),
        "PEM_HEADER": "-----BEGIN RSA " + "PRIVATE KEY-----",
    }
    for i in range(1, 7):
        t["ENV_SECRET%d" % i] = rnd(r, 24)
    return t


def render(text, tokens):
    def sub(m):
        return tokens[m.group(1)]
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", sub, text)


def build(seed=1337):
    if TARGET.exists():
        shutil.rmtree(TARGET)
    tokens = make_tokens(seed)
    count = 0
    for src in sorted(TEMPLATES.rglob("*.tpl")):
        rel = src.relative_to(TEMPLATES)
        name = src.name[:-4]  # drop .tpl
        name = RENAMES.get(name, name)
        dest = TARGET / rel.parent / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render(src.read_text(encoding="utf-8"), tokens), encoding="utf-8", newline="\n")
        count += 1

    # a real (fake-data) SQLite database that the demo serves by mistake
    db = TARGET / "db.sqlite3"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT, pw_hash TEXT)")
    con.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [
        (1, "Alice Demo", "alice@example.test", "admin", "5f4dcc3b5aa765d61d8327deb882cf99"),
        (2, "Bob Demo", "bob@example.test", "customer", "e10adc3949ba59abbe56e057f20f883e"),
        (3, "Carol Demo", "carol@example.test", "customer", "25d55ad283aa400af464c76d713c07ad"),
    ])
    con.commit()
    con.close()

    leaky = TARGET / "leaky"
    leaky.mkdir(exist_ok=True)
    with zipfile.ZipFile(str(leaky / "backup.zip"), "w") as zf:
        zf.writestr("site-backup/README.txt", "Fake backup archive from the CipherBloom Test Lab.\n")
    (leaky / "DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1" + b"\x00" * 64)

    print("Built %d files + database in %s" % (count, TARGET))
    print("Scan it:   cipherbloom scan target --live http://127.0.0.1:8000")
    print("Run it:    python lab.py serve")


def ensure_built():
    if not (TARGET / "server.py").exists():
        build()


def serve(port):
    ensure_built()
    try:
        subprocess.call([sys.executable, str(TARGET / "server.py"), "--port", str(port)], cwd=str(TARGET))
    except KeyboardInterrupt:
        pass


def wait_for_port(port, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def scoreboard(port, guardian):
    ensure_built()
    env = dict(os.environ)
    if guardian:
        env["PYTHONPATH"] = guardian + os.pathsep + env.get("PYTHONPATH", "")
    probe = subprocess.run([sys.executable, "-c", "import cipherbloom"], env=env, capture_output=True)
    if probe.returncode != 0:
        print("CipherBloom Guardian is not installed.\n"
              "Install:  pip install git+https://github.com/dev-shubh-madara/project-protector\n"
              "or pass   --guardian path/to/project-protector")
        return 2
    server = subprocess.Popen([sys.executable, str(TARGET / "server.py"), "--port", str(port)],
                              cwd=str(TARGET), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for_port(port):
            print("The demo shop did not start on port %d (is it busy? try --port 8001)." % port)
            return 2
        out_json = HERE / "scoreboard-report.json"
        out_html = HERE / "scoreboard-report.html"
        cmd = [sys.executable, "-m", "cipherbloom", "scan", str(TARGET), "--live", "http://127.0.0.1:%d" % port,
               "--yes-i-own-this", "--no-history", "--no-color", "--quiet",
               "--json", str(out_json), "--html", str(out_html)]
        subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not out_json.exists():
            print("CipherBloom did not produce a report.")
            return 2
        report = json.loads(out_json.read_text(encoding="utf-8"))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()

    counts = {}
    for f in report["findings"]:
        counts[f["rule"]] = counts.get(f["rule"], 0) + 1
    expected = json.loads((HERE / "expected.json").read_text(encoding="utf-8"))
    print("\nCIPHERBLOOM SCOREBOARD  (%d findings, health score %d/100)\n" % (len(report["findings"]), report["score"]))
    hit = 0
    for item in expected:
        need = item.get("min", 1)
        got = counts.get(item["rule"], 0)
        ok = got >= need
        hit += ok
        print("  [%s]  %-34s %s%s" % ("PASS" if ok else "MISS", item["rule"], item["what"],
                                       "" if ok else "   (found %d, expected %d)" % (got, need)))
    print("\nCaught %d of %d planted problems." % (hit, len(expected)))
    print("Reports saved: %s and %s" % (out_html.name, out_json.name))
    return 0 if hit == len(expected) else 1


def main():
    ap = argparse.ArgumentParser(description="CipherBloom Test Lab")
    sub = ap.add_subparsers(dest="cmd")
    b = sub.add_parser("build", help="create ./target")
    b.add_argument("--seed", type=int, default=1337, help="seed for the fake secrets")
    s = sub.add_parser("serve", help="run the demo shop (localhost only)")
    s.add_argument("--port", type=int, default=8000)
    c = sub.add_parser("scoreboard", help="scan the lab with CipherBloom and show what it caught")
    c.add_argument("--port", type=int, default=8000)
    c.add_argument("--guardian", help="path to a project-protector checkout (if not pip-installed)")
    sub.add_parser("clean", help="delete ./target")
    args = ap.parse_args()
    if args.cmd == "build":
        build(args.seed)
    elif args.cmd == "serve":
        serve(args.port)
    elif args.cmd == "scoreboard":
        sys.exit(scoreboard(args.port, args.guardian))
    elif args.cmd == "clean":
        shutil.rmtree(TARGET, ignore_errors=True)
        print("Removed ./target")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
