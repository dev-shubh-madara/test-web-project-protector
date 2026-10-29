"""Old admin helpers. Nothing in server.py imports this file, so it can never run in the demo.
It only exists so CipherBloom has risky code to find."""
import os
import pickle
import subprocess

import requests
import yaml


def ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)


def run_command(cmd):
    os.system(cmd)


def load_session(blob):
    return pickle.loads(blob)


def read_config(text):
    return yaml.load(text)


def fetch_partner_feed(url):
    return requests.get(url, verify=False)


def run_snippet(code):
    exec(code)


def enable_cors(app, CORSMiddleware):
    app.add_middleware(CORSMiddleware, allow_origins=["*"])
