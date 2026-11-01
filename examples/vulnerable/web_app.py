"""Intentionally vulnerable code covering the non-ReDoS checks redoscan runs
(SQL injection, command injection, insecure deserialization, weak crypto,
path traversal, SSRF, IDOR). For demo and test purposes only -- see
examples/safe/web_app.py for the corrected versions.
"""
import hashlib
import os
import pickle
import random
import subprocess
import zipfile

import jwt
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


def search_users(user_id):
    # CWE-89: SQL built with an f-string
    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def backup(path):
    # CWE-78: shell command built from a non-literal argument
    os.system("tar -czf backup.tar.gz " + path)


def run_job(cmd):
    # CWE-78: shell=True with a variable command
    subprocess.run(cmd, shell=True)


def load_session(blob):
    # CWE-502: pickle on data that came from outside the process
    return pickle.loads(blob)


def load_config(raw_yaml):
    # CWE-502: yaml.load without a safe loader
    return yaml.load(raw_yaml)


def hash_password(password):
    # CWE-327: MD5 is not a password hash
    return hashlib.md5(password.encode()).hexdigest()


def new_reset_token():
    # CWE-330: non-cryptographic RNG used for a security token
    return random.randint(100000, 999999)


def read_report(filename):
    # CWE-22: path built directly from request input
    return open(request.args.get("path")).read()


def fetch_preview(url):
    # CWE-918: outbound request built directly from request input
    return requests.get(request.args.get("url")).text


@app.route("/users/<int:id>")
def get_user(id):
    # CWE-639: looks up a resource by id with no ownership/auth check
    return db.get(id)


def issue_token(user_id):
    # CWE-798: JWT signed with a hardcoded secret literal
    return jwt.encode({"user_id": user_id}, "supersecret123")


@app.route("/export")
def export_archive():
    # CWE-409: no member-size check before extracting (zip bomb risk)
    zipfile.ZipFile(request.files["archive"]).extractall("/tmp/out")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # CWE-798: hardcoded credential check (a backdoor, intentionally or not)
    if username == "admin" and password == "admin123":
        resp = app.make_response("ok")
        # CWE-614: session cookie set without secure/httponly flags
        resp.set_cookie("session", "abc123")
        return resp
