"""Hardened versions of examples/vulnerable/web_app.py.

Each fix removes the specific weakness redoscan found, using the narrowest
change that does it -- see docs/METHOD.md for how vulnscan's checks work and
what "heuristic" means for this half of the tool.
"""
import os
import secrets
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import jwt
import requests
import yaml
from flask import Flask, abort, request
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import safe_join

app = Flask(__name__)
BASE_DIR = Path("/srv/reports")
ALLOWED_PREVIEW_HOSTS = {"images.example.com"}
MAX_EXTRACT_SIZE = 50 * 1024 * 1024  # 50 MB


def search_users(user_id):
    # Parameterized query: the driver, not string formatting, builds the SQL.
    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def backup(path):
    # Argument list, no shell involved -- nothing to inject into.
    subprocess.run(["tar", "-czf", "backup.tar.gz", path], shell=False)


def run_job(cmd_args):
    # Caller passes a list, not a shell string.
    subprocess.run(cmd_args, shell=False)


def load_session(blob):
    # JSON can't deserialize into arbitrary objects.
    import json
    return json.loads(blob)


def load_config(raw_yaml):
    # safe_load refuses to construct anything but plain data.
    return yaml.safe_load(raw_yaml)


def hash_password(password):
    # werkzeug's generate_password_hash uses a salted, slow KDF (scrypt).
    return generate_password_hash(password)


def new_reset_token():
    # `secrets` is seeded from the OS CSPRNG, unlike `random`.
    return secrets.token_urlsafe(32)


def read_report(filename):
    # Resolve the path and verify it's still inside BASE_DIR before opening.
    path = safe_join(str(BASE_DIR), filename)
    if path is None:
        abort(400)
    return open(path).read()


def fetch_preview(url):
    # Validate the host against an allow-list before making the request.
    host = urlparse(url).hostname
    if host not in ALLOWED_PREVIEW_HOSTS:
        abort(400)
    return requests.get(url, timeout=5).text


@app.route("/users/<int:id>")
@login_required
def get_user(id):
    # Ownership check before the resource is returned.
    user = db.get(id)
    if user is None or user.owner_id != current_user.id:
        abort(403)
    return user


def issue_token(user_id):
    # Secret comes from the environment, never a literal in source, and the
    # algorithm is pinned explicitly.
    return jwt.encode({"user_id": user_id}, os.environ["JWT_SECRET"], algorithm="HS256")


@app.route("/export")
@login_required
def export_archive():
    # Check every member's size before extracting anything, to rule out a
    # decompression bomb.
    with zipfile.ZipFile(request.files["archive"]) as zf:
        total = 0
        for info in zf.infolist():
            total += info.file_size
            if total > MAX_EXTRACT_SIZE:
                abort(413)
        zf.extractall("/tmp/out")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # Check against a stored, properly hashed credential -- no hardcoded
    # username/password pair in source.
    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password_hash, password):
        abort(401)
    resp = app.make_response("ok")
    # secure + httponly: not sent over plain HTTP, not readable from JS.
    resp.set_cookie("session", secrets.token_urlsafe(32), secure=True, httponly=True, samesite="Lax")
    return resp
