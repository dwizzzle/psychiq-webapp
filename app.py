"""
PSYCHIQ Web Application
Enterprise Adversary Gym — Hardened version with security fixes applied.

Remediated vulnerabilities:
  PSYCHIQ-003 CWE-89:  SQL Injection — parameterized queries
  PSYCHIQ-004 CWE-78:  OS Command Injection — input validation, no shell=True
  PSYCHIQ-005 CWE-22:  Path Traversal — secure_filename + realpath validation
  PSYCHIQ-006 CWE-79:  Reflected XSS — Jinja2 template with auto-escaping
  PSYCHIQ-007 CWE-434: Unrestricted Upload — extension whitelist + secure_filename
  PSYCHIQ-008 CWE-798: Hardcoded secrets — env vars + hashed passwords
"""

import os
import re
import sqlite3
import subprocess
import hashlib
from flask import (
    Flask, request, render_template, redirect,
    send_file, flash, session
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
# PSYCHIQ-008 fix: Use environment variable for secret key instead of hardcoded value
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

UPLOAD_FOLDER = "/app/uploads"
DB_PATH = "/app/data/psychiq.db"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# ── Database setup ──────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            filename TEXT,
            uploaded_by TEXT,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # PSYCHIQ-008 fix: Hash passwords instead of storing plaintext
    def _hash_pw(pw):
        return hashlib.sha256(pw.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("admin", _hash_pw(os.environ.get("ADMIN_PASSWORD", "changeme")), "admin"))
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("webuser", _hash_pw(os.environ.get("WEBUSER_PASSWORD", "changeme")), "user"))
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("svc_backup", _hash_pw(os.environ.get("SVCBACKUP_PASSWORD", "changeme")), "service"))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()


init_db()


# ── Routes ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok", "app": "psychiq-webapp", "version": "1.0.0"}


# ── CWE-89: SQL Injection ───────────────────────────────────────
# CodeQL: py/sql-injection
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # PSYCHIQ-003 fix: Parameterized query prevents SQL injection
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = user[1]
            session["role"] = user[3]
            return redirect("/dashboard")
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, uploaded_by, uploaded_at FROM files ORDER BY uploaded_at DESC LIMIT 20")
    files = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", user=session["user"], role=session.get("role"), files=files)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── CWE-434: Unrestricted File Upload ───────────────────────────
# CodeQL: py/path-injection (via unsanitized filename)
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # PSYCHIQ-007 fix: Sanitize filename and validate extension
            ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".csv", ".doc", ".docx"}
            filename = secure_filename(f.filename)
            if not filename:
                flash("Invalid filename")
                return redirect("/upload")
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                flash(f"File type '{ext}' not allowed")
                return redirect("/upload")
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            f.save(save_path)

            # Record in database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO files (filename, uploaded_by) VALUES (?, ?)",
                (filename, session.get("user", "anonymous"))
            )
            conn.commit()
            conn.close()

            flash(f"File '{filename}' uploaded successfully")
            return redirect("/upload")

    # List uploaded files
    uploaded = os.listdir(UPLOAD_FOLDER) if os.path.exists(UPLOAD_FOLDER) else []
    return render_template("upload.html", files=uploaded)


# ── CWE-22: Path Traversal ─────────────────────────────────────
# CodeQL: py/path-injection
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    if not filename:
        return "Missing file parameter", 400

    # PSYCHIQ-005 fix: Sanitize filename and validate resolved path
    safe_name = secure_filename(filename)
    if not safe_name:
        return "Invalid file path", 400
    file_path = os.path.join(UPLOAD_FOLDER, safe_name)
    if not os.path.realpath(file_path).startswith(os.path.realpath(UPLOAD_FOLDER)):
        return "Invalid file path", 400
    if os.path.exists(file_path):
        return send_file(file_path)
    return "File not found", 404


# ── CWE-78: OS Command Injection ───────────────────────────────
# CodeQL: py/command-line-injection
@app.route("/diagnostics", methods=["GET", "POST"])
def diagnostics():
    output = None
    if request.method == "POST":
        target = request.form.get("target", "")
        # PSYCHIQ-004 fix: Input validation and no shell=True
        if not re.match(r'^[a-zA-Z0-9.\-]+$', target):
            output = "Invalid target: only hostnames and IPs allowed"
        else:
            result = subprocess.run(["ping", "-c", "3", target], capture_output=True, text=True)
            output = result.stdout + result.stderr

    return render_template("diagnostics.html", output=output)


# ── CWE-79: Reflected XSS ──────────────────────────────────────
# CodeQL: py/reflected-xss
@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM files WHERE filename LIKE ?", (f"%{query}%",))
    results = cursor.fetchall()
    conn.close()

    # PSYCHIQ-006 fix: Use Jinja2 template with auto-escaping instead of f-string HTML
    return render_template("search.html", query=query, results=results)


# ── Serve uploaded files (enables webshell execution in ASPX scenario) ──
@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # PSYCHIQ-005 fix: Validate path for serve_upload as well
    safe_name = secure_filename(filename)
    if not safe_name:
        return "Invalid file path", 400
    file_path = os.path.join(UPLOAD_FOLDER, safe_name)
    if not os.path.realpath(file_path).startswith(os.path.realpath(UPLOAD_FOLDER)):
        return "Invalid file path", 400
    return send_file(file_path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
