"""
PSYCHIQ Web Application
Enterprise Adversary Gym — Remediated by SecurityIQ AppSec Blue Team Agent.

Fixes applied (2026-03-27):
  CWE-89:  Parameterized SQL queries (login form)
  CWE-78:  Subprocess list form, no shell=True (diagnostics)
  CWE-22:  secure_filename + path validation (download)
  CWE-434: Extension whitelist + secure_filename (upload)
  CWE-79:  Jinja2 template rendering with autoescaping (search)
  CWE-94:  Removed uploaded file execution (serve_upload)
  CWE-798: Secrets moved to environment variables
  CWE-200: Config endpoint protected + redacted
"""

import os
import re
import sqlite3
import subprocess
from flask import (
    Flask, request, render_template, redirect,
    send_file, flash, session, abort
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

UPLOAD_FOLDER = "/app/uploads"
DB_PATH = "/app/data/psychiq.db"
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.gif', '.doc', '.docx', '.csv'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "")


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
    # Seed default users
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'P@ssw0rd!', 'admin')")
        c.execute("INSERT INTO users (username, password, role) VALUES ('webuser', 'Welcome1', 'user')")
        c.execute("INSERT INTO users (username, password, role) VALUES ('svc_backup', 'Backup2024!', 'service')")
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
        # FIXED: Parameterized query prevents SQL injection
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
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
            # FIXED: Sanitize filename and validate extension
            filename = secure_filename(f.filename)
            if not filename:
                flash("Invalid filename")
                return redirect("/upload")
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                flash(f"File type '{ext}' not allowed. Permitted: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
                return redirect("/upload")
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            if not os.path.realpath(save_path).startswith(os.path.realpath(UPLOAD_FOLDER)):
                flash("Invalid file path")
                return redirect("/upload")
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

    # FIXED: Sanitize filename and validate path stays within UPLOAD_FOLDER
    safe_name = secure_filename(filename)
    if not safe_name:
        return "Invalid filename", 400
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
        # FIXED: Validate input and use subprocess list form (no shell=True)
        if not re.match(r'^[a-zA-Z0-9.\-]+$', target):
            output = "Error: Invalid target. Only hostnames and IP addresses are allowed."
        else:
            result = subprocess.run(
                ["ping", "-c", "3", target],
                capture_output=True, text=True, timeout=15
            )
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

    # FIXED: Use Jinja2 template rendering with autoescaping
    return render_template("search_results.html", query=query, results=results)


# ── Serve uploaded files (static only — never execute) ──────────
@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # FIXED: Sanitize filename, validate path, serve as attachment (never execute)
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(400, "Invalid filename")
    file_path = os.path.join(UPLOAD_FOLDER, safe_name)
    if not os.path.realpath(file_path).startswith(os.path.realpath(UPLOAD_FOLDER)):
        abort(400, "Invalid file path")
    if not os.path.exists(file_path):
        abort(404, "File not found")
    return send_file(file_path, as_attachment=True)


# ── Internal API (FIXED: key from environment) ─────────────────
@app.route("/api/v1/status")
def api_status():
    """Internal status endpoint — requires API key from environment"""
    if not INTERNAL_API_KEY:
        return {"error": "API key not configured"}, 503
    key = request.headers.get("X-API-Key", "")
    if key != INTERNAL_API_KEY:
        return {"error": "Unauthorized"}, 401

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users")
    users = [{"username": r[0], "role": r[1]} for r in cursor.fetchall()]
    conn.close()

    return {
        "status": "ok",
        "version": "1.0.0",
        "users": users
    }


@app.route("/api/v1/config")
def api_config():
    """Config endpoint — FIXED: requires admin session, redacted sensitive data"""
    if session.get("role") != "admin":
        return {"error": "Forbidden"}, 403
    return {
        "debug": app.debug,
        "version": "1.0.0"
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
