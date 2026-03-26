"""
PSYCHIQ Vulnerable Web Application
Enterprise Adversary Gym — Intentionally vulnerable web application
for red team exercises. DO NOT deploy in production.

Vulnerabilities (all CodeQL-detectable):
  CWE-89:  SQL Injection (login form)
  CWE-78:  OS Command Injection (diagnostics endpoint)
  CWE-22:  Path Traversal (file download)
  CWE-434: Unrestricted File Upload (upload form)
  CWE-79:  Reflected XSS (search)
"""

import os
import sqlite3
import subprocess
from flask import (
    Flask, request, render_template, redirect,
    send_file, flash, session
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "psychiq-insecure-secret-key-changeme"

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
        # VULN: String concatenation in SQL query — SQL injection
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        cursor.execute(query)
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
            # VULN: No file extension validation — allows .py, .sh, .aspx, .php, .jsp uploads
            # VULN: Using user-supplied filename directly without secure_filename()
            filename = f.filename
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

    # VULN: No path sanitization — allows ../../../etc/passwd
    file_path = os.path.join(UPLOAD_FOLDER, filename)
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
        # VULN: User input passed directly to shell command
        cmd = "ping -c 3 " + target
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
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

    # VULN: Rendering user input directly in response without escaping
    return f"""
    <html>
    <head><title>Search Results</title>
    <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
    <div class="container">
        <h2>Search Results for: {query}</h2>
        <ul>
        {"".join(f"<li>{r[0]}</li>" for r in results) if results else "<li>No results found</li>"}
        </ul>
        <a href="/">Back</a>
    </div>
    </body>
    </html>
    """


# ── Serve uploaded files (enables webshell execution in ASPX scenario) ──
@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
