"""
VulnScan - Local AI Code Vulnerability Scanner
Powered by Qwen3.5 via Ollama
"""

import os
import uuid
import json
import time
import hashlib
import logging
import mimetypes
from pathlib import Path
from datetime import datetime
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, request, jsonify, render_template,
    send_from_directory, session, abort
)
from werkzeug.utils import secure_filename

from core.scanner import VulnerabilityScanner
from core.guardrails import Guardrails
from core.file_manager import FileManager

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("vulnscan.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("vulnscan")

# ─── App Config ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config.update(
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,   # 50 MB total upload limit
    UPLOAD_FOLDER=Path("uploads"),
    OUTPUT_FOLDER=Path("outputs"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("outputs")
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ─── Allowed file extensions ─────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".go", ".rs", ".php", ".rb", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".sql", ".html", ".css",
    ".json", ".yaml", ".yml", ".toml", ".env", ".cfg", ".conf",
    ".xml", ".tf", ".hcl"
}

MAX_FILE_SIZE = 500 * 1024   # 500 KB per file
MAX_FILES = 100

# ─── Rate limiting ───────────────────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 10       # requests
RATE_WINDOW = 60      # seconds


def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = time.time()
        window_start = now - RATE_WINDOW
        _rate_store[ip] = [t for t in _rate_store[ip] if t > window_start]
        if len(_rate_store[ip]) >= RATE_LIMIT:
            log.warning(f"Rate limit hit for {ip}")
            return jsonify({"error": "Rate limit exceeded. Please wait before retrying."}), 429
        _rate_store[ip].append(now)
        return f(*args, **kwargs)
    return wrapper


# ─── Helpers ─────────────────────────────────────────────────────────────────
def get_session_dir() -> Path:
    sid = session.get("scan_id")
    if not sid:
        sid = str(uuid.uuid4())
        session["scan_id"] = sid
    d = UPLOAD_DIR / sid
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_path(base: Path, filename: str) -> Path:
    """Ensure the resolved path stays within base to prevent traversal."""
    resolved = (base / filename).resolve()
    if not str(resolved).startswith(str(base.resolve())):
        abort(400, "Invalid file path")
    return resolved


def allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def is_text_file(path: Path) -> bool:
    """Quick binary sniff — reject non-text files."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        return b"\x00" not in chunk
    except Exception:
        return False


# ─── Routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
@rate_limited
def upload_files():
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "Empty file list"}), 400
    if len(files) > MAX_FILES:
        return jsonify({"error": f"Maximum {MAX_FILES} files allowed per scan"}), 400

    session_dir = get_session_dir()
    saved = []
    skipped = []

    for f in files:
        original_name = f.filename or ""
        if not original_name:
            continue

        # Sanitize filename & enforce path safety
        safe_name = secure_filename(original_name)
        if not safe_name or not allowed_file(safe_name):
            skipped.append({"name": original_name, "reason": "Extension not allowed"})
            continue

        dest = safe_path(session_dir, safe_name)

        # Size check before write
        f.seek(0, 2)
        size = f.tell()
        f.seek(0)
        if size > MAX_FILE_SIZE:
            skipped.append({"name": original_name, "reason": "File exceeds 500 KB limit"})
            continue

        f.save(dest)

        # Text check after save (reject binaries that sneaked through)
        if not is_text_file(dest):
            dest.unlink(missing_ok=True)
            skipped.append({"name": original_name, "reason": "Binary file detected"})
            continue

        # Content guard-rail: check for obvious prompt injection attempts
        content = dest.read_text(errors="replace")
        if Guardrails.is_prompt_injection(content):
            dest.unlink(missing_ok=True)
            skipped.append({"name": original_name, "reason": "Suspicious content detected"})
            log.warning(f"Prompt injection attempt in file: {original_name}")
            continue

        saved.append(safe_name)
        log.info(f"Uploaded: {safe_name} ({size} bytes) session={session['scan_id']}")

    if not saved:
        return jsonify({"error": "No valid files uploaded", "skipped": skipped}), 400

    return jsonify({
        "status": "ok",
        "files": saved,
        "skipped": skipped,
        "session_id": session["scan_id"]
    })


@app.route("/api/scan", methods=["POST"])
@rate_limited
def run_scan():
    if "scan_id" not in session:
        return jsonify({"error": "No active session. Upload files first."}), 400

    session_dir = UPLOAD_DIR / session["scan_id"]
    if not session_dir.exists():
        return jsonify({"error": "Session directory not found"}), 400

    files = list(session_dir.glob("*"))
    if not files:
        return jsonify({"error": "No files to scan"}), 400

    data = request.get_json(silent=True) or {}
    severity_filter = data.get("severity", "all")   # all | critical | high | medium | low
    target_files = data.get("files", [])             # optional subset

    scanner = VulnerabilityScanner()
    fm = FileManager(session_dir)

    scan_files = fm.get_files(target_files if target_files else None)
    if not scan_files:
        return jsonify({"error": "No scannable files found"}), 400

    log.info(f"Starting scan: {len(scan_files)} files, session={session['scan_id']}")

    try:
        result = scanner.scan_codebase(scan_files, severity_filter=severity_filter)
    except ConnectionError:
        return jsonify({"error": "Cannot reach Ollama. Is it running on port 11434?"}), 503
    except Exception as e:
        log.error(f"Scan error: {e}", exc_info=True)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # Save results to output dir
    out_id = session["scan_id"]
    out_path = OUTPUT_DIR / f"{out_id}_results.json"
    out_path.write_text(json.dumps(result, indent=2))

    return jsonify(result)


@app.route("/api/fix", methods=["POST"])
@rate_limited
def apply_fix():
    if "scan_id" not in session:
        return jsonify({"error": "No active session"}), 400

    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")
    vuln_id = data.get("vuln_id", "")

    if not filename or not vuln_id:
        return jsonify({"error": "filename and vuln_id required"}), 400

    session_dir = UPLOAD_DIR / session["scan_id"]
    results_path = OUTPUT_DIR / f"{session['scan_id']}_results.json"

    if not results_path.exists():
        return jsonify({"error": "No scan results found. Run a scan first."}), 400

    results = json.loads(results_path.read_text())

    # Find the vulnerability
    vuln = None
    file_result = None
    for fr in results.get("files", []):
        if fr["filename"] == filename:
            file_result = fr
            for v in fr.get("vulnerabilities", []):
                if v["id"] == vuln_id:
                    vuln = v
                    break

    if not vuln or not file_result:
        return jsonify({"error": "Vulnerability not found"}), 404

    file_path = safe_path(session_dir, filename)
    if not file_path.exists():
        return jsonify({"error": "Source file not found"}), 404

    original_code = file_path.read_text(errors="replace")

    scanner = VulnerabilityScanner()
    try:
        fix_result = scanner.generate_fix(
            filename=filename,
            original_code=original_code,
            vulnerability=vuln,
            all_files=FileManager(session_dir).get_files()
        )
    except ConnectionError:
        return jsonify({"error": "Cannot reach Ollama"}), 503
    except Exception as e:
        log.error(f"Fix generation error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

    return jsonify(fix_result)


@app.route("/api/apply-patch", methods=["POST"])
@rate_limited
def apply_patch():
    """Write fixed code back to the session directory."""
    if "scan_id" not in session:
        return jsonify({"error": "No active session"}), 400

    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")
    fixed_code = data.get("fixed_code", "")

    if not filename or not fixed_code:
        return jsonify({"error": "filename and fixed_code required"}), 400

    # Guard-rail: scan fixed code for injections before writing
    if Guardrails.is_prompt_injection(fixed_code):
        return jsonify({"error": "Fixed code failed safety check"}), 400

    session_dir = UPLOAD_DIR / session["scan_id"]
    file_path = safe_path(session_dir, filename)

    # Backup original
    backup = file_path.with_suffix(file_path.suffix + ".bak")
    if file_path.exists():
        backup.write_text(file_path.read_text(errors="replace"))

    file_path.write_text(fixed_code)
    log.info(f"Patch applied: {filename} session={session['scan_id']}")

    return jsonify({"status": "ok", "backup": backup.name})


@app.route("/api/download/<filename>")
def download_file(filename: str):
    if "scan_id" not in session:
        abort(403)
    safe_name = secure_filename(filename)
    session_dir = UPLOAD_DIR / session["scan_id"]
    return send_from_directory(session_dir, safe_name, as_attachment=True)


@app.route("/api/session/clear", methods=["POST"])
def clear_session():
    if "scan_id" in session:
        sid = session.pop("scan_id")
        # Clean up files
        import shutil
        d = UPLOAD_DIR / sid
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        r = OUTPUT_DIR / f"{sid}_results.json"
        r.unlink(missing_ok=True)
        log.info(f"Session cleared: {sid}")
    return jsonify({"status": "cleared"})


@app.route("/api/status")
def status():
    """Check if Ollama is reachable."""
    import urllib.request
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3) as r:
            tags = json.loads(r.read())
        models = [m["name"] for m in tags.get("models", [])]
        qwen_available = any("qwen" in m.lower() for m in models)
        return jsonify({
            "ollama": "online",
            "models": models,
            "qwen_ready": qwen_available
        })
    except Exception as e:
        return jsonify({"ollama": "offline", "error": str(e)}), 503


# ─── Security headers ─────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response


if __name__ == "__main__":
    log.info("VulnScan starting — http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)