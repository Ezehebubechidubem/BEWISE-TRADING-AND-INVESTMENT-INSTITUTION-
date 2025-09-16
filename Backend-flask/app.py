
# app.py
import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from flask import (
    Flask, request, jsonify, send_from_directory,
    g, render_template, redirect, url_for, make_response
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
STATIC_FOLDER = os.path.join(BASE_DIR, "static")
DB_PATH = os.path.join(BASE_DIR, "data.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder=STATIC_FOLDER, template_folder=os.path.join(BASE_DIR, "templates"))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = secrets.token_urlsafe(32)

# In-memory session tokens (for demo). In production persist or use flask-login.
sessions = {}  # token -> {pin_id, device_id, expires_at}

# ---------- DB helpers ----------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS pins (
        id INTEGER PRIMARY KEY,
        pin TEXT UNIQUE,
        note TEXT,
        device_id TEXT,
        ip TEXT,
        revoked INTEGER DEFAULT 0,
        created_at TEXT,
        assigned_at TEXT
    )""")
    db.execute("""
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY,
        title TEXT,
        filename TEXT,
        uploaded_at TEXT
    )""")
    db.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY,
        name TEXT,
        email TEXT,
        course_title TEXT,
        proof_filename TEXT,
        created_at TEXT
    )""")
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# ---------- Utilities ----------
def generate_pin():
    return "{:06d}".format(secrets.randbelow(900000) + 100000)

def now_iso():
    return datetime.utcnow().isoformat()

def make_session(pin_id, device_id):
    token = secrets.token_urlsafe(32)
    sessions[token] = {
        "pin_id": pin_id,
        "device_id": device_id,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(hours=24)
    }
    return token

def validate_session_token(token):
    s = sessions.get(token)
    if not s:
        return None
    if s["expires_at"] < datetime.utcnow():
        sessions.pop(token, None)
        return None
    # also check that pin still exists and is not revoked
    db = get_db()
    row = db.execute("SELECT * FROM pins WHERE id=?", (s["pin_id"],)).fetchone()
    if not row or row["revoked"] == 1:
        sessions.pop(token, None)
        return None
    return s

# ---------- Routes (pages) ----------
@app.route("/")
def index():
    return render_template("authentication.html")

@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")

@app.route("/course")
def course_page():
    return render_template("course.html")

@app.route("/payment")
def payment_page():
    return render_template("payment.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")

# ---------- API ----------
@app.route("/api/login", methods=["POST"])
def api_login():
    """
    JSON: { pin: "123456", device_id: "device-uuid" }
    Behavior:
      - If pin not found or revoked => error.
      - If pin found and device_id is NULL => assign to device and issue session.
      - If pin found and device_id == provided => issue session.
      - If pin found and device_id != provided => automatically revoke the PIN and deny login.
    """
    db = get_db()
    data = request.json or {}
    pin = (data.get("pin") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    ip = request.remote_addr

    if not pin or len(pin) != 6:
        return jsonify({"success": False, "error": "invalid_pin_format"}), 400

    row = db.execute("SELECT * FROM pins WHERE pin=?", (pin,)).fetchone()
    if not row:
        return jsonify({"success": False, "error": "pin_not_found"}), 404

    if row["revoked"] == 1:
        return jsonify({"success": False, "error": "pin_revoked"}), 403

    # Unassigned -> assign to device
    if not row["device_id"]:
        db.execute("UPDATE pins SET device_id=?, ip=?, assigned_at=? WHERE id=?",
                   (device_id, ip, now_iso(), row["id"]))
        db.commit()
        token = make_session(row["id"], device_id)
        resp = jsonify({"success": True, "message": "logged_in"})
        resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
        return resp

    # assigned and matches
    if row["device_id"] == device_id:
        token = make_session(row["id"], device_id)
        resp = jsonify({"success": True, "message": "logged_in"})
        resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
        return resp

    # assigned but different device -> automatically revoke and deny
    db.execute("UPDATE pins SET revoked=1 WHERE id=?", (row["id"],))
    db.commit()
    return jsonify({"success": False, "error": "revoked_due_to_multiple_devices", "message": "PIN revoked because it was used on another device."}), 403

@app.route("/api/check_session")
def api_check_session():
    token = request.cookies.get("session_token")
    s = validate_session_token(token)
    if not s:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "pin_id": s["pin_id"], "device_id": s["device_id"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("session_token")
    if token and token in sessions:
        sessions.pop(token, None)
    resp = jsonify({"success": True})
    resp.delete_cookie("session_token")
    return resp

# Get all videos metadata
@app.route("/api/videos")
def api_videos():
    db = get_db()
    rows = db.execute("SELECT id, title, filename, uploaded_at FROM videos ORDER BY uploaded_at DESC").fetchall()
    videos = [dict(r) for r in rows]
    return jsonify(videos)

# Serve video only if session is valid and pin not revoked.
@app.route("/stream/<int:video_id>")
def stream_video(video_id):
    token = request.cookies.get("session_token")
    s = validate_session_token(token)
    if not s:
        return "Unauthorized", 401

    db = get_db()
    row = db.execute("SELECT * FROM videos WHERE id=?", (video_id,)).fetchone()
    if not row:
        return "Not found", 404

    filename = row["filename"]
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return "File missing", 404

    # Serve with headers that dissuade direct download and caching
    resp = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], filename))
    resp.headers["Content-Disposition"] = f'inline; filename="{filename}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

# Admin: upload video
@app.route("/api/admin/upload_video", methods=["POST"])
def api_admin_upload_video():
    # simple admin auth via header or cookie
    pw = request.headers.get("X-ADMIN-PW") or request.form.get("admin_pw")
    if pw != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "admin_auth_required"}), 403

    title = request.form.get("title", "").strip()
    f = request.files.get("video")
    if not f or not title:
        return jsonify({"success": False, "error": "missing_title_or_file"}), 400

    # safe filename
    safe_name = secrets.token_hex(8) + "_" + f.filename.replace(" ", "_")
    path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
    f.save(path)

    db = get_db()
    db.execute("INSERT INTO videos (title, filename, uploaded_at) VALUES (?, ?, ?)",
               (title, safe_name, now_iso()))
    db.commit()
    return jsonify({"success": True})

# Admin: generate pin
@app.route("/api/admin/generate_pin", methods=["POST"])
def api_admin_generate_pin():
    pw = request.headers.get("X-ADMIN-PW")
    if pw != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "admin_auth_required"}), 403

    note = (request.json or {}).get("note", "")[:200]
    pin = generate_pin()
    db = get_db()
    try:
        db.execute("INSERT INTO pins (pin, note, created_at) VALUES (?, ?, ?)", (pin, note, now_iso()))
        db.commit()
    except Exception as e:
        return jsonify({"success": False, "error": "db_error", "detail": str(e)}), 500

    return jsonify({"success": True, "pin": pin})

# Admin: list pins
@app.route("/api/admin/pins")
def api_admin_pins():
    pw = request.headers.get("X-ADMIN-PW")
    if pw != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    db = get_db()
    rows = db.execute("SELECT id, pin, note, device_id, ip, revoked, created_at, assigned_at FROM pins ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

# Admin: revoke pin by id
@app.route("/api/admin/revoke_pin", methods=["POST"])
def api_admin_revoke_pin():
    pw = request.headers.get("X-ADMIN-PW")
    if pw != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.json or {}
    pin_id = data.get("pin_id")
    if not pin_id:
        return jsonify({"success": False, "error": "missing_pin_id"}), 400
    db = get_db()
    db.execute("UPDATE pins SET revoked=1 WHERE id=?", (pin_id,))
    db.commit()
    return jsonify({"success": True})

# Payment proof upload (from payment page)
@app.route("/api/payment/proof", methods=["POST"])
def api_payment_proof():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    course_title = request.form.get("course_title", "")
    f = request.files.get("proof")
    if not name or not f:
        return jsonify({"success": False, "error": "missing_fields"}), 400
    safe_name = secrets.token_hex(8) + "_" + f.filename.replace(" ", "_")
    path = os.path.join(STATIC_FOLDER, safe_name)
    f.save(path)
    db = get_db()
    db.execute("INSERT INTO payments (name, email, course_title, proof_filename, created_at) VALUES (?, ?, ?, ?, ?)",
               (name, email, course_title, safe_name, now_iso()))
    db.commit()
    return jsonify({"success": True})

# serve logo
@app.route("/logo.png")
def logo():
    path = os.path.join(STATIC_FOLDER, "logo.png")
    if os.path.exists(path):
        return send_from_directory(STATIC_FOLDER, "logo.png")
    # return a small placeholder SVG if logo not provided
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='200' height='60'><rect width='100%' height='100%' fill='#444'/>"
           "<text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#fff' font-size='18'>LOGO</text></svg>")
    resp = make_response(svg)
    resp.headers['Content-Type'] = 'image/svg+xml'
    return resp

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
