# app.py
import os
import secrets
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import (
    Flask, request, jsonify, render_template, send_from_directory,
    make_response, abort, url_for
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from jinja2 import TemplateNotFound

# --------------- Configuration ---------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "data.db")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Environment-configurable settings (set via Render env)
ADMIN_PIN = os.environ.get("ADMIN_PIN", "891959")            # admin pin default
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", ADMIN_PIN) # header fallback
ALLOWED_DEVICE_HASH = os.environ.get("ALLOWED_DEVICE_HASH")  # optional: lock to a single device fingerprint
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(24))
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024))  # bytes
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"  # set 0 for local http testing

RENDER_HOST = os.environ.get("RENDER_HOST", "bewise-trading-and-investment-institution.onrender.com")

# --------------- App setup ---------------
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = SECRET_KEY

# CORS for API endpoints; allow credentials
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("crypto_training")

db = SQLAlchemy(app)

# --------------- Models ---------------
class Pin(db.Model):
    __tablename__ = "pins"
    id = db.Column(db.Integer, primary_key=True)
    pin = db.Column(db.String(6), unique=True, nullable=False)
    note = db.Column(db.String(256))
    device_id = db.Column(db.String(512))
    ip = db.Column(db.String(64))
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_at = db.Column(db.DateTime, nullable=True)

class Video(db.Model):
    __tablename__ = "videos"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512))
    filename = db.Column(db.String(1024))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    course_title = db.Column(db.String(300))
    proof_filename = db.Column(db.String(1024))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Session(db.Model):
    __tablename__ = "sessions"
    token = db.Column(db.String(128), primary_key=True)
    pin_id = db.Column(db.Integer, db.ForeignKey("pins.id"))
    device_id = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

# --------------- Utilities ---------------
def now():
    return datetime.utcnow()

def generate_pin():
    for _ in range(30):
        candidate = "{:06d}".format(secrets.randbelow(900000) + 100000)
        if not Pin.query.filter_by(pin=candidate).first():
            return candidate
    raise RuntimeError("Unable to generate unique PIN")

def create_session(pin_id, device_id, hours=24):
    token = secrets.token_urlsafe(40)
    s = Session(token=token, pin_id=pin_id, device_id=device_id,
                created_at=now(), expires_at=now() + timedelta(hours=hours))
    db.session.add(s); db.session.commit()
    return token

def validate_session(token):
    if not token:
        return None
    s = Session.query.filter_by(token=token).first()
    if not s:
        return None
    if s.expires_at < now():
        try:
            db.session.delete(s); db.session.commit()
        except Exception:
            pass
        return None
    p = Pin.query.get(s.pin_id)
    if not p or p.revoked:
        try:
            db.session.delete(s); db.session.commit()
        except Exception:
            pass
        return None
    return s

def admin_auth_ok(req):
    header = req.headers.get("X-ADMIN-PW")
    if header and header == ADMIN_PASSWORD:
        return True
    token = req.cookies.get("session_token")
    s = validate_session(token)
    if s:
        p = Pin.query.get(s.pin_id)
        if p and p.pin == ADMIN_PIN:
            return True
    return False

def set_session_cookie(resp, token):
    # samesite None required when cross-site cookies are used with Secure
    samesite_val = "None" if COOKIE_SECURE else "Lax"
    resp.set_cookie("session_token", token, httponly=True, samesite=samesite_val, secure=COOKIE_SECURE)
    return resp

# --------------- Init DB & ensure admin pin ---------------
with app.app_context():
    db.create_all()
    if not Pin.query.filter_by(pin=ADMIN_PIN).first():
        p = Pin(pin=ADMIN_PIN, note="admin-pin", created_at=now(), revoked=False)
        db.session.add(p); db.session.commit()
        logger.info("Created admin PIN %s", ADMIN_PIN)

# --------------- Error handling ---------------
@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "file_too_large"}), 413

@app.errorhandler(Exception)
def handle_all_exceptions(e):
    # Log
    logger.exception("Unhandled exception: %s", e)
    # If request is API path, return JSON; else return a simple HTML error page.
    if request.path.startswith("/api/") or request.accept_mimetypes.accept_json:
        return jsonify({"error": "internal_server_error", "message": str(e), "success": False}), 500
    # For HTML requests, try to show a friendly page
    try:
        return render_template("error.html", message=str(e)), 500
    except TemplateNotFound:
        # minimal HTML fallback
        body = f"<h1>Internal Server Error</h1><p>{str(e)}</p>"
        return make_response(body, 500)

# --------------- Page routes (serve both /admin and /admin.html) ---------------
def safe_render(name):
    """Render template name.html from templates or fallback to file serving."""
    tpl_name = f"{name}.html"
    try:
        return render_template(tpl_name)
    except TemplateNotFound:
        # fallback: try to serve the HTML file from templates folder
        path = os.path.join(app.template_folder, tpl_name)
        if os.path.exists(path):
            return send_from_directory(app.template_folder, tpl_name)
        raise

# Root and pages
@app.route("/", methods=["GET"])
def page_root():
    return safe_render("authentication")

@app.route("/authentication.html", methods=["GET"])
def auth_html():
    return safe_render("authentication")

@app.route("/admin", methods=["GET"])
def page_admin():
    return safe_render("admin")

@app.route("/admin.html", methods=["GET"])
def admin_html():
    return safe_render("admin")

@app.route("/dashboard", methods=["GET"])
def page_dashboard():
    return safe_render("dashboard")

@app.route("/dashboard.html", methods=["GET"])
def dashboard_html():
    return safe_render("dashboard")

@app.route("/course", methods=["GET"])
def page_course():
    return safe_render("course")

@app.route("/course.html", methods=["GET"])
def course_html():
    return safe_render("course")

@app.route("/payment", methods=["GET"])
def page_payment():
    return safe_render("payment")

@app.route("/payment.html", methods=["GET"])
def payment_html():
    return safe_render("payment")

# Serve logo
@app.route("/logo.png")
def logo():
    path = os.path.join(app.static_folder or STATIC_DIR, "logo.png")
    if os.path.exists(path):
        return send_from_directory(app.static_folder, "logo.png")
    # fallback svg
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='240' height='60'>"
           "<rect width='100%' height='100%' fill='#062035'/>"
           "<text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#cfefff' font-size='16'>LOGO</text></svg>")
    r = make_response(svg)
    r.headers["Content-Type"] = "image/svg+xml"
    return r

# --------------- API: Auth ---------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    pin = (data.get("pin") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    ip = request.remote_addr

    if not pin or len(pin) != 6 or not pin.isdigit():
        return jsonify({"success": False, "error": "invalid_pin_format"}), 400

    if ALLOWED_DEVICE_HASH and device_id and device_id != ALLOWED_DEVICE_HASH:
        return jsonify({"success": False, "error": "device_not_allowed", "message": "This installation is locked to a single device."}), 403

    p = Pin.query.filter_by(pin=pin).first()
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    if p.revoked:
        return jsonify({"success": False, "error": "pin_revoked"}), 403

    # Assign to first device
    if not p.device_id:
        p.device_id = device_id
        p.ip = ip
        p.assigned_at = now()
        db.session.add(p); db.session.commit()
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in", "role": ("admin" if p.pin == ADMIN_PIN else "user")})
        set_session_cookie(resp, token)
        return resp

    # If device matches
    if p.device_id == device_id:
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in", "role": ("admin" if p.pin == ADMIN_PIN else "user")})
        set_session_cookie(resp, token)
        return resp

    # Different device -> revoke
    p.revoked = True
    db.session.add(p); db.session.commit()
    return jsonify({"success": False, "error": "revoked_due_to_multiple_devices", "message": "PIN revoked because it was used on another device."}), 403

@app.route("/api/check_session", methods=["GET"])
def api_check_session():
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        return jsonify({"logged_in": False})
    p = Pin.query.get(s.pin_id)
    return jsonify({"logged_in": True, "pin_id": s.pin_id, "device_id": s.device_id, "is_admin": (p.pin == ADMIN_PIN if p else False)})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("session_token")
    if token:
        s = Session.query.get(token)
        if s:
            db.session.delete(s); db.session.commit()
    resp = jsonify({"success": True})
    resp.delete_cookie("session_token")
    return resp

# --------------- API: Videos ----------------
@app.route("/api/videos", methods=["GET"])
def api_videos():
    rows = Video.query.order_by(Video.uploaded_at.desc()).all()
    return jsonify([{"id": r.id, "title": r.title, "uploaded_at": r.uploaded_at.isoformat()} for r in rows])

@app.route("/stream/<int:video_id>", methods=["GET"])
def stream_video(video_id):
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        return ("Unauthorized", 401)
    v = Video.query.get(video_id)
    if not v:
        return ("Not found", 404)
    path = os.path.join(app.config["UPLOAD_FOLDER"], v.filename)
    if not os.path.exists(path):
        return ("File missing", 404)
    resp = make_response(send_from_directory(app.config["UPLOAD_FOLDER"], v.filename))
    resp.headers["Content-Disposition"] = f'inline; filename="{v.filename}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

# --------------- API: Admin ----------------
@app.route("/api/admin/upload_video", methods=["POST"])
def api_admin_upload_video():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    title = (request.form.get("title") or "").strip()
    f = request.files.get("video")
    if not f or not title:
        return jsonify({"success": False, "error": "missing_title_or_file"}), 400
    safe_name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    dest = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    f.save(dest)
    v = Video(title=title, filename=safe_name, uploaded_at=now())
    db.session.add(v); db.session.commit()
    return jsonify({"success": True, "video_id": v.id})

@app.route("/api/admin/generate_pin", methods=["POST"])
def api_admin_generate_pin():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    note = (request.get_json() or {}).get("note", "")[:200]
    pin = generate_pin()
    p = Pin(pin=pin, note=note, created_at=now(), revoked=False)
    db.session.add(p); db.session.commit()
    return jsonify({"success": True, "pin": pin})

@app.route("/api/admin/pins", methods=["GET"])
def api_admin_pins():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    rows = Pin.query.order_by(Pin.created_at.desc()).all()
    data = []
    for r in rows:
        data.append({
            "id": r.id, "pin": r.pin, "note": r.note, "device_id": r.device_id,
            "ip": r.ip, "revoked": r.revoked,
            "created_at": (r.created_at.isoformat() if r.created_at else None),
            "assigned_at": (r.assigned_at.isoformat() if r.assigned_at else None)
        })
    return jsonify(data)

@app.route("/api/admin/revoke_pin", methods=["POST"])
def api_admin_revoke_pin():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    pin_id = data.get("pin_id")
    if not pin_id:
        return jsonify({"success": False, "error": "missing_pin_id"}), 400
    p = Pin.query.get(pin_id)
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    p.revoked = True
    db.session.add(p); db.session.commit()
    return jsonify({"success": True})

# --------------- API: Payment ----------------
@app.route("/api/payment/proof", methods=["POST"])
def api_payment_proof():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    course_title = request.form.get("course_title", "")
    f = request.files.get("proof")
    if not name or not f:
        return jsonify({"success": False, "error": "missing_fields"}), 400
    safe_name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    path = os.path.join(app.static_folder, safe_name)
    f.save(path)
    pay = Payment(name=name, email=email, course_title=course_title, proof_filename=safe_name, created_at=now())
    db.session.add(pay); db.session.commit()
    return jsonify({"success": True})

# --------------- Health (optional) ----------------
@app.route("/api/health")
def health():
    try:
        db.session.execute("SELECT 1")
        return jsonify({"ok": True})
    except Exception as e:
        logger.exception("Health check failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# --------------- Run server ---------------
if __name__ == "__main__":
    debug_flag = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_flag, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))