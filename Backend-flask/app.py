# app.py
import os
import secrets
from datetime import datetime, timedelta
from flask import (
    Flask, request, jsonify, send_from_directory, render_template, make_response, abort
)
from flask_sqlalchemy import SQLAlchemy

# ---------- Config ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL")  # e.g. postgres://user:pass@host:5432/dbname
if not DATABASE_URL:
    # fallback to sqlite for local dev if DATABASE_URL not provided
    DATABASE_URL = "sqlite:///" + os.path.join(BASE_DIR, "data.db")

ADMIN_PIN = os.environ.get("ADMIN_PIN", "891959")           # admin-pin (your requirement)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", ADMIN_PIN)  # admin API auth header value (default = ADMIN_PIN)
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(24))
# optional: set ALLOWED_DEVICE_HASH to restrict ALL logins to a single device fingerprint (server-side device lock)
ALLOWED_DEVICE_HASH = os.environ.get("ALLOWED_DEVICE_HASH")  # set this to your device fingerprint to lock site to your device

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = SECRET_KEY

db = SQLAlchemy(app)

# ---------- Models ----------
class Pin(db.Model):
    __tablename__ = "pins"
    id = db.Column(db.Integer, primary_key=True)
    pin = db.Column(db.String(6), unique=True, nullable=False)
    note = db.Column(db.String(200))
    device_id = db.Column(db.String(512))  # fingerprint assigned to
    ip = db.Column(db.String(64))
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_at = db.Column(db.DateTime)

class Video(db.Model):
    __tablename__ = "videos"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300))
    filename = db.Column(db.String(1000))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    course_title = db.Column(db.String(300))
    proof_filename = db.Column(db.String(1000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Session(db.Model):
    __tablename__ = "sessions"
    token = db.Column(db.String(128), primary_key=True)
    pin_id = db.Column(db.Integer, db.ForeignKey("pins.id"))
    device_id = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

# ---------- Helpers ----------
def now():
    return datetime.utcnow()

def generate_pin():
    return "{:06d}".format(secrets.randbelow(900000) + 100000)

def create_session(pin_id, device_id, hours=24):
    token = secrets.token_urlsafe(40)
    s = Session(token=token, pin_id=pin_id, device_id=device_id,
                created_at=now(), expires_at=now() + timedelta(hours=hours))
    db.session.add(s); db.session.commit()
    return token

def validate_session(token):
    if not token: return None
    s = Session.query.filter_by(token=token).first()
    if not s: return None
    if s.expires_at < now():
        try:
            db.session.delete(s); db.session.commit()
        except: pass
        return None
    # check pin not revoked
    p = Pin.query.get(s.pin_id)
    if not p or p.revoked:
        try:
            db.session.delete(s); db.session.commit()
        except: pass
        return None
    return s

def admin_auth_ok(req):
    header = req.headers.get("X-ADMIN-PW") or req.form.get("admin_pw")
    return header and header == ADMIN_PASSWORD

# ---------- Init DB & ensure admin pin exists ----------
with app.app_context():
    db.create_all()
    # ensure admin pin exists in the pins table (so admin login flows like a normal pin)
    admin_pin_obj = Pin.query.filter_by(pin=ADMIN_PIN).first()
    if not admin_pin_obj:
        p = Pin(pin=ADMIN_PIN, note="admin-pin", created_at=now(), revoked=False)
        db.session.add(p); db.session.commit()

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
    # keep payment.html untouched if you already have it in templates
    return render_template("payment.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")

# ---------- API endpoints ----------
@app.route("/api/login", methods=["POST"])
def api_login():
    """
    JSON body: { pin: "123456", device_id: "<fingerprint>" }
    Device-binding + single-device policy implemented:
      - If ALLOWED_DEVICE_HASH is set and device_id != allowed => deny
      - If PIN not found => 404
      - If pin.revoked => 403
      - If pin.device_id is null: assign to this device and issue session
      - If pin.device_id == device_id: issue session
      - If pin.device_id != device_id: auto-revoke pin and deny
    """
    data = request.get_json() or {}
    pin = (data.get("pin") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    ip = request.remote_addr

    if not pin or len(pin) != 6:
        return jsonify({"success": False, "error": "invalid_pin_format"}), 400

    # server-side device lock (optional)
    if ALLOWED_DEVICE_HASH and device_id and device_id != ALLOWED_DEVICE_HASH:
        return jsonify({"success": False, "error": "device_not_allowed", "message": "This installation is locked to a specific device."}), 403

    p = Pin.query.filter_by(pin=pin).first()
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404

    if p.revoked:
        return jsonify({"success": False, "error": "pin_revoked"}), 403

    # if unassigned -> assign to this device
    if not p.device_id:
        p.device_id = device_id
        p.ip = ip
        p.assigned_at = now()
        db.session.add(p); db.session.commit()
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in"})
        resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
        return resp

    # assigned and matching => session
    if p.device_id == device_id:
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in"})
        resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
        return resp

    # assigned to different device -> revoke automatically and deny
    p.revoked = True
    db.session.add(p); db.session.commit()
    return jsonify({"success": False, "error": "revoked_due_to_multiple_devices", "message": "PIN revoked because it was used on another device."}), 403

@app.route("/api/check_session")
def api_check_session():
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "pin_id": s.pin_id, "device_id": s.device_id})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("session_token")
    if token:
        s = Session.query.filter_by(token=token).first()
        if s:
            db.session.delete(s); db.session.commit()
    resp = jsonify({"success": True})
    resp.delete_cookie("session_token")
    return resp

# list videos metadata
@app.route("/api/videos")
def api_videos():
    rows = Video.query.order_by(Video.uploaded_at.desc()).all()
    data = [{"id":r.id, "title":r.title, "uploaded_at": r.uploaded_at.isoformat()} for r in rows]
    return jsonify(data)

# stream protected video
@app.route("/stream/<int:video_id>")
def stream_video(video_id):
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        return "Unauthorized", 401
    v = Video.query.get(video_id)
    if not v:
        return "Not found", 404
    path = os.path.join(app.config["UPLOAD_FOLDER"], v.filename)
    if not os.path.exists(path):
        return "File missing", 404
    resp = make_response(send_from_directory(app.config["UPLOAD_FOLDER"], v.filename))
    resp.headers["Content-Disposition"] = f'inline; filename="{v.filename}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

# admin: upload video
@app.route("/api/admin/upload_video", methods=["POST"])
def api_admin_upload_video():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    title = request.form.get("title", "").strip()
    f = request.files.get("video")
    if not f or not title:
        return jsonify({"success": False, "error": "missing_title_or_file"}), 400
    safe_name = secrets.token_hex(8) + "_" + f.filename.replace(" ", "_")
    path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    f.save(path)
    v = Video(title=title, filename=safe_name, uploaded_at=now())
    db.session.add(v); db.session.commit()
    return jsonify({"success": True})

# admin: generate pin
@app.route("/api/admin/generate_pin", methods=["POST"])
def api_admin_generate_pin():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    note = (request.json or {}).get("note", "")[:200]
    # try unique pin
    tries = 0
    pin = None
    while tries < 5:
        tries += 1
        candidate = generate_pin()
        if not Pin.query.filter_by(pin=candidate).first():
            pin = candidate; break
    if not pin:
        return jsonify({"success": False, "error": "could_not_create_pin"}), 500
    p = Pin(pin=pin, note=note, created_at=now())
    db.session.add(p); db.session.commit()
    return jsonify({"success": True, "pin": pin})

# admin: list pins
@app.route("/api/admin/pins")
def api_admin_pins():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    rows = Pin.query.order_by(Pin.created_at.desc()).all()
    data = []
    for r in rows:
        data.append({
            "id": r.id, "pin": r.pin, "note": r.note, "device_id": r.device_id,
            "ip": r.ip, "revoked": r.revoked, "created_at": (r.created_at.isoformat() if r.created_at else None),
            "assigned_at": (r.assigned_at.isoformat() if r.assigned_at else None)
        })
    return jsonify(data)

# admin: revoke pin
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

# payment proof upload
@app.route("/api/payment/proof", methods=["POST"])
def api_payment_proof():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    course_title = request.form.get("course_title", "")
    f = request.files.get("proof")
    if not name or not f:
        return jsonify({"success": False, "error": "missing_fields"}), 400
    safe_name = secrets.token_hex(8) + "_" + f.filename.replace(" ", "_")
    path = os.path.join(app.static_folder, safe_name)
    f.save(path)
    pay = Payment(name=name, email=email, course_title=course_title, proof_filename=safe_name, created_at=now())
    db.session.add(pay); db.session.commit()
    return jsonify({"success": True})

# serve logo (static/logo.png) fallback
@app.route("/logo.png")
def logo():
    p = os.path.join(app.static_folder, "logo.png")
    if os.path.exists(p):
        return send_from_directory(app.static_folder, "logo.png")
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='200' height='60'><rect width='100%' height='100%' fill='#444'/>"
           "<text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#fff' font-size='18'>LOGO</text></svg>")
    return make_response(svg, 200, {"Content-Type": "image/svg+xml"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)