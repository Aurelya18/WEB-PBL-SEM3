from flask import Flask, render_template, redirect, url_for, request, session, flash, g, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash as werkzeug_check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from argon2.low_level import Type as Argon2Type
import os, re, json, base64, csv, smtplib
from io import StringIO, BytesIO
from email.message import EmailMessage
from sqlalchemy.types import TypeDecorator, Text
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ================= Env =================
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ================= App =================
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///konseling.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-this')

# Cookie/HTTPS defaults
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('SESSION_COOKIE_SECURE', True)
app.config.setdefault('PREFERRED_URL_SCHEME', 'https')

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# ================= Email =================
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
MAIL_USE_TLS = str(os.environ.get('MAIL_USE_TLS', 'True')).lower() == 'true'
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME or 'noreply@example.com')

# ================= Policy self-register =================
ALLOW_STAFF_SELF_REGISTER = str(os.environ.get('ALLOW_STAFF_SELF_REGISTER', 'false')).lower() == 'true'

# ================= Password (Argon2id) =================
ph = PasswordHasher(time_cost=3, memory_cost=128 * 1024, parallelism=1,
                    hash_len=32, salt_len=16, type=Argon2Type.ID)

def is_werkzeug_pbkdf2(hash_str: str) -> bool:
    return isinstance(hash_str, str) and hash_str.startswith('pbkdf2:')

def set_password_argon2(plain_password: str) -> str:
    return ph.hash(plain_password)

def verify_password_and_migrate(user, input_password: str) -> bool:
    stored = user.password_hash or ''
    try:
        # migrasi dari hash lama (Werkzeug) -> Argon2
        if is_werkzeug_pbkdf2(stored):
            if not werkzeug_check_password_hash(stored, input_password):
                return False
            user.password_hash = set_password_argon2(input_password)
            db.session.commit()
            return True

        ok = ph.verify(stored, input_password)
        if not ok:
            return False
        if ph.check_needs_rehash(stored):
            user.password_hash = set_password_argon2(input_password)
            db.session.commit()
        return True
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False

# ================= Hybrid Encryption (soft-fallback) =================
RSA_PRIVATE_KEY_PATH = os.environ.get("RSA_PRIVATE_KEY_PATH")
RSA_PUBLIC_KEY_PATH  = os.environ.get("RSA_PUBLIC_KEY_PATH")
RSA_PRIVATE_KEY_PEM  = os.environ.get("RSA_PRIVATE_KEY")
RSA_PUBLIC_KEY_PEM   = os.environ.get("RSA_PUBLIC_KEY")
APP_KEY_ID           = os.environ.get("APP_KEY_ID", "v1")

def _load_private_key():
    if RSA_PRIVATE_KEY_PATH and os.path.exists(RSA_PRIVATE_KEY_PATH):
        with open(RSA_PRIVATE_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    if RSA_PRIVATE_KEY_PEM:
        return serialization.load_pem_private_key(RSA_PRIVATE_KEY_PEM.encode(), password=None)
    raise RuntimeError("RSA private key belum diset.")

def _load_public_key():
    if RSA_PUBLIC_KEY_PATH and os.path.exists(RSA_PUBLIC_KEY_PATH):
        with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    if RSA_PUBLIC_KEY_PEM:
        return serialization.load_pem_public_key(RSA_PUBLIC_KEY_PEM.encode())
    raise RuntimeError("RSA public key belum diset.")

# Coba muat kunci, jika gagal -> fallback non-encrypted (app tetap jalan)
try:
    _RSA_PRIV = _load_private_key()
    _RSA_PUB  = _load_public_key()
    ENCRYPTION_OK = True
except Exception as e:
    print("[warn] RSA keys not set. Running WITHOUT field encryption. Reason:", e)
    _RSA_PRIV = None
    _RSA_PUB  = None
    ENCRYPTION_OK = False

def _encrypt_value(plaintext: str) -> str:
    if not ENCRYPTION_OK:
        return plaintext
    data_key = Fernet.generate_key()
    f = Fernet(data_key)
    ct = f.encrypt(plaintext.encode()).decode()
    wk = _RSA_PUB.encrypt(
        data_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    wk_b64 = base64.b64encode(wk).decode()
    return json.dumps({"v": 1, "alg": "fernet+rsa-oaep", "kid": APP_KEY_ID, "ct": ct, "wk": wk_b64})

def _decrypt_value(db_value: str) -> str:
    if db_value is None:
        return None
    if not ENCRYPTION_OK:
        # Jika DB sudah berisi blob terenkripsi tapi kunci tidak ada,
        # tampilkan placeholder agar UI tidak "aneh".
        try:
            blob = json.loads(db_value)
            if isinstance(blob, dict) and "ct" in blob and "wk" in blob:
                return "[data terenkripsi]"
        except Exception:
            pass
        return db_value
    try:
        blob = json.loads(db_value)
        if not isinstance(blob, dict) or "ct" not in blob or "wk" not in blob:
            return db_value
        data_key = _RSA_PRIV.decrypt(
            base64.b64decode(blob["wk"]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        f = Fernet(data_key)
        return f.decrypt(blob["ct"].encode()).decode()
    except Exception:
        return db_value

class HybridEncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True
    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return _encrypt_value(value)
    def process_result_value(self, value, dialect):
        return _decrypt_value(value)

# ================= Models =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)   # pola sesuai peran
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)                     # mahasiswa | konselor | admin

    keluhan = db.relationship("Keluhan", backref="mahasiswa", foreign_keys="Keluhan.mahasiswa_id")
    tangani = db.relationship("Keluhan", backref="konselor", foreign_keys="Keluhan.konselor_id")
    respon = db.relationship("Respon", backref="konselor", lazy=True)

    def set_password(self, password: str):
        self.password_hash = set_password_argon2(password)

    def check_password(self, password: str) -> bool:
        return verify_password_and_migrate(self, password)

class Keluhan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    kategori = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(HybridEncryptedText, nullable=False)
    status = db.Column(db.String(50), default="Menunggu")
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    tanggal_direspon = db.Column(db.DateTime)
    mahasiswa_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    konselor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    respon = db.relationship("Respon", backref="keluhan", lazy=True, order_by="Respon.tanggal_respon.asc()")

class Respon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pesan = db.Column(HybridEncryptedText, nullable=False)
    tanggal_respon = db.Column(db.DateTime, default=datetime.utcnow)
    keluhan_id = db.Column(db.Integer, db.ForeignKey("keluhan.id"), nullable=False)
    konselor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# ================= Auth helpers & CSRF =================
@app.before_request
def load_current_user():
    g.current_user = None
    if "user_id" in session:
        g.current_user = User.query.get(session["user_id"])

@app.context_processor
def inject_user():
    # expose csrf_token() ke semua template
    return dict(current_user=g.current_user, csrf_token=generate_csrf)

def require_role(role_name):
    return ("user_id" in session) and (session.get("role") == role_name)

# ================= Username pattern (role inference) =================
STU_RE = re.compile(r'^[a-z][a-z0-9]*\.[0-9]{6,}$')     # contoh: aurel.4335908
KNS_RE = re.compile(r'(?i)^KNS-\d{4,}$')                # contoh: KNS-0001
ADM_RE = re.compile(r'(?i)^ADM-\d{4,}$')                # contoh: ADM-0001

def infer_role_and_normalize(raw_username: str):
    """
    return (role, normalized_username) or (None, None) jika tidak match.
    - mahasiswa -> lowercase
    - konselor/admin -> uppercase
    """
    if not raw_username:
        return (None, None)
    u = raw_username.strip()
    if ADM_RE.match(u): return ("admin", u.upper())
    if KNS_RE.match(u): return ("konselor", u.upper())
    if STU_RE.match(u.lower()): return ("mahasiswa", u.lower())
    return (None, None)

# ================= Routes - Public =================
@app.route("/")
def index():
    return render_template("index.html")

# ================= Routes - Mahasiswa =================
@app.route("/dashboard_mahasiswa")
def dashboard_mahasiswa():
    if "user_id" not in session or session.get("role") != "mahasiswa":
        return redirect(url_for("login"))
    user_id = session["user_id"]
    total_keluhan = Keluhan.query.filter_by(mahasiswa_id=user_id).count()
    keluhan_menunggu = Keluhan.query.filter_by(mahasiswa_id=user_id, status="Menunggu").count()
    keluhan_diproses = Keluhan.query.filter_by(mahasiswa_id=user_id, status="Diproses").count()
    keluhan_selesai = Keluhan.query.filter_by(mahasiswa_id=user_id, status="Selesai").count()

    notifications = []
    for k in Keluhan.query.filter_by(mahasiswa_id=user_id).all():
        if k.status == "Diproses" and k.tanggal_direspon:
            notifications.append(f"Keluhan '{k.judul}' sedang diproses konselor.")
        elif k.status == "Selesai":
            notifications.append(f"Keluhan '{k.judul}' telah selesai ditangani.")

    return render_template("dashboard_mahasiswa.html",
        total_keluhan=total_keluhan,
        keluhan_menunggu=keluhan_menunggu,
        keluhan_diproses=keluhan_diproses,
        keluhan_selesai=keluhan_selesai,
        notifications=notifications
    )

@app.route("/ajukan_keluhan", methods=["GET", "POST"])
def ajukan_keluhan():
    if "user_id" not in session or session.get("role") != "mahasiswa":
        return redirect(url_for("login"))
    if request.method == "POST":
        judul = request.form["judul"].strip()
        kategori = request.form["kategori"].strip()
        deskripsi = request.form["deskripsi"].strip()
        if not judul or not kategori or not deskripsi:
            flash("Semua field wajib diisi.", "warning")
            return redirect(url_for("ajukan_keluhan"))
        keluhan_baru = Keluhan(judul=judul, kategori=kategori, deskripsi=deskripsi, mahasiswa_id=session["user_id"])
        db.session.add(keluhan_baru)
        db.session.commit()
        flash("Keluhan berhasil diajukan!", "success")
        return redirect(url_for("riwayat_keluhan"))
    return render_template("ajukan_keluhan.html")

@app.route("/riwayat_keluhan")
def riwayat_keluhan():
    if "user_id" not in session or session.get("role") != "mahasiswa":
        return redirect(url_for("login"))
    keluhan_list = (Keluhan.query
                    .filter_by(mahasiswa_id=session["user_id"])
                    .order_by(Keluhan.tanggal_dibuat.desc())
                    .all())
    return render_template("riwayat_keluhan.html", keluhan_list=keluhan_list)

@app.route("/detail_keluhan/<int:keluhan_id>", methods=["GET", "POST"])
def detail_keluhan(keluhan_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    keluhan = Keluhan.query.get_or_404(keluhan_id)

    if session["role"] == "mahasiswa" and keluhan.mahasiswa_id != session["user_id"]:
        flash("Anda tidak berhak melihat keluhan ini.", "danger")
        return redirect(url_for("riwayat_keluhan"))

    if session["role"] == "konselor" and request.method == "POST":
        pesan = request.form.get("pesan", "").strip()
        if not pesan:
            flash("Pesan respon tidak boleh kosong.", "warning")
            return redirect(url_for("detail_keluhan", keluhan_id=keluhan.id))
        respon_baru = Respon(pesan=pesan, keluhan_id=keluhan.id, konselor_id=session["user_id"])
        keluhan.status = "Diproses"
        keluhan.konselor_id = session["user_id"]
        keluhan.tanggal_direspon = datetime.utcnow()
        db.session.add(respon_baru)
        db.session.commit()
        flash("Respon berhasil dikirim!", "success")
        return redirect(url_for("detail_keluhan", keluhan_id=keluhan.id))

    return render_template("detail_keluhan.html", keluhan=keluhan)

# ================= Routes - Actions =================
@app.route("/selesaikan_keluhan/<int:keluhan_id>", methods=["POST"])
def selesaikan_keluhan(keluhan_id):
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    keluhan = Keluhan.query.get_or_404(keluhan_id)
    keluhan.status = "Selesai"
    db.session.commit()
    flash(f"Keluhan '{keluhan.judul}' berhasil ditandai selesai.", "success")
    return redirect(url_for("dashboard_konselor"))

# ================= Routes - Auth =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        raw_username = request.form.get("username","").strip()
        password = request.form.get("password","")
        confirm  = request.form.get("confirm","")

        if not raw_username or not password or not confirm:
            flash("Semua field wajib diisi.", "warning")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Konfirmasi password tidak cocok.", "warning")
            return redirect(url_for("register"))
        if len(password) < 12:
            flash("Password minimal 12 karakter.", "warning")
            return redirect(url_for("register"))

        role, username = infer_role_and_normalize(raw_username)
        if not role:
            flash("Format username tidak valid. Mahasiswa: nama.nim (contoh aurel.4335908). Konselor: KNS-1234. Admin: ADM-1234.", "danger")
            return redirect(url_for("register"))

        # Batasi self-register staf jika dibutuhkan
        if role in ("konselor", "admin") and not ALLOW_STAFF_SELF_REGISTER:
            flash("Registrasi untuk Konselor/Admin tidak dibuka. Silakan hubungi Administrator.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username sudah digunakan.", "danger")
            return redirect(url_for("register"))

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registrasi berhasil, silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Throttling login sederhana
_LOGIN_ATTEMPTS = {}  # key: identifier (username/ip) -> (count, last_ts)
_MAX_ATTEMPTS = 7
_BLOCK_SECS = 60  # blokir 60 detik setelah melebihi batas

def _throttle_check(identifier: str) -> bool:
    now = datetime.utcnow().timestamp()
    rec = _LOGIN_ATTEMPTS.get(identifier)
    if not rec:
        return True
    count, last_ts = rec
    if count >= _MAX_ATTEMPTS and (now - last_ts) < _BLOCK_SECS:
        return False
    if (now - last_ts) >= _BLOCK_SECS:
        _LOGIN_ATTEMPTS.pop(identifier, None)
    return True

def _throttle_fail(identifier: str):
    now = datetime.utcnow().timestamp()
    count, last_ts = _LOGIN_ATTEMPTS.get(identifier, (0, now))
    _LOGIN_ATTEMPTS[identifier] = (count + 1, now)

def _throttle_ok(identifier: str):
    _LOGIN_ATTEMPTS.pop(identifier, None)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        raw_username = request.form.get("username","").strip()
        password = request.form.get("password","")

        ident = (raw_username or request.remote_addr or "anon")
        if not _throttle_check(ident):
            flash("Terlalu banyak percobaan login. Coba lagi dalam beberapa saat.", "warning")
            return render_template("login.html")

        # Cari user: exact -> lower -> upper (toleran input)
        user = User.query.filter_by(username=raw_username).first()
        if not user:
            user = User.query.filter_by(username=raw_username.lower()).first()
        if not user:
            user = User.query.filter_by(username=raw_username.upper()).first()

        if user and user.check_password(password):
            _throttle_ok(ident)
            session.clear()
            session["user_id"] = user.id
            session["role"] = user.role
            flash("Login berhasil!", "success")
            if user.role == "mahasiswa":
                return redirect(url_for("dashboard_mahasiswa"))
            elif user.role == "konselor":
                return redirect(url_for("dashboard_konselor"))
            elif user.role == "admin":
                return redirect(url_for("dashboard_admin"))
            else:
                return redirect(url_for("index"))
        else:
            _throttle_fail(ident)
            flash("Username atau password salah.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Anda telah logout", "info")
    return redirect(url_for("login"))

# ================= Routes - Konselor =================
@app.route("/dashboard_konselor")
def dashboard_konselor():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    konselor = User.query.get(session["user_id"])
    keluhan_menunggu = (Keluhan.query
                        .filter_by(status="Menunggu")
                        .order_by(Keluhan.tanggal_dibuat.desc())
                        .all())
    keluhan_saya = (Keluhan.query
                    .filter(Keluhan.konselor_id == konselor.id)
                    .order_by(Keluhan.tanggal_dibuat.desc())
                    .all())
    return render_template("dashboard_konselor.html",
        konselor=konselor,
        keluhan_menunggu=keluhan_menunggu,
        keluhan_saya=keluhan_saya
    )

@app.route("/tangani_keluhan/<int:keluhan_id>", methods=["POST"])
def tangani_keluhan(keluhan_id):
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    keluhan = Keluhan.query.get_or_404(keluhan_id)
    if keluhan.status != "Selesai":
        keluhan.status = "Diproses"
        keluhan.konselor_id = session["user_id"]
        keluhan.tanggal_direspon = datetime.utcnow()
        db.session.commit()
        flash(f"Keluhan '{keluhan.judul}' ditangani.", "success")
    return redirect(url_for("dashboard_konselor"))

@app.route("/respon_keluhan/<int:keluhan_id>", methods=["GET", "POST"])
def respon_keluhan(keluhan_id):
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    keluhan = Keluhan.query.get_or_404(keluhan_id)
    if request.method == "POST":
        pesan = request.form.get("pesan", "").strip()
        status = request.form.get("status", "Diproses")
        if not pesan:
            flash("Pesan respon tidak boleh kosong.", "warning")
            return redirect(url_for("respon_keluhan", keluhan_id=keluhan.id))
        respon = Respon(pesan=pesan, keluhan_id=keluhan.id, konselor_id=session["user_id"])
        if keluhan.status == "Menunggu":
            keluhan.konselor_id = session["user_id"]
            keluhan.tanggal_direspon = datetime.utcnow()
        keluhan.status = status if status in ("Diproses", "Selesai") else "Diproses"
        db.session.add(respon)
        db.session.commit()
        flash("Respon berhasil dikirim.", "success")
        return redirect(url_for("detail_keluhan", keluhan_id=keluhan.id))
    return render_template("respon_keluhan.html", keluhan=keluhan)

@app.route("/riwayat_keluhan_konselor")
def riwayat_keluhan_konselor():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    konselor = User.query.get(session["user_id"])
    status = request.args.get("status", "Semua")
    qtext = request.args.get("q", "").strip().lower()
    q_base = Keluhan.query.filter(Keluhan.konselor_id == konselor.id)
    if status in ("Menunggu", "Diproses", "Selesai"):
        q_base = q_base.filter(Keluhan.status == status)
    q_base = q_base.join(User, Keluhan.mahasiswa).order_by(Keluhan.tanggal_dibuat.desc())
    semua = q_base.all()
    if not qtext:
        keluhan_list = semua
    else:
        keluhan_list = [
            k for k in semua
            if (qtext in (k.judul or "").lower())
            or (qtext in (k.deskripsi or "").lower())
            or (qtext in (k.mahasiswa.username or "").lower())
        ]
    return render_template("riwayat_keluhan_konselor.html",
        konselor=konselor,
        keluhan_list=keluhan_list,
        status_filter=status
    )

# ================= Util Laporan Konselor =================
def _parse_date(s, default):
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return default

def _query_laporan(konselor_id, d_from, d_to, status, qtext):
    q = Keluhan.query.filter(Keluhan.konselor_id == konselor_id)
    if d_from:
        q = q.filter(Keluhan.tanggal_dibuat >= d_from)
    if d_to:
        q = q.filter(Keluhan.tanggal_dibuat < (d_to + timedelta(days=1)))
    if status in ("Menunggu", "Diproses", "Selesai"):
        q = q.filter(Keluhan.status == status)
    q = q.join(User, Keluhan.mahasiswa).order_by(Keluhan.tanggal_dibuat.desc())
    data = q.all()
    if qtext:
        t = qtext.lower().strip()
        data = [
            k for k in data
            if (t in (k.judul or "").lower())
            or (t in (k.deskripsi or "").lower())
            or (t in (k.mahasiswa.username or "").lower())
        ]
    return data

def _csv_bytes(rows):
    sio = StringIO(newline='')
    w = csv.writer(sio)
    w.writerow(["ID","Tanggal Dibuat","Mahasiswa","Judul","Kategori","Status","Tanggal Direspon","Konselor"])
    for k in rows:
        w.writerow([
            k.id,
            k.tanggal_dibuat.strftime("%Y-%m-%d %H:%M") if k.tanggal_dibuat else "",
            k.mahasiswa.username if k.mahasiswa else "-",
            k.judul or "",
            k.kategori or "",
            k.status or "",
            k.tanggal_direspon.strftime("%Y-%m-%d %H:%M") if k.tanggal_direspon else "",
            k.konselor.username if k.konselor else "-"
        ])
    return sio.getvalue().encode('utf-8-sig')

def _pdf_bytes(rows, konselor_name, period_text):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except Exception:
        raise RuntimeError("PDF module tidak tersedia. Install: pip install reportlab")

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Laporan Konselor")
    styles = getSampleStyleSheet()
    elems = []
    elems.append(Paragraph("Laporan Keluhan Konselor", styles["Title"]))
    elems.append(Paragraph(f"Konselor: {konselor_name}", styles["Normal"]))
    elems.append(Paragraph(period_text, styles["Normal"]))
    elems.append(Spacer(1, 8))

    data = [["Judul","Mahasiswa","Kategori","Status","Masuk","Direspons"]]
    for k in rows:
        data.append([
            (k.judul or ""),
            (k.mahasiswa.username if k.mahasiswa else "-"),
            (k.kategori or ""),
            (k.status or ""),
            k.tanggal_dibuat.strftime("%d/%m/%Y %H:%M") if k.tanggal_dibuat else "-",
            k.tanggal_direspon.strftime("%d/%m/%Y %H:%M") if k.tanggal_direspon else "-"
        ])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
        ('TEXTCOLOR',(0,0),(-1,0), colors.black),
        ('GRID',(0,0),(-1,-1), 0.25, colors.grey),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),9),
        ('FONTSIZE',(0,1),(-1,-1),8),
        ('ALIGN',(3,1),(3,-1),'CENTER'),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    elems.append(table)
    doc.build(elems)
    pdf = buf.getvalue()
    buf.close()
    return pdf

def _send_email_with_csv(subject: str, html: str, recipients, attachment_name: str, attachment_bytes: bytes):
    if not (MAIL_SERVER and MAIL_USERNAME and MAIL_PASSWORD):
        raise RuntimeError("Konfigurasi email belum lengkap.")
    if isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
    if not recipients:
        raise RuntimeError("Alamat email tujuan kosong.")
    msg = EmailMessage()
    msg["From"] = MAIL_DEFAULT_SENDER
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content("Laporan terlampir. Versi HTML tersedia.")
    msg.add_alternative(html, subtype="html")
    msg.add_attachment(attachment_bytes, maintype="text", subtype="csv", filename=attachment_name)
    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as smtp:
        if MAIL_USE_TLS:
            smtp.starttls()
        smtp.login(MAIL_USERNAME, MAIL_PASSWORD)
        smtp.send_message(msg)

# ================= Routes - Laporan Konselor =================
@app.route("/laporan_konselor", methods=["GET"])
def laporan_konselor():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    today = datetime.utcnow().date()
    default_from = today - timedelta(days=30)
    d_from = _parse_date(request.args.get("from",""), datetime.combine(default_from, datetime.min.time()))
    d_to   = _parse_date(request.args.get("to",""),   datetime.combine(today, datetime.min.time()))
    status = request.args.get("status","Semua")
    qtext  = request.args.get("q","")
    rows = _query_laporan(session["user_id"], d_from, d_to, status, qtext)
    df_str = d_from.date().isoformat()
    dt_str = d_to.date().isoformat()
    return render_template("laporan_konselor.html",
                           rows=rows,
                           items=rows,               # kompatibel dengan versi template lama
                           date_from=df_str,
                           date_to=dt_str,
                           start_date=df_str,        # kompat lama
                           end_date=dt_str,          # kompat lama
                           status_filter=status,
                           qtext=qtext)

@app.route("/laporan_konselor_export", methods=["GET"])
def laporan_konselor_export():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    today = datetime.utcnow().date()
    default_from = datetime.combine(today - timedelta(days=30), datetime.min.time())
    default_to   = datetime.combine(today, datetime.min.time())
    d_from = _parse_date(request.args.get("from") or request.args.get("start_date",""), default_from)
    d_to   = _parse_date(request.args.get("to")   or request.args.get("end_date",""),   default_to)
    status = request.args.get("status","Semua")
    qtext  = request.args.get("q","")
    rows = _query_laporan(session["user_id"], d_from, d_to, status, qtext)
    data = _csv_bytes(rows)
    filename = f"laporan_konselor_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.route("/laporan_konselor_pdf", methods=["GET"])
def laporan_konselor_pdf():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    konselor = User.query.get(session["user_id"])
    today = datetime.utcnow().date()
    default_from = datetime.combine(today - timedelta(days=30), datetime.min.time())
    default_to   = datetime.combine(today, datetime.min.time())
    d_from = _parse_date(request.args.get("from") or request.args.get("start_date",""), default_from)
    d_to   = _parse_date(request.args.get("to")   or request.args.get("end_date",""),   default_to)
    status = request.args.get("status","Semua")
    qtext  = request.args.get("q","")
    rows = _query_laporan(session["user_id"], d_from, d_to, status, qtext)
    period_text = f"Periode: {d_from.date().isoformat()} s/d {d_to.date().isoformat()}"
    try:
        pdf = _pdf_bytes(rows, konselor.username if konselor else "-", period_text)
    except Exception as e:
        flash(f"Gagal membuat PDF: {e}", "danger")
        return redirect(url_for("laporan_konselor", **{
            "from": d_from.date().isoformat(),
            "to": d_to.date().isoformat(),
            "status": status,
            "q": qtext
        }))
    filename = f"laporan_konselor_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.route("/laporan_konselor_print", methods=["GET"])
def laporan_konselor_print():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    today = datetime.utcnow().date()
    default_from = datetime.combine(today - timedelta(days=30), datetime.min.time())
    default_to   = datetime.combine(today, datetime.min.time())
    d_from = _parse_date(request.args.get("from") or request.args.get("start_date",""), default_from)
    d_to   = _parse_date(request.args.get("to")   or request.args.get("end_date",""),   default_to)
    status = request.args.get("status","Semua")
    qtext  = request.args.get("q","")
    rows = _query_laporan(session["user_id"], d_from, d_to, status, qtext)
    df_str = d_from.date().isoformat()
    dt_str = d_to.date().isoformat()
    return render_template("laporan_konselor_print.html",
                           items=rows,
                           rows=rows,
                           start_date=df_str,
                           end_date=dt_str,
                           date_from=df_str,
                           date_to=dt_str,
                           status_filter=status,
                           qtext=qtext,
                           datetime=datetime)

@app.route("/laporan_konselor_email", methods=["POST"])
def laporan_konselor_email():
    if "user_id" not in session or session.get("role") != "konselor":
        return redirect(url_for("login"))
    konselor = User.query.get(session["user_id"])
    to_addr = request.form.get("to","").strip()
    subj = request.form.get("subject","Laporan Konselor SIGMA").strip()
    body_note = request.form.get("body","").strip()
    d_from = _parse_date(request.form.get("from",""), None)
    d_to   = _parse_date(request.form.get("to",""), None)
    status = request.form.get("status","Semua")
    qtext  = request.form.get("q","")
    rows = _query_laporan(session["user_id"], d_from, d_to, status, qtext)

    total = len(rows)
    total_m = len([k for k in rows if k.status == "Menunggu"])
    total_p = len([k for k in rows if k.status == "Diproses"])
    total_s = len([k for k in rows if k.status == "Selesai"])

    rows_html = []
    for k in rows:
        rows_html.append(
            f"<tr>"
            f"<td>{(k.judul or '').replace('<','&lt;').replace('>','&gt;')}</td>"
            f"<td>{(k.mahasiswa.username if k.mahasiswa else '-')}</td>"
            f"<td>{(k.kategori or '')}</td>"
            f"<td>{(k.status or '')}</td>"
            f"<td>{k.tanggal_dibuat.strftime('%d/%m/%Y %H:%M') if k.tanggal_dibuat else '-'}</td>"
            f"<td>{k.tanggal_direspon.strftime('%d/%m/%Y %H:%M') if k.tanggal_direspon else '-'}</td>"
            f"</tr>"
        )
    html_table = (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;font-size:13px'>"
        "<thead style='background:#f1f5f9'>"
        "<tr><th>Judul</th><th>Mahasiswa</th><th>Kategori</th><th>Status</th><th>Masuk</th><th>Direspons</th></tr>"
        "</thead><tbody>" + "".join(rows_html) + "</tbody></table>"
    )
    html = (
        f"<h3>Laporan Keluhan Konselor</h3>"
        f"<p><b>Konselor:</b> {konselor.username if konselor else '-'}<br>"
        f"<b>Periode:</b> {request.form.get('from','-')} s/d {request.form.get('to','-')}<br>"
        f"<b>Ringkasan:</b> Total {total} | Menunggu {total_m} | Diproses {total_p} | Selesai {total_s}</p>"
        + (f"<p>{body_note.replace('<','&lt;').replace('>','&gt;')}</p>" if body_note else "")
        + html_table +
        "<p style='color:#64748b;font-size:12px'>Email ini otomatis dikirim dari SIGMA.</p>"
    )
    try:
        csv_bytes = _csv_bytes(rows)
        _send_email_with_csv(
            subject=subj,
            html=html,
            recipients=to_addr,
            attachment_name=f"laporan_konselor_{datetime.utcnow().strftime('%Y%m%d')}.csv",
            attachment_bytes=csv_bytes
        )
        flash("Laporan berhasil dikirim ke email tujuan.", "success")
    except Exception as e:
        flash(f"Gagal mengirim email: {e}", "danger")

    return redirect(url_for("laporan_konselor", **{
        "from": request.form.get("from",""),
        "to": request.form.get("to",""),
        "status": status,
        "q": request.form.get("q","")
    }))

# ================= Routes - Admin =================
@app.route("/dashboard_admin")
def dashboard_admin():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    total_users = User.query.count()
    total_mahasiswa = User.query.filter_by(role="mahasiswa").count()
    total_konselor = User.query.filter_by(role="konselor").count()
    total_keluhan = Keluhan.query.count()
    return render_template("dashboard_admin.html",
        admin_username=g.current_user.username if g.current_user else "-",
        total_users=total_users,
        total_mahasiswa=total_mahasiswa,
        total_konselor=total_konselor,
        total_keluhan=total_keluhan
    )

@app.route("/kelola_user")
def kelola_user():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    users = User.query.all()
    return render_template("kelola_user.html", users=users)

@app.route("/laporan_sistem")
def laporan_sistem():
    # Route lama dipertahankan demi kompatibilitas,
    # tapi templatenya sudah diganti menjadi 'rekap_keluhan.html'
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    keluhan = Keluhan.query.all()
    return render_template("rekap_keluhan.html", keluhan=keluhan)

# ================= Run =================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Seed admin pertama (jika belum ada)
        if not User.query.filter_by(role="admin").first():
            default_admin_user = os.environ.get("DEFAULT_ADMIN_USER", "ADM-0001").upper()
            default_admin_pass = os.environ.get("DEFAULT_ADMIN_PASS", "GantiPasswordIni-123!")
            if not User.query.filter_by(username=default_admin_user).first():
                u = User(username=default_admin_user, role="admin")
                u.set_password(default_admin_pass)
                db.session.add(u); db.session.commit()
                print(f"[seed] Admin dibuat: {default_admin_user} / {default_admin_pass}")

    # Untuk dev lokal tanpa HTTPS cookie, boleh un-comment baris berikut:
    # app.config['SESSION_COOKIE_SECURE'] = False

    app.run(debug=True)
