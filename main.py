from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os, sqlite3, time, base64, hmac, hashlib

app = FastAPI(title="storeapp api", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/storeapp/v1"

DB_PATH = os.getenv("DB_PATH", "/data/storeapp.db")  # ✅ Railway Volume를 /data로 마운트 추천
SECRET = os.getenv("TOKEN_SECRET", "change-me-please")
SUPER_ID = os.getenv("SUPERADMIN_ID", "dldydtjq159")
SUPER_PW = os.getenv("SUPERADMIN_PW", "tkfkd4026")

LATEST_VERSION = os.getenv("LATEST_VERSION", "1.0.0")
VERSION_NOTES = os.getenv("VERSION_NOTES", "")
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "")

def _db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _hash_pw(pw: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 120_000)
    return dk.hex()

def _ensure_tables():
    conn = _db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,
        salt TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def _ensure_superadmin():
    conn = _db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id=?", (SUPER_ID,))
    row = cur.fetchone()
    if row is None:
        salt = os.urandom(16)
        pw_hash = _hash_pw(SUPER_PW, salt)
        cur.execute("INSERT INTO users(id,salt,pw_hash,role) VALUES(?,?,?,?)",
                    (SUPER_ID, salt.hex(), pw_hash, "superadmin"))
        conn.commit()
    conn.close()

@app.on_event("startup")
def startup():
    _ensure_tables()
    _ensure_superadmin()

def _sign(payload: str) -> str:
    sig = hmac.new(SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

def make_token(user_id: str, role: str, exp_ts: int) -> str:
    payload = f"{user_id}|{role}|{exp_ts}"
    sig = _sign(payload)
    token = base64.urlsafe_b64encode(f"{payload}|{sig}".encode("utf-8")).decode("utf-8").rstrip("=")
    return token

def verify_token(token: str):
    try:
        raw = base64.urlsafe_b64decode(token + "===").decode("utf-8")
        user_id, role, exp_ts, sig = raw.split("|", 3)
        payload = f"{user_id}|{role}|{exp_ts}"
        if _sign(payload) != sig:
            return None
        if int(exp_ts) < int(time.time()):
            return None
        return {"id": user_id, "role": role}
    except:
        return None

def get_bearer(request: Request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""

class LoginIn(BaseModel):
    id: str
    pw: str

class AdminCreateIn(BaseModel):
    id: str
    pw: str

@app.get(f"{API_PREFIX}/version")
def version():
    return {"version": LATEST_VERSION, "notes": VERSION_NOTES, "download_url": DOWNLOAD_URL}

@app.post(f"{API_PREFIX}/auth/login")
def login(body: LoginIn):
    uid = body.id.strip()
    pw = body.pw
    if not uid or not pw:
        raise HTTPException(status_code=400, detail="missing")

    conn = _db()
    cur = conn.cursor()
    cur.execute("SELECT id,salt,pw_hash,role FROM users WHERE id=?", (uid,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="invalid")

    salt = bytes.fromhex(row["salt"])
    pw_hash = _hash_pw(pw, salt)
    if pw_hash != row["pw_hash"]:
        raise HTTPException(status_code=401, detail="invalid")

    role = row["role"]
    exp = int(time.time()) + 30*60
    token = make_token(uid, role, exp)
    return {"ok": True, "role": role, "token": token, "exp": exp}

@app.post(f"{API_PREFIX}/admins")
def create_admin(body: AdminCreateIn, request: Request):
    token = get_bearer(request)
    v = verify_token(token)
    if not v or v.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="forbidden")

    uid = body.id.strip()
    pw = body.pw
    if not uid or not pw:
        raise HTTPException(status_code=400, detail="missing")
    if uid == SUPER_ID:
        raise HTTPException(status_code=400, detail="reserved")

    conn = _db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id=?", (uid,))
    if cur.fetchone() is not None:
        conn.close()
        raise HTTPException(status_code=409, detail="exists")

    salt = os.urandom(16)
    pw_hash = _hash_pw(pw, salt)
    cur.execute("INSERT INTO users(id,salt,pw_hash,role) VALUES(?,?,?,?)",
                (uid, salt.hex(), pw_hash, "admin"))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/")
def root():
    return {"ok": True, "service": "storeapp api"}
