import os
import json
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

# ============================================================
# ENV
# ============================================================
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "change-me")
SUPERADMIN_ID = os.environ.get("SUPERADMIN_ID", "dldydtjq159")
SUPERADMIN_PW = os.environ.get("SUPERADMIN_PW", "tkfkd4026")

JWT_ALG = "HS256"
JWT_TTL_SEC = 60 * 60 * 12  # 12h
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ============================================================
# Storage (simple JSON file; Railway filesystem is ephemeral)
# ============================================================
DATA_FILE = os.environ.get("DATA_FILE", "data.json")
ADMINS_FILE = os.environ.get("ADMINS_FILE", "admins.json")

def _read_json(path: str, default: Any):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except:
        pass
    return default

def _write_json(path: str, obj: Any):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _ensure_files():
    if not os.path.exists(DATA_FILE):
        _write_json(DATA_FILE, {"stores": ["김경영 요리 연구소", "청년회관"], "byStore": {}, "lastSync": ""})
    if not os.path.exists(ADMINS_FILE):
        _write_json(ADMINS_FILE, {
            "superadmin": {"id": SUPERADMIN_ID, "pw_hash": pwd_ctx.hash(SUPERADMIN_PW)},
            "admins": []
        })

_ensure_files()

# ============================================================
# Auth
# ============================================================
def _make_token(user_id: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": user_id, "role": role, "iat": now, "exp": now + JWT_TTL_SEC}
    return jwt.encode(payload, TOKEN_SECRET, algorithm=JWT_ALG)

def _decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, TOKEN_SECRET, algorithms=[JWT_ALG])

def get_bearer_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None

def require_role(required: str):
    def _dep(token: Optional[str] = Depends(get_bearer_token)) -> Dict[str, Any]:
        if not token:
            raise HTTPException(status_code=401, detail="Missing bearer token")
        try:
            payload = _decode_token(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")
        role = payload.get("role")
        if required == "admin":
            if role not in ("admin", "superadmin"):
                raise HTTPException(status_code=403, detail="Admin only")
        elif required == "superadmin":
            if role != "superadmin":
                raise HTTPException(status_code=403, detail="Superadmin only")
        return payload
    return _dep

# ============================================================
# Data normalization
# ============================================================
def default_store_data():
    return {
        "inventory": {"닭": [], "떡": [], "소스": [], "포장재": []},
        "recipes": {"치킨": {}, "떡볶이": {}, "파스타": {}, "사이드": {}, "가게부": {}},
        "memo": "",
        "ledger": []
    }

def normalize_store(st: Any) -> Dict[str, Any]:
    base = default_store_data()
    if isinstance(st, dict):
        base.update(st)
    if not isinstance(base.get("inventory"), dict):
        base["inventory"] = default_store_data()["inventory"]
    if not isinstance(base.get("recipes"), dict):
        base["recipes"] = default_store_data()["recipes"]
    if not isinstance(base.get("memo"), str):
        base["memo"] = ""
    if not isinstance(base.get("ledger"), list):
        base["ledger"] = []
    return base

def normalize_all(data: Any) -> Dict[str, Any]:
    d = {"stores": ["김경영 요리 연구소", "청년회관"], "byStore": {}, "lastSync": ""}
    if isinstance(data, dict):
        if isinstance(data.get("stores"), list) and data["stores"]:
            d["stores"] = data["stores"]
        if isinstance(data.get("byStore"), dict):
            d["byStore"] = {k: normalize_store(v) for k, v in data["byStore"].items()}
        if isinstance(data.get("lastSync"), str):
            d["lastSync"] = data["lastSync"]
    for s in d["stores"]:
        d["byStore"].setdefault(s, default_store_data())
        d["byStore"][s] = normalize_store(d["byStore"][s])
    return d

# ============================================================
# FastAPI app
# ============================================================
app = FastAPI(title="stock-server + storeapp", version="6.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "running", "service": "stock-server"}

@app.get("/ok")
def ok():
    return {"ok": True}

@app.get("/version")
def version():
    return {"service": "stock-server", "version": "6.1"}

# ============================================================
# storeapp/v1 router
# ============================================================
router = APIRouter(prefix="/storeapp/v1", tags=["storeapp"])

@router.get("/version")
def storeapp_version():
    return {"service": "storeapp", "version": "1.0"}

class LoginReq(BaseModel):
    id: str
    pw: str

@router.post("/auth/login")
def login(req: LoginReq):
    admins_obj = _read_json(ADMINS_FILE, {"superadmin": {"id": SUPERADMIN_ID, "pw_hash": pwd_ctx.hash(SUPERADMIN_PW)}, "admins": []})
    sup = admins_obj.get("superadmin", {})
    if req.id == sup.get("id") and pwd_ctx.verify(req.pw, sup.get("pw_hash", "")):
        return {"token": _make_token(req.id, "superadmin"), "role": "superadmin"}
    for a in admins_obj.get("admins", []):
        if req.id == a.get("id") and pwd_ctx.verify(req.pw, a.get("pw_hash", "")):
            return {"token": _make_token(req.id, "admin"), "role": "admin"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.get("/auth/me")
def me(payload=Depends(require_role("admin"))):
    return {"id": payload.get("sub"), "role": payload.get("role")}

class AdminCreateReq(BaseModel):
    id: str
    pw: str

@router.post("/auth/admins")
def create_admin(req: AdminCreateReq, _=Depends(require_role("superadmin"))):
    uid = req.id.strip()
    pw = req.pw.strip()
    if not uid or not pw:
        raise HTTPException(status_code=400, detail="id/pw required")
    admins_obj = _read_json(ADMINS_FILE, {"superadmin": {"id": SUPERADMIN_ID, "pw_hash": pwd_ctx.hash(SUPERADMIN_PW)}, "admins": []})
    if uid == admins_obj.get("superadmin", {}).get("id"):
        raise HTTPException(status_code=409, detail="Cannot overwrite superadmin")
    for a in admins_obj.get("admins", []):
        if a.get("id") == uid:
            raise HTTPException(status_code=409, detail="Admin already exists")
    admins_obj["admins"].append({"id": uid, "pw_hash": pwd_ctx.hash(pw), "created_at": int(time.time())})
    _write_json(ADMINS_FILE, admins_obj)
    return {"ok": True}

@router.get("/auth/admins")
def list_admins(_=Depends(require_role("superadmin"))):
    admins_obj = _read_json(ADMINS_FILE, {"superadmin": {"id": SUPERADMIN_ID, "pw_hash": ""}, "admins": []})
    return {"admins": [{"id": a.get("id"), "created_at": a.get("created_at")} for a in admins_obj.get("admins", [])]}

# ---- Data endpoints (compatible with PC app) ----
@router.get("/data")
def get_all():
    return normalize_all(_read_json(DATA_FILE, {}))

class SaveAllReq(BaseModel):
    data: Dict[str, Any]

@router.post("/save")
def save_all(req: SaveAllReq, _=Depends(require_role("admin"))):
    data = normalize_all(req.data)
    data["lastSync"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_json(DATA_FILE, data)
    return {"ok": True}

@router.get("/store/{store_name}")
def get_store(store_name: str):
    data = normalize_all(_read_json(DATA_FILE, {}))
    st = data.get("byStore", {}).get(store_name)
    if not isinstance(st, dict):
        st = default_store_data()
    return {"store": store_name, "store_data": normalize_store(st)}

class SaveStoreReq(BaseModel):
    store_data: Dict[str, Any]

@router.post("/store/{store_name}")
def save_store(store_name: str, req: SaveStoreReq, _=Depends(require_role("admin"))):
    data = normalize_all(_read_json(DATA_FILE, {}))
    data.setdefault("byStore", {})
    data.setdefault("stores", [])
    if store_name not in data["stores"]:
        data["stores"].append(store_name)
    data["byStore"][store_name] = normalize_store(req.store_data)
    data["lastSync"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_json(DATA_FILE, data)
    return {"ok": True}

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run("server:app", host="0.0.0.0", port=port)
