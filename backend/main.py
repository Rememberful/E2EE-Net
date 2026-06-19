import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ─── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# ─── App Bootstrap ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="Zero-Knowledge Note Vault API",
    version="3.0.0",
    description=(
        "Blind ciphertext storage. The server never receives, generates, or stores "
        "a decryption key — all encryption and decryption happens client-side. "
        "The server cannot read note contents under any circumstance."
    ),
    docs_url="/docs",
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── CORS ──────────────────────────────────────────────────────────────────────
RAW_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
ALLOWED_ORIGINS = [o.strip() for o in RAW_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

# ─── In-Memory Stores ──────────────────────────────────────────────────────────
SERVER_START_TIME = time.time()

# Blind vault — server only ever sees ciphertext + IV. Never a key, never plaintext.
# Each record: { id, ciphertext, iv, mode, expires_at, created_at, viewed }
vault: dict[str, dict] = {}

# Audit log — metadata only (no ciphertext, no keys, no plaintext)
audit_log: list[dict] = []

MAX_VAULT_SIZE = 1000
DEFAULT_TTL_SECONDS = 24 * 60 * 60   # 24h default expiry
MAX_TTL_SECONDS = 7 * 24 * 60 * 60   # 7 days max
MAX_CIPHERTEXT_B64_LEN = 200_000     # ~150KB plaintext ceiling, generous for notes


# ─── Models ────────────────────────────────────────────────────────────────────
class CreateNoteRequest(BaseModel):
    ciphertext: str = Field(..., description="AES-GCM ciphertext + tag, base64")
    iv: str = Field(..., description="AES-GCM 96-bit IV, base64")
    mode: str = Field("burn", description="'burn' (delete after first read) or 'expire' (delete after ttl)")
    ttl_seconds: Optional[int] = Field(None, description="Lifetime in seconds, used when mode='expire'")
    client_id: Optional[str] = Field(None, description="Opaque client identifier")


class NoteResponse(BaseModel):
    id: str
    ciphertext: str
    iv: str
    mode: str


# ─── Helpers ───────────────────────────────────────────────────────────────────
def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _append_audit(entry: dict):
    audit_log.append(entry)
    if len(audit_log) > 200:
        audit_log.pop(0)


def _purge_expired():
    now = _utc_now()
    expired_ids = [
        nid for nid, rec in vault.items()
        if rec["mode"] == "expire" and rec["expires_at"] and now > rec["expires_at"]
    ]
    for nid in expired_ids:
        del vault[nid]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ─── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["ops"])
def health_check():
    """Render health-check endpoint."""
    return {
        "status": "online",
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "vault_records": len(vault),
        "audit_entries": len(audit_log),
    }


@app.post("/api/notes", tags=["vault"])
@limiter.limit("20/minute")
def create_note(payload: CreateNoteRequest, request: Request):
    """
    Stores an opaque encrypted note. The server never sees the AES key, the IV
    alone is meaningless, and ciphertext is unreadable without the key — which
    never leaves the sender's browser except inside the share-link URL fragment
    (URL fragments are never transmitted to any server by the browser).
    """
    _purge_expired()

    if payload.mode not in ("burn", "expire"):
        raise HTTPException(status_code=400, detail="mode must be 'burn' or 'expire'.")

    if len(payload.ciphertext) > MAX_CIPHERTEXT_B64_LEN:
        raise HTTPException(status_code=413, detail="Note exceeds maximum size.")

    if len(vault) >= MAX_VAULT_SIZE:
        raise HTTPException(status_code=507, detail="Vault at capacity. Try again later.")

    note_id = uuid.uuid4().hex
    now = _utc_now()

    expires_at = None
    if payload.mode == "expire":
        ttl = payload.ttl_seconds or DEFAULT_TTL_SECONDS
        ttl = max(60, min(ttl, MAX_TTL_SECONDS))  # clamp 1min .. 7days
        expires_at = now + timedelta(seconds=ttl)

    vault[note_id] = {
        "id": note_id,
        "ciphertext": payload.ciphertext,
        "iv": payload.iv,
        "mode": payload.mode,
        "created_at": now,
        "expires_at": expires_at,
        "viewed": False,
    }

    _append_audit({
        "id": note_id,
        "timestamp": _iso(now),
        "client_id": payload.client_id,
        "source_ip": _client_ip(request),
        "action": "CREATE",
        "mode": payload.mode,
        "payload_size_bytes": len(payload.ciphertext) + len(payload.iv),
    })

    print(f"[{_iso(now)}] [{note_id[:8]}] NOTE STORED | mode={payload.mode} | server cannot read contents")

    return {
        "id": note_id,
        "mode": payload.mode,
        "expires_at": _iso(expires_at) if expires_at else None,
        "created_at": _iso(now),
    }


@app.get("/api/notes/{note_id}", response_model=NoteResponse, tags=["vault"])
@limiter.limit("30/minute")
def get_note(note_id: str, request: Request):
    """
    Returns the raw ciphertext + IV for a note. Decryption happens entirely in
    the requester's browser using the key from the URL fragment — a value this
    endpoint never receives and the server never has access to.
    """
    _purge_expired()

    rec = vault.get(note_id)
    now = _utc_now()

    if rec is None:
        _append_audit({
            "id": note_id, "timestamp": _iso(now), "client_id": None,
            "source_ip": _client_ip(request), "action": "READ_MISS",
            "mode": "-", "payload_size_bytes": 0,
        })
        raise HTTPException(status_code=404, detail="Note not found, already viewed, or expired.")

    if rec["mode"] == "expire" and rec["expires_at"] and now > rec["expires_at"]:
        del vault[note_id]
        raise HTTPException(status_code=404, detail="Note not found, already viewed, or expired.")

    response = {
        "id": rec["id"],
        "ciphertext": rec["ciphertext"],
        "iv": rec["iv"],
        "mode": rec["mode"],
    }

    if rec["mode"] == "burn":
        del vault[note_id]  # one-time read — gone immediately after this response
        action = "READ_AND_BURN"
    else:
        rec["viewed"] = True
        action = "READ"

    _append_audit({
        "id": note_id, "timestamp": _iso(now), "client_id": None,
        "source_ip": _client_ip(request), "action": action,
        "mode": rec["mode"], "payload_size_bytes": len(rec["ciphertext"]),
    })

    print(f"[{_iso(now)}] [{note_id[:8]}] NOTE RETRIEVED | action={action} | server cannot read contents")

    return response


@app.get("/api/audit-log", tags=["ops"])
@limiter.limit("10/minute")
def get_audit_log(request: Request, limit: int = 20):
    """Last N audit entries — metadata only, never ciphertext or keys."""
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be 1-100.")
    return {
        "entries": list(reversed(audit_log[-limit:])),
        "total": len(audit_log),
    }


@app.get("/api/server-info", tags=["ops"])
def server_info():
    """Non-sensitive runtime metadata for the UI dashboard."""
    _purge_expired()
    return {
        "version": "3.0.0",
        "architecture": "Zero-Knowledge Blind Vault (AES-256-GCM, client-side keys only)",
        "vault_capacity": MAX_VAULT_SIZE,
        "vault_used": len(vault),
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "default_ttl_seconds": DEFAULT_TTL_SECONDS,
        "max_ttl_seconds": MAX_TTL_SECONDS,
    }