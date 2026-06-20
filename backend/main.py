import os
import json
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

try:
    import redis.asyncio as aioredis
except ImportError:  # pragma: no cover - redis is in requirements.txt, but keep import-time safe
    aioredis = None

# ─── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# ─── App Bootstrap ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="Zero-Knowledge Note Vault API",
    version="4.0.0",
    description=(
        "Blind ciphertext storage backed by Redis with native TTL eviction. The "
        "server never receives, generates, or stores a decryption key — all "
        "encryption and decryption happens client-side. The server cannot read "
        "note contents under any circumstance. Reads are split into a "
        "non-destructive 'status' peek (safe for bots/link previews) and a "
        "destructive 'reveal' (POST, fired only on deliberate user click). "
        "Notes may optionally require a sender-chosen passphrase as a second "
        "factor: the server only ever sees a boolean 'has_passphrase' flag, "
        "never the passphrase or the PBKDF2-derived key. Note state survives "
        "container restarts, redeploys, and free-tier spin-down — it no longer "
        "lives in volatile application memory."
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

# ─── Storage backend ───────────────────────────────────────────────────────────
# Redis is the primary store: note state survives container restarts, redeploys,
# and free-tier spin-down because it lives in a separate, persistent process —
# not inside this web service's volatile memory.
#
# If REDIS_URL is unset (e.g. running locally without Redis installed), the app
# falls back to an in-memory dict so local development still works without a
# hard Redis dependency. This fallback inherits the exact same volatility this
# migration exists to fix — it is for local testing convenience only, never use
# it in production. The vault_backend field in /api/server-info reports which
# mode is active.
REDIS_URL = os.getenv("REDIS_URL")
redis_client = None
if REDIS_URL and aioredis is not None:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

SERVER_START_TIME = time.time()

# In-memory fallback structures (local dev only, when REDIS_URL is not set)
_fallback_vault: dict[str, dict] = {}
_fallback_audit: list[dict] = []

NOTE_KEY_PREFIX = "note:"
AUDIT_LIST_KEY = "audit_log"
AUDIT_MAX_ENTRIES = 200

DEFAULT_TTL_SECONDS = 24 * 60 * 60     # 24h default expiry for mode="expire"
MAX_TTL_SECONDS = 7 * 24 * 60 * 60     # 7 days max
BURN_SAFETY_NET_SECONDS = 30 * 24 * 60 * 60  # 30 days — unread burn notes still expire eventually
MAX_CIPHERTEXT_B64_LEN = 200_000       # ~150KB plaintext ceiling, generous for notes


# ─── Models ────────────────────────────────────────────────────────────────────
class CreateNoteRequest(BaseModel):
    ciphertext: str = Field(..., description="AES-GCM ciphertext + tag, base64")
    iv: str = Field(..., description="AES-GCM 96-bit IV, base64")
    mode: str = Field("burn", description="'burn' (delete after first read) or 'expire' (delete after ttl)")
    ttl_seconds: Optional[int] = Field(None, description="Lifetime in seconds, used when mode='expire'")
    has_passphrase: bool = Field(
        False,
        description=(
            "True if the sender added a passphrase second factor. The server never "
            "receives the passphrase itself or the derived key — only this boolean. "
            "The server has no way to verify a passphrase guess; correctness is "
            "proven only by the AES-GCM authentication tag succeeding client-side."
        ),
    )
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


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _redis_key(note_id: str) -> str:
    return f"{NOTE_KEY_PREFIX}{note_id}"


async def _append_audit(entry: dict):
    """
    Metadata-only audit trail — never ciphertext, never keys, never plaintext.
    Backed by a Redis list with LTRIM as the natural equivalent of the old
    capped Python list (append + pop(0)); falls back to an in-memory list
    locally when Redis isn't configured.
    """
    if redis_client is not None:
        await redis_client.lpush(AUDIT_LIST_KEY, json.dumps(entry))
        await redis_client.ltrim(AUDIT_LIST_KEY, 0, AUDIT_MAX_ENTRIES - 1)
    else:
        _fallback_audit.append(entry)
        if len(_fallback_audit) > AUDIT_MAX_ENTRIES:
            _fallback_audit.pop(0)


async def _get_audit_entries(limit: int) -> list[dict]:
    if redis_client is not None:
        raw_entries = await redis_client.lrange(AUDIT_LIST_KEY, 0, limit - 1)
        return [json.loads(e) for e in raw_entries]  # already newest-first via lpush
    return list(reversed(_fallback_audit[-limit:]))


async def _get_audit_total() -> int:
    if redis_client is not None:
        return await redis_client.llen(AUDIT_LIST_KEY)
    return len(_fallback_audit)


async def _store_note(note_id: str, record: dict, ttl_seconds: Optional[int]):
    """
    Persists a note. Redis enforces TTL natively at the engine level via SETEX —
    no manual purge loop or background sweep needed; expired keys are evicted
    automatically (passively on access, actively via Redis's own sampling).
    Burn-mode notes get a generous safety-net TTL so an unread note doesn't
    live forever if the recipient never opens it, while still surviving
    container restarts in the meantime.
    """
    payload = json.dumps(record)
    effective_ttl = ttl_seconds or BURN_SAFETY_NET_SECONDS

    if redis_client is not None:
        await redis_client.setex(_redis_key(note_id), effective_ttl, payload)
    else:
        # In-memory fallback: emulate expiry with a stored timestamp, checked
        # on read. This does NOT survive a process restart — that volatility
        # is exactly what the Redis path exists to eliminate.
        record_copy = dict(record)
        record_copy["_fallback_expires_at"] = (_utc_now() + timedelta(seconds=effective_ttl)).isoformat()
        _fallback_vault[note_id] = record_copy


async def _load_note(note_id: str) -> Optional[dict]:
    if redis_client is not None:
        raw = await redis_client.get(_redis_key(note_id))
        if raw is None:
            return None
        return json.loads(raw)

    rec = _fallback_vault.get(note_id)
    if rec is None:
        return None
    expires_at = rec.get("_fallback_expires_at")
    if expires_at and _utc_now() > datetime.fromisoformat(expires_at):
        del _fallback_vault[note_id]
        return None
    return rec


async def _delete_note(note_id: str):
    if redis_client is not None:
        await redis_client.delete(_redis_key(note_id))
    else:
        _fallback_vault.pop(note_id, None)


async def _vault_size() -> Optional[int]:
    """
    Returns an approximate note count for the dashboard. Redis doesn't expose
    an O(1) "count keys matching prefix" primitive without a maintained index,
    so this uses SCAN (non-blocking, safe for production, but an estimate
    under concurrent writes) for the Redis path, and an exact count locally.
    """
    if redis_client is not None:
        count = 0
        async for _ in redis_client.scan_iter(match=f"{NOTE_KEY_PREFIX}*"):
            count += 1
        return count
    return len(_fallback_vault)


# ─── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["ops"])
async def health_check():
    """Render health-check endpoint."""
    redis_ok = True
    if redis_client is not None:
        try:
            await redis_client.ping()
        except Exception:
            redis_ok = False

    return {
        "status": "online" if redis_ok else "degraded",
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "storage_backend": "redis" if redis_client is not None else "in-memory-fallback",
        "redis_reachable": redis_ok if redis_client is not None else None,
        "audit_entries": await _get_audit_total(),
    }


@app.post("/api/notes", tags=["vault"])
@limiter.limit("20/minute")
async def create_note(payload: CreateNoteRequest, request: Request):
    """
    Stores an opaque encrypted note. The server never sees the AES key, the IV
    alone is meaningless, and ciphertext is unreadable without the key — which
    never leaves the sender's browser except inside the share-link URL fragment
    (URL fragments are never transmitted to any server by the browser).

    Persisted in Redis with native TTL eviction: the note survives this web
    service's container being restarted, redeployed, or spun down for
    inactivity, and Redis itself handles expiry without any backend polling.
    """
    if payload.mode not in ("burn", "expire"):
        raise HTTPException(status_code=400, detail="mode must be 'burn' or 'expire'.")

    if len(payload.ciphertext) > MAX_CIPHERTEXT_B64_LEN:
        raise HTTPException(status_code=413, detail="Note exceeds maximum size.")

    note_id = uuid.uuid4().hex
    now = _utc_now()

    expires_at = None
    ttl_seconds = None
    if payload.mode == "expire":
        ttl_seconds = payload.ttl_seconds or DEFAULT_TTL_SECONDS
        ttl_seconds = max(60, min(ttl_seconds, MAX_TTL_SECONDS))  # clamp 1min .. 7days
        expires_at = now + timedelta(seconds=ttl_seconds)

    record = {
        "id": note_id,
        "ciphertext": payload.ciphertext,
        "iv": payload.iv,
        "mode": payload.mode,
        "has_passphrase": payload.has_passphrase,
        "created_at": _iso(now),
        "expires_at": _iso(expires_at) if expires_at else None,
    }

    await _store_note(note_id, record, ttl_seconds)

    await _append_audit({
        "id": note_id,
        "timestamp": _iso(now),
        "client_id": payload.client_id,
        "source_ip": _client_ip(request),
        "action": "CREATE",
        "mode": payload.mode + ("+passphrase" if payload.has_passphrase else ""),
        "payload_size_bytes": len(payload.ciphertext) + len(payload.iv),
    })

    print(f"[{_iso(now)}] [{note_id[:8]}] NOTE STORED | mode={payload.mode} | passphrase={payload.has_passphrase} | backend={'redis' if redis_client else 'memory'}")

    return {
        "id": note_id,
        "mode": payload.mode,
        "expires_at": _iso(expires_at) if expires_at else None,
        "created_at": _iso(now),
    }


@app.get("/api/notes/{note_id}/status", tags=["vault"])
@limiter.limit("60/minute")
async def peek_note(note_id: str, request: Request):
    """
    Non-destructive existence check. Safe for link-preview bots (WhatsApp,
    Telegram, Slack, iMessage, etc.) to call — it never burns a one-time note
    and never returns ciphertext. Used by the frontend to render the
    "Click to reveal" gate before the user deliberately commits to opening it.
    """
    rec = await _load_note(note_id)

    if rec is None:
        raise HTTPException(status_code=404, detail="Note not found, already viewed, or expired.")

    return {
        "id": rec["id"],
        "mode": rec["mode"],
        "has_passphrase": rec.get("has_passphrase", False),
        "exists": True,
    }


@app.post("/api/notes/{note_id}/reveal", response_model=NoteResponse, tags=["vault"])
@limiter.limit("30/minute")
async def reveal_note(note_id: str, request: Request):
    """
    Destructive read. Returns ciphertext + IV and, for burn-mode notes,
    deletes the record immediately afterward. This is intentionally a POST
    (not GET) so that automated link-preview fetchers — which only ever issue
    GET requests — cannot trigger it, even by accident. The frontend only
    calls this in direct response to a deliberate user click on
    "Click to reveal," never on page load.
    """
    rec = await _load_note(note_id)
    now = _utc_now()

    if rec is None:
        await _append_audit({
            "id": note_id, "timestamp": _iso(now), "client_id": None,
            "source_ip": _client_ip(request), "action": "READ_MISS",
            "mode": "-", "payload_size_bytes": 0,
        })
        raise HTTPException(status_code=404, detail="Note not found, already viewed, or expired.")

    response = {
        "id": rec["id"],
        "ciphertext": rec["ciphertext"],
        "iv": rec["iv"],
        "mode": rec["mode"],
    }

    if rec["mode"] == "burn":
        await _delete_note(note_id)  # one-time reveal — gone immediately after this response
        action = "REVEAL_AND_BURN"
    else:
        action = "REVEAL"
        # expire-mode notes are left in place — Redis's own TTL (set at
        # creation via SETEX) will evict them; no manual bookkeeping needed.

    await _append_audit({
        "id": note_id, "timestamp": _iso(now), "client_id": None,
        "source_ip": _client_ip(request), "action": action,
        "mode": rec["mode"], "payload_size_bytes": len(rec["ciphertext"]),
    })

    print(f"[{_iso(now)}] [{note_id[:8]}] NOTE REVEALED | action={action} | backend={'redis' if redis_client else 'memory'}")

    return response


@app.get("/api/audit-log", tags=["ops"])
@limiter.limit("10/minute")
async def get_audit_log(request: Request, limit: int = 20):
    """Last N audit entries — metadata only, never ciphertext or keys."""
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be 1-100.")
    return {
        "entries": await _get_audit_entries(limit),
        "total": await _get_audit_total(),
    }


@app.get("/api/server-info", tags=["ops"])
async def server_info():
    """Non-sensitive runtime metadata for the UI dashboard."""
    return {
        "version": "4.0.0",
        "architecture": "Zero-Knowledge Blind Vault (AES-256-GCM, client-side keys only)",
        "vault_backend": "redis" if redis_client is not None else "in-memory-fallback",
        "vault_used": await _vault_size(),
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "default_ttl_seconds": DEFAULT_TTL_SECONDS,
        "max_ttl_seconds": MAX_TTL_SECONDS,
    }