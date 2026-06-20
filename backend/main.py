import os
import json
import time
import uuid
import hashlib
import secrets
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
    version="4.2.0",
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
        "lives in volatile application memory. Senders may optionally opt in "
        "to delivery tracking: the server stores only a SHA-256 hash of a "
        "client-generated tracking token, never the raw token, and that hash "
        "has no relationship to the decryption key — it proves the right to "
        "see active/viewed/expired status, nothing about content."
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
_fallback_trackers: dict[str, dict] = {}  # keyed by hashed_tracking_token
_fallback_sessions: dict[str, dict] = {}  # keyed by session_token, grace-period reveal sessions

NOTE_KEY_PREFIX = "note:"
TRACK_KEY_PREFIX = "track:"
SESSION_KEY_PREFIX = "session:"
AUDIT_LIST_KEY = "audit_log"
AUDIT_MAX_ENTRIES = 200

DEFAULT_TTL_SECONDS = 24 * 60 * 60     # 24h default expiry for mode="expire"
MAX_TTL_SECONDS = 7 * 24 * 60 * 60     # 7 days max
BURN_SAFETY_NET_SECONDS = 30 * 24 * 60 * 60  # 30 days — unread burn notes still expire eventually
MAX_CIPHERTEXT_B64_LEN = 200_000       # ~150KB plaintext ceiling, generous for notes

# Tracker records outlive the note itself by a fixed margin, so a sender can
# still see "viewed" or "expired" status for a while after the underlying
# note is gone. Independent of the note's own TTL/burn lifecycle.
TRACK_RECORD_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days

# Grace-period session window: how long a burn-mode note survives in
# "consuming" state after Reveal is clicked, before being hard-deleted even
# without explicit confirmation. Protects against the recipient's connection
# dropping, tab crashing, or refresh right after Reveal — without this, a
# network blip at the worst possible moment loses the secret permanently.
GRACE_PERIOD_SECONDS = 90

MIN_VIEW_DURATION_SECONDS = 5
MAX_VIEW_DURATION_SECONDS = 600
MIN_EXTEND_SECONDS = 60
MAX_TOTAL_TTL_SECONDS = 14 * 24 * 60 * 60  # hard ceiling even after extension


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
    hashed_tracking_token: Optional[str] = Field(
        None,
        description=(
            "SHA-256 hash of a sender-generated tracking token, used to let the "
            "sender later check delivery status (active/viewed/expired) without "
            "any user account. The server only ever sees this hash, never the "
            "raw token — so the server cannot use it to look anything up on its "
            "own; only someone holding the original raw token can query status. "
            "The hash has zero mathematical relationship to the AES decryption "
            "key, which lives separately in the URL fragment and never reaches "
            "the server at all. Optional — notes can be created without tracking. "
            "This same hash also authorizes management actions (destroy, extend, "
            "freeze) on this note, since possessing the raw token is the only "
            "proof of sender identity in this account-free system."
        ),
    )
    tracking_title: Optional[str] = Field(
        None,
        max_length=80,
        description=(
            "Optional sender-chosen label shown only in the sender's own "
            "tracking dashboard, stored in the tracker record — never in the "
            "note record itself, and never derived from or related to the "
            "note's plaintext content. Used only so the sender can tell tracked "
            "notes apart by something other than the note's actual contents."
        ),
    )
    view_duration_seconds: Optional[int] = Field(
        None,
        description=(
            "If set, the recipient's browser auto-clears the decrypted plaintext "
            "from screen this many seconds after a successful reveal. Purely a "
            "client-side display timer enforced by the recipient's own browser, "
            "separate from the server-side grace-period session window."
        ),
    )


class TrackingManageRequest(BaseModel):
    tracking_token: str = Field(..., description="Raw sender tracking token, proves the right to manage this note")


class ExtendRequest(BaseModel):
    tracking_token: str
    additional_seconds: int = Field(..., ge=MIN_EXTEND_SECONDS, le=MAX_TTL_SECONDS)


class NoteResponse(BaseModel):
    id: str
    ciphertext: str
    iv: str
    mode: str
    view_duration_seconds: Optional[int] = None
    session_token: Optional[str] = Field(
        None,
        description=(
            "Present only for burn-mode reveals. Proves this specific browser "
            "session performed the reveal, so it may call confirm-consumed (or "
            "survive a refresh within the grace period) without re-triggering "
            "a second destructive reveal against the same note."
        ),
    )
    grace_period_seconds: Optional[int] = None


class TrackingStatusResponse(BaseModel):
    note_id: str
    title: Optional[str] = None
    status: str  # "active" | "viewed" | "expired" | "frozen" | "consuming" | "destroyed"
    viewed_at: Optional[str] = None
    expires_at: Optional[str] = None
    mode: Optional[str] = None


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


def _track_key(hashed_token: str) -> str:
    return f"{TRACK_KEY_PREFIX}{hashed_token}"


async def _store_tracker(hashed_token: str, note_id: str, title: Optional[str], mode: str, expires_at: Optional[str]):
    """
    Creates the tracking index entry at note-creation time. Keyed by the
    SHA-256 hash of the sender's tracking token — the server stores only the
    hash, never the raw token, so possessing the raw token (which never
    leaves the sender's browser except into their own localStorage) is what
    proves the right to query status AND perform management actions
    (destroy/extend/freeze) on this note.

    title is sender-chosen and stored only here, in the tracker — never in
    the note record itself, and with no relationship to the note's content.
    """
    record = {
        "note_id": note_id, "title": title, "mode": mode,
        "status": "active", "viewed_at": None, "frozen": False,
        "expires_at": expires_at,
    }
    payload = json.dumps(record)

    if redis_client is not None:
        await redis_client.setex(_track_key(hashed_token), TRACK_RECORD_TTL_SECONDS, payload)
    else:
        record_copy = dict(record)
        record_copy["_fallback_expires_at"] = (_utc_now() + timedelta(seconds=TRACK_RECORD_TTL_SECONDS)).isoformat()
        _fallback_trackers[hashed_token] = record_copy


async def _mark_tracker_viewed(note_id: str, viewed_at: datetime):
    """
    Called once a reveal is fully confirmed-consumed (burn mode) or on every
    reveal (expire mode). This ordering matters: if the tracker weren't
    updated before the note's own key disappears, a successfully-viewed burn
    note would later be indistinguishable from a note that silently expired
    unread, since both end with the note key gone from the vault. We don't
    index notes by note_id -> tracker, so this does a bounded scan over
    tracker keys to find the matching one. For this app's expected volume
    that's acceptable; a high-volume deployment would maintain a
    note_id -> hashed_token reverse index instead.
    """
    await _update_tracker_by_note_id(note_id, lambda data: data.get("status") in ("active", "consuming"), {
        "status": "viewed", "viewed_at": _iso(viewed_at),
    })


async def _update_tracker_by_note_id(note_id: str, predicate, updates: dict):
    """Shared scan-and-update helper used by viewed/frozen/destroyed transitions."""
    if redis_client is not None:
        async for key in redis_client.scan_iter(match=f"{TRACK_KEY_PREFIX}*"):
            raw = await redis_client.get(key)
            if raw is None:
                continue
            data = json.loads(raw)
            if data.get("note_id") == note_id and predicate(data):
                data.update(updates)
                ttl = await redis_client.ttl(key)
                await redis_client.setex(key, ttl if ttl and ttl > 0 else TRACK_RECORD_TTL_SECONDS, json.dumps(data))
                return True
        return False
    else:
        for hashed_token, rec in _fallback_trackers.items():
            if rec.get("note_id") == note_id and predicate(rec):
                rec.update(updates)
                return True
        return False


async def _load_tracker(hashed_token: str) -> Optional[dict]:
    if redis_client is not None:
        raw = await redis_client.get(_track_key(hashed_token))
        if raw is None:
            return None
        return json.loads(raw)

    rec = _fallback_trackers.get(hashed_token)
    if rec is None:
        return None
    expires_at = rec.get("_fallback_expires_at")
    if expires_at and _utc_now() > datetime.fromisoformat(expires_at):
        del _fallback_trackers[hashed_token]
        return None
    return rec


async def _update_tracker_fields(hashed_token: str, updates: dict) -> Optional[dict]:
    """Loads, updates, and re-saves a tracker by its own hash (used by destroy/extend/freeze, which the sender calls directly with their raw token)."""
    if redis_client is not None:
        raw = await redis_client.get(_track_key(hashed_token))
        if raw is None:
            return None
        data = json.loads(raw)
        data.update(updates)
        ttl = await redis_client.ttl(_track_key(hashed_token))
        await redis_client.setex(_track_key(hashed_token), ttl if ttl and ttl > 0 else TRACK_RECORD_TTL_SECONDS, json.dumps(data))
        return data
    else:
        rec = _fallback_trackers.get(hashed_token)
        if rec is None:
            return None
        rec.update(updates)
        return rec


def _session_key(session_token: str) -> str:
    return f"{SESSION_KEY_PREFIX}{session_token}"


async def _store_session(session_token: str, note_id: str, rec: dict):
    """
    Grace-period session: created the instant Reveal succeeds for a burn-mode
    note. Holds a COPY of the ciphertext/iv (the note's own key is deleted
    immediately to prevent a second independent reveal attempt from another
    tab/device), so a refresh within the grace window can re-serve the exact
    same ciphertext without re-running destructive logic against the note.
    Expires automatically after GRACE_PERIOD_SECONDS regardless of whether
    confirm-consumed is ever called — this is the fallback hard-delete.
    """
    payload = json.dumps({
        "note_id": note_id, "ciphertext": rec["ciphertext"], "iv": rec["iv"], "mode": rec["mode"],
    })
    if redis_client is not None:
        await redis_client.setex(_session_key(session_token), GRACE_PERIOD_SECONDS, payload)
    else:
        _fallback_sessions[session_token] = {
            "note_id": note_id, "ciphertext": rec["ciphertext"], "iv": rec["iv"], "mode": rec["mode"],
            "_fallback_expires_at": (_utc_now() + timedelta(seconds=GRACE_PERIOD_SECONDS)).isoformat(),
        }


async def _load_session(session_token: str) -> Optional[dict]:
    if redis_client is not None:
        raw = await redis_client.get(_session_key(session_token))
        if raw is None:
            return None
        return json.loads(raw)

    rec = _fallback_sessions.get(session_token)
    if rec is None:
        return None
    expires_at = rec.get("_fallback_expires_at")
    if expires_at and _utc_now() > datetime.fromisoformat(expires_at):
        del _fallback_sessions[session_token]
        return None
    return rec


async def _delete_session(session_token: str):
    if redis_client is not None:
        await redis_client.delete(_session_key(session_token))
    else:
        _fallback_sessions.pop(session_token, None)


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

    view_duration = payload.view_duration_seconds
    if view_duration is not None:
        view_duration = max(MIN_VIEW_DURATION_SECONDS, min(view_duration, MAX_VIEW_DURATION_SECONDS))

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
        "view_duration_seconds": view_duration,
        "frozen": False,
    }

    await _store_note(note_id, record, ttl_seconds)

    if payload.hashed_tracking_token:
        await _store_tracker(
            payload.hashed_tracking_token, note_id, payload.tracking_title,
            payload.mode, _iso(expires_at) if expires_at else None,
        )

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

    A frozen note still reports exists=True here (per the sender's choice
    that freezing should not make the link appear broken) — only the
    destructive reveal step is actually blocked while frozen.
    """
    rec = await _load_note(note_id)

    if rec is None:
        raise HTTPException(status_code=404, detail="Note not found, already viewed, or expired.")

    return {
        "id": rec["id"],
        "mode": rec["mode"],
        "has_passphrase": rec.get("has_passphrase", False),
        "frozen": rec.get("frozen", False),
        "exists": True,
    }


@app.post("/api/notes/{note_id}/reveal", response_model=NoteResponse, tags=["vault"])
@limiter.limit("30/minute")
async def reveal_note(note_id: str, request: Request):
    """
    Destructive read, with a grace-period session window for burn-mode notes.

    Without a grace period, a connection drop or tab crash at the exact
    moment of reveal loses the secret permanently — the note is gone from the
    server but never successfully reached the recipient's screen. To fix
    that, a burn-mode reveal here does NOT instantly delete the note. It:
      1. Deletes the note's own key immediately (so a second, independent
         reveal attempt — e.g. from another tab or device — cannot also
         succeed; only one reveal is ever allowed to start).
      2. Copies the ciphertext into a short-lived session, keyed by a fresh
         session_token, with its own GRACE_PERIOD_SECONDS TTL.
      3. Returns that session_token to the caller.

    The recipient's browser can re-fetch the same session (via
    POST /notes/{id}/session/{session_token}) if it needs to recover from a
    refresh or dropped connection, for as long as the grace period lasts.
    Once the recipient's UI finishes displaying the note (or its own
    view-duration timer elapses), it calls POST .../confirm-consumed to hard-
    delete the session immediately. If that's never called — tab closed,
    crash, abandoned — the session's own TTL guarantees deletion anyway,
    just up to GRACE_PERIOD_SECONDS later instead of instantly.

    Expire-mode notes don't need any of this, since they aren't deleted on
    reveal in the first place — left as an instant, idempotent read.

    POST (not GET) so automated link-preview fetchers — which only ever
    issue GET — cannot trigger it, even by accident. The frontend only calls
    this in direct response to a deliberate user click on "Click to reveal."
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

    if rec.get("frozen", False):
        await _append_audit({
            "id": note_id, "timestamp": _iso(now), "client_id": None,
            "source_ip": _client_ip(request), "action": "REVEAL_BLOCKED_FROZEN",
            "mode": rec["mode"], "payload_size_bytes": 0,
        })
        raise HTTPException(status_code=423, detail="This note has been temporarily frozen by its sender.")

    view_duration = rec.get("view_duration_seconds")

    if rec["mode"] == "burn":
        session_token = secrets.token_urlsafe(24)
        await _store_session(session_token, note_id, rec)
        await _delete_note(note_id)  # only one reveal can ever start; the session now holds the data
        action = "REVEAL_AND_BURN"

        response = {
            "id": rec["id"], "ciphertext": rec["ciphertext"], "iv": rec["iv"], "mode": rec["mode"],
            "view_duration_seconds": view_duration, "session_token": session_token,
            "grace_period_seconds": GRACE_PERIOD_SECONDS,
        }
        # Tracker moves to an intermediate "consuming" status — distinct from
        # both "active" (note untouched) and "viewed" (fully confirmed) — so
        # the sender's dashboard can show "being read right now" accurately,
        # and so get_tracking_status doesn't misread the note's own key being
        # gone (deleted above) as expiry while a grace-period session is
        # still legitimately in flight. Only confirm_consumed promotes this
        # to "viewed"; if confirm never arrives, status stays "consuming"
        # until the session's own TTL lapses, at which point absence of both
        # the note AND any non-active tracker state reads as "expired" — a
        # reasonably honest description of "reveal started but never
        # completed," distinct from "sender's TTL ran out unread."
        await _update_tracker_by_note_id(note_id, lambda d: d.get("status") == "active", {"status": "consuming"})
    else:
        action = "REVEAL"
        await _mark_tracker_viewed(note_id, now)
        response = {
            "id": rec["id"], "ciphertext": rec["ciphertext"], "iv": rec["iv"], "mode": rec["mode"],
            "view_duration_seconds": view_duration, "session_token": None, "grace_period_seconds": None,
        }
        # expire-mode notes are left in place — Redis's own TTL (set at
        # creation via SETEX) will evict them; no manual bookkeeping needed.

    await _append_audit({
        "id": note_id, "timestamp": _iso(now), "client_id": None,
        "source_ip": _client_ip(request), "action": action,
        "mode": rec["mode"], "payload_size_bytes": len(rec["ciphertext"]),
    })

    print(f"[{_iso(now)}] [{note_id[:8]}] NOTE REVEALED | action={action} | backend={'redis' if redis_client else 'memory'}")

    return response


@app.get("/api/notes/{note_id}/session/{session_token}", response_model=NoteResponse, tags=["vault"])
@limiter.limit("30/minute")
async def get_reveal_session(note_id: str, session_token: str, request: Request):
    """
    Re-fetches an in-progress grace-period reveal session. Used when the
    recipient's browser needs to recover after a refresh or a dropped
    connection that happened after Reveal already succeeded — without this,
    that scenario would permanently lose a burn-mode note even though the
    server still has it (briefly) in the session window.
    """
    session = await _load_session(session_token)
    if session is None or session.get("note_id") != note_id:
        raise HTTPException(status_code=404, detail="Reveal session not found or its grace period has elapsed.")

    return {
        "id": note_id, "ciphertext": session["ciphertext"], "iv": session["iv"], "mode": session["mode"],
        "view_duration_seconds": None, "session_token": session_token, "grace_period_seconds": GRACE_PERIOD_SECONDS,
    }


@app.post("/api/notes/{note_id}/confirm-consumed", tags=["vault"])
@limiter.limit("30/minute")
async def confirm_consumed(note_id: str, session_token: str, request: Request):
    """
    Called by the recipient's browser once it has finished displaying a
    burn-mode note (decryption succeeded and either the view-duration timer
    elapsed or the user navigated away deliberately). Hard-deletes the
    session immediately rather than waiting out the rest of the grace period,
    and marks the tracker as "viewed" now that consumption is actually
    confirmed complete.
    """
    session = await _load_session(session_token)
    if session is None or session.get("note_id") != note_id:
        # Already cleaned up (grace period elapsed naturally, or already
        # confirmed once) — not an error, just nothing left to do.
        return {"status": "already_cleared"}

    await _delete_session(session_token)
    await _mark_tracker_viewed(note_id, _utc_now())

    await _append_audit({
        "id": note_id, "timestamp": _iso(_utc_now()), "client_id": None,
        "source_ip": _client_ip(request), "action": "CONSUME_CONFIRMED",
        "mode": "burn", "payload_size_bytes": 0,
    })

    return {"status": "confirmed"}


@app.get("/api/notes/track/{tracking_token}", response_model=TrackingStatusResponse, tags=["vault"])
@limiter.limit("30/minute")
async def get_tracking_status(tracking_token: str, request: Request):
    """
    Sender-side delivery confirmation, without any user account or login.

    The raw tracking_token never touches the server at note-creation time —
    only its SHA-256 hash does. Here, the server hashes whatever token it's
    given and looks up that hash. Possessing the original raw token (which
    lives only in the sender's own browser localStorage) is what proves the
    right to see this note's status; the server has no independent way to
    derive or guess it.

    This hash has no mathematical relationship to the AES-256-GCM decryption
    key, which lives separately in the URL fragment the recipient uses and
    never reaches the server in any form. Even a full database compromise
    exposes only "note X was viewed at time Y" — nothing about content.
    """
    hashed = hashlib.sha256(tracking_token.encode()).hexdigest()
    tracker = await _load_tracker(hashed)

    if tracker is None:
        raise HTTPException(status_code=404, detail="Tracking record not found or expired.")

    note_id = tracker["note_id"]
    title = tracker.get("title")
    mode = tracker.get("mode")

    if tracker.get("frozen"):
        return {"note_id": note_id, "title": title, "status": "frozen", "viewed_at": None, "expires_at": tracker.get("expires_at"), "mode": mode}

    if tracker["status"] == "viewed":
        return {"note_id": note_id, "title": title, "status": "viewed", "viewed_at": tracker.get("viewed_at"), "expires_at": tracker.get("expires_at"), "mode": mode}

    if tracker["status"] == "consuming":
        # Reveal has started (grace-period session in flight) but confirm
        # hasn't landed yet — could be mid-transfer, or could be an
        # abandoned session waiting on its own TTL. Reported distinctly so
        # the sender's dashboard reads "being read right now" rather than
        # the more alarming and less accurate "expired."
        return {"note_id": note_id, "title": title, "status": "consuming", "viewed_at": None, "expires_at": tracker.get("expires_at"), "mode": mode}

    if tracker["status"] == "destroyed_by_sender":
        return {"note_id": note_id, "title": title, "status": "destroyed", "viewed_at": tracker.get("viewed_at"), "expires_at": tracker.get("expires_at"), "mode": mode}

    # Status is still "active" as far as the tracker knows — check whether
    # the underlying note still exists. If it doesn't, and nothing marked it
    # viewed, the only remaining explanation is that its TTL expired unread.
    note_still_exists = (await _load_note(note_id)) is not None

    if note_still_exists:
        return {"note_id": note_id, "title": title, "status": "active", "viewed_at": None, "expires_at": tracker.get("expires_at"), "mode": mode}

    return {"note_id": note_id, "title": title, "status": "expired", "viewed_at": None, "expires_at": tracker.get("expires_at"), "mode": mode}


@app.post("/api/notes/{note_id}/destroy", tags=["vault"])
@limiter.limit("20/minute")
async def destroy_note(note_id: str, payload: TrackingManageRequest, request: Request):
    """
    Sender-initiated manual destruction. Requires the raw tracking token —
    the only credential that exists in this account-free system to prove
    "I created this note." Deletes the underlying note immediately; the
    tracker is preserved and marked destroyed so the dashboard can show
    confirmation rather than just having the entry vanish silently.
    """
    hashed = hashlib.sha256(payload.tracking_token.encode()).hexdigest()
    tracker = await _load_tracker(hashed)

    if tracker is None:
        raise HTTPException(status_code=404, detail="Tracking record not found or expired.")

    note_id_from_tracker = tracker["note_id"]
    if note_id_from_tracker != note_id:
        raise HTTPException(status_code=403, detail="Tracking token does not match this note.")

    await _delete_note(note_id)
    await _update_tracker_fields(hashed, {"status": "destroyed_by_sender", "viewed_at": tracker.get("viewed_at")})

    await _append_audit({
        "id": note_id, "timestamp": _iso(_utc_now()), "client_id": None,
        "source_ip": _client_ip(request), "action": "DESTROYED_BY_SENDER",
        "mode": tracker.get("mode", "-"), "payload_size_bytes": 0,
    })

    return {"status": "destroyed", "note_id": note_id}


@app.post("/api/notes/{note_id}/freeze", tags=["vault"])
@limiter.limit("20/minute")
async def toggle_freeze_note(note_id: str, payload: TrackingManageRequest, request: Request):
    """
    Sender-initiated freeze/unfreeze toggle. While frozen, /reveal is blocked
    with 423 Locked, but /status still reports the note as existing (the
    sender's choice: a frozen link should look temporarily locked, not
    broken). Does not affect the note's underlying TTL/expiry countdown —
    freezing pauses access, not the clock.
    """
    hashed = hashlib.sha256(payload.tracking_token.encode()).hexdigest()
    tracker = await _load_tracker(hashed)

    if tracker is None:
        raise HTTPException(status_code=404, detail="Tracking record not found or expired.")

    if tracker["note_id"] != note_id:
        raise HTTPException(status_code=403, detail="Tracking token does not match this note.")

    rec = await _load_note(note_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Note no longer exists (already viewed, destroyed, or expired).")

    new_frozen_state = not rec.get("frozen", False)
    rec["frozen"] = new_frozen_state

    # Re-store with whatever TTL remains — freezing must not reset or extend
    # the note's own expiry, only gate the reveal action.
    remaining_ttl = None
    if redis_client is not None:
        ttl = await redis_client.ttl(_redis_key(note_id))
        remaining_ttl = ttl if ttl and ttl > 0 else None
    await _store_note(note_id, rec, remaining_ttl)

    await _update_tracker_fields(hashed, {"frozen": new_frozen_state})

    await _append_audit({
        "id": note_id, "timestamp": _iso(_utc_now()), "client_id": None,
        "source_ip": _client_ip(request), "action": "FROZEN" if new_frozen_state else "UNFROZEN",
        "mode": rec.get("mode", "-"), "payload_size_bytes": 0,
    })

    return {"status": "frozen" if new_frozen_state else "active", "note_id": note_id}


@app.post("/api/notes/{note_id}/extend", tags=["vault"])
@limiter.limit("20/minute")
async def extend_note(note_id: str, payload: ExtendRequest, request: Request):
    """
    Sender-initiated TTL extension for expire-mode notes. Burn-mode notes
    have no extendable TTL in the same sense (their lifespan is "until
    revealed," not a clock) so this only applies to mode='expire'. The total
    remaining lifetime is capped at MAX_TOTAL_TTL_SECONDS regardless of how
    many times a sender extends, to keep an eventual hard ceiling on how long
    any ciphertext can persist.
    """
    hashed = hashlib.sha256(payload.tracking_token.encode()).hexdigest()
    tracker = await _load_tracker(hashed)

    if tracker is None:
        raise HTTPException(status_code=404, detail="Tracking record not found or expired.")

    if tracker["note_id"] != note_id:
        raise HTTPException(status_code=403, detail="Tracking token does not match this note.")

    rec = await _load_note(note_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Note no longer exists (already viewed, destroyed, or expired).")

    if rec.get("mode") != "expire":
        raise HTTPException(status_code=400, detail="Only expire-mode notes have a TTL that can be extended.")

    current_ttl = None
    if redis_client is not None:
        ttl = await redis_client.ttl(_redis_key(note_id))
        current_ttl = ttl if ttl and ttl > 0 else 0
    else:
        expires_at_str = rec.get("_fallback_expires_at")
        if expires_at_str:
            remaining = (datetime.fromisoformat(expires_at_str) - _utc_now()).total_seconds()
            current_ttl = max(0, int(remaining))
        else:
            current_ttl = 0

    new_ttl = min(current_ttl + payload.additional_seconds, MAX_TOTAL_TTL_SECONDS)
    new_expires_at = _utc_now() + timedelta(seconds=new_ttl)
    rec["expires_at"] = _iso(new_expires_at)

    await _store_note(note_id, rec, new_ttl)
    await _update_tracker_fields(hashed, {"expires_at": _iso(new_expires_at)})

    await _append_audit({
        "id": note_id, "timestamp": _iso(_utc_now()), "client_id": None,
        "source_ip": _client_ip(request), "action": "EXTENDED",
        "mode": "expire", "payload_size_bytes": 0,
    })

    return {"status": "extended", "note_id": note_id, "new_expires_at": _iso(new_expires_at)}


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
        "version": "4.2.0",
        "architecture": "Zero-Knowledge Blind Vault (AES-256-GCM, client-side keys only)",
        "vault_backend": "redis" if redis_client is not None else "in-memory-fallback",
        "vault_used": await _vault_size(),
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "default_ttl_seconds": DEFAULT_TTL_SECONDS,
        "max_ttl_seconds": MAX_TTL_SECONDS,
    }