import os
import base64
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# ─── App Bootstrap ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="E2EE Cyber Core API",
    version="2.1.0",
    description="Hybrid RSA-OAEP + AES-256-GCM end-to-end encryption backend",
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

# ─── Server Crypto Infrastructure ──────────────────────────────────────────────
SERVER_START_TIME = time.time()

print("[INIT] Generating RSA-2048 key pair on server boot...")
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_pem: str = _private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

KEY_FINGERPRINT = base64.b64encode(
    _private_key.public_key()
    .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    [-32:]
).decode()

print(f"[INIT] Key fingerprint (last 32B SHA): {KEY_FINGERPRINT}")

# ─── In-Memory Stores ──────────────────────────────────────────────────────────
# Encrypted vault — never stores plaintext
secure_vault: list[dict] = []

# Audit log — stores metadata only, no ciphertext bodies
audit_log: list[dict] = []

MAX_VAULT_SIZE = 500  # Cap memory usage on free Render tier


# ─── Models ────────────────────────────────────────────────────────────────────
class HybridPayload(BaseModel):
    encrypted_session_key: str = Field(..., description="RSA-OAEP encrypted AES-256 key, base64")
    iv: str = Field(..., description="AES-GCM 96-bit IV, base64")
    ciphertext: str = Field(..., description="AES-256-GCM ciphertext + auth tag, base64")
    client_id: Optional[str] = Field(None, description="Optional opaque client identifier")


class AuditEntry(BaseModel):
    id: str
    timestamp: str
    client_id: Optional[str]
    source_ip: str
    status: str
    payload_size_bytes: int


# ─── Helpers ───────────────────────────────────────────────────────────────────
def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append_audit(entry: dict):
    audit_log.append(entry)
    # Keep last 200 entries to avoid unbounded memory growth
    if len(audit_log) > 200:
        audit_log.pop(0)


# ─── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["ops"])
def health_check():
    """Render health-check endpoint. Returns 200 when the service is live."""
    return {
        "status": "online",
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "vault_records": len(secure_vault),
        "audit_entries": len(audit_log),
    }


@app.get("/api/public-key", tags=["crypto"])
@limiter.limit("30/minute")
def get_public_key(request: Request):
    """
    Returns the server RSA-2048 public key for client-side hybrid encryption.
    Also returns a fingerprint so the client can pin the key for the session.
    """
    return {
        "public_key": _public_pem,
        "algorithm": "RSA-2048 / OAEP-SHA256",
        "key_fingerprint": KEY_FINGERPRINT,
        "server_time": _utc_now(),
    }


@app.post("/api/send-message", tags=["crypto"])
@limiter.limit("20/minute")
def ingest_payload(payload: HybridPayload, request: Request):
    """
    Accepts a hybrid-encrypted payload.
    1. Decrypts the AES session key with the server RSA private key (OAEP-SHA256).
    2. Decrypts + authenticates the message body with AES-256-GCM.
    3. Stores the *encrypted* payload in the vault (zero-knowledge at rest).
    4. Appends a metadata-only entry to the audit log.
    Returns a preview of the decrypted plaintext so the client can verify.
    """
    request_id = str(uuid.uuid4())
    source_ip = request.client.host if request.client else "unknown"
    received_at = _utc_now()

    try:
        # ── 0. Validate rough payload sizes before decoding ────────────────────
        payload_json = payload.model_dump()
        raw_size = sum(len(v) for v in payload_json.values() if isinstance(v, str))

        if raw_size > 65_536:  # 64 KB encoded limit
            raise HTTPException(status_code=413, detail="Payload exceeds maximum size.")

        # ── 1. Asymmetric layer: unwrap AES session key ────────────────────────
        enc_key_bytes = base64.b64decode(payload.encrypted_session_key)
        session_key = _private_key.decrypt(
            enc_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        if len(session_key) != 32:
            raise ValueError("Session key must be 256-bit.")

        # ── 2. Symmetric layer: AES-256-GCM decrypt + authenticate ────────────
        iv_bytes = base64.b64decode(payload.iv)
        ct_bytes = base64.b64decode(payload.ciphertext)

        if len(iv_bytes) != 12:
            raise ValueError("IV must be 96-bit.")

        aesgcm = AESGCM(session_key)
        plaintext_bytes = aesgcm.decrypt(iv_bytes, ct_bytes, None)
        plaintext = plaintext_bytes.decode("utf-8")

        # ── 3. Zero-knowledge vault write (encrypted payload only) ────────────
        vault_entry = {
            "id": request_id,
            "timestamp": received_at,
            "client_id": payload.client_id,
            "encrypted_session_key": payload.encrypted_session_key,
            "iv": payload.iv,
            "ciphertext": payload.ciphertext,
        }
        if len(secure_vault) < MAX_VAULT_SIZE:
            secure_vault.append(vault_entry)

        # ── 4. Audit log (metadata only, no payload body) ─────────────────────
        audit_entry = {
            "id": request_id,
            "timestamp": received_at,
            "client_id": payload.client_id,
            "source_ip": source_ip,
            "status": "VERIFIED",
            "payload_size_bytes": raw_size,
        }
        _append_audit(audit_entry)

        print(
            f"[{received_at}] [{request_id[:8]}] INGESTION OK | "
            f"IP={source_ip} | size={raw_size}B | plaintext={plaintext!r}"
        )

        return JSONResponse(
            content={
                "status": "AUTHENTICATED & VERIFIED",
                "request_id": request_id,
                "vault_records_stored": len(secure_vault),
                "decrypted_preview": plaintext,
                "received_at": received_at,
            },
            headers={"X-Request-ID": request_id},
        )

    except HTTPException:
        raise
    except Exception as exc:
        # Intentionally generic — prevents oracle/timing-attack leakage
        _append_audit(
            {
                "id": request_id,
                "timestamp": received_at,
                "client_id": payload.client_id,
                "source_ip": source_ip,
                "status": "FAILED",
                "payload_size_bytes": 0,
            }
        )
        print(f"[{received_at}] [{request_id[:8]}] INGESTION FAILED | {type(exc).__name__}")
        raise HTTPException(status_code=400, detail="Cryptographic verification failed.")


@app.get("/api/audit-log", tags=["ops"])
@limiter.limit("10/minute")
def get_audit_log(request: Request, limit: int = 20):
    """
    Returns the last N audit entries (metadata only — no ciphertext, no plaintext).
    Useful for monitoring transmission history in the UI.
    """
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be 1–100.")
    return {
        "entries": list(reversed(audit_log[-limit:])),
        "total": len(audit_log),
    }


@app.get("/api/server-info", tags=["ops"])
def server_info():
    """Returns non-sensitive server metadata for the UI dashboard."""
    return {
        "version": "2.1.0",
        "key_algorithm": "RSA-2048-OAEP-SHA256 + AES-256-GCM",
        "key_fingerprint": KEY_FINGERPRINT,
        "vault_capacity": MAX_VAULT_SIZE,
        "vault_used": len(secure_vault),
        "uptime_seconds": round(time.time() - SERVER_START_TIME),
        "environment": os.getenv("ENVIRONMENT", "development"),
    }
