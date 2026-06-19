# CYBER-CORE // E2EE Net

End-to-end encrypted message transmission demo.  
**Hybrid RSA-2048-OAEP + AES-256-GCM** — all encryption happens client-side before any data leaves the browser.

---

## Architecture

```
Browser (React + node-forge)
  └─ Generates ephemeral AES-256 key
  └─ Encrypts message → AES-256-GCM
  └─ Wraps AES key    → RSA-OAEP-SHA256 (server public key)
  └─ POST /api/send-message  ──────────────────► FastAPI (Python)
                                                    └─ Unwraps AES key with RSA private key
                                                    └─ Decrypts + authenticates via AES-GCM
                                                    └─ Stores ONLY ciphertext in vault (zero-knowledge)
                                                    └─ Returns integrity status + audit entry
```

---

## Local Development

### 1. Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API docs available at http://127.0.0.1:8000/docs

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — Vite proxies `/api` to the backend automatically (no CORS issues locally).

---

## Deploy to Render

### Step 1 — Push to GitHub
```bash
git init && git add . && git commit -m "init"
# create a GitHub repo, then:
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

### Step 2 — Create services on Render

#### Backend (Web Service)
| Setting | Value |
|---|---|
| Runtime | Python 3 |
| Root Directory | `backend` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/health` |

Add Environment Variable:
- `ALLOWED_ORIGINS` → `https://<your-frontend>.onrender.com`

#### Frontend (Static Site)
| Setting | Value |
|---|---|
| Root Directory | `frontend` |
| Build Command | `npm install && npm run build` |
| Publish Directory | `dist` |

Add Environment Variable:
- `VITE_API_URL` → `https://<your-backend>.onrender.com`

> **Note:** On Render's free tier, services spin down after inactivity.  
> The first request after a cold start may take ~30s while the backend boots and regenerates its RSA key pair.

### Step 3 — Using render.yaml (optional)
The `render.yaml` at the repo root lets you deploy both services at once via Render's Blueprint feature.  
Update the two URL values in that file to match your actual service names, then import the repo in the Render dashboard.

---

## API Reference

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check (used by Render) |
| GET | `/api/public-key` | Server RSA-2048 public key + fingerprint |
| POST | `/api/send-message` | Ingest hybrid-encrypted payload |
| GET | `/api/audit-log?limit=N` | Metadata-only transmission history |
| GET | `/api/server-info` | Runtime stats, vault usage, uptime |
| GET | `/docs` | Interactive Swagger UI |

Rate limits (per IP): 20 req/min on send-message, 30 on public-key, 10 on audit-log.

---

## Security Notes

- **Ephemeral AES keys** — a fresh 256-bit key is generated per transmission (session-layer forward secrecy).
- **Zero-knowledge vault** — the server never stores plaintext; only the encrypted payload is retained.
- **Generic error responses** — the `/api/send-message` endpoint returns a single 400 for all crypto failures to prevent oracle/timing attacks.
- **CORS restricted** — `ALLOWED_ORIGINS` must be set explicitly in production.
- **Key fingerprint** — the client displays the server public key fingerprint so you can pin it visually.
