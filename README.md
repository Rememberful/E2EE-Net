# Zero-Knowledge Note Vault

A self-destructing, end-to-end encrypted note-sharing service. All encryption and decryption happens in the browser — the server only ever stores and serves opaque ciphertext it cannot read.

Live at: **https://e2ee-net.onrender.com**

---

## Why this exists

Most "secure note" tools on the internet ask you to trust the server. This one is built so you don't have to: the AES-256 decryption key never leaves the sender's browser except inside a URL fragment, which by design of how HTTP and browsers work is **never transmitted to any server**. The backend stores ciphertext it is structurally incapable of decrypting, even if the database were fully compromised.

This project started as a demo where the server held the private key and printed decrypted plaintext to its own logs — the opposite of zero-knowledge. It was rebuilt from that mistake into the architecture described below.

---

## Architecture

```
Sender's browser                          FastAPI backend                    Recipient's browser
─────────────────                         ────────────────                   ────────────────────
1. Generate AES-256 key
   (or derive via PBKDF2
   from a passphrase)
2. Encrypt note locally
   (AES-256-GCM)
3. POST ciphertext + IV  ──────────────►  4. Store ciphertext only
                                              in Redis, with TTL
                                              (key never received)
5. Build share link:
   /view/<id>#<key>
   (key in URL fragment —
   browsers never send
   fragments to servers)
                                                                          6. Open link, extract
                                                                             id from path, key
                                                                             from fragment
                                           7. GET /status (safe peek,  ◄── 
                                              bots/previews can't burn
                                              the note)
                                           8. User clicks "Reveal" ──────►
                                              POST /reveal — note
                                              deleted from main store,
                                              moved into a 90s grace-
                                              period session
                                           9. Return ciphertext  ─────────►  10. Decrypt locally
                                                                                 with the key from
                                                                                 the URL fragment
```

The server's role, at every step, is to move bytes it cannot interpret. Decryption only ever happens in a browser.

---

## Features

### Core encryption
- **AES-256-GCM**, performed entirely client-side via the native Web Crypto API (`crypto.subtle`) — no third-party crypto library
- **Key in URL fragment**, never sent to the server, by browser design rather than application discipline
- **Optional passphrase second factor** — PBKDF2-HMAC-SHA256 at 100,000 iterations derives the AES key from a sender-chosen passphrase plus the URL token as salt. The server only ever sees a `has_passphrase` boolean; it cannot verify a guess. Correctness is proven solely by the AES-GCM authentication tag succeeding in the recipient's browser

### Note lifecycle
- **Burn after read** — one-time notes, deleted the instant they're revealed
- **Expire after time** — sender-chosen TTL from 1 hour to 7 days, enforced natively by Redis (`SETEX`), no manual cleanup loop
- **Reveal-on-click, not reveal-on-load** — `GET /status` is non-destructive and safe for link-preview bots (WhatsApp, Telegram, Slack, etc.) to hit automatically; only a deliberate `POST /reveal`, fired by an explicit button click, can consume a one-time note
- **Grace-period session window** — a burn-mode reveal doesn't instantly and irreversibly delete on the first server response. The note's record is removed immediately (so a second independent reveal can't also succeed), but the ciphertext survives in a short-lived session for 90 seconds, recoverable if the recipient's connection drops or their tab crashes between clicking Reveal and finishing decryption — the "phone died in the elevator" failure mode that most self-destructing note tools don't handle
- **Recipient-side view-duration auto-clear** — sender can set a timer (5–600s) after which the decrypted text is wiped from the recipient's screen and from memory, not just visually hidden

### Sender-side delivery tracking (optional, account-free)
- A locally-generated tracking token (never sent to the server in raw form — only its SHA-256 hash is) lets the sender check delivery status: active, viewed (with timestamp), expired unread, or being read right now
- Sender-chosen **title**, stored separately from the note and with zero relationship to its content — used only so the sender can tell entries apart in their own dashboard, not derived from what was typed
- **Freeze / unfreeze** — temporarily blocks `POST /reveal` (`423 Locked`) without deleting the note or affecting its TTL; `GET /status` still reports it as present so the link doesn't look broken
- **Destroy now** — sender can manually delete a note early
- **Extend** — add time to an expire-mode note's TTL after the fact (not applicable to burn-mode, which has no clock to extend)
- All four management actions are authenticated purely by possession of the raw tracking token — there are no user accounts in this system

### Operational
- **Redis-backed persistence** with an automatic in-memory fallback for local development when `REDIS_URL` isn't set — note state survives container restarts, redeploys, and free-tier spin-down, none of which it did in the original in-memory-dict version
- **Rate limiting** per IP on every mutating endpoint (`slowapi`)
- **Metadata-only audit log** — timestamps, action type, byte size — never ciphertext, never keys, never plaintext
- **CORS locked to configured origins** in production

---

## Project structure

```
e2ee-web-app/
├── backend/
│   ├── main.py              FastAPI app: all routes, Redis storage layer, crypto-adjacent logic
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx          Entire UI: compose, recipient view, tracking dashboard
│   │   ├── main.jsx
│   │   └── index.css        Theme variables (charcoal + rose, light/dark)
│   ├── public/
│   │   └── favicon.svg
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── render.yaml               Render Blueprint config (see note below on actual deployment)
```

---

## API reference

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Render health check; reports which storage backend is active |
| `POST` | `/api/notes` | Create a note (ciphertext + IV only — server never sees the key) |
| `GET` | `/api/notes/{id}/status` | Non-destructive existence check, safe for bots |
| `POST` | `/api/notes/{id}/reveal` | Destructive read; starts a grace-period session for burn-mode |
| `GET` | `/api/notes/{id}/session/{token}` | Recover an in-flight grace-period session after a refresh |
| `POST` | `/api/notes/{id}/confirm-consumed` | Recipient confirms display finished; finalizes burn-mode cleanup |
| `GET` | `/api/notes/track/{token}` | Sender checks delivery status by raw tracking token |
| `POST` | `/api/notes/{id}/destroy` | Sender manually deletes a note early |
| `POST` | `/api/notes/{id}/freeze` | Sender toggles a temporary reveal lock |
| `POST` | `/api/notes/{id}/extend` | Sender adds time to an expire-mode note's TTL |
| `GET` | `/api/audit-log` | Metadata-only transmission history |
| `GET` | `/api/server-info` | Runtime stats for the UI dashboard |
| `GET` | `/docs` | Interactive Swagger UI |

Rate limits (per IP): 20/min on note creation, destroy, freeze, extend; 30/min on reveal and session recovery; 60/min on status checks; 10/min on the audit log.

---

## Local development

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Without `REDIS_URL` set, the backend automatically falls back to an in-memory store — fine for local testing, but it does not persist across restarts. API docs at `http://127.0.0.1:8000/docs`.

To test with real persistence locally, install Redis and set `REDIS_URL=redis://localhost:6379` in a `.env` file (see `backend/.env.example`).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` and `/health` to `127.0.0.1:8000`, so no CORS configuration is needed locally.

---

## Deployment

This project is deployed on Render as three separate services, created individually through the dashboard (not via Blueprint sync, despite `render.yaml` being present in the repo for reference):

1. **Key Value (Redis-compatible) instance** — free tier, `noeviction` policy (the app manages its own expiry via TTLs and should not have keys evicted early under memory pressure)
2. **Backend web service** — Python runtime, `REDIS_URL` pointed at the Key Value instance's internal connection string, `ALLOWED_ORIGINS` set to the frontend's URL, health check path `/health`
3. **Frontend static site** — Node build (`npm install && npm run build`, publish `dist`), `VITE_API_URL` pointed at the backend, with a `/* → /index.html` rewrite rule configured in the dashboard's Redirects/Rewrites tab (required for direct links like `/view/<id>` to load correctly — static-site rewrite rules on Render are dashboard-configured, not picked up from a `_redirects` file)

`render.yaml` at the repo root reflects this same topology and can be used to recreate the setup via Render Blueprints if starting fresh.

---

## Security notes and honest limitations

- **Ephemeral keys** — a fresh AES-256 key is generated per note (or derived fresh per passphrase), giving forward secrecy at the session layer
- **Generic error responses** on `/reveal` for all decryption-adjacent failures, to avoid oracle/timing attacks
- **Management actions are gated by tracking-token possession only** — there are no user accounts, so the threat model is the same as the share link itself: whoever has the token can act on the note
- **The in-memory fallback is for local development only.** Running it in production reintroduces the exact data-loss problem the Redis migration exists to fix
- **A wrong passphrase on a burn-mode note is unrecoverable** — the destructive reveal fires before the client knows whether decryption will succeed, so a mistyped passphrase destroys the note on that single attempt
- **No protection against a determined attacker with OS-level clipboard or screen monitoring** during the window a note is actually being read — this app intentionally does not attempt anti-forensic display tricks (blur-until-hover, clipboard auto-clear) after concluding they added complexity without a real security guarantee to show for it

---

## Tech stack

**Backend:** FastAPI, Redis (via `redis.asyncio`), slowapi, Pydantic, Uvicorn
**Frontend:** React 18, Vite, native Web Crypto API — no encryption or icon libraries
**Hosting:** Render (web services + free Key Value/Valkey instance)

---

## Contact the developer

**Aditya Kumar**

- Phone: [+91 70794 87671](tel:+917079487671)
- Email: [adii.utsav@gmail.com](mailto:adii.utsav@gmail.com)
- LinkedIn: [linkedin.com/in/aditya-kumar-3241b6286](https://www.linkedin.com/in/aditya-kumar-3241b6286/)
- GitHub: [github.com/Rememberful](https://github.com/Rememberful)
- Medium: [medium.com/@adii.utsav](https://medium.com/@adii.utsav)
- Contribute: [github.com/Rememberful/E2EE-Net](https://github.com/Rememberful/E2EE-Net.git)

---

*THE END.*