import React, { useState, useEffect, useRef, useCallback } from 'react';

// ─── Config ────────────────────────────────────────────────────────────────────
const API_BASE =
  import.meta.env.VITE_API_URL !== undefined ? import.meta.env.VITE_API_URL : '';

// ─── Web Crypto helpers (AES-256-GCM, key never leaves the browser) ──────────
async function generateKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function exportKeyRaw(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufToBase64Url(raw);
}

async function importKeyRaw(b64url) {
  const raw = base64UrlToBuf(b64url);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
}

// ─── Passphrase key stretching (PBKDF2-HMAC-SHA256, second factor) ───────────
// The URL fragment token doubles as a per-note salt — it's already unique and
// high-entropy per note, so it prevents rainbow-table reuse across notes
// without needing a second random value. The passphrase itself never leaves
// this function's scope and is never sent anywhere.
const PBKDF2_ITERATIONS = 100_000;

async function deriveKeyFromPassphrase(passphrase, urlToken, usage) {
  const encoder = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );

  const salt = encoder.encode(urlToken);

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable — the derived key bytes can never be read back out of the browser, only used
    usage === 'encrypt' ? ['encrypt'] : ['decrypt'],
  );
}

async function encryptText(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return {
    ciphertext: bufToBase64(ctBuf),
    iv: bufToBase64(iv.buffer),
  };
}

async function decryptText(key, ciphertextB64, ivB64) {
  const ct = base64ToBuf(ciphertextB64);
  const iv = base64ToBuf(ivB64);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

// ─── Sender-side delivery tracking ─────────────────────────────────────────────
// The tracking token is generated entirely client-side and only its SHA-256
// hash is ever sent to the server. The server stores that hash as a lookup
// key but never learns the raw token — only whoever holds the raw token
// (kept in this browser's localStorage) can later query status. The hash has
// no mathematical relationship to the AES decryption key, which lives
// separately in the URL fragment and never reaches the server in any form.
function generateTrackingToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return bufToBase64Url(bytes.buffer);
}

async function sha256Hex(input) {
  const encoded = new TextEncoder().encode(input);
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
  const bytes = new Uint8Array(hashBuf);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const TRACKED_NOTES_STORAGE_KEY = 'zk-vault-tracked-notes';
const MIN_VIEW_DURATION = 5;
const MAX_VIEW_DURATION = 600;

function loadTrackedNotes() {
  try {
    const raw = window.localStorage?.getItem?.(TRACKED_NOTES_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveTrackedNote(entry) {
  try {
    const existing = loadTrackedNotes();
    const updated = [entry, ...existing].slice(0, 50); // cap local history
    window.localStorage?.setItem?.(TRACKED_NOTES_STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // localStorage unavailable (private browsing, etc.) — tracking still
    // works for the current session via React state, just won't persist.
  }
}

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToBase64Url(buf) {
  return bufToBase64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlToBuf(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return base64ToBuf(b64);
}

// ─── Small utils ───────────────────────────────────────────────────────────────
const ts = () => new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

// Shared font stacks — one for normal UI text, one for IDs/keys/timestamps
// that genuinely benefit from a monospace look.
const FONT_UI = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
const FONT_MONO = "ui-monospace, 'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace";

// ─── Sub-components ─────────────────────────────────────────────────────────────
function Badge({ tone, children }) {
  const map = {
    success: 'var(--success)',
    accent:  'var(--accent)',
    warning: 'var(--warning)',
    danger:  'var(--danger)',
    dim:     'var(--text-secondary)',
  };
  const c = map[tone] || map.dim;
  return (
    <span style={{
      background: `${c}14`, color: c, fontSize: '11.5px', fontWeight: 600,
      padding: '4px 10px', borderRadius: '5px', fontFamily: FONT_UI,
      whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  );
}

function Field({ label, value, color }) {
  return (
    <div style={{ marginBottom: '12px' }}>
      <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginBottom: '3px', fontFamily: FONT_UI }}>
        {label}
      </div>
      <div className="mono-value" style={{ color: color || 'var(--text-primary)', fontSize: '13.5px', wordBreak: 'break-all', fontFamily: FONT_UI }}>
        {value || '—'}
      </div>
    </div>
  );
}

function Card({ title, subtitle, borderColor, children, style }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${borderColor || 'var(--border-base)'}`,
      borderRadius: 'var(--radius-lg)',
      padding: '22px 24px',
      fontFamily: FONT_UI,
      ...style,
    }}>
      {title && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            {title}
          </div>
          {subtitle && (
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px', lineHeight: 1.5 }}>
              {subtitle}
            </div>
          )}
        </div>
      )}
      {children}
    </div>
  );
}

function ThemeToggle({ theme, onToggle }) {
  const isDark = theme === 'dark';
  return (
    <button
      onClick={onToggle}
      aria-label="Toggle theme"
      style={{
        position: 'relative',
        width: '44px',
        height: '24px',
        borderRadius: '999px',
        border: '1px solid var(--border-base)',
        background: 'var(--bg-input)',
        cursor: 'pointer',
        transition: 'background 150ms ease',
      }}
    >
      <span style={{
        position: 'absolute',
        top: '2px',
        left: isDark ? '21px' : '2px',
        width: '18px',
        height: '18px',
        borderRadius: '50%',
        background: 'var(--accent)',
        transition: 'left 150ms ease',
      }} />
    </button>
  );
}

function AuditRow({ entry, index }) {
  const toneColor = {
    CREATE: 'var(--accent)', READ: 'var(--success)', READ_AND_BURN: 'var(--warning)', READ_MISS: 'var(--danger)',
  };
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '36px 84px 1fr 110px 64px',
      gap: '8px', padding: '9px 0', borderBottom: '1px solid var(--border-dim)',
      fontSize: '13px', alignItems: 'center', fontFamily: FONT_UI,
    }}>
      <span style={{ color: 'var(--text-muted)' }}>{index + 1}</span>
      <span style={{ color: 'var(--text-secondary)' }}>{entry.timestamp?.slice(11, 19)}</span>
      <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.id?.slice(0, 10)}
      </span>
      <span style={{ color: toneColor[entry.action] || 'var(--accent)', fontWeight: 600 }}>
        {entry.action}
      </span>
      <span style={{ color: 'var(--text-muted)', textAlign: 'right' }}>{entry.payload_size_bytes}B</span>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [theme, setTheme] = useState(() => {
    const saved = typeof window !== 'undefined' ? window.localStorage?.getItem?.('theme') : null;
    return saved || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { window.localStorage?.setItem?.('theme', theme); } catch { /* ignore */ }
  }, [theme]);

  // Routing: are we viewing a shared note? (id is in the path, key in the hash)
  const [route, setRoute] = useState(() => parseRoute());

  function parseRoute() {
    const path = window.location.pathname;
    const match = path.match(/\/view\/([a-f0-9]+)/);
    const hash = window.location.hash.replace(/^#/, '');
    if (match) return { view: 'read', noteId: match[1], key: hash || null };
    return { view: 'create' };
  }

  // Server connectivity
  const [serverInfo, setServerInfo] = useState(null);
  const [serverStatus, setServerStatus] = useState('connecting');

  // Compose pane
  const [message, setMessage] = useState('');
  const [mode, setMode] = useState('burn');           // 'burn' | 'expire'
  const [ttlHours, setTtlHours] = useState(24);
  const [usePassphrase, setUsePassphrase] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [enableTracking, setEnableTracking] = useState(true);
  const [trackingTitle, setTrackingTitle] = useState('');
  const [viewDurationEnabled, setViewDurationEnabled] = useState(false);
  const [viewDurationSeconds, setViewDurationSeconds] = useState(30);
  const [clientId] = useState(() => 'cli_' + Math.random().toString(36).slice(2, 10));

  const [creating, setCreating] = useState(false);
  const [shareLink, setShareLink] = useState(null);
  const [createError, setCreateError] = useState(null);
  const [linkCopied, setLinkCopied] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showHowItWorks, setShowHowItWorks] = useState(false);
  const [showActivityLog, setShowActivityLog] = useState(false);

  // Sender-side delivery tracking dashboard
  const [trackedNotes, setTrackedNotes] = useState(() => loadTrackedNotes());
  const [trackingStatuses, setTrackingStatuses] = useState({}); // noteId -> { status, viewedAt, title, expiresAt, mode }
  const [trackingLoading, setTrackingLoading] = useState(false);
  const [managingNoteId, setManagingNoteId] = useState(null); // which entry has an action in flight
  const [extendInputFor, setExtendInputFor] = useState(null); // noteId currently showing the extend-by input
  const [extendHours, setExtendHours] = useState(1);

  // Audit log
  const [auditLog, setAuditLog] = useState([]);
  const [logLoading, setLogLoading] = useState(false);

  // Read pane
  // idle -> checking -> gated (waiting for click) -> revealing -> ready/burned
  //                  \-> passphrase_required -> revealing -> ready/burned
  //                  \-> error
  const [readState, setReadState] = useState('idle');
  const [readError, setReadError] = useState(null);
  const [decrypted, setDecrypted] = useState(null);
  const [noteMeta, setNoteMeta] = useState(null); // { mode, hasPassphrase, frozen } from the safe /status peek
  const [readPassphrase, setReadPassphrase] = useState('');
  const [passphraseAttemptFailed, setPassphraseAttemptFailed] = useState(false);

  // Grace-period session (burn-mode only) + recipient-side view-duration auto-clear
  const [sessionToken, setSessionToken] = useState(null);
  const [viewSecondsLeft, setViewSecondsLeft] = useState(null);
  const [autoCleared, setAutoCleared] = useState(false);

  // Activity log
  const [termLines, setTermLines] = useState([
    { t: ts(), msg: 'Ready.', tone: 'dim' },
  ]);
  const termRef = useRef(null);
  const log = useCallback((msg, tone = 'dim') => {
    setTermLines(prev => [...prev.slice(-49), { t: ts(), msg, tone }]);
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [termLines]);

  // ── Boot: server info ──────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/server-info`);
        const data = await res.json();
        setServerInfo(data);
        setServerStatus('active');
        log(`Connected. Architecture: ${data.architecture}`, 'success');
      } catch {
        setServerStatus('error');
        log('Cannot reach the server. Is it running?', 'danger');
      }
    })();
  }, [log]);

  const fetchAuditLog = useCallback(async () => {
    setLogLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/audit-log?limit=20`);
      const data = await res.json();
      setAuditLog(data.entries || []);
    } catch {
      log('Failed to fetch activity log.', 'danger');
    } finally {
      setLogLoading(false);
    }
  }, [log]);

  // ── Sender delivery tracking ───────────────────────────────────────────
  // Queries status for every locally-saved tracked note. Each query sends
  // only the raw tracking token over HTTPS to be hashed server-side for
  // lookup — the server never learns it ahead of time and has no way to
  // enumerate trackers on its own; only someone holding a specific raw
  // token (kept in this browser's localStorage) can check that note.
  const checkAllTrackingStatuses = useCallback(async () => {
    if (trackedNotes.length === 0) return;
    setTrackingLoading(true);
    try {
      const results = await Promise.all(
        trackedNotes.map(async entry => {
          try {
            const res = await fetch(`${API_BASE}/api/notes/track/${entry.trackingToken}`);
            if (!res.ok) return [entry.noteId, { status: 'unknown' }];
            const data = await res.json();
            return [entry.noteId, {
              status: data.status, viewedAt: data.viewed_at,
              title: data.title, expiresAt: data.expires_at, mode: data.mode,
            }];
          } catch {
            return [entry.noteId, { status: 'unknown' }];
          }
        })
      );
      setTrackingStatuses(Object.fromEntries(results));
    } finally {
      setTrackingLoading(false);
    }
  }, [trackedNotes]);

  useEffect(() => {
    if (trackedNotes.length > 0) checkAllTrackingStatuses();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // only on initial mount — manual refresh button covers the rest

  // ── Sender-side management actions: destroy / freeze / extend ─────────
  // All three are authenticated purely by possession of the raw tracking
  // token stored in this browser's localStorage — there is no account or
  // login, so that token is the only proof of "I created this note."
  const handleDestroy = async (entry) => {
    if (!window.confirm(`Permanently destroy this note${entry.title ? ` ("${entry.title}")` : ''}? This cannot be undone.`)) return;
    setManagingNoteId(entry.noteId);
    try {
      const res = await fetch(`${API_BASE}/api/notes/${entry.noteId}/destroy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tracking_token: entry.trackingToken }),
      });
      if (res.ok) {
        setTrackingStatuses(prev => ({ ...prev, [entry.noteId]: { ...prev[entry.noteId], status: 'destroyed' } }));
        log(`Note ${entry.noteId.slice(0, 10)}… destroyed.`, 'warning');
      } else {
        log('Failed to destroy note — it may already be gone.', 'danger');
      }
    } catch {
      log('Network error while destroying note.', 'danger');
    } finally {
      setManagingNoteId(null);
    }
  };

  const handleToggleFreeze = async (entry) => {
    setManagingNoteId(entry.noteId);
    try {
      const res = await fetch(`${API_BASE}/api/notes/${entry.noteId}/freeze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tracking_token: entry.trackingToken }),
      });
      if (res.ok) {
        const data = await res.json();
        setTrackingStatuses(prev => ({ ...prev, [entry.noteId]: { ...prev[entry.noteId], status: data.status } }));
        log(`Note ${entry.noteId.slice(0, 10)}… ${data.status === 'frozen' ? 'frozen' : 'unfrozen'}.`, 'accent');
      } else {
        log('Failed to update freeze state.', 'danger');
      }
    } catch {
      log('Network error while toggling freeze.', 'danger');
    } finally {
      setManagingNoteId(null);
    }
  };

  const handleExtend = async (entry) => {
    setManagingNoteId(entry.noteId);
    try {
      const res = await fetch(`${API_BASE}/api/notes/${entry.noteId}/extend`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tracking_token: entry.trackingToken, additional_seconds: extendHours * 3600 }),
      });
      if (res.ok) {
        const data = await res.json();
        setTrackingStatuses(prev => ({ ...prev, [entry.noteId]: { ...prev[entry.noteId], expiresAt: data.new_expires_at } }));
        log(`Note ${entry.noteId.slice(0, 10)}… extended by ${extendHours}h.`, 'accent');
        setExtendInputFor(null);
      } else {
        const err = await res.json().catch(() => ({}));
        log(`Failed to extend: ${err.detail || 'unknown error'}`, 'danger');
      }
    } catch {
      log('Network error while extending note.', 'danger');
    } finally {
      setManagingNoteId(null);
    }
  };

  const removeTrackedEntry = (noteId) => {
    const updated = trackedNotes.filter(e => e.noteId !== noteId);
    setTrackedNotes(updated);
    try { window.localStorage?.setItem?.(TRACKED_NOTES_STORAGE_KEY, JSON.stringify(updated)); } catch { /* ignore */ }
  };

  // ── Create note flow ───────────────────────────────────────────────────
  const handleCreate = async () => {
    if (!message.trim()) return;
    if (usePassphrase && passphrase.length < 8) {
      setCreateError('Passphrase must be at least 8 characters.');
      return;
    }

    setCreating(true);
    setCreateError(null);
    setShareLink(null);
    setLinkCopied(false);

    try {
      let key, rawToken;

      if (usePassphrase) {
        // The fragment token is random, high-entropy, and unique per note —
        // it serves as the PBKDF2 salt. It is NOT the key itself; without the
        // passphrase, the salt alone derives nothing useful.
        const tokenBytes = crypto.getRandomValues(new Uint8Array(18));
        rawToken = bufToBase64Url(tokenBytes.buffer);
        log('Deriving key from passphrase (PBKDF2-HMAC-SHA256, 100,000 iterations)...', 'dim');
        key = await deriveKeyFromPassphrase(passphrase, rawToken, 'encrypt');
        log('Key derived locally — passphrase discarded from memory.', 'accent');
      } else {
        log('Generating an encryption key in your browser...', 'dim');
        key = await generateKey();
        rawToken = await exportKeyRaw(key);
      }

      log('Encrypting note locally (AES-256-GCM)...', 'dim');
      const { ciphertext, iv } = await encryptText(key, message);

      if (!usePassphrase) {
        log('Key will be embedded in the link, never sent to the server.', 'accent');
      }

      let rawTrackingToken = null;
      let hashedTrackingToken = null;
      if (enableTracking) {
        rawTrackingToken = generateTrackingToken();
        hashedTrackingToken = await sha256Hex(rawTrackingToken);
        log('Generated a tracking token locally — only its hash is sent to the server.', 'dim');
      }

      const body = {
        ciphertext,
        iv,
        mode,
        ttl_seconds: mode === 'expire' ? ttlHours * 3600 : null,
        has_passphrase: usePassphrase,
        client_id: clientId,
        hashed_tracking_token: hashedTrackingToken,
        tracking_title: enableTracking && trackingTitle.trim() ? trackingTitle.trim().slice(0, 80) : null,
        view_duration_seconds: viewDurationEnabled ? viewDurationSeconds : null,
      };

      log('Sending ciphertext to the server...', 'dim');
      const res = await fetch(`${API_BASE}/api/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const result = await res.json();
      const link = `${window.location.origin}/view/${result.id}#${rawToken}`;
      setShareLink({
        url: link, mode: result.mode, expiresAt: result.expires_at,
        hasPassphrase: usePassphrase, trackingToken: rawTrackingToken,
      });

      log(`Note saved. id=${result.id.slice(0, 10)}… mode=${result.mode}`, 'success');
      log('The server received no key material and cannot decrypt this note.', 'success');
      if (usePassphrase) {
        log('Share the passphrase with the recipient through a different channel than the link.', 'accent');
      }

      if (rawTrackingToken) {
        // Only the sender-typed title is kept locally — never the note's
        // own content, even truncated. The title has no relationship to
        // what the note says; it exists purely so the sender can tell
        // tracked entries apart in their own dashboard.
        const entry = {
          noteId: result.id,
          trackingToken: rawTrackingToken,
          mode: result.mode,
          createdAt: result.created_at,
          title: body.tracking_title || null,
        };
        saveTrackedNote(entry);
        setTrackedNotes(prev => [entry, ...prev].slice(0, 50));
        // We know it's freshly created and unread — show that immediately
        // rather than waiting on a round-trip to /track for the first paint.
        setTrackingStatuses(prev => ({
          ...prev,
          [result.id]: { status: 'active', viewedAt: null, title: entry.title, expiresAt: result.expires_at, mode: result.mode },
        }));
      }

      setMessage('');
      setPassphrase('');
      setTrackingTitle('');
      await fetchAuditLog();
    } catch (err) {
      setCreateError(err.message || 'Encryption or transmission failed.');
      log(`Error: ${err.message}`, 'danger');
    } finally {
      setCreating(false);
    }
  };

  const copyLink = async () => {
    if (!shareLink) return;
    try {
      await navigator.clipboard.writeText(shareLink.url);
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    } catch {
      log('Clipboard write failed — copy the link manually.', 'warning');
    }
  };

  // ── On load (route.view === 'read'): recover an in-flight grace-period
  // session first, falling back to a fresh SAFE peek only if none exists.
  //
  // Why this matters: if Reveal was already clicked in this tab and the
  // connection dropped, the tab crashed, or the page was refreshed before
  // decryption finished rendering, a naive reload would just re-run /status
  // — which now 404s, because the note's own key was deleted the moment
  // Reveal succeeded. Without recovery, that's a permanent, silent loss of
  // the secret purely from a network blip, which is the exact failure mode
  // self-destructing-note tools are notorious for. sessionStorage (not
  // localStorage) is used deliberately: recovery should only apply to the
  // same tab/window that initiated the reveal, not leak across tabs.
  useEffect(() => {
    if (route.view !== 'read') return;
    (async () => {
      setReadState('checking');
      setReadError(null);

      if (!route.key) {
        setReadState('error');
        setReadError('No decryption key present in the link. The key lives after the # and never reaches the server.');
        return;
      }

      const recoveryKey = `zk-vault-session-${route.noteId}`;
      let recoveredSessionToken = null;
      try {
        recoveredSessionToken = window.sessionStorage?.getItem?.(recoveryKey);
      } catch { /* sessionStorage unavailable — proceed without recovery */ }

      if (recoveredSessionToken) {
        try {
          const res = await fetch(`${API_BASE}/api/notes/${route.noteId}/session/${recoveredSessionToken}`);
          if (res.ok) {
            const data = await res.json();
            log('Recovered an in-progress reveal after a refresh or dropped connection.', 'accent');
            const key = await importKeyRaw(route.key);
            const plaintext = await decryptText(key, data.ciphertext, data.iv);
            setDecrypted({ text: plaintext, mode: data.mode });
            setSessionToken(recoveredSessionToken);
            try { window.sessionStorage?.removeItem?.(recoveryKey); } catch { /* ignore */ }
            fetch(`${API_BASE}/api/notes/${route.noteId}/confirm-consumed?session_token=${encodeURIComponent(recoveredSessionToken)}`, { method: 'POST' })
              .catch(() => { /* best-effort */ });
            setReadState('burned');
            return;
          }
          // Session expired or already confirmed — the grace period ran out
          // or this same reveal already completed elsewhere. Fall through to
          // a normal peek, which will correctly report the note as gone.
          try { window.sessionStorage?.removeItem?.(recoveryKey); } catch { /* ignore */ }
        } catch {
          // Recovery attempt failed — fall through to a normal peek below.
        }
      }

      try {
        const res = await fetch(`${API_BASE}/api/notes/${route.noteId}/status`);
        if (res.status === 404) {
          setReadState('error');
          setReadError('This note was not found. It may have already been viewed (burn-after-read) or has expired.');
          return;
        }
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        if (data.frozen) {
          setReadState('frozen');
          setNoteMeta({ mode: data.mode, hasPassphrase: !!data.has_passphrase, frozen: true });
          return;
        }
        setNoteMeta({ mode: data.mode, hasPassphrase: !!data.has_passphrase, frozen: false });
        // Notes with a passphrase go straight to the passphrase challenge —
        // entering the correct passphrase IS the deliberate reveal action,
        // so no separate "click to reveal" button is needed for those.
        setReadState(data.has_passphrase ? 'passphrase_required' : 'gated');
      } catch (err) {
        setReadState('error');
        setReadError('Could not reach the server to check this note.');
      }
    })();
  }, [route]);

  // ── Deliberate user action: DESTRUCTIVE reveal ─────────────────────────
  // Only this function calls POST /reveal. It never runs on page load — only
  // from the "Click to reveal" button or the passphrase form's submit, both
  // of which require a deliberate user action. An automated fetch can never
  // trigger it.
  const handleReveal = async () => {
    setReadState('revealing');
    setReadError(null);
    setPassphraseAttemptFailed(false);

    try {
      const res = await fetch(`${API_BASE}/api/notes/${route.noteId}/reveal`, { method: 'POST' });
      if (res.status === 404) {
        setReadState('error');
        setReadError('This note was not found. It may have already been viewed (burn-after-read) or has expired.');
        return;
      }
      if (res.status === 423) {
        // Frozen between the initial peek and this click — a real but rare
        // race. Treated the same as the dedicated frozen state.
        setReadState('frozen');
        return;
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();

      // Persist the session token immediately, before attempting decryption —
      // this is the actual window the grace period protects: a crash, tab
      // close, or refresh between the server confirming the reveal and this
      // tab finishing local decryption. sessionStorage is tab-scoped on
      // purpose, since recovery should only apply to the same tab/window
      // that initiated the reveal.
      const recoveryKey = `zk-vault-session-${route.noteId}`;
      if (data.session_token) {
        try { window.sessionStorage?.setItem?.(recoveryKey, data.session_token); } catch { /* ignore */ }
      }

      let key;
      if (noteMeta?.hasPassphrase) {
        key = await deriveKeyFromPassphrase(readPassphrase, route.key, 'decrypt');
      } else {
        key = await importKeyRaw(route.key);
      }

      // A wrong passphrase produces a different derived key, which makes the
      // GCM authentication tag check fail — this throw is how an incorrect
      // guess is detected. There is no separate "is this correct" call to
      // the server; the server cannot know either way.
      const plaintext = await decryptText(key, data.ciphertext, data.iv);

      setDecrypted({ text: plaintext, mode: data.mode });
      setSessionToken(data.session_token || null);

      if (data.mode === 'burn' && data.session_token) {
        // Decryption succeeded in this tab, so there's nothing left to
        // recover from — confirm consumption now, which both clears the
        // recovery entry and flips the sender's tracker from "consuming"
        // to "viewed."
        try { window.sessionStorage?.removeItem?.(recoveryKey); } catch { /* ignore */ }
        fetch(`${API_BASE}/api/notes/${route.noteId}/confirm-consumed?session_token=${encodeURIComponent(data.session_token)}`, { method: 'POST' })
          .catch(() => { /* best-effort — the session's own TTL is the fallback cleanup */ });
      }

      if (data.view_duration_seconds) {
        setViewSecondsLeft(data.view_duration_seconds);
      }

      setReadState(data.mode === 'burn' ? 'burned' : 'ready');
    } catch (err) {
      if (noteMeta?.hasPassphrase) {
        // The note is already consumed server-side at this point if it was
        // burn mode — a wrong passphrase on a burn note means the plaintext
        // is now permanently unrecoverable. This is the same trade-off
        // Privnote-style tools make: the link should only be opened by the
        // intended recipient who knows the passphrase.
        setPassphraseAttemptFailed(true);
        setReadState('passphrase_required');
        setReadPassphrase('');
      } else {
        setReadState('error');
        setReadError('Decryption failed. The key may be incorrect or the ciphertext corrupted.');
      }
    }
  };

  // ── Recipient-side view-duration auto-clear ────────────────────────────
  // Purely a client-side display timer, separate from the server's
  // grace-period session window. Counts down once per second after a
  // successful reveal; when it hits zero, the plaintext is wiped from React
  // state (not just visually hidden) so it no longer exists in memory.
  useEffect(() => {
    if (viewSecondsLeft === null || viewSecondsLeft <= 0) {
      if (viewSecondsLeft === 0 && decrypted && !autoCleared) {
        setAutoCleared(true);
        setDecrypted(null);
      }
      return;
    }
    const timer = setTimeout(() => setViewSecondsLeft(s => (s !== null ? s - 1 : null)), 1000);
    return () => clearTimeout(timer);
  }, [viewSecondsLeft, decrypted, autoCleared]);

  // ── Render: READ VIEW ──────────────────────────────────────────────────
  if (route.view === 'read') {
    return (
      <Shell theme={theme} onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} minimal>
        <div style={{ maxWidth: '600px', margin: '60px auto', padding: '0 20px' }}>
          <Card
            title="Secure note"
            subtitle="Decryption happens in this browser only. The server never had your key."
            borderColor={readState === 'error' ? 'var(--danger)' : 'var(--border-base)'}
          >
            {readState === 'checking' && (
              <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>Checking note status…</div>
            )}

            {readState === 'error' && (
              <div style={{ color: 'var(--danger)', fontSize: '14px', lineHeight: 1.6 }}>{readError}</div>
            )}

            {readState === 'frozen' && (
              <div>
                <div style={{ marginBottom: '14px' }}>
                  <Badge tone="warning">Temporarily frozen by sender</Badge>
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: 1.6 }}>
                  This note's sender has temporarily locked it. It still exists and has not expired — try
                  this link again later, or contact the sender.
                </div>
              </div>
            )}

            {readState === 'passphrase_required' && (
              <div>
                <div style={{ marginBottom: '16px' }}>
                  <Badge tone={noteMeta?.mode === 'burn' ? 'warning' : 'accent'}>
                    {noteMeta?.mode === 'burn' ? 'Passphrase required — burns after this attempt' : 'Passphrase required'}
                  </Badge>
                </div>

                {passphraseAttemptFailed && (
                  <div style={{
                    marginBottom: '14px', padding: '10px 13px', background: 'var(--danger)15',
                    border: '1px solid var(--danger)', borderRadius: 'var(--radius-sm)',
                    fontSize: '13px', color: 'var(--danger)', lineHeight: 1.55,
                  }}>
                    {noteMeta?.mode === 'burn'
                      ? 'That passphrase was incorrect, and this note was burn-after-read — it has now been permanently consumed and cannot be recovered.'
                      : 'That passphrase was incorrect. You can try again before this note expires.'}
                  </div>
                )}

                <form
                  onSubmit={e => { e.preventDefault(); if (readPassphrase) handleReveal(); }}
                  style={{
                    background: 'var(--bg-input)', border: '1px solid var(--border-base)',
                    borderRadius: 'var(--radius-sm)', padding: '20px 18px', marginBottom: '14px',
                  }}
                >
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '14px', lineHeight: 1.6 }}>
                    {noteMeta?.mode === 'burn' && !passphraseAttemptFailed
                      ? 'This note requires a passphrase and will burn after this single attempt, whether it succeeds or not. Make sure you have the correct passphrase before submitting.'
                      : 'Enter the passphrase the sender shared with you separately.'}
                  </div>
                  <input
                    type="password"
                    value={readPassphrase}
                    onChange={e => setReadPassphrase(e.target.value)}
                    placeholder="Passphrase"
                    autoFocus
                    style={{
                      width: '100%', background: 'var(--bg-root)', color: 'var(--text-primary)',
                      border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                      padding: '10px 13px', fontSize: '14px', fontFamily: FONT_UI, marginBottom: '14px',
                      boxSizing: 'border-box',
                    }}
                  />
                  <button
                    type="submit"
                    disabled={!readPassphrase}
                    style={{
                      padding: '10px 24px', background: readPassphrase ? 'var(--accent)' : 'var(--border-base)',
                      color: '#1a1418', border: 'none', borderRadius: 'var(--radius-sm)',
                      fontFamily: FONT_UI, fontWeight: 600, fontSize: '14px',
                      opacity: readPassphrase ? 1 : 0.55, width: '100%', cursor: readPassphrase ? 'pointer' : 'default',
                    }}
                  >
                    Submit and reveal
                  </button>
                </form>

                <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  The passphrase is checked entirely in your browser. The server never sees it and cannot verify it.
                </div>
              </div>
            )}

            {readState === 'gated' && (
              <div>
                <div style={{ marginBottom: '16px' }}>
                  <Badge tone={noteMeta?.mode === 'burn' ? 'warning' : 'accent'}>
                    {noteMeta?.mode === 'burn' ? 'This note will burn after you reveal it' : 'This note can be revealed until it expires'}
                  </Badge>
                </div>
                <div style={{
                  background: 'var(--bg-input)', border: '1px solid var(--border-base)',
                  borderRadius: 'var(--radius-sm)', padding: '26px 18px', textAlign: 'center',
                  marginBottom: '14px',
                }}>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: 1.6 }}>
                    {noteMeta?.mode === 'burn'
                      ? 'Decrypting now will permanently delete this note from the server. This cannot be undone.'
                      : 'Click below to decrypt this note in your browser.'}
                  </div>
                  <button
                    onClick={handleReveal}
                    style={{
                      padding: '11px 26px', background: 'var(--accent)', color: '#1a1418',
                      border: 'none', borderRadius: 'var(--radius-sm)', fontFamily: FONT_UI,
                      fontWeight: 600, fontSize: '14px', cursor: 'pointer',
                    }}
                  >
                    Click to reveal
                  </button>
                </div>
                <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  Checking this link does not consume it — link previews from messaging apps cannot burn this note. Only this button does.
                </div>
              </div>
            )}

            {readState === 'revealing' && (
              <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
                {noteMeta?.hasPassphrase ? 'Deriving key and decrypting in your browser…' : 'Decrypting in your browser…'}
              </div>
            )}

            {(readState === 'ready' || readState === 'burned') && decrypted && (
              <>
                {readState === 'burned' && (
                  <div style={{ marginBottom: '14px' }}>
                    <Badge tone="warning">Burned after this read — it no longer exists on the server</Badge>
                  </div>
                )}
                {viewSecondsLeft !== null && viewSecondsLeft > 0 && (
                  <div style={{ marginBottom: '14px' }}>
                    <Badge tone="accent">Clearing from screen in {viewSecondsLeft}s</Badge>
                  </div>
                )}
                <div style={{
                  background: 'var(--bg-input)', border: '1px solid var(--border-dim)',
                  borderRadius: 'var(--radius-sm)', padding: '16px 18px', fontSize: '15px',
                  color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  lineHeight: 1.7, fontFamily: FONT_UI,
                }}>
                  {decrypted.text}
                </div>
                <div style={{ marginTop: '14px' }}>
                  <a href="/" style={{ fontSize: '13px', color: 'var(--accent)' }}>Create a new secure note →</a>
                </div>
              </>
            )}

            {(readState === 'ready' || readState === 'burned') && !decrypted && autoCleared && (
              <div>
                <div style={{ marginBottom: '14px' }}>
                  <Badge tone="dim">Cleared from screen</Badge>
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: 1.6 }}>
                  This note's sender-set view duration elapsed, so the text has been removed from this
                  page's memory. {readState === 'burned' ? "It was already deleted from the server when you revealed it." : 'Reopen the link to view it again, if it has not expired.'}
                </div>
              </div>
            )}

          </Card>
        </div>
      </Shell>
    );
  }

  // ── Render: CREATE VIEW ────────────────────────────────────────────────
  const canSend = !!message.trim() && !creating && (!usePassphrase || passphrase.length >= 8);
  const uptimeStr = serverInfo ? `${Math.floor(serverInfo.uptime_seconds / 60)}m ${serverInfo.uptime_seconds % 60}s` : '—';

  return (
    <Shell theme={theme} onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} serverStatus={serverStatus}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '680px', margin: '0 auto' }}>

          {/* Compose */}
          <Card title="Send a secret" subtitle="Write your message below. It's encrypted on your device before it ever reaches the server.">
            <textarea
              rows={6}
              value={message}
              onChange={e => setMessage(e.target.value)}
              placeholder="Type a password, a private message, anything sensitive…"
              style={{
                width: '100%', background: 'var(--bg-input)', color: 'var(--text-primary)',
                border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                padding: '14px 16px', fontSize: '15px', fontFamily: FONT_UI,
                resize: 'vertical', lineHeight: 1.6, transition: 'border-color 150ms ease',
                boxSizing: 'border-box',
              }}
              onFocus={e => e.target.style.borderColor = 'var(--accent)'}
              onBlur={e => e.target.style.borderColor = 'var(--border-base)'}
            />
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px', textAlign: 'right' }}>
              {message.length} characters
            </div>

            <div style={{ marginTop: '16px' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                When should this disappear?
              </div>
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <RadioCard
                  active={mode === 'burn'}
                  onClick={() => setMode('burn')}
                  title="After it's read once"
                  subtitle="Deleted the moment your recipient opens it"
                />
                <RadioCard
                  active={mode === 'expire'}
                  onClick={() => setMode('expire')}
                  title="After some time"
                  subtitle="Stays available until it expires, even if unread"
                />
              </div>
              {mode === 'expire' && (
                <div style={{ marginTop: '10px' }}>
                  <select
                    value={ttlHours}
                    onChange={e => setTtlHours(Number(e.target.value))}
                    style={{
                      background: 'var(--bg-input)', color: 'var(--text-primary)',
                      border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                      padding: '8px 12px', fontSize: '13.5px', fontFamily: FONT_UI,
                    }}
                  >
                    <option value={1}>Expires in 1 hour</option>
                    <option value={6}>Expires in 6 hours</option>
                    <option value={24}>Expires in 24 hours</option>
                    <option value={72}>Expires in 3 days</option>
                    <option value={168}>Expires in 7 days</option>
                  </select>
                </div>
              )}
            </div>

            <div style={{ marginTop: '18px', borderTop: '1px solid var(--border-dim)', paddingTop: '14px' }}>
              <Collapsible
                open={showAdvanced}
                onToggle={() => setShowAdvanced(v => !v)}
                label="Add a passphrase, tracking, or auto-clear timer"
                openLabel="Hide extra options"
              >
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <Switch
                    checked={usePassphrase}
                    onChange={() => setUsePassphrase(v => !v)}
                    label="Require a passphrase to open"
                    description="An extra word or phrase the recipient must enter — share it separately from the link itself"
                  />
                  {usePassphrase && (
                    <div style={{ marginBottom: '8px', paddingLeft: '50px' }}>
                      <input
                        type="password"
                        value={passphrase}
                        onChange={e => setPassphrase(e.target.value)}
                        placeholder="At least 8 characters"
                        style={{
                          width: '100%', maxWidth: '360px', background: 'var(--bg-input)', color: 'var(--text-primary)',
                          border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                          padding: '9px 12px', fontSize: '13.5px', fontFamily: FONT_UI,
                          transition: 'border-color 150ms ease', boxSizing: 'border-box',
                        }}
                        onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                        onBlur={e => e.target.style.borderColor = 'var(--border-base)'}
                      />
                    </div>
                  )}

                  <Switch
                    checked={enableTracking}
                    onChange={() => setEnableTracking(v => !v)}
                    label="Let me see when it's opened"
                    description="Adds this note to your delivery tracker below — the server only learns a status, never the note's content"
                  />
                  {enableTracking && (
                    <div style={{ marginBottom: '8px', paddingLeft: '50px' }}>
                      <input
                        type="text"
                        value={trackingTitle}
                        onChange={e => setTrackingTitle(e.target.value.slice(0, 80))}
                        placeholder='Label for your own reference, e.g. "Wifi password for Sam"'
                        style={{
                          width: '100%', maxWidth: '360px', background: 'var(--bg-input)', color: 'var(--text-primary)',
                          border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                          padding: '9px 12px', fontSize: '13.5px', fontFamily: FONT_UI,
                          transition: 'border-color 150ms ease', boxSizing: 'border-box',
                        }}
                        onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                        onBlur={e => e.target.style.borderColor = 'var(--border-base)'}
                      />
                    </div>
                  )}

                  <Switch
                    checked={viewDurationEnabled}
                    onChange={() => setViewDurationEnabled(v => !v)}
                    label="Clear it from the screen automatically"
                    description="After opening, the text disappears on its own so it isn't left visible"
                  />
                  {viewDurationEnabled && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', paddingLeft: '50px', marginBottom: '8px' }}>
                      <input
                        type="range"
                        min={MIN_VIEW_DURATION}
                        max={MAX_VIEW_DURATION}
                        step={5}
                        value={viewDurationSeconds}
                        onChange={e => setViewDurationSeconds(Number(e.target.value))}
                        style={{ flex: 1, maxWidth: '260px' }}
                      />
                      <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                        {viewDurationSeconds}s
                      </span>
                    </div>
                  )}
                </div>
              </Collapsible>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '18px' }}>
              <button
                onClick={handleCreate}
                disabled={!canSend}
                style={{
                  padding: '12px 26px',
                  background: canSend ? 'var(--accent)' : 'var(--border-base)',
                  color: '#1a1418',
                  border: 'none', borderRadius: 'var(--radius-sm)',
                  fontFamily: FONT_UI, fontWeight: 600, fontSize: '14.5px',
                  opacity: canSend ? 1 : 0.55,
                  transition: 'opacity 150ms ease', minWidth: '220px',
                  cursor: canSend ? 'pointer' : 'default',
                }}
              >
                {creating ? 'Encrypting…' : 'Create secure link'}
              </button>
            </div>

            {createError && (
              <div style={{ marginTop: '12px', padding: '10px 13px', background: 'var(--danger)15', border: '1px solid var(--danger)', borderRadius: 'var(--radius-sm)', fontSize: '13px', color: 'var(--danger)' }}>
                {createError}
              </div>
            )}
          </Card>

          {/* Share link */}
          {shareLink && (
            <Card title="Link ready" subtitle="This link contains the decryption key after the # — it is never sent to any server." borderColor="var(--accent)">
              <div style={{
                background: 'var(--bg-input)', border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-sm)', padding: '12px 14px', fontSize: '13px',
                color: 'var(--accent-strong)', wordBreak: 'break-all', marginBottom: '12px',
                fontFamily: FONT_MONO,
              }}>
                {shareLink.url}
              </div>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  onClick={copyLink}
                  style={{
                    padding: '8px 16px', background: 'transparent', border: '1px solid var(--accent)',
                    color: 'var(--accent)', borderRadius: 'var(--radius-sm)', fontFamily: FONT_UI,
                    fontSize: '13px', fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  {linkCopied ? 'Copied' : 'Copy link'}
                </button>
                <Badge tone={shareLink.mode === 'burn' ? 'warning' : 'accent'}>
                  {shareLink.mode === 'burn' ? 'Burns after first read' : `Expires ${shareLink.expiresAt?.slice(0, 16)} UTC`}
                </Badge>
                {shareLink.hasPassphrase && (
                  <Badge tone="accent">Passphrase required</Badge>
                )}
                {shareLink.trackingToken && (
                  <Badge tone="success">Tracking enabled</Badge>
                )}
              </div>
              {shareLink.hasPassphrase && (
                <div style={{ marginTop: '10px', fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.55 }}>
                  Remember to share the passphrase with your recipient separately — it is not in this link.
                </div>
              )}
              {shareLink.trackingToken && (
                <div style={{ marginTop: '10px', fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.55 }}>
                  Delivery status for this note now appears in the tracking dashboard below — the tracking
                  token stays in this browser's storage and was never sent to the server, only its hash was.
                </div>
              )}
            </Card>
          )}

          {/* Delivery tracking dashboard */}
          {trackedNotes.length > 0 && (
            <Card
              title="Delivery tracking"
              subtitle="Status checked locally by your browser. The server only ever sees a hash of each tracking token — never the raw token, never what a note contained."
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                  {trackedNotes.length} tracked note{trackedNotes.length === 1 ? '' : 's'} (this browser only)
                  {trackedNotes.length > 5 && ' — consider clearing old entries below'}
                </span>
                <button
                  onClick={checkAllTrackingStatuses}
                  disabled={trackingLoading}
                  style={{
                    padding: '5px 13px', background: 'transparent', border: '1px solid var(--border-base)',
                    borderRadius: 'var(--radius-sm)', color: 'var(--accent)', fontFamily: FONT_UI,
                    fontSize: '12px', fontWeight: 600, opacity: trackingLoading ? 0.5 : 1, cursor: 'pointer',
                  }}
                >
                  {trackingLoading ? 'Checking…' : 'Refresh status'}
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {trackedNotes.map(entry => {
                  const status = trackingStatuses[entry.noteId];
                  const toneMap = {
                    active: 'warning', viewed: 'success', expired: 'dim',
                    consuming: 'accent', frozen: 'accent', destroyed: 'dim', unknown: 'dim',
                  };
                  const labelMap = {
                    active: 'Unread',
                    viewed: status?.viewedAt ? `Viewed at ${status.viewedAt.slice(0, 16)} UTC` : 'Viewed',
                    expired: 'Expired unread',
                    consuming: 'Being read right now…',
                    frozen: 'Frozen by you',
                    destroyed: 'Destroyed by you',
                    unknown: 'Status unavailable',
                  };
                  const statusKey = status?.status || 'unknown';
                  const tone = toneMap[statusKey] || 'dim';
                  const label = status ? (labelMap[statusKey] || statusKey) : 'Checking…';
                  const isManaging = managingNoteId === entry.noteId;
                  const canManage = statusKey === 'active' || statusKey === 'frozen';
                  const isExpireMode = entry.mode === 'expire';
                  const isFinal = statusKey === 'viewed' || statusKey === 'expired' || statusKey === 'destroyed';

                  return (
                    <div
                      key={entry.noteId}
                      style={{
                        padding: '10px 0', borderBottom: '1px solid var(--border-dim)', fontSize: '13px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
                        <div style={{ minWidth: 0 }}>
                          <div style={{ color: 'var(--text-primary)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {entry.title || 'Untitled note'}
                          </div>
                          <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>
                            {entry.noteId.slice(0, 10)} · {entry.mode} · {entry.createdAt?.slice(0, 16)} UTC
                            {status?.expiresAt && ` · expires ${status.expiresAt.slice(0, 16)} UTC`}
                          </div>
                        </div>
                        <Badge tone={tone}>{label}</Badge>
                      </div>

                      {canManage && (
                        <div style={{ display: 'flex', gap: '6px', marginTop: '8px', flexWrap: 'wrap' }}>
                          <button
                            onClick={() => handleToggleFreeze(entry)}
                            disabled={isManaging}
                            style={{
                              padding: '4px 10px', background: 'transparent',
                              border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                              color: 'var(--text-secondary)', fontFamily: FONT_UI, fontSize: '12px',
                              fontWeight: 600, opacity: isManaging ? 0.5 : 1, cursor: 'pointer',
                            }}
                          >
                            {statusKey === 'frozen' ? 'Unfreeze' : 'Freeze'}
                          </button>

                          {isExpireMode && (
                            <button
                              onClick={() => setExtendInputFor(extendInputFor === entry.noteId ? null : entry.noteId)}
                              disabled={isManaging}
                              style={{
                                padding: '4px 10px', background: 'transparent',
                                border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                                color: 'var(--text-secondary)', fontFamily: FONT_UI, fontSize: '12px',
                                fontWeight: 600, opacity: isManaging ? 0.5 : 1, cursor: 'pointer',
                              }}
                            >
                              Extend
                            </button>
                          )}

                          <button
                            onClick={() => handleDestroy(entry)}
                            disabled={isManaging}
                            style={{
                              padding: '4px 10px', background: 'transparent',
                              border: '1px solid var(--danger)', borderRadius: 'var(--radius-sm)',
                              color: 'var(--danger)', fontFamily: FONT_UI, fontSize: '12px',
                              fontWeight: 600, opacity: isManaging ? 0.5 : 1, cursor: 'pointer',
                            }}
                          >
                            Destroy now
                          </button>
                        </div>
                      )}

                      {extendInputFor === entry.noteId && (
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '8px' }}>
                          <select
                            value={extendHours}
                            onChange={e => setExtendHours(Number(e.target.value))}
                            style={{
                              background: 'var(--bg-input)', color: 'var(--text-primary)',
                              border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                              padding: '5px 8px', fontSize: '12px', fontFamily: FONT_UI,
                            }}
                          >
                            <option value={1}>+1 hour</option>
                            <option value={6}>+6 hours</option>
                            <option value={24}>+1 day</option>
                            <option value={72}>+3 days</option>
                            <option value={168}>+7 days</option>
                          </select>
                          <button
                            onClick={() => handleExtend(entry)}
                            disabled={isManaging}
                            style={{
                              padding: '5px 12px', background: 'var(--accent)', color: '#1a1418',
                              border: 'none', borderRadius: 'var(--radius-sm)', fontFamily: FONT_UI,
                              fontSize: '12px', fontWeight: 600, opacity: isManaging ? 0.5 : 1, cursor: 'pointer',
                            }}
                          >
                            Confirm
                          </button>
                        </div>
                      )}

                      {isFinal && (
                        <div style={{ marginTop: '6px' }}>
                          <button
                            onClick={() => removeTrackedEntry(entry.noteId)}
                            style={{
                              padding: '3px 9px', background: 'transparent', border: 'none',
                              color: 'var(--text-muted)', fontFamily: FONT_UI, fontSize: '12px',
                              textDecoration: 'underline', cursor: 'pointer',
                            }}
                          >
                            Remove from this list
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '12px', lineHeight: 1.55 }}>
                This list lives only in this browser's local storage. Clearing site data or switching
                browsers/devices loses it — there is no account or server-side record tying notes back to you.
              </div>
            </Card>
          )}

          <Collapsible
            open={showActivityLog}
            onToggle={() => setShowActivityLog(v => !v)}
            label="Show activity log"
            openLabel="Hide activity log"
          >
            <Card title="Activity log" subtitle="Metadata only — no ciphertext, no keys, no plaintext ever recorded here.">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Last 20 operations</span>
                <button
                  onClick={fetchAuditLog}
                  disabled={logLoading}
                  style={{
                    padding: '5px 13px', background: 'transparent', border: '1px solid var(--border-base)',
                    borderRadius: 'var(--radius-sm)', color: 'var(--accent)', fontFamily: FONT_UI,
                    fontSize: '12px', fontWeight: 600, opacity: logLoading ? 0.5 : 1, cursor: 'pointer',
                  }}
                >
                  {logLoading ? 'Loading…' : 'Refresh'}
                </button>
              </div>
              {auditLog.length === 0 ? (
                <div style={{ fontSize: '13px', color: 'var(--text-muted)', padding: '12px 0' }}>
                  No activity yet. Create a note to populate the log.
                </div>
              ) : (
                <>
                  <div style={{
                    display: 'grid', gridTemplateColumns: '36px 84px 1fr 110px 64px', gap: '8px',
                    padding: '0 0 8px', borderBottom: '1px solid var(--border-base)',
                    fontSize: '11.5px', color: 'var(--text-muted)', fontWeight: 600,
                  }}>
                    <span>#</span><span>Time</span><span>Note ID</span><span>Action</span><span style={{ textAlign: 'right' }}>Size</span>
                  </div>
                  {auditLog.map((entry, i) => <AuditRow key={entry.id + entry.timestamp} entry={entry} index={i} />)}
                </>
              )}
              <div style={{ marginTop: '14px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>
                  Recent activity
                </div>
                <div ref={termRef} style={{
                  background: 'var(--bg-panel)', border: '1px solid var(--border-dim)',
                  borderRadius: 'var(--radius-md)', padding: '12px 15px', height: '120px',
                  overflowY: 'auto', fontSize: '12.5px', lineHeight: 1.8, fontFamily: FONT_UI,
                }}>
                  {termLines.map((line, i) => (
                    <div key={i}>
                      <span style={{ color: 'var(--text-muted)', marginRight: '10px' }}>{line.t.slice(11, 19)}</span>
                      <span style={{ color: `var(--${line.tone === 'dim' ? 'text-secondary' : line.tone})` }}>{line.msg}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          </Collapsible>

          <Collapsible
            open={showHowItWorks}
            onToggle={() => setShowHowItWorks(v => !v)}
            label="How this stays private"
            openLabel="Hide details"
          >
            <Card>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '14px', marginBottom: '18px' }}>
                <Field label="Model" value="Zero-knowledge, end-to-end encrypted" color="var(--accent)" />
                <Field label="Encryption" value="AES-256-GCM (client-side)" />
                <Field label="Key handling" value="Never transmitted to the server" color="var(--success)" />
                <Field label="Status" value={serverStatus === 'active' ? 'Connected' : serverStatus} color={serverStatus === 'active' ? 'var(--success)' : 'var(--warning)'} />
                <Field label="Environment" value={serverInfo?.environment || '—'} />
                <Field label="Uptime" value={uptimeStr} />
                <Field label="Storage used" value={serverInfo ? `${serverInfo.vault_used} / ${serverInfo.vault_capacity}` : '—'} color="var(--accent)" />
                <Field label="Version" value={serverInfo?.version || '—'} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                <div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '2px' }}>Keys live in the link, not the server</div>
                  The decryption key sits after the # in the link. Browsers never send that part of a URL to a server.
                </div>
                <div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '2px' }}>The server only sees ciphertext</div>
                  It stores opaque bytes it cannot interpret. There's no private key on the server to compromise.
                </div>
                <div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '2px' }}>Burn after read</div>
                  One-time notes are deleted the instant they're served — even the server operator can't re-read them.
                </div>
                <div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '2px' }}>Optional passphrase</div>
                  A second factor the server never sees: 100,000 PBKDF2 iterations derive the key from a passphrase known only to sender and recipient.
                </div>
                <div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '2px' }}>Optional delivery tracking</div>
                  The server stores only a hash of a sender-generated token — never the token, never your identity, never note content. It can confirm a note was viewed, nothing more.
                </div>
              </div>
            </Card>
          </Collapsible>
      </div>
    </Shell>
  );
}

// ─── Layout shell with header + theme toggle ──────────────────────────────────
function Shell({ children, theme, onToggleTheme, serverStatus, minimal }) {
  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-root)', padding: '28px 20px 60px', fontFamily: FONT_UI }}>
      <div style={{ maxWidth: '960px', margin: '0 auto' }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          borderBottom: '1px solid var(--border-base)', paddingBottom: '16px', marginBottom: '26px',
        }}>
          <div>
            <a href="/" style={{ textDecoration: 'none' }}>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
                Zero-Knowledge Note <span style={{ color: 'var(--accent)' }}>Vault</span>
              </div>
            </a>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              AES-256-GCM, encrypted in your browser — the server never holds a decryption key
            </div>
          </div>
          <div style={{ display: 'flex', gap: '14px', alignItems: 'center' }}>
            {!minimal && serverStatus && (
              <>
                {serverStatus === 'connecting' && <Badge tone="warning">Connecting</Badge>}
                {serverStatus === 'active' && <Badge tone="success">Connected</Badge>}
                {serverStatus === 'error' && <Badge tone="danger">Offline</Badge>}
              </>
            )}
            <ThemeToggle theme={theme} onToggle={onToggleTheme} />
          </div>
        </div>

        {children}

        <ContactFooter />

        <div style={{ marginTop: '24px', textAlign: 'center', fontSize: '12px', color: 'var(--text-muted)' }}>
          Zero-Knowledge Note Vault v4.2.0 — FastAPI + React — AES-256-GCM, keys never leave the browser
        </div>
      </div>
    </div>
  );
}

// ─── Inline icon set (no external icon library — keeps the app dependency-free) ──
function IconPhone() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z" />
    </svg>
  );
}
function IconMail() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
      <path d="m22 6-10 7L2 6" />
    </svg>
  );
}
function IconLinkedIn() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M20.45 20.45h-3.55v-5.57c0-1.33-.03-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 2.94v5.67H9.36V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.38-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.06 2.06 0 1 1 0-4.12 2.06 2.06 0 0 1 0 4.12zM7.12 20.45H3.56V9h3.56v11.45z" />
    </svg>
  );
}
function IconGitHub() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.09 3.29 9.4 7.86 10.93.57.1.78-.25.78-.55 0-.27-.01-1.16-.02-2.1-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.74.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.04 0 0 .97-.31 3.18 1.18a11.07 11.07 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.64 1.58.24 2.75.12 3.04.74.81 1.19 1.83 1.19 3.09 0 4.41-2.7 5.39-5.26 5.67.41.36.78 1.06.78 2.15 0 1.55-.01 2.8-.01 3.18 0 .31.21.66.79.55A10.51 10.51 0 0 0 23.5 12c0-6.35-5.15-11.5-11.5-11.5z" />
    </svg>
  );
}
function IconMedium() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M2.5 6.5c0-.5-.02-.9-.4-1.32L.4 3.3V3h6.36l4.92 10.78L16.04 3h6.06v.3l-1.45 1.4a.43.43 0 0 0-.16.41v10.36c0 .1.04.32.16.41l1.42 1.4v.3h-7.13v-.3l1.47-1.43c.14-.14.14-.18.14-.41V6.93l-4.1 10.41h-.55L7.18 6.93v6.97c-.04.3.06.6.27.82l1.91 2.32v.3H3.8v-.3l1.91-2.32a.97.97 0 0 0 .25-.82V6.5z" />
    </svg>
  );
}
function IconCode() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m16 18 6-6-6-6" />
      <path d="m8 6-6 6 6 6" />
    </svg>
  );
}

function ContactLink({ href, icon, label }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: '7px',
        padding: '7px 13px', border: '1px solid var(--border-base)',
        borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)',
        fontSize: '12.5px', fontWeight: 500, textDecoration: 'none',
        fontFamily: FONT_UI,
        transition: 'border-color 150ms ease, color 150ms ease',
        whiteSpace: 'nowrap',
      }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-base)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
    >
      {icon}
      {label}
    </a>
  );
}

function ContactFooter() {
  return (
    <div style={{
      marginTop: '32px', paddingTop: '22px', borderTop: '1px solid var(--border-base)',
    }}>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '12px', textAlign: 'center' }}>
        Contact the developer
      </div>
      <div style={{ fontSize: '13px', color: 'var(--text-secondary)', textAlign: 'center', marginBottom: '14px' }}>
        Built by <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Aditya Kumar</span>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '8px' }}>
        <ContactLink href="tel:+917079487671" icon={<IconPhone />} label="+91 70794 87671" />
        <ContactLink href="mailto:adii.utsav@gmail.com" icon={<IconMail />} label="adii.utsav@gmail.com" />
        <ContactLink href="https://www.linkedin.com/in/aditya-kumar-3241b6286/" icon={<IconLinkedIn />} label="LinkedIn" />
        <ContactLink href="https://github.com/Rememberful" icon={<IconGitHub />} label="GitHub" />
        <ContactLink href="https://medium.com/@adii.utsav" icon={<IconMedium />} label="Medium" />
      </div>
      <div style={{ textAlign: 'center', marginTop: '14px' }}>
        <ContactLink href="https://github.com/Rememberful/E2EE-Net.git" icon={<IconCode />} label="Contribute to this project" />
      </div>
    </div>
  );
}

function RadioCard({ active, onClick, title, subtitle }) {
  return (
    <button
      onClick={onClick}
      style={{
        flex: 1, textAlign: 'left', padding: '14px 16px', cursor: 'pointer',
        background: active ? 'var(--accent-soft)' : 'var(--bg-input)',
        border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border-base)'}`,
        borderRadius: 'var(--radius-md)', fontFamily: FONT_UI,
        transition: 'all 150ms ease', display: 'flex', alignItems: 'flex-start', gap: '10px',
      }}
    >
      <span style={{
        marginTop: '2px', width: '16px', height: '16px', borderRadius: '50%', flexShrink: 0,
        border: `2px solid ${active ? 'var(--accent)' : 'var(--border-base)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        {active && <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--accent)' }} />}
      </span>
      <span>
        <div style={{ fontSize: '14px', fontWeight: 600, color: active ? 'var(--accent)' : 'var(--text-primary)' }}>{title}</div>
        <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '2px', lineHeight: 1.4 }}>{subtitle}</div>
      </span>
    </button>
  );
}

function Switch({ checked, onChange, label, description }) {
  return (
    <label style={{
      display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer',
      padding: '10px 0', fontFamily: FONT_UI,
    }}>
      <span
        onClick={onChange}
        style={{
          position: 'relative', width: '38px', height: '22px', borderRadius: '999px', flexShrink: 0, marginTop: '1px',
          background: checked ? 'var(--accent)' : 'var(--border-base)',
          transition: 'background 150ms ease',
        }}
      >
        <span style={{
          position: 'absolute', top: '2px', left: checked ? '18px' : '2px',
          width: '18px', height: '18px', borderRadius: '50%', background: '#fff',
          transition: 'left 150ms ease', boxShadow: '0 1px 2px rgba(0,0,0,0.25)',
        }} />
      </span>
      <span>
        <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)' }}>{label}</div>
        {description && <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px', lineHeight: 1.45 }}>{description}</div>}
      </span>
    </label>
  );
}

function Collapsible({ open, onToggle, label, openLabel, children }) {
  return (
    <div>
      <button
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: '6px', background: 'transparent',
          border: 'none', color: 'var(--accent)', fontFamily: FONT_UI, fontSize: '13px',
          fontWeight: 600, cursor: 'pointer', padding: '6px 0',
        }}
      >
        <span style={{
          display: 'inline-block', transition: 'transform 150ms ease',
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)', fontSize: '11px',
        }}>▶</span>
        {open ? (openLabel || label) : label}
      </button>
      {open && <div style={{ marginTop: '8px' }}>{children}</div>}
    </div>
  );
}

function ModeButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '7px 14px',
        background: active ? 'var(--accent-soft)' : 'transparent',
        border: `1px solid ${active ? 'var(--accent)' : 'var(--border-base)'}`,
        color: active ? 'var(--accent)' : 'var(--text-secondary)',
        borderRadius: 'var(--radius-sm)',
        fontFamily: FONT_UI, fontSize: '12.5px', fontWeight: 600,
        transition: 'all 150ms ease', cursor: 'pointer',
      }}
    >
      {children}
    </button>
  );
}