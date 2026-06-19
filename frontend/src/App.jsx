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
      border: `1px solid ${c}`, color: c, fontSize: '10.5px', fontWeight: 600,
      padding: '3px 9px', borderRadius: 'var(--radius-sm)', letterSpacing: '0.4px',
      whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  );
}

function Field({ label, value, color }) {
  return (
    <div style={{ marginBottom: '11px' }}>
      <div style={{ fontSize: '10.5px', color: 'var(--text-secondary)', letterSpacing: '0.4px', marginBottom: '3px', fontWeight: 500 }}>
        {label}
      </div>
      <div className="mono-value" style={{ color: color || 'var(--text-primary)', fontSize: '13px', wordBreak: 'break-all' }}>
        {value || '\u2014'}
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
      ...style,
    }}>
      {title && (
        <div style={{ marginBottom: '17px' }}>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--accent)', letterSpacing: '0.2px' }}>
            {title}
          </div>
          {subtitle && (
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '3px', lineHeight: 1.55 }}>
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
        width: '52px',
        height: '28px',
        borderRadius: '999px',
        border: '1px solid var(--border-base)',
        background: 'var(--bg-input)',
        cursor: 'pointer',
        transition: 'background var(--transition)',
      }}
    >
      <span style={{
        position: 'absolute',
        top: '2px',
        left: isDark ? '26px' : '2px',
        width: '22px',
        height: '22px',
        borderRadius: '50%',
        background: 'var(--accent)',
        transition: 'left var(--transition)',
      }} />
    </button>
  );
}

function AuditRow({ entry, index }) {
  const toneMap = {
    CREATE: 'accent', READ: 'success', READ_AND_BURN: 'warning', READ_MISS: 'danger',
  };
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '44px 84px 1fr 110px 64px',
      gap: '8px', padding: '8px 0', borderBottom: '1px solid var(--border-dim)',
      fontSize: '11.5px', alignItems: 'center',
    }}>
      <span style={{ color: 'var(--text-muted)' }}>{String(index + 1).padStart(3, '0')}</span>
      <span style={{ color: 'var(--text-secondary)' }}>{entry.timestamp?.slice(11, 19)}</span>
      <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.id?.slice(0, 10)}
      </span>
      <span style={{ color: `var(--${toneMap[entry.action] === 'danger' ? 'danger' : toneMap[entry.action] === 'warning' ? 'warning' : toneMap[entry.action] === 'success' ? 'success' : 'accent'})`, fontWeight: 600 }}>
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
  const [clientId] = useState(() => 'cli_' + Math.random().toString(36).slice(2, 10));

  const [creating, setCreating] = useState(false);
  const [shareLink, setShareLink] = useState(null);
  const [createError, setCreateError] = useState(null);
  const [linkCopied, setLinkCopied] = useState(false);

  // Audit log
  const [auditLog, setAuditLog] = useState([]);
  const [logLoading, setLogLoading] = useState(false);

  // Read pane
  const [readState, setReadState] = useState('idle'); // idle | loading | ready | error | burned
  const [readError, setReadError] = useState(null);
  const [decrypted, setDecrypted] = useState(null);

  // System log
  const [termLines, setTermLines] = useState([
    { t: ts(), msg: 'Zero-knowledge vault terminal initialised.', tone: 'dim' },
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
        log(`Connected to vault. Architecture: ${data.architecture}`, 'success');
      } catch {
        setServerStatus('error');
        log('Cannot reach backend. Is uvicorn running?', 'danger');
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
      log('Failed to fetch audit log.', 'danger');
    } finally {
      setLogLoading(false);
    }
  }, [log]);

  // ── Create note flow ───────────────────────────────────────────────────
  const handleCreate = async () => {
    if (!message.trim()) return;
    setCreating(true);
    setCreateError(null);
    setShareLink(null);
    setLinkCopied(false);

    try {
      log('Generating ephemeral AES-256 key in-browser...', 'dim');
      const key = await generateKey();

      log('Encrypting note locally (AES-256-GCM)...', 'dim');
      const { ciphertext, iv } = await encryptText(key, message);

      const rawKey = await exportKeyRaw(key);
      log('Key exported to memory only \u2014 will be embedded in URL fragment, never sent to server.', 'accent');

      const body = {
        ciphertext,
        iv,
        mode,
        ttl_seconds: mode === 'expire' ? ttlHours * 3600 : null,
        client_id: clientId,
      };

      log('Transmitting ciphertext to vault (key withheld)...', 'dim');
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
      const link = `${window.location.origin}/view/${result.id}#${rawKey}`;
      setShareLink({ url: link, mode: result.mode, expiresAt: result.expires_at });

      log(`Note stored as ciphertext. id=${result.id.slice(0, 10)}\u2026 mode=${result.mode}`, 'success');
      log('Server received zero key material. It cannot decrypt this note.', 'success');

      setMessage('');
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
      log('Clipboard write failed \u2014 copy the link manually.', 'warning');
    }
  };

  // ── Read note flow (runs when route.view === 'read') ──────────────────
  useEffect(() => {
    if (route.view !== 'read') return;
    (async () => {
      setReadState('loading');
      setReadError(null);

      if (!route.key) {
        setReadState('error');
        setReadError('No decryption key present in the link. The key lives after the # and never reaches the server.');
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/api/notes/${route.noteId}`);
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
        const key = await importKeyRaw(route.key);
        const plaintext = await decryptText(key, data.ciphertext, data.iv);

        setDecrypted({ text: plaintext, mode: data.mode });
        setReadState(data.mode === 'burn' ? 'burned' : 'ready');
      } catch (err) {
        setReadState('error');
        setReadError('Decryption failed. The key may be incorrect or the ciphertext corrupted.');
      }
    })();
  }, [route]);

  // ── Render: READ VIEW ──────────────────────────────────────────────────
  if (route.view === 'read') {
    return (
      <Shell theme={theme} onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} minimal>
        <div style={{ maxWidth: '620px', margin: '60px auto', padding: '0 20px' }}>
          <Card
            title="SECURE NOTE"
            subtitle="Decryption happens in this browser only. The server never had your key."
            borderColor={readState === 'error' ? 'var(--danger)' : 'var(--border-base)'}
          >
            {readState === 'loading' && (
              <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>Retrieving and decrypting\u2026</div>
            )}

            {readState === 'error' && (
              <div style={{ color: 'var(--danger)', fontSize: '13px', lineHeight: 1.6 }}>{readError}</div>
            )}

            {(readState === 'ready' || readState === 'burned') && decrypted && (
              <>
                {readState === 'burned' && (
                  <div style={{ marginBottom: '14px' }}>
                    <Badge tone="warning">BURNED AFTER THIS READ \u2014 it no longer exists on the server</Badge>
                  </div>
                )}
                <div style={{
                  background: 'var(--bg-input)', border: '1px solid var(--border-dim)',
                  borderRadius: 'var(--radius-sm)', padding: '16px 18px', fontSize: '14px',
                  color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  lineHeight: 1.7,
                }}>
                  {decrypted.text}
                </div>
                <div style={{ marginTop: '14px' }}>
                  <a href="/" style={{ fontSize: '12px', color: 'var(--accent)' }}>Create a new secure note &rarr;</a>
                </div>
              </>
            )}
          </Card>
        </div>
      </Shell>
    );
  }

  // ── Render: CREATE VIEW ────────────────────────────────────────────────
  const canSend = !!message.trim() && !creating;
  const uptimeStr = serverInfo ? `${Math.floor(serverInfo.uptime_seconds / 60)}m ${serverInfo.uptime_seconds % 60}s` : '\u2014';

  return (
    <Shell theme={theme} onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} serverStatus={serverStatus}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: '20px', alignItems: 'start' }}>

        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

          {/* Compose */}
          <Card title="COMPOSE SECURE NOTE" subtitle="Encrypted with AES-256-GCM in your browser before anything is sent.">
            <textarea
              rows={5}
              value={message}
              onChange={e => setMessage(e.target.value)}
              placeholder="Type your confidential note..."
              style={{
                width: '100%', background: 'var(--bg-input)', color: 'var(--text-primary)',
                border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                padding: '12px 14px', fontSize: '13.5px', fontFamily: 'inherit',
                resize: 'vertical', lineHeight: 1.65, transition: 'border-color var(--transition)',
              }}
              onFocus={e => e.target.style.borderColor = 'var(--accent)'}
              onBlur={e => e.target.style.borderColor = 'var(--border-base)'}
            />

            <div style={{ display: 'flex', gap: '18px', marginTop: '14px', flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{ display: 'flex', gap: '8px' }}>
                <ModeButton active={mode === 'burn'} onClick={() => setMode('burn')}>Burn after read</ModeButton>
                <ModeButton active={mode === 'expire'} onClick={() => setMode('expire')}>Expire after time</ModeButton>
              </div>
              {mode === 'expire' && (
                <select
                  value={ttlHours}
                  onChange={e => setTtlHours(Number(e.target.value))}
                  style={{
                    background: 'var(--bg-input)', color: 'var(--text-primary)',
                    border: '1px solid var(--border-base)', borderRadius: 'var(--radius-sm)',
                    padding: '6px 10px', fontSize: '12px', fontFamily: 'inherit',
                  }}
                >
                  <option value={1}>1 hour</option>
                  <option value={6}>6 hours</option>
                  <option value={24}>24 hours</option>
                  <option value={72}>3 days</option>
                  <option value={168}>7 days</option>
                </select>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', gap: '10px' }}>
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
                {message.length} characters
              </span>
              <button
                onClick={handleCreate}
                disabled={!canSend}
                style={{
                  padding: '10px 22px',
                  background: canSend ? 'var(--accent)' : 'var(--border-base)',
                  color: '#1a1418',
                  border: 'none', borderRadius: 'var(--radius-sm)',
                  fontFamily: 'inherit', fontWeight: 600, fontSize: '12.5px',
                  letterSpacing: '0.3px', opacity: canSend ? 1 : 0.55,
                  transition: 'opacity var(--transition)', minWidth: '210px',
                }}
              >
                {creating ? 'Encrypting...' : 'Encrypt & Generate Link'}
              </button>
            </div>

            {createError && (
              <div style={{ marginTop: '12px', padding: '10px 13px', background: 'var(--danger)15', border: '1px solid var(--danger)', borderRadius: 'var(--radius-sm)', fontSize: '12.5px', color: 'var(--danger)' }}>
                {createError}
              </div>
            )}
          </Card>

          {/* Share link */}
          {shareLink && (
            <Card title="SHARE LINK GENERATED" subtitle="This link contains the decryption key after the # — it is never sent to any server." borderColor="var(--accent)">
              <div style={{
                background: 'var(--bg-input)', border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-sm)', padding: '12px 14px', fontSize: '12px',
                color: 'var(--accent-strong)', wordBreak: 'break-all', marginBottom: '12px',
              }}>
                {shareLink.url}
              </div>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  onClick={copyLink}
                  style={{
                    padding: '8px 16px', background: 'transparent', border: '1px solid var(--accent)',
                    color: 'var(--accent)', borderRadius: 'var(--radius-sm)', fontFamily: 'inherit',
                    fontSize: '12px', fontWeight: 600,
                  }}
                >
                  {linkCopied ? 'Copied' : 'Copy link'}
                </button>
                <Badge tone={shareLink.mode === 'burn' ? 'warning' : 'accent'}>
                  {shareLink.mode === 'burn' ? 'Burns after first read' : `Expires ${shareLink.expiresAt?.slice(0, 16)} UTC`}
                </Badge>
              </div>
            </Card>
          )}

          {/* Audit log */}
          <Card title="VAULT AUDIT LOG" subtitle="Metadata only \u2014 no ciphertext, no keys, no plaintext ever recorded here.">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '11px' }}>
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Last 20 vault operations</span>
              <button
                onClick={fetchAuditLog}
                disabled={logLoading}
                style={{
                  padding: '4px 13px', background: 'transparent', border: '1px solid var(--border-base)',
                  borderRadius: 'var(--radius-sm)', color: 'var(--accent)', fontFamily: 'inherit',
                  fontSize: '10.5px', fontWeight: 600, opacity: logLoading ? 0.5 : 1,
                }}
              >
                {logLoading ? 'Loading...' : 'Refresh'}
              </button>
            </div>
            {auditLog.length === 0 ? (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '12px 0' }}>
                No vault activity yet. Create a note to populate the log.
              </div>
            ) : (
              <>
                <div style={{
                  display: 'grid', gridTemplateColumns: '44px 84px 1fr 110px 64px', gap: '8px',
                  padding: '0 0 7px', borderBottom: '1px solid var(--border-base)',
                  fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.3px', fontWeight: 600,
                }}>
                  <span>#</span><span>TIME</span><span>NOTE ID</span><span>ACTION</span><span style={{ textAlign: 'right' }}>SIZE</span>
                </div>
                {auditLog.map((entry, i) => <AuditRow key={entry.id + entry.timestamp} entry={entry} index={i} />)}
              </>
            )}
          </Card>
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <Card title="VAULT ARCHITECTURE">
            <Field label="MODEL" value="Zero-Knowledge Blind Vault" color="var(--accent)" />
            <Field label="ENCRYPTION" value="AES-256-GCM (client-side)" />
            <Field label="KEY HANDLING" value="Never transmitted to server" color="var(--success)" />
            <Field label="STATUS" value={serverStatus === 'active' ? 'CONNECTED' : serverStatus.toUpperCase()} color={serverStatus === 'active' ? 'var(--success)' : 'var(--warning)'} />
          </Card>

          <Card title="SERVER METRICS">
            <Field label="ENVIRONMENT" value={serverInfo?.environment?.toUpperCase() || '\u2014'} />
            <Field label="UPTIME" value={uptimeStr} />
            <Field label="VAULT USED" value={serverInfo ? `${serverInfo.vault_used} / ${serverInfo.vault_capacity}` : '\u2014'} color="var(--accent)" />
            <Field label="VERSION" value={serverInfo?.version || '\u2014'} />
          </Card>

          <Card title="WHY THIS IS ZERO-KNOWLEDGE">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '11px', fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.65 }}>
              <div>
                <div style={{ color: 'var(--accent)', fontWeight: 600, marginBottom: '2px' }}>URL fragment keys</div>
                The decryption key sits after the # in the link. Browsers never send the fragment to a server on request.
              </div>
              <div>
                <div style={{ color: 'var(--accent)', fontWeight: 600, marginBottom: '2px' }}>Server sees ciphertext only</div>
                The vault stores opaque bytes it cannot interpret. There is no private key on the server to compromise.
              </div>
              <div>
                <div style={{ color: 'var(--accent)', fontWeight: 600, marginBottom: '2px' }}>Burn after read</div>
                One-time notes are deleted the instant they're served \u2014 even the server operator cannot re-read them.
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* System log */}
      <div style={{ marginTop: '24px' }}>
        <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', letterSpacing: '0.4px', marginBottom: '7px', fontWeight: 600 }}>
          SYSTEM LOG
        </div>
        <div ref={termRef} style={{
          background: 'var(--bg-panel)', border: '1px solid var(--border-dim)',
          borderRadius: 'var(--radius-md)', padding: '13px 15px', height: '130px',
          overflowY: 'auto', fontSize: '11.5px', lineHeight: 1.75,
        }}>
          {termLines.map((line, i) => (
            <div key={i}>
              <span style={{ color: 'var(--text-muted)', marginRight: '10px' }}>{line.t.slice(11, 19)}</span>
              <span style={{ color: `var(--${line.tone === 'dim' ? 'text-secondary' : line.tone})` }}>{line.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </Shell>
  );
}

// ─── Layout shell with header + theme toggle ──────────────────────────────────
function Shell({ children, theme, onToggleTheme, serverStatus, minimal }) {
  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-root)', padding: '28px 20px 60px' }}>
      <div style={{ maxWidth: '960px', margin: '0 auto' }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          borderBottom: '1px solid var(--border-base)', paddingBottom: '16px', marginBottom: '26px',
        }}>
          <div>
            <a href="/" style={{ textDecoration: 'none' }}>
              <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.2px' }}>
                Zero-Knowledge <span style={{ color: 'var(--accent)' }}>Note Vault</span>
              </div>
            </a>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              AES-256-GCM, client-side only \u2014 the server never holds a decryption key
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

        <div style={{ marginTop: '24px', textAlign: 'center', fontSize: '10.5px', color: 'var(--text-muted)' }}>
          Zero-Knowledge Note Vault v3.0.0 \u2014 FastAPI + React \u2014 AES-256-GCM, keys never leave the browser
        </div>
      </div>
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
        fontFamily: 'inherit', fontSize: '11.5px', fontWeight: 600,
        transition: 'all var(--transition)',
      }}
    >
      {children}
    </button>
  );
}