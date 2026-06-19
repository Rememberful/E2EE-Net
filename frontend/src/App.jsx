import React, { useState, useEffect, useRef, useCallback } from 'react';
import forge from 'node-forge';

// ─── Config ────────────────────────────────────────────────────────────────────
// In dev, Vite proxies /api → backend. In production, use the env var.
const API_BASE =
  import.meta.env.VITE_API_URL !== undefined
    ? import.meta.env.VITE_API_URL
    : '';   // empty string = same-origin proxy in dev

// ─── Utility helpers ───────────────────────────────────────────────────────────
const ts = () => new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

const truncate = (str, n = 64) =>
  str && str.length > n ? str.slice(0, n) + '…' : str;

function classNames(...cls) {
  return cls.filter(Boolean).join(' ');
}

// ─── Sub-components ───────────────────────────────────────────────────────────

/** Blinking cursor for terminal feel */
function Cursor() {
  return <span style={{ animation: 'blink 1s step-end infinite', color: 'var(--green)' }}>█</span>;
}

/** Coloured status pill */
function Badge({ color, children }) {
  const colorMap = {
    green:  { border: 'var(--green)',  color: 'var(--green)'  },
    cyan:   { border: 'var(--cyan)',   color: 'var(--cyan)'   },
    amber:  { border: 'var(--amber)',  color: 'var(--amber)'  },
    red:    { border: 'var(--red)',    color: 'var(--red)'    },
    purple: { border: 'var(--purple)', color: 'var(--purple)' },
    dim:    { border: 'var(--border-base)', color: 'var(--text-secondary)' },
  };
  const c = colorMap[color] || colorMap.dim;
  return (
    <span style={{
      border: `1px solid ${c.border}`,
      color: c.color,
      fontSize: '10px',
      fontWeight: 600,
      padding: '2px 8px',
      borderRadius: 'var(--radius-sm)',
      letterSpacing: '0.8px',
      whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  );
}

/** A labelled field inside a card */
function Field({ label, value, color, mono = true }) {
  return (
    <div style={{ marginBottom: '10px' }}>
      <div style={{ fontSize: '10px', color: 'var(--text-secondary)', letterSpacing: '0.8px', marginBottom: '3px' }}>
        {label}
      </div>
      <div style={{
        fontFamily: mono ? 'var(--font-mono)' : 'var(--font-sans)',
        color: color || 'var(--text-primary)',
        fontSize: '12px',
        wordBreak: 'break-all',
      }}>
        {value || '—'}
      </div>
    </div>
  );
}

/** Scrollable hex-dump style block */
function HexBlock({ label, icon, value }) {
  return (
    <div style={{ marginBottom: '14px' }}>
      <div style={{ fontSize: '10px', color: 'var(--text-secondary)', letterSpacing: '0.8px', marginBottom: '4px' }}>
        {icon} {label}
      </div>
      <div style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-dim)',
        borderRadius: 'var(--radius-sm)',
        padding: '8px 10px',
        fontSize: '11px',
        color: '#f85149',
        overflowX: 'auto',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
        maxHeight: '80px',
        lineHeight: 1.5,
      }}>
        {value}
      </div>
    </div>
  );
}

/** Section card wrapper */
function Card({ title, subtitle, borderColor, children }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${borderColor || 'var(--border-base)'}`,
      borderRadius: 'var(--radius-lg)',
      padding: '20px 22px',
    }}>
      {title && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cyan)', letterSpacing: '0.5px' }}>
            {title}
          </div>
          {subtitle && (
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              {subtitle}
            </div>
          )}
        </div>
      )}
      {children}
    </div>
  );
}

/** Audit log row */
function AuditRow({ entry, index }) {
  const statusColor = entry.status === 'VERIFIED' ? 'var(--green)' : 'var(--red)';
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '80px 90px 1fr 80px 70px',
      gap: '8px',
      padding: '7px 0',
      borderBottom: '1px solid var(--border-dim)',
      fontSize: '11px',
      alignItems: 'center',
    }}>
      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
        #{String(index + 1).padStart(3, '0')}
      </span>
      <span style={{ color: 'var(--text-secondary)' }}>
        {entry.timestamp?.slice(11, 19)} UTC
      </span>
      <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.id?.slice(0, 8)}…
      </span>
      <span style={{ color: statusColor, fontWeight: 600 }}>{entry.status}</span>
      <span style={{ color: 'var(--text-muted)', textAlign: 'right' }}>
        {entry.payload_size_bytes}B
      </span>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  // Key infrastructure
  const [serverKey, setServerKey] = useState(null);       // { public_key, key_fingerprint, algorithm }
  const [serverInfo, setServerInfo] = useState(null);
  const [keyStatus, setKeyStatus] = useState('connecting'); // connecting | active | error

  // Compose pane
  const [message, setMessage] = useState('');
  const [clientId] = useState(() => 'cli_' + Math.random().toString(36).slice(2, 10));

  // Pipeline state
  const [loading, setLoading] = useState(false);
  const [intercepted, setIntercepted] = useState(null);   // raw encrypted packet
  const [serverResult, setServerResult] = useState(null);
  const [error, setError] = useState(null);

  // Audit log
  const [auditLog, setAuditLog] = useState([]);
  const [logLoading, setLogLoading] = useState(false);

  // Terminal log lines
  const [termLines, setTermLines] = useState([
    { t: ts(), msg: 'CYBER-CORE terminal initialised.', color: 'var(--text-secondary)' },
    { t: ts(), msg: 'Initiating cryptographic handshake…', color: 'var(--amber)' },
  ]);
  const termRef = useRef(null);

  const log = useCallback((msg, color = 'var(--text-secondary)') => {
    setTermLines(prev => [...prev.slice(-49), { t: ts(), msg, color }]);
  }, []);

  // ── Boot: fetch public key + server info ──────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const [keyRes, infoRes] = await Promise.all([
          fetch(`${API_BASE}/api/public-key`),
          fetch(`${API_BASE}/api/server-info`),
        ]);
        const keyData  = await keyRes.json();
        const infoData = await infoRes.json();

        setServerKey(keyData);
        setServerInfo(infoData);
        setKeyStatus('active');
        log(`RSA-2048 public key received. Fingerprint: ${keyData.key_fingerprint}`, 'var(--green)');
        log(`Server environment: ${infoData.environment} | vault capacity: ${infoData.vault_capacity}`, 'var(--text-secondary)');
      } catch (e) {
        setKeyStatus('error');
        log('Handshake failed — is the backend running?', 'var(--red)');
        setError('Cannot reach backend. Start uvicorn and refresh.');
      }
    })();
  }, [log]);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [termLines]);

  // ── Fetch audit log ──────────────────────────────────────────────────────
  const fetchAuditLog = useCallback(async () => {
    setLogLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/api/audit-log?limit=20`);
      const data = await res.json();
      setAuditLog(data.entries || []);
    } catch {
      log('Failed to fetch audit log.', 'var(--red)');
    } finally {
      setLogLoading(false);
    }
  }, [log]);

  // ── Crypto pipeline ──────────────────────────────────────────────────────
  const runPipeline = async () => {
    if (!serverKey?.public_key || !message.trim()) return;
    setLoading(true);
    setError(null);
    setIntercepted(null);
    setServerResult(null);

    log(`[TX] Composing payload (${message.length}B plaintext)…`, 'var(--amber)');

    try {
      // 1. Generate ephemeral 256-bit AES key + 96-bit IV
      const sessionKeyBytes = forge.random.getBytesSync(32);
      const ivBytes         = forge.random.getBytesSync(12);
      log('[CRYPTO] AES-256 session key generated (ephemeral).', 'var(--text-secondary)');

      // 2. AES-256-GCM encrypt the plaintext
      const cipher = forge.cipher.createCipher('AES-GCM', sessionKeyBytes);
      cipher.start({ iv: ivBytes });
      cipher.update(forge.util.createBuffer(message, 'utf8'));
      cipher.finish();
      const ciphertext     = cipher.output.getBytes();
      const tag            = cipher.mode.tag.getBytes();
      const completeCt     = ciphertext + tag; // 16-byte GCM auth tag appended
      log('[CRYPTO] AES-256-GCM encryption + auth-tag computed.', 'var(--text-secondary)');

      // 3. RSA-OAEP-SHA256 wrap the session key
      const rsaPublicKey = forge.pki.publicKeyFromPem(serverKey.public_key);
      const encryptedKey = rsaPublicKey.encrypt(sessionKeyBytes, 'RSA-OAEP', {
        md:   forge.md.sha256.create(),
        mgf1: { md: forge.md.sha256.create() },
      });
      log('[CRYPTO] Session key wrapped with RSA-OAEP-SHA256.', 'var(--text-secondary)');

      // 4. Build wire packet
      const packet = {
        encrypted_session_key: forge.util.encode64(encryptedKey),
        iv:                    forge.util.encode64(ivBytes),
        ciphertext:            forge.util.encode64(completeCt),
        client_id:             clientId,
      };
      setIntercepted(packet);
      log('[NET] Encrypted packet assembled — transmitting…', 'var(--cyan)');

      // 5. POST to backend
      const response = await fetch(`${API_BASE}/api/send-message`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(packet),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `HTTP ${response.status}`);
      }

      const result = await response.json();
      setServerResult(result);
      log(`[RX] Server verified. Request ID: ${result.request_id}`, 'var(--green)');
      log(`[RX] Vault size: ${result.vault_records_stored} records at rest.`, 'var(--green)');

      // Refresh audit log automatically after a successful send
      await fetchAuditLog();
    } catch (err) {
      setError(err.message || 'Pipeline failure.');
      log(`[ERR] ${err.message}`, 'var(--red)');
    } finally {
      setLoading(false);
    }
  };

  // ── Derived UI states ────────────────────────────────────────────────────
  const canSend = !!serverKey && !!message.trim() && !loading;
  const uptimeStr = serverInfo
    ? `${Math.floor(serverInfo.uptime_seconds / 60)}m ${serverInfo.uptime_seconds % 60}s`
    : '—';

  // ────────────────────────────────────────────────────────────────────────
  return (
    <>
      <style>{`
        @keyframes blink { 0%, 100% { opacity: 1 } 50% { opacity: 0 } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px) } to { opacity: 1; transform: translateY(0) } }
        .fade-in { animation: fadeIn 220ms ease forwards; }
        textarea:focus, button:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
        button { cursor: pointer; }
        button:disabled { cursor: not-allowed; }
      `}</style>

      <div style={{ minHeight: '100vh', background: 'var(--bg-root)', padding: '28px 20px 60px', fontFamily: 'var(--font-mono)' }}>
        <div style={{ maxWidth: '960px', margin: '0 auto' }}>

          {/* ── Header ─────────────────────────────────────────────── */}
          <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            borderBottom: '1px solid var(--border-base)', paddingBottom: '14px', marginBottom: '24px',
          }}>
            <div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '1px' }}>
                ⚡ CYBER-CORE <span style={{ color: 'var(--cyan)' }}>//</span> E2EE NET
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px', letterSpacing: '0.5px' }}>
                Hybrid RSA-2048-OAEP + AES-256-GCM · Zero-knowledge vault
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              {keyStatus === 'connecting' && <Badge color="amber">● CONNECTING</Badge>}
              {keyStatus === 'active'     && <Badge color="green">● LINK ACTIVE</Badge>}
              {keyStatus === 'error'      && <Badge color="red">○ OFFLINE</Badge>}
            </div>
          </div>

          {/* ── Main grid ──────────────────────────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: '20px', alignItems: 'start' }}>

            {/* Left column */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

              {/* [01] Compose */}
              <Card title="[ 01 ] COMPOSE PLAINTEXT PAYLOAD" subtitle="Message is encrypted client-side before leaving this tab.">
                <textarea
                  rows={4}
                  value={message}
                  onChange={e => setMessage(e.target.value)}
                  placeholder="Type confidential payload…"
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-base)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                    fontSize: '13px',
                    fontFamily: 'var(--font-mono)',
                    resize: 'vertical',
                    lineHeight: 1.6,
                    transition: 'border-color var(--transition)',
                  }}
                  onFocus={e => e.target.style.borderColor = 'var(--cyan)'}
                  onBlur={e  => e.target.style.borderColor = 'var(--border-base)'}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px', gap: '10px' }}>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                    {message.length} chars · client_id: {clientId}
                  </span>
                  <button
                    onClick={runPipeline}
                    disabled={!canSend}
                    style={{
                      padding: '9px 20px',
                      background: loading ? 'var(--amber)' : canSend ? 'var(--green)' : 'var(--border-base)',
                      color: '#0a0c10',
                      border: 'none',
                      borderRadius: 'var(--radius-sm)',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      fontSize: '11px',
                      letterSpacing: '0.8px',
                      transition: 'background var(--transition), opacity var(--transition)',
                      opacity: canSend ? 1 : 0.45,
                      minWidth: '200px',
                    }}
                  >
                    {loading ? 'COMPUTING CIPHERS…' : 'ENCRYPT & TRANSMIT ▶'}
                  </button>
                </div>
                {error && (
                  <div className="fade-in" style={{ marginTop: '10px', padding: '9px 12px', background: '#f8514912', border: '1px solid var(--red)', borderRadius: 'var(--radius-sm)', fontSize: '12px', color: 'var(--red)' }}>
                    ✕ {error}
                  </div>
                )}
              </Card>

              {/* [02] Wiretap intercept */}
              {intercepted && (
                <Card
                  title="[ 02 ] WIRETAP SIMULATION — DATA IN TRANSIT"
                  subtitle="What an attacker on the wire sees. Ciphertext is meaningless without the server private key."
                  borderColor="var(--amber)"
                  className="fade-in"
                >
                  <HexBlock label="ENCRYPTED AES SESSION KEY  (RSA-OAEP-SHA256 wrapper)" icon="🔑" value={intercepted.encrypted_session_key} />
                  <HexBlock label="INITIALISATION VECTOR  (96-bit / AES-GCM nonce)" icon="📌" value={intercepted.iv} />
                  <HexBlock label="AUTHENTICATED CIPHERTEXT + GCM TAG  (AES-256-GCM)" icon="🔒" value={intercepted.ciphertext} />
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '4px' }}>
                    <Badge color="amber">AES-256-GCM</Badge>
                    <Badge color="amber">RSA-OAEP-SHA256</Badge>
                    <Badge color="amber">EPHEMERAL KEY</Badge>
                    <Badge color="amber">INTEGRITY PROTECTED</Badge>
                  </div>
                </Card>
              )}

              {/* [03] Server result */}
              {serverResult && (
                <Card
                  title="[ 03 ] SERVER TELEMETRY & VERIFICATION"
                  subtitle="Decrypted and integrity-verified on the server. Vault stores only the encrypted form."
                  borderColor="var(--cyan)"
                  className="fade-in"
                >
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 20px' }}>
                    <Field label="INTEGRITY STATUS"      value={serverResult.status}                color="var(--green)" />
                    <Field label="REQUEST ID"            value={serverResult.request_id?.slice(0,16) + '…'} />
                    <Field label="VAULT RECORDS AT REST" value={`${serverResult.vault_records_stored} encrypted records`} color="var(--cyan)" />
                    <Field label="SERVER TIMESTAMP"      value={serverResult.received_at} />
                  </div>
                  <div style={{ marginTop: '12px', padding: '10px 12px', background: 'var(--bg-input)', border: '1px solid var(--border-dim)', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-secondary)', letterSpacing: '0.8px', marginBottom: '4px' }}>
                      SERVER PLAINTEXT READOUT (confirms successful decryption)
                    </div>
                    <div style={{ color: 'var(--green)', fontSize: '13px' }}>
                      "{serverResult.decrypted_preview}"
                    </div>
                  </div>
                </Card>
              )}

              {/* [04] Audit log */}
              <Card title="[ 04 ] TRANSMISSION AUDIT LOG" subtitle="Metadata only — no ciphertext or plaintext stored here.">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Last 20 transmissions</span>
                  <button
                    onClick={fetchAuditLog}
                    disabled={logLoading}
                    style={{
                      padding: '4px 12px',
                      background: 'transparent',
                      border: '1px solid var(--border-base)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--cyan)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '10px',
                      letterSpacing: '0.5px',
                      opacity: logLoading ? 0.5 : 1,
                    }}
                  >
                    {logLoading ? 'LOADING…' : '↻ REFRESH'}
                  </button>
                </div>
                {auditLog.length === 0 ? (
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '12px 0' }}>
                    No transmissions yet. Send a message to populate the log.
                  </div>
                ) : (
                  <>
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '80px 90px 1fr 80px 70px',
                      gap: '8px',
                      padding: '0 0 6px',
                      borderBottom: '1px solid var(--border-base)',
                      fontSize: '10px',
                      color: 'var(--text-muted)',
                      letterSpacing: '0.6px',
                    }}>
                      <span>#</span><span>TIME</span><span>REQ ID</span><span>STATUS</span><span style={{ textAlign: 'right' }}>SIZE</span>
                    </div>
                    {auditLog.map((entry, i) => <AuditRow key={entry.id} entry={entry} index={i} />)}
                  </>
                )}
              </Card>
            </div>

            {/* Right column — status panels */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '12px' }}>

              {/* Key status */}
              <Card title="KEY INFRASTRUCTURE">
                <Field label="ALGORITHM"   value={serverKey?.algorithm   || '—'} />
                <Field label="FINGERPRINT" value={serverKey?.key_fingerprint ? truncate(serverKey.key_fingerprint, 28) : '—'} color="var(--purple)" />
                <Field label="STATUS"      value={keyStatus === 'active' ? 'ACTIVE' : keyStatus.toUpperCase()} color={keyStatus === 'active' ? 'var(--green)' : 'var(--amber)'} />
              </Card>

              {/* Server metrics */}
              <Card title="SERVER METRICS">
                <Field label="ENVIRONMENT"    value={serverInfo?.environment?.toUpperCase() || '—'} />
                <Field label="UPTIME"         value={uptimeStr} />
                <Field label="VAULT USED"     value={serverInfo ? `${serverInfo.vault_used} / ${serverInfo.vault_capacity}` : '—'} color="var(--cyan)" />
                <Field label="VERSION"        value={serverInfo?.version || '—'} />
              </Card>

              {/* Crypto legend */}
              <Card title="CIPHER LEGEND">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  <div>
                    <div style={{ color: 'var(--amber)', fontWeight: 600, marginBottom: '2px' }}>RSA-2048-OAEP</div>
                    Asymmetric wrapper. Encrypts the ephemeral AES key so only the server can unwrap it.
                  </div>
                  <div>
                    <div style={{ color: 'var(--amber)', fontWeight: 600, marginBottom: '2px' }}>AES-256-GCM</div>
                    Authenticated encryption. Protects confidentiality + integrity of the message body.
                  </div>
                  <div>
                    <div style={{ color: 'var(--amber)', fontWeight: 600, marginBottom: '2px' }}>EPHEMERAL KEYS</div>
                    A fresh AES key is generated per transmission — forward secrecy in the session layer.
                  </div>
                  <div>
                    <div style={{ color: 'var(--amber)', fontWeight: 600, marginBottom: '2px' }}>ZERO-KNOWLEDGE VAULT</div>
                    Vault stores only ciphertext. Plaintext never persists server-side.
                  </div>
                </div>
              </Card>

              {/* Rate limit note */}
              <div style={{ padding: '10px 12px', background: 'var(--bg-card)', border: '1px solid var(--border-dim)', borderRadius: 'var(--radius-md)', fontSize: '10px', color: 'var(--text-muted)', lineHeight: 1.7 }}>
                <span style={{ color: 'var(--amber)' }}>⚠ RATE LIMITS</span><br />
                /api/send-message: 20 req/min<br />
                /api/public-key: 30 req/min<br />
                /api/audit-log: 10 req/min<br />
                Limits enforced per IP via slowapi.
              </div>
            </div>
          </div>

          {/* ── Terminal log ─────────────────────────────────────── */}
          <div style={{ marginTop: '24px' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.8px', marginBottom: '6px' }}>
              SYSTEM LOG
            </div>
            <div
              ref={termRef}
              style={{
                background: 'var(--bg-panel)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                height: '140px',
                overflowY: 'auto',
                fontSize: '11px',
                lineHeight: 1.7,
              }}
            >
              {termLines.map((line, i) => (
                <div key={i}>
                  <span style={{ color: 'var(--text-muted)', marginRight: '10px' }}>{line.t.slice(11, 19)}</span>
                  <span style={{ color: line.color }}>{line.msg}</span>
                </div>
              ))}
              <div style={{ marginTop: '2px' }}><Cursor /></div>
            </div>
          </div>

          {/* ── Footer ──────────────────────────────────────────── */}
          <div style={{ marginTop: '20px', textAlign: 'center', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.5px' }}>
            E2EE CYBER-CORE v2.1.0 · FastAPI + React · Hybrid RSA-OAEP + AES-256-GCM · Zero-knowledge at rest
          </div>

        </div>
      </div>
    </>
  );
}
