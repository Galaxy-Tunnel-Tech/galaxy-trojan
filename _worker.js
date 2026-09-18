import { connect } from "cloudflare:sockets";
const DEFAULT_WS_PATH = "trojan-ws";
const DEFAULT_RATE_LIMIT = 60;
const CONNECTION_TIMEOUT_MS = 30000;
const MAX_HANDSHAKE_BYTES = 4096;

class Logger {
  constructor(requestId, clientIp) { this.requestId = requestId; this.clientIp = clientIp; }
  log(level, event, details = {}) {
    const entry = { timestamp: new Date().toISOString(), level, requestId: this.requestId, clientIp: this.clientIp, event, ...details };
    (level === "ERROR" ? console.error : level === "WARN" ? console.warn : console.log)(JSON.stringify(entry));
  }
  info(event, details) { this.log("INFO", event, details); }
  warn(event, details) { this.log("WARN", event, details); }
  error(event, details) { this.log("ERROR", event, details); }
}

function requestId() { return crypto.randomUUID?.() || `req_${Math.random().toString(36).slice(2, 12)}`; }
function isValidUUID(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || "").trim()); }
function normalizePath(value) {
  const path = String(value || DEFAULT_WS_PATH).trim().replace(/^\/+|\/+$/g, "");
  return path && path.length <= 128 && !/[\s?#\\]/.test(path) ? path : DEFAULT_WS_PATH;
}
function headers(type = "text/html; charset=utf-8") {
  return {
    "Content-Type": type,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Protocol",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"
  };
}

// SHA-224 is required by the Trojan protocol. This implementation hashes the UUID credential.
function sha224Bytes(input) {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const H = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  const bytes = input instanceof Uint8Array ? input : new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  padded.set(bytes); padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(padded.length - 4, bitLen >>> 0);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let offset = 0; offset < padded.length; offset += 64) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      [h,g,f,e,d,c,b,a] = [g,f,e,(d+t1)>>>0,c,b,a,(t1+t2)>>>0];
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(28);
  const outView = new DataView(out.buffer);
  H.slice(0, 7).forEach((v, i) => outView.setUint32(i * 4, v));
  return out;
}
function hex(bytes) { return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""); }
function concat(...parts) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; }
function indexOfBytes(haystack, needle, start = 0) { outer: for (let i = start; i <= haystack.length - needle.length; i++) { for (let j = 0; j < needle.length; j++) if (haystack[i+j] !== needle[j]) continue outer; return i; } return -1; }
function equalBytes(a, b) { if (a.length !== b.length) return false; let x = 0; for (let i=0;i<a.length;i++) x |= a[i] ^ b[i]; return x === 0; }
function privateHost(host) { const h = String(host || "").toLowerCase().replace(/^\[|\]$/g, ""); if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true; const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); if (!m) return h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:"); const [a,b] = [+m[1], +m[2]]; return a===0 || a===10 || a===127 || (a===169&&b===254) || (a===172&&b>=16&&b<=31) || (a===192&&b===168) || (a===100&&b>=64&&b<=127); }
function parseAddress(bytes, index) {
  const type = bytes[index++];
  if (type === 1) { if (bytes.length < index + 4 + 2) return null; const host = [...bytes.slice(index,index+4)].join("."); index += 4; return { host, port: (bytes[index]<<8)|bytes[index+1], end: index+2 }; }
  if (type === 3) { const n = bytes[index++]; if (!n || bytes.length < index+n+2) return null; const host = new TextDecoder().decode(bytes.slice(index,index+n)); index += n; return { host, port: (bytes[index]<<8)|bytes[index+1], end: index+2 }; }
  if (type === 4) { if (bytes.length < index + 16 + 2) return null; const h = []; for (let i=0;i<16;i+=2) h.push(((bytes[index+i]<<8)|bytes[index+i+1]).toString(16)); index += 16; return { host: h.join(":"), port: (bytes[index]<<8)|bytes[index+1], end: index+2 }; }
  return null;
}

function getMaskPage(host = "localhost", isAuthEnabled = true, clientIp = "127.0.0.1", colo = "EDGE-LOCAL") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EdgeTunnel Cloud | Edge Network & Diagnostics</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: #f8fafc;
      color: #0f172a;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      padding: 14px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .logo-area {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 800;
      font-size: 17px;
      color: #000000;
      cursor: pointer;
      user-select: none;
      line-height: 1.15;
    }
    .logo-icon {
      width: 32px;
      height: 32px;
      background: #000000;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-weight: 900;
      font-size: 16px;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #000000;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 800;
      color: #ffffff;
      letter-spacing: 0.5px;
    }
    .btn-portal {
      background: transparent;
      border: none;
      color: #000000;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: opacity 0.2s;
    }
    .btn-portal:hover {
      opacity: 0.7;
    }
    main {
      flex: 1;
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .hero-card {
      background: linear-gradient(180deg, #ecfdf5 0%, #ffffff 40%);
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.03);
      position: relative;
    }
    .hero-top-badge {
      position: absolute;
      top: 24px;
      right: 24px;
      background: #dcfce7;
      border: 1px solid #bbf7d0;
      color: #166534;
      font-size: 12px;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 9999px;
    }
    .hero-title {
      font-size: 23px;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 8px;
      padding-right: 70px;
      line-height: 1.25;
    }
    .hero-desc {
      color: #475569;
      font-size: 14px;
      line-height: 1.6;
      max-width: 680px;
      margin-bottom: 18px;
    }
    .btn-run {
      background: #000000;
      color: #ffffff;
      border: none;
      padding: 9px 18px;
      border-radius: 8px;
      font-weight: 700;
      font-size: 13px;
      cursor: pointer;
      transition: opacity 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
    }
    .btn-run:hover { opacity: 0.85; }
    .btn-run:disabled { opacity: 0.6; cursor: not-allowed; }
    .bench-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }
    .bench-box {
      border-radius: 12px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .bench-box-1 {
      background: linear-gradient(135deg, #d1fae5 0%, #ecfdf5 100%);
      border: 1px solid #a7f3d0;
    }
    .bench-box-2 {
      background: linear-gradient(135deg, #dcfce7 0%, #f0fdf4 100%);
      border: 1px solid #bbf7d0;
    }
    .bench-box-3 {
      background: linear-gradient(135deg, #e0e7ff 0%, #f5f3ff 100%);
      border: 1px solid #c7d2fe;
    }
    .bench-box-4 {
      background: linear-gradient(135deg, #fce7f3 0%, #fdf4ff 100%);
      border: 1px solid #fbcfe8;
    }
    .bench-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .bench-box-1 .bench-label { color: #047857; }
    .bench-box-2 .bench-label { color: #15803d; }
    .bench-box-3 .bench-label { color: #4338ca; }
    .bench-box-4 .bench-label { color: #9d174d; }
    .bench-val {
      font-size: 24px;
      font-weight: 800;
      color: #0f172a;
      margin-top: 4px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    }
    .bench-meta {
      font-size: 12px;
      font-weight: 600;
      margin-top: 2px;
    }
    .bench-box-1 .bench-meta { color: #059669; }
    .bench-box-2 .bench-meta { color: #16a34a; }
    .bench-box-3 .bench-meta { color: #4f46e5; }
    .bench-box-4 .bench-meta { color: #db2777; }
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
    }
    @media (min-width: 768px) {
      .grid-2 { grid-template-columns: 1fr 1fr; }
    }
    .card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.02);
    }
    .card-heading {
      font-size: 15px;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 9px 0;
      border-bottom: 1px solid #f1f5f9;
      font-size: 13px;
    }
    .info-row:last-child { border-bottom: none; }
    .info-k { color: #475569; font-weight: 500; }
    .info-v { color: #0f172a; font-family: monospace; font-weight: 700; }
    .footer-bar {
      background: linear-gradient(90deg, #dcfce7 0%, #bbf7d0 50%, #dcfce7 100%);
      border: 1px solid #a7f3d0;
      border-radius: 10px;
      padding: 12px;
      text-align: center;
      font-size: 12px;
      font-weight: 700;
      color: #065f46;
      margin-top: 4px;
    }
    
    /* Access Modal */
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(6px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s;
    }
    .modal-overlay.open {
      opacity: 1;
      pointer-events: auto;
    }
    .modal-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
      border-radius: 16px;
      width: 100%;
      max-width: 420px;
      padding: 24px;
      margin: 16px;
    }
    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .modal-title {
      font-size: 17px;
      font-weight: 800;
      color: #0f172a;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .btn-close {
      background: transparent;
      border: none;
      color: #64748b;
      font-size: 18px;
      cursor: pointer;
    }
    .modal-input {
      width: 100%;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      padding: 11px 14px;
      border-radius: 8px;
      color: #0f172a;
      font-family: monospace;
      font-size: 14px;
      outline: none;
      margin-bottom: 14px;
    }
    .modal-input:focus {
      border-color: #000000;
      background: #ffffff;
      box-shadow: 0 0 0 3px rgba(0, 0, 0, 0.05);
    }
    .btn-submit {
      width: 100%;
      background: #000000;
      color: #ffffff;
      border: none;
      padding: 11px;
      border-radius: 8px;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-submit:hover { opacity: 0.85; }
    .auth-msg {
      font-size: 12px;
      margin-top: 10px;
      text-align: center;
      color: #dc2626;
      font-weight: 600;
      display: none;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo-area" onclick="handleLogoClick()">
      <div class="logo-icon">⚡</div>
      <div>
        <div>EdgeTunnel</div>
        <div>Cloud</div>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-pill">
        <span>EDGE OPERATIONAL</span>
      </div>
      <button class="btn-portal" onclick="openPortalModal()">
        <span>🔒 Portal Access</span>
      </button>
    </div>
  </header>

  <main>
    <div class="hero-card">
      <div class="hero-top-badge">Active</div>
      <h1 class="hero-title">Edge Network Diagnostic &amp; Latency Monitor</h1>
      <p class="hero-desc">Real-time edge server telemetry, DNS-over-HTTPS status verification, and full-duplex socket connectivity diagnostics for cloud edge clusters.</p>
      
      <button class="btn-run" id="btnBench" onclick="runDiagnostics()">
        ⚡ Re-Run Benchmark
      </button>

      <div class="bench-grid">
        <div class="bench-box bench-box-1">
          <div class="bench-label">Edge Roundtrip Ping</div>
          <div class="bench-val" id="pingVal">-- ms</div>
          <div class="bench-meta" id="pingStatus">Measuring...</div>
        </div>
        <div class="bench-box bench-box-2">
          <div class="bench-label">DNS-Over-HTTPS (DoH)</div>
          <div class="bench-val">Active</div>
          <div class="bench-meta">Cloudflare 1.1.1.1</div>
        </div>
        <div class="bench-box bench-box-3">
          <div class="bench-label">WebSocket Engine</div>
          <div class="bench-val">Full-Duplex</div>
          <div class="bench-meta">RFC 6455 Ready</div>
        </div>
        <div class="bench-box bench-box-4">
          <div class="bench-label">Edge Cluster Location</div>
          <div class="bench-val">${colo}</div>
          <div class="bench-meta">Anycast Network</div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-heading">🌐 Connection Telemetry</div>
        <div class="info-row">
          <span class="info-k">Client Remote IP:</span>
          <span class="info-v">${clientIp}</span>
        </div>
        <div class="info-row">
          <span class="info-k">Serving Host:</span>
          <span class="info-v">${host}</span>
        </div>
        <div class="info-row">
          <span class="info-k">HTTP Protocol:</span>
          <span class="info-v">HTTP/2 &amp; HTTP/3 (QUIC)</span>
        </div>
        <div class="info-row">
          <span class="info-k">Encryption &amp; Cipher:</span>
          <span class="info-v">TLS 1.3 / AEAD ChaCha20</span>
        </div>
      </div>

      <div class="card">
        <div class="card-heading">🛡️ Edge Security &amp; Health</div>
        <div class="info-row">
          <span class="info-k">DDoS Mitigation:</span>
          <span class="info-v" style="color: #16a34a;">Active (Strict)</span>
        </div>
        <div class="info-row">
          <span class="info-k">Global Edge Cache:</span>
          <span class="info-v">100% Operational</span>
        </div>
        <div class="info-row">
          <span class="info-k">WAF Security Layer:</span>
          <span class="info-v">Enforced</span>
        </div>
        <div class="info-row">
          <span class="info-k">Service Status:</span>
          <span class="info-v" style="color: #16a34a;">Optimal (99.99%)</span>
        </div>
      </div>
    </div>

    <div class="footer-bar">
      EdgeTunnel Cloud Network • High Availability Edge Gateway • All Systems Running
    </div>
  </main>

  <!-- Admin Auth Modal -->
  <div class="modal-overlay" id="portalModal">
    <div class="modal-card">
      <div class="modal-head">
        <div class="modal-title">
          <span>🔒 Edge Gateway Access</span>
        </div>
        <button class="btn-close" onclick="closePortalModal()">✕</button>
      </div>
      <p style="font-size: 13px; color: #64748b; margin-bottom: 14px; line-height: 1.5;">
        Please enter your Universal Unique Identifier (UUID) or Dashboard Access Password to unlock the administrative console.
      </p>
      <form onsubmit="handlePortalLogin(event)">
        <input type="password" id="authKeyInput" class="modal-input" placeholder="Enter UUID or Password" required autofocus />
        <button type="submit" class="btn-submit" id="submitBtn">Unlock Console</button>
      </form>
      <div class="auth-msg" id="authErrorMsg">⚠️ Invalid UUID or Password. Access Denied.</div>
    </div>
  </div>

  <script>
    let logoClicks = 0;
    function handleLogoClick() {
      logoClicks++;
      if (logoClicks >= 3) {
        openPortalModal();
        logoClicks = 0;
      }
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
        openPortalModal();
      }
      if (e.key === 'Escape') {
        closePortalModal();
      }
    });

    function openPortalModal() {
      document.getElementById('portalModal').classList.add('open');
      document.getElementById('authKeyInput').focus();
    }

    function closePortalModal() {
      document.getElementById('portalModal').classList.remove('open');
      document.getElementById('authErrorMsg').style.display = 'none';
    }

    async function handlePortalLogin(e) {
      e.preventDefault();
      const key = document.getElementById('authKeyInput').value.trim();
      const errorMsg = document.getElementById('authErrorMsg');
      const submitBtn = document.getElementById('submitBtn');

      if (!key) return;
      submitBtn.textContent = "Verifying...";
      submitBtn.disabled = true;
      errorMsg.style.display = 'none';

      try {
        const resp = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
        });
        const data = await resp.json();

        if (resp.ok && data.success) {
          window.location.href = data.redirect || ('/' + encodeURIComponent(key));
        } else {
          errorMsg.textContent = data.message || "⚠️ Invalid Access Key / UUID.";
          errorMsg.style.display = 'block';
          submitBtn.textContent = "Unlock Console";
          submitBtn.disabled = false;
        }
      } catch (err) {
        // Fallback: direct navigation with key
        window.location.href = '/' + encodeURIComponent(key);
      }
    }

    async function runDiagnostics() {
      const btn = document.getElementById('btnBench');
      const pingVal = document.getElementById('pingVal');
      const pingStatus = document.getElementById('pingStatus');

      btn.disabled = true;
      btn.textContent = "Testing Edge Latency...";
      pingVal.textContent = "...";
      pingStatus.textContent = "Measuring round-trip...";

      const pings = [];
      for (let i = 0; i < 3; i++) {
        const start = performance.now();
        try {
          await fetch('/api/health?t=' + Date.now(), { cache: 'no-store' });
          const latency = Math.round(performance.now() - start);
          pings.push(latency);
        } catch (e) {
          pings.push(32);
        }
        await new Promise(r => setTimeout(r, 120));
      }

      const avg = Math.round(pings.reduce((a, b) => a + b, 0) / pings.length);
      pingVal.textContent = avg + ' ms';
      pingStatus.textContent = "Good Latency";
      btn.disabled = false;
      btn.textContent = "⚡ Re-Run Benchmark";
    }

    // Auto run once
    setTimeout(runDiagnostics, 500);
  </script>
</body>
</html>`;
}

function trojanUri(host, uuid, path) {
  const p = `%2F${encodeURIComponent(path)}%3Fed%3D2048`;
  return `trojan://${encodeURIComponent(uuid)}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=${p}#Galaxy-Trojan%20(${host})`;
}
function cookieAuth(request) { return (request.headers.get("Cookie") || "").split(";").some((x) => x.trim() === "galaxy_auth=1"); }

const rateRecords = new Map();
function rateCheck(ip) { const now = Date.now(); const old = rateRecords.get(ip); if (!old || now - old.start > 60000) { rateRecords.set(ip, { start: now, count: 1 }); return true; } old.count++; return old.count <= DEFAULT_RATE_LIMIT; }

async function handleTrojan(request, env, logger) {
  const path = normalizePath(env.WS_PATH || DEFAULT_WS_PATH);
  if (new URL(request.url).pathname.replace(/^\/+|\/+$/g, "") !== path) return new Response("Not found", { status: 404 });
  const uuid = String(env.UUID || env.uuid || "").trim().toLowerCase();
  if (!isValidUUID(uuid)) return new Response("Trojan credential is not configured", { status: 503 });
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.binaryType = "arraybuffer";
  server.accept({ allowHalfOpen: true });
  const expectedHash = new TextEncoder().encode(hex(sha224Bytes(uuid)));
  let buffer = new Uint8Array(0), socket = null, writer = null, established = false, closed = false;
  const timer = setTimeout(() => { if (!established) { logger.warn("TROJAN_HANDSHAKE_TIMEOUT"); try { server.close(1008, "timeout"); } catch {} } }, CONNECTION_TIMEOUT_MS);
  const closeAll = () => { if (closed) return; closed = true; clearTimeout(timer); try { writer?.releaseLock(); } catch {} try { socket?.close(); } catch {} try { server.close(); } catch {} };
  const forwardRemote = async () => { try { for await (const chunk of socket.readable) { if (server.readyState === 1) server.send(chunk); } } catch (e) { logger.warn("TROJAN_REMOTE_READ_ERROR", { error: String(e?.message || e) }); } finally { closeAll(); } };
  const establish = async (payload) => {
    const crlf = new Uint8Array([13,10]);
    const hashEnd = indexOfBytes(payload, crlf);
    if (hashEnd !== 56) throw new Error("invalid trojan credential frame");
    if (!equalBytes(payload.slice(0,56), expectedHash)) throw new Error("invalid trojan credential");
    const reqStart = hashEnd + 2;
    const request = parseAddress(payload, reqStart + 1);
    if (!request || payload[reqStart] !== 1) throw new Error("unsupported trojan request");
    if (privateHost(request.host)) throw new Error("private destination blocked");
    socket = connect({ hostname: request.host, port: request.port });
    writer = socket.writable.getWriter();
    established = true; clearTimeout(timer);
    logger.info("TROJAN_CONNECTED", { target: `${request.host}:${request.port}` });
    await writer.write(payload.slice(request.end + 2));
    writer.releaseLock(); writer = null;
    forwardRemote();
  };
  server.addEventListener("message", async (event) => {
    try {
      const incoming = typeof event.data === "string" ? new TextEncoder().encode(event.data) : new Uint8Array(await new Response(event.data).arrayBuffer());
      if (!established) {
        if (buffer.length + incoming.length > MAX_HANDSHAKE_BYTES) throw new Error("handshake too large");
        buffer = concat(buffer, incoming);
        const hashEnd = indexOfBytes(buffer, new Uint8Array([13,10]));
        if (hashEnd < 0 || hashEnd < 56) return;
        const reqStart = hashEnd + 2;
        if (buffer.length < reqStart + 4) return;
        const type = buffer[reqStart + 3];
        const addressLen = type === 3 ? (buffer.length > reqStart + 4 ? buffer[reqStart+4] : 0) : type === 1 ? 4 : type === 4 ? 16 : 0;
        const need = reqStart + 4 + (type === 3 ? 1 : 0) + addressLen + 2 + 2;
        if (buffer.length < need) return;
        await establish(buffer); buffer = new Uint8Array(0); return;
      }
      if (socket) { const w = socket.writable.getWriter(); await w.write(incoming); w.releaseLock(); }
    } catch (e) { logger.warn("TROJAN_CONNECTION_REJECTED", { error: String(e?.message || e) }); closeAll(); }
  });
  server.addEventListener("close", closeAll); server.addEventListener("error", closeAll);
  return new Response(null, { status: 101, webSocket: client });
}

const worker_default = {
  async fetch(request, env) {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const logger = new Logger(requestId(), ip);
    if (!rateCheck(ip)) return new Response(JSON.stringify({ error: "Too Many Requests" }), { status: 429, headers: headers("application/json") });
    const url = new URL(request.url), path = url.pathname.replace(/^\/+|\/+$/g, "");
    const uuid = String(env.UUID || env.uuid || "").trim().toLowerCase();
    const wsPath = normalizePath(env.WS_PATH || DEFAULT_WS_PATH);
    if (url.pathname === "/health" || url.pathname === "/api/health") return new Response(JSON.stringify({ status: "healthy", service: "galaxy-tunnel-trojan", uuidConfigured: isValidUUID(uuid), wsPath, transport: "trojan-over-websocket", timestamp: new Date().toISOString() }), { headers: headers("application/json") });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers("text/plain") });
    if (url.pathname === "/api/login" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const submitted = String(body.key || body.uuid || "").trim().toLowerCase();
      if (isValidUUID(uuid) && submitted === uuid) {
        return new Response(JSON.stringify({ success: true }), { headers: { ...headers("application/json"), "Set-Cookie": "galaxy_auth=1; Path=/; Max-Age=86400; SameSite=Lax; HttpOnly" } });
      }
      return new Response(JSON.stringify({ success: false, message: "Invalid UUID" }), { status: 401, headers: headers("application/json") });
    }
    if (url.pathname === "/sub" && request.method === "GET") {
      if (!isValidUUID(uuid)) return new Response("Trojan credential is not configured", { status: 503, headers: headers("text/plain") });
      return new Response(btoa(trojanUri(request.headers.get("Host") || url.host, uuid, wsPath)), { headers: { ...headers("text/plain; charset=utf-8"), "Profile-Update-Interval": "24" } });
    }
    if (url.pathname === "/api/logout") return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": "galaxy_auth=0; Path=/; Max-Age=0; SameSite=Lax" } });
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") return handleTrojan(request, env, logger);
    if (path === "" || path === wsPath) return new Response(getMaskPage(request.headers.get("Host") || url.host, isValidUUID(uuid), ip, request.cf?.colo || "EDGE-GLOBAL"), { headers: headers() });
    if (cookieAuth(request)) return new Response(getMaskPage(request.headers.get("Host") || url.host, true, ip, request.cf?.colo || "EDGE-GLOBAL"), { headers: headers() });
    return new Response(getMaskPage(request.headers.get("Host") || url.host, isValidUUID(uuid), ip, request.cf?.colo || "EDGE-GLOBAL"), { headers: headers() });
  }
};

export default worker_default;
