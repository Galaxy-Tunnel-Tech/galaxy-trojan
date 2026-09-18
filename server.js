import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const DEFAULT_LOCAL_PROXIES = [
  "bpb.yousef.isegaro.com",
  "icook.hk",
  "icook.tw",
  "www.visa.com.sg"
];

const DEFAULT_DOH_URL = ["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query","https://dns.quad9.net/dns-query","https://dns.adguard-dns.com/dns-query"];
const CONNECTION_TIMEOUT_MS = 30000; // 30 seconds timeout
const DEFAULT_RATE_LIMIT_PER_MINUTE = 60;
const DEFAULT_WS_PATH = "galaxy-tunnel";
const MAX_CONFIG_PATH_LENGTH = 128;

function isValidUUID(uuid) {
  if (!uuid || typeof uuid !== "string") return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid.trim());
}

function getGalaxyPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <title>Galaxy-Tunnel Trojan</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body, html {
      width: 100%; height: 100%;
      background: #02060d; overflow: hidden;
      font-family: 'Segoe UI', Arial, sans-serif;
      display: flex; justify-content: center; align-items: center;
    }
    .space-bg {
      position: absolute; width: 100%; height: 100%;
      background: 
        radial-gradient(circle at 50% 35%, rgba(10, 45, 80, 0.7) 0%, transparent 65%),
        radial-gradient(circle at 80% 80%, rgba(0, 150, 200, 0.15) 0%, transparent 50%),
        #02060d;
      z-index: 1;
    }
    .starfield {
      position: absolute; width: 100%; height: 100%;
      background-image: 
        radial-gradient(2px 2px at 20px 30px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 40px 70px, rgba(0,212,255,0.8), rgba(0,0,0,0)),
        radial-gradient(1px 1px at 90px 40px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 160px 120px, rgba(0,212,255,0.9), rgba(0,0,0,0));
      background-repeat: repeat; background-size: 220px 220px;
      animation: starTwinkle 4s ease-in-out infinite alternate; opacity: 0.6;
    }
    @keyframes starTwinkle {
      0% { opacity: 0.4; transform: scale(1); }
      100% { opacity: 0.8; transform: scale(1.02); }
    }
    .card-frame {
      position: relative; z-index: 10;
      width: 90vw; max-width: 480px; aspect-ratio: 1 / 1;
      background: rgba(4, 12, 24, 0.75);
      border: 1.5px solid rgba(0, 212, 255, 0.6);
      box-shadow: 0 0 25px rgba(0, 212, 255, 0.25), inset 0 0 25px rgba(0, 212, 255, 0.1);
      backdrop-filter: blur(12px);
      display: flex; flex-direction: column; justify-content: space-between; align-items: center;
      padding: 35px 25px 25px 25px; border-radius: 4px;
    }
    .graphic-container {
      position: relative; width: 230px; height: 230px;
      display: flex; justify-content: center; align-items: center;
    }
    .ring {
      position: absolute; width: 240px; height: 75px;
      border: 2px solid rgba(0, 230, 255, 0.85); border-radius: 50%;
      transform: rotate(-28deg);
      box-shadow: 0 0 15px rgba(0, 212, 255, 0.8), inset 0 0 15px rgba(0, 212, 255, 0.5);
      pointer-events: none; animation: ringGlow 3s ease-in-out infinite alternate;
    }
    @keyframes ringGlow {
      0% { opacity: 0.7; box-shadow: 0 0 12px rgba(0,212,255,0.6); }
      100% { opacity: 1; box-shadow: 0 0 25px rgba(0,212,255,1); }
    }
    canvas { position: absolute; top: 0; left: 0; }
    .content-bottom {
      width: 100%; display: flex; flex-direction: column; align-items: center;
      text-align: center; position: relative;
    }
    .title {
      font-size: 34px; font-weight: 900; font-style: italic;
      color: #ffffff; letter-spacing: 2px; text-transform: uppercase;
      text-shadow: 0 0 12px rgba(255, 255, 255, 0.7); line-height: 1.1;
    }
    .subtitle {
      font-size: 16px; font-weight: 600; color: #7b93a7;
      letter-spacing: 5px; margin-top: 6px; text-transform: uppercase;
    }
    .access-badge {
      align-self: flex-end; margin-top: 15px; font-size: 20px;
      font-weight: 900; font-style: italic; color: #00e5ff;
      text-transform: uppercase; text-align: right; letter-spacing: 1px; line-height: 1.1;
      text-shadow: 0 0 15px rgba(0, 229, 255, 0.85); animation: statusPulse 2s infinite alternate;
    }
    @keyframes statusPulse {
      0% { opacity: 0.8; text-shadow: 0 0 8px rgba(0,229,255,0.5); }
      100% { opacity: 1; text-shadow: 0 0 20px rgba(0,229,255,1); }
    }
  </style>
</head>
<body>
  <div class="space-bg"></div>
  <div class="starfield"></div>
  <div class="card-frame" id="mainCard">
    <div class="graphic-container">
      <div class="ring"></div>
      <canvas id="nodeCanvas" width="230" height="230"></canvas>
    </div>
    <div class="content-bottom">
      <h1 class="title">GALAXY-TUNNEL</h1>
      <div class="subtitle">TROJAN CONFIG</div>
      <div class="access-badge">
        GALAXY VPROXY<br>IS ACCESS
      </div>
    </div>
  </div>
  <script>
    const canvas = document.getElementById('nodeCanvas');
    const ctx = canvas.getContext('2d');
    const numNodes = 32; const nodes = []; const radius = 75;
    let angleX = 0.004; let angleY = 0.007;

    for (let i = 0; i < numNodes; i++) {
      let theta = Math.acos(Math.random() * 2 - 1);
      let phi = Math.random() * Math.PI * 2;
      nodes.push({
        x: radius * Math.sin(theta) * Math.cos(phi),
        y: radius * Math.sin(theta) * Math.sin(phi),
        z: radius * Math.cos(theta)
      });
    }

    function rotateX(node, angle) {
      let cos = Math.cos(angle); let sin = Math.sin(angle);
      let y1 = node.y * cos - node.z * sin;
      let z1 = node.z * cos + node.y * sin;
      node.y = y1; node.z = z1;
    }

    function rotateY(node, angle) {
      let cos = Math.cos(angle); let sin = Math.sin(angle);
      let x1 = node.x * cos - node.z * sin;
      let z1 = node.z * cos + node.x * sin;
      node.x = x1; node.z = z1;
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      let cx = canvas.width / 2; let cy = canvas.height / 2;

      nodes.forEach(node => {
        rotateX(node, angleX);
        rotateY(node, angleY);
      });

      ctx.strokeStyle = 'rgba(0, 220, 255, 0.35)';
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          let dist = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y, nodes[i].z - nodes[j].z);
          if (dist < 60) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x + cx, nodes[i].y + cy);
            ctx.lineTo(nodes[j].x + cx, nodes[j].y + cy);
            ctx.stroke();
          }
        }
      }

      nodes.forEach(node => {
        let size = (node.z + radius) / (2 * radius) * 3 + 2;
        ctx.beginPath();
        ctx.arc(node.x + cx, node.y + cy, size, 0, Math.PI * 2);
        ctx.fillStyle = '#00f0ff';
        ctx.shadowBlur = 8; ctx.shadowColor = '#00f0ff';
        ctx.fill(); ctx.shadowBlur = 0;
      });

      requestAnimationFrame(draw);
    }
    draw();
  </script>
</body>
</html>`;
}

// 401 Unauthorized Step-by-Step Setup Page (Item 1)
function getUnauthorizedPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <title>401 Unauthorized - Galaxy-Tunnel Setup</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #090d16; color: #e2e8f0;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 24px; line-height: 1.6;
    }
    .container {
      max-width: 620px; width: 100%;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(56, 189, 248, 0.3);
      border-radius: 12px; padding: 32px 28px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
    }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
    .badge {
      background: #ef4444; color: #fff; font-weight: 700;
      font-size: 12px; padding: 4px 10px; border-radius: 9999px;
      letter-spacing: 0.5px;
    }
    h1 { font-size: 22px; color: #f8fafc; font-weight: 700; }
    p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
    .step-list { list-style: none; display: flex; flex-direction: column; gap: 16px; }
    .step-item {
      background: rgba(30, 41, 59, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px; padding: 14px 16px;
    }
    .step-title {
      font-weight: 600; font-size: 14px; color: #38bdf8;
      display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
    }
    .step-desc { font-size: 13px; color: #cbd5e1; }
    code {
      background: #020617; color: #38bdf8;
      padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px;
    }
    .step-num {
      background: #0284c7; color: #fff; border-radius: 50%;
      width: 20px; height: 20px; display: inline-flex;
      align-items: center; justify-content: center; font-size: 11px; font-weight: bold;
    }
    .footer-note {
      margin-top: 24px; font-size: 12px; color: #64748b; text-align: center;
    }
  </style>
</head>
<body>
  <div class="container" id="unauthorizedContainer">
    <div class="header">
      <span class="badge">401 UNAUTHORIZED</span>
      <h1>UUID/Password Configuration Required</h1>
    </div>
    <p>Galaxy-Tunnel Trojan server is running, but no valid authentication (UUID or Password) has been configured.</p>
    <ul class="step-list">
      <li class="step-item">
        <div class="step-title"><span class="step-num">1</span> Generate a secure Password or UUID</div>
        <div class="step-desc">Create a strong password, or run <code>uuidgen</code> in your terminal or generate one at <a href="https://www.uuidgenerator.net" target="_blank" rel="noopener" style="color:#38bdf8;">uuidgenerator.net</a>.</div>
      </li>
      <li class="step-item">
        <div class="step-title"><span class="step-num">2</span> Set the Environment Variable</div>
        <div class="step-desc">Set the <code>TROJAN_PASSWORD</code> or <code>UUID</code> environment variable in your deployment environment.</div>
      </li>
      <li class="step-item">
        <div class="step-title"><span class="step-num">3</span> Configure Your Client</div>
        <div class="step-desc">In V2Ray, v2rayN, Sing-box, Clash, or NekoBox, add a Trojan node with WebSocket transport pointing to your domain on port 443 with TLS enabled.</div>
      </li>
      <li class="step-item">
        <div class="step-title"><span class="step-num">4</span> Redeploy / Reload</div>
        <div class="step-desc">Deploy your app and test the connection.</div>
      </li>
    </ul>
    <div class="footer-note">Galaxy-Tunnel Trojan Security Guard &bull; Automatic Access Protection</div>
  </div>
</body>
</html>`;
}

// 404 Camouflage Page (Item 11)
function getCamouflage404() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <title>404 Not Found</title>
  <style>
    body{font-family:sans-serif;background:#fff;color:#222;text-align:center;padding:50px;}
    h1{font-size:32px;margin-bottom:10px;}p{color:#666;}
  </style>
</head>
<body>
  <h1>404 Not Found</h1>
  <p>The requested resource was not found on this server.</p>
</body>
</html>`;
}

// ============================================
// CAMOUFLAGE MASK WEBSITE (EDGE DIAGNOSTICS)
// ============================================
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


// ============================================
// TROJAN CONFIGURATION & SUBSCRIPTION OUTPUT
// ============================================


function generateTrojanConfigs(host, uuid, wsPath, proxyIP = "", trojanPassword = "") {
  // Use trojanPassword if available, fallback to uuid
  const authKey = trojanPassword || uuid;
  // Mock config generation for UI
  return {
    tls: `trojan://${authKey}@${host}:443?type=ws&path=/${wsPath}#Galaxy-Trojan`,
    plainList: "trojan...",
    base64: Buffer.from("trojan...").toString("base64")
  };
}

app.get('/', (req, res) => {
  const host = req.hostname || "localhost";
  const clientIp = req.ip || "127.0.0.1";
  res.send(getMaskPage(host, true, clientIp, "AI-STUDIO"));
});

app.get('/health', (req, res) => res.json({ status: "healthy", service: "galaxy-tunnel-trojan" }));
app.get('/api/health', (req, res) => res.json({ status: "healthy", service: "galaxy-tunnel-trojan" }));

app.post('/api/login', (req, res) => {
  const body = req.body || {};
  const submittedKey = String(body.key || body.password || body.uuid || "").trim();
  const userID = process.env.UUID || "";
  const envPassword = process.env.PASSWORD || process.env.TROJAN_PASSWORD || "";
  
  const validUuidKey = isValidUUID(userID) && submittedKey.toLowerCase() === userID.toLowerCase();
  const validPasswordKey = Boolean(envPassword) && submittedKey === envPassword;
  
  if (validUuidKey || validPasswordKey) {
    res.cookie("galaxy_auth", "1", { maxAge: 86400000 });
    return res.json({ success: true, redirect: isValidUUID(userID) ? `/${userID}` : "/" });
  }
  
  res.status(401).json({ success: false, message: "Invalid UUID or Password" });
});

app.get('/api/logout', (req, res) => {
  res.clearCookie("galaxy_auth");
  res.redirect('/');
});

app.get('/sub', (req, res) => {
  const userID = process.env.UUID || "";
  if (!isValidUUID(userID)) {
    return res.status(401).send("UUID is not configured");
  }
  res.send(generateTrojanConfigs(req.hostname, userID, process.env.WS_PATH || "galaxy-tunnel", "", process.env.TROJAN_PASSWORD).base64);
});

app.get('/:uuid', (req, res, next) => {
  const userID = process.env.UUID || "";
  if (isValidUUID(req.params.uuid) && req.params.uuid.toLowerCase() === userID.toLowerCase()) {
    return res.send(getGalaxyPage());
  }
  if (req.params.uuid === 'unauthorized') {
    return res.send(getUnauthorizedPage());
  }
  next();
});

// Fallback to camouflage 404
app.use((req, res) => {
  res.status(404).send(getCamouflage404());
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
