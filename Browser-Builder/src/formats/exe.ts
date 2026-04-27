import { execSync } from "child_process";
import { writeFileSync, unlinkSync, existsSync, readFileSync } from "fs";
import { join } from "path";
import { createRequire } from "module";
import os from "os";

const require = createRequire(import.meta.url);

export async function buildExe(jsCode: string): Promise<Buffer> {
  const tmpDir = os.tmpdir();
  const src  = join(tmpDir, `bb_src_${Date.now()}.cjs`);
  const out  = join(tmpDir, `bb_out_${Date.now()}.exe`);

  writeFileSync(src, jsCode, "utf8");

  try {
    execSync(
      `node "${require.resolve("pkg/lib-es5/bin.js")}" "${src}" ` +
      `--target node18-win-x64 --output "${out}" --compress GZip`,
      { timeout: 120_000, stdio: "pipe" }
    );
    return readFileSync(out);
  } finally {
    try { unlinkSync(src); } catch {}
    try { if (existsSync(out)) unlinkSync(out); } catch {}
  }
}
