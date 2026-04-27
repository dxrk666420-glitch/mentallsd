// js-confuser obfuscation wrapper (CommonJS require because js-confuser is CJS)
import { createRequire } from "module";
const require = createRequire(import.meta.url);

const JsConfuser = require("js-confuser");

export async function obfuscate(source: string): Promise<string> {
  const result = await JsConfuser.obfuscate(source, {
    target: "node",
    preset: "medium",
    renameVariables: true,
    renameGlobals: false,    // keep require/process/Buffer etc.
    stringConcealing: true,
    stringEncoding: true,
    controlFlowFlattening: 0.4,
    opaquePredicates: 0.4,
    deadCode: 0.15,
    compact: true,
  });
  return typeof result === "string" ? result : result.code ?? source;
}
