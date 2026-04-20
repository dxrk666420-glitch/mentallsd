import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const TEMPLATE = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../retriever.ps1"),
  "utf8"
);

export function buildPs1(webhook: string): string {
  return TEMPLATE.replace(/__WEBHOOK__/g, webhook.replace(/'/g, "''"));
}
