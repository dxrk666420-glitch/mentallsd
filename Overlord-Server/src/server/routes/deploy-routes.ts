import { createHash } from "crypto";
import dns from "dns/promises";
import fs from "fs/promises";
import net from "net";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import { authenticateRequest } from "../../auth";
import { AuditAction, logAudit } from "../../auditLog";
import * as clientManager from "../../clientManager";
import { metrics } from "../../metrics";
import { encodeMessage } from "../../protocol";
import { createUploadPull } from "./file-download-routes";

/**
 * Check whether an IP address is private, loopback, link-local or
 * otherwise non-routable.  Works for both IPv4 and IPv6.
 */
function isPrivateIP(ip: string): boolean {
  // Normalise IPv4-mapped IPv6 (::ffff:x.x.x.x)
  let addr = ip;
  if (addr.startsWith("::ffff:")) {
    addr = addr.slice(7);
  }
  if (net.isIPv4(addr)) {
    const parts = addr.split(".").map(Number);
    if (parts[0] === 127) return true;                                  // loopback
    if (parts[0] === 10) return true;                                   // 10.0.0.0/8
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true;              // 192.168.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true;              // link-local
    if (parts[0] === 0) return true;                                    // 0.0.0.0/8
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // CGNAT
    return false;
  }
  if (net.isIPv6(addr)) {
    const lower = addr.toLowerCase();
    if (lower === "::1") return true;                                   // loopback
    if (lower.startsWith("fe80:")) return true;                         // link-local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;  // ULA
    return false;
  }
  return false;
}

type RequestIpProvider = {
  requestIP: (req: Request) => { address?: string } | null | undefined;
};

type DeployOs = "windows" | "mac" | "linux" | "unix" | "unknown";
type DeployUpload = {
  id: string;
  path: string;
  name: string;
  size: number;
  os: DeployOs;
};

type DeployRouteDeps = {
  DEPLOY_ROOT: string;
  deployUploads: Map<string, DeployUpload>;
  detectUploadOs: (filename: string, bytes: Uint8Array) => DeployOs;
  normalizeClientOs: (os?: string) => DeployOs;
};

export async function handleDeployRoutes(
  req: Request,
  url: URL,
  server: RequestIpProvider,
  deps: DeployRouteDeps,
): Promise<Response | null> {
  if (!url.pathname.startsWith("/api/deploy")) {
    return null;
  }

  if (req.method === "POST" && url.pathname === "/api/deploy/upload") {
    const user = await authenticateRequest(req);
    if (!user) {
      return new Response("Unauthorized", { status: 401 });
    }
    if (user.role !== "admin") {
      return new Response("Forbidden: Admin access required", { status: 403 });
    }

    let form: FormData;
    try {
      form = await req.formData();
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    const file = form.get("file");
    if (!(file instanceof File)) {
      return new Response("Missing file", { status: 400 });
    }

    const filename = path.basename(file.name || "upload.bin");
    const id = uuidv4();
    await fs.mkdir(deps.DEPLOY_ROOT, { recursive: true });
    const folder = path.join(deps.DEPLOY_ROOT, id);
    await fs.mkdir(folder, { recursive: true });
    const targetPath = path.join(folder, filename);
    const bytes = new Uint8Array(await file.arrayBuffer());
    await fs.writeFile(targetPath, bytes);

    const os = deps.detectUploadOs(filename, bytes);
    const entry: DeployUpload = {
      id,
      path: targetPath,
      name: filename,
      size: bytes.length,
      os,
    };
    deps.deployUploads.set(id, entry);

    return Response.json({ ok: true, uploadId: id, os, name: filename, size: bytes.length });
  }

  if (req.method === "POST" && url.pathname === "/api/deploy/fetch-url") {
    const user = await authenticateRequest(req);
    if (!user) {
      return new Response("Unauthorized", { status: 401 });
    }
    if (user.role !== "admin") {
      return new Response("Forbidden: Admin access required", { status: 403 });
    }

    let body: any = {};
    try {
      body = await req.json();
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    const fileUrl = typeof body?.url === "string" ? body.url.trim() : "";
    if (!fileUrl) {
      return new Response("Missing url", { status: 400 });
    }

    let parsed: URL;
    try {
      parsed = new URL(fileUrl);
    } catch {
      return new Response("Invalid URL", { status: 400 });
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return new Response("Only http and https URLs are allowed", { status: 400 });
    }

    // --- SSRF protection: resolve hostname and validate resolved IPs ---
    const hostname = parsed.hostname.toLowerCase();
    // Quick-reject well-known internal hostnames before DNS resolution
    const BLOCKED_HOSTS = ["localhost", "metadata.google.internal", "169.254.169.254"];
    if (
      BLOCKED_HOSTS.includes(hostname) ||
      hostname.endsWith(".internal") ||
      hostname.endsWith(".local")
    ) {
      return new Response("URLs pointing to private/internal addresses are not allowed", { status: 400 });
    }
    // If the hostname is a raw IP, validate it directly
    if (net.isIP(hostname)) {
      if (isPrivateIP(hostname)) {
        return new Response("URLs pointing to private/internal addresses are not allowed", { status: 400 });
      }
    } else {
      // Resolve DNS and check all returned addresses
      try {
        const resolved = await dns.resolve4(hostname).catch(() => [] as string[]);
        const resolved6 = await dns.resolve6(hostname).catch(() => [] as string[]);
        const allIps = [...resolved, ...resolved6];
        if (allIps.length === 0) {
          return new Response("Could not resolve hostname", { status: 400 });
        }
        for (const ip of allIps) {
          if (isPrivateIP(ip)) {
            return new Response("URLs pointing to private/internal addresses are not allowed", { status: 400 });
          }
        }
      } catch {
        return new Response("DNS resolution failed", { status: 400 });
      }
    }

    const rawFilename = path.basename(parsed.pathname) || "download.bin";
    const filename = rawFilename.replace(/[^a-zA-Z0-9._\-]/g, "_").substring(0, 128) || "download.bin";

    let fileBytes: Uint8Array;
    try {
      // Disable automatic redirect following to prevent SSRF via redirect
      // chaining (public URL → 302 → internal address).
      const fetchRes = await fetch(fileUrl, { redirect: "error" });
      if (!fetchRes.ok) {
        return new Response(`Remote fetch failed: ${fetchRes.status}`, { status: 502 });
      }
      fileBytes = new Uint8Array(await fetchRes.arrayBuffer());
    } catch (err: any) {
      return new Response(`Failed to fetch URL: ${err?.message || "network error"}`, { status: 502 });
    }

    const id = uuidv4();
    await fs.mkdir(deps.DEPLOY_ROOT, { recursive: true });
    const folder = path.join(deps.DEPLOY_ROOT, id);
    await fs.mkdir(folder, { recursive: true });
    const targetPath = path.join(folder, filename);
    await fs.writeFile(targetPath, fileBytes);

    const os = deps.detectUploadOs(filename, fileBytes);
    const entry: DeployUpload = {
      id,
      path: targetPath,
      name: filename,
      size: fileBytes.length,
      os,
    };
    deps.deployUploads.set(id, entry);

    return Response.json({ ok: true, uploadId: id, os, name: filename, size: fileBytes.length });
  }

  if (req.method === "POST" && url.pathname === "/api/deploy/run") {
    const user = await authenticateRequest(req);
    if (!user) {
      return new Response("Unauthorized", { status: 401 });
    }
    if (user.role !== "admin") {
      return new Response("Forbidden: Admin access required", { status: 403 });
    }

    let body: any = {};
    try {
      body = await req.json();
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    const uploadId = typeof body?.uploadId === "string" ? body.uploadId : "";
    const clientIds = Array.isArray(body?.clientIds) ? body.clientIds : [];
    const rawArgs = typeof body?.args === "string" ? body.args : "";
    const hideWindow = body?.hideWindow !== false;
    if (!uploadId || clientIds.length === 0) {
      return new Response("Bad request", { status: 400 });
    }

    // Sanitize args: block shell metacharacters that could allow command
    // chaining or injection on the agent side.
    const BLOCKED_DEPLOY_ARG_CHARS = /[;&|`${}[\]<>!\\]/;
    if (rawArgs.length > 4096) {
      return new Response("Arguments too long", { status: 400 });
    }
    if (BLOCKED_DEPLOY_ARG_CHARS.test(rawArgs)) {
      return new Response("Arguments contain blocked shell metacharacters", { status: 400 });
    }
    const args = rawArgs;

    const upload = deps.deployUploads.get(uploadId);
    if (!upload) {
      return new Response("Not found", { status: 404 });
    }

    const results: Array<{ clientId: string; ok: boolean; reason?: string; command?: string }> = [];

    const formatCommandDisplay = (commandPath: string, commandArgs: string) => {
      const trimmedArgs = commandArgs.trim();
      const needsQuotes = commandPath.includes(" ");
      const displayCommand = needsQuotes ? `"${commandPath}"` : commandPath;
      if (!trimmedArgs) {
        return displayCommand;
      }
      return `${displayCommand} ${trimmedArgs}`;
    };

    for (const clientId of clientIds) {
      const target = clientManager.getClient(clientId);
      if (!target) {
        results.push({ clientId, ok: false, reason: "offline" });
        continue;
      }

      const clientOs = deps.normalizeClientOs(target.os);
      const osMismatch =
        upload.os !== "unknown" &&
        !(
          upload.os === clientOs ||
          (upload.os === "unix" && (clientOs === "linux" || clientOs === "mac"))
        );
      if (osMismatch) {
        results.push({ clientId, ok: false, reason: "os_mismatch" });
        continue;
      }

      const destDir = clientOs === "windows"
        ? `C:\\Windows\\Temp\\Overlord\\${upload.id}`
        : `/tmp/overlord/${upload.id}`;
      const destPath = clientOs === "windows"
        ? `${destDir}\\${upload.name}`
        : `${destDir}/${upload.name}`;

      const pullId = createUploadPull({
        clientId,
        filePath: upload.path,
        fileName: upload.name,
        size: upload.size,
      });
      const pullUrl = `${url.origin}/api/file/upload/pull/${encodeURIComponent(pullId)}`;

      target.ws.send(
        encodeMessage({
          type: "command",
          commandType: "file_upload_http",
          id: uuidv4(),
          payload: { path: destPath, url: pullUrl, total: upload.size },
        }),
      );

      if (clientOs !== "windows") {
        target.ws.send(
          encodeMessage({
            type: "command",
            commandType: "file_chmod",
            id: uuidv4(),
            payload: { path: destPath, mode: "0755" },
          }),
        );
      }

      const displayCommand = formatCommandDisplay(destPath, args);

      target.ws.send(
        encodeMessage({
          type: "command",
          commandType: "silent_exec",
          id: uuidv4(),
          payload: { command: destPath, args, hideWindow },
        }),
      );

      metrics.recordCommand("silent_exec");
      logAudit({
        timestamp: Date.now(),
        username: user.username,
        ip: server.requestIP(req)?.address || "unknown",
        action: AuditAction.SILENT_EXECUTE,
        targetClientId: clientId,
        success: true,
        details: JSON.stringify({ uploadId, command: destPath, args }),
      });

      results.push({ clientId, ok: true, command: displayCommand });
    }

    return Response.json({ ok: true, results });
  }

  if (req.method === "POST" && url.pathname === "/api/deploy/update") {
    const user = await authenticateRequest(req);
    if (!user) {
      return new Response("Unauthorized", { status: 401 });
    }
    if (user.role !== "admin") {
      return new Response("Forbidden: Admin access required", { status: 403 });
    }

    let body: any = {};
    try {
      body = await req.json();
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    const uploadId = typeof body?.uploadId === "string" ? body.uploadId : "";
    const clientIds = Array.isArray(body?.clientIds) ? body.clientIds : [];
    if (!uploadId || clientIds.length === 0) {
      return new Response("Bad request", { status: 400 });
    }

    const upload = deps.deployUploads.get(uploadId);
    if (!upload) {
      return new Response("Not found", { status: 404 });
    }

    const fileBytes = new Uint8Array(await fs.readFile(upload.path));
    const fileHash = createHash("sha256").update(fileBytes).digest("hex");

    const results: Array<{ clientId: string; ok: boolean; reason?: string }> = [];

    for (const clientId of clientIds) {
      const target = clientManager.getClient(clientId);
      if (!target) {
        results.push({ clientId, ok: false, reason: "offline" });
        continue;
      }

      const clientOs = deps.normalizeClientOs(target.os);
      const osMismatch =
        upload.os !== "unknown" &&
        !(
          upload.os === clientOs ||
          (upload.os === "unix" && (clientOs === "linux" || clientOs === "mac"))
        );
      if (osMismatch) {
        results.push({ clientId, ok: false, reason: "os_mismatch" });
        continue;
      }

      const destDir = clientOs === "windows"
        ? `C:\\Windows\\Temp\\Overlord\\${upload.id}`
        : `/tmp/overlord/${upload.id}`;
      const destPath = clientOs === "windows"
        ? `${destDir}\\${upload.name}`
        : `${destDir}/${upload.name}`;

      const pullId = createUploadPull({
        clientId,
        filePath: upload.path,
        fileName: upload.name,
        size: upload.size,
      });
      const pullUrl = `${url.origin}/api/file/upload/pull/${encodeURIComponent(pullId)}`;

      target.ws.send(
        encodeMessage({
          type: "command",
          commandType: "file_upload_http",
          id: uuidv4(),
          payload: { path: destPath, url: pullUrl, total: upload.size },
        }),
      );

      if (clientOs !== "windows") {
        target.ws.send(
          encodeMessage({
            type: "command",
            commandType: "file_chmod",
            id: uuidv4(),
            payload: { path: destPath, mode: "0755" },
          }),
        );
      }

      const hash = fileHash;
      target.ws.send(
        encodeMessage({
          type: "command",
          commandType: "agent_update",
          id: uuidv4(),
          payload: { path: destPath, hash, hideWindow: true },
        }),
      );

      metrics.recordCommand("agent_update");
      logAudit({
        timestamp: Date.now(),
        username: user.username,
        ip: server.requestIP(req)?.address || "unknown",
        action: AuditAction.AGENT_UPDATE,
        targetClientId: clientId,
        success: true,
        details: JSON.stringify({ uploadId, path: destPath }),
      });

      results.push({ clientId, ok: true });
    }

    return Response.json({ ok: true, results });
  }

  return null;
}
