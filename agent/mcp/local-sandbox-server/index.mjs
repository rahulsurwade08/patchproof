#!/usr/bin/env node
// Local Docker sandbox MCP server — keyless alternative to cloud sandboxes.
//
// Tools:
//   sandbox_exec   — run a shell command inside a per-session, network-isolated
//                    container (created on first use, reused afterwards so the
//                    service and the PoC share /tmp and localhost)
//   sandbox_write  — write a file into a session container
//   sandbox_read   — read a file out of a session container
//   sandbox_stop   — destroy a session container
//
// Isolation contract (mirrors scripts/run_poc_local.sh):
//   - containers always run with `--network none`
//   - exploit traffic can only reach 127.0.0.1 inside the container
//   - nothing executes on the host itself
//
// Transport: MCP Streamable HTTP (POST JSON-RPC at /mcp, JSON responses,
// no session state beyond the docker containers themselves).
// No external dependencies; Node >= 18.

import http from "node:http";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";

const PORT = Number(process.env.LOCAL_SANDBOX_PORT || 8081);
const IMAGE = process.env.LOCAL_SANDBOX_IMAGE || "python:3.11-slim";
const MAX_OUTPUT = 20000;
const MAX_BODY_BYTES = 1024 * 1024;
// Ownership labels: every container we create carries these, so crash
// recovery on startup can reclaim leftovers from ANY previous instance.
const LABELS = ["--label", "patchproof-sbx=1"];

// Best-effort redaction of credential-looking strings in tool output.
function redact(text) {
  return String(text)
    .replace(/sk-or-v1-[A-Za-z0-9_-]{8,}/g, "<redacted>")
    .replace(/ghp_[A-Za-z0-9]{20,}/g, "<redacted>")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "<redacted>")
    .replace(/dtn_[A-Za-z0-9_-]{8,}/g, "<redacted>")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, "$1<redacted>")
    .replace(/((?:api[_-]?key|token|password|secret)(?:['"\s:=]+))['"]?[A-Za-z0-9._~+/=-]{12,}['"]?/gi,
      "$1<redacted>");
}

// Per-container async locks so concurrent ensureContainer calls can't race.
const locks = new Map();
async function withLock(key, fn) {
  const prev = locks.get(key) || Promise.resolve();
  const run = prev.then(fn, fn);
  locks.set(key, run.catch(() => {}));
  await run;
}

function docker(args, { timeoutMs = 120000, input } = {}) {
  return new Promise((resolve) => {
    const child = execFile(
      "docker",
      args,
      { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err && err.killed) {
          resolve({ code: 124, stdout: String(stdout).slice(0, MAX_OUTPUT),
            stderr: (String(stderr) + "\ntimed out").slice(0, MAX_OUTPUT) });
        } else if (err && typeof err.code === "number") {
          resolve({ code: err.code, stdout: String(stdout).slice(0, MAX_OUTPUT),
            stderr: String(stderr).slice(0, MAX_OUTPUT) });
        } else if (err) {
          resolve({ code: 125, stdout: "", stderr: String(err.message).slice(0, MAX_OUTPUT) });
        } else {
          resolve({ code: 0, stdout: String(stdout).slice(0, MAX_OUTPUT),
            stderr: String(stderr).slice(0, MAX_OUTPUT) });
        }
      }
    );
    if (input !== undefined && child.stdin) {
      child.stdin.end(input);
    }
  });
}

function containerName(session) {
  // Hash the RAW label: distinct labels can never collide, however similar.
  const h = createHash("sha256").update(String(session || "default")).digest("hex").slice(0, 16);
  return `patchproof-sbx-${h}`;
}

async function startContainer(name, network = "none", image = IMAGE) {
  const netArgs =
    network === "none" ? ["--network", "none"] : ["--network", String(network)];
  for (let attempt = 0; attempt < 3; attempt++) {
    await docker(["rm", "-f", name]);
    const started = await docker([
      "run", "--rm", "-d",
      "--name", name,
      ...netArgs,
      ...LABELS,
      "--pids-limit", "512",
      "--memory", "1g",
      "--cpus", "1",
      "-w", "/srv",
      image,
      "sh", "-c", "sleep infinity",
    ]);
    if (started.code === 0) return;
    // Another caller may have created it between our rm and run — re-check.
    const inspect = await docker(["inspect", "-f", "{{.State.Running}}", name]);
    if (inspect.code === 0 && inspect.stdout.trim() === "true") return;
  }
  throw new Error(`failed to start container ${name} after 3 attempts`);
}

async function ensureContainer(session, network = "none", image = IMAGE) {
  const name = containerName(session);
  await withLock(name, async () => {
    const running = await docker(["inspect", "-f", "{{.State.Running}}", name]);
    if (running.code === 0 && running.stdout.trim() === "true") return;
    await startContainer(name, network, image);
  });
  return name;
}

async function cleanupAllContainers() {
  // Label-filtered: removes every container ever created by this server
  // (including orphans from crashed instances), touches nothing else.
  const listed = await docker(["ps", "-aq", "--filter", "label=patchproof-sbx=1"]);
  const ids = listed.stdout.trim().split("\n").filter(Boolean);
  for (const id of ids) await docker(["rm", "-f", id]);
  return ids.length;
}

let shuttingDown = false;
function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { cleanupAllContainers(); } catch { /* best effort */ }
  process.exit(code);
}

function registerShutdownCleanup() {
  process.on("SIGINT", () => shutdown(0));
  process.on("SIGTERM", () => shutdown(0));
  process.on("uncaughtException", (err) => {
    console.error("uncaught exception:", err);
    shutdown(1);
  });
  process.on("unhandledRejection", (err) => {
    console.error("unhandled rejection:", err);
    shutdown(1);
  });
}

const TOOLS = [
  {
    name: "sandbox_build",
    description:
      "Build a Docker image on the host from a directory containing a Dockerfile " +
      "(build-time network is allowed; the resulting image is what runs offline). " +
      "Use this to bake scenario dependencies (e.g. pinned requirements) into an " +
      "image before starting an offline session with sandbox_exec(image=tag).",
    inputSchema: {
      type: "object",
      properties: {
        tag: { type: "string", description: "image tag to produce, e.g. patchproof-s01" },
        context_path: { type: "string", description: "absolute host path containing the Dockerfile" },
      },
      required: ["tag", "context_path"],
    },
  },
  {
    name: "sandbox_exec",
    description:
      "Run a shell command inside an isolated local Docker container for the given session. " +
      "The container has NO network access; services started inside it are reachable only at " +
      "127.0.0.1 within the same container. First call starts the container (may take a few " +
      "seconds); later calls reuse it so files persist between calls. Pass `image` on the " +
      "first call to start from a pre-built image (see sandbox_build) — needed when the " +
      "command requires packages that cannot be installed offline.",
    inputSchema: {
      type: "object",
      properties: {
        session: { type: "string", description: "logical session label; containers are isolated per session" },
        command: { type: "string", description: "shell command to execute inside the container" },
        timeout_secs: { type: "number", description: "per-command timeout (default 60, max 600)" },
        network: {
          type: "string",
          description:
            "Docker network to attach (default 'none'). Only the verifier may set a named compose network to reach staging; reproduction and patching always use 'none'.",
        },
        image: {
          type: "string",
          description: "image used when creating the container (default python:3.11-slim). Only honored on first call / after sandbox_stop.",
        },
      },
      required: ["session", "command"],
    },
  },
  {
    name: "sandbox_write",
    description: "Write a text file into a session container.",
    inputSchema: {
      type: "object",
      properties: {
        session: { type: "string" },
        path: { type: "string", description: "absolute path inside the container, e.g. /srv/poc.py" },
        content: { type: "string" },
      },
      required: ["session", "path", "content"],
    },
  },
  {
    name: "sandbox_read",
    description: "Read a text file out of a session container (e.g. verdict.json).",
    inputSchema: {
      type: "object",
      properties: { session: { type: "string" }, path: { type: "string" } },
      required: ["session", "path"],
    },
  },
  {
    name: "sandbox_stop",
    description: "Destroy a session container. Call when finished with an investigation.",
    inputSchema: {
      type: "object",
      properties: { session: { type: "string" } },
      required: ["session"],
    },
  },
];

async function toolCall(name, args = {}) {
  switch (name) {
    case "sandbox_build": {
      // Host-side build: Dockerfile RUN steps get network access; the built
      // image is what later runs offline inside sandbox containers.
      const res = await docker(["build", "-t", String(args.tag), String(args.context_path)],
        { timeoutMs: 600000 });
      return { exit_code: res.code, output: redact((res.stdout + res.stderr).slice(-MAX_OUTPUT)) };
    }
    case "sandbox_exec": {
      const name2 = await ensureContainer(args.session, args.network, args.image);
      const timeout = Math.min(Number(args.timeout_secs || 60), 600);
      const res = await docker(
        ["exec", "-w", "/srv", name2, "sh", "-c", String(args.command)],
        { timeoutMs: timeout * 1000 + 5000 }
      );
      return {
        exit_code: res.code,
        stdout: redact(res.stdout),
        stderr: redact(res.stderr),
        container: name2,
      };
    }
    case "sandbox_write": {
      const name2 = await ensureContainer(args.session, args.network, args.image);
      const res = await docker(["exec", "-i", name2, "sh", "-c",
        `mkdir -p "$(dirname '${args.path}')" && cat > '${args.path}'`],
        { input: String(args.content ?? "") });
      if (res.code !== 0) throw new Error(res.stderr);
      return { written: args.path, bytes: Buffer.byteLength(String(args.content ?? "")) };
    }
    case "sandbox_read": {
      const res = await docker(["exec", containerName(args.session),
        "sh", "-c", `cat '${args.path}' 2>&1`]);
      return { path: args.path, exists: res.code === 0 && !/^cat: /.test(res.stdout),
        content: redact(res.stdout) };
    }
    case "sandbox_stop": {
      await docker(["rm", "-f", containerName(args.session)]);
      return { stopped: containerName(args.session) };
    }
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return send(res, 200, { ok: true });
  }
  if (req.method !== "POST" || !req.url.startsWith("/mcp")) {
    res.writeHead(405, { Allow: "POST" });
    return res.end();
  }
  let msg;
  try {
    const bodyText = await new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on("data", (c) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) {
          reject(Object.assign(new Error("request body too large"), { tooLarge: true }));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => resolve(Buffer.concat(chunks).toString()));
      req.on("error", reject);
    });
    msg = JSON.parse(bodyText);
  } catch (err) {
    if (err.tooLarge) return send(res, 413, { jsonrpc: "2.0", id: null,
      error: { code: -32700, message: "request body exceeds 1 MiB" } });
    return send(res, 400, { jsonrpc: "2.0", id: null,
      error: { code: -32700, message: "parse error" } });
  }
  const { id, method, params } = msg;
  try {
    if (method === "initialize") {
      return send(res, 200, { jsonrpc: "2.0", id, result: {
        protocolVersion: params?.protocolVersion || "2025-03-26",
        capabilities: { tools: {} },
        serverInfo: { name: "patchproof-local-sandbox", version: "0.1.0" },
      } });
    }
    if (method === "notifications/initialized") return send(res, 202, {});
    if (method === "ping") return send(res, 200, { jsonrpc: "2.0", id, result: {} });
    if (method === "tools/list") {
      return send(res, 200, { jsonrpc: "2.0", id, result: { tools: TOOLS } });
    }
    if (method === "tools/call") {
      const { name, arguments: args } = params || {};
      if (!TOOLS.some((t) => t.name === name)) {
        return send(res, 200, { jsonrpc: "2.0", id,
          error: { code: -32602, message: `unknown tool: ${name}` } });
      }
      try {
        const result = await toolCall(name, args);
        return send(res, 200, { jsonrpc: "2.0", id, result: {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }] } });
      } catch (toolErr) {
        return send(res, 200, { jsonrpc: "2.0", id, result: {
          content: [{ type: "text", text: `error: ${toolErr.message}` }],
          isError: true } });
      }
    }
    return send(res, 200, { jsonrpc: "2.0", id,
      error: { code: -32601, message: `method not supported: ${method}` } });
  } catch (err) {
    return send(res, 200, { jsonrpc: "2.0", id,
      error: { code: -32603, message: err.message } });
  }
});

registerShutdownCleanup();
// Crash-recovery: reclaim containers orphaned by a previous instance before
// accepting new work.
cleanupAllContainers().then((n) => {
  if (n > 0) console.log(`startup cleanup: removed ${n} leftover container(s)`);
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`local-sandbox MCP listening on http://127.0.0.1:${PORT}/mcp (image: ${IMAGE}, request-id: ${randomUUID().slice(0, 8)})`);
  });
});
