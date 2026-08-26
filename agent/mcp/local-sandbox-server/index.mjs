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
import { randomUUID } from "node:crypto";

const PORT = Number(process.env.LOCAL_SANDBOX_PORT || 8081);
const IMAGE = process.env.LOCAL_SANDBOX_IMAGE || "python:3.11-slim";
const MAX_OUTPUT = 20000;

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
  // Sanitized: sessions are agent-chosen labels.
  const safe = String(session || "default").replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 40);
  return `patchproof-sbx-${safe}`;
}

async function ensureContainer(session) {
  const name = containerName(session);
  const running = await docker(["inspect", "-f", "{{.State.Running}}", name]);
  if (running.code === 0 && running.stdout.trim() === "true") return name;
  await docker(["rm", "-f", name]);
  const started = await docker([
    "run", "--rm", "-d",
    "--name", name,
    "--network", "none",
    "--pids-limit", "512",
    "--memory", "1g",
    "--cpus", "1",
    "-w", "/srv",
    IMAGE,
    "sh", "-c", "sleep infinity",
  ]);
  if (started.code !== 0) {
    throw new Error(`failed to start container: ${started.stderr}`);
  }
  return name;
}

const TOOLS = [
  {
    name: "sandbox_exec",
    description:
      "Run a shell command inside an isolated local Docker container for the given session. " +
      "The container has NO network access; services started inside it are reachable only at " +
      "127.0.0.1 within the same container. First call starts the container (may take a few " +
      "seconds); later calls reuse it so files persist between calls.",
    inputSchema: {
      type: "object",
      properties: {
        session: { type: "string", description: "logical session label; containers are isolated per session" },
        command: { type: "string", description: "shell command to execute inside the container" },
        timeout_secs: { type: "number", description: "per-command timeout (default 60, max 600)" },
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
    case "sandbox_exec": {
      const name2 = await ensureContainer(args.session);
      const timeout = Math.min(Number(args.timeout_secs || 60), 600);
      const res = await docker(
        ["exec", "-w", "/srv", name2, "sh", "-c", String(args.command)],
        { timeoutMs: timeout * 1000 + 5000 }
      );
      return {
        exit_code: res.code,
        stdout: res.stdout,
        stderr: res.stderr,
        container: name2,
      };
    }
    case "sandbox_write": {
      const name2 = await ensureContainer(args.session);
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
        content: res.stdout };
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
    msg = JSON.parse(await new Promise((resolve, reject) => {
      let buf = "";
      req.on("data", (c) => (buf += c));
      req.on("end", () => resolve(buf));
      req.on("error", reject);
    }));
  } catch {
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

server.listen(PORT, "127.0.0.1", () => {
  console.log(`local-sandbox MCP listening on http://127.0.0.1:${PORT}/mcp (image: ${IMAGE}, request-id: ${randomUUID().slice(0, 8)})`);
});
