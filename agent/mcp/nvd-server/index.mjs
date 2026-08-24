#!/usr/bin/env node
// Minimal MCP stdio server exposing the NVD CVE feed.
// Tools:
//   nvd_list_recent  — newest published CVEs (resultsPerPage, startIndex)
//   nvd_get_cve      — full record for one CVE id
// Speaks newline-delimited JSON-RPC 2.0 on stdio (MCP stdio transport).
// No dependencies; Node >= 18 (built-in fetch).

import readline from "node:readline";

const API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const HEADERS = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};

const TOOLS = [
  {
    name: "nvd_list_recent",
    description:
      "List recently published CVEs from the NVD feed. Returns compact summaries: id, description, affected products.",
    inputSchema: {
      type: "object",
      properties: {
        resultsPerPage: { type: "number", default: 5 },
        startIndex: { type: "number", default: 0 },
      },
    },
  },
  {
    name: "nvd_get_cve",
    description: "Fetch one CVE record by id, e.g. CVE-2020-14343.",
    inputSchema: {
      type: "object",
      properties: { cveId: { type: "string" } },
      required: ["cveId"],
    },
  },
];

function summarize(item) {
  const cve = item.cve ?? {};
  const desc =
    (cve.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "";
  // Compact product list from configurations nodes when present
  const prods = new Set();
  for (const cfg of item.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        const parts = (match.criteria ?? "").split(":");
        if (parts.length > 4) prods.add(`${parts[3]} ${parts[5] ?? ""}`.trim());
      }
    }
  }
  return { id: cve.id, description: desc.slice(0, 400), products: [...prods] };
}

async function nvdList({ resultsPerPage = 5, startIndex = 0 } = {}) {
  const url = `${API}?resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;
  const res = await fetch(url, { headers: HEADERS });
  if (!res.ok) throw new Error(`NVD API ${res.status}`);
  const body = await res.json();
  return {
    totalResults: body.totalResults,
    cves: (body.vulnerabilities ?? []).map((v) => summarize(v)),
  };
}

async function nvdGet({ cveId }) {
  const res = await fetch(`${API}?cveId=${encodeURIComponent(cveId)}`, {
    headers: HEADERS,
  });
  if (!res.ok) throw new Error(`NVD API ${res.status}`);
  const body = await res.json();
  const items = body.vulnerabilities ?? [];
  if (!items.length) throw new Error(`${cveId} not found`);
  return summarize(items[0]);
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function dispatch(method, params) {
  if (method === "initialize") {
    return {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "patchproof-nvd", version: "0.1.0" },
    };
  }
  if (method === "tools/list") return { tools: TOOLS };
  if (method === "tools/call") {
    const { name, arguments: args } = params;
    let text;
    try {
      text = JSON.stringify(
        name === "nvd_list_recent"
          ? await nvdList(args)
          : await nvdGet(args),
        null, 2
      );
    } catch (err) {
      text = `error: ${err.message}`;
    }
    return { content: [{ type: "text", text }] };
  }
  throw new Error(`method not supported: ${method}`);
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id === undefined) return; // notifications: ignore
  try {
    send({ jsonrpc: "2.0", id: msg.id, result: await dispatch(msg.method, msg.params ?? {}) });
  } catch (err) {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32601, message: err.message },
    });
  }
});
