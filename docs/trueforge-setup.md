# TrueForge setup (verified against v0.1.4)

TrueForge has **no config file** — models, connectors, skills, and the sandbox
are configured once via **Settings** (UI at `http://localhost:8790` or the HTTP
API), then referenced by name when creating agents. The former
`agent/trueforge.json` draft was removed: its mechanism does not exist.

## 1. Start the server

```bash
npx @truefoundry/trueforge        # serves UI + API on http://localhost:8790
```

## 2. Model provider — OpenRouter

Settings → Models → add a **custom OpenAI-compatible** endpoint:

| Field | Value |
|---|---|
| Base URL | `https://openrouter.ai/api/v1` |
| API key | value of `OPENROUTER_API_KEY` |
| Model IDs | value of `OPENROUTER_MODEL` (e.g. `deepseek/deepseek-chat-v3.1:free`) |

## 3. GitHub connector

Settings → Connectors → **GitHub** from the shipped catalog:

- Preferred: **OAuth** — authorize in the browser; no static token anywhere
- Fallback: header auth — paste a repo-scope PAT (the `GITHUB_TOKEN` from
  `.env`) into the connector's Authorization header here; storing it in `.env`
  alone does not configure the connector

Used by the orchestrator (advisory → repo matching) and the patcher (evidence PRs).

## 4. Sandbox — local Docker MCP server (no Daytona)

TrueForge's only built-in sandbox provider is **Daytona (paid)**; this project
does not use it. Instead, our own keyless sandbox runs as a local MCP server:

```bash
node agent/mcp/local-sandbox-server/index.mjs &   # serves http://127.0.0.1:8081/mcp
```

Register it once (remote-URL server, no auth):

```json
{"manifest": {"type": "remote", "name": "local-sandbox",
  "description": "Keyless local Docker sandbox.",
  "url": "http://127.0.0.1:8081/mcp"}}
```

Tools: `sandbox_exec`, `sandbox_write`, `sandbox_read`, `sandbox_stop` — each
runs inside disposable Docker containers with `--network none`, one container
per session label so the service and PoC share `/tmp` and localhost. Requires
only Docker. Leave Settings → Sandbox providers unconfigured and keep
`sandbox.enabled: false` on agents so nothing provisions Daytona.

## 5. CVE feed MCP server — dual-source legitimacy check

MCP servers in TrueForge are remote-URL only (header auth / OAuth); local stdio
servers are not supported. Our dual-source feed server
(`agent/mcp/cve-feed-server/index.mjs`) speaks stdio and therefore needs an
HTTP (streamable) transport wrapper before it can be registered.

Tools it exposes:

| Tool | Source | Purpose |
|---|---|---|
| `cve_get_cve` | CVE.org (`cveawg.mitre.org`) | canonical record: exists, state, description |
| `osv_query_package` | OSV.dev | vulns for ecosystem/package[/version] |
| `osv_get_vuln` | OSV.dev | full OSV record |
| `cve_cross_check` | both | one-call legitimacy verdict: CONFIRMED / NOT_IN_SCOPE / UNKNOWN |

Until the wrapper lands, the legitimacy gate **fails closed**: only advisories
explicitly marked `"demo": true` (via `scripts/fake_cve_injector.py`, trusted
local demo) may proceed without a cross-check, recorded as
`legitimacy: "demo-bypass"` in state.json. Once registered, triage runs
`cve_cross_check` on every advisory.
