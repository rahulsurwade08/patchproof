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

- Auth type: header auth
- Header: `Authorization: Bearer <GITHUB_TOKEN>` (repo-scope PAT)

Used by the orchestrator (advisory → repo matching) and the patcher (evidence PRs).

## 4. Sandbox provider — Daytona

Daytona is the **only** supported sandbox provider today.

Settings → Sandbox providers → Daytona preset → paste `DAYTONA_API_KEY`.

Enable the sandbox per agent (`config.sandbox.enabled` in the agent spec).
The sandbox is provisioned on demand and reused across turns within a session,
which is what the PoC/service shared-`/tmp` contract relies on.

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

Until the wrapper lands, advisories still arrive via `data/inbox/`
(`scripts/fake_cve_injector.py`) and the orchestrator treats them as
pre-confirmed; triage should run `cve_cross_check` once the server is
registered.
