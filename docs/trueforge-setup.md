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

## 5. NVD MCP server — open item

MCP servers in TrueForge are remote-URL only (header auth / OAuth); local stdio
servers are not supported. Our custom NVD feed server
(`agent/mcp/nvd-server/index.mjs`) speaks stdio and therefore cannot be
registered as-is. Options:

1. Wrap it behind an HTTP (streamable) transport and register its URL.
2. Skip live-NVD for now: advisories arrive via `data/inbox/`
   (`scripts/fake_cve_injector.py`), which the orchestrator reads directly.

Decision pending; option 2 unblocks the first end-to-end run.
