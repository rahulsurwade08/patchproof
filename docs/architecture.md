# Architecture

## Pipeline

```
                 ┌───────────────────────────────────────────────────┐
                 │        TrueForge session (one per CVE)            │
  CVE advisory ─►│  ORCHESTRATOR                                     │
  (nvd-mcp /     │  • match advisory → scenario repo (github MCP)    │
   data/inbox)   │  • spawn reproducer subagent per candidate        │
                 │        │                                          │
                 │  ┌────▼─────┬──────────┐                           │
                 │  Reproducer Reproducer …  (parallel)              │
                 │  REPRODUCER: start service @pinned deps,          │
                 │  run PoC, write verdict.json                      │
                 │        │ verdict summaries merged                 │
                 │        ▼                                          │
                 │  PATCHER: bump dep → test suite in sandbox →      │
                 │  open PR with evidence                            │
                 │        ▼                                          │
                 │  ■ APPROVAL GATE: merge & deploy staging          │
                 │        ▼ human approves                           │
                 │  VERIFIER: re-run PoC vs staging → report         │
                 └───────────────────────────────────────────────────┘
```

## Components

| Component | Location | Role |
|---|---|---|
| Orchestrator | `agent/prompts/orchestrator.md` | Matches advisories to repos, fans out reproducers, merges verdicts, owns the approval gate |
| Reproducer | `agent/prompts/reproducer.md` | Sandbox contract: service @pinned deps + PoC execution |
| Patcher | `agent/prompts/patcher.md` | Dependency bump + test suite in sandbox + evidence PR |
| Verifier | `agent/prompts/verifier.md` | Post-approval re-verification against staging |
| nvd-mcp | `agent/mcp/nvd-server/index.mjs` | Custom MCP server over the NVD REST API (`nvd_list_recent`, `nvd_get_cve`) |
| github-mcp | GitHub connector from the TrueForge catalog (`docs/trueforge-setup.md`) | Repos, PRs, evidence comments |
| Scenario services | `scenarios/` | Deliberately vulnerable demo services with deterministic PoCs |
| Staging target | `infra/docker-compose.yml` | Local deploy destination behind the approval gate |

## State model (memory stays out of context)

- Per-CVE investigation state lives in files, not chat history:
  - `scenarios/<id>/state.json` — status, attempt count, current stage
  - `scenarios/<id>/verdict.json` — machine-readable outcome
  - raw logs stay in sandbox files; agents read ≤15-line summaries
- Any session resumes by reading one small state file.

## TrueForge capability map

| Capability | Where PatchProof uses it |
|---|---|
| MCP tools | `github` + custom `nvd` servers |
| Sandbox execution | PoC exploit code and patch test suites |
| Human approval | Merge & deploy-to-staging pause |
| Subagents | Parallel reproducer fan-out per CVE |
| Session persistence | Long-running scans survive refresh/reconnect |
| Skills | `agent/skills/cve-triage/SKILL.md` |
