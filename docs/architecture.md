# Architecture

## Pipeline

```
                 ┌───────────────────────────────────────────────────┐
                 │        TrueForge session (one per CVE)            │
  CVE advisory ─►│  ORCHESTRATOR                                     │
  (cve-feed /    │  • match advisory → scenario repo (github MCP)    │
   data/inbox)   │  • spawn reproducer subagent per candidate        │
                 │        │                                          │
                 │  ┌────▼─────┬──────────┐                           │
                 │  Reproducer Reproducer …  (parallel)              │
                 │  REPRODUCER: start service @pinned deps,          │
                 │  run PoC, write verdict.json                      │
                 │        │ verdict summaries merged                 │
                 │        ▼                                          │
                 │  JUDGE: review evidence quality + ranges          │
                 │  (assessment.json; never flips the verdict)       │
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
| Judge | `agent/prompts/judge.md` | LLM-as-a-judge: reviews verdict evidence quality/consistency, writes `assessment.json`, never flips outcomes |
| Patcher | `agent/prompts/patcher.md` | Dependency bump + test suite in sandbox + evidence PR |
| Verifier | `agent/prompts/verifier.md` | Post-approval re-verification against staging |
| cve-feed | `agent/mcp/cve-feed-server/index.mjs` | Dual-source legitimacy: CVE.org canonical records + OSV.dev package matching (`cve_get_cve`, `osv_query_package`, `osv_get_vuln`, `cve_cross_check`) — needs an HTTP wrapper before TrueForge registration; until then advisories arrive via `data/inbox/` |
| github-mcp | GitHub connector from the TrueForge catalog (`docs/trueforge-setup.md`) | Repos, PRs, evidence comments |
| local-sandbox | `agent/mcp/local-sandbox-server/index.mjs` (Streamable HTTP, `127.0.0.1:8081/mcp`) | Keyless execution sandbox: `sandbox_build` + `sandbox_exec/write/read/stop` (offline) |
| Test-runner | `agent/prompts/test-runner.md` + `scripts/run_gate_before_push.sh` + `scripts/install-hooks.sh` | Subagent gate: `sandbox_build` image + `sandbox_exec` pytest + PoC → `test_gate.json`; tracked pre-push hook installer |
| Scenario services | `scenarios/` | Deliberately vulnerable demo services with deterministic PoCs |
| Staging target | `infra/docker-compose.yml` | Local deploy destination behind the approval gate |

## State model (memory stays out of context)

- Per-CVE investigation state lives in files, not chat history:
  - `scenarios/<id>/state.json` — status, attempt count, current stage
- `scenarios/<id>/verdict.json` — machine-readable outcome
  - `scenarios/<id>/assessment.json` — LLM-judge review of the verdict:
    `{cve_id, agrees_with_verdict, confidence, range_check, rationale}`
  - raw logs stay in sandbox files; agents read ≤15-line summaries
- Any session resumes by reading one small state file.

## TrueForge capability map

| Capability | Where PatchProof uses it |
|---|---|
| MCP tools | `github` + custom `cve-feed` (CVE.org + OSV.dev) + `local-sandbox` (keyless Docker execution) servers |
| Sandbox execution | PoC exploit code and patch test suites — via the `local-sandbox` MCP server, never on the host |
| Human approval | Merge & deploy-to-staging pause |
| Subagents | Parallel reproducer fan-out per CVE |
| Session persistence | Long-running scans survive refresh/reconnect |
| Skills | `agent/skills/cve-triage/SKILL.md` |
