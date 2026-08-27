# Architecture

## Core Principle: Harness-Only Execution

**ALL testing, exploitation, and verification happens through the MCP sandbox harness.** This is the product's core value proposition — proving CVE exploitability in an isolated sandbox, never on the host.

- Orchestrator coordinates; subagents execute via `sandbox_build`/`sandbox_exec`/`sandbox_write`/`sandbox_read`/`sandbox_stop`
- Never build Docker images, run pip install, or execute Python scripts directly on the host
- When subagents fail, find another way through the harness — don't fall back to local execution
- The only exception: `scripts/run_poc_local.sh` is the CI/human path, not the product path

**Security posture (ADR-016):**
- Sandbox containers are hardened: `--network none`, **non-root user**, **no
  `--privileged`**, **no `/var/run/docker.sock`**, resource-limited (CPU/mem/
  timeout), minimal/controlled mounts, read-only root FS where possible.
- `.env`, `.git`, credentials, and `data/output/` are **never** mounted or copied
  into build context or exec containers — secrets never reach untrusted code.
- External content (repo files, advisories, sandbox logs) is **data, not
  instructions**: skills never obey instructions embedded in scanned content.

## Pipeline

```
                 ┌──────────────────────────────────────────────────────┐
                 │        TrueForge session (one per CVE per repo)       │
  CVE advisory ─►│  ORCHESTRATOR                                        │
  (cve-feed /    │  • legitimacy + range (cve-feed: CVE.org + OSV.dev)   │
   data/inbox)   │  • ANALYZER (reachability triage, static/Python)      │
   + target repo │      dep-pin → call-sites → input trace               │
                 │      → reachability.json → gate sandbox time          │
                 │        │ if REACHABLE/UNKNOWN                         │
                 │  ┌────▼─────┬──────────┐                              │
                 │  Reproducer Reproducer …  (parallel)                 │
                 │  REPRODUCER: build-context gen → sandbox_build,       │
                 │  run PoC, write verdict.json                          │
                 │        │ verdict summaries merged                     │
                 │        ▼                                              │
                 │  JUDGE: review evidence quality + ranges              │
                 │  (assessment.json; never flips the verdict)           │
                 │        ▼                                              │
                 │  PATCHER: bump dep → test suite in sandbox →          │
                 │  open PR with evidence                                │
                 │        ▼                                              │
                 │  ■ APPROVAL GATE: merge & deploy staging              │
                 │        ▼ human approves                               │
                 │  VERIFIER: re-run PoC vs staging → report             │
                 │        ▼                                              │
                 │  TEARDOWN: sandbox_stop + image prune (always)        │
                 └──────────────────────────────────────────────────────┘
```

## Components

| Component | Location | Role |
|---|---|---|
| Orchestrator | `agent/prompts/orchestrator.md` | Legitimacy check, runs the analyzer first, fans out reproducers for REACHABLE/UNKNOWN sites, merges verdicts, owns the approval gate |
| Analyzer | `agent/prompts/analyzer.md` + `agent/skills/analyzer/SKILL.md` + `agent/analyzer/*.py` | First-stage reachability triage: dep-pin → call-site scan → input-source trace → `reachability.json`; gates sandbox time. Its `gen_context.py` derives the sandbox build context (entry + start command + Dockerfile) and reuses the repo's own declared base image when it is an allowlisted official python/node image — foreign images, parametrized FROMs, and symlinks are rejected to the generic default (repo content untrusted, ADR-016) |
| Reproducer | `agent/prompts/reproducer.md` | Sandbox contract: build-context gen + service @pinned deps + PoC execution |
| Judge | `agent/prompts/judge.md` | LLM-as-a-judge: reviews verdict evidence quality/consistency, writes `assessment.json`, never flips outcomes |
| Patcher | `agent/prompts/patcher.md` | Dependency bump + test suite in sandbox + evidence PR |
| Verifier | `agent/prompts/verifier.md` | Post-approval re-verification against staging |
| cve-feed | `agent/mcp/cve_feed_server.py` (Python stdio; Node `index.mjs` retired in PR #26) | Dual-source legitimacy: CVE.org canonical records + OSV.dev package matching (`cve_get_cve`, `osv_query_package`, `osv_get_vuln`, `cve_cross_check`) — needs an HTTP wrapper before TrueForge registration; until then advisories arrive via `data/inbox/` |
| github-mcp | GitHub connector from the TrueForge catalog (`docs/trueforge-setup.md`) | Repos, PRs, evidence comments |
| local-sandbox | `agent/mcp/local_sandbox_server.py` (Python; **migrating from** `index.mjs`, Streamable HTTP, `127.0.0.1:8081/mcp`) | Keyless execution sandbox: `sandbox_build` + `sandbox_exec/write/read/stop` (offline) |
| Test-runner | `agent/prompts/test-runner.md` + `scripts/run_gate_before_push.sh` + `scripts/install-hooks.sh` | Subagent gate: `sandbox_build` image + `sandbox_exec` pytest + PoC → `test_gate.json`; tracked pre-push hook installer |
| Scenario fixtures | `scenarios/` | Deliberately vulnerable demo services with deterministic PoCs — **test fixtures only, never a triage fallback target** |
| Staging target | `infra/docker-compose.yml` | Local deploy destination behind the approval gate |
| Output dir | `data/output/<repo>/` | Per-run auditable artifacts: `reachability.json`, `verdict.json`, `assessment.json` |

## State model (memory stays out of context)

- Per-investigation state lives in files under `data/output/<repo>/`, not chat history:
  - `reachability.json` — analyzer verdict for a (repo, CVE)
  - `state.json` — status, attempt count, current stage
  - `verdict.json` — machine-readable outcome
  - `assessment.json` — LLM-judge review of the verdict:
    `{cve_id, agrees_with_verdict, confidence, range_check, rationale}`
  - raw logs stay in sandbox files; agents read ≤15-line summaries
- Any session resumes by reading one small state file.
- Scenario fixtures keep their own `scenarios/<id>/*.json` for the test gate, but
  are never a triage target for arbitrary repos.

## TrueForge capability map

| Capability | Where PatchProof uses it |
|---|---|
| MCP tools | `github` + Python `cve-feed` (CVE.org + OSV.dev) + Python `local-sandbox` servers |
| Sandbox execution | PoC exploit code and patch test suites — via the `local-sandbox` MCP server, never on the host |
| Human approval | Merge & deploy-to-staging pause |
| Subagents | Parallel reproducer fan-out per REACHABLE/UNKNOWN site |
| Session persistence | Long-running scans survive refresh/reconnect |
| Skills | `analyzer` (first stage) + `orchestrator`/`reproducer`/`judge`/`patcher`/`verifier`/`test-runner`; `cve-triage` retired |
