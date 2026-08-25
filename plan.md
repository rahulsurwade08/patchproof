# PatchProof — Plan

> Scanners tell you you're *maybe* vulnerable. PatchProof proves whether you
> actually are — by exploiting your exact code inside an isolated sandbox —
> then fixes it, verifies the fix works, and asks permission before shipping.

## 1. Mission

Dependency-vulnerability alerts are noisy because scanners do pattern matching
on version numbers: they cannot tell whether *your* code path triggers the bug.
The result is alert fatigue and unfixed vulnerabilities. PatchProof closes the
loop empirically:

1. A CVE lands for a library a scenario service depends on.
2. A reproducer subagent exploits the exact pinned versions inside the
   TrueForge sandbox — never on the host.
   - Exploit fails → case closed as **NOT AFFECTED**, alert dismissed.
   - Exploit succeeds → patcher bumps the dependency, runs the test suite in
     the sandbox, opens a PR with the exploit output attached as evidence.
3. Deploying the fix to staging is irreversible → the agent pauses for human
   approval.
4. After approval, the verifier re-runs the original PoC against staging to
   confirm the vulnerability is dead.

## 2. Decisions

| Decision | Value |
|---|---|
| Location | `~/Projects/patchproof` |
| Team | Solo |
| Scenario stack | Python only |
| Core scenarios | S1 PyYAML RCE (CVE-2020-14343) · S5 negative case (same CVE, safe usage) |
| Stretch scenario | S4 Jinja2 sandbox escape (stub only) |
| UI | Thin live dashboard, built after the core loop works; TrueForge chat UI is the fallback surface |
| Models | OpenRouter free models via BYOK; assume ~50 req/day ceiling until tested |
| Repo | Public from day 1 · runtime is localhost-only, on demand |

## 3. Sponsor tools

- **TrueForge** is the runtime, not a wrapper: every pipeline step maps to a
  harness capability (see §4).
- **Qodo** reviews pull requests from day 1; findings are resolved before merge.

## 4. Architecture

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

Capability map:

| Harness capability | Where PatchProof uses it |
|---|---|
| MCP tools | `github` (repos/PRs) + custom `cve-feed` server (CVE.org + OSV.dev cross-check, `agent/mcp/cve-feed-server`) |
| Sandbox execution | PoC exploit code and patch test suites — never run on host |
| Human approval | Merge-and-deploy-to-staging step pauses until approved |
| Subagents | One reproducer per CVE candidate, parallel fan-out |
| Session persistence | Scans span hours; sessions survive refresh/reconnect |
| Skills | `cve-triage` instruction pack loaded when a task matches |

## 5. Scenario acceptance criteria

- PoC exits `0` with `verdict.json` = `{cve_id, exploitable, evidence}` in <60 s,
  deterministically.
- Service starts with `uvicorn`; staging deploys via `infra/docker-compose.yml`.
- S5 must self-conclude `NOT AFFECTED` using the same generic PoC contract.
- Run service and PoC inside the same sandbox instance (shared `/tmp` marker).

## 6. Cost & quota notes

- Evidence is written to files; agents return ≤15-line summaries, never raw logs.
- Pre-baked PoC templates: LLM fills parameters only.
- One session per CVE; hard retry cap of 3; batched verdict merges.
- Cache-stable prompt prefixes (volatile content last); shortlist free models
  before committing to one.

## 7. Risks & fallbacks

| Risk | Fallback |
|---|---|
| Flaky PoC generation | Ship pre-baked verified PoCs with each scenario |
| Weak tool-calling on free models | Deterministic scripts do mechanical steps; narrow scope at S1+S5 |
| Time overrun | Cut order: S4 → S5 automation depth → dashboard. Approval gate never cut |

## 8. Pointers

- `docs/architecture.md` — diagrams + capability map
- `docs/demo.md` — end-to-end walkthrough of a demo run
- `docs/decisions.md` — ADR log
