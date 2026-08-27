# Decision Log (ADR-style)

## ADR-001 — Curated CVE scenarios over live zero-day reproduction
**Status:** accepted
We reproduce *known* CVEs with public PoCs against our own demo services.
Rationale: deterministic demos within the time budget; novelty is in the
verification pipeline, not in exploit research.

## ADR-002 — Evidence-to-file pattern
**Status:** accepted
PoCs write `verdict.json`; agents return ≤15-line summaries. Rationale: keeps
token/quota use low (OpenRouter free tier), prevents log flooding in context.

## ADR-003 — Pre-baked PoC templates parameterized by the model
**Status:** accepted
LLM fills target URL/marker paths into shipped templates instead of composing
exploits. Rationale: reliability under weak free models; halves failure modes.

## ADR-004 — One TrueForge session per CVE investigation
**Status:** accepted
Bounded context per session; resumable via `state.json`. Rationale: quota caps
and cache-stable prefixes; matches harness persistence features.

## ADR-005 — Dashboard deferred until the core loop works
**Status:** accepted
Thin read-only event viewer first, approve-action second. Rationale: solo
capacity; the gate must never be blocked by UI work.

## ADR-006 — LLM-as-a-judge annotates, never decides
**Status:** accepted
A judge subagent reviews each verdict's evidence quality and OSV-range
consistency into `assessment.json`
(`agrees_with_verdict`/`confidence`/`range_check`/`rationale`). The PoC
exit code remains the only source of truth for `exploitable`; disagreement or
low confidence triggers at most one more reproduction attempt (cap 3).
Rationale: deterministic outcomes stay tamper-proof while weak-evidence cases
(e.g. HTTP 500 mistaken for "payload rejected") get caught before patching.

## ADR-008 — Keyless local Docker sandbox MCP server + host-side build boundary (updated)
**Status:** accepted (updated PR #13)
**Status:** accepted (supersedes the Daytona-based sandbox setup)
TrueForge's only built-in sandbox provider is a paid cloud service, which is
incompatible with an open-source project (and, as of June 2026, Daytona's core
went closed-source). PatchProof therefore ships its own `local-sandbox` MCP
server (Streamable HTTP, `127.0.0.1:8081/mcp`): disposable `--network none`
Docker containers — one per investigation so service and PoC share `/tmp` —
with resource limits, credential redaction, ownership labels, crash-recovery
startup cleanup, and full shutdown cleanup. This is the default and only
execution path for open-source users and CI.

**Evaluated open-source alternatives** (2026 survey):
- **Microsandbox** (Apache-2.0): local libkrun/KVM microVMs, own-kernel
  isolation (stronger than Docker), no daemon or account, official MCP server,
  OCI-image compatible. Recommended future upgrade for stronger isolation;
  requires KVM on Linux / Apple Silicon on macOS, currently beta.
- **Nightona** (AGPL-3.0): community fork of the last open Daytona release,
  self-hosted via Docker Compose/Helm. API-compatible with Daytona v0.190.0,
  but TrueForge's built-in provider hardcodes the cloud endpoint, so it cannot
  be used through the native integration anyway.
- **Beam/beta9** (AGPL-3.0) and **E2B infra** (Apache-2.0): capable but require
  Kubernetes/Nomad operations far beyond this project's scope.

Rationale: zero cost, zero accounts, same isolation contract, verified
end-to-end against TrueForge v0.1.4 tool listing.

**Build-time network boundary (added PR #13)**: containers run with `--network none`, so runtime `pip install` fails. A `sandbox_build` stage runs host-side `docker build` (temporary build-time network access) to bake pinned dependencies into images; `sandbox_exec`/`sandbox_write` then start from those pre-built images (`image=` param). The build context accepts a `files` override (e.g. patched `requirements.lock`) and uses `--no-cache` for patched builds. This preserves the offline execution contract while allowing dependency resolution at build time.

## ADR-007 — GitHub connector via header-auth token derived from gh CLI
**Status:** accepted (corrected after implementation; supersedes earlier
OAuth-first and gh-token-display drafts)
Reality check against TrueForge v0.1.4: the shipped GitHub MCP catalog entry
points at GitHub's hosted server with **header auth**, and that server exposes
**no DCR registration endpoint**, so TrueForge-side OAuth is impossible
(422 "has no DCR support"). The working setup: a repo-scope token taken from
the user's existing gh CLI credential store, written by the human directly
into `.env` without being displayed, then pasted into the connector's
header-auth field — never shown, never handled by agent sessions, and no
token-printing command is endorsed in committed docs. Rationale: one step for
anyone already using `gh`; no new secret creation; complies with the
no-secrets-in-session rule.

## ADR-009 — Product pivot to arbitrary-repo reachability triage
**Status:** accepted
Re-running *public* CVEs against *pre-packaged* scenarios proves nothing new —
the exploit is already public. The actual value is proving whether a flagged
CVE is *reachable* with attacker-controlled input in a **specific repo**.
PatchProof therefore becomes a **reachability triage engine**: dep-pin → call
sites → input-source trace → sandbox-confirmed verdict → auto-patch. The
headline outcome is `NOT_REACHABLE` (killing scanner alert-fatigue), which
scanners cannot produce. The 6 scenarios become test fixtures, never triage
targets.

## ADR-010 — OSV/CVE.org only; no hardcoded CVE data, no scenario fallback
**Status:** accepted

**Context.** The analyzer needs CVE/package/range/symbol knowledge to triage
arbitrary repos. Hand-curated symbol maps, affected-range tables, or scenario
fallbacks would harden stale knowledge into the codebase, silently drift from
the canonical records, and reintroduce exactly the false positives and silent
misses the reachability pivot exists to remove.

**Decision.** CVE.org (canonical records) and OSV.dev (affected ranges +
advisory text/symbol hints) are the **only** sources of CVE knowledge. We
**hardcode no CVE data** anywhere — no local symbol map. Symbol/range
knowledge is derived at runtime from the advisory. If neither source yields a
usable advisory for a (package, version), the honest verdict is `UNKNOWN`;
we spend **no sandbox time** on it and **never** fall back to a scenario
match. `UNKNOWN` call sites get sandbox confirmation; `NOT_REACHABLE`
requires the non-attacker-controlled input source be identified. Every
report carries a coverage/source disclaimer.

## ADR-011 — Python migration of MCP servers (uniformity standard)
**Status:** accepted
All `agent/` runtime code is Python. The two existing MCP servers
(`cve-feed-server/index.mjs`, `local-sandbox-server/index.mjs`) are migrated to
Python (`agent/mcp/cve_feed_server.py`, `agent/mcp/local_sandbox_server.py`)
with identical tool contracts, plus a new Python analyzer (`agent/analyzer/`).
Rationale: redundancy up front but a durable standard for all future MCP
servers and analyzer code. Node remains allowed only in the non-runtime
scaffolding (opencode skills/config, qodo tooling), not in the pipeline.

## ADR-012 — Mandatory sandbox + image teardown after every run
**Status:** accepted
After each investigation, the orchestrator always runs a teardown stage:
`sandbox_stop` the session container and prune built images. Rationale: sandbox
containers and images consume real host resources; leaking them across many
scans would exhaust the host and is a hard rule (see AGENTS.md / plan.md §9).

## ADR-013 — Intermittent small PRs + Qodo review loop
**Status:** accepted
Changes land in small, intermittent PRs (not one large diff) so each is easy to
understand and to Qodo-review. After a PR opens, load `qodo-get-rules` before
coding and `qodo-pr-resolver` when resolving findings; after each finding is
fixed, reply on the thread and send `/review`, looping until Qodo reports clean
code before the human merges. Rationale: smaller diffs review faster and catch
issues earlier; the loop keeps every PR clean before merge.

## ADR-014 — Lean run-graph (run spec + status store), no graph framework
**Status:** accepted
The pipeline is a DAG (fan-out reproducers, judge→reproducer loop, approval
gate) but we do **not** adopt a graph/DAG framework. Instead each run is a
**run spec** (nodes = skills, edges = handoffs, gates, retries) plus a
**per-node status store** (`run-spec.json` / `run-status.json` under
`data/output/<repo>/`). The orchestrator walks the graph through the harness,
and the status store + TrueForge per-turn events provide the per-skill
interaction/observability surface. Rationale (option A): a lean, frameworkless
representation gives us graph semantics and auditable per-node detail without
the complexity, dependency, and risk of a generic graph runtime for what is a
mostly-linear pipeline with one fan-out.

## ADR-015 — Memory & token strategy: files as memory, telemetry, eval-gated compression
**Status:** accepted
**Memory is files, not stores.** Durable state lives under `data/output/<repo>/`
(files audit, survive, resume via one small state file). Working memory is the
run graph + artifact pointers; nodes are self-contained (state, not history).
We explicitly do **not** add Redis or a vector-DB now: structured state is
queried by field from files. An optional *local, file-based* embedding index
over prior outputs for cross-run semantic recall is deferred as an eval-gated
future idea.
**Token budget.** Three ordered levers: fetch less (read-through protocol;
dep-pin short-circuits most pairs), cache more (stable prompt prefix; Python
scripts do token-heavy grunt work via `sandbox_exec`), and write/read tiny
(≤15-line summaries; artifacts carry detail). The run-status store records
`total_tokens`/request count per node so it doubles as a quota dashboard.
Retries (cap 3) re-run the narrow node only, never from the analyzer up.
**Compression tooling is deferred behind measurement.** The local
input-compression proxy (caveman) is considered only *after* telemetry shows
where spend is and only if it beats our own baseline; its output-purpose skill
is skipped (we are already terse and it can net-negative). Judge and approval
reasoning stay in full prose (security reasoning untouched).
Rationale: our structural levers (read less, cache, node-artifacts) dominate any
compression hack, and nothing is adopted before the telemetry we just added
shows it earns its place.

## ADR-016 — Security posture: hardened sandbox, external-content-as-data, secrets never in sandbox
**Status:** accepted
**Sandbox hardening.** The `local-sandbox` Python server defaults are hardened:
containers run `--network none`, as a **non-root user**, **without `--privileged`**,
**without `/var/run/docker.sock`**, with **resource limits** (CPU/mem/timeout),
**minimal/controlled mounts**, and read-only root FS where possible. `.env`,
`.git`, credentials, and `data/output/` are **never** mounted or copied into
build context or exec containers — secrets never reach untrusted exploit code.
The `sandbox_build` (network for deps) / `sandbox_exec` (offline) boundary stays
strict so a hostile PoC cannot reach the network at runtime.
**External content is data, not instructions.** Repo files, CVE/OSV advisory
text, and sandbox logs are untrusted (potentially prompt-injected). Skills never
obey instructions embedded in scanned content; the analyzer/reproducer operate
on deterministic-script outputs, and the judge reviews evidence with provenance.
**Stronger isolation** (e.g. microVMs) is a deferred eval, not a blocker.
Rationale: PatchProof runs untrusted exploit code and ships patches, so it must
not be less secure than the code it audits; secrets and host access stay out of
the sandbox, and external content is never trusted as instructions.
