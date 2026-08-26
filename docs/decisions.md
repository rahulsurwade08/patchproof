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

## ADR-008 — Keyless local Docker sandbox MCP server (cloud providers removed)
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
