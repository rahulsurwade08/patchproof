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

## ADR-008 — Local Docker sandbox MCP server over Daytona
**Status:** accepted (supersedes the Daytona-based sandbox setup)
TrueForge's only built-in sandbox provider is Daytona (paid), which is
incompatible with an open-source project. PatchProof instead ships its own
`local-sandbox` MCP server (Streamable HTTP, `127.0.0.1:8081/mcp`) that runs
commands in disposable `--network none` Docker containers — one per
investigation so service and PoC share `/tmp`. The built-in provider stays
disabled. Rationale: zero cost, zero cloud accounts for contributors, same
isolation contract; verified end-to-end against TrueForge v0.1.4 tool listing.

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
