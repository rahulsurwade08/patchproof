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

## ADR-007 — OAuth-first GitHub credential, PAT fallback
**Status:** accepted (supersedes earlier gh-token draft)
The GitHub connector authenticates via TrueForge's OAuth flow
(Settings → Connectors → GitHub; browser authorization, no static token
handled by the user or agents). For API-only use outside the harness, a classic
PAT placed in `.env` remains a documented fallback. Agent sessions never invoke
token-printing commands, and docs never endorse them.
Rationale: zero static credentials is the strongest security posture and keeps
setup to one browser click for contributors who already have a GitHub account.
