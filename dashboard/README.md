# Dashboard — deferred

Thin live-status UI for PatchProof. Build ONLY after the core agent loop is
solid (see plan.md §7 and docs/decisions.md ADR-005).

## Scope (in build order)

1. Read-only event viewer: tool calls, sandbox job status, verdicts — fed by
   TrueForge's HTTP API / session events.
2. "Waiting on" panel surfacing the approval gate with an approve action.

## Non-goals

- No custom chat surface (TrueForge's own UI covers it).
- No persistence beyond the harness's own session storage.
