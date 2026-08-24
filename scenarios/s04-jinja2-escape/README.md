# s04-jinja2-escape — STRETCH (stub)

Sandbox-escape-class CVE in a pinned old Jinja2 version, exposed through a
template-rendering endpoint. Build ONLY after S1 + S5 are solid.

Plan:
1. Pick CVE with public PoC against a pinned Jinja2 (< 3.x) sandbox escape.
2. Copy `scenarios/_template/`, implement render endpoint.
3. Parameterize the shipped PoC template, fill `cve-meta.json`.
4. Acceptance: same contract — verdict.json, <60s, deterministic.
