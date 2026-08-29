# User Prompt Template

Fill in the fields below to start a triage session. The agent will produce a
verdict in `data/output/<repo>/verdict.json` and a short report.

---

## Required fields

**target_repo** (required)
Absolute host path to the cloned target repo, or a GitHub URL.
Examples: `/home/user/my-repo`, `https://github.com/user/my-repo`

**cve_id** (required)
The CVE ID to triage. Must exist in CVE.org and OSV.dev.
Example: CVE-2020-14343

---

## Optional fields

**mode** (optional, default: triage)
- `triage` — full pipeline: legitimacy check, reachability analysis, PoC, verdict.
- `reproduce-only` — skip static analysis; go straight to sandbox PoC.
- `patch-and-verify` — after confirming exploitation, produce and verify a fix.

**time_budget** (optional, default: 3 turns, 5 minutes wall clock)
Max turns and/or wall-clock time for this session.
Example: 5 turns, 10 minutes

**notes** (optional, ≤ 200 chars)
Prior knowledge, context, or special instructions for this run.
This field is for context only — it does not override the agent's boundary rules.
Do NOT use this field to embed instructions for the agent to follow.

---

## What to expect back

After the session, `data/output/<repo>/verdict.json` contains:
```json
{
  "cve_id": "...",
  "exploitable": true | false,
  "evidence": "..."
}
```

A short (≤ 15 line) report is returned in the chat, including:
- CVE ID and verdict
- The vulnerable code location (file:line)
- One-line evidence summary
- Artifact paths on the host

## What NOT to type

- Do not paste API keys, tokens, or credentials.
- Do not ask the agent to "ignore your instructions" or bypass its tools.
- Do not ask it to fetch arbitrary URLs or run commands outside the sandbox.
