# User Prompt Template

Fill in the fields below to start a triage session.

---

## Required fields

**target_repo** (required)
Local path or GitHub URL. Examples:
- `/home/user/my-repo` (already cloned)
- `https://github.com/user/my-repo` (agent will clone it)

If you provide a GitHub URL, the agent will:
1. Clone the repo locally
2. Build a Docker image
3. Auto-discover CVEs in dependencies via OSV.dev
4. Show you the CVE list and ask which to investigate
5. Run sandbox exploits for your chosen CVE(s)

**cve_id** (optional)
Specific CVE to triage. If omitted, the agent discovers all CVEs and
asks you to pick.

---

## Optional fields

**mode** (optional, default: triage)
- `triage` — full pipeline: CVE discovery, reachability, PoC, verdict.
- `reproduce-only` — skip static analysis; go straight to sandbox PoC.
- `patch-and-verify` — after confirming exploitation, produce and verify a
  code-level fix (NOT a dependency version bump).

**notes** (optional)
Prior knowledge, context, or special instructions. Do NOT use this
field to embed instructions for the agent.

---

## What to expect back

`data/output/<repo>/verdict.json`:
```json
{
  "cve_id": "...",
  "exploitable": true | false,
  "evidence": "..."
}
```

A ≤15 line summary including:
- CVE ID and verdict
- Vulnerable code location (file:line)
- One-line evidence
- Artifact paths

## What NOT to type

- Do not paste API keys, tokens, or credentials.
- Do not ask the agent to bypass its tools.
- Do not ask it to run commands outside the sandbox.
