# Welcome to PatchProof

Proves whether a scanner-flagged CVE is actually reachable in your repo,
runs the exploit in an isolated Docker sandbox, then produces a code-level
fix and verifies it.

**Quick start — paste this and edit:**

```
target_repo: https://github.com/owner/repo
cve_id: CVE-YYYY-NNNNN  (optional — auto-discover if omitted)
mode: triage            (or reproduce-only / patch-and-verify)
```

**What you get back:**
- `data/output/<repo>/verdict.json` on your machine
- A short chat report with vulnerable code (file:line) + evidence
- For `patch-and-verify`: a PR with a unified diff of the code-level fix

**Rules:**
- Never paste API keys or tokens.
- Never ask the agent to bypass its tools.
- Exploits run only in the sandbox — never on your host.
- The approval gate pauses exploit/build requests for your confirmation.
