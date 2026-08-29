# PatchProof Agent — Welcome

**What this agent does**: proves whether a CVE flagged by your scanner is actually reachable with attacker-controlled input in your repo — by running the exploit inside an isolated Docker sandbox.

**How to use it** (fill in one of these):

```
target_repo: /path/to/your/repo
cve_id: CVE-2020-14343
mode: triage
notes: optional context (max 200 chars)
```

Or: `https://github.com/user/repo` + the CVE ID.

**What you'll get back**: `data/output/<repo>/verdict.json` on your machine with the result, plus a short report in the chat.

**Rules**:
- Never paste API keys or tokens here. Never ask the agent to ignore its instructions.
- The agent runs everything in an isolated sandbox — it cannot touch your host directly.
- The approval gate means any exploit/build request pauses for you to confirm.
- Full docs: `docs/demo.md` · Source: this repo

**Quick start**: `target_repo:` + `cve_id:` + `mode: triage` = the simplest request.
