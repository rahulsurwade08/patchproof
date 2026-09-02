---
description: Run PatchProof on a repo path or git URL. Scans for CVEs, runs real exploits in a sandbox, generates verified patches, writes report.md and report.json.
agent: patchproof
---

The user is invoking PatchProof. Args: $ARGUMENTS (a local path or git URL; defaults to current directory if empty).

1. Resolve the repo:
   - If $ARGUMENTS is empty: use the current working directory.
   - If it starts with `/`, `./`, `../`, or exists locally: use as a local path.
   - If it looks like a URL: it's a git URL to clone.

2. Run the mechanical driver:
   `python3 agent/orchestrate.py <resolved-repo>`

3. Read the triage.json it writes to data/output/<repo>/triage.json.

4. For each CVE in triage['to_test'] (the agent decides order by severity):
   - You (LLM) generate a PoC script.
   - Use `agent/exploit.py:run_exploit_for_cve()` to run it.
   - Read /srv/verdict.json from the container.
   - If exploitable: you write a patch, apply via `sandbox_write`,
     restart the service, re-run the same PoC, verify the post-patch
     verdict is non-exploitable.

5. Write data/output/<repo>/report.json and report.md.

6. Tell the user where the report is.

Do not stub out the LLM-driven parts (PoC generation, patch generation,
verdict judgment). The user is paying for an actual reasoning agent.
