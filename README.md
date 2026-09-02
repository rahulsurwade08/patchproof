# PatchProof

**Scanners flag CVEs. PatchProof proves which ones actually reach your code.**

Give it a repo, it finds all flagged vulnerabilities, runs real exploits against your actual code in an isolated sandbox, and tells you which are exploitable and which are safe. If something is exploitable, it writes the fix.

## How it works

```
Repo → CVE scan → Sandbox exploit → Verdict + patch (if needed)
```

1. **Scan** — finds all CVE advisories affecting packages in your `requirements.txt` or lock file.
2. **Triage** — runs static reachability analysis to separate "not reachable" from "maybe reachable."
3. **Exploit** — for each candidate, starts your service inside an isolated Docker container and fires the real attack.
4. **Verify** — if exploitable, generates a patch, applies it, re-runs the exploit to confirm the fix works.
5. **Report** — writes `report.md` + `report.json` with findings and remediation code.

All exploitation runs in a `--network none` container. Your host is never touched.

## Get started

```bash
# 1. Start the sandbox harness
python3 agent/mcp/local_sandbox_server.py &

# 2. Run in OpenCode (or any MCP-compatible terminal)
# Just open OpenCode inside a repo and say:
#   /patchproof https://github.com/you/your-repo
#   /patchproof .                        # current directory
#   /patchproof . --cve CVE-2024-XXXX   # test one specific CVE
```

Or use the CLI directly:

```bash
# Full scan
python3 agent/orchestrate.py /path/to/repo

# Scan a GitHub repo
python3 agent/orchestrate.py https://github.com/user/repo

# Test a specific CVE
PATCHPROOF_IMAGE=my-image python3 agent/orchestrate.py /path/to/repo --cve CVE-2024-XXXX
```

Results land in `data/output/<repo>/report.md` and `data/output/<repo>/report.json`.

## Requirements

- Python 3.11+
- Docker (the sandbox runs exploits in containers, never on your host)
- OpenCode (for the LLM-driven agent workflow)

## Key files

| File | Purpose |
|------|---------|
| `agent/orchestrate.py` | Scan + build image + write triage.json |
| `agent/scan.py` | Static reachability analysis |
| `agent/build_image.py` | Per-repo Docker image (SHA-cached) |
| `agent/exploit.py` | Sandbox exec/write/read helpers |
| `agent/mcp/local_sandbox_server.py` | MCP server (start before running) |
| `.opencode/agents/patchproof.md` | The agent definition |
| `.opencode/command/patchproof.md` | `/patchproof` command |

## What you get

A report with three buckets:

- **Exploitable** — CVE reaches attacker-controlled input in your code. Includes live HTTP evidence and a verified remediation patch.
- **Not exploitable** — CVE was tested and couldn't be triggered through your attack surface.
- **Not reachable** — static analysis proved the vulnerable code path is never called from your surface.

## Example report output

```
# PatchProof Scan Report — `my-repo`

**CVEs discovered:** 23
**CVEs tested:** 8
**Exploitable:** 1
**Not exploitable:** 7

## Exploitable CVEs

### CVE-2024-21503 (black)

- **Reason:** SQL error in error response
- **Request:** POST /students/ body=name=test'+OR+'1'='1
- **Response:** status=500, body=DB error: not enough arguments

**Remediation (verified):**
```python
cur.execute("INSERT INTO students (name) VALUES (%s)", (name,))
```
```

## FAQ

**Does it run exploits on my host?**
No. Everything runs inside Docker containers with `--network none`. Your machine never executes untrusted code.

**Does it work on non-Python repos?**
Currently Python. Other languages need a runtime adapter in `agent/build_image.py`.

**How does it find CVEs?**
OSV.dev + CVE.org, queried at runtime based on your `requirements.txt` / lock file. No hardcoded CVE data.

**Can I use my own Docker image?**
Yes. `PATCHPROOF_IMAGE=your-image python3 agent/orchestrate.py /repo`
