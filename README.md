# PatchProof

**Scanners flag CVEs. PatchProof proves which ones actually reach your code.**

Give it a repo, it finds all flagged vulnerabilities, runs real exploits against your actual code in an isolated sandbox, and tells you which are exploitable and which are safe. If something is exploitable, it writes and verifies the fix.

## How it works

PatchProof runs entirely inside Docker containers with `--network none` — your host never executes untrusted code.

The flow has two parts: a mechanical driver (Python) that clones, scans, and builds the image, and an LLM agent that generates PoCs, runs exploits, judges verdicts, and produces patches.

```
User invokes /patchproof
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  agent/orchestrate.py (Python — mechanical)             │
│                                                         │
│  1. Clone or resolve repo (local path or GitHub URL)  │
│  2. agent/scan.py — query OSV.dev for every package   │
│     → run reachability analysis per CVE                │
│     → bucket as to_test / not_reachable               │
│  3. agent/build_image.py — build Docker image          │
│     (SHA-cached: pp-sandbox:<repo>-<sha>)             │
│  4. Write data/output/<repo>/triage.json              │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  PatchProof LLM agent (the brain)                      │
│                                                         │
│  For each CVE in triage['to_test']:                   │
│    • Read reachability.json (call sites)              │
│    • Generate a PoC script (HTTP request)             │
│    • sandbox_write /srv/poc.py                        │
│    • sandbox_exec — start service, run PoC             │
│    • sandbox_read /srv/verdict.json                   │
│    • Judge: was that really an exploit?              │
│    • If exploitable:                                  │
│        write patch → sandbox_write → restart → re-run │
│        → post-patch verdict must be non-exploitable   │
│    • sandbox_stop                                     │
│                                                         │
│  Write report.md + report.json                         │
└─────────────────────────────────────────────────────────┘
```

Each CVE gets its own container — failures on CVE-1 cannot bleed into CVE-2.

## Get started

### 1. Start the MCP servers

```bash
python3 agent/mcp/local_sandbox_server.py &   # sandbox tools: sandbox_build, sandbox_exec, etc.
python3 agent/mcp/cve_feed_server.py &        # CVE tools: cve_get_cve, osv_query_package, etc.
```

### 2. Run the agent

In OpenCode, invoke the `/patchproof` command:

```
/patchproof https://github.com/user/repo
/patchproof .                        # current directory
/patchproof . --cve CVE-2024-XXXX   # test one specific CVE
```

Or use the CLI directly for a full scan:

```bash
python3 agent/orchestrate.py /path/to/repo
python3 agent/orchestrate.py https://github.com/user/repo
```

To skip the image build and use a pre-built one:

```bash
PATCHPROOF_IMAGE=my-image python3 agent/orchestrate.py /path/to/repo
```

Results are written to `data/output/<repo>/report.md` and `data/output/<repo>/report.json`.

## Requirements

- Python 3.11+
- Docker
- OpenCode (for the LLM-driven agent workflow; the mechanical CLI works without it)

## Key files

| File | Purpose |
|---|---|
| `agent/orchestrate.py` | Mechanical driver — clone, scan, build image, write triage.json |
| `agent/scan.py` | CVE discovery + reachability bucketing (to_test / not_reachable) |
| `agent/build_image.py` | Per-repo Docker image build, SHA-cached |
| `agent/exploit.py` | Sandbox harness helpers (exec, write, read, stop, pull) |
| `agent/analyzer/reach.py` | Static reachability analysis (dep-pin → call-sites → input trace) |
| `agent/mcp/local_sandbox_server.py` | MCP server — sandbox tools (sandbox_build, sandbox_exec, etc.) |
| `agent/mcp/cve_feed_server.py` | MCP server — CVE tools (cve_get_cve, osv_query_package, etc.) |
| `.opencode/agents/patchproof.md` | The LLM agent definition |
| `.opencode/command/patchproof.md` | `/patchproof` command |

## What you get

A report with three buckets:

- **Exploitable** — CVE reaches attacker-controlled input in your code. Includes live HTTP evidence and a verified remediation patch.
- **Not exploitable** — CVE was tested and couldn't be triggered through your attack surface.
- **Not reachable** — static analysis proved the vulnerable code path is never called from your surface.

## Example report

```
# PatchProof Scan Report — `my-repo`

CVEs discovered: 23
CVEs tested: 8
Exploitable: 1
Not exploitable: 7

## Exploitable CVEs

### CVE-2024-21503

- Reason: SQL error in error response
- Request: POST /students/ body=name=test'+OR+'1'='1
- Response: status=500, body=DB error: not enough arguments

Remediation (verified):

cur.execute("INSERT INTO students (name) VALUES (%s)", (name,))
```

## FAQ

**Does it run exploits on my host?**
No. Everything runs inside Docker containers with `--network none`. Your machine never executes untrusted code.

**How does it find CVEs?**
It queries OSV.dev at runtime for every package in your `requirements.txt` or lock file. No CVE data is hardcoded. Each CVE is cross-checked against CVE.org to confirm it is PUBLISHED before testing.

**Does it work on non-Python repos?**
Currently Python only.

**What's the difference between the CLI and the agent?**
The CLI (`agent/orchestrate.py`) handles the deterministic parts: cloning, scanning, building the image, and writing `triage.json`. The LLM agent handles the creative parts: writing PoCs, judging verdicts, and generating patches.
