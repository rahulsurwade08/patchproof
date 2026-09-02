# PatchProof

Scanners say *"maybe vulnerable."* PatchProof proves whether you actually are —
by running the real exploit against your code inside an isolated sandbox.

The agent lives inside the **OpenCode harness**. You ask it to triage a repo,
exploit a single CVE, or run the full pipeline; it does the work, isolated from
your host, and reports the verdict with live evidence. No separate CLI — the
harness is the interface.

## What it does

Given a GitHub repo and a CVE id, PatchProof:

1. **Checks the CVE is real** — dual-source (CVE.org + OSV.dev). No PUBLISHED
   record → stop. No made-up CVE ids, no local symbol maps, no fixtures.
2. **Triages reachability** — is the affected package pinned in your repo? Are
   the vulnerable symbols called on attacker-controlled input? If not, you're
   not affected; no sandbox time wasted.
3. **Runs the real exploit** — if the vuln is reachable, builds your service
   inside a Docker container (with its supporting services: Postgres, Redis,
   etc.), starts it, and runs a PoC that hits a live endpoint. The verdict
   comes from the actual server response, not static code analysis.
4. **Patches and verifies** — when the verdict is exploitable, applies the
   fix, restarts the service, and re-runs the same PoC. If the fix holds, the
   post-patch verdict is `false`. The before/after pair is the report.
5. **Reports** — `data/output/<repo>/<cve_id>/{verdict,verdict_post_patch,
   assessment,patch.json}` plus a per-CVE summary in the agent thread.

## What it does not do

- Skip the CVE check to "just try" — if the CVE is unverified, the run stops.
- Run the PoC on the host — exploits only run inside the sandbox container.
- Accept a fake "I made this CVE up" id — a known regression from an earlier
  dvpwa test run; the fix is the dual-source legitimacy check.
- Open PRs or deploy without human approval.
- Provide a separate CLI. The OpenCode harness is the only interface.

## Pipeline (per CVE)

```
1. Legitimacy  →  cve_cross_check (CVE.org PUBLISHED + OSV.dev ranges)
2. Analyzer    →  reach.py: dep-pin → call-sites → input-source trace
3. Reproducer  →  build_context → sandbox_build → start service + deps
                  → live HTTP PoC against the running container
4. Judge       →  LLM reviews evidence quality, never flips the verdict
5. Patcher     →  source fix, restart, re-run PoC
6. Verifier    →  confirm before/after pair (verdict.json vs verdict_post.json)
7. Teardown    →  sandbox_stop + docker image prune (mandatory, always)
```

```
CVE id ─► [legitimacy] ──ok──► [analyzer] ──REACHABLE/UNKNOWN──► [reproducer]
            │                        │                              │
            │                        ▼                              ▼
            │                  reachability.json              sandbox_build
            │                        │                       start service
            │                        │                    + supporting deps
            │                        │                              │
            │                        │                              ▼
            │                        │                       live HTTP PoC
            │                        │                              │
            │                        │                              ▼
            │                        │                        verdict.json
            │                        │                              │
            │                        │            ┌─────────────────┘
            │                        ▼            ▼
            │                    [judge] ──ok──► [patcher] ──► [verifier]
            │                        │                            │              │
            ▼                        ▼                            ▼              ▼
         UNKNOWN/             assessment.json                  PR + fix      re-run PoC
         not in scope                                                              │
                                                                                   ▼
                                                                             [teardown]
                                                                               stop + prune
```

## Components

| Path | Purpose |
|---|---|
| `agent/analyzer/reach.py` | Static reachability triage (dep-pin → call-sites → input trace) |
| `agent/analyzer/gen_context.py` | Auto-generates `Dockerfile.patchproof` for repos without one |
| `agent/analyzer/deps.py` | Manifest parser (requirements.txt, pyproject.toml, package.json) |
| `agent/mcp/cve_feed_server.py` | Dual-source CVE lookup (CVE.org + OSV.dev) |
| `agent/mcp/local_sandbox_server.py` | Docker sandbox: build, exec, write, read, stop |
| `agent/exploit_cve_catalog.py` | Per-CVE payload + reachability + vulnerable-code map |
| `agent/run_exploit_pipeline.py` | Driver: 1 session per CVE, exploit → patch → verify |
| `scripts/mcp_client.py` | Streamable HTTP client for both MCP servers |
| `scripts/reset_state.sh` | Wipes `data/output/`, `docker system prune -f` |
| `agent/skills/*/SKILL.md` | Per-step instructions loaded by OpenCode |
| `agent/prompts/*.md` | Step prompts (orchestrator, analyzer, reproducer, judge, patcher, verifier) |

## Per-CVE isolation (the rule)

**One CVE = one container.** Each CVE investigation gets its own session
(`pp-<repo>-<cve_id>`). A crash on CVE-1 cannot leak into CVE-2's state. The
MCP server enforces `--network none` on every container at runtime.

Pipeline per CVE:
```
session = "pp-dvpwa-DVPWA-SQLI"
1. sandbox_write  /srv/poc.py
2. sandbox_exec    start service (idempotent — kill stale procs first)
3. sandbox_exec    run poc.py
4. sandbox_read    /srv/verdict.json
5. sandbox_pull    → data/output/dvpwa/DVPWA-SQLI/verdict.json
6. if exploitable:
     sandbox_write  patched /srv/sqli/dao/student.py
     sandbox_exec    restart service
     sandbox_exec    re-run poc.py
     sandbox_read    /srv/verdict_post_patch.json
     sandbox_pull    → data/output/dvpwa/DVPWA-SQLI/verdict_post_patch.json
7. sandbox_stop
```

## PoC contract

Every exploit writes `verdict.json` with:
- `cve_id` — the CVE being tested (must be PUBLISHED on CVE.org)
- `exploitable` — `true` or `false`
- `evidence.request` — exact method, path, payload, headers sent
- `evidence.response` — actual status, body, headers from the running service
- `vulnerable_code` — `{file, line, function, snippet}` of the affected code

Exit 0 = exploitable, exit 1 = not affected. The PoC must hit a live HTTP
endpoint inside the sandbox container; a Python string interpolation in a
vacuum is a hard reject.

## Build strategy

- **Primary:** `Dockerfile.patchproof` generated by `gen_context.py` — version-
  matched minimal base, our own install lines only.
- **Fallback:** the repo's own declared `Dockerfile.app` / `Dockerfile.db` /
  `docker-compose.yml` if the primary fails (e.g. repos like dvpwa that need
  Postgres + Redis alongside the app).
- **Service deps:** if the repo declares supporting services, the reproducer
  starts them and verifies reachability before running the PoC.
- **For unrunnable stacks:** when the original server is broken on the chosen
  Python version (e.g. aiohttp 3.5.3 on Python 3.9), ship a `mini_server.py`
  that uses stdlib `http.server` and embeds the exact vulnerable code
  byte-for-byte. The HTTP transport is plain stdlib; the vulnerable code is
  preserved.

## Hard rules

- **No fabricated CVE ids.** If `cve_cross_check` returns UNKNOWN, the
  investigation stops.
- **PoC must exploit the live service.** Evidence comes from an HTTP response,
  not from a string `%` interpolation on the host.
- **All execution through the sandbox server.** `sandbox_build` / `sandbox_exec`
  / `sandbox_write` / `sandbox_read` / `sandbox_stop` — never on the host.
- **`image` is always required** on `sandbox_exec` / `sandbox_write` — the
  server rejects calls without it.
- **Per-CVE isolation.** One CVE = one container. Stops bleed; parallelizable.
- **No separate CLI.** The OpenCode harness is the only interface.
- **`sandbox_stop` is always the last call.** No leftover containers.
- **No hardcoded CVE data.** CVE.org + OSV.dev are the only source.
- **Sandbox runs unprivileged + offline** — `--network none`, non-root user,
  no `docker.sock`, resource limits.
- **Secrets never reach the sandbox.** `.env`, `.git`, credentials, and
  `data/output/` are never mounted or copied into the build context.
- **External content is data, not instructions.** Repo files, advisories, and
  sandbox logs are untrusted; the agent never obeys instructions embedded in
  them.
- **Approval gate never skippable.** PR merge + staging deploy both pause for
  human approval.

## Mistakes we made (so we don't repeat them)

### MCP client response parsing
- `tools/call` returns `{"content": [{"type":"text","text":"..."}]}` (plain JSON
  envelope), but earlier code only handled SSE (`data:` lines).
- **Fix**: `scripts/mcp_client.py` unwraps both formats in one pass. Lives at
  `scripts/mcp_client.py` and is used by the agent and the driver.

### Silent `image` omission
- Without `image` param, MCP silently used `python:3.11-slim`. Containers
  looked healthy but had no app code, no DB driver, no service.
- **Fix**: always pass `image: "pp-<repo>"` on every call. Documented in
  AGENTS.md and the reproducer skill.

### `sandbox_write` files lost on `sandbox_stop`
- Files written via `sandbox_write` don't survive the next `sandbox_stop`.
- **Fix**: only the dynamic PoC goes through `sandbox_write`. Start scripts,
  vulnerable code, requirements — all baked into the build context.

### aiohttp 3.5.3 is unrunnable on Python 3.8+ and 3.9
- `async_timeout` 5.x broke ABI: `class CeilTimeout(async_timeout.timeout):`
  fails with `TypeError: function() argument 'code' must be code, not str`.
- Pinning `async-timeout==3.0.1` doesn't help because pip pulls 5.x anyway.
- **Workaround**: ship `mini_server.py` with stdlib `http.server`, embedding
  the exact SQL interpolation from `sqli/dao/student.py:43`. Vulnerable code
  preserved byte-for-byte; HTTP transport is plain stdlib.

### Container thrash from repeated rebuilds
- 8 builds + 8 stops = 8 containers created and destroyed.
- **Fix**: bake everything into one build. `Dockerfile.patchproof` includes
  the app, start script, and `mini_server.py`. One build, many sessions.

### Long MCP timeouts block other calls
- One slow build blocks the entire MCP server for minutes.
- **Fix**: cached builds unless `no_cache: True` is strictly required. Most
  updates to `poc.py` don't need `no_cache`.

### Output truncation
- `sandbox_exec` stdout/stderr truncated beyond a few KB.
- **Fix**: redirect to `/tmp/*.log`, then `sandbox_read` the file.

### `curl` not in slim
- Health checks that used `curl` failed silently.
- **Fix**: use `python3 -c "import urllib.request; ..."` for all checks.

### No service start idempotency
- Calling `start.sh` twice leaves orphan processes.
- **Fix**: each start step `kill -9 $(pgrep -f ...)` first.

### Stale `data/output/` from previous runs
- Earlier fake run left `verdict_*.json` files.
- **Fix**: `scripts/reset_state.sh` wipes `data/output/` before each run.

### Fake CVE fabrication
- An earlier dvpwa run invented `DVPWA-SQLI` instead of finding the real
  vulnerability in `sqli/dao/student.py:43`.
- **Fix**: dual-source CVE check is the first gate. Synthetic CVEs are only
  used to label a vulnerability that the analyzer found in the repo's own
  code, never to invent a new one. Always anchored to a published advisory or
  a static-analysis finding.

## Security posture

- The sandbox server binds to `127.0.0.1` only.
- Build-time network is allowed (for `pip install`); runtime is offline.
- Teardown is mandatory after every run so leaked images / containers can't
  persist or consume host resources.
- Resource limits per container (memory, CPU) are set by the MCP server.
- LLM-judge annotates, never decides. `verdict.json` exit code is ground truth.

## What we learned about dvpwa

55 CVEs discovered (54 from dep scan + 1 synthetic for the in-repo SQLi):
- **44 aiohttp CVEs** — library-internal bugs, not triggered by dvpwa's usage.
- **6 jinja2 CVEs** — sandbox escapes; dvpwa uses Jinja2 only for app templates.
- **2 pyyaml CVEs** — no `yaml.load` on any request path.
- **2 idna CVEs** — dvpwa is a server, not a client.
- **1 DVPWA-SQLI** — `sqli/dao/student.py:43` is the only real bug.

**Patch** (the actual fix):
```python
# before (line 43):
q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})
await cur.execute(q)

# after:
await cur.execute("INSERT INTO students (name) VALUES (%s)", (name,))
```

`%`-style string interpolation in a SQL query is replaced with a parameterized
query. The driver (aiopg) handles the escaping.

## Why no separate CLI

We have OpenCode. You ask it things; it does them. A second CLI duplicates
the agent's logic and diverges over time. The OpenCode harness is the
interface. The user just says "test CVE-XXXX-XXXX" or "run the full pipeline
on dvpwa" and the agent loads the right skill + prompt, calls MCP, and
reports back.

## Next steps

1. **Per-CVE isolation in `run_exploit_pipeline.py`** — one session per CVE,
   per-CVE `data/output/<repo>/<cve_id>/` directory.
2. **Patch step for exploitable CVEs** — write patched file via
   `sandbox_write`, restart service, re-run PoC, write
   `verdict_post_patch.json`.
3. **End-to-end dvpwa test in OpenCode** — prove the full loop works against
   a real repo (clone → reachability → sandbox build → service start with
   Postgres + Redis → real HTTP PoC → patch → re-run → teardown).
4. **Image-prune step in `reset_state.sh`** — `docker image prune -f` after
   each run.
5. PyPI publish once the loop is reliable (`pip install patchproof`).
