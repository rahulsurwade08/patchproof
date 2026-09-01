# PatchProof

Scanners say *"maybe vulnerable."* PatchProof proves whether you actually are —
by exploiting your exact code inside an isolated sandbox — proposes a fix,
and asks permission before shipping.

## The problem it solves

Version-number scanners can't tell whether *your* code path triggers a CVE.
Teams drown in false positives and stop fixing things. PatchProof closes the
loop empirically:

```
CVE advisory ──► orchestrator matches it to a repo
                      │
                      ▼
         analyzer runs static reachability on YOUR code
                      │
                      ▼
         reproducer starts YOUR service at YOUR pinned versions
         inside an isolated sandbox and runs an exploit against it
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
   exploit fails             exploit succeeds
   "NOT AFFECTED" ──► done   patcher bumps the dependency, runs the test
                             suite in the sandbox, opens a PR with the exploit
                             output as evidence
                                       │
                                       ▼
                         ■ pauses: deploying is irreversible → human approves
                                       │
                                       ▼
                         verifier re-runs the PoC against staging → fixed ✓
```

## Quickstart

Prerequisites: Python 3.11+ (or Docker). API keys for OpenRouter and GitHub
via `.env`.

```bash
# 1. Configure
cp .env.example .env          # then fill in your keys

# 2. Start the local-sandbox MCP server
python3 agent/mcp/local_sandbox_server.py &     # http://127.0.0.1:8081/mcp
python3 agent/mcp/cve_feed_server.py &           # http://127.0.0.1:8091/mcp

# 3. Run a triage against a target repo
python3 agent/analyzer/reach.py <repo-path> <cve-or-advisory> [--out <dir>]

# 4. Or run everything through staging
docker compose -f infra/docker-compose.yml up --build
```

## Repository layout

```
plan.md                  project plan
agent/                   MCP servers, prompts, skills, analyzer
  analyzer/              static reachability engine (reach.py, gen_context.py)
  mcp/                   local-sandbox + cve-feed servers
  prompts/               subagent prompts
  skills/                harness skills (SKILL.md per node)
infra/                   local staging (docker compose)
scripts/                 helpers
data/output/<repo>/      per-run artifacts (reachability, verdict, assessment)
```

## Sandbox

PatchProof runs exploits in an isolated sandbox — never on your host. The
`local-sandbox` MCP server executes disposable Docker containers with
networking disabled, one per investigation (service and PoC share it).
Zero cloud accounts. Start it before a run:

```bash
python3 agent/mcp/local_sandbox_server.py &
```

Requires Docker plus Python 3.9+ on the host (the MCP server itself is a
small stdlib-only script). No cloud sandbox providers are used anywhere in
this project.

## PoC contract

Every exploit writes `verdict.json` in the sandbox `/srv` directory:

- PoC script exits `0` **iff** exploitable; exit `1` means not affected.
- It writes `verdict.json`: `{cve_id, exploitable, evidence}`.
- Deterministic, <60 s, safe to run in an isolated sandbox.

`agent/skills/reproducer` owns writing PoCs that follow this contract.

## Harness compatibility

The agent is designed to run on any harness that supports MCP tools. Skills
in `agent/skills/` follow the standard SKILL.md format, and prompts in
`agent/prompts/` are harness-agnostic. The first supported target is
OpenCode — configure MCP servers via `opencode mcp add <name> --url <url>`.

## Code review

Every pull request is reviewed before merge. All findings must be addressed
(closed or explicitly waived with a rationale) before the PR is considered
done. Test status is the primary merge signal; small intermittent PRs, one
concern each.
