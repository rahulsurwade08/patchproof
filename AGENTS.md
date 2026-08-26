# AGENTS.md

PatchProof: agent that verifies CVE exploitability by running real exploits against pinned vulnerable services in a sandbox, then patches and verifies fixes. Built on TrueForge harness.

## Commands

Local dev commands below are for smoke-testing a scenario *service* (health endpoint, pytest suite) during development. Exploit/PoC execution itself never runs on the host — see the sandbox rule under Hard rules; on Python ≥3.12 hosts use Docker staging instead (the vulnerable pins won't build there).

```bash
# Run one scenario service locally (dev smoke-test only)
cd scenarios/s01-pyyaml-rce/app && pip install -r requirements.lock
uvicorn main:app --port 8000

# Run its PoC — ONLY inside the TrueForge sandbox (or docker exec into staging)
python poc.py                 # writes verdict.json

# Scenario tests (run inside scenarios/<id>/app)
python -m pytest test_main.py -q

# Staging via docker
docker compose -f infra/docker-compose.yml up --build

# Reset all demo state between runs
scripts/reset_demo.sh

# Keyless sandbox: service+PoC in one network-isolated container (no API keys)
scripts/run_poc_local.sh <scenario-id>   # writes verdict.json, exits PoC code

# Mandatory pre-push test gate (routes through local-sandbox MCP)
bash scripts/run_gate_before_push.sh <scenario-id>  # sandbox_build + sandbox_exec via MCP
scripts/install-hooks.sh                             # install git pre-push hook (run once per clone)
```

## Hard rules

- **Prioritize security on every change**: no secrets in code or git history; never weaken the sandbox or approval model; scenario services are live-exploit targets — run them only on localhost/sandbox, never exposed.
- **Never display secrets in the session**: don't read/print `.env`, API keys, or tokens into tool output, commands, diffs, or replies; refer to keys by name only. Never use `gh auth status --show-token` or `gh auth token` in-session; treat any command output as potentially token-bearing and redact token lines if present.
- **Exploits and patch tests never run on the host.** All execution goes through our `local-sandbox` MCP server (`agent/mcp/local-sandbox-server/index.mjs`, Streamable HTTP at `127.0.0.1:8081/mcp`): `sandbox_build` (host-side image build, build-time network allowed), `sandbox_exec`/`sandbox_write`/`sandbox_read`/`sandbox_stop` (offline `--network none` containers, one per session sharing `/tmp`). **Start it before any harness run**: `node agent/mcp/local-sandbox-server/index.mjs &` (no dependencies). No cloud sandbox providers are used — TrueForge's built-in provider is paid and stays unconfigured (see ADR-008 for evaluated open-source alternatives). `scripts/run_poc_local.sh` remains the no-harness human/CI path (exit codes: 0 exploitable, 1 not affected, 3 service-start failure, 4 PoC timeout).
- **Deploy-to-staging pauses for explicit human approval** (irreversible step); this gate is never cut even when scope shrinks.
- **Never commit `.env`.** Never bump versions in any `requirements.lock` *except the patcher's deliberate CVE-remediation bump* (which goes through PR + sandbox test suite) — pins reproduce vulnerable versions, so casual edits destroy the scenarios.
- **PoC contract** (every scenario): exit 0 iff exploitable, exit 1 = not affected; write `verdict.json` with `{cve_id, exploitable, evidence}`; deterministic, <60s. Breaking this breaks the whole verification loop. Note s05-negative-case uses the *same* generic PoC but must self-conclude NOT AFFECTED — don't special-case its verdict.
- **LLM-judge annotates, never decides** (`agent/prompts/judge.md`): every verdict gets a judge review written to `scenarios/<id>/assessment.json` (`agrees_with_verdict/confidence/range_check/rationale`). The PoC exit code stays ground truth; disagreement or low confidence triggers at most one more reproduction attempt within the cap of 3.
- **Adding a scenario**: copy `scenarios/_template/`, follow its comments, fill `cve-meta.json`. Do not build `s04-jinja2-escape` until s01 + s05 pass acceptance (it's a marked stub).
- **PRs: address every Qodo code-review comment** before a PR is considered done — after each raise/push, **wait ~5 minutes for Qodo's review to post**, then check `gh pr view <n> --comments` for findings, fix each one with commits to the same branch, post a traceability comment mapping finding → resolution, **and update the README "Qodo Code Review Evidence" section** (finding + resolution for that PR). Never merge over unresolved findings. Merging itself is always done by the human, never by the agent.
- **TrueForge has no config file** (verified against v0.1.4 docs): models/connectors/skills/sandbox are configured via Settings — see `docs/trueforge-setup.md`. Its built-in sandbox provider is paid and stays unconfigured; we use the local-sandbox MCP server instead (ADR-008 lists evaluated open-source alternatives). MCP servers are remote-URL only; stdio servers need an HTTP wrapper or must be bypassed via `data/inbox/` injection.
- Gitignored but real: `docs/hackathon-checklist.md`, `docs/blog-draft.md` (local-only strategy docs), `data/inbox/` (advisory drop dir), `scenarios/*/verdict.json`.

## Lessons learned (mistakes to never repeat)

Maintained list — append a lesson whenever a real mistake is identified.

- **Check BOTH comment surfaces on every PR review pass**: `gh pr view <n> --comments` AND inline review comments via `gh api repos/:owner/:repo/pulls/<n>/comments`. Inline Medium findings were missed once and the user caught them. After fixing an inline finding, reply **on that thread** and resolve it (GraphQL `resolveReviewThread`) — a separate PR-level comment leaves the thread showing open.
- **Never commit without first switching to a feature branch.** A commit landed on main by accident because branching was skipped.
- **Don't push follow-up commits to a branch whose PR is awaiting merge** — a pushed-after-open commit (`de93e49`) never reached main when the PR merged, silently losing content. Verify post-merge that every intended change actually landed on main.
- **After any edit that removes or deduplicates lines, re-read the whole section** — a README row was accidentally deleted while removing an adjacent duplicate.
- **Clean up test artifacts immediately** — a stray root-level `verdict.json` from a manual PoC run sat in the working tree; run tests from the right directory or remove artifacts in the same step.
- **Cross-check new guidance against existing hard rules before writing it** — docs once endorsed a token-printing command that violated our own no-secrets-in-session rule; Qodo flagged it. Security rules always win over convenience features.
- **Verify claims of "done/clean" against primary sources**, not memory: grep for placeholders/stale references after doc surgery, re-read files after rebases, and confirm merged content on origin/main.

## Demo & hackathon compliance

**Parked by maintainer decision**: build the whole project first; do not let demo/video/presentation concerns drive any implementation decision. Revisit only when the core pipeline is proven end-to-end. (The README Qodo-evidence upkeep below is exempt — it's part of the normal PR loop.)

- Demo video must show the harness visibly working: a real MCP tool call, code execution in the sandbox, and the pause before the irreversible step.
- README keeps a **"Qodo Code Review Evidence"** section — every Qodo finding on any PR must be listed there with its resolution, kept current as PRs land; if a PR merges before its findings are fixed, record them as fixed-forward once resolved.
- Only connect tools/data/accounts that are yours; keys and personal data stay out of the repo **and** out of the demo video (never show `.env` or TrueForge Settings screens on camera).

## Maintenance & verification policy

- **Decadal audit**: after every 10 merged PRs (10, 20, 30, …), run a full-repo audit — stale references (grep for retired names/paths), docs-vs-code consistency, AGENTS.md accuracy against reality, secrets scan of history and working tree — and fix or file anything found.
- **Subagent test gate** (post-completion): `agent/prompts/test-runner.md` verifies scenario tests via `sandbox_build` + `sandbox_exec`, writes `test_gate.json`. Every change must pass this gate before push.
- **Subagent test gate (post-completion)**: once the project is complete, every code change must be verified by local test-case runs executed through a dedicated test-runner subagent (spawn it per change; report pass/fail in the PR) before the change is pushed.

## Working loop

Work autonomously: pick the next step (see plan.md cut-order), implement, verify, raise/push PRs, and resolve Qodo findings — then continue to the next item. **Only stop for human input** when genuinely required: the deploy-approval gate, missing credentials/keys, ambiguity that changes scope, or an explicit user decision. Do not pause for confirmation on routine steps.

**PR gate:** after a PR is open, keep working only on that PR (Qodo findings etc.). Once it is clean, **stop and wait for the human to review/approve/merge** — never start the next work item while a PR is pending, and never merge it yourself.

## Keeping this file current

Whenever a change adds or alters any of the following, update this file **in the same change**:
- new tools, skills, or MCP servers (incl. install quirks)
- commands or verification steps
- architecture decisions (cross-check `docs/decisions.md`)
- hard rules or workflow conventions

The same applies to sibling sources of truth, updated **in the same change**:
- `plan.md` — whenever the plan changes: mission flow, decisions table, scope/cut-order
- `docs/decisions.md` — every accepted/rejected/superseded decision gets an ADR
- `docs/architecture.md` — whenever components or pipeline stages change

## Layout

- `scenarios/<id>/` — self-contained vulnerable FastAPI service (`app/`) + `poc.py` + `cve-meta.json`
- `agent/` — subagent prompts (`agent/prompts/`: orchestrator, reproducer, judge, patcher, verifier, test-runner), local dual-source CVE feed MCP server (`agent/mcp/cve-feed-server/index.mjs`), local Docker sandbox MCP server (`agent/mcp/local-sandbox-server/index.mjs`, Streamable HTTP on `127.0.0.1:8081/mcp`)
- `docs/demo.md` — full walkthrough incl. harness wiring and human-approval flow
- `plan.md` — mission, decisions table, cost/quota constraints, cut-order if time runs out (S4 → S5 automation → dashboard; approval gate never)

## Environment notes

- `rg` (ripgrep) is required by the repo's Qodo skills (`rg` execution fails in skill loader until opencode is restarted after install).
