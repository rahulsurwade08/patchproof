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
```

## Hard rules

- **Prioritize security on every change**: no secrets in code or git history; never weaken the sandbox or approval model; scenario services are live-exploit targets — run them only on localhost/sandbox, never exposed.
- **Never display secrets in the session**: don't read/print `.env`, API keys, or tokens into tool output, commands, diffs, or replies; refer to keys by name only. Never use `gh auth status --show-token` or `gh auth token` in-session; treat any command output as potentially token-bearing and redact token lines if present.
- **Exploits and patch tests run in the TrueForge sandbox only — never on the host.** Service and PoC must run in the same sandbox instance (PoC relies on a shared `/tmp` marker file).
- **Deploy-to-staging pauses for explicit human approval** (irreversible step); this gate is never cut even when scope shrinks.
- **Never commit `.env`.** Never bump versions in any `requirements.lock` *except the patcher's deliberate CVE-remediation bump* (which goes through PR + sandbox test suite) — pins reproduce vulnerable versions, so casual edits destroy the scenarios.
- **PoC contract** (every scenario): exit 0 iff exploitable, exit 1 = not affected; write `verdict.json` with `{cve_id, exploitable, evidence}`; deterministic, <60s. Breaking this breaks the whole verification loop. Note s05-negative-case uses the *same* generic PoC but must self-conclude NOT AFFECTED — don't special-case its verdict.
- **Adding a scenario**: copy `scenarios/_template/`, follow its comments, fill `cve-meta.json`. Do not build `s04-jinja2-escape` until s01 + s05 pass acceptance (it's a marked stub).
- **PRs: address every Qodo code-review comment** before a PR is considered done — after each raise/push, **wait ~5 minutes for Qodo's review to post**, then check `gh pr view <n> --comments` for findings, fix each one with commits to the same branch, post a traceability comment mapping finding → resolution, **and update the README "Qodo Code Review Evidence" section** (finding + resolution for that PR). Never merge over unresolved findings. Merging itself is always done by the human, never by the agent.
- **TrueForge has no config file** (verified against v0.1.4 docs): models/connectors/skills/sandbox are configured via Settings — see `docs/trueforge-setup.md`. Sandbox provider is **Daytona only**; MCP servers are remote-URL only, so the local cve-feed stdio server needs an HTTP wrapper or must be bypassed via `data/inbox/` injection.
- Gitignored but real: `docs/hackathon-checklist.md`, `docs/blog-draft.md` (local-only strategy docs), `data/inbox/` (advisory drop dir), `scenarios/*/verdict.json`.

## Demo & hackathon compliance

- Demo video must show the harness visibly working: a real MCP tool call, code execution in the sandbox, and the pause before the irreversible step.
- README keeps a **"Qodo Code Review Evidence"** section — every Qodo finding on any PR must be listed there with its resolution, kept current as PRs land; if a PR merges before its findings are fixed, record them as fixed-forward once resolved.
- Only connect tools/data/accounts that are yours; keys and personal data stay out of the repo **and** out of the demo video (never show `.env` or TrueForge Settings screens on camera).

## Working loop

Work autonomously: pick the next step (see plan.md cut-order), implement, verify, raise/push PRs, and resolve Qodo findings — then continue to the next item. **Only stop for human input** when genuinely required: the deploy-approval gate, missing credentials/keys, ambiguity that changes scope, or an explicit user decision. Do not pause for confirmation on routine steps.

**PR gate:** after a PR is open, keep working only on that PR (Qodo findings etc.). Once it is clean, **stop and wait for the human to review/approve/merge** — never start the next work item while a PR is pending, and never merge it yourself.

## Keeping this file current

Whenever a change adds or alters any of the following, update this file **in the same change**:
- new tools, skills, or MCP servers (incl. install quirks)
- commands or verification steps
- architecture decisions (cross-check `docs/decisions.md`)
- hard rules or workflow conventions

## Layout

- `scenarios/<id>/` — self-contained vulnerable FastAPI service (`app/`) + `poc.py` + `cve-meta.json`
- `agent/` — subagent prompts in `agent/prompts/`, local dual-source CVE feed MCP server (`agent/mcp/cve-feed-server/index.mjs`: CVE.org + OSV.dev legitimacy cross-check; needs HTTP wrapper — see `docs/trueforge-setup.md`)
- `docs/demo.md` — full walkthrough incl. harness wiring and human-approval flow
- `plan.md` — mission, decisions table, cost/quota constraints, cut-order if time runs out (S4 → S5 automation → dashboard; approval gate never)

## Environment notes

- `rg` (ripgrep) is required by the repo's Qodo skills (`rg` execution fails in skill loader until opencode is restarted after install).
