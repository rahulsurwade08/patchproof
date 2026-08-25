# AGENTS.md

PatchProof: agent that verifies CVE exploitability by running real exploits against pinned vulnerable services in a sandbox, then patches and verifies fixes. Built on TrueForge harness.

## Commands

```bash
# Run one scenario service locally
cd scenarios/s01-pyyaml-rce/app && pip install -r requirements.lock
uvicorn main:app --port 8000

# Run its PoC (from scenario dir, service running)
python poc.py                 # writes verdict.json

# Scenario tests (run inside scenarios/<id>/app)
python -m pytest test_main.py -q

# Staging via docker
docker compose -f infra/docker-compose.yml up --build

# Reset all demo state between runs
scripts/reset_demo.sh
```

## Hard rules

- **Exploits and patch tests run in the TrueForge sandbox only — never on the host.** Service and PoC must run in the same sandbox instance (PoC relies on a shared `/tmp` marker file).
- **Deploy-to-staging pauses for explicit human approval** (irreversible step); this gate is never cut even when scope shrinks.
- **Never commit `.env`** or bump versions in any `requirements.lock` — pins are the point (they reproduce vulnerable versions). Add deps to the lock deliberately.
- **PoC contract** (every scenario): exit 0 iff exploitable, exit 1 = not affected; write `verdict.json` with `{cve_id, exploitable, evidence}`; deterministic, <60s. Breaking this breaks the whole verification loop. Note s05-negative-case uses the *same* generic PoC but must self-conclude NOT AFFECTED — don't special-case its verdict.
- **Adding a scenario**: copy `scenarios/_template/`, follow its comments, fill `cve-meta.json`. Do not build `s04-jinja2-escape` until s01 + s05 pass acceptance (it's a marked stub).
- **PRs: address every Qodo code-review comment** before a PR is considered done — resolve each finding with commits to the same branch, never merge over unresolved findings. Merging itself is always done by the human, never by the agent.
- `agent/trueforge.json` is an **unverified draft** — its field names must be checked against TrueForge docs on first run of `npx @truefoundry/trueforge`; don't trust the shape.
- Gitignored but real: `docs/hackathon-checklist.md`, `docs/blog-draft.md` (local-only strategy docs), `data/inbox/` (advisory drop dir), `scenarios/*/verdict.json`.

## Keeping this file current

Whenever a change adds or alters any of the following, update this file **in the same change**:
- new tools, skills, or MCP servers (incl. install quirks)
- commands or verification steps
- architecture decisions (cross-check `docs/decisions.md`)
- hard rules or workflow conventions

## Layout

- `scenarios/<id>/` — self-contained vulnerable FastAPI service (`app/`) + `poc.py` + `cve-meta.json`
- `agent/` — TrueForge config (`trueforge.json`), subagent prompts in `agent/prompts/`, local NVD MCP server (`agent/mcp/nvd-server/index.mjs`)
- `docs/demo.md` — full walkthrough incl. harness wiring and human-approval flow
- `plan.md` — mission, decisions table, cost/quota constraints, cut-order if time runs out (S4 → S5 automation → dashboard; approval gate never)

## Environment notes

- `rg` (ripgrep) is required by the repo's Qodo skills (`rg` execution fails in skill loader until opencode is restarted after install).
