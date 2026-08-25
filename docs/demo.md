# Demo Walkthrough

End-to-end run of PatchProof. Everything is localhost-only; nothing hosted.

## 0. Prerequisites

- `.env` filled from `.env.example` (OpenRouter key, GitHub token)
- TrueForge running: `npx @truefoundry/trueforge`
- Docker for staging

## 1. Seed an advisory

```bash
python scripts/fake_cve_injector.py --scenario s01-pyyaml-rce
# writes data/inbox/CVE-2020-14343.json pointing at scenario metadata
```

## 2. Start a TrueForge session and give it the orchestrator prompt

Paste `agent/prompts/orchestrator.md` as the session system/task brief. The
orchestrator:

1. Reads the inbox via `nvd_get_cve`.
2. Matches the advisory to `scenarios/s01-pyyaml-rce` via GitHub MCP.
3. Spawns a reproducer subagent.

## 3. Watch the reproducer

The reproducer starts the service at pinned deps
(`pyyaml==5.3.1`) inside the sandbox, parameterizes `poc.py`, runs it:

- `verdict.json` appears with `exploitable: true`
- evidence: marker file created by code-executed payload
- subagent returns a ≤15-line summary

## 4. The patch

The patcher bumps `pyyaml` in `requirements.lock`, re-runs the PoC plus the
service's test suite in the sandbox, and opens a PR whose body quotes the
original exploit output.

## 5. The approval gate

Merging and deploying to staging is irreversible. The agent stops and asks.
Approve only after reviewing the PR.

```bash
docker compose -f infra/docker-compose.yml up --build   # staging now patched
```

## 6. Verification loop

The verifier re-runs the same PoC against staging:

- payload no longer executes → `exploitable: false` → case closed ✓

## 7. Persistence beat

Refresh the browser or restart TrueForge mid-run: sessions resume from
`state.json`; the investigation continues where it left off.

## Reset between runs

```bash
./scripts/reset_demo.sh
```
