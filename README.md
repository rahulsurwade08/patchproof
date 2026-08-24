# PatchProof

Scanners say *"maybe vulnerable."* PatchProof proves whether you actually are —
by exploiting your exact code inside an isolated sandbox — fixes it, verifies
the fix works, and asks permission before shipping.

An agent built on [TrueForge](https://github.com/truefoundry/trueforge),
TrueFoundry's open-source agent harness.

## The problem it solves

Version-number scanners can't tell whether *your* code path triggers a CVE.
Teams drown in false positives and stop fixing things. PatchProof closes the
loop empirically:

```
CVE advisory ──► orchestrator matches it to a repo (GitHub MCP)
                     │
                     ▼
        reproducer subagent starts YOUR service at YOUR pinned versions
        inside the TrueForge sandbox and runs an exploit against it
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

Prerequisites: Python 3.11+, Docker, Node 20+, a TrueForge install
(`npx @truefoundry/trueforge`), an OpenRouter API key.

```bash
# 1. Configure
cp .env.example .env          # then fill in your keys

# 2. Run a scenario service locally
cd scenarios/s01-pyyaml-rce/app
pip install -r requirements.lock
uvicorn main:app --port 8000

# 3. Run its PoC from another shell
python poc.py                 # writes verdict.json, exits 0 if exploitable

# 4. Or run everything through staging
docker compose -f infra/docker-compose.yml up --build
```

Full walkthrough including harness wiring and the approval flow:
[docs/demo.md](docs/demo.md).

## Repository layout

```
plan.md                  project plan
docs/                    architecture, demo walkthrough, decision log
scenarios/               vulnerable demo services + their PoC contracts
agent/                   TrueForge config, MCP servers, prompts, skills
infra/                   local staging (docker compose)
scripts/                 demo helpers
dashboard/               thin live-status UI (built after the core loop)
```

## Scenario contract

Every scenario ships `cve-meta.json` and follows one PoC contract:

- PoC script exits `0` **iff** exploitable; exit `1` means not affected.
- It writes `verdict.json`: `{cve_id, exploitable, evidence}`.
- Deterministic, <60 s, safe to run in an isolated sandbox.

Adding a scenario: copy `scenarios/_template/` and follow its comments.
