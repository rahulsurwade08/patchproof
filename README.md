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

Prerequisites: Python 3.11+ (or Docker), Node 20+, a TrueForge install
(`npx @truefoundry/trueforge`), and API keys for OpenRouter, GitHub, and
Daytona — configured via TrueForge Settings, see
[docs/trueforge-setup.md](docs/trueforge-setup.md).

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

Adding a scenario: copy `scenarios/_template/` and follow its comments, then fill `cve-meta.json`.

## Qodo Code Review Evidence

Every pull request in this repo is reviewed by [Qodo](https://www.qodo.ai) from day 1, and all findings are resolved before merge (or fixed forward immediately after).

- [#1 — chore: add qodo agent skills](https://github.com/rahulsurwade08/patchproof/pull/1): Qodo raised 3 findings — unsafe `c['API_KEY']` config parsing, a wrong usage path in `scope-parse.sh`, and non-spec `triggers:` frontmatter on both vendored skills. Merged before resolution; **fixed forward** in [#3](https://github.com/rahulsurwade08/patchproof/pull/3).
- [#2 — Add AGENTS.md and repair doc redaction placeholders](https://github.com/rahulsurwade08/patchproof/pull/2): Qodo raised 3 findings (host commands conflicting with the sandbox-only rule, a `requirements.lock` rule contradicting the patcher workflow, an overly broad `.gitignore` pattern). All three were fixed on the same branch with a finding → resolution traceability comment: [review + resolution thread](https://github.com/rahulsurwade08/patchproof/pull/2#issuecomment-5409113173).
- [#3 — TrueForge setup guide, README Qodo evidence, PR #1 finding fixes](https://github.com/rahulsurwade08/patchproof/pull/3): Qodo raised 3 findings — NVD-MCP docs inconsistency across demo/architecture, conflicting `.env.example` vs Settings setup paths for Daytona, and an API-key parse that could mask a missing key. Fixed in fbfa395: docs now route NVD through `data/inbox/` until the HTTP wrapper exists, `.env.example` is annotated as a reference for Settings-based config, and the snippet exits explicitly on a missing key. Resolution thread: [comment](https://github.com/rahulsurwade08/patchproof/pull/3#issuecomment-5409544317).
- [#4 — AGENTS.md: never display secrets in the session](https://github.com/rahulsurwade08/patchproof/pull/4): Qodo raised 1 finding — the rule's parenthetical could be read as license to paste `gh auth status` output (which can leak tokens via `--show-token`). Fixed in f08da6b: rule now bans `gh auth status --show-token` / `gh auth token` outright and requires treating all command output as potentially token-bearing. Resolution thread: [comment](https://github.com/rahulsurwade08/patchproof/pull/4#issuecomment-5409797304).
- [#5 — Dual-source CVE legitimacy server: CVE.org + OSV.dev](https://github.com/rahulsurwade08/patchproof/pull/5): Qodo raised 3 findings — OSV results truncated before the legitimacy match (risk of false NOT_IN_SCOPE), tool exceptions returned as successful MCP results, and an inbox fallback that bypassed the legitimacy gate. Fixed in cb1168e: pagination is followed before any verdict, execution failures return `isError: true` with protocol errors for unknown tools, and unverified advisories fail closed (only explicit `"demo": true` injections may bypass, recorded as `demo-bypass` in state).
- [#4 — AGENTS.md: never display secrets in the session](https://github.com/rahulsurwade08/patchproof/pull/4): Qodo raised 1 finding — the rule's parenthetical could be read as license to paste `gh auth status` output (which can leak tokens via `--show-token`). Fixed in f08da6b: rule now bans `gh auth status --show-token` / `gh auth token` outright and requires treating all command output as potentially token-bearing.
