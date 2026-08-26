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
(`npx @truefoundry/trueforge`), and API keys for OpenRouter and GitHub —
configured via TrueForge Settings, see
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

## Sandbox options

PatchProof runs exploits in an isolated sandbox — never on your host. Two supported modes:

### 1. Local Docker sandbox via TrueForge (recommended, keyless)

The agentic loop executes through our own `local-sandbox` MCP server: disposable
Docker containers with networking disabled, one per investigation (service and
PoC share it). Zero cloud accounts. Start it before a harness run:

```bash
node agent/mcp/local-sandbox-server/index.mjs &
```

Requires only Docker. See [docs/trueforge-setup.md](docs/trueforge-setup.md).

### 2. Keyless local Docker without the harness

Verify any scenario with zero accounts and without running the harness:

```bash
scripts/run_poc_local.sh s01-pyyaml-rce   # → verdict.json + PoC exit code
```

This path is for **human- and CI-run verification only** — the autonomous
agentic pipeline goes through the `local-sandbox` server above.

No cloud sandbox providers are used anywhere in this project. See ADR-008
(`docs/decisions.md`) for the evaluated open-source alternatives
(Microsandbox, Nightona, beta9, E2B infra).

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
- [#6 — Keyless sandbox mode alongside TrueForge + Daytona](https://github.com/rahulsurwade08/patchproof/pull/6): Qodo raised 4 findings — readiness fall-through could mask startup failures as NOT_AFFECTED, shared container names broke concurrent runs, PoC had no deadline, and keyless mode needed explicit scoping against the TrueForge-sandbox rule. Fixed in 690d3f6: dedicated exit codes for service-start failure (3) and timeout (4), per-invocation container names (`$$` suffix), a 60s PoC deadline via `timeout`, and docs scoped so the agentic pipeline always uses the TrueForge + Daytona sandbox while keyless mode is human/CI-run verification only.
- [#7 — Park demo concerns](https://github.com/rahulsurwade08/patchproof/pull/7): Qodo found no issues.
- [#8 — LLM-as-a-judge subagent + credential guidance](https://github.com/rahulsurwade08/patchproof/pull/8): Qodo raised 8 findings (3 PR-level + 5 inline) — judge depended on unregistrable cve-feed tools, a judge-triggered retry left a stale assessment, gh-token guidance violated the no-secrets-in-session compliance rule, the assessment schema mismatched ADR-006, a PAT in `.env` didn't actually configure the connector, and related gaps. Fixed across 5809971, 12d7f86 and 52e8de8: degraded-mode contract (`range_check: "skipped"`), re-judging of retried verdicts on the latest machine verdict, OAuth-first GitHub credentials (no static token), canonical `agrees_with_verdict/confidence/range_check/rationale` schema, and explicit connector-config instructions for the PAT fallback.
- [#9 — Lessons-learned register](https://github.com/rahulsurwade08/patchproof/pull/9): Qodo found no issues.
- [#10 — Pre-flight consistency fixes](https://github.com/rahulsurwade08/patchproof/pull/10): Qodo raised 1 finding — the new JUDGE pipeline stage wasn't reflected in AGENTS.md per the keep-current policy. Fixed in b1f448e: judge role, `assessment.json` output, and its never-decides rule are now documented in AGENTS.md hard rules, alongside a decadal audit policy (full audit every 10 merged PRs) and a post-completion subagent test gate.
- [#12 — Local Docker sandbox MCP server (drop paid Daytona)](https://github.com/rahulsurwade08/patchproof/pull/12): Qodo raised 11 findings (6 bugs + 5 rule violations) — session-label container collisions, container-creation races, leaked containers on shutdown, unbounded request bodies, unknown tools reported as tool errors, unredacted sandbox output, forbidden `gh auth token` command in docs, and three stale-doc gaps. Fixed across 24797f2 and f786f5c: SHA-256 hashed container names with per-container locks, ownership-labeled containers with startup crash-recovery and full crash/graceful shutdown cleanup, 1 MiB body cap, `-32602` for unknown tools, credential redaction in all sandbox output, OAuth-command-free credential guidance, and full docs sync (architecture components, plan decisions, ADR-007 correction).
