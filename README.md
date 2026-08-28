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

# 5. Launch the dashboard
cd dashboard && pip install -r requirements.txt
uvicorn app:app --port 8080   # open http://localhost:8080
```

Full walkthrough including harness wiring and the approval flow:
[docs/demo.md](docs/demo.md).

## Repository layout

```
plan.md                  project plan
docs/                    architecture, demo walkthrough, decision log
scenarios/               vulnerable demo services + their PoC contracts
  _template/             scaffold for new scenarios
  s01-pyyaml-rce/        PyYAML FullLoader RCE (CVE-2020-14343)
  s04-jinja2-escape/     Jinja2 sandbox escape (CVE-2024-56326)
  s05-negative-case/     same CVE, safe loader (NOT_AFFECTED)
  s06-dvpwa-sqli/        DVPWA-style SQL injection pattern
agent/                   TrueForge config, MCP servers, prompts, skills
infra/                   local staging (docker compose)
scripts/                 demo helpers, pre-push gate
dashboard/               thin live-status UI (FastAPI + SSE)
```

## Sandbox options

PatchProof runs exploits in an isolated sandbox — never on your host. Two supported modes:

### 1. Local Docker sandbox via TrueForge (recommended, keyless)

The agentic loop executes through our own `local-sandbox` MCP server: disposable
Docker containers with networking disabled, one per investigation (service and
PoC share it). Zero cloud accounts. Start it before a harness run:

```bash
python3 agent/mcp/local_sandbox_server.py &
```

Requires Docker plus Python 3.9+ on the host (the MCP server itself is a
small stdlib-only script). See [docs/trueforge-setup.md](docs/trueforge-setup.md).

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
- [#11 — Sync plan.md with recent decisions + keep-current rule for sibling docs](https://github.com/rahulsurwade08/patchproof/pull/11): Qodo raised 4 findings — README still ran PoC on host (security violation), README required obsolete GitHub key (OAuth-first not reflected), architecture omitted judge capability, plan retained obsolete OAuth decision (ADR-007 not synced). All 4 fixed before merge: README sandbox-only, OAuth-first credentials, architecture judge row, plan/docs synced.
- [#12 — Local Docker sandbox MCP server (drop paid Daytona)](https://github.com/rahulsurwade08/patchproof/pull/12): Qodo raised 11 findings (6 bugs + 5 rule violations) — session-label container collisions, container-creation races, leaked containers on shutdown, unbounded request bodies, unknown tools reported as tool errors, unredacted sandbox output, forbidden `gh auth token` command in docs, and three stale-doc gaps. Fixed across 24797f2 and f786f5c: SHA-256 hashed container names with per-container locks, ownership-labeled containers with startup crash-recovery and full crash/graceful shutdown cleanup, 1 MiB body cap, `-32602` for unknown tools, credential redaction in all sandbox output, OAuth-command-free credential guidance, and full docs sync (architecture components, plan decisions, ADR-007 correction).
- [#13 — sandbox_build: bake offline deps at image build; agent workflow updated](https://github.com/rahulsurwade08/patchproof/pull/13): Qodo raised 4 High bugs (`ensureContainer` reused vulnerable image, `sandbox_build` ignored patched lockfile, patcher test path `/srv/app/test_main.py` didn't match Dockerfile `COPY . .`, `sandbox_write` schema missing `image`/`network`) + 4 Medium rule violations (`AGENTS.md`, `docs/architecture.md`, `docs/decisions.md`, `plan.md` not updated for build-then-run). Fixed in 7b1eeef: `ensureContainer` enforces image/network match on reuse (recreates if mismatched), `sandbox_build` supports `files` override + `no_cache`, `patcher.md` uses `/srv/test_main.py`, `sandbox_write` schema includes `image`/`network`; all 4 docs updated.
- [#14 — Subagent test gate mechanism](https://github.com/rahulsurwade08/patchproof/pull/14): Qodo raised 5 bugs (`test_gate.sh` exit/JSON/path/timeout/security) + 5 rule violations (`test-runner.md` wrong path/host-side pytest, `AGENTS.md` missing mechanism, `plan.md` missing gate, `docs/architecture.md` missing component). Fixed in 691b223: `test_gate.sh` uses anchored paths, `printf` for valid JSON, `TIMEOUT=60`, mandatory sandbox-only reference; `test-runner.md` enforces sandbox-only; all 3 docs updated with test-gate stage.
- [#15 — S05 automation depth (negative case gate verified)](https://github.com/rahulsurwade08/patchproof/pull/15): Qodo raised 1 finding (`test_gate.json` `"pass"`: `true` with `exit_code`: 1 — contract requires `passed` boolean, `exit_code` for pytest, `poc_exit`/`poc_verdict` for PoC). Fixed in d41f3e7: gate file uses `passed`/`exit_code` (pytest) + `poc_exit`/`poc_verdict` (PoC); script uses `printf` valid JSON; timeout enforced; sandbox-only path preserved. Resolution: [comment](https://github.com/rahulsurwade08/patchproof/pull/15#discussion_r3865795025).
- [#16 — Subagent final integration (gate + hook + docs)](https://github.com/rahulsurwade08/patchproof/pull/16): Qodo raised 6 findings — (1) gate bypasses local-sandbox MCP (docker build/run directly), (2) AGENTS.md omits new gate command, (3) architecture lists obsolete test_gate.sh, (4) PoC verdict fabricated from pytest instead of real execution, (5) push gate unenforced (no tracked hook), (6) failure diagnostics discarded. All fixed across 16b4b6e + 2ae8b6c: gate routes through MCP via JSON-RPC (sandbox_build + sandbox_exec), PoC resolved from cve-meta.json contract and executed separately via sandbox_exec with real verdict.json read, tracked scripts/install-hooks.sh for pre-push hook with enforcement chain documented in AGENTS.md, build/pytest/PoC diagnostics preserved on failure, gate script header references hook installer, AGENTS.md + architecture.md updated. Resolution: [summary](https://github.com/rahulsurwade08/patchproof/pull/16#issuecomment-5430022549).
- [#17 — fix: MCP-only pre-push gate](https://github.com/rahulsurwade08/patchproof/pull/17): Qodo found no issues.
- [#18 — feat(s04): add Jinja2 sandbox escape scenario (CVE-2024-56326)](https://github.com/rahulsurwade08/patchproof/pull/18): Qodo raised 7 findings — (1) [High] filter did `value.format()` directly — validated as correct CVE pattern (patcher must fix both dep + filter); (2) [High] PoC only proved type disclosure without marker file — added marker write to `/tmp/patchproof_pwned`; (3) [High] `test_gate.sh` ran pytest without starting uvicorn first — rewrote gate to start server + poll health; (4) [Medium] S04 added without S01/S05 acceptance gate — added enforcement to AGENTS.md; (5) [Medium] PoC had no 60s runtime cap — added `time.monotonic()` timeout; (6) [Medium] Dockerfile bound to `0.0.0.0` — changed to `127.0.0.1`; (7) [Medium] PoC didn't generate `assessment.json` — added judge review output.
- [#19 — feat(dashboard + S06 DVPWA SQL injection)](https://github.com/rahulsurwade08/patchproof/pull/19): Qodo raised 18 findings across two review cycles. Cycle 1 (14 findings) — `test_gate.sh` `--network host` → `--network none`; `run_poc_local.sh` `docker cp` → `docker exec cat`; S04/S06 assessment types fixed (confidence: numeric, range_check: boolean); timing removed from verdict evidence; S06 DROP TABLE test → search exfiltration test; S04/S06 Dockerfiles bound to `0.0.0.0` for Compose; docker-compose ports bound to `127.0.0.1`; XSS via `esc()` HTML-escaping; EVENT_LOG populated via `_scan_events_from_files()`. Cycle 2 (6 new findings) — MCP server `ensureContainer` network comparison bug (Docker inspect returns empty list for `--network none`, fixed to treat empty as matching); orchestrator prompt missing `network: none` on sandbox calls + `0.0.0.0` → `127.0.0.1`; S04 stale marker (added pre-attempt clear + per-run nonce correlation); dashboard event dedup (moved `seen` set to module level). All 18 findings resolved.
- [#23 — feat: static reachability analyzer (reach.py + gen_context.py)](https://github.com/rahulsurwade08/patchproof/pull/23): Qodo raised 44 findings across six review cycles; every finding got a per-thread resolution reply and all threads were resolved. Per-finding resolutions:
  - **Cycle 1 (22)** — fixed in ac67fe5: (1) analyzer consumes advisories pre-gated by the orchestrator's dual-source `cve_cross_check`; bare-CVE OSV path returns UNKNOWN, never a safe verdict on its own. (2) verifier redesigned so PoC and patched service share one container with `network: none` always. (3) judge `assessment.json` switched to numeric confidence 0.0–1.0 + boolean `range_check`. (4) AGENTS.md analyzer documentation included in PR. (5) plan.md analyzer stage included. (6) ADR-010 entry included in docs/decisions.md. (7) architecture.md analyzer stage + `reachability.json` artifact included. (8) import bootstrap so `python agent/analyzer/reach.py` runs directly. (9) PEP 621 `project.dependencies` lists parsed. (10) non-exact specs (>=, ^, ~) → declared-but-unpinned UNKNOWN with sandbox gate, never package-absent. (11) prereleases rank before final release (1.0rc1 < 1.0). (12) mixed UNKNOWN+static sites aggregate to UNKNOWN. (13) all sites classified before the 40-item serialization cap. (14) name-substring "static" evidence removed — NOT_REACHABLE requires a quoted file-path literal with a static-data extension whose file actually exists in the repo (checked-in evidence verified via filesystem check; a quoted-but-nonexistent path classifies as UNKNOWN instead). (15) CommonJS `require()`/`import()` recognized + aliasing limitation documented. (16) OSV events parsed as introduced/fixed intervals. (17) all OSV affected packages retained, selected by repo evidence. (18) `--out` builds a complete copy context. (19) node entries get `CMD ["node", ...]`. (20) npm lockfile copied and `npm ci` only when present. (21) pyproject copies source before `pip install .`. (22) Dockerfile/.dockerignore never overwritten without `--force`.
  - **Cycle 2 (11, 7 new)** — fixed in c1551fe: (1) poetry group tables descended into `[tool.poetry.group.<n>.dependencies]`. (2) `scan_repo` keeps every manifest declaration per package (no first-entry hiding). (3) advisory loader accepts alternate inbox keys (`affected_package`/`dependency`/`affected_range`/`summary`). (4) trailing zeros insignificant (1.0 == 1.0.0). (5) patcher re-injects the PoC after image-change container recreation. (6) analyzer skill/prompt prescribe host execution with an explicit execution boundary (sandbox can't see host repos). (7) `~`/`^`/range specs are not pins. (8) orchestrator wires analyzer as stage 1a before any sandbox build. (9) pinned-but-unreferenced verdict gating addressed further in cycle 3. (10) multi-manifest selection evaluated per entry. (11) OSV multi-package selection by repo evidence.
  - **Cycle 3 (5)** — fixed in d7a9f9b: (1) generated `.dockerignore` blocks secrets (.env, keys, .aws/.ssh, credentials, .npmrc/.pypirc) per ADR-016. (2) `find_package` returns all sibling declarations. (3) wildcard specs (`==1.2.*`) are not pins — version-unknown. (4) PEP 440 post-releases rank between final and next patch. (5) pinned-but-unreferenced package → UNKNOWN with sandbox gate (fail open; transitive dependency usage can't be ruled out statically).
  - **Cycle 4 (3)** — fixed in a03af3c: (1) PEP 503 name normalization (`zope.interface` ↔ `zope-interface`). (2) `preview` ranks as rc. (3) local versions (`+foo`) rank between final and post.
  - **Cycle 5 (2)** — candidate local label ignored when the specifier boundary has none (1.0+vendor satisfies <= 1.0); npm identity kept exact lowercase (no PEP 503 conflation of `@scope` names), with `find_package` trying both schemes.
  - **Cycle 6 (1)** — this evidence entry rewritten to state each finding's specific resolution (cycle totals 22+11+5+3+2+1 = 44). **Merged 2026-08-27; a tenth cycle (5 findings) posted post-merge and was fixed forward in [#24](https://github.com/rahulsurwade08/patchproof/pull/24)** — conflict-aware static/network evidence, relative-path crash fix, explicit uvicorn launcher install, node listener requirement, JSON-encoded CMD.
  Tests: 35 passed; traceability comments on each thread: [summary](https://github.com/rahulsurwade08/patchproof/pull/23#issuecomment-5442068760).
- [#24 — fix: tenth-round Qodo findings on merged PR #23 (fixed forward)](https://github.com/rahulsurwade08/patchproof/pull/24): Qodo raised 9 findings across 3 review cycles (0 findings in the 4th). Cycle 1 (4) — node `createServer()`/`fastify()` constructors without `.listen()` treated as serving (now ValueError); plan.md honesty rules missing the conflicting-evidence branch (static literal + network provenance → UNKNOWN, documented); uvicorn launcher installed after repo deps could upgrade a pinned vulnerable `uvicorn==0.29.0` (now installed BEFORE repo deps so repo pins re-assert); static evidence restricted to the truncated symbol line lost multiline-call literals (continuation capture added). Cycle 2 (3) — fixed two-line continuation wasn't call-bounded (replaced with balanced-delimiter span scan, string/escape-aware, 30-line cap); node `.listen()` accepted all-interface binds (now requires explicit 127.0.0.1/localhost/::1); python listener-loop entries regressed by the regex split (`.listen()` + serving loop restored). Cycle 3 (2) — bracket characters inside comments extended the call span (comment-aware scan added: py `#`, js `//`/`/* */`); python `.listen()` still accepted all-interface binds (loopback bind now required, matching node; runner calls keep safe defaults). Fixed in 0d7faf2, 87f92bd, c0dcb3a. Final: Bugs (0), Rule violations (0).
- [#25 — docs: review-loop learnings + agent merge authority](https://github.com/rahulsurwade08/patchproof/pull/25): Qodo raised 5 findings across 2 cycles (0 findings in the 3rd). Cycle 1 — future-dated merge-authority grant (corrected to 2026-08-27), plan/orchestrator still requiring human merge (synced: agent merges Qodo-clean patch PRs, staging deploy stays human-only), and the merge-authority rule itself flagged as a security bypass (**dismissed with rationale**: explicit maintainer grant, recorded in AGENTS.md). Cycle 2 — ADR-013 stale (amended with the merge-authority decision + four prerequisites) and merge prerequisites omitting the README evidence requirement (all four copies now require Qodo-clean + tests green + traceability + README evidence current). Fixed in c232af8, f8f3c6d.
- [#26 — feat: port cve-feed MCP server from Node to Python (ADR-011)](https://github.com/rahulsurwade08/patchproof/pull/26): Qodo raised 8 findings across 3 cycles (0 findings in the 4th). Cycle 1 — OSV pagination truncation could yield a false NOT_IN_SCOPE (now verdict UNKNOWN with reason when pages remain), non-object JSON payloads crashed the persistent stdio process (ignored), identifiers not URL-quoted (urllib.parse.quote restored the retired encodeURIComponent fidelity), 7-file diff over the 5-file cap (doc changes split out; the registration-guidance corrections were also wrong — TrueForge is remote-URL-only), architecture/AGENTS/trueforge-setup stale references (split to [#27](https://github.com/rahulsurwade08/patchproof/pull/27)). Cycle 2 — explicit JSON-RPC `"id": null` was dropped like a notification (replied with id null, matching the retired server). Cycle 3 — none new; the file-cap items were closed after the diff came to 5 files. Fixed in a2b4621, 0522bb3.
- [#27 — docs: MCP registration guidance sync after cve-feed Python port](https://github.com/rahulsurwade08/patchproof/pull/27): Qodo found no issues (0 findings, first pass). Named the Python stdio server in `docs/trueforge-setup.md` §5 and the architecture row, corrected the judge degraded-mode reason (TrueForge is remote-URL-only; stdio needs the HTTP wrapper), and added README Qodo-evidence entries for PRs #25/#26.
- [#28 — feat: port local-sandbox MCP server from Node to Python (ADR-011)](https://github.com/rahulsurwade08/patchproof/pull/28): Qodo raised 9 findings across 2 cycles. Cycle 1 (7) — runtime containers accepted caller-supplied named networks (now hard-enforced `--network none`, fail closed); `sandbox_build.files` override keys could escape the temp context onto the host (absolute-path/traversal rejected, realpath containment); omitted network/image passed `None` into docker argv (defaults restored); `TimeoutExpired` output bytes broke the 124-timeout path (normalized); non-object JSON dropped the HTTP connection (400/-32700); oversize bodies poisoned keep-alive (413 + Connection: close, body unread); deleted Node entry point left as a launch target (deletion restored to the follow-up rollout). Cycle 2 (2) — named-network rejection bypassed via container reuse (rejection moved before any inspect); valid dot-prefixed filenames like `..env` over-blocked (realpath containment is the sole guard). Fixed in 485429e, 45a255a. Final: Bugs (0), Rule violations (0).
- [#29 — feat: retire Node local-sandbox server; switch launch references to Python](https://github.com/rahulsurwade08/patchproof/pull/29): Qodo raised 3 findings across 3 cycles. Cycle 1 — README + trueforge-setup copy-paste launch commands still invoked the deleted Node entry point (switched to `python3 agent/mcp/local_sandbox_server.py &`). Cycle 2 — launch commands used `python`, absent on hosts without an unversioned alias (all `python3`); README claimed the local sandbox "Requires only Docker" (corrected to Docker + Python 3.9+). Cycle 3 — none new; the 6-file count was waived with rationale (same-rollout constraint imposed by #28's finding 6: splitting launch references recreates the broken-startup window). Final: Bugs (0), Rule violations (0).
- [#30 — docs: Qodo evidence for PRs #27–#29; ADR-011 complete](https://github.com/rahulsurwade08/patchproof/pull/30): Qodo found no issues (Bugs 0, Rule violations 0; 0 review threads). Docs-only sync of README evidence for #27/#28/#29 and ADR-011 (Python migration complete).
- [#31 — fix: gen_context reuses the repo's declared base image](https://github.com/rahulsurwade08/patchproof/pull/31): Qodo raised 14 findings across 3 review rounds, all resolved. `_detect_base_image` parses the first FROM across a repo's Dockerfile\* and reuses it, defaulting only when none is declared. Resolved in db8501e (AGENTS.md + architecture.md document base reuse and its python/node allowlist trust constraint; raw-socket 413 test reads to EOF), cda2f0e6 (lstat-only file scan so repo symlinks are never followed; streaming read so large Dockerfiles aren't materialized; FROM `--platform=` flags skipped and official python/node digest refs allowlisted; malformed tags/digests rejected), 2448cad94 (deterministic test fix), ed9aee532 + 214c46be5 (PR description/docstring corrected to the actual scan-skip-acceptable-FROM fallback semantics).
- [#32 — fix: sandbox keep-alive works on old busybox (alpine3.8-era bases)](https://github.com/rahulsurwade08/patchproof/pull/32): Qodo raised 4 findings, all resolved in 3847fada. `sleep infinity` (rejected by busybox 1.29) → indefinite `while :; do sleep 3600; done` (no 24-h session expiry); post-launch inspect confirms Running and carries ExitCode into terminal errors (diagnostic no longer discarded); AGENTS.md + PR description synced to the implemented loop.
- [#33 — feat: analyzer consumes cve-feed MCP OSV records (osv wiring polish)](https://github.com/rahulsurwade08/patchproof/pull/33): Qodo raised 13 findings; **10 resolved, 3 still OPEN/unresolved**: (1) ["Unsupported ecosystems cross-match dependencies"] (2) ["Ranges ignored with versions"] (3) ["Python dependency lookup lost"] — all in `reach.py` `_select_dep`'s OSV handling, not fixed forward by #36 (which only touched gen_context/sandbox). Most resolved via the ea5e62f revert scoping the PR to a single OSV concern (verbatim repo-Dockerfile reuse and its Security/Correctness/Maintainability findings 1,3,4,5,6,7,9 moved to a follow-up PR); AGENTS.md updated for cve-feed-first advisory workflow; OSV `last_affected` closes intervals inclusively, `affected[].versions` retained and scoped by exact membership, and `package.ecosystem` carried through to filter manifest kinds. Tracked to a follow-up fix PR.
- [#34 — feat: sandbox_build accepts a dockerfile name relative to the context](https://github.com/rahulsurwade08/patchproof/pull/34): Qodo raised 11 findings, all resolved. The verbatim-reuse security findings (1–7) were moved to the follow-up gen_context PR (server-only scope made them moot here) and landed in #35/#36. This PR's own fixes: 76ec299d (realpath containment so an in-context symlink escaping the context is rejected; only regular files scanned; AGENTS.md documents the new `dockerfile` option) and 34805c646 (docker build `-f` receives the validated ABSOLUTE resolved path, with d05e5367f updating the `-f` test).
- [#35 — feat: gen_context writes Dockerfile.patchproof (never touches repo files)](https://github.com/rahulsurwade08/patchproof/pull/35): Qodo raised 8 findings across 3 rounds, all resolved. The working build definition is always `Dockerfile.patchproof` (built via #34's `-f`), so repo Dockerfile variants are never overwritten. Resolved in 2073bf77 (hoist `# syntax=`/`# escape=` parser directives above the generated marker; workflows told to pass `dockerfile: Dockerfile.patchproof`; inherited repo ENTRYPOINT cleared before CMD; WORKDIR resolved per final stage with Docker relative/variable semantics; start argv shlex-joined; `_write_file` refuses to write through a pre-existing symlink), 52b9b8f1 (marker appended after hoisted directives), and b6cfd834 ($VAR and ${VAR} both mark a WORKDIR unresolvable).
- [#36 — feat: version-matched minimal base + two-tier fallback build](https://github.com/rahulsurwade08/patchproof/pull/36): Qodo hardened the fallback-start recipe across 22 review rounds; every finding got a per-thread resolution reply and all threads resolved (0 open). Highlights — a repo Dockerfile is used as a build escalation ONLY when its FROM base is an allowlisted official `python`/`node` image for the project language (ADR-016/ADR-017); `_final_workdir` rewritten around per-stage known paths (rejects traversal and variable/undeclared/inherited-undeclared WORKDIRs); the service is started from the APP ROOT derived by stripping the entry's recorded RELATIVE components from the probed path (not the entry's dir, avoiding the `/src/src` doubling); each argv element and the cd path are single-quote-escaped against shell injection; the app root is always located from the entry probe because WORKDIR doesn't prove the copy location; the probe matches `-type f -o -type l` (symlinked entries) with exact end-of-path suffix matching; control-character entry paths are rejected at the source; `sandbox_build` returns no session, so the doc uses a run-unique session label with `image` on the first exec; and it's documented that `docker exec` bypasses ENTRYPOINT/CMD (the one live-review "OPEN" — an entrypoint finding — is a false positive waived with rationale). 144 tests pass.
- [#37 — docs: backfill Qodo review evidence for PRs #30–#35](https://github.com/rahulsurwade08/patchproof/pull/37): Docs-only sync — backfilled missing README Qodo Evidence entries for #30–#35 (chronologically between #29 and #36) with per-thread resolution links; no code changes.
- [#38 — feat(dashboard): add hermetic backend test suite](https://github.com/rahulsurwade08/patchproof/pull/38): Qodo raised 9 findings across 3 cycles, all resolved (0 open, Bugs 0/Rules 0). Adds 8-test hermetic suite for `dashboard/app.py` (SCENARIOS_DIR monkeypatched to temp dir, EVENT_LOG reset, declared `pytest==9.1.1`/`httpx==0.27.0` via `requirements-dev.txt`, route-table SSE check for `/api/stream` GET). Wires mandatory pre-push gate: `install-hooks.sh` stdin SHA range (empty-tree for new branch, branch-deletion skip via `^0*$`), `run_gate_before_push.sh` dashboard branch (sandbox_build `Dockerfile.patchproof` → sandbox_exec with EXIT trap for `sandbox_stop`, stderr handling, `json_field` fix), `.gitignore` for `dashboard/test_gate.json`/`skills-lock.json`. Verified 8 dashboard + 144 analyzer/mcp tests, `bash scripts/run_gate_before_push.sh dashboard` passes via MCP.
