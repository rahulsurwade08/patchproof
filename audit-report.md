# PatchProof Audit & Code Review Plan

**Branch:** `audit/code-review` (no PR, no merge — operator merges manually)
**Date:** 2026-09-02
**Mode:** ponytail full

## Goal

Two passes:
1. **ponytail-audit** — find over-engineering, dead code, stdlib rewrites, single-implementation abstractions, yagni, hand-rolled stdlib. Rank biggest cuts first. No fixes.
2. **Code review** — correctness, security, performance, robustness, error handling, edge cases, naming, docstring accuracy. Also no fixes — just a report.

Both passes are read-only. Operator reviews the report, picks what to act on.

## Scope

In scope:
- `agent/` — orchestrator, scan, build_image, exploit, analyzer, mcp, prompts, skills
- `scripts/` — mcp_client, reset_state
- `data/output/` — only as reference, not audited
- `.opencode/` — agent + command (no ponytail on harness config)
- Top-level: README, AGENTS, plan, .env.example, .gitignore

Out of scope:
- `data/output/` runs (per-run artifacts)
- `session-*.md` (session logs)
- `node_modules/`, `.pytest_cache/`, `__pycache__/`
- `scenarios/`, `dashboard/`, `demo-app/`, `harness/`, `infra/` (already deleted)

## Method

Read each file once. Build the finding list while reading. After all files:
- ponytail-audit pass: ranked by `lines_saved * reach`
- code review pass: ranked by severity (correctness > security > robustness > perf > style)

Both reports written to this file's tail at the end. No edits to source.

## Pass 1: ponytail-audit

Tags: `delete`, `stdlib`, `native`, `yagni`, `shrink`

Loop:
1. Glob one module/subtree
2. Read all files in parallel
3. Add findings as `[path:line] <tag> <finding>. <replacement>.`
4. Continue

## Pass 2: code review

Categories:
- **correctness** — logic bugs, off-by-one, wrong file paths
- **security** — sandbox escapes, path traversal, command injection, secrets
- **robustness** — error handling, retries, timeouts, edge cases
- **api/contract** — function signatures, return types, data contracts
- **docs** — README/AGENTS/plan vs code reality

Loop:
1. Read with grep for known anti-patterns
2. Add findings as `[path:line] <sev> <finding>.`
3. Continue

## Output

Two tables at the end:
- ponytail: ranked by `lines*reach`
- review: ranked by severity

Then a "small wins I noticed but won't auto-fix" section for things a code-reviewer would catch but a ponytail pass shouldn't.

## Pass 1: ponytail-audit (ranked by impact)

Findings:

**1. delete `exploit.py:64-70` — `pull_()` has wrong param names. `sandbox_pull` takes `path`/`host_path`, `pull_()` passes `src`/`dst`. Function is never called anywhere. 7 lines.**

**2. delete `local_sandbox_server.py:216` — `_shutting_down` flag is set in `shutdown()` and checked at the top of `shutdown()`, but `shutdown()` is only ever called once per process (from a signal handler or `main()` exit). The flag is never read from another thread or call site. 1 line.**

**3. delete `local_sandbox_server.py:343-345` — `_GITHUB_URL_RE` is defined but never used. `gen_build_context` delegates to `agent.analyzer.gen_context`, which does its own URL parsing. The regex is dead code. 3 lines.**

**4. yagni `agent/exploit.py` — wrapper module with 5 helper functions. `write_()`, `exec_()`, `stop_()` map 1:1 to the MCP tool. `read_()` has wrong `image` param. Only `run_exploit_for_cve()` is non-trivial. The helpers add indirection without abstraction value — the agent calls MCP directly anyway. Consider inlining into `run_exploit_for_cve()` or dropping the module entirely. 0 lines saved, but 118 lines of confusion.**

**5. yagni `exploit.py:24-25` — `session_id()` is a one-liner f-string. No need for a function. 2 lines.**

**6. shrink `build_image.py:69-93` — `start_sh` template could use a heredoc or simpler string formatting. Current 25-line template with embedded bash is readable but could be 10 lines. Low priority.**

**7. native `build_image.py:33-37` — `image_exists()` runs `docker images -q`. Python's `subprocess` is fine here; the alternative is the `docker` Python SDK which is a much heavier dep. Not worth cutting.**

**8. native `versions.py:61-70` — `_mixed_compare()` hand-rolls comparator logic. `functools.cmp_to_key` could replace it. But version comparison is security-adjacent and the hand-rolled version is auditable. Not worth touching.**

**net: ~13 lines deletable. 0 dependencies to remove. The codebase is lean.**

---

## Pass 2: Code Review (ranked by severity)

### Correctness

**1. `exploit.py:64` — `pull_()` `src`/`dst` vs `sandbox_pull`'s `path`/`host_path`.** Wrong param names. The function is dead (never called), so it has no runtime effect. But if anyone tries to use it, it silently passes wrong keys. Severity: low (dead code).

**2. `exploit.py:48` — `read_()` passes `image` but `sandbox_read` has no `image` param.** The MCP tool schema for `sandbox_read` only takes `{session, path}`. The `image` kwarg is silently ignored. Doesn't break anything but is misleading. Severity: low.

**3. `reach.py:674-707` — `_version_in_affected_ranges` ecosystem check: if OSV returns an empty ecosystem string, the check `pkg.get("ecosystem", "") and pkg["ecosystem"] != ecosystem` evaluates to `False`, so the ecosystem mismatch is silently skipped. A PyPI package with an empty ecosystem field in OSV data would incorrectly match an npm advisory. Severity: low (OSV always populates ecosystem in practice, but the code is fragile).

**4. `scan.py:44-45` — when `discovered_cves.json` is missing, returns `"cves_discovered": 0`. But the caller `orchestrate.py` uses this for the "CVEs found" print. If the file doesn't exist, it means the scan failed (e.g., no packages found), and 0 is misleading — should indicate a warning. Severity: low.

### Security

**1. `exploit.py:102` — `run_exploit_for_cve()` command construction is safe.** The PoC filename `/srv/poc.py` is hardcoded, so no injection. The `start_cmd` parameter could theoretically contain user-supplied content, but it comes from `build_image.py`'s own `start_sh` template (hardcoded), not from user input. No security issue.

**2. `local_sandbox_server.py:508-511` — `sandbox_write` uses `docker exec -i ... cat > "$1"` with path as argv. Path is a literal string parameter, not interpolated into a shell string. The input content goes through stdin. No injection. **Clean.**

**3. `local_sandbox_server.py:70-74` — `redact()` regexes run on all tool output. Backtracking on complex credential patterns is possible but unlikely to cause DoS from untrusted container output. Acceptable.**

### Robustness

**1. `exploit.py:96-99` — service start check is fragile.** Checks `"READY" in r.get("stdout", "")`. If the service prints something before "READY" (e.g., a warning or debug log), the check still works because it's a substring search. But if the service crashes after printing "READY" but before the PoC runs, the function proceeds with a dead service. The PoC then fails or times out, producing a misleading "service start failed" verdict. Severity: medium. Fix: check `start_cmd` exit code too, not just stdout.

**2. `exploit.py:91-117` — no container cleanup on MCP failure.** If `write_()` or `exec_()` raises (MCP server down, connection error), the `finally` block calls `stop_()`, which is also an MCP call — if that fails too, the container is orphaned. Severity: low. In practice the MCP server is local and reliable.

**3. `build_image.py:107-125` — symlink-based build context.** `(ctx / item.name).symlink_to(item)` for directories. If a directory in the repo is a symlink pointing outside the repo, Docker will follow it and copy external content into the image. Also, symlinks to `data/` or `venv/` (which are in the root but not filtered) could cause issues. Severity: medium. Fix: skip symlinks entirely (copy dirs instead).

**4. `build_image.py:112-119` — `.env` excluded, but `_env`, `.env.local`, `.env.production` are not.** Any dotfile in the repo root gets copied into the image. Severity: low. Fix: filter all dot-prefixed items.

**5. `local_sandbox_server.py:469-471` — `MAX_OUTPUT = 20000` truncation: `res["stdout"] + res["stderr"]` could be up to 40000 chars before truncation. Truncation is post-redaction. Not a real issue.**

**6. `cve_feed_server.py:186-201` — `osv_query_all` caps at 5 pages (50 entries). The `max_pages=5` default means if OSV has >5 pages of vulnerabilities for a package, the result is silently truncated and `truncated=True` is returned. For packages like `aiohttp` (89 CVEs across many pages), this under-reports. Severity: medium. Fix: increase cap or paginate to completion for small-package-name lookups.

### API / Contract

**1. `exploit.py` interface vs reality.** The module docstring says "the agent uses these helpers." But the agent calls MCP tools directly. `exploit.py` is only used by `orchestrate.py`'s Python code path (not the LLM agent path). This is fine — two paths, both documented — but the docstring is misleading. Severity: docs.

**2. `orchestrate.py:55-68` — `--cve` mode with no existing `triage.json` creates a triage with `cves_discovered: 0` and `exploitable: [args.cve]`. This bypasses the scan entirely. The LLM agent would then try to test this CVE without any reachability info. If the CVE doesn't exist in OSV, the PoC would run against a "dummy" target. Severity: medium (misuse scenario, but dangerous — the CVE would be tested with no context).

**3. `reach.py:818-830` — `main()` returns 0 but errors call `sys.exit(1)`. The `_handle_discover` and `_handle_regular` paths print errors and exit, not return. Consistent, but the `return 0` at the end of `main()` is unreachable. Severity: style.

### Performance

**1. `build_image.py:26-30` — file-hash fallback is O(repo size).** The comment acknowledges this. For large repos, `git rev-parse HEAD` is fast, but on repos without `.git` (e.g., downloaded tarballs), the full scan runs. Severity: low. Rare case.

**2. `reach.py:287-313` — `_find_call_sites` walks the entire repo tree on every CVE.** For a repo with 100 CVEs, the same source files are read 100 times. An index built once and cached would be faster. Severity: low. `reach.py` is only run once per CVE (via `scan.py`'s loop), not re-run.

**3. `cve_feed_server.py:186` — `osv_query_all` with `max_pages=5` is the default but `osv_query` calls it with the same cap. No page-size limit means the cap is arbitrary. See robustness issue above.**

### Docs

**1. `exploit.py:1-9` — docstring says "the agent uses these" but the agent uses MCP directly.** The Python path (`orchestrate.py` → `exploit.run_exploit_for_cve`) does use the helpers. The statement is technically true but ambiguous.

**2. `local_sandbox_server.py:24` — "This is the Python port of agent/mcp/local-sandbox-server/index.mjs (ADR-011)" — ADR-011 was deleted in PR #84. The reference is stale.

**3. `reach.py:16` — "Honesty rules (ADR-010)" — ADR-010 was deleted in PR #84. Reference is stale.**

**4. `build_image.py:6` — "ponytail: only Python is supported" — the comment correctly describes the current state, not a planned limitation. Should say "currently Python only" instead of "ponytail:" prefix which reads as a future deferred item.

---

## Summary

### Ponytail: net -13 lines deletable. Lean codebase.

| Rank | Tag | Finding | Location | Lines |
|---|---|---|---|---|
| 1 | delete | `pull_()` wrong schema + never called | `exploit.py:64-70` | 7 |
| 2 | delete | `_shutting_down` flag never read | `local_sandbox_server.py:216` | 1 |
| 3 | delete | `_GITHUB_URL_RE` never used | `local_sandbox_server.py:343-345` | 3 |
| 4 | yagni | `exploit.py` helpers add indirection; agent calls MCP directly | `exploit.py` | 118 conf |
| 5 | yagni | `session_id()` one-liner | `exploit.py:24-25` | 2 |

### Code review: 18 findings

| Rank | Severity | Category | Finding |
|---|---|---|---|
| 1 | medium | robustness | Service start check doesn't verify service is still alive |
| 2 | medium | robustness | Symlink build context can follow external symlinks into image |
| 3 | medium | robustness | `osv_query_all` silently caps at 5 pages, under-reporting CVEs |
| 4 | medium | api/contract | `--cve` mode with no triage.json bypasses all analysis |
| 5 | low | correctness | `pull_()` wrong param names (dead code) |
| 6 | low | correctness | `read_()` passes unused `image` param |
| 7 | low | correctness | `_version_in_affected_ranges` fragile ecosystem check |
| 8 | low | docs | `exploit.py` docstring misleading |
| 9 | low | docs | ADR-010, ADR-011 references in code are stale |
| 10 | low | robustness | Dotfiles other than `.env` copied into image |
| 11 | low | robustness | No container cleanup if `stop_()` MCP call fails |
| 12 | style | api | `main()` has unreachable `return 0` |

### Small wins (not auto-fixed, code-reviewer's notes)

- `local_sandbox_server.py:143` — `while :` busy-loop is correct but `sleep 3600` is more idiomatic. Not a bug.
- `exploit.py:97` — `"READY" in ... or "ready" in ...` is case-insensitive but the actual start.sh outputs uppercase "READY". The lowercase check is dead code.
- `reach.py:106-109` — `_load_advisory` has two nested code paths for OSV-shaped files (both `"affected"` list and `"affected_versions"` string) that return subtly different `source` values. The difference matters for the verdict.
- `build_image.py:83-90` — the port 8080 hardcode in the wait loop doesn't match the `EXPOSE 8080` in the Dockerfile. The start.sh waits for 8080 but the Dockerfile exposes it. If a service listens on a different port, the wait never succeeds.
- `cve_feed_server.py:408` — `request-id: {os.getpid()}` is wrong: each request gets the server's PID, not a per-request ID. Should be a counter or UUID.

---

## Status

[draft — pending operator review before acting on findings]
