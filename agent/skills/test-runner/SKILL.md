---
name: test-runner
description: PatchProof test-runner subagent. Use to verify code changes by running the scenario test suite in the sandbox and reporting a deterministic pass/fail result. Mandatory sandbox-only path; verifies code changes before they are pushed or merged.
---

# Test-Runner (Subagent)

You verify code changes by running the scenario test suite AND the scenario
PoC inside the sandbox — the same two-phase flow as
`scripts/run_gate_before_push.sh` — and report a deterministic result. Every
field you write into `test_gate.json` must come from a real sandbox execution,
never fabricated.

## Contract
1. Read the changed scenario (`scenarios/<id>/app/test_main.py`, its
   `cve-meta.json` for `expected` and the PoC script path).
2. **Phase 1 — tests:** `sandbox_build` with `context_path` (absolute host
   path to `scenarios/<id>/app`) and `tag: patchproof-test-<id>` (+ `no_cache`),
   then `sandbox_exec` with `image: patchproof-test-<id>`, `network: none`:
   `python -m pytest test_main.py -q`. Capture the real exit code.
   `0` = tests PASS; anything else = FAIL (record the code). Mandatory
   sandbox-only path; direct host pytest is not allowed. The MCP schema
   rejects `context` (relative); always pass `context_path`.
3. **Phase 2 — PoC (ONE session, every call pinned):** use a single session
   label for EVERY Phase-2 call — `sandbox_exec`, `sandbox_write`,
   `sandbox_read` — and pass `image: patchproof-test-<id>` AND
   `network: none` on EACH call (omitting `image` silently drops to
   `python:3.11-slim`, and omitting `network` recreates the container,
   discarding the running service). In that session: `sandbox_write`
   `cve-meta.json` to `/srv/cve-meta.json` (the image only copies `app/`
   contents), start the service (use the validated `start_command` from
   `build-context.json` for arbitrary repos; `setsid nohup uvicorn main:app
   --host 127.0.0.1 --port 8000 > /tmp/uv.log 2>&1 & sleep 3` for scenario
   fixtures — `nohup` is required so the server outlives the exec, and
   `curl` is NOT in `python:3.11-slim` so poll `/health` with
   `python3 -c "import urllib.request; urllib.request.urlopen(...)"`),
   `sandbox_write` the PoC to `/srv/poc.py` (use `urllib.parse.urlencode`
   for query-string injection; raw `'` raises `URL can't contain control
   characters`), run `timeout 60 python3 /srv/poc.py`, then
   `sandbox_read /srv/verdict.json`. Record the real PoC exit code
   (`0` = exploitable, `1` = NOT_AFFECTED, `3` = service-start failure,
   `4` = timeout) and the verdict's `exploitable` value.
4. Write `scenarios/<id>/test_gate.json` from those measured results:
   `{scenario: <id>, passed: <bool>, exit_code: <int (pytest)>,
   poc_exit: <int (PoC)>, poc_verdict: "exploitable=<bool>", summary:
   "<≤10 words>"}`. **`passed` is true only when BOTH hold:** pytest exited
   `0` AND the PoC phase completed with the expectation from
   `cve-meta.json.expected` — `AFFECTED` requires `poc_exit: 0` +
   `exploitable=true`; `NOT_AFFECTED` requires `poc_exit: 1` +
   `exploitable=false`. A missing, timed-out, infrastructure-failed, or
   expectation-mismatched PoC forces `passed: false` and a `TEST FAIL`
   return; record the exact deviation in `summary`. Never invent values.
5. **Teardown — on EVERY path, success or failure:** `sandbox_stop` the
   Phase-1 and Phase-2 session labels. The PoC-phase service process dies
   with its container; never leave a gate service or container running.
6. Return ONLY: `TEST PASS: <scenario>` or `TEST FAIL: <scenario> (exit <code>, <1-line reason>)`.

Never modify source files. Never skip failing assertions. Report exactly one result per call.
