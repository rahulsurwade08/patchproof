# Custom Harness Build Plan — Frontend + Backend

> Build PatchProof's own harness (frontend + backend) on top of TrueForge, so every skill and MCP works through the harness and tests are centralized. This replaces host-side `python -m pytest` / `curl 127.0.0.1:8081` with `POST /api/v1/sessions/{id}/turns` on `http://[::1]:8790`.

---

## 1. Why custom

Current harness is stock `npx @truefoundry/trueforge --port 8790` with Settings-wired `openrouter` + `github` + `local-sandbox` + 7 PatchProof skills (`analyzer`/`orchestrator`/`reproducer`/`judge`/`patcher`/`verifier`/`test-runner`). It works, but:

- **Frontend** is split: TrueForge UI at `http://[::1]:8790` vs PatchProof `dashboard/app.py` (8 tests, read-only). Demo needs one surface that shows **scanning, reachability, exploit, patch, approval gate** in a single chat transcript with `sandbox_artifacts`.
- **Backend** is borrowed: TrueForge's built-in bwrap sandbox is disabled (`Can't mount on symlink /bin`), we rely on our Docker MCP `agent/mcp/local_sandbox_server.py` at `127.0.0.1:8081/mcp`. No custom server logic for PatchProof-specific concerns (OSV caching, `data/inbox` → `cve-feed` wrapper, `data/output` artifact store).
- **Tests are scattered**: `agent/analyzer/tests` (3, 100 tests), `agent/mcp/tests` (2, 28 tests), `dashboard/test_dashboard.py` (8), `scenarios/*/app/test_main.py` (7), `demo-app/tests` (2) — 15 files, no single `pytest` entry point, no harness-driven CI.

Custom build keeps TrueForge core (agent loop, MCP, skills, sandbox-as-tool) but owns the UI and the server glue so PatchProof skills/MCPs work properly under the harness.

---

## 2. Frontend — custom build on `@truefoundry/trueforge-ui`

**Base:** `https://trueforge.dev/chat-ui` + `https://ui.trueforge.dev` live configurator. SDK is `npx trueforge-ui` React component already shipped with the harness.

**What to build (in `harness/`):**

```
harness/
  frontend/
    package.json            # @truefoundry/trueforge-ui, react, vite
    src/
      App.tsx               # <TrueForgeUI serverUrl="http://[::1]:8790" agentMode="fixed-agent" ... />
      theme.ts              # truefoundry preset + PatchProof red/green/amber (exploitable/UNKNOWN/not_affected)
      layout.tsx            # drawer (dashboard table + chat) vs full-screen with sidebar
      PatchProofArtifacts.tsx # renders reachability.json / verdict.json / assessment.json from sandbox_artifacts
    vite.config.ts
    Dockerfile              # node:20 → nginx, or serve via FastAPI StaticFiles
```

**Customizations:**
- **Agent mode** `fixed-agent` `patchproof-v2` only (hide composer, enforce one-session-per-CVE ADR-004, protect approval gate). Also keep `patchproof-orchestrator` for `s01` demo.
- **Theme** `truefoundry` + PatchProof brand (red `exploitable:true`, green `NOT_REACHABLE`, amber `UNKNOWN`, dark mode optional) via `Theme` provider `customTheme` slot (`ui-sdk/reference/theme.md`).
- **Artifacts** — Generative UI for `reachability.json` (file:line+snippet+input trace), `verdict.json` (marker proof), `assessment.json` (judge). Use `Containers` + `Atoms` (`ui-sdk/reference/containers.md`, `atoms.md`) to render code fences, not just JSON.
- **File flow** — `data/inbox/*.json` advisory drop as UI file attachment → session turn input (replaces host `scripts/fake_cve_injector.py` for demo video).
- **Approval gate** — `ask_user_questions:true` + `require_approval_for_tools:["@write","@destructive"]` on `patcher`/`verifier` → UI shows **Approve/Deny** checkpoint before PR/staging deploy (harness-native, `user.tool_approval` event).
- **Server URL** — `http://[::1]:8790` on this host (`ss [::1]:8790` LISTEN) or `PUBLIC_BASE_URL` if proxied (see `mcp-servers#authentication` for OAuth).

**Not building:** `MODEL_CATALOG_PATH` fork, `customTheme` dark toggle v2, `library+composer` mode — Day 2.

---

## 3. Backend — custom build on TrueForge server

**Base:** `npx @truefoundry/trueforge` Node server (SQLite `~/.local/share/trueforge/db/db.sqlite`, `dist/main.js`). Keep it stock; add PatchProof glue as MCP + skills, not a fork.

**What to build (in `harness/backend/` or keep `agent/mcp/`):**

```
harness/
  backend/
    mcp/
      local_sandbox_server.py   # already Python stdlib, 127.0.0.1:8081/mcp — keep, add image-prune on sandbox_stop
      cve_feed_server.py        # add HTTP wrapper (streamable) so it can be registered as remote MCP (currently stdio, needs wrapper per docs/trueforge-setup.md:70)
    skills/
      # 7 existing skills stay in agent/skills/ but are also registered in harness Settings → Skills as git skills
      # No code change, just Settings → Skills Add git repo https://github.com/rahulsurwade08/patchproof path agent/skills/<name> pin SHA
    server/
      patchproof-bridge.ts      # tiny TrueForge extension: OSV cache, data/output artifact store, data/inbox watcher (optional)
```

**MCPs must work properly:**
- `github` — header `Bearer <GITHUB_TOKEN>` (repo PAT, `auth_status:authenticated` via `GET /api/v1/mcp-servers`), used by orchestrator/patcher for repo matching + PRs.
- `local-sandbox` — `remote` `http://127.0.0.1:8081/mcp`, no auth, `sandbox_build` (with network, `files` override for patched lockfile, `no_cache`) + `sandbox_exec/write/read/stop` (`--network none`, `label=patchproof-sbx=1`, `image` param required — lessons learned). Fix remaining `ensure_container` image-reuse bug (old container still runs) and add `sandbox_stop` EXIT trap.
- `cve-feed` — currently stdio, needs `agent/mcp/cve_feed_server.py` HTTP wrapper (streamable) to register as `remote` (TrueForge is remote-URL only). Until then `data/inbox/*.json` with `demo:true` → `demo-bypass`, fail-closed ADR-010. Provide `cve_get_cve`/`osv_query_package`/`osv_get_vuln`/`cve_cross_check`.

**Skills must work properly:**
- All 7 `SKILL.md` already pass `rg -i daytona` 0 and Qodo 0/0 up to PR #53. Register them in harness Settings → Skills (git, pin SHA) so `GET /api/v1/skills` lists them and `GET /api/v1/catalogs/skills` shows PatchProof skills. Harness materializes them under `/opt/tfy/skills/{name}` at runtime (needs `sandbox.enabled:false` on agents — we use MCP sandbox, not bwrap).
- Ensure `agent: {mcp_servers: [{name:local-sandbox, enable_tools:["@all"]}, {name:github}], skills: [analyzer,...], config: {sandbox:{enabled:false}, dynamic_sub_agents:true, ask_user_questions:true}}` for `patchproof-v2`.

**Server glue (minimal):**
- Optional `harness/backend/server/patchproof-bridge.ts` that watches `data/inbox/` and mirrors `data/output/<repo>/` to `GET /api/v1/sessions/{id}/turns/{id}/download` `sandbox_artifacts` — not required for MVP, but helps the UI show `reachability.json` without extra tool calls.

---

## 4. Centralized test suite — one folder

**Current:** scattered 15 files, `python -m pytest` must be told each dir, `scenarios/*/test_main.py` run via `scripts/run_gate_before_push.sh` sandbox, `demo-app/tests` separate. No single harness-driven CI.

**New layout (in `harness/` or `tests/`):**

```
harness/
  tests/
    conftest.py                 # shared fixtures: harness at [::1]:8790, local-sandbox at 127.0.0.1:8081, temp data/output
    unit/
      test_analyzer_reach.py    # was agent/analyzer/tests/test_reach.py (100)
      test_analyzer_gen_context.py # was test_gen_context.py
      test_analyzer_e2e.py      # was test_e2e.py
      test_cve_feed.py          # was agent/mcp/tests/test_cve_feed_server.py (19)
      test_local_sandbox.py     # was test_local_sandbox_server.py (28) + image-reuse regression
      test_dashboard.py         # was dashboard/test_dashboard.py (8) — now via harness UI
    integration/
      test_scenarios.py         # parametrized over s01-s06 + _template + demo-app (via harness sandbox_build/exec, not host)
      test_harness_e2e.py       # full orchestrator → judge → patcher → verifier via POST /api/v1/sessions/{id}/turns on [::1]:8790
    fixtures/
      scenarios/ -> symlink to ../scenarios
      demo-app/ -> symlink to ../demo-app
```

Or at root `tests/` with same structure — pick `harness/tests/` to keep harness ownership clear.

**Migration steps (separate folder, centralized):**
1. Create `harness/tests/` + `unit/` + `integration/` + `fixtures/`.
2. Move (not copy) existing tests: `git mv agent/analyzer/tests/*.py harness/tests/unit/`, `git mv agent/mcp/tests/*.py harness/tests/unit/`, `git mv dashboard/test_dashboard.py harness/tests/unit/`, keep `scenarios/*/app/test_main.py` as fixtures but add `harness/tests/integration/test_scenarios.py` that drives them via `sandbox_build`/`sandbox_exec` on `[::1]:8790` (replaces `scripts/run_gate_before_push.sh` host path).
3. Add `harness/tests/conftest.py` that starts/stops `local_sandbox_server.py` and asserts `GET http://[::1]:8790/api/v1/mcp-servers` shows `local-sandbox`.
4. One command: `pytest harness/tests -q` → 155+ tests (unit + integration) via harness, not host. Update `.gitignore` if needed (no new ignored files — tests are committed).
5. CI: `scripts/run_gate_before_push.sh` now calls `pytest harness/tests/integration/test_scenarios.py -k $SCENARIO` via harness, not host docker.

**Verification:**
- `pytest harness/tests/unit -q` → 155 passed (same as before, now centralized)
- `pytest harness/tests/integration/test_scenarios.py -k s01 -q` → `s01 exploitable:true` via harness `sandbox_build`/`sandbox_exec`/`sandbox_read`/`sandbox_stop` (container `patchproof-sbx-...`), not host
- `pytest harness/tests/integration/test_harness_e2e.py -q` → one `POST /api/v1/sessions` + `POST /turns` on `[::1]:8790` that streams `tool.call local-sandbox:sandbox_build` and returns `verdict.json` `exploitable:true` → `assessment.json` `agrees:true`

---

## 5. Loop to build it (small PRs, Qodo, harness-only)

| PR | Touch | Verify via harness |
|----|-------|--------------------|
| 1 `harness/frontend` scaffold | `harness/frontend/package.json` + `src/App.tsx` (≤2 files) | `npm run build` → `harness/frontend/dist` loads `http://[::1]:8790` chat |
| 2 `harness/backend` wrapper | `agent/mcp/cve_feed_server.py` HTTP wrapper | `curl http://[::1]:8790/api/v1/mcp-servers` shows `cve-feed` |
| 3 `harness/tests` centralize | `harness/tests/` move (git mv, ≤5 files per PR, split if needed) | `pytest harness/tests/unit -q` 155 passed |
| 4 `fix/sandbox-reuse` | `local_sandbox_server.py:ensure_container` image check + `sandbox_stop` trap | `pytest harness/tests/integration/test_scenarios.py -k demo-app` no `address already in use` |
| 5 `feat/approval-gate` | `agent/skills/orchestrator/SKILL.md` ask_user_questions | harness turn shows `awaiting_approval` before PR |

Each PR: `qodo-get-rules` before coding, `qodo-pr-resolver` on findings, reply + `/review` until `Bugs 0/Rules 0`, merge commit, delete branch. No host `docker`/`pytest` except `scripts/run_poc_local.sh` (CI fallback).

Next: start with `harness/frontend` scaffold on `feat/harness-frontend` branch.
