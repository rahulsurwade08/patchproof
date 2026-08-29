# Custom Harness Build Plan — Frontend + Backend

> Build PatchProof's own harness (frontend + backend) on top of TrueForge, so every skill and MCP works through the harness and tests are centralized. This replaces host-side `python -m pytest` / `curl 127.0.0.1:8081` with `POST /api/v1/sessions/{id}/turns` on `http://[::1]:8790`.

---

## 1. Why custom

Current harness is stock `npx @truefoundry/trueforge --port 8790` with Settings-wired `openrouter` + `github` + `local-sandbox` + 7 PatchProof skills (`analyzer`/`orchestrator`/`reproducer`/`judge`/`patcher`/`verifier`/`test-runner`). It works, but:

- **Frontend** is split: TrueForge UI at `http://[::1]:8790` vs PatchProof `dashboard/app.py` (8 tests, read-only). Demo needs one surface that shows **scanning, reachability, exploit, patch, approval gate** in a single chat transcript with `sandbox_artifacts`.
- **Backend** is borrowed: TrueForge's built-in bwrap sandbox is disabled (`Can't mount on symlink /bin`), we rely on our Docker MCP `agent/mcp/local_sandbox_server.py` at `127.0.0.1:8081/mcp`. No custom server logic for PatchProof-specific concerns (OSV caching, `data/inbox` advisory drop, `data/output` artifact store).
- **Tests are scattered**: `agent/analyzer/tests` (3, 100 tests), `agent/mcp/tests` (2, 28 tests), `dashboard/test_dashboard.py` (8), `scenarios/*/app/test_main.py` (7), `demo-app/tests` (2) — 15 files, no single `pytest` entry point, no harness-driven CI.

Custom build keeps TrueForge core (agent loop, MCP, skills, sandbox-as-tool) but owns the UI and the server glue so PatchProof skills/MCPs work properly under the harness.

---

## 2. Frontend — custom build on `@truefoundry/trueforge-ui`

**Base:** `https://trueforge.dev/chat-ui` + `https://ui.trueforge.dev` live configurator. SDK: `npm install @truefoundry/trueforge-ui @truefoundry/trueforge-sdk` (peer deps `react`/`react-dom` 18–19). `TrueForgeUI` renders the full chat — streaming, history, tool calls, approvals — against the stock server.

**What to build (in `harness/`):**

```
harness/
  frontend/
    package.json            # @truefoundry/trueforge-ui, react, vite
    src/
      App.tsx               # <TrueForgeUI server={{type:"trueforge", baseUrl:"http://[::1]:8790"}} agentConfig={{mode:"SingleAgent", name:"patchproof-v2"}} layout="sidebar" />
      theme.ts              # truefoundry preset + PatchProof red/green/amber (exploitable/UNKNOWN/not_affected)
      layout.tsx            # drawer (dashboard table + chat) vs full-screen with sidebar
      PatchProofArtifacts.tsx # renders reachability.json / verdict.json / assessment.json from sandbox_artifacts
    vite.config.ts
    Dockerfile              # node:20 → nginx, or serve via FastAPI StaticFiles
```

**Customizations:**
- **Agent mode** `agentConfig={{mode:"SingleAgent", name:"patchproof-v2"}}` — hides agent picker + composer (per `ui-sdk/guides/agent-modes.md`), enforces one-session-per-CVE ADR-004, protects the approval gate. Switch the name to `patchproof-orchestrator` for the `s01` demo.
- **Theme** `truefoundry` + PatchProof brand (red `exploitable:true`, green `NOT_REACHABLE`, amber `UNKNOWN`, dark mode optional) via `Theme` provider `customTheme` slot (`ui-sdk/reference/theme.md`).
- **Artifacts** — Generative UI for `reachability.json` (file:line+snippet+input trace), `verdict.json` (marker proof), `assessment.json` (judge). Use `Containers` + `Atoms` (`ui-sdk/reference/containers.md`, `atoms.md`) to render code fences, not just JSON. Artifact files download via `GET /api/v1/sessions/{id}/turns/{turn_id}/files` (paths come from the assistant's `sandbox_artifacts` block; requires `config.sandbox.file_downloads:true`, which is the default).
- **File flow** — `data/inbox/*.json` advisory drop as UI file attachment → session turn input (replaces host `scripts/fake_cve_injector.py` for demo video).
- **Approval gate** — `ask_user_questions:{enabled:true}` (default) + `require_approval_for_tools:["@write","@destructive"]` (API-only, set **per MCP server**; the default already gates write/destructive-annotated tools) → UI shows **Approve/Deny** checkpoint before PR/staging deploy (harness-native tool-approval pause).
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
      cve_feed_server.py        # done: Streamable HTTP at 127.0.0.1:8091/mcp (PR #71)
    skills/
      # 7 existing skills stay in agent/skills/ but are also registered in harness Settings → Skills as git skills
      # No code change, just Settings → Skills Add git repo https://github.com/rahulsurwade08/patchproof path agent/skills/<name> pin SHA
    server/
      patchproof-bridge.ts      # tiny TrueForge extension: OSV cache, data/output artifact store, data/inbox watcher (optional)
```

**MCPs must work properly:**
- `github` — header `Bearer <GITHUB_TOKEN>` (repo PAT, `auth_status:authenticated` via `GET /api/v1/mcp-servers`), used by orchestrator/patcher for repo matching + PRs.
- `local-sandbox` — `remote` `http://127.0.0.1:8081/mcp`, no auth, `sandbox_build` (with network, `files` override for patched lockfile, `no_cache`) + `sandbox_exec/write/read/stop` (`--network none`, `label=patchproof-sbx=1`, `image` param required — lessons learned). Fix remaining `ensure_container` image-reuse bug (old container still runs) and add `sandbox_stop` EXIT trap.
- `cve-feed` — transport done in PR #71: `agent/mcp/cve_feed_server.py` is Streamable HTTP at `127.0.0.1:8091/mcp` (port via `CVE_FEED_PORT`). Remote-URL registration with TrueForge is the next PR (cut-order step 3) and still pending; `data/inbox/*.json` with `demo:true` → `demo-bypass` remains the fail-closed ADR-010 path until registration. Tools: `cve_get_cve`/`osv_query_package`/`osv_get_vuln`/`cve_cross_check`.

**Skills must work properly:**
- All 7 `SKILL.md` already pass `rg -i daytona` 0 and Qodo 0/0 up to PR #53. Register them in harness Settings → Skills (git repo URL + path `agent/skills/<name>`, pin a commit SHA for production stability) so `GET /api/v1/skills` lists them and `GET /api/v1/catalogs/skills` shows PatchProof skills. Harness materializes them under `/opt/tfy/skills/{name}` at runtime when the model picks the skill (progressive disclosure).
- **Correction from official docs (`trueforge.dev/skills.md`, `create-agent/overview.md`): attaching skills requires `config.sandbox.enabled: true`** — the built-in sandbox materializes skill repos and backs `sandbox_artifacts` file downloads. Set `config: {sandbox:{enabled:true, file_downloads:true}, dynamic_sub_agents:{enabled:true}, ask_user_questions:{enabled:true}}` on `patchproof-v2`. Exploit/PoC execution still goes **only** through the `local-sandbox` MCP server (`--network none`) — never the built-in sandbox, never the host.
- **Runtime risk to verify:** earlier runs recorded built-in bwrap mount failures on this host ("Can't mount on symlink /bin"). If skill materialization fails with `sandbox.enabled:true`, record the finding in `feedback-issues.md` and fall back to instructions-only skills (key content inline in agent `instructions`); triage still fails closed to honest `UNKNOWN` — never scenario-match.

**Server glue (minimal):**
- Optional `harness/backend/server/patchproof-bridge.ts` that watches `data/inbox/` and mirrors `data/output/<repo>/` into the turn sandbox so `sandbox_artifacts` blocks expose `reachability.json`/`verdict.json`/`assessment.json` for download — not required for MVP, but helps the UI render artifacts without extra tool calls.

---

## 4. Test suite v2 — recreated for the custom harness (user decision 2026-08-29)

The intermediate centralized suite (`harness/tests/`, 155 tests) predates the
custom-UI plan and is being **recreated, not migrated**: tests are written
against the attached components (frontend, skills registration, MCP wiring,
agent manifest) as each lands. Old tests are triaged, not bulk-moved.

**Layout:**

```
harness/
  tests/
    conftest.py                 # fixtures: harness API at [::1]:8790, local-sandbox at 127.0.0.1:8081, temp data/output
    unit/
      test_cve_feed_http.py     # done: cve_get_cve / osv_* / cve_cross_check (harness/tests/unit/test_cve_feed.py)
      test_local_sandbox.py     # recreated: exec/write/read/stop + ensure_container image-reuse regression
      test_bridge.py            # new (if bridge lands): data/output → sandbox_artifacts mirroring
    integration/
      test_skills_registered.py # GET /api/v1/skills lists all 7 PatchProof skills; catalog shows them
      test_mcp_registered.py    # GET /api/v1/mcp-servers shows github (authenticated) + local-sandbox + cve-feed
      test_frontend_build.py    # npm run build succeeds; dist loads the TrueForgeUI chat against [::1]:8790
      test_agent_manifest.py    # patchproof-v2 manifest: model, mcp_servers, skills[7], sandbox.enabled:true, approvals ([local-sandbox:sandbox_build|exec|write|read, cve-feed:@write|@destructive+readOnlyHint, github:default])
    e2e/
      test_reachability_run.py  # session turn on [::1]:8790 → tool.call sandbox_build/exec → verdict.json + assessment.json via turn files API
      test_approval_gate.py     # patcher turn pauses with awaiting_approval (Allow/Deny) before any PR/staging action
```

**Triage of the old suite:**
- **Keep** (recreate under v2): analyzer + MCP server unit tests — they cover code that stays attached (`agent/analyzer/*.py`, `agent/mcp/*.py`).
- **Retire**: host-coupled suites superseded by the harness path (`dashboard/test_dashboard.py` read-only surface replaced by the custom UI; gate scripts that drove scenario pytest on the host).
- **Never run on host**: exploit/PoC/patch execution only via `local-sandbox` MCP; scenario services only inside sandbox containers.

**Verification targets:**
- `pytest harness/tests/unit -q` → green (wrapper + sandbox regressions)
- `pytest harness/tests/integration -q` → 7 skills listed, 3 MCP servers registered, frontend dist builds, `patchproof-v2` manifest matches spec
- `pytest harness/tests/e2e -q` → one full session turn yields `verdict.json` + `assessment.json` through the turn files API; approval gate pauses before PR

---

## 5. Loop to build it (small PRs, Qodo, harness-only)

| PR | Touch | Verify via harness |
|----|-------|--------------------|
| 1 `harness/frontend` scaffold | `harness/frontend/package.json` + `src/App.tsx` (≤2 files) | `npm run build` → `harness/frontend/dist` loads `http://[::1]:8790` chat (`SingleAgent patchproof-v2`) |
| 2 `cve-feed` HTTP wrapper | `agent/mcp/cve_feed_server.py` streamable wrapper (≤2 files) — done in PR #71 | `curl http://127.0.0.1:8091/mcp` tools/list; registration done in step 3 |
| 3 attach skills + MCPs | `scripts/harness_setup.py` (register skills/MCPs/agent) + updated docs — done in PR #72 | `GET /api/v1/skills` lists 7; `GET /api/v1/mcp-servers` lists 2 (local-sandbox + cve-feed); github connector is the catalog entry added in the UI per step 3 of docs/trueforge-setup.md; agent manifest matches spec |
| 4 `fix/sandbox-reuse` | `local_sandbox_server.py:ensure_container` image check + `sandbox_stop` trap | back-to-back `sandbox_exec` reuse container; no stale `patchproof-sbx` containers after stop |
| 5 `feat/approval-gate` | manifest `require_approval_for_tools` per MCP server (API) — done in PR #73: `local-sandbox=[sandbox_build,exec,write,read]` (exploit/build/write/read gated; sandbox_stop exempt for mandatory teardown ADR-012); `cve-feed=["@write","@destructive"]` with `readOnlyHint: true` on all 4 tools; `github` uses default (PRs via github MCP, patcher stops before merge/staging) | harness turn pauses before any sandbox_build/exec/write/read call; PRs opened via github MCP; sandbox_stop teardown runs automatically |
| 6+ test suite v2 | `harness/tests/` recreated per §4, ≤5 files per PR | `pytest harness/tests/unit -q` then integration then e2e, green |

Each PR: `qodo-get-rules` before coding, `qodo-pr-resolver` on findings, reply + `/review` until `Bugs 0/Rules 0`, merge commit, delete branch. No host `docker`/`pytest` except `scripts/run_poc_local.sh` (CI fallback).

Next: start with `harness/frontend` scaffold on `feat/harness-frontend` branch.
