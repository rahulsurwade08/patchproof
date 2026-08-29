# Harness Loop Plan — Harness Setup + Custom UI (ADR-018)

> **Sources:** [TrueForge Initial Setup](https://trueforge.dev/harness/initial-setup) + [Chat UI](https://trueforge.dev/chat-ui) + [UI SDK](https://trueforge.dev/ui-sdk) via `@truefoundry/trueforge-ui` (ADR-018). This plan follows ADR-018: custom UI in `harness/frontend/` with `SingleAgent patchproof-v2` (`server={{type:"trueforge", baseUrl}}`, `agentConfig={{mode:"SingleAgent", name:"patchproof-v2"}}`; see `docs/custom-harness-build-plan.md` §2 and `docs/decisions.md` ADR-018). The built-in paid sandbox provider stays unconfigured (we use `local-sandbox` Docker MCP per ADR-008). The authoritative cut-order is in `plan.md` §9.

---

## 0. Loop contract

- **One concern per PR** (`≤5 files`, `~400 lines`, tests+docs included). After opening a PR, load `qodo-get-rules` before coding, `qodo-pr-resolver` when resolving, reply on thread + `/review` until `Bugs 0/Rules 0`, then merge via merge commit (maintainer grant 2026-08-27). Deploy-to-staging approval stays human-only.
- **All execution via harness MCP** `sandbox_build` (with network) + `sandbox_exec/write/read/stop` (`--network none`, `label=patchproof-sbx=1`, `image` param always). Never host `docker`/`pytest` except `scripts/run_poc_local.sh`. Teardown `sandbox_stop` + image prune after every run (ADR-012).
- **Harness is the deliverable** — host scripts (`reach.py` on host, `pytest` on host) are engine fixtures, not product. Every turn below runs as a TrueForge session at `http://[::1]:8790` (or `http://localhost:8790`) with `python3 agent/mcp/local_sandbox_server.py &` at `127.0.0.1:8081/mcp`.

---

## 1. Initial Setup — wire the harness once (Settings)

Do once in TrueForge **Settings** (no config file, `v0.1.4`):

| Resource | Settings page | PatchProof value | Catalog |
|----------|---------------|------------------|---------|
| **Models** | Settings → Models | `custom` → `openrouter` / `https://openrouter.ai/api/v1` / `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` (`openrouter/free` + pinned e.g. `z-ai/glm-4.5-air:free`, `context_length 200000`) | Add via **Add custom provider** (not in `model-catalog.yaml`) — [Setup Models](https://trueforge.dev/models) |
| **MCP github** | Settings → Connectors | `https://api.githubcopilot.com/mcp/` / Header `Bearer <GITHUB_TOKEN>` (repo PAT from `gh` CLI, written into `.env` without display, ADR-007) | Preset |
| **MCP local-sandbox** | Settings → Connectors → Add MCP Server | `remote` `local-sandbox` `http://127.0.0.1:8081/mcp` / No auth — start `python3 agent/mcp/local_sandbox_server.py &` first | Not in `mcp-catalog.yaml` |
| **MCP cve-feed** | Settings → Connectors → Add MCP Server | `agent/mcp/cve_feed_server.py` (Python stdlib, Streamable HTTP at `http://127.0.0.1:8091/mcp`) — transport done in PR #71, remote-URL registration wired in cut-order step 3; `data/inbox/*.json` (`demo:true` → `demo-bypass`, fail-closed ADR-010) remains the fallback | — |
| **Skills (7)** | Settings → Skills → Add skill (git) | Repo `https://github.com/rahulsurwade08/patchproof`, paths `agent/skills/{analyzer,orchestrator,reproducer,judge,patcher,verifier,test-runner}`, pin SHA | Not in `skill-catalog.yaml` — [Setup Skills](https://trueforge.dev/skills) |
| **Sandbox** | Settings → Sandbox providers | Leave providers empty; agents set `sandbox.enabled: true` (TrueForge built-in materializes skills + `sandbox_artifacts`); exploit/PoC execution stays on `local-sandbox` MCP (ADR-008/016, disposable `--network none`, non-root, no `docker.sock`, never mount `.env/.git/data/output/`) | [Setup Sandbox](https://trueforge.dev/sandbox) — PatchProof uses sandbox-as-tool |

**Start:**
```bash
npx @truefoundry/trueforge --port 8790   # UI http://[::1]:8790 (ss shows [::1]:8790 LISTEN, docs /api/v1/docs)
python3 agent/mcp/local_sandbox_server.py &   # 127.0.0.1:8081/mcp
python3 agent/mcp/cve_feed_server.py &        # 127.0.0.1:8091/mcp (transport done PR #71; register in Settings → Connectors in step 3)
curl http://[::1]:8790/api/v1/mcp-servers | jq .data[].name  # → github, local-sandbox (cve-feed after step 3 registration)
curl http://[::1]:8790/api/v1/models | jq .data[].name       # → openrouter/openrouter-free
curl http://[::1]:8790/api/v1/agents | jq .data[].name       # → patchproof-orchestrator, patchproof-v2
```

**Env update trap:** `.env` is read only at `npx` start. After editing `OPENROUTER_*`/`GITHUB_TOKEN`, `kill -9 <pid>` (`ps -eo pid,args | grep trueforge`, avoid `pkill` hang) and restart both processes. Agents snapshot model/skill manifests at creation — delete and recreate agent if old text persists. Sessions are immutable — start a new one.

---

## 2. Chat UI — custom build on `@truefoundry/trueforge-ui` (ADR-018)

**Why:** PatchProof’s approval gate (deploy to staging pauses for human, never skippable) and evidence (`reachability.json`/`verdict.json`/`assessment.json` as `sandbox_artifacts`) need TrueForge’s chat, streaming, tool-approval, and file-download primitives. The current `dashboard/app.py` (8 hermetic tests, read-only scan list) cannot stream `Turn` events or approve `sandbox_build` with `files` override.

**What the SDK gives** ([Chat UI](https://trueforge.dev/chat-ui), [UI SDK](https://trueforge.dev/ui-sdk), live at `https://ui.trueforge.dev`): `TrueForgeUI` with `server={{type:"trueforge", baseUrl}}` and `agentConfig={{mode:"SingleAgent", name:"patchproof-v2"}}`, `Chat` (streaming `Turn` `model.message`/`tool.call`/`sandbox_artifacts`, approvals, file attachments as session-turn input — advisory JSON attached in the UI becomes turn input for the orchestrator; `data/inbox/*.json` remains the host-side advisory drop dir for local/demo ingestion), `Themes` (`truefoundry` + custom), `Layouts` (full-screen sidebar vs embedded drawer/widget).

**Plan (modifies UI layer only, no server fork — see `docs/custom-harness-build-plan.md` §2):**

1. **Embed SDK** `harness/frontend/src/App.tsx` (`≤2 files, ~80 lines`): `npm i @truefoundry/trueforge-ui @truefoundry/trueforge-sdk react react-dom` in `harness/frontend/`, render `<TrueForgeUI server={{type:"trueforge", baseUrl:"http://[::1]:8790"}} agentConfig={{mode:"SingleAgent", name:"patchproof-v2"}} theme="truefoundry" />` as the single demo surface. Verify `npm run build` → `harness/frontend/dist` streams `sandbox_build` while harness at `[::1]:8790` + MCP at `127.0.0.1:8081` are up.

2. **Theme + SingleAgent** `harness/frontend/src/theme.ts`: `truefoundry` base with PatchProof red `exploitable:true` / green `NOT_REACHABLE` / amber `UNKNOWN`, `SingleAgent patchproof-v2` only — enforces “one session per CVE” (ADR-004) and protects the approval gate.

3. **Generative UI artifacts** `agent/skills/orchestrator/SKILL.md` (≤5 lines): ensure `verdict.json`/`assessment.json` emitted as `sandbox_artifacts` so chat shows `tool.call: sandbox_read verdict.json` and `GET /api/v1/sessions/{id}/turns/{id}/download?path=verdict.json` works. Keep `ask_user_questions:true`, `generative_ui:true`. Approval policy is set per MCP server in the agent manifest: `local-sandbox=["@all"]` (every sandbox call requires approval before the irreversible exploit step), `cve-feed` and `github` use default `["@write","@destructive"]`.

4. **Register skills** (no code): Settings → Skills add 7 git skills at pinned SHA; verify `curl http://[::1]:8790/api/v1/skills | jq .data[].name` shows all.

Cut-order satisfies demo video (“harness visibly working: MCP tool call, code execution in sandbox, pause before irreversible step”) at step 1 alone; 2-4 polish.

---

## 3. Working loop — how the agent runs on the harness (not host)

Each item is a TrueForge session, not a host bash. The agent picks the next step, implements, verifies **via harness MCP**, opens a small PR, loops Qodo, merges, then continues. Stop only for human approval (staging deploy), missing credentials, or scope ambiguity.

**Per-CVE session (orchestrator skill):**
1. **Legitimacy** `cve-feed:cve_cross_check` (or `demo-bypass` until wrapper) → `UNKNOWN` short-circuits.
2. **Analyzer** `analyzer` skill → `reach.py` via `sandbox_exec` (det Python) → `reachability.json` (`dep-pin` → `call-sites` → `input-source trace` → `REACHABLE/NOT_REACHABLE/UNKNOWN`, `needs_sandbox`).
3. **Reproducer** fan-out (one subagent per `REACHABLE/UNKNOWN` site) → `gen_context.py` → `sandbox_build` (`Dockerfile.patchproof`, `python:<ver>-slim` + build-tools) → fallback `fallback_dockerfile` if install fails (ADR-017) → `sandbox_write` PoC → `sandbox_exec` (service + PoC, exit 0/1, `verdict.json`) → merge verdicts.
4. **Judge** → `assessment.json` (`agrees_with_verdict/confidence/range_check/rationale`), retry reproducer once on disagree/low-confidence (cap 3).
5. **Patcher** (only if `exploitable:true`) → `sandbox_build` with `files` override (bump `requirements.lock`) → `sandbox_exec` tests + PoC → PR with evidence. Smallest diff, lockfile bump only via PR.
6. **■ Approval gate** → pause, human approves merge & staging deploy (irreversible, never cut).
7. **Verifier** → re-run original PoC vs staging → `exploitable:false` confirms fix → report.
8. **Teardown** → `sandbox_stop` + image prune (always, even on failure).

**Host smoke that proves harness works (while harness at `[::1]:8790` is up):**
```bash
curl http://[::1]:8790/api/v1/mcp-servers | jq .data[].name
python3 agent/analyzer/reach.py scenarios/s01-pyyaml-rce scenarios/s01-pyyaml-rce/cve-meta.json --out /tmp/harness-reach
curl http://127.0.0.1:8081/mcp -X POST -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_build","arguments":{"tag":"patchproof-s01","context_path":"/home/rahuls/Projects/patchproof/scenarios/s01-pyyaml-rce/app"}}}'
curl http://127.0.0.1:8081/mcp -X POST -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sandbox_exec","arguments":{"session":"s01","image":"patchproof-s01","command":"cd /srv && uvicorn main:app --host 0.0.0.0 --port 8000 & sleep 3; python /srv/poc.py"}}}'
# → {"exploitable":true} then patched image → {"exploitable":false}, containers 0
```

---

## 4. Verification after every change (harness-driven)

- `python3 -m pytest harness/tests/unit -q` → 155 passed (harness skills work even when harness down — deterministic Python); `harness/tests/integration` drives scenarios/demo-app via `http://[::1]:8790`.
- `bash scripts/run_gate_before_push.sh s01-pyyaml-rce` → `PASS: gate passed` (requires `local_sandbox_server.py` at `127.0.0.1:8081/mcp`).
- `docker ps -aq --filter label=patchproof-sbx=1` = 0, `rg -i "sk-or-v1|ghp_|github_pat"` only redaction code, `git log --all -- .env` empty.
- Chat UI: session **Turns** shows `sandbox_build`/`sandbox_exec` with `image` param, **Generative UI** shows `verdict.json`, approval checkpoint pauses before `verifier`.

---

## 5. What not to build now

- Custom `MODEL_CATALOG_PATH`/`MCP_CATALOG_PATH`/`SKILL_CATALOG_PATH` YAML or `SANDBOX_CATALOG_PATH` preset — use shipped catalogs + **Add custom** for `openrouter`/`local-sandbox`.
- New Python sandbox provider — shipped provider unused; Docker MCP satisfies ADR-008.
- `customTheme` dark mode, `library+composer`, headless `POST /api/v1/sessions/{id}/turns` streams outside UI — Day 2.

**Next step for the agent:** start with §2 step 1 (`feat/chat-ui-embed` branch, `≤2 files`), verify via `curl http://[::1]:8790/api/v1/agents` + MCP smoke while harness is up, then layer theme. Keep the loop per AGENTS.md: work autonomously, small PRs, Qodo until clean, merge via merge commit, delete branch, next item.


NOTE (user decisions 2026-08-29): (1) build a custom UI from TrueForge (`@truefoundry/trueforge-ui`, `SingleAgent patchproof-v2`) and attach the 7 skills, the MCPs (github / local-sandbox / cve-feed HTTP wrapper), and the backend — plan in `docs/custom-harness-build-plan.md`, ADR-018. (2) The intermediate centralized test suite (155 tests) is superseded: **test suite v2 is recreated** against the attached components as each PR lands (see `docs/custom-harness-build-plan.md` §4). PRs stay small (≤5 files / ~400 lines) so Qodo findings remediate quickly.
