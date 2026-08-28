# Harness Loop Plan — Combined Initial Setup + Chat UI for PatchProof

> **Sources:** [TrueForge Initial Setup](https://trueforge.dev/harness/initial-setup) (Models/MCP/Skills/Sandbox via Settings) + [Chat UI](https://trueforge.dev/chat-ui) (`@truefoundry/trueforge-ui` SDK). This is the **single loop plan** the agent follows — it merges the harness wiring (models/MCP/skills) and the Chat UI plan into one work loop. The built-in paid sandbox provider stays unconfigured (we use `local-sandbox` Docker MCP per ADR-008).

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
| **MCP cve-feed** | — | `agent/mcp/cve_feed_server.py` (Python stdio, `index.mjs` retired PR #26) — needs HTTP wrapper before registration; until then `data/inbox/*.json` (`demo:true` → `demo-bypass`, fail-closed ADR-010) | — |
| **Skills (7)** | Settings → Skills → Add skill (git) | Repo `https://github.com/rahulsurwade08/patchproof`, paths `agent/skills/{analyzer,orchestrator,reproducer,judge,patcher,verifier,test-runner}`, pin SHA | Not in `skill-catalog.yaml` — [Setup Skills](https://trueforge.dev/skills) |
| **Sandbox** | Settings → Sandbox providers | **Leave empty**, `sandbox.enabled:false` on agents, `file_downloads:true` for `verdict.json`. Built-in provider unused; isolation is `local-sandbox` MCP (ADR-016, disposable `--network none`, non-root, no `docker.sock`, never mount `.env/.git/data/output/`) | [Setup Sandbox](https://trueforge.dev/sandbox) — PatchProof uses sandbox-as-tool |

**Start:**
```bash
npx @truefoundry/trueforge --port 8790   # UI http://[::1]:8790 (ss shows [::1]:8790 LISTEN, docs /api/v1/docs)
python3 agent/mcp/local_sandbox_server.py &   # 127.0.0.1:8081/mcp
curl http://[::1]:8790/api/v1/mcp-servers | jq .data[].name  # → github, local-sandbox
curl http://[::1]:8790/api/v1/models | jq .data[].name       # → openrouter/openrouter-free
curl http://[::1]:8790/api/v1/agents | jq .data[].name       # → patchproof-orchestrator, patchproof-v2
```

**Env update trap:** `.env` is read only at `npx` start. After editing `OPENROUTER_*`/`GITHUB_TOKEN`, `kill -9 <pid>` (`ps -eo pid,args | grep trueforge`, avoid `pkill` hang) and restart both processes. Agents snapshot model/skill manifests at creation — delete and recreate agent if old text persists. Sessions are immutable — start a new one.

---

## 2. Chat UI — embed the harness UI for PatchProof

**Why:** PatchProof’s approval gate (deploy to staging pauses for human, never skippable) and evidence (`reachability.json`/`verdict.json`/`assessment.json` as `sandbox_artifacts`) need TrueForge’s chat, streaming, tool-approval, and file-download primitives. The current `dashboard/app.py` (8 hermetic tests, read-only scan list) cannot stream `Turn` events or approve `sandbox_build` with `files` override.

**What the SDK gives** ([Chat UI](https://trueforge.dev/chat-ui), live at `https://ui.trueforge.dev`): `AgentModes` (`fixed-agent`/`agent-library`/`composer`), `Chat` (streaming `Turn` `model.message`/`tool.call`/`sandbox_artifacts`, approvals, file attachments for `data/inbox/*.json`), `Themes` (`claude`/`chatgpt`/`gemini`/`truefoundry` + custom), `Layouts` (full-screen sidebar vs embedded drawer/widget).

**Plan (modifies UI layer only, no server fork):**

1. **Embed SDK** `dashboard/ui/TrueForgeChat.tsx` (`≤2 files, ~80 lines`): `npm i @truefoundry/trueforge-ui react react-dom` in `dashboard/`, render `<TrueForgeUI serverUrl="http://[::1]:8790" agentMode="fixed-agent" agentName="patchproof-v2" layout="drawer" theme="truefoundry" />` docked next to `dashboard/app.py` scan table. Verify `npm run build` → `dashboard/static/ui.js` streams `sandbox_build` while harness at `[::1]:8790` + MCP at `127.0.0.1:8081` are up.

2. **Theme + fixed-agent** `dashboard/ui/theme.ts`: `truefoundry` base with PatchProof red `exploitable:true` / green `NOT_REACHABLE` / amber `UNKNOWN`, hide composer (`agentMode="fixed-agent"`), only `patchproof-v2` selectable — enforces “one session per CVE” (ADR-004) and protects the approval gate.

3. **Generative UI artifacts** `agent/skills/orchestrator/SKILL.md` (≤5 lines): ensure `verdict.json`/`assessment.json` emitted as `sandbox_artifacts` so chat shows `tool.call: sandbox_read verdict.json` and `GET /api/v1/sessions/{id}/turns/{id}/download?path=verdict.json` works. Keep `ask_user_questions:true`, `require_approval_for_tools: ["@write","@destructive"]` on patcher/verifier, `generative_ui:true`.

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

