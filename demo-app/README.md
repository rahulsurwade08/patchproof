# DemoApp — PatchProof Showcase (Vulnerable Python App)

> **Purpose:** Realistic, intentionally vulnerable Python app for the PatchProof demo video. Shows scanner alert fatigue vs PatchProof's reachability triage, sandbox-confirmed exploit, and verified patch — all via the TrueForge harness.

**Stack:** FastAPI + PyYAML 5.3.1 (CVE-2020-14343) + Jinja2 3.1.2 (CVE-2024-56326) + SQLite. Pinned to vulnerable versions so a scanner (e.g. Trivy/Grype) flags it, but PatchProof must prove *reachability* with attacker-controlled input.

**Why “big enough”:** 6 modules, ~450 lines, 8 endpoints, 3 deps, both reachable and not-reachable call sites — the minimal s01 (24 lines, 1 endpoint) is too small to demo `NOT_REACHABLE` (alert fatigue) vs `REACHABLE` (real risk) on one repo.

## Quick start (host, for dev only)

```bash
cd demo-app
pip install -r requirements.lock
uvicorn app.main:app --host 127.0.0.1 --port 8000
# or via TrueForge sandbox (product path):
python3 ../agent/mcp/local_sandbox_server.py &  # 127.0.0.1:8081/mcp
# harness then: sandbox_build demo-app (tag patchproof-demo-app) → sandbox_write poc → sandbox_exec
```

## Endpoints

| Route | Input | Vuln | Reachable? | Scanner flag |
|-------|-------|------|------------|--------------|
| `POST /api/config/import` | `Content-Type: application/yaml` body | `yaml.load(..., Loader=FullLoader)` on **untrusted** bytes → RCE (CVE-2020-14343) | **Yes** — direct HTTP body | **Flagged** |
| `POST /api/render` | JSON `{template, context}` | `SandboxedEnvironment.from_string` + custom `fmt` filter calling `value.format()` → sandbox escape (CVE-2024-56326) | **Yes** — JSON body | **Flagged** |
| `GET /api/documents/{id}/export` | `id` → DB → template | Same `fmt` filter but `template` is **checked-in** Jinja file on disk, not user input | **No** — static file | **Flagged but NOT_REACHABLE** (alert fatigue) |
| `GET /api/config/defaults` | none | `yaml.safe_load` on `app/defaults.yaml` (static file) | **No** | Not flagged (safe API) |
| `GET /health`, `GET /api/documents`, `POST /api/documents`, `GET /api/templates` | — | — | — | — |

## Project layout

```
demo-app/
  app/
    main.py       — FastAPI, 8 routes, lifespan DB init
    config.py     — YAML loading: vulnerable FullLoader (import) + safe safe_load (defaults) + static startup loader
    templates.py  — Jinja2: vulnerable fmt filter + safe rendering of checked-in templates
    models.py     — Pydantic models (Document, Template, ConfigImport)
    utils.py      — helpers (DB, marker writing for PoC proof)
    defaults.yaml — static YAML loaded at startup (NOT_REACHABLE example)
    templates/
      invoice.html.j2  — checked-in Jinja template (NOT_REACHABLE)
  tests/
    test_main.py  — contract tests (health, CRUD, defaults)
    test_config.py — YAML safe vs vulnerable unit tests
  requirements.lock — pinned vulnerable versions
  Dockerfile      — python:3.11-slim, WORKDIR /srv, no .env mount
```

## How PatchProof uses this app (demo video flow)

1. **Scanner:** flags `pyyaml==5.3.1 ≤5.3.1` and `jinja2==3.1.2 <3.1.5` on this repo — 2 alerts.
2. **Analyzer (`agent/analyzer/reach.py`):** dep-pin confirms both pinned versions are in affected ranges (OSV/CVE.org) → call-site scan finds 3 `yaml.load`/`yaml.safe_load` + 2 Jinja `from_string` sites → input-source trace: `POST /api/config/import` body is attacker-controlled (REACHABLE), `defaults.yaml` at startup is checked-in (NOT_REACHABLE), `POST /api/render` body is attacker-controlled (REACHABLE), `GET /api/documents/{id}/export` template is checked-in (NOT_REACHABLE) → `reachability.json` with `REACHABLE` (2) + `NOT_REACHABLE` (2) + `needs_sandbox:true`.
3. **Reproducer (harness MCP, never host):** `sandbox_build` `patchproof-demo-app` → `sandbox_write` `poc-yaml.py` + `poc-jinja.py` → `sandbox_exec` → `verdict.json` `exploitable:true` for both REACHABLE sites (marker at `/tmp/patchproof_pwned`), not for the two NOT_REACHABLE sites (proves scanner fatigue).
4. **Judge:** `assessment.json` agrees, confidence high, range_check passes.
5. **Patcher:** bumps `pyyaml==6.0.1` + `jinja2==3.1.5` via `sandbox_build` `files` override → `sandbox_exec pytest` (tests still pass) → `sandbox_exec` PoCs now `exploitable:false` (500), opens PR with evidence.
6. **Approval gate:** human approves (irreversible, never skipped).
7. **Verifier:** re-runs PoCs vs staging → still `false` → case closed.
8. **Teardown:** `sandbox_stop` + image prune (ADR-012).

See `docs/harness-loop-plan.md` for the full harness loop and `docs/demo.md` for the TrueForge session steps.

## Pinned versions (vulnerable)

```
pyyaml==5.3.1      # CVE-2020-14343: FullLoader bypass < =5.3.1, fixed in 5.4
jinja2==3.1.2      # CVE-2024-56326: sandbox escape via fmt filter <3.1.5, fixed in 3.1.5
fastapi==0.110.0
uvicorn==0.29.0
pydantic==2.6.0
```

Scanner truth: bump to `pyyaml==6.0.1` + `jinja2==3.1.5` → no longer flagged.
