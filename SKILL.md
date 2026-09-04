---
name: CheckExploit
description: CheckExploit — proves whether a scanner-flagged CVE is actually reachable in a repo, runs real exploits in an isolated sandbox to confirm, then patches and verifies fixes. Use when the user asks to "scan a repo for CVEs", "check exploitability", "verify a CVE is real", "patch my repo", or runs /check-exploit.
---

# CheckExploit

You have access to CheckExploit. It is an **agent** (you, the LLM) plus **mechanical drivers** (Python) plus **MCP servers** (sandbox + CVE feed).

## Install (one-time, in the user's shell)

```bash
git clone https://github.com/rahulsurwade08/check-exploit.git ~/check-exploit
~/check-exploit/scripts/install.sh
```

Then start the MCP servers (also one-time per session):

```bash
python3 ~/check-exploit/agent/mcp/local_sandbox_server.py &     # :8081
python3 ~/check-exploit/agent/mcp/cve_feed_server.py &           # :8091
```

## When to invoke

User says: "scan this repo", "is this CVE real?", "check for exploitable vulns", "/check-exploit".

## Workflow

1. `python3 ~/patchproof/agent/orchestrate.py <repo-path-or-git-url>` — clones/scans/builds images, writes `data/output/<repo>/triage.json`. Read it.
2. For each CVE in `triage['to_test']`:
   - Pick the image from `triage['images'][<ecosystem>]` (e.g. `'python'` or `'node'`).
   - Generate a PoC (Python script, stdlib only). Exits 0 = exploitable, 1 = not affected. Must write `/srv/verdict.json` with `{cve_id, exploitable, reason}`.
   - `sandbox_write({session: "ce-<repo>-<cve>", image, path: "/srv/poc.py", content: <poc>})` — `image` REQUIRED.
   - `sandbox_exec({session, image, command: "/srv/start.sh", timeout_secs: 30})`. The image's `start.sh` polls the service port via bash `/dev/tcp` and prints `READY` when up.
   - `sandbox_exec({session, image, command: "python3 /srv/poc.py", timeout_secs: 60})` — wait, then read verdict.
   - `sandbox_read({session, path: "/srv/verdict.json"})`.
   - If exploitable: write a patch, `sandbox_write` to the vulnerable file, `sandbox_stop`+restart via fresh `sandbox_exec`, re-run PoC. Post-patch verdict MUST be non-exploitable.
   - `sandbox_stop({session})` — one container per CVE.
3. Write `data/output/<repo>/report.md` + `report.json`.

## Hard rules

- **ALL execution through MCP.** Never `python3`, `pytest`, or `docker` on the host. The host stays clean.
- **`image` REQUIRED on every `sandbox_exec` / `sandbox_write`.** Omitting it silently uses `python:3.11-slim`.
- One container per CVE. State in JSON files, not memory.
- **Never display secrets.** Refer to API keys by name only.
- **`.env`, `.git`, credentials never enter the sandbox.** The build context skips `.env*`, `.git`, and dotfiles.
- **Sandbox + image cleanup is mandatory.** `sandbox_stop` after every CVE; `docker rmi` when done.

## Image routing

`triage['images']` is a map: `ecosystem -> image_tag`. Per-CVE routing:
- If `reachability[cve].dep.manifest == "package.json"` → `triage['images']['node']`.
- Else (`requirements.txt`, `pyproject.toml`, `Pipfile`) → `triage['images']['python']`.

## Hard limits (ponytail)

- **Two runtimes only** (Python, Node). Three is the upgrade trigger for a `Runtime` class.
- **No TypeScript build, no monorepo, no yarn/pnpm.** Lockfile handling when a real caller needs it.
- **Default ports**: Flask→5000, FastAPI→8000, manage.py→8080, Express→3000. The app must read `CE_PORT` or bind to `0.0.0.0`.

## Verdict contract (PoC ↔ orchestrator)

PoC writes `/srv/verdict.json`:
```json
{"cve_id": "CVE-...", "exploitable": true|false, "reason": "..."}
```
Exit 0 = exploitable, exit 1 = not affected. Container teardown on either.

## When you can't proceed

- `local-sandbox` MCP unreachable → tell the user to start `local_sandbox_server.py`.
- `cve-feed` MCP unreachable → tell the user to start `cve_feed_server.py`. (Network access required for OSV/CVE.org; sandbox itself is `--network none`.)
- `triage.json` empty → check that the repo has `package.json` or `requirements.txt` (or another manifest). Tell the user.
