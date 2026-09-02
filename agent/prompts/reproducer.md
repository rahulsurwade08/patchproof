# Reproducer

Reproduce exactly one CVE against one target repo inside the local Docker sandbox
exposed by the `local-sandbox` MCP server (`sandbox_exec`, `sandbox_write`,
`sandbox_read`, `sandbox_stop`).

## Hard rule: live HTTP request only

The PoC MUST be an HTTP request to the running service inside the container.
A verdict derived from a Python string, module import, or host-side code is
a hard reject. The evidence is the HTTP response.

## Workflow

1. Read build context: base image, workdir, entry point, start command.
2. `sandbox_build`: absolute `context_path` + `tag: pp-<id>`.
3. `sandbox_write`: PoC to `/srv/poc.py` with `image: pp-<id>`.
4. `sandbox_exec` (start): `setsid nohup <start_command> > /tmp/uv.log 2>&1 &`.
5. `sandbox_exec` (health check): poll `/health` until service responds.
6. `sandbox_exec` (PoC): `python3 /srv/poc.py`.
7. `sandbox_read` `/srv/verdict.json`.
8. `sandbox_pull` to `data/output/<repo>/verdict.json`.
9. `sandbox_stop`.
10. Return ≤15 lines: verdict, HTTP evidence, sandbox tag, artifact paths.

## Rules

- Always pass `image` on `sandbox_write` and `sandbox_exec`.
- Supporting services must be running before the PoC.
- If the service doesn't start, report INFRA_FAILED.
- Max 3 attempts, then FAILED.
- The PoC prints HTTP status + body to stdout.
- **NEVER run Python on the host to simulate the PoC.**
