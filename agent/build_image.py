"""Build a sandbox image for any Python or Node.js repo.

Caches by repo git SHA. Skips rebuild if image:<sha> already exists.

ponytail: two runtimes only (Python, Node). A third runtime justifies
extracting a Runtime class; not before.
"""
import hashlib
import shutil
import subprocess
from pathlib import Path

IMAGE_PREFIX = "pp-sandbox"


def repo_sha(repo: Path) -> str:
    """Stable identifier for the repo state. Uses git if available, else file hash."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()[:12]
    except Exception:
        # ponytail: file-hash fallback is O(repo size); upgrade to git index hash
        # for large repos
        h = hashlib.sha256()
        for p in sorted(repo.rglob("*"))[:5000]:
            if p.is_file():
                h.update(p.read_bytes()[:1024])
        return h.hexdigest()[:12]


def image_exists(tag: str) -> bool:
    r = subprocess.run(
        ["docker", "images", "-q", tag], capture_output=True, text=True
    )
    return bool(r.stdout.strip())


def detect_runtime(repo: Path) -> tuple[str, str, int] | None:
    """Detect runtime, entry command, and port for a repo.

    Returns (runtime, cmd, port). runtime is "python" or "node".
    port is the TCP port the server will bind to.

    Detection order:
      1. package.json with "scripts": {"start": "..."}  -> node
      2. server.js / app.js / index.js / main.js at root       -> node
      3. manage.py / run.py / app.py / main.py at root         -> python
      4. None (falls back to a sleep-hold for non-server repos)

    ponytail: no TypeScript build, no monorepo/workspace walk.
    Node port is always 3000 (Express convention); the app must read
    PATCHPROOF_PORT env or bind to 0.0.0.0.
    """
    pkg_json = repo / "package.json"
    if pkg_json.exists():
        try:
            import json
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            scripts = (data.get("scripts") or {})
            start = scripts.get("start") or scripts.get("dev")
            if start:
                cmd = start
                # strip leading "node " if the script already has it
                if cmd.startswith("node "):
                    cmd = cmd[5:].strip()
                return "node", f"node {cmd}", 3000
        except (OSError, ValueError):
            pass
        for fname in ("server.js", "app.js", "index.js", "main.js"):
            if (repo / fname).exists():
                return "node", f"node {fname}", 3000

    for fname, cmd, port in (
        ("manage.py", "python3 manage.py runserver 0.0.0.0:8080", 8080),
        ("run.py",     "python3 run.py",                                8080),
        ("app.py",     "python3 app.py",                                5000),
        ("main.py",    "python3 main.py",                               8000),
    ):
        if (repo / fname).exists():
            return "python", cmd, port

    return None


def build_image_for_repo(repo: Path) -> str:
    """Return the docker image tag to use for this repo."""
    sha = repo_sha(repo)
    tag = f"{IMAGE_PREFIX}:{repo.name}-{sha}"

    if image_exists(tag):
        return tag

    runtime_info = detect_runtime(repo)
    if runtime_info:
        runtime, entrypoint, port = runtime_info
    else:
        runtime, entrypoint, port = "python", "python3 -c 'import time; time.sleep(3600)'", 8080

    # ponytail: each sandbox_exec starts a fresh container, so the kill loop
    # was dead code (and a footgun: pgrep -f "main.py" would match anything on
    # the line). Drop it. Upgrade path: add targeted pkill -f "$ENTRYPOINT"
    # only if/when sandbox_exec supports in-place restart.
    start_sh = f"""#!/bin/bash
set +e
PATCHPROOF_PORT={port} bash -c "{entrypoint.strip()}" >> /tmp/srv.log 2>&1 &
for i in $(seq 1 20); do
    (echo > /dev/tcp/127.0.0.1/{port}) 2>/dev/null && {{
        echo READY
        exit 0
    }}
    sleep 0.5
done
echo FAILED
exit 1
"""
    # ponytail: Dockerfile assembled as a list of lines for readability;
    # extracted template class if a 3rd runtime is added.
    dockerfile_lines = []
    if runtime == "python":
        dockerfile_lines = [
            "FROM python:3.11-slim",
            "WORKDIR /srv",
            "COPY . /srv/",
            "RUN chmod +x start.sh",
        ]
        if (repo / "requirements.txt").exists():
            dockerfile_lines.append("RUN pip install --no-cache-dir -r requirements.txt")
    else:  # node
        dockerfile_lines = [
            "FROM node:20-slim",
            "WORKDIR /srv",
            "COPY . /srv/",
            "RUN chmod +x start.sh",
        ]
        # ponytail: --omit=dev skips devDeps; --no-fund --no-audit keeps the layer small.
        # No npm ci (lockfile not guaranteed). Lockfile handling when a real caller needs it.
        if (repo / "package.json").exists():
            dockerfile_lines.append(
                "RUN npm install --omit=dev --no-fund --no-audit 2>/dev/null || true"
            )
    dockerfile_lines.extend([f"EXPOSE {port}", f"ENV PATCHPROOF_PORT={port}", 'CMD ["/srv/start.sh"]'])
    dockerfile = "\n".join(dockerfile_lines) + "\n"

    # Build with a temp context dir to avoid embedding secrets.
    # Copy repo contents first, then overwrite with our generated files
    # (so any Dockerfile in the repo doesn't replace ours).
    ctx = Path(f"/tmp/pp-build-{sha}")
    ctx.mkdir(exist_ok=True)
    (ctx / "start.sh").write_text(start_sh)
    skip_names = {".git", ".venv", "venv", "__pycache__", "node_modules"}
    for item in repo.iterdir():
        if item.name in skip_names or item.name.startswith("."):
            continue
        target = ctx / item.name
        if item.is_symlink():
            continue
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(".env*", "__pycache__", "node_modules"))
        else:
            target.write_bytes(item.read_bytes())
    # Must write AFTER copying so we overwrite any Dockerfile from the repo
    (ctx / "Dockerfile").write_text(dockerfile)

    subprocess.run(
        ["docker", "build", "-t", tag, str(ctx)],
        check=True, capture_output=True,
    )
    shutil.rmtree(ctx, ignore_errors=True)
    return tag
