"""Build a sandbox image for any Python repo.

Caches by repo git SHA. Skips rebuild if image:<sha> already exists.

For non-Python repos, this is a no-op (returns the requested image name
or raises). ponytail: only Python is supported; add a runtime adapter per
language when needed.
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


def detect_entrypoint(repo: Path) -> tuple[str, int] | None:
    """Best-effort: find a runnable command in the repo. Returns (cmd, port).

    ponytail: heuristic only — covers the common patterns. Add a real
    manifest parser (pyproject script entry-points, Procfile, etc.) when
    repos we care about need it.
    """
    candidates = [
        ("run.py", "python3 run.py", 8080),
        ("app.py", "python3 app.py", 5000),
        ("main.py", "python3 main.py", 8000),
        ("manage.py", "python3 manage.py runserver 0.0.0.0:8080", 8080),
    ]
    for fname, cmd, port in candidates:
        if (repo / fname).exists():
            return cmd, port
    return None


def build_image_for_repo(repo: Path) -> str:
    """Return the docker image tag to use for this repo."""
    sha = repo_sha(repo)
    tag = f"{IMAGE_PREFIX}:{repo.name}-{sha}"

    if image_exists(tag):
        return tag

    # Build context = repo itself (read-only mount at build time)
    entry = detect_entrypoint(repo) or ("python3 -c 'import time; time.sleep(3600)'", 8080)
    entrypoint, port = entry
    req_files = [f for f in ("requirements.txt", "pyproject.toml", "Pipfile") if (repo / f).exists()]

    # ponytail: Dockerfile + start.sh are templated inline; upgrade to a
    # proper template engine when we support more than Python. The container
    # exposes PATCHPROOF_PORT so the agent can health-check the actual port
    # the service bound to (Flask→5000, FastAPI→8000, uvicorn→8080).
    start_sh = f"""#!/bin/bash
set +e
ENTRYPOINT="{entrypoint.strip()}"
ENTRYPOINT="${{ENTRYPOINT#python3 }}"
ENTRYPOINT="${{ENTRYPOINT#python }}"
for p in $ENTRYPOINT app.py run.py main.py; do
    pids=$(pgrep -f "$p" 2>/dev/null)
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null
done
sleep 1
PATCHPROOF_PORT={port} python3 $ENTRYPOINT >> /tmp/srv.log 2>&1 &
for i in $(seq 1 20); do
    python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', {port})); s.close(); exit(0)" 2>/dev/null && {{
        echo READY
        exit 0
    }}
    sleep 0.5
done
echo FAILED
exit 1
"""
    dockerfile = f"""
FROM python:3.11-slim
WORKDIR /srv
COPY . /srv/
RUN chmod +x start.sh
""" + (
        "RUN pip install --no-cache-dir -r requirements.txt\n" if "requirements.txt" in req_files else ""
    ) + f"""
EXPOSE {port}
ENV PATCHPROOF_PORT={port}
CMD ["/srv/start.sh"]
"""

    # Build with a temp context dir to avoid embedding secrets.
    # Skip symlinks to prevent following external content into the image.
    ctx = Path(f"/tmp/pp-build-{sha}")
    ctx.mkdir(exist_ok=True)
    (ctx / "Dockerfile").write_text(dockerfile)
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

    subprocess.run(
        ["docker", "build", "-t", tag, str(ctx)],
        check=True, capture_output=True,
    )
    shutil.rmtree(ctx, ignore_errors=True)
    return tag
