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


def detect_entrypoint(repo: Path) -> str | None:
    """Best-effort: find a runnable command in the repo."""
    # ponytail: heuristic only — looks for the most common patterns
    for candidate in [
        ("run.py", "python3 run.py"),
        ("app.py", "python3 app.py"),
        ("main.py", "python3 main.py"),
        ("manage.py", "python3 manage.py runserver 0.0.0.0:8080"),
    ]:
        if (repo / candidate[0]).exists():
            return candidate[1]
    return None


def build_image_for_repo(repo: Path) -> str:
    """Return the docker image tag to use for this repo."""
    sha = repo_sha(repo)
    tag = f"{IMAGE_PREFIX}:{repo.name}-{sha}"

    if image_exists(tag):
        return tag

    # Build context = repo itself (read-only mount at build time)
    entrypoint = detect_entrypoint(repo) or "python3 -c 'import time; time.sleep(3600)'"
    req_files = [f for f in ("requirements.txt", "pyproject.toml", "Pipfile") if (repo / f).exists()]

    # ponytail: Dockerfile is templated inline; upgrade to a proper template
    # engine when we support more than Python. start.sh is required by
    # exploit.py to know the service is ready.
    start_sh = f"""#!/bin/bash
set +e
ENTRYPOINT="{entrypoint.strip()}"
# Strip leading "python3 " or "python " from entrypoint if present
ENTRYPOINT="${{ENTRYPOINT#python3 }}"
ENTRYPOINT="${{ENTRYPOINT#python }}"
# Kill stale app processes
for p in $ENTRYPOINT app.py run.py main.py; do
    pids=$(pgrep -f "$p" 2>/dev/null)
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null
done
sleep 1
# Start the app
python3 $ENTRYPOINT >> /tmp/srv.log 2>&1 &
# Wait for port 8080 (max 10s)
for i in $(seq 1 20); do
    python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', 8080)); s.close(); exit(0)" 2>/dev/null && {{
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
    ) + """
EXPOSE 8080
CMD ["/srv/start.sh"]
"""

    # Build with a temp context dir to avoid embedding secrets
    ctx = Path(f"/tmp/pp-build-{sha}")
    ctx.mkdir(exist_ok=True)
    (ctx / "Dockerfile").write_text(dockerfile)
    (ctx / "start.sh").write_text(start_sh)
    # Symlink only the needed files (avoid .git, .env, etc.)
    for item in repo.iterdir():
        if item.name in {".git", ".env", "venv", "__pycache__", ".venv", "node_modules"}:
            continue
        target = ctx / item.name
        if item.is_dir():
            target.symlink_to(item)
        else:
            target.write_bytes(item.read_bytes())

    subprocess.run(
        ["docker", "build", "-t", tag, str(ctx)],
        check=True, capture_output=True,
    )
    shutil.rmtree(ctx, ignore_errors=True)
    return tag
