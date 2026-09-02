"""PatchProof mechanical driver — scan + build image + emit triage.

After this, the agent (LLM) picks up triage.json, generates PoCs,
runs exploits, judges verdicts, generates patches, writes reports.
"""
import argparse
import json
import subprocess
import sys
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.build_image import build_image_for_repo  # noqa: E402
from agent.scan import run_reach, scan_repo  # noqa: E402


def clone_or_resolve(repo_arg: str) -> Path:
    """Return a local path to the repo.

    - If already a local path with a .git, use it.
    - If a local path without .git, use it as-is.
    - If a URL (github.com, gitlab.com, etc.), clone into /tmp/pp-clones/.
    """
    p = Path(repo_arg).resolve()
    if p.exists() and (p / ".git").exists():
        return p
    if p.exists():
        return p
    if "://" in repo_arg or repo_arg.startswith("git@"):
        clone_dir = Path(f"/tmp/pp-clones/{Path(urllib.parse.urlparse(repo_arg).path).stem}")
        if not clone_dir.exists():
            clone_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", "--quiet", repo_arg, str(clone_dir)], check=True)
        return clone_dir
    raise FileNotFoundError(f"repo not found: {repo_arg}")


def run():
    p = argparse.ArgumentParser(description="PatchProof scan driver")
    p.add_argument("repo", help="local path or git URL")
    p.add_argument("--out", default=str(REPO_ROOT / "data" / "output"))
    p.add_argument("--skip-image", action="store_true",
                   help="skip docker image build (use existing PATCHPROOF_IMAGE env var)")
    p.add_argument("--cve", help="test only this CVE (skip discovery scan)")
    args = p.parse_args()

    repo = clone_or_resolve(args.repo)
    out_root = Path(args.out) / repo.name
    out_root.mkdir(parents=True, exist_ok=True)

    if args.cve:
        # Single-CVE mode: load existing triage if present, else run the
        # per-CVE reachability check so the agent has a real verdict
        # (NOT_REACHABLE → skip, REACHABLE/UNKNOWN → test) instead of
        # blindly trusting the user-supplied CVE id.
        triage_path = out_root / "triage.json"
        if triage_path.exists():
            triage = json.loads(triage_path.read_text())
        else:
            reach = run_reach(repo, args.cve, out_root / "_reach" / args.cve)
            verdict = reach.get("verdict", "UNKNOWN")
            triage = {
                "repository": repo.name,
                "cves_discovered": 1,
                "to_test": [args.cve] if verdict in ("REACHABLE", "UNKNOWN") else [],
                "not_reachable": [args.cve] if verdict == "NOT_REACHABLE" else [],
                "exploitable": [],
                "not_exploitable": [],
                "reachability": {args.cve: reach},
            }
    else:
        print(f"[1/2] scanning {repo} ...", flush=True, end="", file=sys.stderr)
        triage = scan_repo(repo, out_root)
        print(f" done. {triage['cves_discovered']} CVEs found, "
              f"{len(triage['to_test'])} to test, "
              f"{len(triage['not_reachable'])} not reachable", flush=True, file=sys.stderr)

    # Save triage
    triage_path = out_root / "triage.json"
    triage_path.write_text(json.dumps(triage, indent=2))
    print(f"  triage: {triage_path}", file=sys.stderr)
    if args.cve:
        reach = triage.get("reachability", {}).get(args.cve, {})
        verdict = reach.get("verdict", "UNKNOWN")
        action = "not testing" if verdict == "NOT_REACHABLE" else "queued for sandbox"
        print(f"  {args.cve}: {verdict} — {action}", file=sys.stderr)

    # Build image
    import os
    image = os.environ.get("PATCHPROOF_IMAGE", "")
    if not args.skip_image:
        if image:
            print(f"  image: {image} (from PATCHPROOF_IMAGE env)", file=sys.stderr)
        else:
            print(f"[2/2] building sandbox image ...", flush=True, end="", file=sys.stderr)
            image = build_image_for_repo(repo)
            print(f" done. image={image}", flush=True, file=sys.stderr)

    print(
        f"\nPatchProof triage saved to {triage_path}\n"
        f"Image: {image}\n"
        f"Repo: {repo}\n"
        f"\nThe agent should now:\n"
        f"  1. Read {triage_path}\n"
        f"  2. For each CVE in triage['to_test']:\n"
        f"     (skip triage['not_reachable'] — static proof they aren't invoked)\n"
        f"     a. Generate a PoC (HTTP request or library call)\n"
        f"     b. Run it via sandbox_exec → get verdict.json\n"
        f"     c. If exploitable: generate + apply patch, re-run, verify\n"
        f"  3. Write report.json + report.md to {out_root}/\n",
        file=sys.stderr
    )


if __name__ == "__main__":
    run()
