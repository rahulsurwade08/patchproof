"""Reachability scan — wraps reach.py and produces a triage dict.

Returns:
    {
        "repository": <name>,
        "cves_discovered": int,
        "to_test":     [<cve_id>, ...],   # all CVEs that need sandbox confirmation
        "not_reachable": [<cve_id>, ...], # static analysis says not invoked (informational)
        "exploitable":    [<cve_id>, ...], # static analysis says REACHABLE
        "reachability": {cve_id: reach.py result dict}
    }
"""
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REACH_PY = REPO_ROOT / "agent" / "analyzer" / "reach.py"


def run_reach(repo: Path, cve_id: str, out_dir: Path) -> dict:
    """Run reach.py for one CVE. Returns parsed reachability.json or empty dict."""
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["python3", str(REACH_PY), str(repo), cve_id, "--out", str(out_dir)],
        capture_output=True, timeout=60,
    )
    rj = out_dir / "reachability.json"
    if rj.exists():
        return json.loads(rj.read_text())
    return {}


def scan_repo(repo: Path, out_root: Path) -> dict:
    """Run --discover, then per-CVE reachability. Bucket by verdict."""
    discover_dir = out_root / "_discover"
    discover_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["python3", str(REACH_PY), str(repo), "--discover", "--out", str(discover_dir)],
        capture_output=True, timeout=120,
    )
    disc = discover_dir / "discovered_cves.json"
    if not disc.exists():
        return {"repository": repo.name, "cves_discovered": 0,
                "to_test": [], "not_reachable": [], "exploitable": [], "reachability": {}}

    cves = json.loads(disc.read_text())
    reach_dir = out_root / "_reach"
    reach = {}
    for cve in cves:
        cid = cve["cve_id"]
        if not cve.get("affected", True):
            continue
        reach[cid] = run_reach(repo, cid, reach_dir / cid)

    # ponytail: agent tests every CVE that the static analyzer couldn't
    # definitively rule out. NOT_REACHABLE CVEs are skipped (static proof
    # they aren't invoked). Everything else is in `to_test`.
    not_reachable = [c for c, r in reach.items() if r.get("verdict") == "NOT_REACHABLE"]
    to_test = [c for c in reach if c not in not_reachable]
    exploitable = [c for c, r in reach.items() if r.get("verdict") == "REACHABLE"]

    return {
        "repository": repo.name,
        "cves_discovered": len(cves),
        "to_test": to_test,
        "not_reachable": not_reachable,
        "exploitable": exploitable,
        "reachability": reach,
    }


if __name__ == "__main__":
    import sys
    repo = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/dvpwa")
    out = REPO_ROOT / "data" / "output" / repo.name
    out.mkdir(parents=True, exist_ok=True)
    print(json.dumps(scan_repo(repo, out), indent=2))
