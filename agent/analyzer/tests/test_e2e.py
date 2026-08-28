"""E2E smoke: analyzer reachability."""

import json

from agent.analyzer import reach


def test_e2e_s01_reach(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("pyyaml==5.3.1\n")
    (repo / "app.py").write_text("import yaml\nyaml.load(open('data.yaml').read())\n")
    (repo / "data.yaml").write_text("a: 1\n")
    adv = {"cve_id": "CVE-2020-14343", "packages": [{"name": "pyyaml", "ranges": ["<= 5.3.1"], "versions": [], "ecosystem": "pypi"}]}
    out = tmp_path / "out"
    rec = reach.reach(str(repo), adv, str(out))
    assert rec["verdict"] in ("REACHABLE", "UNKNOWN", "NOT_REACHABLE")
    assert (out / "reachability.json").exists()
    data = json.loads((out / "reachability.json").read_text())
    assert data["cve_id"] == "CVE-2020-14343"
