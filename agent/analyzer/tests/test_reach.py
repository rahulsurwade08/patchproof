"""Unit tests for the reachability analyzer.

Fixtures are tiny throwaway repos built in tmp_path; the analyzer must decide
REACHABLE / NOT_REACHABLE / UNKNOWN honestly across the triage paths.
"""

import json
import os

import pytest

from agent.analyzer import deps, gen_context, reach, versions  # noqa: E402


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _require(repo, body="pyyaml==3.13\n"):
    _write(os.path.join(repo, "requirements.txt"), body)


def _advisory(tmp_path, cve="CVE-X", pkg="pyyaml", affected="< 5.4",
              desc="load() executes arbitrary code"):
    p = tmp_path / "advisory.json"
    _write(str(p), json.dumps({
        "cve_id": cve, "package": pkg, "affected_versions": affected,
        "description": desc}))
    return str(p)


def _run(repo, tmp_path, **kw):
    adv = _advisory(tmp_path, **kw)
    out_dir = str(tmp_path / "out")
    return reach.reach(str(repo), reach._load_advisory(adv), out_dir), out_dir


def test_dep_out_of_scope(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    rec, _ = _run(repo, tmp_path, affected=">= 5.4")
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False
    assert rec["in_scope"] is False


def test_package_not_pinned(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "requirements.txt"), "flask==2.0\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["in_scope"] is False
    assert rec["needs_sandbox"] is False


def test_direct_load_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), (
        "import yaml\n"
        "async def load_config(request):\n"
        "    raw = await request.body()\n"
        "    cfg = yaml.load(raw)\n"))
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "REACHABLE"
    assert rec["needs_sandbox"] is True


def test_pinned_but_unreferenced_not_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hello')\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False


def test_safe_symbol_not_mistaken_for_vulnerable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), (
        "import yaml\n"
        "async def load_config(request):\n"
        "    raw = await request.body()\n"
        "    cfg = yaml.safe_load(raw)\n"))
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False


def test_static_config_not_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "config.py"), (
        "import yaml\n"
        "cfg = yaml.load(open('./dev.yaml', 'r'))\n"))
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False


def test_no_package_in_advisory_unknown(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    adv_path = _advisory(tmp_path, pkg="")
    rec = reach.reach(str(repo), reach._load_advisory(adv_path), str(tmp_path / "o"))
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_reachability_json_written(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    rec, out_dir = _run(repo, tmp_path)
    out_file = os.path.join(out_dir, "reachability.json")
    assert os.path.isfile(out_file)
    with open(out_file, encoding="utf-8") as fh:
        assert json.load(fh)["cve_id"] == rec["cve_id"]


def test_gen_context_generates_dockerfile(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    result = gen_context.generate(str(repo), str(repo))
    assert os.path.isfile(os.path.join(str(repo), "Dockerfile"))
    assert result["entry"] == "main.py"
    assert result["base_image"].startswith("python:")


def test_versions_range_parsing():
    assert versions.version_in_range("3.13", "< 5.4") is True
    assert versions.version_in_range("5.4", "< 5.4") is False
    assert versions.version_in_range("4.5", ">= 4.0, < 5.4") is True
    assert versions.version_in_range("5.3.1", "< 5.4") is True
    assert versions.version_in_range("3.9", ">= 3.0, < 3.1.5") is False


def test_deps_scan_requirements():
    repo = "/tmp/nonexistent-does-not-exist"
    # no-op sanity: scanning a missing dir returns empty
    assert deps.scan_repo("/nonexistent") == {}
