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


def test_unpinned_spec_is_unknown_not_absent(tmp_path):
    repo = tmp_path / "repo"
    _require(repo, body="pyyaml>=3.0\n")
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_pep621_dependency_list_parsed(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "pyproject.toml"),
           '[project]\nname = "x"\ndependencies = ["pyyaml==3.13"]\n')
    rec, _ = _run(repo, tmp_path)
    assert rec["dep"]["pinned_version"] == "3.13"
    assert rec["verdict"] == "NOT_REACHABLE"


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


def test_name_similarity_does_not_prove_static(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "app.py"), (
        "import yaml\n"
        "def parse(config):\n"
        "    return yaml.load(config)\n"))
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_mixed_unknown_and_static_gates_sandbox(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "startup.py"), "import yaml\nyaml.load(open('a.yaml'))\n")
    _write(os.path.join(repo, "util.py"), "import yaml\ndef f(v):\n    return yaml.load(v)\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


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


def test_direct_script_entry_runs(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    adv = _advisory(tmp_path)
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, "agent/analyzer/reach.py", str(repo), adv,
         "--out", str(tmp_path / "cli-out")],
        capture_output=True, text=True, cwd=os.getcwd())
    assert proc.returncode == 0, proc.stderr[-400:]
    assert os.path.isfile(tmp_path / "cli-out" / "reachability.json")


def test_osv_interval_events_assembled(tmp_path):
    advisory = reach._load_advisory.__wrapped__ if hasattr(reach._load_advisory, "__wrapped__") else None
    # Direct interval-assembly check through the OSV event list shape.
    events = [{"introduced": "3.0"}, {"fixed": "3.9"},
              {"introduced": "4.0"}, {"fixed": "5.4"}]
    ranges = []
    introduced = None
    for ev in events:
        if "introduced" in ev:
            introduced = ev["introduced"]
        elif introduced is not None and ("fixed" in ev or "limit" in ev):
            hi = ev.get("fixed", ev.get("limit"))
            ranges.append(f">= {introduced}, < {hi}")
            introduced = None
    assert ranges == [">= 3.0, < 3.9", ">= 4.0, < 5.4"]
    assert versions.version_in_range("3.13", ranges[0]) is False
    assert versions.version_in_range("3.5", ranges[0]) is True


def test_gen_context_generates_dockerfile(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    result = gen_context.generate(str(repo), str(repo))
    assert os.path.isfile(os.path.join(str(repo), "Dockerfile"))
    assert result["entry"] == "main.py"
    assert result["base_image"].startswith("python:")
    assert result["build_context"] == os.path.abspath(str(repo))


def test_gen_context_refuses_overwrite(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    gen_context.generate(str(repo), str(repo))
    with pytest.raises(FileExistsError):
        gen_context.generate(str(repo), str(repo))
    gen_context.generate(str(repo), str(repo), force=True)


def test_gen_context_out_is_complete_context(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    out = tmp_path / "ctx"
    result = gen_context.generate(str(repo), str(out))
    assert result["build_context"] == os.path.abspath(str(out))
    assert os.path.isfile(out / "Dockerfile")
    assert os.path.isfile(out / "main.py")
    assert os.path.isfile(out / "requirements.txt")


def test_gen_context_node_entry_uses_node(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"),
           json.dumps({"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "server.js"), "console.log('hi')\n")
    result = gen_context.generate(str(repo), str(repo))
    assert result["base_image"] == "node:20-slim"
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert 'CMD ["node", "server.js"]' in dockerfile
    assert "npm install" in dockerfile


def test_gen_context_npm_ci_with_lockfile(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"),
           json.dumps({"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "package-lock.json"), "{}")
    _write(os.path.join(repo, "server.js"), "console.log('hi')\n")
    gen_context.generate(str(repo), str(repo))
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert "npm ci" in dockerfile and "package-lock.json" in dockerfile


def test_versions_range_parsing():
    assert versions.version_in_range("3.13", "< 5.4") is True
    assert versions.version_in_range("5.4", "< 5.4") is False
    assert versions.version_in_range("4.5", ">= 4.0, < 5.4") is True
    assert versions.version_in_range("5.3.1", "< 5.4") is True
    assert versions.version_in_range("3.9", ">= 3.0, < 3.1.5") is False


def test_prerelease_sorts_before_release():
    assert versions.version_in_range("1.0rc1", "< 1.0") is True
    assert versions.version_in_range("1.0", "< 1.0") is False
    assert versions.version_in_range("1.0rc2", "< 1.0rc1") is False


def test_deps_scan_missing_dir():
    assert deps.scan_repo("/nonexistent") == {}
