"""Reachability triage entry point.

Usage (dev/CI; the product path drives this via the harness skill with
sandbox_exec):
    python agent/analyzer/reach.py <repo-path> <cve-or-advisory> [--out <dir>]
    python -m agent.analyzer.reach <repo-path> <cve-or-advisory> [--out <dir>]

Writes reachability.json into --out (default data/output/<repo-basename>/).

Triage pipeline: dep-pin short-circuit -> call-site scan -> input-source trace.

Honesty rules (ADR-010):
  - All symbol/range knowledge comes from the advisory (file or OSV) at
    runtime; nothing is hardcoded into this tool.
  - NOT_REACHABLE requires identifying a non-attacker-controlled input source
    (e.g. a checked-in config file parsed at startup).
  - Ambiguous input sources are UNKNOWN, which gates sandbox time rather than
    assuming safe. The sandbox is the arbiter, never this heuristic.
"""

import argparse
import json
import os
import re
import sys
import urllib.request

if __package__ in (None, ""):  # direct-file execution: make the package importable
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    from agent.analyzer import deps, versions
else:
    from . import deps, versions

OSV_QUERY_URL = "https://api.osv.dev/v1/vulns/"

_SKIP_DIRS = deps._SKIP_PARTS + ("static", "assets", "dist", "build", "public", "vendor")
_SKIP_FILES = (".min.js",)

# Candidate symbols derived from advisory prose, kept conservative.
_FN_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{1,40})\s*\(")

# Input-source trace indicators (heuristic; the sandbox arbitrates).
# NETWORK: evidence the site is fed from an HTTP/argv/stdin source.
# STATIC: evidence of a checked-in file literal being parsed. Variable or
# function NAMES (config/settings/schema) prove nothing and are ignored.
_NETWORK_INDICATORS = (
    "@app.", "@router.", "@bp.", "@get(", "@post(", "@put(", "@patch(",
    "@delete(", "request", "body", "sys.argv", "stdin", "environ", "input(",
)
_STATIC_INDICATORS = (".yaml", ".yml", ".json")

_CODE_EXT = (".py", ".js", ".ts", ".jsx", ".tsx")
_SERIALIZATION_CAP = 40


def _load_advisory(arg):
    """Load advisory from a JSON file path or a bare CVE id via OSV.

    Returns {"cve_id", "source", "description", "packages": [{"name",
    "ranges": [range-str, ...]}]}. Empty range string means "all versions".
    """
    if os.path.isfile(arg):
        with open(arg, encoding="utf-8") as fh:
            data = json.load(fh)
        cve_id = str(data.get("cve_id") or data.get("id") or os.path.basename(arg))
        raw_pkg = data.get("package")
        if isinstance(raw_pkg, dict):
            raw_pkg = raw_pkg.get("name")
        affected = data.get("affected_versions") or data.get("affected") or ""
        if not isinstance(affected, str):
            affected = ""
        packages = [{"name": raw_pkg, "ranges": [affected]}] if raw_pkg else []
        return {"cve_id": cve_id, "source": "advisory-file",
                "description": data.get("description") or "", "packages": packages}

    cve_id = arg
    source = "unknown"
    desc = ""
    try:
        with urllib.request.urlopen(OSV_QUERY_URL + cve_id, timeout=15) as resp:
            data = json.load(resp)
        desc = data.get("details") or data.get("summary") or ""
        packages = []
        for aff in (data.get("affected") or []):
            name = (aff.get("package") or {}).get("name")
            if not name:
                continue
            ranges = []
            for r in (aff.get("ranges") or []):
                introduced = None
                for ev in (r.get("events") or []):
                    if "introduced" in ev:
                        introduced = ev["introduced"]
                    elif introduced is not None and ("fixed" in ev or "limit" in ev):
                        hi = ev.get("fixed", ev.get("limit"))
                        ranges.append(f">= {introduced}, < {hi}")
                        introduced = None
                if introduced is not None:
                    ranges.append("" if introduced == "0" else f">= {introduced}")
            packages.append({"name": name, "ranges": ranges})
        source = "osv"
    except Exception as exc:  # noqa: BLE001 - honest UNKNOWN on lookup failure
        return {"cve_id": cve_id, "source": source, "packages": [],
                "description": f"(OSV lookup failed: {exc})"}
    return {"cve_id": cve_id, "source": source, "description": desc,
            "packages": packages}


def _derive_vuln_funcs(advisory, pkg):
    """Conservative function-name candidates from advisory prose (ADR-010)."""
    funcs = set()
    desc = advisory.get("description") or ""
    for m in _FN_HINT_RE.finditer(desc):
        fn = m.group(1)
        if fn not in ("function", "class", "if", "for", "while", "def",
                      "return", "and", "or", "not"):
            funcs.add(fn.lower())
    for token in re.findall(r"\b[a-z]+_[a-z0-9_]*\b", desc):
        funcs.add(token.lower())
    if pkg:
        plow = pkg.lower().split(".")[-1]
        funcs.add(plow)
        for meth in ("load", "loads", "from_string", "render", "dumps", "execute"):
            funcs.add(f"{plow}.{meth}")
    return sorted(funcs)


def _is_direct_call(line, funcs, pkg):
    """True if the line invokes one of the vulnerable functions or the package.

    Word-boundary matching keeps distinct identifiers like ``safe_load`` from
    matching the vulnerable ``load`` token. Recognizes Python import forms and
    CommonJS ``require()``/dynamic ``import()``.
    """
    low = line.lower()
    for fn in funcs:
        if fn in ("yaml", "pickle", "jinja2", "trafaret_config"):
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(fn)}\(", low) or \
           re.search(rf"\.{re.escape(fn)}\(", low):
            return True
    if pkg:
        plow = re.escape(pkg.lower().split(".")[-1])
        if re.search(rf"import {plow}\b", low) or re.search(rf"from {plow}\b", low) or \
           re.search(rf"""require\(['"]{plow}['"]\)""", low) or \
           re.search(rf"""import\(['"]{plow}['"]\)""", low):
            return True
    return False


def _is_pkg_reference(line, pkg):
    low = line.lower()
    plow = pkg.lower().split(".")[-1]
    return (f"import {plow}" in low or f"from {plow}" in low or f"{plow}." in low or
            f"require('{plow}')" in low or f'require("{plow}")' in low)


def _file_is_code(fname):
    return fname.endswith(_CODE_EXT) and not fname.endswith(_SKIP_FILES)


_CONTEXT_WINDOW = 8


def _collected_site(rel, lineno, line, context):
    return {"file": rel, "line": lineno, "symbol": line.strip()[:160],
            "context": (context or line).strip()[:600]}


def _find_call_sites(repo_path, funcs, pkg):
    """Find candidate sites: direct vulnerable-fn/package calls.

    Every candidate is classified before any cap is applied; only the
    serialized report is truncated.
    """
    direct, pkg_sites = [], []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if not _file_is_code(fname):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo_path)
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            context = ""
            for lineno, line in enumerate(lines, 1):
                low = line.lower()
                if low.lstrip().startswith(("def ", "async def ", "@app.", "@router.", "@bp.")):
                    context = line
                window = "".join(lines[lineno:lineno + _CONTEXT_WINDOW])
                if _is_direct_call(line, funcs, pkg):
                    direct.append(_collected_site(rel, lineno, line, context + window))
                elif pkg and _is_pkg_reference(line, pkg):
                    pkg_sites.append(_collected_site(rel, lineno, line, context + window))
    return direct, pkg_sites


def _classify_site(site):
    """Classify a call site's input source using its context window.

    Returns REACHABLE / NOT_REACHABLE / UNKNOWN. Names alone prove nothing:
    NOT_REACHABLE requires a checked-in file literal in context; unresolved
    provenance stays UNKNOWN.
    """
    context = (site.get("context") or site["symbol"]).lower()
    if any(ind in context for ind in _NETWORK_INDICATORS):
        return "REACHABLE"
    if any(ind in context for ind in _STATIC_INDICATORS):
        return "NOT_REACHABLE"
    return "UNKNOWN"


def _trace_input_sources(sites):
    """Classify all candidate sites; aggregate into a verdict.

    Any REACHABLE site dominates. Any UNKNOWN site gates sandbox time —
    ambiguous sites never collapse into a static NOT_REACHABLE.
    """
    classified = []
    for site in sites:
        classified.append({**site, "input_source": _classify_site(site)})
    if not classified:
        return classified, ("UNKNOWN", "no candidate sites found in repo source")
    reachable = [c for c in classified if c["input_source"] == "REACHABLE"]
    unknown = [c for c in classified if c["input_source"] == "UNKNOWN"]
    notr = [c for c in classified if c["input_source"] == "NOT_REACHABLE"]

    def _loc(items):
        return "; ".join(f"{c['file']}:{c['line']}" for c in items[:5])

    if reachable:
        return classified, ("REACHABLE",
                            f"{len(reachable)} candidate site(s) fed by attacker-controlled/"
                            f"network input: {_loc(reachable)}")
    if unknown:
        return classified, ("UNKNOWN",
                            f"{len(unknown)} candidate site(s) with ambiguous input source "
                            f"(sandbox required): {_loc(unknown)}")
    return classified, ("NOT_REACHABLE",
                        f"only checked-in file inputs reach candidate site(s): {_loc(notr)}")


def _select_dep(repo_path, packages):
    """Pick the advisory package the repo actually pins.

    Returns (pkg_name, dep_entry, scan) using repository evidence rather than
    advisory order. A package declared without an exact pin is reported as
    version-unknown, never as absent.
    """
    scan = deps.scan_repo(repo_path)
    unknown = None
    for adv in packages:
        dep = deps.find_package(scan, adv["name"])
        if not dep:
            continue
        if dep["pinned"]:
            return adv["name"], dep, scan
        if unknown is None:
            unknown = (adv["name"], dep, scan)
    if unknown:
        return unknown
    return None, None, scan


def reach(repo_path, advisory, out_dir):
    packages = advisory.get("packages") or []
    record = {
        "cve_id": advisory["cve_id"],
        "source": advisory.get("source", "unknown"),
        "disclaimer": ("heuristic static verdict for scanned call sites only; symbol "
                       "knowledge derived from the advisory, no hardcoded map; "
                       "REACHABLE/UNKNOWN gate sandbox confirmation; import aliases "
                       "may evade static scanning — sandbox re-confirmation is "
                       "available for any verdict"),
    }

    if not packages:
        record.update({"in_scope": None, "verdict": "UNKNOWN", "confidence": "low",
                       "rationale": "no package derivable from advisory",
                       "needs_sandbox": True})
        _write(record, out_dir)
        return record

    pkg, dep, scan = _select_dep(repo_path, packages)
    record["advisory_packages"] = [p["name"] for p in packages]

    if dep is None:
        names = ", ".join(p["name"] for p in packages)
        record.update({"dep": None, "in_scope": False, "verdict": "NOT_REACHABLE",
                       "confidence": "high",
                       "rationale": f"no affected package ({names}) pinned in repo manifests",
                       "needs_sandbox": False})
        _write(record, out_dir)
        return record

    record["dep"] = {"name": pkg, "manifest": dep["manifest"],
                     "manifest_path": dep["path"], "spec": dep["spec"]}
    ranges = next((p["ranges"] for p in packages if p["name"] == pkg), [])
    if ranges:
        record["dep"]["affected_ranges"] = ranges

    if not dep["pinned"]:
        record.update({"in_scope": None, "verdict": "UNKNOWN", "confidence": "low",
                       "rationale": (f"{pkg} declared with non-exact spec "
                                     f"'{dep['spec']}'; installed version unknown "
                                     f"(resolve lockfile or confirm in sandbox)"),
                       "needs_sandbox": True})
        _write(record, out_dir)
        return record

    pinned = dep["version"]
    record["dep"]["pinned_version"] = pinned
    in_scope = any(versions.version_in_range(pinned, r) for r in ranges) if ranges else True
    record["in_scope"] = in_scope
    if not in_scope:
        record.update({"verdict": "NOT_REACHABLE", "confidence": "high",
                       "rationale": f"pinned {pkg}=={pinned} outside affected range "
                                    f"({'; '.join(ranges)})",
                       "needs_sandbox": False})
        _write(record, out_dir)
        return record

    funcs = _derive_vuln_funcs(advisory, pkg)
    direct, pkg_sites = _find_call_sites(repo_path, funcs, pkg)

    # Direct vulnerable calls first; package references as fallback. All sites
    # are classified before any cap; only the report is truncated.
    candidate = direct or pkg_sites
    record["call_sites"] = {"direct": direct[:_SERIALIZATION_CAP],
                            "pkg": pkg_sites[:_SERIALIZATION_CAP],
                            "totals": {"direct": len(direct), "pkg": len(pkg_sites)}}

    if not candidate:
        # The repo pins the package but its own source never references it.
        record.update({
            "verdict": "NOT_REACHABLE",
            "confidence": "high",
            "rationale": (f"pinned {pkg}=={pinned} not referenced in repo source; "
                          f"no call site of the vulnerable symbol"),
            "needs_sandbox": False,
        })
        _write(record, out_dir)
        return record

    classified, (verdict, rationale) = _trace_input_sources(candidate)
    record["call_sites_scanned"] = classified[:_SERIALIZATION_CAP]
    record.update({
        "verdict": verdict,
        "confidence": "high" if verdict == "NOT_REACHABLE" else (
            "medium" if verdict == "REACHABLE" else "low"),
        "rationale": rationale,
        "needs_sandbox": verdict in ("REACHABLE", "UNKNOWN"),
    })
    _write(record, out_dir)
    return record


def _write(record, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "reachability.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)


def _default_outdir(repo_path):
    return os.path.join("data", "output", os.path.basename(os.path.abspath(repo_path)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="PatchProof reachability analyzer")
    parser.add_argument("repo_path", help="path to the target repository")
    parser.add_argument("cve_or_advisory", help="advisory JSON path or a CVE id")
    parser.add_argument("--out", help="output directory (default data/output/<repo-basename>)")
    args = parser.parse_args(argv)

    advisory = _load_advisory(args.cve_or_advisory)
    out_dir = args.out or _default_outdir(args.repo_path)
    record = reach(args.repo_path, advisory, out_dir)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    print(f"\nwrote {os.path.join(out_dir, 'reachability.json')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
