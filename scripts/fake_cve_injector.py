#!/usr/bin/env python3
"""Inject a crafted advisory into the orchestrator inbox.

Used to trigger an investigation without waiting on the live NVD feed.
Usage: python scripts/fake_cve_injector.py --scenario s01-pyyaml-rce
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INBOX = ROOT / "data" / "inbox"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True,
                        help="scenario id, e.g. s01-pyyaml-rce")
    args = parser.parse_args()

    meta_path = ROOT / "scenarios" / args.scenario / "cve-meta.json"
    meta = json.loads(meta_path.read_text())

    advisory = {
        "source": "patchproof-injector",
        "demo": True,
        "cve_id": meta["cve_id"],
        "dependency": meta["dependency"]["name"],
        "affected_range": meta["affected_range"],
        "summary": f"Injected advisory for {meta['cve_id']} "
                   f"({meta['dependency']['name']} {meta['affected_range']})",
        "matched_scenario_hint": args.scenario,
    }

    INBOX.mkdir(parents=True, exist_ok=True)
    out = INBOX / f"{meta['cve_id']}.json"
    out.write_text(json.dumps(advisory, indent=2))
    print(f"injected → {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
