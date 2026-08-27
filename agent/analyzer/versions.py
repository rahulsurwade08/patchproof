"""Minimal version + version-range parsing.

Serves the dep-pin short-circuit: decide whether a repo's pinned version of a
package falls inside an advisory's affected range. No external dependency;
handles the common PEP 440-style specifiers used by OSV/CVE advisories.
"""

import re
from functools import total_ordering

_NUM_RE = re.compile(r"(\d+|[a-zA-Z]+)")


@total_ordering
class _Version:
    def __init__(self, text):
        self.text = text
        self.parts = _parse_parts(text)

    def __eq__(self, other):
        return isinstance(other, _Version) and _compare(_to(other), self.parts) == 0

    def __lt__(self, other):
        return isinstance(other, _Version) and _compare(_to(other), self.parts) < 0

    def __repr__(self):
        return f"Version({self.text!r})"


def _to(other):
    return other if isinstance(other, _Version) else _Version(other)


def _compare(a, b):
    """Compare two part-lists numerically where possible, lexically otherwise."""
    for x, y in zip(a, b):
        if x == y:
            continue
        xnum = isinstance(x, int)
        ynum = isinstance(y, int)
        if xnum and ynum:
            return -1 if x < y else 1
        if xnum != ynum:
            return -1 if xnum else 1
        return -1 if x < y else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def _parse_parts(text):
    parts = []
    for raw in _NUM_RE.findall(str(text).strip()):
        parts.append(int(raw) if raw.isdigit() else raw)
    return parts


def parse_version(text):
    return _Version(text)


def _clause_matches(op, ver, pinned):
    c = _compare(_to(pinned).parts, ver.parts)
    if op == "==":
        return c == 0
    if op == "!=":
        return c != 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    if op == "~=":
        return c >= 0 and _to(pinned).parts[: max(1, len(ver.parts) - 1)] == ver.parts[: max(1, len(ver.parts) - 1)]
    return True


def version_in_range(pinned_version, range_spec):
    """Return True if pinned_version falls inside range_spec.

    range_spec is a comma/space-separated set of clauses, e.g. '< 5.4',
    '>= 4.0, < 5.4', '<=5.3.1', or '3.13'. A bare value with no operator is
    treated as an equality constraint.
    """
    if not pinned_version or not range_spec:
        return False
    pinned = _Version(pinned_version)
    for raw_clause in re.split(r"[,;]", range_spec):
        clause = raw_clause.strip()
        if not clause:
            continue
        m = re.match(r"^(==|!=|<=|>=|<|>|~=)?\s*(.+)$", clause)
        if not m:
            return False
        op, ver_text = m.group(1) or "==", m.group(2).strip()
        if not _clause_matches(op, _Version(ver_text), pinned):
            return False
    return True
