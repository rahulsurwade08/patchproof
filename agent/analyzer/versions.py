"""Minimal version + version-range parsing.

Serves the dep-pin short-circuit: decide whether a repo's pinned version of a
package falls inside an advisory's affected range. No external dependency;
handles the common PEP 440-style specifiers used by OSV/CVE advisories.

Prerelease semantics: ``1.0rc1`` sorts BEFORE ``1.0`` (a release candidate is
older than the final release), so a ``< 1.0`` range includes vulnerable
prereleases instead of wrongly marking them out of scope.
"""

import re
from functools import total_ordering

_NUM_RE = re.compile(r"(\d+|[a-zA-Z]+)")

# Pre-release tokens ranked: a smaller rank sorts older.
# PEP 440 order: dev < alpha < beta < rc(=preview/c) < final < local < post.
# The final release itself sits at rank 4; a local version (+foo) at 4.5;
# post at 5 (see _cmp).
_PRE_RANK = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "pre": 2,
             "c": 3, "rc": 3, "preview": 3, "post": 5, "rev": 5, "r": 5}
_FINAL_RANK = 4
_LOCAL_RANK = 4.5


def _parse(text):
    """Return (num_parts, pre_rank or None, pre_parts, local_parts or None)."""
    base, _, local = str(text).strip().lower().partition("+")
    local_tokens = _NUM_RE.findall(local) if local else None
    tokens = _NUM_RE.findall(base)
    nums, pre, pre_nums = [], None, []
    for tok in tokens:
        if tok.isdigit():
            (pre_nums if pre is not None else nums).append(int(tok))
        elif pre is not None:
            pre_nums.append(tok)
        elif tok in _PRE_RANK:
            pre = _PRE_RANK[tok]
        else:
            nums.append(tok)
    return nums, pre, pre_nums, (local_tokens or None)


@total_ordering
class _Version:
    def __init__(self, text):
        self.text = text
        self.nums, self.pre, self.pre_nums, self.local = _parse(text)

    def __eq__(self, other):
        return _cmp(self, other) == 0

    def __lt__(self, other):
        return _cmp(self, other) < 0

    def __repr__(self):
        return f"Version({self.text!r})"


def _mixed_compare(a, b):
    """Compare part lists holding ints and/or strings."""
    for x, y in zip(a, b):
        if x == y:
            continue
        xnum, ynum = isinstance(x, int), isinstance(y, int)
        if xnum != ynum:
            return -1 if xnum else 1
        return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def _strip_zeros(nums):
    """Trailing zero components are insignificant: 1.0 == 1.0.0 == 1."""
    i = len(nums)
    while i and nums[i - 1] == 0:
        i -= 1
    return nums[:i]


def _cmp(a, b):
    if not isinstance(b, _Version):
        b = _Version(b)
    c = _mixed_compare(_strip_zeros(a.nums), _strip_zeros(b.nums))
    if c:
        return c
    if a.pre is None:
        ra = _LOCAL_RANK if a.local else _FINAL_RANK
    else:
        ra = a.pre
    if b.pre is None:
        rb = _LOCAL_RANK if b.local else _FINAL_RANK
    else:
        rb = b.pre
    if ra != rb:
        return (ra > rb) - (ra < rb)
    if a.local != b.local:
        return _mixed_compare(a.local or [], b.local or [])
    return _mixed_compare(a.pre_nums, b.pre_nums)


def parse_version(text):
    return _Version(text)


def _clause_matches(op, ver, pinned):
    c = _cmp(pinned, ver)
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
        prefix = ver.nums[:max(1, len(ver.nums) - 1)]
        return c >= 0 and pinned.nums[:len(prefix)] == prefix
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
