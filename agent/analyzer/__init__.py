"""CheckExploit static reachability analyzer.

Deterministic, dependency-free Python helpers for reachability triage.
Symbol/range knowledge comes from the advisory at runtime; nothing is
hardcoded (ADR-010).
"""

__all__ = ["versions", "deps", "reach"]
