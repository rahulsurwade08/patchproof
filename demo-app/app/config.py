"""YAML loading — mixed vulnerable and safe patterns for reachability triage."""

from pathlib import Path

import yaml

DEFAULTS_PATH = Path(__file__).resolve().parent / "defaults.yaml"


def load_user_yaml(raw: bytes):
    """REACHABLE site: FullLoader on untrusted HTTP body.

    OSV: pyyaml==5.3.1 GHSA-8q59-q68h-6hv4 — Fixed in 5.4. Loader thought safe,
    but FullLoader processes python/object tags leading to RCE.
    """
    # Vulnerable — must be flagged by scanner and marked REACHABLE by analyzer
    return yaml.load(raw, Loader=yaml.FullLoader)


def load_defaults():
    """NOT_REACHABLE site: safe_load on checked-in static file.

    This is loaded at startup from app/defaults.yaml (committed to git),
    never from user input. Analyzer must mark NOT_REACHABLE (no sandbox needed).
    Scanner still flags the pyyaml pin, but PatchProof proves this site safe.
    """
    text = DEFAULTS_PATH.read_text()
    return yaml.safe_load(text)


def load_strict_yaml(text: str):
    """Safe alternative — used by health checks."""
    return yaml.safe_load(text)
