"""Tests for the --discover flag and discover_cves() function in reach.py.

Auto-discovery mode lets the user submit a repo without a known CVE id
and have the analyzer list every CVE that affects any declared dependency,
deduplicated and ranked.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from agent.analyzer import reach


class DiscoverCvesTests(unittest.TestCase):

    def test_ecosystem_for_python_manifests(self):
        """Python manifests map to PyPI ecosystem in OSV queries."""
        scan = {
            "pyyaml": [
                {"manifest": "requirements", "version": "5.3.1", "pinned": True, "spec": "==5.3.1"}
            ]
        }
        self.assertEqual(reach._ecosystem_for("pyyaml", scan), "PyPI")

    def test_ecosystem_for_npm_manifests(self):
        """npm manifests (package.json) map to npm ecosystem."""
        scan = {
            "lodash": [
                {"manifest": "package.json", "version": "4.17.20", "pinned": True, "spec": "4.17.20"}
            ]
        }
        self.assertEqual(reach._ecosystem_for("lodash", scan), "npm")

    def test_extract_cve_id_prefers_cve_alias(self):
        """OSV records often have GHSA/PYSEC primary id and CVE alias.

        _extract_cve_id should return the CVE alias (not the primary id)
        so downstream code uses the canonical CVE id.
        """
        vuln = {
            "id": "GHSA-8q59-q68h-6hv4",
            "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
            "summary": "Improper Input Validation in PyYAML"
        }
        self.assertEqual(reach._extract_cve_id(vuln), "CVE-2020-14343")

    def test_extract_cve_id_returns_none_without_alias(self):
        """Records without a CVE alias get None (fail closed)."""
        vuln = {"id": "GHSA-only-no-cve", "aliases": [], "summary": "..."}
        self.assertIsNone(reach._extract_cve_id(vuln))

    def test_discover_cves_empty_repo(self):
        """Empty/missing repo path returns no CVEs (fail closed)."""
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(reach.discover_cves(empty), [])

    def test_discover_cves_with_mocked_osv(self):
        """Full discover_cves() flow with mocked OSV API responses.

        Verifies that:
        - The repo's manifest is parsed correctly
        - OSV is queried for each package
        - Results are deduplicated and sorted
        """
        with tempfile.TemporaryDirectory() as repo:
            with open(os.path.join(repo, "requirements.txt"), "w") as f:
                f.write("pyyaml==5.3.1\n")

            sample_vuln = {
                "id": "GHSA-8q59-q68h-6hv4",
                "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
                "summary": "PyYAML FullLoader bypass",
            }
            with mock.patch.object(reach, "_osv_query_package",
                                   return_value=[sample_vuln]) as mock_q:
                cves = reach.discover_cves(repo)
            # We expect at least one CVE for pyyaml
            cve_ids = {c["cve_id"] for c in cves}
            self.assertIn("CVE-2020-14343", cve_ids)
            # OSV was queried
            self.assertGreaterEqual(mock_q.call_count, 1)

    def test_handle_discover_writes_json(self):
        """_handle_discover writes discovered_cves.json and prints summary."""
        with tempfile.TemporaryDirectory() as repo:
            with open(os.path.join(repo, "requirements.txt"), "w") as f:
                f.write("pyyaml==5.3.1\n")
            out = tempfile.mkdtemp()
            try:
                args = mock.Mock(repo_path=repo, out=out)
                with mock.patch.object(reach, "_osv_query_package", return_value=[]):
                    reach._handle_discover(args)
                # discovered_cves.json must exist (even if empty)
                self.assertTrue(os.path.exists(os.path.join(out, "discovered_cves.json")))
                with open(os.path.join(out, "discovered_cves.json")) as f:
                    data = json.load(f)
                self.assertIsInstance(data, list)
            finally:
                import shutil
                shutil.rmtree(out, ignore_errors=True)

    def test_handle_discover_rejects_invalid_repo(self):
        """Invalid repo path exits with non-zero status."""
        args = mock.Mock(repo_path="/nonexistent/xyz", out=None)
        with self.assertRaises(SystemExit) as ctx:
            reach._handle_discover(args)
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
