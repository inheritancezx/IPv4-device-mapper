from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from create_scope import build_scope, main


SCOPES = Path(__file__).resolve().parents[1] / "scopes"


class ScopeTests(unittest.TestCase):
    def test_device_mapping_scope_is_fixed_to_the_compose_lab(self) -> None:
        scope = build_scope("g01", "device-map")
        self.assertEqual(scope["network"], "172.28.70.0/28")
        self.assertEqual(scope["authorised_hosts"], ["172.28.70.3", "172.28.70.10"])
        self.assertEqual(scope["maximum_rate_pps"], 20)

    def test_syn_scope_is_a_single_host_with_a_short_allow_list(self) -> None:
        scope = build_scope("g01", "tcp-syn-scan")
        self.assertEqual(scope["target"], "172.28.70.10")
        self.assertLessEqual(len(scope["ports"]), 30)

    def test_invalid_group_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_scope("G 01", "device-map")

    def test_cli_writes_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scope.json"
            import sys
            old_argv = sys.argv
            try:
                sys.argv = ["create_scope.py", "--group", "g01", "--option", "device-map", "--output", str(output)]
                self.assertEqual(main(), 0)
            finally:
                sys.argv = old_argv
            self.assertEqual(json.loads(output.read_text())["scope_id"], "local-compose-g01-device-map")

    def test_standard_scopes_are_completed_and_bound_to_the_compose_topology(self) -> None:
        device = json.loads((SCOPES / "assignment-01-device-map.json").read_text())
        syn = json.loads((SCOPES / "assignment-01-tcp-syn-scan.json").read_text())
        self.assertEqual(device["network"], "172.28.70.0/28")
        self.assertEqual(device["authorised_hosts"], ["172.28.70.3", "172.28.70.10"])
        self.assertEqual(syn["target"], "172.28.70.10")
        self.assertEqual(syn["ports"], [22, 80, 443, 8080])


if __name__ == "__main__":
    unittest.main()
