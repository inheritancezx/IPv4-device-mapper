import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import mapper


def response(ip, mac, op=2):
    # op=2 means "this packet is an ARP reply" (1 would be a request)
    return SimpleNamespace(psrc=ip, hwsrc=mac, op=op)


def show(title, data):
    print(f"\n  {title}:")
    for line in json.dumps(data, indent=2).splitlines():
        print("    " + line)


def good_scope(**changes):
    scope = {
        "scope_id": "test-scope",
        "option": "device-map",
        "network": "192.0.2.0/28",
        "interface": "eth0",
        "maximum_rate_pps": 20,
        "maximum_attempts": 2,
    }
    scope.update(changes)
    return scope


def write_scope(directory, scope):
    filename = Path(directory) / "scope.json"
    filename.write_text(json.dumps(scope), encoding="utf-8")
    return filename


class MapperTests(unittest.TestCase):
    def setUp(self):
        print(f"\n{'=' * 60}")
        print(f"TEST: {self._testMethodName}")
        print(f"{'=' * 60}")

    def test_normal(self):
        with patch.object(
            mapper,
            "srp",
            return_value=(
                [(None, response("192.0.2.1", "00:11:22:33:44:55"))],
                [],
            ),
        ):
            devices, missing = mapper.execute_device_map(
                mapper.ipaddress.ip_network("192.0.2.0/30"),
                "eth0",
                20,
                1,
                1.5,
            )

        self.assertEqual(devices[0]["ip"], "192.0.2.1")
        self.assertEqual(devices[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(devices[0]["observation_count"], 1)
        self.assertEqual(missing, ["192.0.2.2"])
        show("devices found", devices)
        show("not observed", missing)

    def test_duplicate(self):
        reply = ([(None, response("192.0.2.1", "00:11:22:33:44:55"))], [])
        with patch.object(mapper, "srp", side_effect=[reply, reply]):
            devices, _ = mapper.execute_device_map(
                mapper.ipaddress.ip_network("192.0.2.0/30"),
                "eth0",
                20,
                2,
                1.5,
            )

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["observation_count"], 2)
        self.assertEqual(len(devices[0]["observation_times"]), 2)
        show("devices found (same device answered twice, listed once)", devices)

    def test_missing(self):
        with patch.object(mapper, "srp", return_value=([], [])):
            devices, missing = mapper.execute_device_map(
                mapper.ipaddress.ip_network("192.0.2.0/30"),
                "eth0",
                20,
                1,
                1.5,
            )

        self.assertEqual(devices, [])
        self.assertEqual(missing, ["192.0.2.1", "192.0.2.2"])
        show("devices found", devices)
        show("not observed", missing)

    def test_invalid_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "scope.json"
            filename.write_text(
                json.dumps(
                    {
                        "scope_id": "invalid",
                        "option": "device-map",
                        "network": "192.0.2.0/27",
                        "interface": "eth0",
                        "maximum_rate_pps": 20,
                        "maximum_attempts": 2,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as caught:
                mapper.load_scope(filename)
        print("\n  scope had network 192.0.2.0/27")
        print("  error raised:", caught.exception)

    def test_cli(self):
        with self.assertRaises(SystemExit) as missing_output:
            mapper.parse(["--scope", "scope.json", "--dryrun"])
        print("\n  missing --output -> exit code", missing_output.exception.code)

        with self.assertRaises(SystemExit) as duplicate_scope:
            mapper.parse(
                [
                    "--scope",
                    "one.json",
                    "--scope",
                    "two.json",
                    "--output",
                    "result.json",
                    "--dryrun",
                ]
            )
        print("  duplicate --scope -> exit code", duplicate_scope.exception.code)

    def test_placeholder(self):
        for bad in ({"scope_id": "TBD"}, {"network": "<network>"},
                    {"interface": ""}, {"scope_id": "REPLACE_ME"}):
            with tempfile.TemporaryDirectory() as directory:
                filename = write_scope(directory, good_scope(**bad))
                with self.assertRaises(ValueError) as caught:
                    mapper.load_scope(filename)
            print(f"\n  bad value {bad} ->", caught.exception)

    def test_dryrun(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = write_scope(directory, good_scope())
            output = Path(directory) / "result.json"
            with patch.object(mapper, "srp") as fake, \
                 contextlib.redirect_stdout(io.StringIO()) as printed:
                status = mapper.main(
                    ["--scope", str(scope), "--output", str(output), "--dryrun"]
                )

            self.assertEqual(status, 0)
            fake.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIn("DRYRUN", printed.getvalue())
        print("\n  what the dry run printed:")
        for line in printed.getvalue().splitlines():
            print("    " + line)
        print("  exit status:", status)
        print("  srp (the packet sender) called?", fake.called)
        print("  result file created?", output.exists())

    def test_retry_analysis(self):
        attempt1 = ([], [])
        attempt2 = ([(None, response("192.0.2.1", "00:11:22:33:44:55"))], [])
        with patch.object(mapper, "srp", side_effect=[attempt1, attempt2]):
            devices, missing = mapper.execute_device_map(
                mapper.ipaddress.ip_network("192.0.2.0/30"), "eth0", 20, 2, 1.5
            )

        self.assertEqual(devices[0]["attempts_seen"], [2])
        summary = mapper.summarise_retry(devices, missing, 2)

        self.assertEqual(summary["found_only_after_retry"], 1)
        self.assertEqual(summary["found_on_first_attempt"], 0)
        self.assertEqual(summary["probes_sent"], 4)
        
        show("devices found", devices)
        show("retry analysis", summary)

class QuietResult(unittest.TextTestResult):
    def startTest(self, test):
        unittest.TestResult.startTest(self, test)

unittest.TextTestRunner.resultclass = QuietResult


if __name__ == "__main__":
    unittest.main(verbosity=2)
