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


def response(ip, mac):
    return SimpleNamespace(psrc=ip, hwsrc=mac)


class MapperTests(unittest.TestCase):
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
        print(
            "PASS normal:",
            devices[0]["ip"],
            devices[0]["mac"],
            "missing=",
            missing,
        )

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
        print(
            "PASS duplicate:",
            "devices=",
            len(devices),
            "observations=",
            devices[0]["observation_count"],
        )

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
        print("PASS missing: devices=", devices, "missing=", missing)

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

            with self.assertRaises(ValueError):
                mapper.load_scope(filename)
        print("PASS invalid-scope: /27 rejected")

    def test_cli_test(self):
        with self.assertRaises(SystemExit):
            mapper.parse(["--scope", "scope.json", "--dryrun"])

        with self.assertRaises(SystemExit):
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
        print("PASS cli-test: missing and duplicate arguments rejected")

if __name__ == "__main__":
    unittest.main()
