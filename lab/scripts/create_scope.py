"""Create a completed Assignment 1 scope for the WQE7002 local Compose rehearsal lab."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


GROUP = re.compile(r"^[a-z][a-z0-9-]{0,15}$")


def build_scope(group: str, option: str) -> dict:
    if not GROUP.fullmatch(group):
        raise ValueError("group must start with a lowercase letter and use only lowercase letters, digits and hyphens")
    common = {
        "schema": "wqe7002-recon-scope-v1",
        "scope_id": f"local-compose-{group}-{option}",
        "option": option,
        "environment": "isolated-course-lab",
        "interface": "eth0",
        "maximum_rate_pps": 20,
        "maximum_attempts": 2,
        "timeout_seconds": 1.5,
        "capture_point": "workbench eth0; records the authorised scanner vantage point",
        "topology": "wqe7002-course-lab Compose internal bridge",
    }
    if option == "device-map":
        return {
            **common,
            "network": "172.28.70.0/28",
            "authorised_hosts": ["172.28.70.3", "172.28.70.10"],
        }
    return {
        **common,
        "target": "172.28.70.10",
        "ports": [22, 80, 443, 8080],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", required=True)
    parser.add_argument("--option", required=True, choices=("device-map", "tcp-syn-scan"))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    scope = build_scope(args.group, args.option)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {scope['scope_id']} to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
