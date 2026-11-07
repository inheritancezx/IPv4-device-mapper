import ipaddress
import json
import sys
from datetime import datetime, timezone

from scapy.all import ARP, Ether, srp


def usage():
    sys.stderr.write(
        "Usage: scope --scope file --output file "
        "[--dryrun | --execute] [--rate n] [--attempts n] [--iface name]\n"
    )
    raise SystemExit(1)


def parse(argv):
    args = list(argv)
    scope = None
    output = None
    dryrun = False
    execute = False
    rate = None
    attempts = None
    iface = None
    index = 0

    while index < len(args):
        arg = args[index]

        if arg in ("--dryrun", "--execute"):
            if dryrun or execute:
                usage()
            dryrun = arg == "--dryrun"
            execute = arg == "--execute"
            index += 1
            continue

        if arg not in ("--scope", "--output", "--rate", "--attempts", "--iface"):
            usage()

        index += 1
        if index >= len(args) or args[index] == "":
            usage()

        value = args[index]
        if arg == "--scope":
            if scope is not None:
                usage()
            scope = value
        elif arg == "--output":
            if output is not None:
                usage()
            output = value
        elif arg == "--rate":
            if rate is not None:
                usage()
            rate = value
        elif arg == "--attempts":
            if attempts is not None:
                usage()
            attempts = value
        elif arg == "--iface":
            if iface is not None:
                usage()
            iface = value
        index += 1

    if scope is None or output is None or (not dryrun and not execute):
        usage()

    return scope, output, dryrun, execute, rate, attempts, iface


def fail(message):
    sys.stderr.write(f"scope: {message}\n")
    return 1


def load_scope(filename):
    try:
        with open(filename, encoding="utf-8") as file:
            manifest = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read scope file: {error}") from error

    required = (
        "scope_id",
        "option",
        "network",
        "interface",
        "maximum_rate_pps",
        "maximum_attempts",
    )
    if any(field not in manifest for field in required):
        raise ValueError("scope manifest is missing required fields")
    if manifest["option"] != "device-map":
        raise ValueError("scope manifest is not for Option A device mapping")

    try:
        network = ipaddress.ip_network(manifest["network"], strict=True)
    except ValueError as error:
        raise ValueError("scope network is not a valid CIDR") from error

    if network.version != 4 or network.prefixlen < 28:
        raise ValueError("scope network must be an IPv4 /28 or smaller")
    if manifest["maximum_rate_pps"] > 20:
        raise ValueError("scope maximum rate exceeds 20 probes per second")
    if manifest["maximum_attempts"] > 2:
        raise ValueError("scope maximum attempts exceeds 2")

    return manifest, network


def positive_integer(value, name):
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if result < 1:
        raise ValueError(f"{name} must be a positive integer")
    return result


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def execute_device_map(network, iface, rate, attempts, timeout):
    targets = [str(address) for address in network.hosts()]
    observations = {}
    packets = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        for target in targets
    ]

    for _ in range(attempts):
        answered, _ = srp(
            packets,
            iface=iface,
            inter=1.0 / rate,
            timeout=timeout,
            verbose=0,
        )

        for _, response in answered:
            address = response.psrc
            if address not in targets:
                continue

            device = observations.setdefault(
                address,
                {
                    "ip": address,
                    "mac": response.hwsrc,
                    "observation_count": 0,
                    "observation_times": [],
                },
            )
            device["observation_count"] += 1
            device["observation_times"].append(utc_now())

    devices = sorted(observations.values(), key=lambda item: item["ip"])
    not_observed = sorted(set(targets) - set(observations))
    return devices, not_observed


def resolve_options(scope_file, rate_arg, attempts_arg, iface_arg):
    try:
        manifest, network = load_scope(scope_file)
        rate = positive_integer(
            rate_arg or manifest["maximum_rate_pps"], "rate"
        )
        attempts = positive_integer(
            attempts_arg or manifest["maximum_attempts"], "attempts"
        )
    except ValueError as error:
        raise ValueError(str(error)) from error

    iface = iface_arg or manifest["interface"]
    if rate > 20 or rate > manifest["maximum_rate_pps"]:
        raise ValueError("rate exceeds the authorised limit")
    if attempts > 2 or attempts > manifest["maximum_attempts"]:
        raise ValueError("attempts exceeds the authorised limit")
    if iface != manifest["interface"]:
        raise ValueError("interface does not match the scope manifest")

    return manifest, network, iface, rate, attempts


def print_dryrun(manifest, network, iface, rate, attempts):
    print("DRY-RUN: no packets will be transmitted")
    print(f"scope: {manifest['scope_id']}")
    print(f"network: {network}")
    print(f"interface: {iface}")
    print(f"rate: {rate} probes per second")
    print(f"attempts: {attempts}")


def run_execution(manifest, network, iface, rate, attempts):
    start = utc_now()
    try:
        devices, not_observed = execute_device_map(
            network,
            iface,
            rate,
            attempts,
            manifest.get("timeout_seconds", 1.5),
        )
    except OSError as error:
        raise RuntimeError(f"execution failed: {error}") from error
    return start, utc_now(), devices, not_observed


def build_result(
    manifest,
    iface,
    rate,
    attempts,
    start,
    end,
    devices,
    not_observed,
):
    return {
        "schema": "wqe7002-device-map-result-v1",
        "scope_id": manifest["scope_id"],
        "option": "device-map",
        "utc_start": start,
        "utc_end": end,
        "parameters": {
            "interface": iface,
            "rate_pps": rate,
            "attempts": attempts,
            "timeout_seconds": manifest.get("timeout_seconds", 1.5),
        },
        "devices": devices,
        "not_observed": not_observed,
    }


def write_result(filename, result):
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=2, sort_keys=True)
            file.write("\n")
    except OSError as error:
        raise OSError(f"cannot write result: {error}") from error


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    scope_file, output, dryrun, execute, rate_arg, attempts_arg, iface_arg = parse(
        argv
    )

    try:
        manifest, network, iface, rate, attempts = resolve_options(
            scope_file,
            rate_arg,
            attempts_arg,
            iface_arg,
        )
    except ValueError as error:
        return fail(str(error))

    if dryrun:
        print_dryrun(manifest, network, iface, rate, attempts)
        return 0

    try:
        start, end, devices, not_observed = run_execution(
            manifest,
            network,
            iface,
            rate,
            attempts,
        )
    except RuntimeError as error:
        return fail(str(error))

    result = build_result(
        manifest,
        iface,
        rate,
        attempts,
        start,
        end,
        devices,
        not_observed,
    )

    try:
        write_result(output, result)
    except OSError as error:
        return fail(str(error))

    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
