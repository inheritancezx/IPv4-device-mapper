import ipaddress
import json
import sys
from datetime import datetime, timezone

from scapy.all import ARP, Ether, srp


def usage():
    sys.stderr.write(
        "Usage: mapper --scope file --output file "
        "[--dryrun | --execute] [--rate n] [--attempts n] [--iface name]\n"
    )
    raise SystemExit(1)

def fail(message):
    sys.stderr.write(f"mapper: {message}\n")
    return 1

def take_value(args, index, flag):
    if index >= len(args) or args[index] != flag:
        usage()
    index += 1
    if index >= len(args) or args[index] == "":
        usage()
    return args[index], index + 1 

def parse(argv):
    args = list(argv)
    index = 0

    scope, index = take_value(args, index, "--scope")
    output, index = take_value(args, index, "--output")

    if index >= len(args) or args[index] not in ("--dryrun", "--execute"):
        usage()
    dryrun = args[index] == "--dryrun"
    execute = not dryrun
    index += 1

    # optional flags
    optional = {"--rate": None, "--attempts": None, "--iface": None}
    while index < len(args):
        flag = args[index]
        if flag not in optional or optional[flag] is not None:
            usage()  # unknown flag or duplicate
        optional[flag], index = take_value(args, index, flag)

    return (scope, output, dryrun, execute,
            optional["--rate"], optional["--attempts"], optional["--iface"])


def positive_integer(value, name):
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if result < 1:
        raise ValueError(f"{name} must be a positive integer")
    return result

def load_scope(filename):
    try:
        with open(filename, encoding="utf-8") as file:
            data = json.load(file)
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
    for field in required:
        if field not in data:
            raise ValueError(f"scope data is missing required field: {field}")

    try:
        network = ipaddress.ip_network(data["network"], strict=True)
    except ValueError as error:
        raise ValueError("scope network is not a valid CIDR") from error
    if network.version != 4 or network.prefixlen < 28:
        raise ValueError("network scope must be an IPv4 /28 or smaller")

    data["maximum_rate_pps"] = positive_integer(data["maximum_rate_pps"], "maximum_rate_pps")
    data["maximum_attempts"] = positive_integer(data["maximum_attempts"], "maximum_attempts")

    if data["maximum_rate_pps"] > 20:
        raise ValueError("rate exceeds 20 probes per second")
    if data["maximum_attempts"] > 2:
        raise ValueError("maximum attempts exceeds 2")

    return data, network

def load_args(scope_file, rate_arg, attempts_arg, iface_arg):
    data, network = load_scope(scope_file)

    if rate_arg is None:
        rate = data["maximum_rate_pps"]
    else:
        rate = positive_integer(rate_arg, "rate")

    if attempts_arg is None:
        attempts = data["maximum_attempts"]
    else:
        attempts = positive_integer(attempts_arg, "attempts")

    if iface_arg is None:
        iface = data["interface"]
    else:
        iface = iface_arg

    if rate > data["maximum_rate_pps"]:
        raise ValueError("rate exceeds the authorised limit")
    if attempts > data["maximum_attempts"]:
        raise ValueError("attempts exceeds the authorised limit")
    if iface != data["interface"]:
        raise ValueError("interface does not match the scope data")

    return data, network, iface, rate, attempts


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


def print_dryrun(data, network, iface, rate, attempts):
    print("DRY-RUN: no packets will be transmitted")
    print(f"scope: {data['scope_id']}")
    print(f"network: {network}")
    print(f"interface: {iface}")
    print(f"rate: {rate} probes per second")
    print(f"attempts: {attempts}")


def run_execution(data, network, iface, rate, attempts):
    start = utc_now()
    try:
        devices, not_observed = execute_device_map(
            network,
            iface,
            rate,
            attempts,
            data.get("timeout_seconds", 1.5),
        )
    except OSError as error:
        raise RuntimeError(f"execution failed: {error}") from error
    return start, utc_now(), devices, not_observed


def build_result(
    data,
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
        "scope_id": data["scope_id"],
        "option": "device-map",
        "utc_start": start,
        "utc_end": end,
        "parameters": {
            "interface": iface,
            "rate_pps": rate,
            "attempts": attempts,
            "timeout_seconds": data.get("timeout_seconds", 1.5),
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
        data, network, iface, rate, attempts = load_args(
            scope_file,
            rate_arg,
            attempts_arg,
            iface_arg,
        )
    except ValueError as error:
        return fail(str(error))

    if dryrun:
        print_dryrun(data, network, iface, rate, attempts)
        return 0

    try:
        start, end, devices, not_observed = run_execution(
            data,
            network,
            iface,
            rate,
            attempts,
        )
    except RuntimeError as error:
        return fail(str(error))

    result = build_result(
        data,
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