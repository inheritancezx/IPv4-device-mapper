import ipaddress
import json
import sys
from datetime import datetime, timezone

from scapy.all import ARP, Ether, srp

TOOL_VERSION = "1.0.0"
EXPECTED_OPTION = "device-map"

PLACEHOLDER_WORDS = (
    "tbd", "todo", "changeme", "change_me", "replace", "placeholder",
    "xxx", "your_", "<", ">", "{{", "}}",
)


### ERROR HANDLING ###

def usage():
    sys.stderr.write(
        "Usage: mapper --scope file --output file "
        "[--dryrun | --execute] [--rate n] [--attempts n] [--iface name]\n"
    )
    raise SystemExit(1)

def fail(message):
    sys.stderr.write(f"mapper: {message}\n")
    return 1


### ARGS & SCOPE FILE PROPERTIES ###

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

def reject_placeholder(value, name):
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{name} must be a non-empty text value")
    
    lowered = value.strip().lower()

    for word in PLACEHOLDER_WORDS:
        if word in lowered:
            raise ValueError(f"{name} looks like a placeholder: {value!r}")


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

    for field in ("scope_id", "option", "network", "interface"):
        reject_placeholder(data[field], field)
    if data["option"] != EXPECTED_OPTION:
        raise ValueError(f"scope option must be {EXPECTED_OPTION!r}")

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


### DRYRUN OPTION ###

def print_dryrun(data, network, iface, rate, attempts):
    print("DRYRUN: no packets will be transmitted")
    print(f"tool version: {TOOL_VERSION}")
    print(f"scope: {data['scope_id']}")
    print(f"network: {network}")
    print(f"interface: {iface}")
    print(f"rate: {rate} probes per second")
    print(f"attempts: {attempts}")


### EXECUTE OPTION ###

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def record_reply(observations, reply, attempt):
    address = reply.psrc
    if address not in observations:
        observations[address] = {
            "ip": address,
            "mac": reply.hwsrc,
            "observation_count": 0,
            "observation_times": [],
            "conflicting_macs": [],
            "attempts_seen": [],
        }

    device = observations[address]
    if reply.hwsrc != device["mac"] and reply.hwsrc not in device["conflicting_macs"]:
        device["conflicting_macs"].append(reply.hwsrc)
        device["conflicting_macs"].sort()
    device["observation_count"] += 1
    device["observation_times"].append(utc_now())
    if attempt not in device["attempts_seen"]:
        device["attempts_seen"].append(attempt)


def is_relevant_reply(reply, target_set):
    return reply.op == 2 and reply.psrc in target_set


def execute_device_map(network, iface, rate, attempts, timeout):
    targets = [str(address) for address in network.hosts()]
    target_set = set(targets)  # using unique list
    observations = {}
    packets = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        for target in targets
    ]

    # knocking
    for attempt in range(1, attempts + 1):
        answered, unanswered = srp(
            packets, iface=iface, inter=1.0 / rate, timeout=timeout, verbose=0
        )

        for sent, reply in answered:
            if is_relevant_reply(reply, target_set):
                record_reply(observations, reply, attempt)

    # sort the IPs, then build the device list in that order
    devices = []
    for ip in sorted(observations, key=ipaddress.ip_address):
        devices.append(observations[ip])

    not_observed = sorted(target_set - set(observations))

    return devices, not_observed

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

# extension: retry analysis
def summarise_retry(devices, not_observed, attempts):
    targets = len(devices) + len(not_observed)

    found = 0
    for device in devices:
        earliest_round = device["attempts_seen"][0]
        if earliest_round == 1:
            found += 1

    found_after_retry = len(devices) - found
    probes_sent = targets * attempts

    return {
        "targets_probed": targets,
        "probes_sent": probes_sent,
        "devices_found": len(devices),
        "found_on_first_attempt": found,
        "found_only_after_retry": found_after_retry,
    }


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
        "tool_version": TOOL_VERSION,
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
        "retry_analysis": summarise_retry(devices, not_observed, attempts),
    }


def write_result(filename, result):
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=2)
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
    else:
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
