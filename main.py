import argparse
import asyncio
from time import perf_counter
from typing import OrderedDict

from network_mapping.ping import Pinger
from network_mapping.utils import parse_cidr_to_ip_list
from reporters.cli_reporter import ConsoleReporter, print_compact_list_of_ints
from reporters.json_reporter import JsonReporter
from reporters.reporter import ScanReporter
from scanners.http_port_scanner import HttpPortScanner
from scanners.scanner import Scanner

# from scanners.scapy_scanner import ScapyScanner
from scanners.socket_scanner import SocketScanner
from scanners.tcp_scanner import TCPScanner


async def main():
    args = parse_args()
    if args.list_ports:
        print(f"Ports to scan: {print_compact_list_of_ints(args.ports)}")
    if (
        args.command == "http_scan"
        or args.command == "tcp_scan"
        or args.command == "socket_scan"
        # or args.command == "scapy_scan"
    ):
        targets: list[str] = args.target

        if not args.disable_host_discover:
            count = len(targets)
            print(f"Checking if {count} targets are up")
            targets = Pinger().get_up_hosts(targets)
            print(f"{len(targets)}/{count} targets are up")

        if args.list_targets:
            print(f"targets to scan: \n{'\n'.join(targets)}")
            exit(0)

        print(f"Scanning {len(targets)} targets")
        tasks = []
        reporter = createReporter(args)
        for target in targets:
            scanner = createScanner(args, target)
            if reporter:
                reporter.report_start(
                    target,
                    args.ports,
                    prefix=type(scanner).__name__ + " ",
                    suffix=f"concurrency={args.concurrent} timeout={args.timeout_ms}ms",
                )

            semaphore = asyncio.Semaphore(args.concurrent)

            async def scan_and_collect(port, target, scanner):
                async with semaphore:
                    is_open = await scanner.scan_port(port)
                    if reporter:
                        reporter.update_progress(target, port, is_open)
                    return is_open

            for p in args.ports:
                tasks.append(scan_and_collect(p, target, scanner))

        start = perf_counter()
        print(f"waiting for {len(tasks)} tasks")
        await asyncio.gather(*tasks)
        elapsed = perf_counter() - start

        if reporter:
            reporter.report_final(elapsed)
    else:
        print(f"Unknown command {args.command}")
        exit(1)


commonPorts = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3000: "dev",
    3001: "dev-alt",
    3389: "rdp",
    4200: "angular",
    5000: "flask",
    5173: "vite",
    8000: "http-alt",
    8008: "http-proxy",
    8080: "http-proxy",
    9000: "portainer",
}


def createScanner(args, target: str) -> Scanner:
    if args.command == "http_scan":
        return HttpPortScanner(
            target=target,
            timeout_ms=args.timeout_ms,
            status_code_filter=args.status_code_filter,
            status_code_ignore_filter=args.status_code_ignore_filter,
            proxy=args.proxy,
            method=args.method,
        )
    if args.command == "tcp_scan":
        return TCPScanner(target, args.timeout_ms / 1000)
    # if args.command == "scapy_scan":
    #     return ScapyScanner(target, args.timeout_ms / 1000)
    return SocketScanner(target, args.timeout_ms / 1000)


def createReporter(args) -> ScanReporter | None:
    if args.reporter == "None":
        return None
    if args.reporter == "text":
        return ConsoleReporter()
    if args.reporter == "json":
        return JsonReporter()


def parse_args():
    parser = argparse.ArgumentParser(prog="scanops", description="ScanOps")
    subparsers = parser.add_subparsers(dest="command")

    http_scanner = subparsers.add_parser("http_scan", help="Scan ports over HTTP")
    subparsers.add_parser("tcp_scan", help="Scan ports over TCP")
    subparsers.add_parser("scapy_scan", help="Scan ports over TCP")
    subparsers.add_parser("socket_scan", help="Scan ports using sockets")
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP/hostname to scan",
        type=parse_target_list,
    )
    parser.add_argument(
        "-Pn",
        "--disable-host-discover",
        default=False,
        action="store_true",
        help="If set, will disable port-scanning",
        # type=bool,
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=commonPorts.keys(),
        help='Ports to scan (e.g. "80,443,8080" or "20-1000")',
        type=parse_int_list,
    )
    parser.add_argument(
        "-c", "--concurrent", type=int, default=50, help="Number of concurrent scans"
    )
    parser.add_argument(
        "--list-ports",
        action=argparse.BooleanOptionalAction,
        help="Prints the ports supplied",
    )
    parser.add_argument(
        "--list-targets",
        action=argparse.BooleanOptionalAction,
        help="Prints the targets supplied",
    )
    parser.add_argument(
        "-", "--timeout_ms", type=int, default=3000, help="Timeout in ms."
    )
    parser.add_argument(
        "--reporter", default="text", help="json, None or text (default)"
    )

    http_scanner.add_argument(
        "-m", "--method", type=str, default="HEAD", help="HTTP-verb to use for scanning"
    )
    http_scanner.add_argument(
        "-s",
        "--status-code-filter",
        default="",
        help='Allows limiting ports considered open to only those defined here. Can be comma-separated, or a range (eg. "200,205" or "200-499")',
        type=parse_int_list,
    )
    http_scanner.add_argument(
        "-S",
        "--status-code-ignore-filter",
        default="",
        help='Allows limiting ports considered open to only those NOT defined here. Can be comma-separated, or a range (eg. "200,205" or "200-499")',
        type=parse_int_list,
    )
    http_scanner.add_argument("--proxy", help='Proxy URL (e.g. "http://proxy:8080")')

    return parser.parse_args()


def parse_target_list(range_str) -> list[str]:
    if range_str == "":
        return []
    target_input = _parse_target_list(range_str.replace(" ", ""))
    return list(
        # remove deuplicates
        OrderedDict.fromkeys(
            ip for cidr in target_input for ip in parse_cidr_to_ip_list(cidr)
        )
    )


def _parse_target_list(range_str) -> list[str]:
    if range_str == "":
        return []
    if "," in range_str:
        return [x for p in range_str.split(",") for x in _parse_target_list(p)]
    elif "-" in range_str:
        startWithPrefix, endStr = map(str, range_str.split("-"))
        prefix, startStr = startWithPrefix.rsplit(".", 1)
        start = int(startStr)
        end = int(endStr) + 1

        return [prefix + "." + str(x) for x in range(start, end)]

    else:
        return [range_str]


def parse_int_list(range_str) -> list[int]:
    if range_str == "":
        return []
    if range_str == "-":
        return list(range(0, 65535))
    return _parse_int_list(range_str.replace(" ", ""))


def _parse_int_list(range_str) -> list[int]:
    if range_str == "":
        return []
    if "," in range_str:
        return [
            portInRange(x) for p in range_str.split(",") for x in _parse_int_list(p)
        ]
    elif "-" in range_str:
        start, end = map(int, range_str.split("-"))
        portInRange(start)
        portInRange(end + 1)
        return list(range(start, end + 1))

    else:
        return [portInRange(int(range_str))]


def portInRange(port: int):
    if port < 0:
        raise ValueError(f"value cannot be below zero, received {port}")
    if port > 65535:
        raise ValueError(f"value cannot be below above 65535, received {port}")
    return port


if __name__ == "__main__":
    asyncio.run(main())
