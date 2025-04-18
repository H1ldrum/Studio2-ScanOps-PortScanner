import asyncio
from platform import platform

import prctl

from app_args import Args, parse_args
from network_mapping.ping import CmdPinger
from network_mapping.pinger import Pinger
from port_scanner import PortScanner
from reporters.cli_reporter import ConsoleReporter
from reporters.json_reporter import JsonReporter
from reporters.reporter import ScanReporter
from scanners.connect_scanner import ConnectScanner
from scanners.http_port_scanner import HttpPortScanner
from scanners.scanner import Scanner
from scanners.scapy_scanner import ScapyScanner
from scanners.tcp_scanner import TCPScanner


async def main():
    args = parse_args()
    reporter = createReporter(args)
    pinger = createPinger(args)

    def scanner(target):
        return createScanner(args, target)

    await PortScanner(args, reporter, pinger, scanner)


def createPinger(args) -> Pinger:
    # The ScapyPinger is really slow, for unknown reason
    # if canRunSynScan():
    #     return ScapyPinger()
    return CmdPinger()


def createScanner(args: Args, target: str) -> Scanner:
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
    if args.command == "connect_scan":
        return ConnectScanner(target, args.timeout_ms / 1000)
    if args.command == "syn_scan":
        return ScapyScanner(target, args.timeout_ms / 1000, args.max_retries)
    if args.command is None:
        if canRunSynScan():
            return ScapyScanner(target, args.timeout_ms / 1000)
        return ConnectScanner(target, args.timeout_ms / 1000)
    raise Exception(f"Unknown command {args.command}")


def createReporter(args: Args) -> ScanReporter | None:
    if args.reporter == "None":
        return None
    if args.reporter == "text":
        return ConsoleReporter(
            with_progress=args.with_progress,
            with_debug=args.with_debug,
            with_closed_ports=args.with_closed_ports_output,
        )
    if args.reporter == "json":
        return JsonReporter()


def canRunSynScan() -> bool | None:
    system = platform().lower()
    if "linux" in system:
        has_cap_net_raw = prctl.cap_effective.net_raw
        return has_cap_net_raw
    return None


if __name__ == "__main__":
    asyncio.run(main())
