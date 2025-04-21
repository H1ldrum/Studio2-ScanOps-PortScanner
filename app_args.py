import argparse
import os
from dataclasses import dataclass, field
from email.policy import default
from socket import gethostbyname
from sys import stderr
from typing import List, Optional, OrderedDict

from network_mapping.utils import parse_cidr_to_ip_list


@dataclass
class Args:
    # Common arguments
    command: Optional[str] = None
    os_detection: bool = False
    target: List[str] = field(default_factory=list)
    disable_host_discover: bool = False
    ports: list[int] = field(default_factory=list)
    concurrent: int = 50
    max_retries: int = 3
    list_ports: bool = False
    list_targets: bool = False
    with_progress: bool = True
    with_banner_extraction: bool = True
    with_debug: bool = True
    with_closed_ports_output: bool = True
    timeout_ms: int = 1000
    reporter: str = "text"

    # HTTP scanner specific arguments
    method: Optional[str] = None
    status_code_filter: list[int] = field(default_factory=list)
    status_code_ignore_filter: list[int] = field(default_factory=list)
    proxy: Optional[str] = None


commonPorts = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "rcp",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
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


def parse_args() -> Args:
    parser = argparse.ArgumentParser(prog="scanops", description="ScanOps")
    subparsers = parser.add_subparsers(dest="command")

    http_scanner = subparsers.add_parser("http_scan", help="Scan ports over HTTP")
    subparsers.add_parser("tcp_scan", help="Scan ports over TCP")
    subparsers.add_parser("connect_scan", help="Scan ports using connect")
    subparsers.add_parser("syn_scan", help="Scan ports using SYN (stealth, half-open)")
    subparsers.add_parser("socket_scan", help="Scan ports using sockets")
    parser.add_argument(
        "-o"  # Same as with nmap
        "--os-detection",  # Possible shortname if needed
        action="store_true",
        help="Enable OS detection based on TTL values",
    )
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
        "--progress",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Hides progress-output",
    )
    parser.add_argument(
        "--extract-banner",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="extract banners from open ports",
    )
    parser.add_argument(
        "--debug",
        default=False,
        action=argparse.BooleanOptionalAction,
        help="Adds debug-information",
    )
    parser.add_argument(
        "--closed-ports-output",
        default=False,
        action=argparse.BooleanOptionalAction,
        help="Hides closed ports from output",
    )
    parser.add_argument(
        "--list-targets",
        action=argparse.BooleanOptionalAction,
        help="Prints the targets supplied",
    )
    parser.add_argument(
        "-", "--timeout_ms", type=int, default=1000, help="Timeout in ms."
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="For unanswered ports (timeouts), we can retry to confirm. An ananswered port is considered filtered if it never receives a reply on any of the retries",
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
    http_scanner.add_argument(
        "--proxy", help='Proxy URL (e.g. "http://proxy:8080") Only for HTTP-scanner'
    )

    args_namespace = parser.parse_args()

    args = Args(
        command=args_namespace.command,
        os_detection=getattr(args_namespace, "os_detection", False),
        target=args_namespace.target,
        disable_host_discover=args_namespace.disable_host_discover,
        ports=args_namespace.ports,
        concurrent=args_namespace.concurrent,
        with_progress=getattr(args_namespace, "progress", True),
        with_debug=getattr(args_namespace, "debug", False),
        with_banner_extraction=getattr(args_namespace, "extract_banner", False),
        with_closed_ports_output=getattr(args_namespace, "closed_ports_output", True),
        list_ports=getattr(args_namespace, "list_ports", False),
        list_targets=getattr(args_namespace, "list_targets", False),
        timeout_ms=getattr(args_namespace, "timeout_ms", 1000),
        reporter=args_namespace.reporter,
    )
    if args.command == "http_scan":
        args.method = getattr(args_namespace, "method", "HEAD")
        args.status_code_filter = getattr(args_namespace, "status_code_filter", list())
        args.status_code_ignore_filter = getattr(
            args_namespace, "status_code_ignore_filter", list()
        )
        args.proxy = getattr(args_namespace, "proxy", None)

    return args


def parse_target_list(range_str) -> list[str]:
    if range_str == "":
        return []
    target_input = _parse_target_list(range_str.replace(" ", ""))
    return list(
        # remove deuplicates
        OrderedDict.fromkeys(
            ip for cidr in target_input for ip in parse_cidr_to_ip_list(to_ip(cidr))
        )
    )


def to_ip(iporhostname: str) -> str:
    try:
        ip = gethostbyname(iporhostname)
        if ip != iporhostname:
            print(f"{iporhostname} resolved to {ip}", file=stderr)
        return ip
    except:  # noqa: E722
        return iporhostname


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
        return list(range(1, 65536))
    port_list = _parse_int_list(range_str.replace(" ", ""))
    return list(set(port_list))


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
        portInRange(end)
        return list(range(start, end + 1))

    else:
        return [portInRange(int(range_str))]


def portInRange(port: int):
    if port == 0:
        print(
            "Warning, port 0 is normally reserved by the OS, and typically cannot be assigned. Consider excluding it from the specified ports.",
            file=stderr,
        )
    if port < 0:
        raise ValueError(f"value cannot be below zero, received {port}")
    if port > 65535:
        raise ValueError(f"value cannot be below above 65535, received {port}")
    return port
