import argparse
import asyncio
from time import sleep

from http_port_scanner import HttpPortScanner


async def main():
    args = parse_args()
    if args.command == "http_scan":
        print(
            f"Scanning '{args.target}', ports='{args.ports}' concurrency='{args.concurrent}' proxy='{args.proxy}' "
        )
        scanner = HttpPortScanner(
            target=args.target,
            ports=parse_int_list(args.ports),
            status_code_filter=parse_int_list(args.status_code_filter),
            concurrent=args.concurrent,
            proxy=args.proxy,
            method=args.method,
        )
        await scanner.run_scans()
    else:
        print(f"Unknown command {args.command}")
        exit(1)


def parse_args():
    parser = argparse.ArgumentParser(prog="scanops", description="ScanOps")
    subparsers = parser.add_subparsers(dest="command")

    http_scanner = subparsers.add_parser("http_scan", help="Scan ports")
    http_scanner.add_argument(
        "-t", "--target", required=True, help="Target IP/hostname to scan"
    )
    http_scanner.add_argument(
        "-p",
        "--ports",
        default="80,443,3000,3001,4200,5000,5173,8000,8008,8080,9000",
        help='Ports to scan (e.g. "80,443,8080" or "20-1000")',
    )
    http_scanner.add_argument(
        "-c", "--concurrent", type=int, default=4, help="Number of concurrent scans"
    )
    http_scanner.add_argument(
        "-m", "--method", type=str, default="HEAD", help="HTTP-verb to use for scanning"
    )
    http_scanner.add_argument(
        "-s",
        "--status-code-filter",
        type=str,
        default="",
        help='Allows filtering by status-code. Can be comma-separated, or a range (eg. "200,205" or "200-499")',
    )
    http_scanner.add_argument("--proxy", help='Proxy URL (e.g. "http://proxy:8080")')

    return parser.parse_args()


def parse_int_list(range_str) -> range | list[int]:
    if range_str == "":
        return []
    return [
        num
        for split in range_str.replace(" ", "").split(";")
        for num in _parse_int_list(split)
    ]


def _parse_int_list(range_str):
    if "-" in range_str:
        start, end = map(int, range_str.split("-"))
        return range(start, end + 1)
    elif "," in range_str:
        return [int(p) for p in range_str.split(",")]
    else:
        return [int(range_str)]


if __name__ == "__main__":
    asyncio.run(main())
