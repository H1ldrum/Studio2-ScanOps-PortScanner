import argparse
import asyncio

from portscanner import PortScanner


def parse_args():
    parser = argparse.ArgumentParser(prog="scanops", description="ScanOps")
    subparsers = parser.add_subparsers(dest="command")

    scanner = subparsers.add_parser("scan", help="Scan ports")
    scanner.add_argument(
        "-t", "--target", required=True, help="Target IP/hostname to scan"
    )
    scanner.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help='Ports to scan (e.g. "80,443,8080" or "20-1000")',
    )
    scanner.add_argument(
        "-c", "--concurrent", type=int, default=4, help="Number of concurrent scans"
    )
    scanner.add_argument(
        "-m", "--method", type=str, default="HEAD", help="HTTP-verb to use for scanning"
    )
    scanner.add_argument("--proxy", help='Proxy URL (e.g. "http://proxy:8080")')

    return parser.parse_args()


async def main():
    args = parse_args()
    print(args.command)
    if args.command == "scan":
        print(
            f"Scanning '{args.target}', ports='{args.ports}' concurrency='{args.concurrent}' proxy='{args.proxy}' "
        )
        scanner = PortScanner(
            target=args.target,
            ports=args.ports,
            concurrent=args.concurrent,
            proxy=args.proxy,
            method=args.method,
        )
        await scanner.run_scans()


if __name__ == "__main__":
    asyncio.run(main())
