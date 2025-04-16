import asyncio
from time import perf_counter
from typing import Callable

from app_args import Args
from network_mapping.pinger import Pinger
from reporters.cli_reporter import print_compact_list_of_ints
from reporters.reporter import ScanReporter
from scanners.scanner import Scanner


async def PortScanner(
    args: Args,
    reporter: ScanReporter | None,  # noqa: F821
    pinger: Pinger,
    scannerfunc: Callable[[str], Scanner],
):
    # args = parse_args()
    if args.list_ports:
        print(f"Ports to scan: {print_compact_list_of_ints(args.ports)}")
    targets: list[str] = args.target

    if not args.disable_host_discover:
        count = len(targets)
        print(f"Checking if {count} targets are up")
        targets = pinger.get_up_hosts(targets, max_timeout=args.timeout_ms / 1000)
        print(f"{len(targets)}/{count} targets are up")

    if args.list_targets:
        print(f"targets to scan: \n{'\n'.join(targets)}")
        exit(0)

    print(f"Scanning {len(targets)} targets")
    tasks = []
    endTasks = []
    for target in targets:
        scanner = scannerfunc(target)
        if reporter:
            reporter.report_start(
                target,
                args.ports,
                prefix=type(scanner).__name__ + " ",
                suffix=f"concurrency={args.concurrent} timeout={args.timeout_ms}ms",
            )

        semaphore = asyncio.Semaphore(args.concurrent)

        if scanner.has_multi_scan():

            async def scan_and_collect_multi(ports, target, scanner):
                async with semaphore:
                    open_ports = await scanner.scan_ports(ports, reporter)

            n = len(tasks)
            for ports in chunks(list(args.ports), args.concurrent):
                tasks.append(scan_and_collect_multi(ports, target, scanner))
            print(
                f"Chunking {len(args.ports)} port-scans into {len(tasks) - n} tasks due to concurrency={args.concurrent}"
            )
        else:

            async def scan_and_collect(port, target, scanner):
                async with semaphore:
                    is_open = await scanner.scan_port(port)
                    if reporter:
                        reporter.update_progress(target, port, is_open)
                    return is_open

            for p in args.ports:
                tasks.append(scan_and_collect(p, target, scanner))
        endTasks.append(scanner.end)

    start = perf_counter()
    print(f"waiting for {len(tasks)} tasks")
    await asyncio.gather(*tasks)
    elapsed = perf_counter() - start
    for t in endTasks:
        await t()

    if reporter:
        reporter.report_final(elapsed)


def chunks(items, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(items), n):
        yield items[i : i + n]
