import asyncio
import math
import time
from time import perf_counter
from typing import Callable

from app_args import Args
from network_mapping.pinger import Pinger
from reporters.cli_reporter import stringify_compact_list_of_ints
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
        reporter.info(f"Ports to scan: {stringify_compact_list_of_ints(args.ports)}")
    targets: list[str] = args.target

    if not args.disable_host_discover:
        count = len(targets)
        reporter.info(f"Checking if {count} targets are up")
        targets = pinger.get_up_hosts(targets, max_timeout=args.timeout_ms / 1000)
        reporter.report_up_targets(targets)
        reporter.info(f"{len(targets)}/{count} targets are up")

    if args.list_targets:
        reporter.info(f"targets to scan: \n{'\n'.join(targets)}")
    if args.list_ports or args.list_targets:
        exit(0)

    reporter.info(f"Scanning {len(targets)} targets")
    tasks = []
    endTasks = []
    if len(args.ports) == 0:
        reporter.report_final(0)
        return
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

            async def scan_and_collect_multi(
                chunk, total_chunks, ports, target, scanner
            ):
                async with semaphore:
                    await scanner.scan_ports(ports, reporter)
                    if args.with_progress:
                        reporter.debug(f"completed chunk {chunk + 1}/{total_chunks}")

            n = len(tasks)
            total_chunks = math.ceil(len(args.ports) / args.concurrent)
            i = 0
            for ports in chunks(list(args.ports), args.concurrent):
                tasks.append(
                    scan_and_collect_multi(i, total_chunks, ports, target, scanner)
                )
                i += 1
            reporter.debug(
                f"Chunking {len(args.ports)} port-scans into {total_chunks} tasks due to concurrency={args.concurrent}"
            )
        else:

            async def scan_and_collect(port, target, scanner):
                async with semaphore:
                    portStatus = None
                    # portStatus = await scanner.scan_port(port)
                    response_time_ms = 0.0
                    retries = args.max_retries
                    while portStatus is None and retries >= 0:
                        retries = retries - 1
                        start = time.perf_counter()
                        portStatus = await scanner.scan_port(port)
                        end = time.perf_counter()
                        response_time_ms = (end - start) * 1000

                    if reporter:
                        reporter.update_progress(
                            target, port, response_time_ms, portStatus
                        )
                    return portStatus

            for p in args.ports:
                tasks.append(scan_and_collect(p, target, scanner))
        endTasks.append(scanner.end)

    start = perf_counter()
    reporter.debug(f"waiting for {len(tasks)} tasks")
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
