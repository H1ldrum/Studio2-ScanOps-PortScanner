import shutil
from sys import stderr, stdout
from typing import List

from osdetection.osdetect import OSDetector
from reporters.reporter import ScanReporter


class ConsoleReporter(ScanReporter):
    def __init__(self, with_progress=True, with_closed_ports=True) -> None:
        self.width = shutil.get_terminal_size()[0]
        self.with_progress = with_progress
        self.with_closed_ports = with_closed_ports
        super().__init__()

    def limit_output(
        self, text, prefix="", suffix="", end="", flush=False, file=stderr
    ):
        free_length = self.width - len(prefix) - len(suffix)
        print(f"{prefix}{text[:free_length]}{suffix}", end=end, flush=flush, file=file)

    def _update_progress_abstract(
        self, target, current_port: int, is_open: bool | Exception | None
    ) -> None:
        if not self.with_progress:
            return
        # super().update_progress(target, current_port, is_open)
        total_open = sum(
            len(list_of_ports) for list_of_ports in self.open_ports.values()
        )
        self.limit_output(
            f"\rScanning: {self.scanned_ports}/{self.total_ports} ports | Open: {total_open} last_error={self.last_error}",
            end="",
            flush=True,
        )

    def _report_start_abstract(
        self, target: str, ports: List[int], prefix="", suffix: str = ""
    ) -> None:
        # super().report_start(target, ports, prefix, suffix)
        self.debug(
            f"{prefix}Starting scan on {target} for {len(ports)} ports. {suffix}. Ports: {stringify_compact_list_of_ints(ports)}"
        )

    def _report_final_abstract(self, time_taken) -> None:
        self.limit_output(
            f"\rCompleted scan of {len(self.open_ports)} targets with {self.scanned_ports} total ports scanned in in {time_taken:.3f}s\n",
            end="",
            flush=True,
            file=stdout,
        )
        for target in self.open_ports:
            ports = self.open_ports[target]
            with_banners = {k: v for k, v in ports.items() if v}
            if with_banners:
                print("Found ports with banners:")
                for key, value in with_banners.items():
                    print(f"  {key}: {value}")
            print(
                f"Found {len(ports)} open ports on {target}: {stringify_compact_list_of_ints(list(ports.keys()))}"
            )
        for target in self.filtered_ports:
            ports = self.filtered_ports[target]
            print(
                f"Found {len(ports)} filtered ports on {target}: {stringify_compact_list_of_ints(ports)}"
            )
        for target in self.closed_ports:
            ports = self.closed_ports[target]
            print(
                f"Found {len(ports)} closed ports on {target}: {stringify_compact_list_of_ints(ports)}"
            )
        if len(self.errors) > 0:
            total = sum(len(v) for v in self.errors.values())
            print(
                f"Additionally, these {len(self.errors)} unique errors occured, which may indicate open non-http-ports (a total of {total})"
            )
            for error_name, ports in self.errors.items():
                print(
                    f"\t Error {error_name} occurred on ports: {stringify_compact_list_of_ints(ports)}"
                )
        if self.ttls:
            for target, ttls in self.ttls.items():
                detected_os_list = [
                    f"{OSDetector.lookup_os_from_ttl(ttl)} ({ttl})" for ttl in ttls
                ]
                print(
                    f"Based on ttl-values, it looks like the target {target} could be one of: {detected_os_list}"
                )

    def debug(self, string) -> None:
        print("DEBUG", string, file=stderr, flush=True)

    def info(self, string) -> None:
        print("info", string, file=stderr, flush=True)


def compact_list_of_ints(numbers: list[int]) -> list[int]:
    if not numbers:
        return []

    numbers = sorted(numbers)
    ranges = []
    start = numbers[0]
    prev: int = start

    for n in numbers[1:] + [-1]:
        if n != prev + 1:
            if start == prev:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{prev}")
            start = n
        prev = n

        "".join(ranges)
    return ranges


def stringify_compact_list_of_ints(numbers: list[int]) -> str:
    ranges = compact_list_of_ints(numbers)
    result = f"[{', '.join(ranges)}]"
    return result
    width = shutil.get_terminal_size()[0]
    return result[:width]
