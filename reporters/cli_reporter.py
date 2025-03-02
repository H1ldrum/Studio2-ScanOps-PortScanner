import shutil
from typing import List

from reporters.reporter import ScanReporter


class ConsoleReporter(ScanReporter):
    def __init__(self) -> None:
        self.width = shutil.get_terminal_size()[0]
        super().__init__()

    def limit_output(self, text, prefix="", suffix="", end="", flush=False):
        free_length = self.width - len(prefix) - len(suffix)
        print(f"{prefix}{text[:free_length]}{suffix}", end=end, flush=flush)

    def _update_progress_abstract(
        self, target, current_port: int, is_open: bool | Exception
    ) -> None:
        # super().update_progress(target, current_port, is_open)
        self.limit_output(
            f"\rScanning: {self.scanned_ports}/{self.total_ports} ports | Open: {len(self.open_ports)} {self.last_error}",
            end="",
            flush=True,
        )

    def _report_start_abstract(
        self, target: str, ports: List[int], prefix="", suffix: str = ""
    ) -> None:
        # super().report_start(target, ports, prefix, suffix)
        print(f"{prefix}Starting scan on {target} for {len(ports)} ports {suffix}")

    def _report_final_abstract(self, time_taken) -> None:
        print(f"\rCompleted scan in {time_taken:.3f}s\n", end="", flush=True)
        for target in self.open_ports:
            open_ports = self.open_ports[target]
            print(
                f"Found {len(open_ports)} open ports on {target}: {print_compact_list_of_ints(open_ports)}"
            )
        if len(self.errors) > 0:
            total = sum(len(v) for v in self.errors.values())
            print(
                f"Additionally, these {len(self.errors)} unique errors occured, which may indicate open non-http-ports (a total of {total})"
            )
            for error_name, ports in self.errors.items():
                print(
                    f"\t Error {error_name} occurred on ports: {print_compact_list_of_ints(ports)}"
                )


def print_compact_list_of_ints(numbers: list[int]) -> str:
    if not numbers:
        return "[]"

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

    width = shutil.get_terminal_size()[0]
    result = f"[{', '.join(ranges)}]"
    return result[:width]
