from typing import List

from reporter import ScanReporter


class ConsoleReporter(ScanReporter):
    def __init__(self) -> None:
        super().__init__()

    def update_progress(self, current_port: int, is_open: bool | Exception) -> None:
        super().update_progress(current_port, is_open)
        print(
            f"\rScanning: {self.scanned_ports}/{self.total_ports} ports | Open: {len(self.open_ports)}",
            end="",
            flush=True,
        )

    def report_start(self, target: str, ports: List[int], extra: str = "") -> None:
        super().report_start(target, ports, extra)
        print(f"Starting scan on {target} {self.total_ports}{extra}")

    def report_final(self) -> None:
        print(f"\rFound {len(self.open_ports)} open ports: {sorted(self.open_ports)}")
        for error_name, ports in self.errors.items():
            print(f"Error {error_name} occurred on ports: {sorted(ports)}")
