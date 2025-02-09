from abc import ABC, abstractmethod
from typing import Dict, List

type Ports = List[int]


class ScanReporter(ABC):
    @abstractmethod
    def update_progress(self, current_port: int, is_open: bool | Exception) -> None:
        self.scanned_ports += 1
        if isinstance(is_open, Exception):
            error_name = is_open.__class__.__name__
            if error_name not in self.errors:
                self.errors[error_name] = []
            self.errors[error_name].append(current_port)
            # last_error = f"Last error {error_name} on {port}"
        elif is_open:
            self.open_ports.append(current_port)

    @abstractmethod
    def report_start(self, target: str, ports: Ports, extra: str = "") -> None:
        self.total_ports = len(ports)
        self.scanned_ports = 0
        self.open_ports: Ports = []
        self.errors: Dict[str, Ports] = {}
        print("foo started")
        pass

    @abstractmethod
    def report_final(self) -> None:
        pass


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
            # if error_name != "ClientConnectorError":
