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
            self.last_error = f"Last error {error_name} on {current_port}"
        elif is_open:
            self.open_ports.append(current_port)

    @abstractmethod
    def report_start(self, target: str, ports: Ports, extra: str = "") -> None:
        self.total_ports = len(ports)
        self.scanned_ports = 0
        self.last_error = ""
        self.open_ports: Ports = []
        self.errors: Dict[str, Ports] = {}
        pass

    @abstractmethod
    def report_final(self) -> None:
        pass
