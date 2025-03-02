import threading
from abc import ABC, abstractmethod
from typing import Dict, List

# Define Ports type
Ports = List[int]


class ScanReporter(ABC):
    def __init__(self):
        # Initialize lock for thread safety
        self._lock = threading.RLock()

        self.total_ports = 0
        self.scanned_ports = 0
        self.last_error = ""
        self.open_ports: Dict[str, Ports] = {}
        self.errors: Dict[str, Ports] = {}

    def update_progress(
        self, target: str, current_port: int, is_open: bool | Exception
    ) -> None:
        with self._lock:
            self.scanned_ports += 1

            if isinstance(is_open, Exception):
                error_name = is_open.__class__.__name__
                if error_name not in self.errors:
                    self.errors[error_name] = []
                self.errors[error_name].append(current_port)
                self.last_error = f"Last error {error_name} on {current_port}"
            elif is_open:
                self.open_ports[target].append(current_port)

            # Call the abstract implementation within the lock
            self._update_progress_abstract(target, current_port, is_open)

    def report_start(
        self, target: str, ports: Ports, prefix="", suffix: str = ""
    ) -> None:
        with self._lock:
            self.total_ports += len(ports)
            self.scanned_ports = 0
            self.last_error = ""
            self.open_ports[target] = []
            self.errors = {}

            self._report_start_abstract(target, ports, prefix, suffix)

    def report_final(self, time_taken) -> None:
        with self._lock:
            self._report_final_abstract(time_taken)

    @abstractmethod
    def _update_progress_abstract(
        self, target: str, current_port: int, is_open: bool | Exception
    ) -> None:
        pass

    @abstractmethod
    def _report_start_abstract(
        self, target: str, ports: Ports, prefix="", suffix: str = ""
    ) -> None:
        pass

    @abstractmethod
    def _report_final_abstract(self, time_taken) -> None:
        pass
