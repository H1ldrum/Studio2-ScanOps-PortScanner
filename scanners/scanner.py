from abc import ABC, abstractmethod
from typing import List, Optional

from reporters.reporter import ScanReporter


class Scanner(ABC):
    @abstractmethod
    def scan_port(self, port: int) -> bool | None | str:
        """Scans a single port.

        To indicate the the port is open, return True, or use a string, which will be used as a banner.
        If providing a non-empty banner, no further attempts at banner grabbing will be performed.

        False indicates that the port is closed,
        None indicating that the port is filtered.
        """
        pass

    async def scan_ports(
        self, ports: List[int], reporter: ScanReporter, retries: Optional[int] = None
    ):
        """Scans multiple ports.

        The implementation must call reporter to update progress, and handle retries
        """
        return []

    @abstractmethod
    def end(self) -> None:
        pass

    def has_multi_scan(self):
        return self.scan_ports.__qualname__ != "Scanner.scan_ports"
