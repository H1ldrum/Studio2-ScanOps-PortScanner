from abc import ABC, abstractmethod
from typing import List


class Scanner(ABC):
    @abstractmethod
    def scan_port(self, port: int) -> bool | None:
        pass

    def scan_ports(self, ports: List[int]) -> List[int]:
        return []

    @abstractmethod
    def end(self) -> None:
        pass

    def has_multi_scan(self):
        return self.scan_ports.__qualname__ != "Scanner.scan_ports"
