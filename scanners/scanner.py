from abc import ABC, abstractmethod


class Scanner(ABC):
    @abstractmethod
    def scan_port(port: int) -> None:
        pass
