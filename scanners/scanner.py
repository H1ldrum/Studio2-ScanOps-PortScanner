from abc import ABC, abstractmethod


class Scanner(ABC):
    @abstractmethod
    def scan_port(self, port: int) -> None:
        pass

    @abstractmethod
    def end(self) -> None:
        pass
