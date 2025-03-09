from abc import ABC, abstractmethod
from typing import List


class Pinger(ABC):
    @abstractmethod
    def get_up_hosts(
        self,
        targets: List[str],
        timeout_factor: float = 2.0,
        min_timeout: float = 0.05,
        max_timeout: float = 5.0,
    ) -> List[str]:
        pass
