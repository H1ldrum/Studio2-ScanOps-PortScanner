import statistics
import time
from platform import platform
from typing import List, Optional, Tuple

from scapy.all import conf, sr1
from scapy.layers.inet import ICMP, IP

from network_mapping.pinger import Pinger

conf.verb = 0


class ScapyPinger(Pinger):
    def __init__(self) -> None:
        self.default_timeout = 1.0
        self.system = platform().lower()
        if self.system == "win32":
            self.system = "windows"
            self.param = "-n"
        else:
            self.param = "-c"

    def ping(self, host: str, timeout: Optional[float]) -> Tuple[bool, Optional[float]]:
        start_time = time.time()
        icmp = IP(dst=host) / ICMP()
        resp = sr1(icmp, timeout=timeout)
        print(f"ping? {host} {resp} {timeout}")
        if resp is None:
            return (False, None)
        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # Convert to ms
        return (True, response_time)

    def get_up_hosts(
        self,
        targets: List[str],
        timeout_factor: float = 2.0,
        min_timeout: float = 0.05,
        max_timeout: float = 5.0,
    ) -> List[str]:
        up_hosts = []
        response_times = []
        avg_response = 0
        adaptive_timeout = max(min_timeout, max_timeout / 2)

        # First pass: Try to ping all hosts with initial timeout
        for target in targets:
            current_timeout = adaptive_timeout
            is_up, response_time = self.ping(target, timeout=current_timeout)
            if not is_up:
                continue

            up_hosts.append(target)
            if response_time is None:
                continue
            response_times.append(response_time)
            avg_response = statistics.mean(response_times) / 1000.0
            adaptive_timeout = min(
                max(avg_response * timeout_factor, min_timeout), max_timeout
            )

        return up_hosts
