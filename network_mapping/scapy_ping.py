import concurrent.futures
import statistics
import time
from platform import platform
from typing import List, Optional, Tuple

from scapy.all import conf, sr1
from scapy.layers.inet import ICMP, IP

from network_mapping.pinger import Pinger

conf.verb = 0


class ScapyPinger(Pinger):
    def ping(self, host: str, timeout: Optional[float]) -> Tuple[bool, Optional[float], str]:
        start_time = time.time()
        icmp = IP(dst=host) / ICMP()
        resp = sr1(icmp, timeout=timeout)
        if resp is None:
            return (False, None, host)
        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # Convert to ms
        return (True, response_time, host)

    def get_up_hosts(
        self,
        targets: List[str],
        timeout_factor: float = 2.0,
        min_timeout: float = 0.05,
        max_timeout: float = 5.0,
    ) -> List[str]:
        up_hosts = []
        workers = 100
        response_times = []
        avg_response = 0

        adaptive_timeout = max(min_timeout, max_timeout / 2)

        # Run ping operations in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all ping tasks
            futures = [executor.submit(self.ping, target, adaptive_timeout) for target in targets]

            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                is_up, response_time, host = future.result()
                if is_up:
                    up_hosts.append(host)
                    if response_time is not None:
                        response_times.append(response_time)
                        if response_times:
                            # Update adaptive timeout for remaining tasks
                            avg_response = statistics.mean(response_times) / 1000.0
                            adaptive_timeout = min(
                                max(avg_response * timeout_factor, min_timeout), max_timeout
                            )

        return up_hosts
