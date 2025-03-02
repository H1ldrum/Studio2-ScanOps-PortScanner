import statistics
import subprocess
import time
from platform import platform
from typing import List, Optional, Tuple

"""
Uses the standard ping-call.
We should implement a ICMP-pinger, but it requires sudo
"""


class Pinger:
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
        command = ["ping", self.param, "1"]

        if timeout is not None:
            if self.system == "windows":
                command.append("-w")
                command.append(str(int(timeout * 1000)))
            else:
                command.append("-W")
                command.append(str(timeout))
        command.append(host)

        try:
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            is_up = result.returncode == 0

            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms

            if is_up and result.stdout:
                for line in result.stdout.splitlines():
                    if "time=" in line or "time<" in line:
                        try:
                            time_part = line.split("time=")[-1].split()[0].strip()
                            if "ms" in time_part:
                                time_part = time_part.replace("ms", "")
                            response_time = float(time_part)
                            break
                        except (ValueError, IndexError):
                            pass

            return is_up, response_time if is_up else None
        except Exception:
            return False, None

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
