from typing import Callable, List

from scapy.all import RandShort, conf, sr, sr1
from scapy.layers.inet import IP, TCP

from scanners.scanner import Scanner

conf.verb = 0

SYNACK = 0x12  # Set flag values for later reference
RSTACK = 0x14


class ScapyScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout

    async def scan_port(self, port: int) -> bool:
        srcport = RandShort()

        try:
            SYNACKpkt = sr1(
                IP(dst=self.host) / TCP(sport=srcport, dport=port, flags="S"),
                timeout=self.timeout,
            )

            if SYNACKpkt and SYNACKpkt.haslayer(TCP) and SYNACKpkt[TCP].flags == 0x12:
                return True
            return False

        finally:
            pass

    async def scan_ports(
        self, ports: List[int], update_progress: Callable[[str, int, bool | None], None]
    ):
        p = IP(dst=self.host) / TCP(dport=ports, flags="S")
        packetPairsWithAnswers, _ = sr(p, timeout=1)
        for req, resp in packetPairsWithAnswers:
            if not resp.haslayer(TCP):
                continue
            tcp = resp.getlayer(TCP)
            if tcp.flags == SYNACK:
                update_progress(self.host, tcp.sport, True)
            elif tcp.flags != RSTACK:
                update_progress(self.host, tcp.sport, False)
                print("unknown flag", tcp.flags, tcp.sport)
            update_progress(self.host, tcp.sport, None)

    async def end(self):
        print("end")
        pass
