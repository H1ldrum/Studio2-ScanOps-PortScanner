from typing import Callable, List

from scapy.all import RandShort, conf, sr, sr1
from scapy.layers.inet import IP, TCP

from reporters.reporter import ScanReporter
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

    async def scan_ports(self, ports: List[int], reporter: ScanReporter):
        p = IP(dst=self.host) / TCP(dport=ports, flags="S")
        packetPairsWithAnswers, packetPairsWithoutAnswers = sr(p, timeout=self.timeout)
        for req in packetPairsWithoutAnswers:
            print("unanswered", req)
            if req.haslayer(TCP):
                port = req.getlayer(TCP).dport
                print(f"unanswered port: {port}")
                if reporter:
                    reporter.update_progress(self.host, port, False)
            else:
                print("what?")
        for req, resp in packetPairsWithAnswers:
            if not resp.haslayer(TCP):
                continue
            tcp = resp.getlayer(TCP)
            if reporter is None:
                continue
            if resp.ttl:
                reporter.report_ttl(self.host, tcp.sport, resp.ttl)
            if tcp.flags == SYNACK:
                reporter.update_progress(self.host, tcp.sport, True)
            elif tcp.flags == RSTACK:
                reporter.update_progress(self.host, tcp.sport, False)
            else:
                print("unknown flag", tcp.flags, tcp.sport)
                reporter.update_progress(
                    self.host, tcp.sport, Exception("unknown flag")
                )

    async def end(self):
        print("end")
        pass
