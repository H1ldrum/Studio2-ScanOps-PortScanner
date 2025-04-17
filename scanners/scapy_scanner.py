from typing import Callable, List, Optional

from scapy.all import RandShort, conf, sr, sr1
from scapy.layers.inet import IP, TCP

from reporters.reporter import ScanReporter
from scanners.scanner import Scanner

conf.verb = 0

SYNACK = 0x12  # Set flag values for later reference
RSTACK = 0x14


class ScapyScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0, max_retries = 3):
        self.host = host
        self.timeout = timeout
        self.max_retries = max_retries

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

    async def scan_ports(self, ports: List[int], reporter: ScanReporter, retries: Optional[int]=None):
        if retries is None:
            retries = self.max_retries
        p = IP(dst=self.host) / TCP(dport=ports, flags="S")
        # print(f"   SYN-scan {ports} / {retries}\n\n")
        ports_to_retry: list[int] =[]
        packetPairsWithAnswers, packetPairsWithoutAnswers = sr(p, timeout=self.timeout)
        for req in packetPairsWithoutAnswers:
            # print("unanswered", req)
            if req.haslayer(TCP):
                port = req.getlayer(TCP).dport
                ports_to_retry.append(port)
                # print(f"unanswered port: {port}")
                if reporter and retries <= 0:
                    reporter.update_progress(self.host, port, None)
            else:
                print("what?")
        for req, resp in packetPairsWithAnswers:
            if reporter is None:
                continue
            if not resp.haslayer(TCP):
                continue
            tcp = resp.getlayer(TCP)
            port = tcp.sport
            # print(f"\nWHAT? port={port}, dport={tcp.dport} sport={tcp.sport} ttl={resp.ttl} flags={tcp.flags} {tcp}\n")
            if resp.ttl:
                reporter.report_ttl(self.host, port, resp.ttl)
            if tcp.flags == SYNACK:
                reporter.update_progress(self.host, port, True)
            elif tcp.flags == RSTACK:
                reporter.update_progress(self.host, port, False)
            else:
                print("unknown flag", tcp.flags, tcp.sport)
                reporter.update_progress(
                    self.host, tcp.sport, Exception("unknown flag")
                )
        if len(ports_to_retry) > 0 and retries > 0:
            # print(f"retrying attempts {retries} left. Ports: {ports_to_retry}\n")
            await self.scan_ports(ports_to_retry, reporter, retries -1)

    async def end(self):
        print("end")
        pass
