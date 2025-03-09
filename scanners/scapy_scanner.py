import os

from scapy.all import RandShort, conf, sr1
from scapy.layers.inet import IP, TCP

from scanners.scanner import Scanner

SYNACK = 0x12  # Set flag values for later reference
RSTACK = 0x14


class ScapyScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout

    async def scan_port(self, port: int) -> bool:
        srcport = RandShort()
        # Add filter to prevent kernel RST
        os.system(
            f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {self.host} -j DROP"
        )  # noqa: F821
        # print(f"scanning {self.host}:{port} with port {srcport}")

        try:
            SYNACKpkt = sr1(
                IP(dst=self.host) / TCP(sport=srcport, dport=port, flags="S"),
                timeout=self.timeout,
            )

            if SYNACKpkt and SYNACKpkt.haslayer(TCP) and SYNACKpkt[TCP].flags == 0x12:
                return True
            return False

        finally:
            # Remove the filter
            os.system(
                f"iptables -D OUTPUT -p tcp --tcp-flags RST RST -s {self.host} -j DROP"
            )
            # RSTpkt = IP(dst=target) / TCP(
            #     sport=srcport, dport=port, flags="R"
            # )  # Construct RST packet
            # send(RSTpkt)  # Send RST packet

    async def end(self):
        print("end")
        pass
