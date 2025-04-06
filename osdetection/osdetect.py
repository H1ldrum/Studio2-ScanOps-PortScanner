import socket


class OSDetector:
    # Common default values for operating systems
    TTL_SIGNATURES = {
        64: ["Linux", "Unix", "FreeBSD", "macOS"],
        128: ["Windows"],
        254: ["Solaris", "AIX"],
        255: ["Network equipment (Cisco, Juniper)"],
    }

    @staticmethod
    def lookup_os_from_ttl(ttl_value):
        if ttl_value in OSDetector.TTL_SIGNATURES:
            return OSDetector.TTL_SIGNATURES[ttl_value]

        for ttl in sorted(OSDetector.TTL_SIGNATURES.keys()):
            if ttl >= ttl_value:
                return OSDetector.TTL_SIGNATURES[ttl]

        return ["Unknown"]

    @staticmethod
    def get_ttl_from_ping(target, timeout=2):
        from scapy.all import ICMP, IP, sr1

        packet = IP(dst=target) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)

        if response:
            return response.ttl
        return None

    @staticmethod
    def grab_banner(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Timeout in seconds
                s.connect((ip, port))
                banner = s.recv(1024)
                return banner.decode(errors="ignore").strip()
        except Exception:
            return None

