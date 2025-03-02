import ipaddress
from typing import List


def parse_cidr_to_ip_list(cidr_notation: str) -> List[str]:
    try:
        network = ipaddress.IPv4Network(cidr_notation, strict=False)

        # Convert each address in the network to a string and return as a list
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr_notation}. Error: {str(e)}")
