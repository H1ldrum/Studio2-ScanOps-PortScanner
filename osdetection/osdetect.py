import json
import socket
from dataclasses import dataclass
from typing import Dict


@dataclass
class OSGuess:
    kind: str
    description: str
    possible_oses: list[str]


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, "__dataclass_fields__"):
            return {k: getattr(o, k) for k in o.__dataclass_fields__}
        return super().default(o)


class OSDetector:
    # Common default values for operating systems
    TTL_SIGNATURES = {
        64: ["Linux", "Unix", "FreeBSD", "macOS"],
        128: ["Windows"],
        254: ["Solaris", "AIX"],
        255: ["Network equipment (Cisco, Juniper)"],
    }

    @staticmethod
    def lookup_os_from_ttl(target: str, ttl_value) -> OSGuess | None:
        possible_oses: list[str] = []
        if ttl_value in OSDetector.TTL_SIGNATURES:
            possible_oses = OSDetector.TTL_SIGNATURES[ttl_value]
        else:
            for ttl in sorted(OSDetector.TTL_SIGNATURES.keys()):
                if ttl >= ttl_value:
                    possible_oses = OSDetector.TTL_SIGNATURES[ttl]

        if len(possible_oses) == 0:
            return None

        g = OSGuess(
            kind="from_ttl_values",
            description=f"Based on ttl-values, it looks like the target {target} could be one of: {', '.join(possible_oses)}",
            possible_oses=possible_oses,
        )
        return g

    @staticmethod
    def lookup_os_from_port_list(
        target: str, ports: Dict[int, str] | None
    ) -> list[OSGuess]:
        guesses: list[OSGuess] = []
        if not ports:
            return guesses
        possible_oses: list[str] = []
        if 135 in ports and 139 in ports and 445 in ports:
            possible_oses = ["Windows"]
            g = OSGuess(
                kind="from_port_list",
                description=f"Based on the combination of ports open (135,139,445), the target {target} is likely windows-based",
                possible_oses=possible_oses,
            )
            guesses.append(g)
        return guesses
