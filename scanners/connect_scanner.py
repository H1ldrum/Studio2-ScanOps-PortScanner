import asyncio
import socket
import struct
from sys import stderr

from scanners.scanner import Scanner


class ConnectScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout

    async def scan_port(self, port: int) -> bool | None | str:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.settimeout(self.timeout)

        try:
            await loop.sock_connect(sock, (self.host, port))
            return True
        except (asyncio.TimeoutError, OSError) as e:
            return None if isinstance(e, asyncio.TimeoutError) else False
        finally:
            # Force RST on close (avoids FIN/ACK exchange)
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )  # Enable linger with 0 timeout (RST on close)
            sock.close()

    async def end(self):
        pass
