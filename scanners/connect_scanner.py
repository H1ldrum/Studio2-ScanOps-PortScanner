import asyncio
import socket

from scanners.scanner import Scanner


class ConnectScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout

    async def scan_port(self, port: int) -> bool:
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            is_open = sock.connect_ex((self.host, port)) == 0

            sock.close()
            return is_open
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def end(self):
        pass
