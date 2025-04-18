import asyncio
import socket
from sys import stderr

from scanners.scanner import Scanner


class ConnectScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout
        message = "Hello, world!"
        self.message_bytes = message.encode("utf-8")

    async def scan_port(self, port: int) -> bool | None | str:
        with socket.socket() as sock:
            try:
                sock.settimeout(self.timeout)

                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                status_code = sock.connect_ex((self.host, port))
                if status_code == 11:
                    return None
                if status_code != 0:
                    return False
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

            try:
                sock.send(self.message_bytes)
                results = sock.recv(1000).decode(errors="ignore").strip()
                if results:
                    return results
                    print(
                        f"GOT {port} '{results}'",
                    )
            except (ConnectionRefusedError, OSError):
                return True
            return True

    async def end(self):
        pass
