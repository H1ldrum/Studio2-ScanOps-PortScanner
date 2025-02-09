import asyncio

from scanners.scanner import Scanner


class TCPScanner(Scanner):
    def __init__(self, host: str, timeout: float = 1.0, concurrent: int = 100):
        self.host = host
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrent)

    async def scan_port(self, port: int) -> bool:
        try:
            future = asyncio.open_connection(self.host, port)
            _, writer = await asyncio.wait_for(future, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
