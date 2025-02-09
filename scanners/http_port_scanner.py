import asyncio

import aiohttp

from scanners.scanner import Scanner


class HttpPortScanner(Scanner):
    def __init__(
        self,
        target: str,
        ports: list[int],
        concurrent: int = 4,
        proxy: str = "",
        method="HEAD",
        timeout_ms: int = 3000,
        status_code_filter: range | list[int] = [],
        status_code_ignore_filter: range | list[int] = [],
    ):
        self.target = target
        self.method = method
        self.concurrent_limit = concurrent
        self.ports = ports
        self.status_code_filter = status_code_filter
        self.status_code_ignore_filter = status_code_ignore_filter
        self.semaphore = asyncio.Semaphore(self.concurrent_limit)

        self.req = URLRequest(
            proxy=proxy,
            timeout=aiohttp.ClientTimeout(total=timeout_ms / 1000),
        )

    async def scan_port(self, port) -> bool | Exception:
        try:
            url = f"http://{self.target}:{port}"
            response = await self.req.get(url, method=self.method)
            code = response.status
            if code in self.status_code_ignore_filter:
                return False
            if not self.status_code_filter:
                return False
            if code in self.status_code_filter:
                return True
            return True

        except aiohttp.ClientConnectorError:
            return False
        except (asyncio.TimeoutError, Exception) as e:
            return e


class URLRequest:
    def __init__(self, proxy: str = "", timeout: aiohttp.ClientTimeout | None = None):
        self.timeout = timeout
        self.proxy = proxy

    async def get(self, url, method="HEAD"):
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, timeout=self.timeout, proxy=self.proxy
            ) as response:
                return response
