import asyncio

import aiohttp

from scanner import Scanner


class HttpPortScanner(Scanner):
    def __init__(
        self,
        target: str,
        ports: list[int],
        concurrent: int = 4,
        proxy=None,
        method="HEAD",
        status_code_filter: range | list[int] = [],
    ):
        self.target = target
        self.proxy = proxy
        self.method = method
        self.concurrent_limit = concurrent
        self.ports = ports
        self.status_code_filter = status_code_filter
        self.semaphore = asyncio.Semaphore(self.concurrent_limit)

        self.req = URLRequest()

    async def scan_port(self, port) -> bool | Exception:
        async with self.semaphore:
            try:
                url = f"http://{self.target}:{port}"
                response = await self.req.get(url, method=self.method)
                if len(self.status_code_filter) == 0:
                    return True
                code = response.status
                return code in self.status_code_filter

            except aiohttp.ClientConnectorError:
                return False
            except (asyncio.TimeoutError, Exception) as e:
                return e


class URLRequest:
    def __init__(
        self,
        proxy: str = "",
        timeout=aiohttp.ClientTimeout(total=3),
    ):
        self.timeout = timeout
        self.proxy = proxy

    async def get(self, url, method="HEAD"):
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, timeout=self.timeout, proxy=self.proxy
            ) as response:
                return response
