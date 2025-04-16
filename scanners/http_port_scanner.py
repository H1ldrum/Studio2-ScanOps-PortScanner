import asyncio

import aiohttp

from scanners.scanner import Scanner


class HttpPortScanner(Scanner):
    def __init__(
        self,
        target: str,
        proxy: str | None = "",
        method: str | None = "HEAD",
        timeout_ms: int = 3000,
        status_code_filter: range | list[int] = [],
        status_code_ignore_filter: range | list[int] = [],
    ):
        self.target = target
        self.method = method
        self.status_code_filter = status_code_filter
        self.status_code_ignore_filter = status_code_ignore_filter

        self.req = URLRequest(
            proxy=proxy or "",
            timeout=aiohttp.ClientTimeout(total=timeout_ms / 1000),
        )

    async def scan_port(self, port) -> bool | Exception:
        try:
            url = f"http://{self.target}:{port}"
            response = await self.req.get(url, method=self.method or "HEAD")
            code = response.status
            if code in self.status_code_ignore_filter:
                return False
            if len(self.status_code_filter) > 0:
                return code in self.status_code_filter
            return True

        except aiohttp.ClientConnectorError:
            return False
        except (asyncio.TimeoutError, Exception) as e:
            return e

    async def end(self):
        pass


class URLRequest:
    def __init__(self, proxy: str = "", timeout: aiohttp.ClientTimeout | None = None):
        self.timeout = timeout
        self.proxy = proxy

    async def get(self, url, method="HEAD"):
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, proxy=self.proxy, timeout=self.timeout
            ) as response:
                return response
