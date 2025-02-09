import asyncio

import aiohttp


class URLRequest:
    async def get(self, url, proxy=None, method="HEAD"):
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, proxy=proxy) as response:
                return response


class PortScanner:
    def __init__(
        self, target, *, ports="1-1000", concurrent=4, proxy=None, method="HEAD"
    ):
        """
        Initialize PortScanner with configuration parameters

        Args:
            target: IP/hostname to scan
            ports: Port range as string ("4444", "20-8080" or "22,80,8080")
            concurrent: Max concurrent scans
            proxy: Proxy URL (http://xxx:xxx)
        """
        self.target = target
        self.proxy = proxy
        self.method = method
        self.concurrent_limit = concurrent
        self.ports = self._parse_ports(ports)
        self.semaphore = asyncio.Semaphore(self.concurrent_limit)

    def _parse_ports(self, ports_str):
        if "-" in ports_str:
            start, end = map(int, ports_str.split("-"))
            return range(start, end + 1)
        elif "," in ports_str:
            return [int(p) for p in ports_str.split(",")]
        else:
            return [int(ports_str)]

    async def scan_port(self, port, req):
        async with self.semaphore:
            try:
                if port % 100 == 0:
                    print(f"Scanning the {port}-range")
                url = f"http://{self.target}:{port}"
                response = await req.get(url, proxy=self.proxy, method=self.method)
                code = response.status
                print(f"{self.target} port {port} seems OPEN (responed with {code})")

            except Exception:
                pass

    async def run_scans(self):
        print(f"Scanning {self.target} with {self.concurrent_limit} concurrent tasks.")
        req = URLRequest()
        tasks = [self.scan_port(port, req) for port in self.ports]
        await asyncio.gather(*tasks)
