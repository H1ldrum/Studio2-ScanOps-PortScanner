import asyncio

import aiohttp


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


class HttpPortScanner:
    def __init__(
        self,
        target: str,
        ports: range | list[int],
        concurrent: int = 4,
        proxy=None,
        method="HEAD",
        status_code_filter: range | list[int] = [],
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
        self.ports = ports
        self.status_code_filter = status_code_filter
        self.semaphore = asyncio.Semaphore(self.concurrent_limit)

    async def scan_port(self, port, req) -> bool | Exception:
        async with self.semaphore:
            try:
                url = f"http://{self.target}:{port}"
                response = await req.get(url, method=self.method)
                if len(self.status_code_filter) == 0:
                    return True
                code = response.status
                return code in self.status_code_filter

            except (
                aiohttp.ClientConnectorError,
                # asyncio.TimeoutError,
            ):
                return False
            except (asyncio.TimeoutError, Exception) as e:
                return e

    async def run_scans(self):
        req = URLRequest()
        open_ports = []
        total_ports = len(self.ports)
        self.errors = {}  # Initialize error tracking
        self.last_error = ""

        async def scan_and_collect(port):
            is_open = await self.scan_port(port, req)
            if isinstance(is_open, Exception):
                error_name = is_open.__class__.__name__
                if error_name not in self.errors:
                    self.errors[error_name] = []
                self.errors[error_name].append(port)
                self.last_error = f" | Last error {error_name} on {port}"
            elif is_open:
                open_ports.append(port)
            # Update progress with last error
            progress = len(open_ports)
            print(
                f"\rScanning: {port}/{total_ports} ports | Open: {progress}{self.last_error}",
                end="",
                flush=True,
            )
            return is_open

        tasks = [scan_and_collect(port) for port in self.ports]
        await asyncio.gather(*tasks)

        print(f"\nFound {len(open_ports)} open ports: {sorted(open_ports)}")
        if len(self.errors) > 0:
            print(
                "In addition, some calls returned errors that might indicate non-http-ports being open"
            )
        for error_name, ports in self.errors.items():
            if error_name != "ClientConnectorError":  # Skip expected errors
                print(f"Error {error_name} occurred on ports: {sorted(ports)}")

        return open_ports
