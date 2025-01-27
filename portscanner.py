import sys
import argparse
import asyncio
import aiohttp

class URLRequest:
    async def get(self, url, proxy):
        async with aiohttp.ClientSession() as session:
            if proxy != None:
                async with session.get(url, proxy=proxy) as response:
                    return response
            else:
                async with session.get(url) as response:
                    return response

class PortScanner:
    def __init__(self):
        """
        Initiating with argparse to properly handle arguments from user
        
        1. Might have to adjust this to take in ip range e.g. 127.0.0.1/27 or 127.0.0.1-150
        2. Add argument for scripts
        3. Add argument for which ports
        """
        argument_parser = argparse.ArgumentParser(
            prog='Portscanner by ScanOps',
            description='Multipurpose portscanner to discover open ports and detect running services | Arguments prepended with * is mandatory'
        )
        argument_parser.add_argument("-t", help="*Define ip to scan",
                            action="store", dest='target')
        #Added args for ports, gotta implement the logic to propely handle it and use it for the portscanner
        argument_parser.add_argument("-p", help="Define the ports you want to scan (e.g., '4444', '20-8080' or '22,80,8080').",
                            action="store", dest='ports', default="1-1000")
        argument_parser.add_argument("--concurrent", help="Concurrent limit in the event loop",
                            action="store", dest='concurrent', default=4)
        argument_parser.add_argument("--proxy", help="Define proxy address/port url(http://xxx:xxx)",
                            action="store", dest='proxy')
        arguments = argument_parser.parse_args()

        #Add more or/and statements here to make sure all needed arguments are provided
        if arguments.target is None:
            argument_parser.print_help()
            sys.exit(1)

        self.target = arguments.target
        if arguments.proxy != None:
            self.proxy = arguments.proxy
        else:
            self.proxy = None
        if arguments.concurrent != None:
            self.concurrent_limit = int(arguments.concurrent)
        else:
            self.concurrent_limit = 4
            
        #Adjust the common_ports to a lower range (for actual common ports), using 9000-9201 for testing
        self.common_ports = [i for i in range(1, 1000)]
        self.semaphore = asyncio.Semaphore(self.concurrent_limit)
    
    #Procedure to handle the actual scanning
    async def scan_port(self, port, req):
        async with self.semaphore:
            try:
                #This is just to show progress as I get quite anxious if I don't get any feedback on it actually running
                if port % 100 == 0:
                    print(f"Scanning the {port}-range")
                url = f"http://{self.target}:{port}"
                response = await req.get(url, self.proxy)
                code = response.status
                
                #Typical codes returned in http if there is no hosted webpage on that port, but the port is listening for something
                if code in (200, 404, 401, 426):
                    print(f"{self.target} port {port} seems OPEN")
            except Exception:
                pass
    
    #Function to handle the setup for scanning
    async def run_scans(self):
        print(f"Scanning {self.target} with {self.concurrent_limit} concurrent tasks.")
        req = URLRequest()
        tasks = [self.scan_port(port, req) for port in self.common_ports]
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    #Initiate the scanner class
    portscanner = PortScanner()
    #Actually scan the target, using asyncio eventloops to speed up the scanning
    asyncio.run(portscanner.run_scans())