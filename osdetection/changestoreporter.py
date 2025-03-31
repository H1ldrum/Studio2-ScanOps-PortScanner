#Add to the ScanReporter class
class ScanReporter:
    def __init__(self):
        self.os_detection_results = {}
        #...

#ConsoleReporter
def report_final(self, elapsed):
    #...
    
    #Add OS detection results if available
    if hasattr(self, 'os_detection_results') and self.os_detection_results:
        print("\nOS Detection Results:")
        for target, data in self.os_detection_results.items():
            print(f"  {target}: TTL={data['ttl']}, Possible OS: {', '.join(data['possible_os'])}")
    
    #...

#JSONReporter
def report_final(self, elapsed):
    #...
    
    #Add OS detection results if available
    if hasattr(self, 'os_detection_results') and self.os_detection_results:
        self.data["os_detection"] = self.os_detection_results