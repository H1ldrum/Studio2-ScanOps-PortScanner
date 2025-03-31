class OSDetector:
    #Common default values for operating systems
    TTL_SIGNATURES = {
        64: ["Linux", "Unix", "FreeBSD", "macOS"],
        128: ["Windows"],
        254: ["Solaris", "AIX"],
        255: ["Network equipment (Cisco, Juniper)"]
    }
    
    @staticmethod
    def detect_os_from_ttl(ttl_value):
        if ttl_value <= 64:
            estimated_ttl = 64
        elif ttl_value <= 128:
            estimated_ttl = 128
        elif ttl_value <= 254:
            estimated_ttl = 254
        else:
            estimated_ttl = 255
            
        return OSDetector.TTL_SIGNATURES.get(estimated_ttl, ["Unknown"])
    
    @staticmethod
    def get_ttl_from_ping(target, timeout=2):
        from scapy.all import sr1, IP, ICMP

        packet = IP(dst=target)/ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response:
            return response.ttl
        return None