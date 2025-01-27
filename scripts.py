import socket
from pwn import *

"""
This python script is to be used in conjunction with the portscanner.py script to enhance the portscanner.py script
and to provide additional functionality to it.
"""
context.log_level = 'error'
#Simple class to add default services to the portscanner
class Default_Service_Discovery:
    def __init__(self, port):
        self.port = port
        self.service = self.get_service()
    
    def get_service(self):
        try:
            return socket.getservbyport(self.port)
        except:
            return None

#Class to try and discover services on non-default ports
class OS_Service_Discovery:
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.service = self.discover_service()
        self.os = self.discover_os()

    def discover_service(self):
        try:
            conn = remote(self.target, self.port, timeout=2)
            
            try:
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                )

                conn.send(request.encode())
                response = conn.recv(1024).decode('utf-8', errors='ignore')

                #Might replace this with grabbing the the response key/value instead
                servers = [
                    ('Windows', 'Windows'),
                    ('Unix', 'Linux/Unix'),
                    ('Linux', 'Linux/Unix'),
                    ('Apache', 'Apache'),
                    ('Nginx', 'Nginx'),
                    ('IIS', 'Microsoft IIS'),
                    ('Node.js', 'Node.js'),
                    ('Python', 'Python'),
                    ('PHP', 'PHP'),
                    ('Ruby', 'Ruby'),
                    ('Perl', 'Perl'),
                    ('cloudflare', 'Cloudflare'),
                    ('Varnish', 'Varnish Cache'),
                    ('LiteSpeed', 'LiteSpeed'),
                    ('OpenResty', 'OpenResty'),
                    ('Gunicorn', 'Gunicorn'),
                    ('uWSGI', 'uWSGI'),
                    ('Caddy', 'Caddy'),
                    ('Jetty', 'Jetty'),
                    ('Tomcat', 'Apache Tomcat'),
                    ('WildFly', 'WildFly'),
                    ('GlassFish', 'GlassFish'),
                    ('JBoss', 'JBoss'),
                    ('ASP.NET', 'ASP.NET'),
                    ('FastCGI', 'FastCGI'),
                    ('Heroku', 'Heroku'),
                    ('AWS', 'AWS'),
                    ('GCP', 'Google Cloud Platform'),
                    ('Azure', 'Microsoft Azure'),
                    ('DigitalOcean', 'DigitalOcean'),
                    ('OVH', 'OVH'),
                    ('Kinsta', 'Kinsta'),
                    ('WP Engine', 'WP Engine'),
                    ('Squarespace', 'Squarespace'),
                    ('Wix', 'Wix'),
                    ('Weebly', 'Weebly'),
                    ('Shopify', 'Shopify')
                ]

                for keyword, server_name in servers:
                    if keyword in response:
                        return server_name
                
                return None
                
            except Exception as e:
                print(f"Port {self.port} is seemingly not web-related.")

            banner = conn.recv(1024).decode('utf-8', errors='ignore')

            if 'Windows' in banner:
                return 'Windows'
            elif 'Unix' in banner or 'Linux' in banner:
                return 'Linux/Unix'
            return None

        except Exception as e:
            print(f"[!] Error: {e}")
            return None
        finally:
            conn.close()
    
    def discover_os(self):    
        try:
            conn = remote(self.target, self.port, timeout=2)
            banner = conn.recv(1024).decode('utf-8', errors='ignore')
            if 'Windows' in banner:
                return 'Windows'
            elif 'Unix' in banner or 'Linux' in banner:
                return 'Linux/Unix'
            else:
                return None
            
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
        
        finally:
                conn.close()

if __name__ == "__main__":
    #Testing usage
    # service = OS_Service_Discovery("127.0.0.1", 8008)
    # print(service.service)
    print("This is a module, not a standalone script.")
    print("Please run portscanner.py with the script flags to use this module.")
    print("For more information, please refer to the README.md file.")