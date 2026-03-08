import socket

class ServiceDetector:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.banner = ""

    def grab_banner(self):
        try:
            # Create a socket connection
            sock = socket.socket()
            sock.connect((self.host, self.port))
            # Set a timeout
            sock.settimeout(2)
            # Attempt to receive data
            self.banner = sock.recv(1024).decode().strip()
            sock.close()
            return self.banner
        except Exception as e:
            return str(e)

    def identify_service(self):
        try:
            # Basic service identification based on port number
            services = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                443: 'HTTPS',
                110: 'POP3',
                143: 'IMAP',
                3306: 'MySQL',
                # Add more as needed
            }
            service = services.get(self.port, 'Unknown Service')
            return service
        except Exception as e:
            return str(e)

# Example usage:
if __name__ == '__main__':
    detector = ServiceDetector('127.0.0.1', 80)  # Change to target IP and port
    print("Service:", detector.identify_service())
    print("Banner:", detector.grab_banner())