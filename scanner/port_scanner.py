import asyncio
import socket

async def scan_port(host, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.setblocking(False)
    try:
        await asyncio.wait_for(loop.run_in_executor(None, conn.connect, (host, port)), timeout=1)
        print(f'Port {port} is open')
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    finally:
        conn.close()

async def scan_ports(host, ports):
    tasks = [scan_port(host, port) for port in ports]
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    host = input('Enter the host to scan: ')
    ports = range(1, 1024)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(scan_ports(host, ports))
