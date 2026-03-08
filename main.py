#!/usr/bin/env python3
"""
Network Scanner - main.py
Ties together all scanner modules into a single CLI + API launcher.

Usage:
    python main.py                                  # Interactive menu
    python main.py scan   -t 192.168.1.1 -p 80,443  # Port scan
    python main.py discover -n 192.168.1.0/24        # Host discovery
    python main.py service  -t 192.168.1.1 -p 80     # Service/banner detection
    python main.py api                               # Launch FastAPI server
    python main.py full   -n 192.168.1.0/24          # Full recon
"""

import argparse
import asyncio
import socket
import sys
from datetime import datetime

# ── Colour helpers ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
 ███╗   ██╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{YELLOW}  github.com/prabhatjalpota/Network-scanner{RESET}
"""

COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,
                3306,3389,5432,5900,6379,8080,8443,27017]

KNOWN_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 5900:"VNC",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB"
}

# ── Graceful module import ─────────────────────────────────────────────────────
def _try_import(dotted_path, label):
    try:
        import importlib
        return importlib.import_module(dotted_path)
    except ImportError as e:
        print(f"{YELLOW}[warn] {label} not available: {e}{RESET}")
        return None

scanner_port    = _try_import("scanner.port_scanner",    "scanner.port_scanner")
scanner_host    = _try_import("scanner.host_discovery",  "scanner.host_discovery")
scanner_service = _try_import("scanner.service_detector","scanner.service_detector")

def resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

# ── Port scan ──────────────────────────────────────────────────────────────────
def run_port_scan(target, ports, timeout=1.0):
    print(f"\n{CYAN}[*] Port scanning {target} — {len(ports)} ports...{RESET}")

    if scanner_port:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            async def _run():
                tasks = [scanner_port.scan_port(target, p) for p in ports]
                await asyncio.gather(*tasks, return_exceptions=True)
            loop.run_until_complete(_run())
            loop.close()
            return
        except Exception as e:
            print(f"{YELLOW}[warn] async scanner failed ({e}), using fallback{RESET}")

    # Built-in threaded fallback
    import concurrent.futures
    open_ports = []
    def _check(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        for r in ex.map(_check, ports):
            if r:
                open_ports.append(r)

    open_ports.sort()
    if not open_ports:
        print(f"{YELLOW}  No open ports found.{RESET}\n")
        return

    print(f"\n{BOLD}{'PORT':<10}{'STATE':<10}SERVICE{RESET}")
    print("─" * 35)
    for p in open_ports:
        print(f"{GREEN}{p:<10}{RESET}{'open':<10}{CYAN}{KNOWN_SERVICES.get(p,'unknown')}{RESET}")
    print(f"\n{BOLD}[+] {len(open_ports)} open port(s){RESET}\n")

# ── Host discovery ─────────────────────────────────────────────────────────────
def run_host_discovery(network):
    print(f"\n{CYAN}[*] Discovering hosts on {network}...{RESET}")

    if scanner_host:
        try:
            print(f"\n{BOLD}── ARP Table ──{RESET}")
            print(scanner_host.arp_discovery())
            base = ".".join(network.split(".")[:3])
            for last in range(1, 11):
                ip = f"{base}.{last}"
                out = scanner_host.icmp_ping(ip)
                alive = any(x in out for x in ["1 received","1 packets received","bytes from"])
                status = f"{GREEN}UP{RESET}" if alive else f"{RED}DOWN{RESET}"
                print(f"  {ip:<20} {status}")
            return []
        except Exception as e:
            print(f"{YELLOW}[warn] host_discovery failed ({e}), using fallback{RESET}")

    # Built-in ping sweep fallback
    import ipaddress, subprocess, concurrent.futures
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"{RED}[!] Invalid network: {e}{RESET}")
        return []

    def _ping(ip):
        cmd = (["ping","-n","1","-w","500",str(ip)] if sys.platform=="win32"
               else ["ping","-c","1","-W","1",str(ip)])
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return str(ip) if r.returncode == 0 else None

    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for r in ex.map(_ping, list(net.hosts())[:254]):
            if r:
                live.append(r)

    if not live:
        print(f"{YELLOW}  No live hosts.{RESET}\n")
        return []

    print(f"\n{BOLD}{'IP':<20}HOSTNAME{RESET}")
    print("─" * 45)
    for ip in sorted(live, key=lambda x:[int(o) for o in x.split(".")]):
        print(f"{GREEN}{ip:<20}{RESET}{resolve(ip)}")
    print(f"\n{BOLD}[+] {len(live)} live host(s){RESET}\n")
    return live

# ── Service detection ─────────────────────────────────────────────────────────
def run_service_detection(target, port):
    print(f"\n{CYAN}[*] Detecting service on {target}:{port}...{RESET}")

    if scanner_service:
        try:
            d = scanner_service.ServiceDetector(target, port)
            print(f"  {BOLD}Service:{RESET} {GREEN}{d.identify_service()}{RESET}")
            print(f"  {BOLD}Banner: {RESET} {CYAN}{d.grab_banner() or 'none'}{RESET}\n")
            return
        except Exception as e:
            print(f"{YELLOW}[warn] service_detector failed ({e}), using fallback{RESET}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(256).decode(errors="ignore").strip()
            print(f"  {BOLD}Banner:{RESET} {CYAN}{banner[:120] or 'none'}{RESET}\n")
    except Exception as e:
        print(f"  {RED}Could not connect: {e}{RESET}\n")

# ── Full recon ─────────────────────────────────────────────────────────────────
def run_full_recon(network, ports):
    print(f"\n{BOLD}{'═'*55}\n  FULL RECON: {network}\n{'═'*55}{RESET}")
    live = run_host_discovery(network)
    if not live:
        print(f"{YELLOW}No hosts — skipping port scan.{RESET}")
        return
    for host in live[:5]:
        print(f"\n{BOLD}── {host} ──{RESET}")
        run_port_scan(host, ports)

# ── Launch API ─────────────────────────────────────────────────────────────────
def run_api(host="0.0.0.0", port=8000):
    try:
        import uvicorn
        from api.app import app
        print(f"\n{CYAN}[*] API server → http://{host}:{port}")
        print(f"    Docs      → http://localhost:{port}/docs{RESET}\n")
        uvicorn.run(app, host=host, port=port)
    except ImportError:
        print(f"{RED}[!] Install uvicorn + fastapi:\n    pip install uvicorn fastapi{RESET}")
    except Exception as e:
        print(f"{RED}[!] API error: {e}{RESET}")

# ── Interactive menu ───────────────────────────────────────────────────────────
def interactive_menu():
    print(BANNER)
    print(f"  {BOLD}Started:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    while True:
        print(f"""{BOLD}
  ┌───────────────────────────────────────┐
  │  [1]  Discover hosts (ping sweep)     │
  │  [2]  Port scan a host                │
  │  [3]  Service / banner detection      │
  │  [4]  Full recon (all-in-one)         │
  │  [5]  Launch REST API                 │
  │  [0]  Exit                            │
  └───────────────────────────────────────┘{RESET}""")
        choice = input("\n  Select: ").strip()
        if choice == "0":
            print(f"\n{CYAN}  Goodbye!{RESET}\n"); break
        elif choice == "1":
            run_host_discovery(input("  Subnet (e.g. 192.168.1.0/24): ").strip())
        elif choice == "2":
            host = input("  Host/IP: ").strip()
            raw  = input("  Ports (comma-sep or range, Enter=common): ").strip()
            ports = parse_ports(raw) if raw else COMMON_PORTS
            run_port_scan(host, ports)
        elif choice == "3":
            run_service_detection(input("  Host/IP: ").strip(), int(input("  Port: ")))
        elif choice == "4":
            net  = input("  Subnet: ").strip()
            raw  = input("  Ports (Enter=common): ").strip()
            run_full_recon(net, parse_ports(raw) if raw else COMMON_PORTS)
        elif choice == "5":
            p = input("  API port (Enter=8000): ").strip()
            run_api(port=int(p) if p else 8000)
        else:
            print(f"{RED}  Invalid option.{RESET}")

# ── Port parsing ───────────────────────────────────────────────────────────────
def parse_ports(raw):
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return ports

# ── CLI entry point ────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Network Scanner — discover, scan, detect, report",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python main.py                                # interactive menu
  python main.py discover -n 192.168.1.0/24
  python main.py scan -t 192.168.1.1 -p 22,80,443
  python main.py scan -t 192.168.1.1 -p 1-1024
  python main.py service -t 192.168.1.1 -p 80
  python main.py full -n 192.168.1.0/24 -p 22,80,443
  python main.py api --api-port 8080
""")

    sub = parser.add_subparsers(dest="command")

    p_d = sub.add_parser("discover", help="Ping sweep to find live hosts")
    p_d.add_argument("-n","--network", required=True)

    p_s = sub.add_parser("scan", help="Port scan a host")
    p_s.add_argument("-t","--target",  required=True)
    p_s.add_argument("-p","--ports",   default="common")
    p_s.add_argument("--timeout",      type=float, default=1.0)

    p_sv = sub.add_parser("service", help="Banner/service detection")
    p_sv.add_argument("-t","--target", required=True)
    p_sv.add_argument("-p","--port",   required=True, type=int)

    p_f = sub.add_parser("full", help="Discover + scan + detect")
    p_f.add_argument("-n","--network", required=True)
    p_f.add_argument("-p","--ports",   default="common")

    p_a = sub.add_parser("api", help="Launch FastAPI REST server")
    p_a.add_argument("--api-host", default="0.0.0.0")
    p_a.add_argument("--api-port", type=int, default=8000)

    args = parser.parse_args()

    if not args.command:
        interactive_menu()
        return

    print(BANNER)

    if args.command == "discover":
        run_host_discovery(args.network)
    elif args.command == "scan":
        ports = COMMON_PORTS if args.ports == "common" else parse_ports(args.ports)
        run_port_scan(args.target, ports, args.timeout)
    elif args.command == "service":
        run_service_detection(args.target, args.port)
    elif args.command == "full":
        ports = COMMON_PORTS if args.ports == "common" else parse_ports(args.ports)
        run_full_recon(args.network, ports)
    elif args.command == "api":
        run_api(args.api_host, args.api_port)

if __name__ == "__main__":
    main()
