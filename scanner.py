import argparse
import ipaddress
import socket
import time
import json
import itertools
import threading
import socks
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

screenlock = ThreadPoolExecutor(max_workers=1)

# Attack Profiles
MODES = {
    "recon": {"scan_type": "basic", "service_detection": False, "os_detection": False, "verbose": True},
    "service": {"scan_type": "detailed", "service_detection": True, "os_detection": False, "verbose": True},
    "firewall-evasion": {"scan_type": "stealth", "service_detection": True, "os_detection": True, "verbose": False},
}

def setup_proxy(proxy_addr, proxy_port):
    """ Setup SOCKS5 proxy for scans """
    socks.set_default_proxy(socks.SOCKS5, proxy_addr, proxy_port)
    socket.socket = socks.socksocket

def parse_ports(port_str):
    """ Parse ports from comma-separated list or range format (e.g., 20-100) """
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def banner_grab(ip, port):
    """ Retrieve service banner """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b'Hello\r\n')
        banner = s.recv(100).decode().strip()
        screenlock.submit(print, colored(f'[*] {ip}:{port} Banner: {banner}', 'yellow'))
    except:
        pass
    finally:
        s.close()

def os_detection(ip):
    """ Detect OS by analyzing responses """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 135))  # Windows RPC port (135) is a common fingerprinting technique
        screenlock.submit(print, colored(f'[+] {ip} likely running Windows', 'cyan'))
    except:
        screenlock.submit(print, colored(f'[+] {ip} might be Unix-based or protected by a firewall', 'cyan'))
    finally:
        s.close()

def con_scan(ip, port, protocol="TCP", service_detection=False, show_closed=False):
    """ Basic port scanning (TCP/UDP) """
    start_time = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM)
        s.settimeout(1)
        
        if protocol == "TCP":
            s.connect((ip, port))
        else:
            s.sendto(b'Hello', (ip, port))
            s.recvfrom(100)  # UDP response handling
        
        latency = round((time.time() - start_time) * 1000, 2)
        screenlock.submit(print, colored(f'[+] {ip}:{port}/{protocol} OPEN (Latency: {latency}ms)', 'green'))
        
        if service_detection and protocol == "TCP":
            banner_grab(ip, port)
    except:
        if show_closed:
            screenlock.submit(print, colored(f'[-] {ip}:{port}/{protocol} CLOSED', 'red'))
    finally:
        s.close()

def traceroute(ip):
    """ Basic traceroute implementation """
    for ttl in range(1, 30):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            s.sendto(b'Traceroute packet', (ip, 33434))
            response, addr = s.recvfrom(100)
            screenlock.submit(print, colored(f'[+] Hop {ttl}: {addr[0]}', 'magenta'))
            if addr[0] == ip:
                break
        except:
            pass
        finally:
            s.close()

def rotating_indicator():
    """ Rotating indicator for scan responsiveness """
    for frame in itertools.cycle(["|", "/", "-", "\\"]):
        print(colored(f"\r[Scanning...] {frame}", 'blue'), end="", flush=True)
        time.sleep(0.3)

def scan_subnet(subnet, ports, protocols, attack_mode, traceroute_enabled, proxy_addr, proxy_port, output_file, show_closed):
    """ Scan entire subnet with advanced options """
    config = MODES.get(attack_mode, MODES["recon"])

    if proxy_addr and proxy_port:
        setup_proxy(proxy_addr, proxy_port)
        print(colored(f"[+] Proxy enabled: {proxy_addr}:{proxy_port}", 'blue'))

    print(colored(f"\n[+] Scanning subnet {subnet} in {attack_mode} mode...\n", 'blue'))

    results = []
    spinner_thread = threading.Thread(target=rotating_indicator, daemon=True)
    spinner_thread.start()

    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ipaddress.IPv4Network(subnet, strict=False):
            for port in ports:
                for protocol in protocols:
                    executor.submit(con_scan, str(ip), port, protocol, config["service_detection"], show_closed)
            if config["os_detection"]:
                executor.submit(os_detection, str(ip))
            if traceroute_enabled:
                executor.submit(traceroute, str(ip))

            results.append({"ip": str(ip), "ports_scanned": ports})

    if output_file:
        with open(output_file, 'w') as f:
            f.write(json.dumps(results, indent=4))
        print(colored(f"[+] Scan results saved to {output_file}", 'blue'))

    print("\n[+] Scan completed!")

def main():
    parser = argparse.ArgumentParser(description="Advanced Security Scanner with Vulnerability Detection")
    parser.add_argument('-s', '--subnet', required=True, help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument('-p', '--ports', required=True, help="Target ports (comma-separated or range)")
    parser.add_argument('-m', '--mode', choices=MODES.keys(), default="recon", help="Attack mode (recon, service, firewall-evasion)")
    parser.add_argument('-T', '--timing', type=int, choices=range(1, 6), default=3, help="Scan timing (1=Slow, 5=Aggressive)")
    parser.add_argument('-sU', '--udp', action='store_true', help="Enable UDP scanning")
    parser.add_argument('--traceroute', action='store_true', help="Enable traceroute mapping")
    parser.add_argument('--proxy', type=str, help="SOCKS5 proxy (format: ip:port)")
    parser.add_argument('--output', type=str, help="Save results to file (TXT/JSON format)")
    parser.add_argument('--show-closed', action='store_true', help="Display closed ports")

    args = parser.parse_args()
    ports = parse_ports(args.ports)
    protocols = ["TCP"] if not args.udp else ["TCP", "UDP"]

    proxy_addr, proxy_port = (args.proxy.split(':') if args.proxy else (None, None))

    print(colored(f"\n[+] Using {args.mode} attack profile with timing level {args.timing}\n", 'blue'))
    scan_subnet(args.subnet, ports, protocols, args.mode, args.traceroute, proxy_addr, proxy_port, args.output, args.show_closed)

if __name__ == "__main__":
    main()
