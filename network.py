v#!/usr/bin/env python3

import socket
import sys
import datetime
import threading
import queue
import nmap
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import ipaddress
import requests
import os
import ssl
import argparse
import time
import csv
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
        self.vulners_api_key = None
        self.report_directory = "scan_reports"
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.known_vulnerabilities = self._load_vulnerability_database()
        
        if not os.path.exists(self.report_directory):
            os.makedirs(self.report_directory)

    def _load_vulnerability_database(self) -> Dict[str, List[Dict[str, str]]]:
        """Load vulnerability database from JSON file, create if not exists."""
        vuln_db = {
            "apache": [
                {"version": "2.4", "cve": "CVE-2021-44790", "description": "Directory traversal vulnerability"},
                {"version": "2.4", "cve": "CVE-2021-41773", "description": "Path traversal vulnerability"}
            ],
            "nginx": [
                {"version": "1.18", "cve": "CVE-2021-23017", "description": "Buffer overflow vulnerability"},
                {"version": "1.14", "cve": "CVE-2019-9511", "description": "HTTP/2 denial of service"}
            ],
            "openssh": [
                {"version": "7", "cve": "CVE-2020-14145", "description": "User enumeration vulnerability"},
                {"version": "8", "cve": "CVE-2021-28041", "description": "Remote memory corruption"}
            ],
            "mysql": [
                {"version": "5.7", "cve": "CVE-2020-14539", "description": "Buffer overflow vulnerability"},
                {"version": "8.0", "cve": "CVE-2021-2154", "description": "Privilege escalation"}
            ]
        }
        return vuln_db

    def banner_grab(self, ip: str, port: int) -> str:
        """Attempt to grab service banner from the specified port."""
        banner = ""
        try:
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        banner = str(ssock.version())
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    sock.connect((ip, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        return banner

    def scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        """Scan a specific port on the given IP address."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        service = "unknown"
        banner = ""
        if result == 0:
            try:
                service = socket.getservbyport(port)
                banner = self.banner_grab(ip, port)
            except:
                pass
            
        return {
            "port": port,
            "state": "open" if result == 0 else "closed",
            "service": service,
            "banner": banner
        }

    def scan_host(self, ip: str, port_range: List[int] = None) -> Dict[str, Any]:
        """Scan a specific host for open ports and services."""
        if port_range is None:
            port_range = self.common_ports

        scan_results = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.scan_port, ip, port) for port in port_range]
            for future in futures:
                result = future.result()
                if result["state"] == "open":
                    scan_results.append(result)

        # Additional Nmap scan for OS detection
        try:
            self.nm.scan(ip, arguments='-O')
            os_info = self.nm[ip].get('osmatch', [{'name': 'Unknown'}])[0]['name']
        except:
            os_info = "Unknown"

        return {
            "ip": ip,
            "timestamp": datetime.datetime.now().isoformat(),
            "os": os_info,
            "ports": scan_results
        }

    def generate_report(self, scan_results: Dict[str, Any], format: str = "json") -> str:
        """Generate a report of the scan results."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_directory}/scan_report_{timestamp}"

        if format == "json":
            with open(f"{filename}.json", 'w') as f:
                json.dump(scan_results, f, indent=4)
            return f"{filename}.json"
        elif format == "csv":
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Port", "State", "Service", "Banner", "OS"])
                for ip, data in scan_results.items():
                    os_info = data.get("os", "Unknown")
                    for port_info in data["ports"]:
                        writer.writerow([
                            ip,
                            port_info["port"],
                            port_info["state"],
                            port_info["service"],
                            port_info["banner"],
                            os_info
                        ])
            return f"{filename}.csv"

def main():
    """Main function to run the network scanner."""
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-t", "--target", help="Target IP address or network (CIDR notation)")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan (default: common ports)")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json", help="Output format (default: json)")
    args = parser.parse_args()

    if not args.target:
        print(f"{Fore.RED}Error: Target IP or network is required{Style.RESET_ALL}")
        sys.exit(1)

    scanner = NetworkScanner()
    
    try:
        network = ipaddress.ip_network(args.target)
        ports = [int(p) for p in args.ports.split(',')] if args.ports else None
        
        results = {}
        total_hosts = len(list(network.hosts()))
        
        print(f"{Fore.CYAN}Starting scan of {total_hosts} hosts...{Style.RESET_ALL}")
        
        for i, ip in enumerate(network.hosts(), 1):
            ip_str = str(ip)
            print(f"{Fore.YELLOW}Scanning host {ip_str} ({i}/{total_hosts}){Style.RESET_ALL}")
            results[ip_str] = scanner.scan_host(ip_str, ports)
            
            # Print immediate results for open ports
            if results[ip_str]["ports"]:
                print(f"{Fore.GREEN}Open ports found on {ip_str}:{Style.RESET_ALL}")
                for port_info in results[ip_str]["ports"]:
                    print(f"  Port {port_info['port']}: {port_info['service']} ({port_info['banner'] or 'No banner'})")
            else:
                print(f"{Fore.RED}No open ports found on {ip_str}{Style.RESET_ALL}")

        # Generate report
        report_file = scanner.generate_report(results, args.format)
        print(f"\n{Fore.GREEN}Scan complete! Report saved to: {report_file}{Style.RESET_ALL}")

    except ValueError as e:
        print(f"{Fore.RED}Error: Invalid IP address or network format{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
