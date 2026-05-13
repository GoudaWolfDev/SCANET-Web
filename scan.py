#!/usr/bin/env python3
# SCANET Pro V1.1 - Kali Recon & Intelligence Tool
# Developed for Educational & Ethical Security Testing

import socket
import requests
import concurrent.futures
import re
import subprocess
import os
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, IntPrompt
from rich.markup import escape
from rich.text import Text
from urllib.parse import urlparse

# Initialize Console
console = Console()

# ==========================================
# Configuration & Constants
# ==========================================

VERSION = "1.1-WEB"
AUTHOR = "Gouda Nasrallah"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NETBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MYSQL", 3389: "RDP", 8080: "HTTP-ALT"
}

CVE_DB = {
    "Apache": {
        "2.4.49": [{"cve": "CVE-2021-41773", "severity": "HIGH", "description": "Path Traversal"}]
    },
    "nginx": {
        "1.18.0": [{"cve": "CVE-2021-23017", "severity": "MEDIUM", "description": "Memory corruption"}]
    }
}

# ==========================================
# Utility Classes
# ==========================================

class ExternalTool:
    @staticmethod
    def is_installed(name):
        return subprocess.call(f"which {name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

    @staticmethod
    def run(command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Error running tool: {str(e)}"

# ==========================================
# Core Scanning Logic
# ==========================================

class ReconScanner:
    def __init__(self, target):
        self.target = target
        try:
            self.ip = socket.gethostbyname(target)
        except:
            self.ip = None
        self.results = {
            "target": target,
            "ip": self.ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ports": [],
            "http": {},
            "external": {}
        }

    def quick_port_scan(self):
        console.print(f"[bold yellow][*] Performing Quick Python Port Scan on {self.ip}...[/bold yellow]")
        open_ports = []
        
        def scan(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((self.ip, port)) == 0:
                    return port
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan, p) for p in COMMON_PORTS.keys()]
            for future in concurrent.futures.as_completed(futures):
                p = future.result()
                if p: open_ports.append(p)
        
        open_ports.sort()
        self.results["ports"] = open_ports
        return open_ports

    def http_fingerprint(self):
        url = f"http://{self.target}"
        try:
            r = requests.get(url, timeout=5, verify=False)
            server = r.headers.get("Server", "Unknown")
            software, version = self.parse_banner(server)
            self.results["http"] = {
                "status": r.status_code,
                "server": server,
                "software": software,
                "version": version
            }
            return self.results["http"]
        except Exception as e:
            return {"error": str(e)}

    def parse_banner(self, server_header):
        match = re.search(r"([A-Za-z\-]+)/([\d\.]+)", server_header)
        return (match.group(1), match.group(2)) if match else (server_header, "Unknown")

    # --- External Tool Integrations ---

    def run_nmap(self):
        if not ExternalTool.is_installed("nmap"):
            return "Nmap is not installed."
        console.print("[bold cyan][*] Running Nmap Service Scan...[/bold cyan]")
        cmd = f"nmap -sV -T4 {self.ip}"
        output = ExternalTool.run(cmd)
        self.results["external"]["nmap"] = output
        return output

    def run_whois(self):
        if not ExternalTool.is_installed("whois"):
            return "Whois is not installed."
        console.print("[bold cyan][*] Running Whois Lookup...[/bold cyan]")
        output = ExternalTool.run(f"whois {self.target}")
        self.results["external"]["whois"] = output
        return output

    def run_dns(self):
        if not ExternalTool.is_installed("dig"):
            return "Dig is not installed."
        console.print("[bold cyan][*] Running DNS Enumeration (dig)...[/bold cyan]")
        output = ExternalTool.run(f"dig {self.target} ANY")
        self.results["external"]["dns"] = output
        return output

    def run_whatweb(self):
        if not ExternalTool.is_installed("whatweb"):
            return "WhatWeb is not installed."
        console.print("[bold cyan][*] Running WhatWeb Fingerprinting...[/bold cyan]")
        output = ExternalTool.run(f"whatweb {self.target}")
        self.results["external"]["whatweb"] = output
        return output

# ==========================================
# Report Generator (Tables)
# ==========================================

class ReportGenerator:
    @staticmethod
    def parse_nmap(nmap_raw):
        table = Table(title="Nmap Scan Results", border_style="cyan")
        table.add_column("Port/Protocol", style="yellow")
        table.add_column("State", style="green")
        table.add_column("Service", style="blue")
        table.add_column("Version", style="white")

        lines = nmap_raw.split("\n")
        for line in lines:
            if "/tcp" in line or "/udp" in line:
                parts = re.split(r"\s+", line.strip(), 3)
                if len(parts) >= 3:
                    version = parts[3] if len(parts) > 3 else "Unknown"
                    table.add_row(escape(parts[0]), escape(parts[1]), escape(parts[2]), escape(version))
        return table

    @staticmethod
    def parse_whois(whois_raw):
        table = Table(title="Whois Intelligence", border_style="magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        keys = ["netname", "country", "descr", "inetnum", "origin", "abuse-mailbox"]
        for key in keys:
            match = re.search(f"^{key}:\\s+(.+)$", whois_raw, re.IGNORECASE | re.MULTILINE)
            if match:
                table.add_row(escape(key.capitalize()), escape(match.group(1).strip()))
        return table

    @staticmethod
    def parse_whatweb(whatweb_raw):
        # Clean ANSI escape codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', whatweb_raw)
        
        table = Table(title="Web Technology Stack", border_style="green")
        table.add_column("URL / IP", style="blue")
        table.add_column("Findings", style="white")

        lines = clean_text.split("\n")
        for line in lines:
            if line.strip():
                parts = line.split(" ", 1)
                url = parts[0]
                findings = parts[1] if len(parts) > 1 else ""
                table.add_row(escape(url), escape(findings))
        return table

    @staticmethod
    def show_full_report(results):
        console.print("\n" + "="*50)
        console.print(f"[bold green]RECON REPORT FOR: {results['target']}[/bold green]")
        console.print(f"[bold white]Timestamp: {results['timestamp']}[/bold white]")
        console.print("="*50 + "\n")

        # Basic Info Table
        info_table = Table(title="General Information")
        info_table.add_column("Target", style="cyan")
        info_table.add_column("IP Address", style="green")
        info_table.add_row(results["target"], results["ip"])
        console.print(info_table)

        # Nmap Results
        if "nmap" in results["external"]:
            console.print(ReportGenerator.parse_nmap(results["external"]["nmap"]))

        # Whois Results
        if "whois" in results["external"]:
            console.print(ReportGenerator.parse_whois(results["external"]["whois"]))

        # WhatWeb Results
        if "whatweb" in results["external"]:
            console.print(ReportGenerator.parse_whatweb(results["external"]["whatweb"]))

        # HTTP Info
        if results.get("http"):
            http_table = Table(title="HTTP Fingerprint")
            http_table.add_column("Field", style="cyan")
            http_table.add_column("Value", style="white")
            for k, v in results["http"].items():
                http_table.add_row(escape(k.capitalize()), escape(str(v)))
            console.print(http_table)

# ================= ==========================
# UI & Menu
# ==========================================

def display_banner():
    banner = f"""
[bold red]
 ██████╗ ██████╗ █████╗ ███╗   ██╗███████╗████████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
╚█████╗ ██║     ███████║██╔██╗ ██║█████╗     ██║   
 ╚═══██╗██║     ██╔══██║██║╚██╗██║██╔══╝     ██║   
██████╔╝╚██████╗██║  ██║██║ ╚████║███████╗   ██║   
╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
[/bold red]
[bold cyan]───[ WEB EDITION ]───[/bold cyan]
[bold white]SCANET Pro V{VERSION} | Advanced Recon Framework[/bold white]
[bold green]Developer: {AUTHOR}[/bold green]
[dim white]Ready for target reconnaissance...[/dim white]
"""
    console.print(Panel(banner, border_style="blue", padding=(1, 2)))

def main():
    display_banner()
    
    target = Prompt.ask("[bold yellow]Enter Target (Domain or IP)[/bold yellow]")
    scanner = ReconScanner(target)

    if not scanner.ip:
        console.print("[bold red][!] Could not resolve target. Exiting.[/bold red]")
        return

    while True:
        console.print("\n[bold white]Available Modules:[/bold white]")
        console.print("1. Full Recon (Built-in + External)")
        console.print("2. Quick Python Port Scan")
        console.print("3. Nmap Service Scan")
        console.print("4. Whois Lookup")
        console.print("5. DNS Enumeration")
        console.print("6. Web Tech Fingerprint (WhatWeb)")
        console.print("7. HTTP Header Intelligence")
        console.print("8. [bold cyan]Show Pretty Report (Tables)[/bold cyan]")
        console.print("9. Save Results to File")
        console.print("0. Exit")

        choice = IntPrompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])

        if choice == 0:
            break
        elif choice == 1:
            scanner.quick_port_scan()
            scanner.http_fingerprint()
            scanner.run_nmap()
            scanner.run_whois()
            scanner.run_dns()
            scanner.run_whatweb()
            console.print("[bold green][+] Full Recon Completed![/bold green]")
            ReportGenerator.show_full_report(scanner.results)
        elif choice == 2:
            ports = scanner.quick_port_scan()
            table = Table(title=f"Open Ports on {scanner.ip}")
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="green")
            for p in ports: table.add_row(str(p), COMMON_PORTS.get(p, "Unknown"))
            console.print(table)
        elif choice == 3:
            output = scanner.run_nmap()
            console.print(ReportGenerator.parse_nmap(output))
        elif choice == 4:
            output = scanner.run_whois()
            console.print(ReportGenerator.parse_whois(output))
        elif choice == 5:
            console.print(Panel(scanner.run_dns(), title="DNS Output"))
        elif choice == 6:
            output = scanner.run_whatweb()
            console.print(ReportGenerator.parse_whatweb(output))
        elif choice == 7:
            info = scanner.http_fingerprint()
            console.print(Panel(str(info), title="HTTP Info"))
        elif choice == 8:
            ReportGenerator.show_full_report(scanner.results)
        elif choice == 9:
            filename = f"scan_{target.replace('.', '_')}.json"
            with open(filename, "w") as f:
                json.dump(scanner.results, f, indent=4)
            console.print(f"[bold green][+] Results saved to {filename}[/bold green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Aborted by user.[/bold red]")
