#!/usr/bin/env python3
import os
import re
import ipaddress
import socket
import time
import requests
import concurrent.futures
import threading
import gc
from datetime import datetime
from colorama import Fore, Back, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TaskProgressColumn,
    TimeRemainingColumn, MofNCompleteColumn, TextColumn
)
from rich import box
from urllib3.exceptions import InsecureRequestWarning

# --- Configuration ---
OUTPUT_DIR = "/storage/emulated/0/Download/RajScan_Results"
SAVE_FILE = os.path.join(OUTPUT_DIR, "extracted_domains.txt")
RESULTS_IP = os.path.join(OUTPUT_DIR, "scanner_ips.txt")
RESULTS_WORD = os.path.join(OUTPUT_DIR, "scanner_results.txt")
CIDR_RESULTS = os.path.join(OUTPUT_DIR, "cidr_results.txt")

# --- Default Ports for Host Scanner ---
HOST_PORTS = [443, 80, 8443, 8080]

# --- Thread Configuration ---
DEFAULT_THREADS = 100
MIN_THREADS = 50
MAX_THREADS = 200
CHUNK_SIZE = 500

# --- Timeout Configuration ---
CONNECTION_TIMEOUT = 3

# --- Developer Info ---
DEV_NAME = "Mr. Raj"
YT_CHANNEL = "Mr Tech Hacker"
INSTAGRAM = "@raj_dark_official"
TG_CHANNEL = "Mr Tech Hacker"
GITHUB = "RajownerTech"

# --- Setup ---
init(autoreset=True)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
console = Console()
lock = threading.Lock()
stop_scan = threading.Event()

# Session pool
session_pool = threading.local()

def should_filter_response(status_code, headers):
    """Check if response should be filtered out"""
    # Filter 302 redirects
    if status_code == 302:
        # Check for Jio balance exhaust in Location header
        location = headers.get("Location", "")
        if location and ("jio.com/balanceexhaust" in location.lower() or 
                        "balanceexhaust" in location.lower() or
                        "jio" in location.lower()):
            return True
        # Filter all 302 redirects
        return True
    
    # Filter based on Server header
    server = headers.get("Server", "")
    if "jio" in server.lower():
        return True
    
    return False

def get_session():
    """Get or create a session for thread-local reuse"""
    if not hasattr(session_pool, 'session'):
        session_pool.session = requests.Session()
        session_pool.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        session_pool.session.verify = False
        session_pool.session.allow_redirects = False  # Don't follow redirects
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=200,
            pool_maxsize=200,
            max_retries=0
        )
        session_pool.session.mount('http://', adapter)
        session_pool.session.mount('https://', adapter)
    return session_pool.session

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_thread_count():
    while True:
        try:
            console.print(f"\n[bright_cyan]⚡ Thread Configuration:[/bright_cyan]")
            console.print(f"  [bright_white]Min: {MIN_THREADS} | Max: {MAX_THREADS} | Default: {DEFAULT_THREADS}[/bright_white]")
            threads = input(f"{Fore.CYAN}👉 Enter threads: {Style.RESET_ALL}").strip()
            
            if threads == "":
                return DEFAULT_THREADS
            
            threads = int(threads)
            if MIN_THREADS <= threads <= MAX_THREADS:
                return threads
            else:
                console.print(f"[bright_red]❌ Threads must be between {MIN_THREADS} and {MAX_THREADS}![/bright_red]")
        except ValueError:
            console.print(f"[bright_red]❌ Invalid input![/bright_red]")

def banner():
    console.print()
    console.print("╔══════════════════════════════════════════════════════════╗", style="bright_red")
    console.print("║         ⚡ MULTI-ADVANCE TOOL v3.0 - STABLE ⚡            ║", style="bright_yellow")
    console.print("╠══════════════════════════════════════════════════════════╣", style="bright_cyan")
    console.print("║       Created by Mr Raj | Mr tech hacker                 ║", style="bright_green")
    console.print("║      [4 PORTS: 443, 80, 8443, 8080]                      ║", style="bright_blue")
    console.print("║         [HTTP/HTTPS BOTH PROTOCOLS]                      ║", style="bright_magenta")
    console.print("╚══════════════════════════════════════════════════════════╝", style="bright_red")
    console.print()

def show_developer_info():
    console.print(f"\n[bold bright_red]👨‍💻 DEVELOPER INFORMATION[/bold bright_red]")
    console.print(f"[bright_cyan]════════════════════════════════════════════════[/bright_cyan]")
    
    profile_table = Table(show_header=False, box=box.ROUNDED)
    profile_table.add_column("Field", style="bright_cyan", width=15)
    profile_table.add_column("Details", style="bright_white")
    
    profile_table.add_row("👤 Name", f"[bold bright_green]{DEV_NAME}[/bold bright_green]")
    profile_table.add_row("📛 Alias", "Mr. Tech Hacker")
    profile_table.add_row("💼 Role", "Security Researcher")
    
    console.print(Panel(profile_table, title="[bold bright_red]PROFILE[/bold bright_red]", border_style="bright_cyan"))
    
    console.print(f"\n[bold bright_magenta]📱 SOCIAL MEDIA[/bold bright_magenta]")
    social_table = Table(show_header=False, box=box.SIMPLE)
    social_table.add_row("📺 YouTube", f"{YT_CHANNEL}")
    social_table.add_row("📸 Instagram", f"{INSTAGRAM}")
    social_table.add_row("📱 Telegram", f"{TG_CHANNEL}")
    social_table.add_row("💻 GitHub", f"{GITHUB}")
    console.print(social_table)
    
    input(f"\n🔄 Press Enter to return to menu...")

def extract_domains(text):
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    return set(domain_pattern.findall(text))

def run_extractor():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]📋 DOMAIN EXTRACTOR[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    console.print(f"\n[bright_blue]📌 Paste your text below (press Enter twice to extract):[/bright_blue]\n")
    
    lines = []
    blank_count = 0
    while True:
        try:
            line = input()
            if line.strip() == "":
                blank_count += 1
                if blank_count == 2:
                    break
            else:
                blank_count = 0
                lines.append(line)
        except KeyboardInterrupt:
            return

    pasted_text = "\n".join(lines)
    extracted = extract_domains(pasted_text)
    
    if extracted:
        existing = set()
        if os.path.exists(SAVE_FILE):
            with open(SAVE_FILE, 'r') as f:
                existing = set(line.strip() for line in f if line.strip())
        
        new = extracted - existing
        if new:
            with open(SAVE_FILE, 'a') as f:
                for domain in new:
                    f.write(domain + '\n')
            console.print(f"\n[bright_green]✅ Saved {len(new)} new domain(s)[/bright_green]")
        else:
            console.print(f"[bright_yellow]⚠️ No new domains found[/bright_yellow]")
    else:
        console.print(f"[bright_yellow]⚠️ No domains found[/bright_yellow]")
    
    input(f"\n🔄 Press Enter to return to menu...")

# --- OPTIMIZED HOST SCANNER - LIKE CIDR SCANNER ---

def save_result_immediately(domain, ip, port, protocol, status, server):
    """Save result immediately to file"""
    try:
        result_line = f"{status} | {server} | {ip} | {protocol}://{domain}:{port}"
        with open(RESULTS_WORD, "a") as word_file:
            word_file.write(f"{result_line}\n")
        # Save IP only once per domain
        with open(RESULTS_IP, "a") as ip_file:
            ip_file.write(f"{ip}\n")
    except Exception as e:
        pass

def scan_domain_port(domain, ip, port):
    """Scan a domain on a specific port - tries both HTTP and HTTPS like CIDR scanner"""
    session = get_session()
    
    # Try HTTPS first, then HTTP (like CIDR scanner)
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}:{port}"
            response = session.get(url, timeout=CONNECTION_TIMEOUT, allow_redirects=False, stream=True)
            
            status = response.status_code
            server = response.headers.get("Server", "Unknown")[:25]
            location = response.headers.get("Location", "")
            response.close()
            
            # Filter out 302 redirects and Jio balance exhaust
            if should_filter_response(status, response.headers):
                continue
            
            # Display result
            if status == 200:
                status_color = "bright_green"
            elif status < 400:
                status_color = "bright_yellow"
            else:
                status_color = "bright_red"
            
            protocol_color = "bright_green" if protocol == "https" else "bright_blue"
            
            with lock:
                console.print(
                    f"[{status_color}]●[/{status_color}] "
                    f"[{status_color}]{status}[/{status_color}] | "
                    f"[bright_cyan]{server[:20]:20}[/bright_cyan] | "
                    f"[bright_magenta]{ip:15}[/bright_magenta] | "
                    f"[{protocol_color}]{protocol}[/{protocol_color}]://"
                    f"[bright_blue]{domain}:{port}[/bright_blue]"
                )
            
            # Save immediately
            save_result_immediately(domain, ip, port, protocol, status, server)
            return True
            
        except:
            continue
    
    return False

def scan_domain_all_ports(domain, ports_list):
    """Scan a single domain on all ports (like CIDR scanner but for domains)"""
    results_count = 0
    
    # DNS lookup
    try:
        ip = socket.gethostbyname(domain)
    except:
        return 0
    
    # Scan each port (like CIDR scanner)
    for port in ports_list:
        if scan_domain_port(domain, ip, port):
            results_count += 1
    
    return results_count

def run_host_scanner():
    """Host scanner - each domain scanned on multiple ports (like CIDR scanner)"""
    ensure_output_dir()
    
    console.print(f"\n[bold bright_red]🔍 HOST SCANNER - LIKE CIDR MODE[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    console.print(f"[bright_yellow]📡 Default Ports: {', '.join(map(str, HOST_PORTS))}[/bright_yellow]")
    console.print(f"[bright_green]🌐 Protocol: HTTP + HTTPS (Both)[/bright_green]")
    
    # Get file path
    file_path = input(f"{Fore.CYAN}📂 Enter file path with domains: {Style.RESET_ALL}").strip()
    
    if not file_path or not os.path.exists(file_path):
        console.print(f"[bright_red]❌ File not found![/bright_red]")
        input(f"\n🔄 Press Enter to return...")
        return
    
    # Custom ports option
    ports_to_use = HOST_PORTS.copy()
    custom_choice = input(f"{Fore.CYAN}🔧 Use custom ports? (y/n, default n): {Style.RESET_ALL}").strip().lower()
    if custom_choice == 'y':
        custom_ports = input(f"{Fore.CYAN}🔌 Enter ports (comma-separated, e.g., 443,80,8443,8080): {Style.RESET_ALL}").strip()
        if custom_ports:
            try:
                ports_to_use = [int(p.strip()) for p in custom_ports.split(',') if p.strip().isdigit()]
                console.print(f"[bright_green]✅ Using custom ports: {', '.join(map(str, ports_to_use))}[/bright_green]")
            except:
                console.print(f"[bright_yellow]⚠️ Invalid ports, using defaults[/bright_yellow]")
                ports_to_use = HOST_PORTS.copy()
    
    # Get threads
    threads = get_thread_count()
    
    # Clear previous results
    try:
        open(RESULTS_IP, "w").close()
        open(RESULTS_WORD, "w").close()
    except:
        pass
    
    # Get total lines
    console.print(f"[bright_yellow]📊 Counting total domains...[/bright_yellow]")
    total_lines = 0
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    total_lines += 1
    except Exception as e:
        console.print(f"[bright_red]❌ Error reading file: {e}[/bright_red]")
        input(f"\n🔄 Press Enter to return...")
        return
    
    total_scans = total_lines * len(ports_to_use) * 2  # *2 for HTTP and HTTPS
    
    console.print(f"[bright_green]✅ Total domains: {total_lines:,}[/bright_green]")
    console.print(f"[bright_cyan]📊 Total scans: {total_scans:,} ({total_lines} domains × {len(ports_to_use)} ports × 2 protocols)[/bright_cyan]")
    console.print(f"[bright_cyan]⚡ Chunk size: {CHUNK_SIZE} | Threads: {threads}[/bright_cyan]")
    console.print(f"[bright_green]🚀 Starting scan...[/bright_green]\n")
    
    total_found = 0
    processed = 0
    start_time = time.time()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="bright_green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            
            task_id = progress.add_task(f"[bright_yellow]Scanning domains...", total=total_lines)
            
            # Read file chunk by chunk
            with open(file_path, 'r') as f:
                chunk = []
                chunk_number = 1
                
                for line in f:
                    domain = line.strip()
                    if not domain:
                        continue
                    
                    chunk.append(domain)
                    
                    # When chunk is full (500 domains), process it
                    if len(chunk) >= CHUNK_SIZE:
                        progress.update(task_id, description=f"[bright_cyan]Processing chunk {chunk_number} ({len(chunk)} domains)...")
                        
                        # Scan this chunk with thread pool
                        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                            futures = {executor.submit(scan_domain_all_ports, domain, ports_to_use): domain for domain in chunk}
                            
                            for future in concurrent.futures.as_completed(futures):
                                try:
                                    count = future.result(timeout=30)
                                    total_found += count
                                except:
                                    pass
                                processed += 1
                                progress.update(task_id, advance=1)
                        
                        # Clear chunk and force garbage collection
                        chunk.clear()
                        chunk_number += 1
                        gc.collect()
                        time.sleep(0.1)
                
                # Process remaining domains
                if chunk:
                    progress.update(task_id, description=f"[bright_cyan]Processing final chunk ({len(chunk)} domains)...")
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                        futures = {executor.submit(scan_domain_all_ports, domain, ports_to_use): domain for domain in chunk}
                        
                        for future in concurrent.futures.as_completed(futures):
                            try:
                                count = future.result(timeout=30)
                                total_found += count
                            except:
                                pass
                            processed += 1
                            progress.update(task_id, advance=1)
    
    except KeyboardInterrupt:
        console.print(f"\n[bright_yellow]⚠️ Scan interrupted![/bright_yellow]")
    except Exception as e:
        console.print(f"\n[bright_red]❌ Error: {e}[/bright_red]")
    
    # Statistics
    elapsed = time.time() - start_time
    
    console.print(f"\n[bold bright_red]📊 SCAN COMPLETE[/bold bright_red]")
    console.print(f"[bright_cyan]════════════════════════════════════════════════[/bright_cyan]")
    console.print(f"[bright_blue]📌 Total Domains:[/bright_blue] {processed:,}")
    console.print(f"[bright_blue]🔌 Ports Scanned:[/bright_blue] {', '.join(map(str, ports_to_use))}")
    console.print(f"[bright_blue]🌐 Protocols:[/bright_blue] HTTP + HTTPS")
    console.print(f"[bright_blue]📊 Total Scans:[/bright_blue] {processed * len(ports_to_use) * 2:,}")
    console.print(f"[bright_green]✅ Responsive Results:[/bright_green] {total_found:,}")
    
    if processed > 0:
        success_rate = (total_found / (processed * len(ports_to_use))) * 100
        console.print(f"[bright_yellow]📈 Success Rate:[/bright_yellow] {success_rate:.2f}%")
    
    console.print(f"[bright_magenta]⏱️  Time Taken:[/bright_magenta] {elapsed:.2f} seconds")
    
    if elapsed > 0 and processed > 0:
        speed = (processed * len(ports_to_use) * 2) / elapsed
        console.print(f"[bright_cyan]⚡ Scan Speed:[/bright_cyan] {speed:.2f} scans/sec")
    
    console.print(f"\n[bright_green]💾 Results saved to:[/bright_green]")
    console.print(f"  [bright_blue]📄 IPs: {RESULTS_IP}[/bright_blue]")
    console.print(f"  [bright_blue]📄 Full Results: {RESULTS_WORD}[/bright_blue]")
    
    input(f"\n🔄 Press Enter to return to menu...")

# --- CIDR SCANNER ---

def scan_cidr_host(ip, port, progress, task_id, total_found):
    protocols = ['https', 'http']
    session = get_session()
    
    for protocol in protocols:
        url = f"{protocol}://{ip}:{port}"
        try:
            response = session.get(url, timeout=2, allow_redirects=False)
            server = response.headers.get('Server', 'Unknown')
            
            if response.status_code != 404:
                with lock:
                    if response.status_code == 200:
                        status_color = "bright_green"
                    elif response.status_code < 400:
                        status_color = "bright_yellow"
                    else:
                        status_color = "bright_red"
                    
                    protocol_color = "bright_green" if protocol == "https" else "bright_blue"
                    
                    console.print(
                        f"[{status_color}]●[/{status_color}] "
                        f"[{status_color}]{response.status_code}[/{status_color}] | "
                        f"[bright_cyan]{server[:20]:20}[/bright_cyan] | "
                        f"[{protocol_color}]{protocol}[/{protocol_color}] | "
                        f"[bright_blue]{ip}:{port}[/bright_blue]"
                    )
                    
                    total_found[0] += 1
                    result_line = f"{response.status_code} | {server} | {protocol}://{ip}:{port}"
                    
                    with open(CIDR_RESULTS, "a") as cidr_file:
                        cidr_file.write(f"{result_line}\n")
                    
                    break
        except:
            continue
    
    progress.update(task_id, advance=1)

def run_cidr_scanner():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]🌐 CIDR SCANNER[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    
    cidr_input = input(f"{Fore.CYAN}📡 Enter CIDR (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
    
    if not cidr_input:
        console.print(f"[bright_red]❌ CIDR cannot be empty![/bright_red]")
        input(f"\n🔄 Press Enter to return...")
        return
    
    try:
        if '/' in cidr_input:
            network = ipaddress.ip_network(cidr_input, strict=False)
        else:
            network = ipaddress.ip_network(f"{cidr_input}/32", strict=False)
    except ValueError as e:
        console.print(f"[bright_red]❌ Invalid CIDR: {e}[/bright_red]")
        input(f"\n🔄 Press Enter to return...")
        return

    ports_input = input(f"{Fore.CYAN}🔌 Enter ports (comma-separated, default 80,443,8080): {Style.RESET_ALL}").strip()
    if ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
        except:
            ports = [80, 443, 8080]
    else:
        ports = [80, 443, 8080]

    threads = get_thread_count()
    
    try:
        open(CIDR_RESULTS, "w").close()
    except:
        pass
    
    hosts = [str(ip) for ip in network.hosts()]
    total_ips = len(hosts)
    total_tasks = total_ips * len(ports)
    total_found = [0]

    console.print(f"\n[bright_cyan]📊 Network: {network} | IPs: {total_ips:,}[/bright_cyan]")
    console.print(f"[bright_green]🚀 Starting CIDR scan...[/bright_green]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task(f"[bright_yellow]Scanning...", total=total_tasks)
            
            for port in ports:
                for i in range(0, total_ips, CHUNK_SIZE):
                    chunk = hosts[i:i + CHUNK_SIZE]
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                        futures = [executor.submit(scan_cidr_host, ip, port, progress, task_id, total_found) for ip in chunk]
                        concurrent.futures.wait(futures)
                    
                    time.sleep(0.1)

    except KeyboardInterrupt:
        console.print(f"\n[bright_yellow]⚠️ Scan interrupted[/bright_yellow]")
    
    console.print(f"\n[bold bright_red]📊 SCAN COMPLETE[/bold bright_red]")
    console.print(f"[bright_green]✅ Responsive Hosts: {total_found[0]:,}[/bright_green]")
    console.print(f"[bright_blue]💾 Results saved to: {CIDR_RESULTS}[/bright_blue]")
    input(f"\n🔄 Press Enter to return...")

# --- MAIN MENU ---

def main():
    while True:
        try:
            os.system("clear" if os.name == "posix" else "cls")
        except:
            pass
        
        banner()
        
        console.print("[bold bright_red]MAIN MENU[/bold bright_red]")
        console.print(f"[bright_cyan]────────────────────[/bright_cyan]")
        console.print(f"[bright_yellow]1.[/bright_yellow] [bright_blue]Host Scanner (HTTP/HTTPS Both)[/bright_blue] 🌐")
        console.print(f"[bright_yellow]2.[/bright_yellow] [bright_blue]CIDR Scanner[/bright_blue] 📡")
        console.print(f"[bright_yellow]3.[/bright_yellow] [bright_blue]Domain Extractor[/bright_blue] 📋")
        console.print(f"[bright_yellow]4.[/bright_yellow] [bright_magenta]Developer Info[/bright_magenta] 👨‍💻")
        console.print(f"[bright_yellow]0.[/bright_yellow] [bright_blue]Exit[/bright_blue]")
        console.print()
        
        choice = input(f"{Fore.YELLOW}⚡ Choose option [0-4]: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            run_host_scanner()
        elif choice == "2":
            run_cidr_scanner()
        elif choice == "3":
            run_extractor()
        elif choice == "4":
            show_developer_info()
        elif choice == "0":
            console.print(f"\n[bright_green]👋 Thank you for using Multi-Advance Tool![/bright_green]")
            console.print(f"[bright_cyan]Follow {DEV_NAME} on social media for updates![/bright_cyan]")
            break
        else:
            console.print(f"[bright_red]❌ Invalid option![/bright_red]")
            time.sleep(1)

if __name__ == "__main__":
    try:
        ensure_output_dir()
        main()
    except KeyboardInterrupt:
        console.print(f"\n[bright_yellow]⚠️ Exiting...[/bright_yellow]")
        console.print(f"[bright_cyan]Follow @raj_dark_official on Instagram![/bright_cyan]")
    except Exception as e:
        console.print(f"\n[bright_red]❌ Fatal Error: {e}[/bright_red]")
