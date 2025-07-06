#!/usr/bin/env python3
import os
import sys
import json
import time
import random
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set
import csv

try:
    import shodan
    import requests
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install shodan requests colorama")
    sys.exit(1)

class S012:
    def __init__(self):
        self.version = "1.0"
        self.api_keys = []
        self.current_key_index = 0
        self.results = []
        self.total_results = 0
        self.rate_limit_delay = 1.0
        self.max_retries = 3
        self.output_formats = ['txt', 'json', 'csv']
        self.unique_ips = set()
        self.stats = {
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'unique_ips': 0,
            'api_switches': 0
        }
        
    def display_banner(self):
        banners = [
            f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                    M012 SHODAN SCANNER v{self.version}                        ║
    ║                     Enhanced IP Intelligence                          ║
    ║───────────────────────────────────────────────────────────────────────║
    ║  📡 Advanced Network Reconnaissance  🔍 Deep Port Analysis           ║
    ║  🌐 Global IP Intelligence          🛡️  Security Assessment          ║
    ║───────────────────────────────────────────────────────────────────────║
    ║  GitHub: github.com/Antidajjal      Site: m012.info                  ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    {Fore.RESET}""",

            f"""{Fore.GREEN}
       ███╗   ███╗ ██████╗  ██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
       ████╗ ████║██╔═████╗███║╚════██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
       ██╔████╔██║██║██╔██║╚██║ █████╔╝    ███████╗██║     ███████║██╔██╗ ██║
       ██║╚██╔╝██║████╔╝██║ ██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
       ██║ ╚═╝ ██║╚██████╔╝ ██║███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
       ╚═╝     ╚═╝ ╚═════╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                  
    {Fore.YELLOW}                    🔥 SHODAN INTELLIGENCE PLATFORM 🔥                    
    {Fore.WHITE}                        Version {self.version} | Enhanced Edition                        
    {Fore.CYAN}               ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━               
    {Fore.MAGENTA}                🌐 m012.info | 📂 github.com/Antidajjal                
    {Fore.RESET}""",

            f"""{Fore.CYAN}
    {Style.BRIGHT}
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄                       │
    │ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌                      │
    │ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌                      │
    │ ▐░▌          ▐░▌       ▐░▌     ▐░▌               ▐░▌                      │
    │ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌     ▐░▌      ▄▄▄▄▄▄▄▄▄█░▌                      │
    │ ▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░▌     ▐░░░░░░░░░░░▌                      │
    │ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌     ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌                      │
    │ ▐░▌          ▐░▌       ▐░▌     ▐░▌               ▐░▌                      │
    │ ▐░▌          ▐░█▄▄▄▄▄▄▄█░▌ ▄▄▄▄█░█▄▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌                      │
    │ ▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌                      │
    │  ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀                       │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │     {Fore.RED}⚡ SHODAN RECONNAISSANCE ENGINE v{self.version} ⚡{Fore.CYAN}                           │
    │     {Fore.YELLOW}🔍 Advanced Network Intelligence & Security Analysis 🔍{Fore.CYAN}                │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  {Fore.GREEN}🌐 Website:{Fore.WHITE} m012.info                                               │
    │  {Fore.GREEN}📂 Source:{Fore.WHITE} github.com/Antidajjal                                   │
    │  {Fore.GREEN}🛡️  Purpose:{Fore.WHITE} Ethical Network Reconnaissance & Security Testing        │
    └─────────────────────────────────────────────────────────────────────────────┘
    {Fore.RESET}""",

            f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                      SHODAN SCANNER v{self.version}                           ║
    ║                    Advanced IP Intelligence                           ║
    ║───────────────────────────────────────────────────────────────────────║
    ║                              ,,,,                                    ║
    ║                           .::;;;;::.                                 ║
    ║                        .;;;;;;;;;;;;;.                               ║
    ║                      .:;;;;;;;;;;;;;;;;;.                            ║
    ║                     .:;;;;;;;;;;;;;;;;;;;:.                          ║
    ║                    .;;;;;;;;;;;;;;;;;;;;;.                           ║
    ║                   .;;;;;;;;;;;;;;;;;;;;:.                            ║
    ║                  .;;;;;;;;;;;;;;;;;;;:.                              ║
    ║                 .;;;;;;;;;;;;;;;;;;.                                 ║
    ║                .;;;;;;;;;;;;;;;;;.                                   ║
    ║               .;;;;;;;;;;;;;;;;.                                     ║
    ║              .;;;;;;;;;;;;;;;.        🦅 EAGLE VISION                ║
    ║             .;;;;;;;;;;;;;;.                                         ║
    ║            .;;;;;;;;;;;;;.                                           ║
    ║           .;;;;;;;;;;;;.                                             ║
    ║          .;;;;;;;;;;;.                                               ║
    ║         .;;;;;;;;;;.                                                 ║
    ║        .;;;;;;;;;.                                                   ║
    ║       .;;;;;;;;.                                                     ║
    ║      .;;;;;;;.                                                       ║
    ║     .;;;;;;.                                                         ║
    ║    .;;;;;.                                                           ║
    ║   .;;;;.                                                             ║
    ║  .;;;.                                                               ║
    ║ .;;.                                                                 ║
    ║.;.                                                                   ║
    ║───────────────────────────────────────────────────────────────────────║
    ║  📡 Network Reconnaissance  🔍 Deep Port Analysis                    ║
    ║  🌐 Global IP Intelligence  🛡️  Security Assessment                  ║
    ║───────────────────────────────────────────────────────────────────────║
    ║  GitHub: github.com/Antidajjal      Site: eagle-scan.info           ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    {Fore.RESET}""",


            f"""{Fore.YELLOW}
        ⚡ THUNDER EAGLE SCANNER ⚡
                        v{self.version}
            
                      ___,.,.__
                     /´_   _   `\\
                    /  (o)-(o)   \\
                   /    /\\_/\\     \\
                  /   .-'\\_/'-.    \\
                 /   /   ___   \\    \\
                /   /   /   \\   \\    \\
               |   |   |  ⚡  |   |    |
               |    \\   \\___/   /    |
                \\    `-.._____.-´    /
                 \\                 /
                  `-.._    ___   _.-´
                       `""`   `""`
        
        {Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        🔥 ADVANCED NETWORK INTELLIGENCE ENGINE 🔥
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        
        {Fore.GREEN}🎯 Target Acquisition & Analysis
        ⚡ Lightning-Fast Scanning
        🛡️  Vulnerability Assessment
        📊 Comprehensive Reporting
        
        {Fore.MAGENTA}🌐 eagle-scan.info | 📂 github.com/Antidajjal
    {Fore.RESET}""",

            f"""{Fore.RED}
    {Style.BRIGHT}
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │  ▄████▄▄████▄  ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄                                │
    │ ██████████████████████████████████████████████                               │
    │ ████████████████████████████████████████████                                │
    │ ███████████████████████████████████████████                                 │
    │ ██████████████████████████████████████████                                  │
    │ █████████████████████████████████████████                                   │
    │ ████████████████████████████████████████                                    │
    │ ███████████████████████████████████████                                     │
    │ ██████████████████████████████████████                                      │
    │ █████████████████████████████████████      🦅 CYBER EAGLE v{self.version}          │
    │ ████████████████████████████████████                                        │
    │ ███████████████████████████████████                                         │
    │ ██████████████████████████████████                                          │
    │ █████████████████████████████████                                           │
    │ ████████████████████████████████                                            │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │     {Fore.CYAN}⚡ SHODAN RECONNAISSANCE ENGINE ⚡{Fore.RED}                                    │
    │     {Fore.YELLOW}🔍 Advanced Network Intelligence & Security Analysis 🔍{Fore.RED}           │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │  {Fore.GREEN}🌐 Website:{Fore.WHITE} eagle-scan.info                                        │
    │  {Fore.GREEN}📂 Source:{Fore.WHITE} github.com/Antidajjal                                  │
    │  {Fore.GREEN}🛡️  Purpose:{Fore.WHITE} Ethical Network Reconnaissance & Security Testing   │
    └─────────────────────────────────────────────────────────────────────────────┘
    {Fore.RESET}""",
        ]

        selected_banner = random.choice(banners)
        print(selected_banner)
        time.sleep(0.5)
        
    def load_api_keys(self):
        api_file = "api_keys.txt"
        
        if os.path.exists(api_file) and os.path.getsize(api_file) > 0:
            with open(api_file, 'r') as f:
                keys = [line.strip() for line in f if line.strip()]
                self.api_keys = keys
                print(f"{Fore.GREEN}[✓] Loaded {len(keys)} API key(s) from {api_file}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] API keys file not found. Creating new one...{Style.RESET_ALL}")
            self.setup_api_keys()
            
    def setup_api_keys(self):
        print(f"\n{Fore.CYAN}[+] API Key Setup{Style.RESET_ALL}")
        print("Enter your Shodan API keys (one per line). Press Enter twice to finish:")
        
        keys = []
        while True:
            key = input(f"{Fore.BLUE}API Key #{len(keys)+1} (or press Enter to finish): {Style.RESET_ALL}").strip()
            if not key:
                if keys:
                    break
                else:
                    print(f"{Fore.RED}[!] At least one API key is required!{Style.RESET_ALL}")
                    continue

            if self.validate_api_key(key):
                keys.append(key)
                print(f"{Fore.GREEN}[✓] API key validated successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[✗] Invalid API key, please try again{Style.RESET_ALL}")
        

        with open("api_keys.txt", 'w') as f:
            for key in keys:
                f.write(f"{key}\n")
        
        self.api_keys = keys
        print(f"{Fore.GREEN}[✓] Saved {len(keys)} API key(s) to api_keys.txt{Style.RESET_ALL}")
        
    def validate_api_key(self, key: str) -> bool:
        """Validate API key by making a test request"""
        try:
            api = shodan.Shodan(key)
            api.info()
            return True
        except Exception:
            return False
            
    def get_current_api(self):

        if not self.api_keys:
            raise Exception("No valid API keys available")
            
        api = shodan.Shodan(self.api_keys[self.current_key_index])
        return api
        
    def rotate_api_key(self):
        if len(self.api_keys) > 1:
            self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
            self.stats['api_switches'] += 1
            print(f"{Fore.YELLOW}[!] Switched to API key #{self.current_key_index + 1}{Style.RESET_ALL}")
            time.sleep(2)  # Cool down period
            
    def intelligent_delay(self):
        base_delay = self.rate_limit_delay
        jitter = random.uniform(0.1, 0.5)
        time.sleep(base_delay + jitter)
        
    def search_with_retry(self, query: str, limit: int = None, offset: int = 0) -> List[Dict]:
        results = []
        
        for attempt in range(self.max_retries):
            try:
                api = self.get_current_api()
                
                if limit:
                    search_results = api.search(query, limit=limit, offset=offset)
                    results.extend(search_results['matches'])
                else:
                    count = 0
                    for banner in api.search_cursor(query):
                        results.append(banner)
                        count += 1
                        if count % 100 == 0:
                            print(f"{Fore.CYAN}[+] Collected {count} results...{Style.RESET_ALL}")
                            self.intelligent_delay()
                        if count >= 50000:  
                            print(f"{Fore.YELLOW}[!] Reached safety limit of 50,000 results{Style.RESET_ALL}")
                            break
                
                self.stats['successful_queries'] += 1
                return results
                
            except shodan.APIError as e:
                self.stats['failed_queries'] += 1
                error_msg = str(e).lower()
                
                if 'rate limit' in error_msg or 'quota' in error_msg:
                    print(f"{Fore.YELLOW}[!] Rate limit reached, rotating API key...{Style.RESET_ALL}")
                    self.rotate_api_key()
                    continue
                    
                elif 'invalid api key' in error_msg:
                    print(f"{Fore.RED}[!] Invalid API key, removing from rotation{Style.RESET_ALL}")
                    if len(self.api_keys) > 1:
                        self.api_keys.pop(self.current_key_index)
                        self.current_key_index = self.current_key_index % len(self.api_keys)
                        continue
                    else:
                        raise Exception("No valid API keys remaining")
                        
                else:
                    print(f"{Fore.RED}[!] API Error: {e}{Style.RESET_ALL}")
                    if attempt < self.max_retries - 1:
                        wait_time = (attempt + 1) * 2
                        print(f"{Fore.CYAN}[+] Retrying in {wait_time} seconds...{Style.RESET_ALL}")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
                if attempt < self.max_retries - 1:
                    time.sleep((attempt + 1) * 2)
                    continue
                else:
                    raise
                    
        return results
        
    def extract_ip_info(self, banner: Dict) -> Dict:
        ip_info = {
            'ip': banner.get('ip_str', ''),
            'port': banner.get('port', ''),
            'protocol': banner.get('transport', ''),
            'organization': banner.get('org', ''),
            'country': banner.get('location', {}).get('country_name', ''),
            'city': banner.get('location', {}).get('city', ''),
            'region': banner.get('location', {}).get('region_code', ''),
            'coordinates': f"{banner.get('location', {}).get('latitude', '')},{banner.get('location', {}).get('longitude', '')}",
            'domains': banner.get('domains', []),
            'hostnames': banner.get('hostnames', []),
            'timestamp': banner.get('timestamp', ''),
            'product': banner.get('product', ''),
            'version': banner.get('version', ''),
            'banner_data': banner.get('data', '').strip()[:500], 
            'vulns': list(banner.get('vulns', [])),
            'tags': banner.get('tags', [])
        }
        return ip_info
        
    def save_results(self, filename: str, format_type: str = 'json'):

        if not self.results:
            print(f"{Fore.YELLOW}[!] No results to save{Style.RESET_ALL}")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        full_filename = f"{filename}_{timestamp}.{format_type}"
        
        try:
            if format_type == 'json':
                with open(full_filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'metadata': {
                            'scan_date': timestamp,
                            'total_results': len(self.results),
                            'unique_ips': len(self.unique_ips),
                            'stats': self.stats
                        },
                        'results': self.results
                    }, f, indent=2, ensure_ascii=False)
                    
            elif format_type == 'csv':
                with open(full_filename, 'w', newline='', encoding='utf-8') as f:
                    if self.results:
                        # Clean the data before writing to CSV
                        cleaned_results = []
                        for result in self.results:
                            cleaned_result = {}
                            for key, value in result.items():
                                if isinstance(value, list):
                                    # Convert lists to string representation
                                    cleaned_result[key] = ', '.join(str(item) for item in value)
                                elif isinstance(value, str):
                                    # Remove or replace problematic characters
                                    cleaned_result[key] = value.encode('utf-8', errors='ignore').decode('utf-8')
                                else:
                                    cleaned_result[key] = str(value) if value is not None else ''
                            cleaned_results.append(cleaned_result)
                        
                        writer = csv.DictWriter(f, fieldnames=cleaned_results[0].keys())
                        writer.writeheader()
                        writer.writerows(cleaned_results)
                        
            elif format_type == 'txt':
                with open(full_filename, 'w', encoding='utf-8') as f:
                    f.write(f"# Shodan Scan Results - {timestamp}\n")
                    f.write(f"# Total Results: {len(self.results)}\n")
                    f.write(f"# Unique IPs: {len(self.unique_ips)}\n\n")
                    
                    for result in self.results:
                        try:
                            f.write(f"IP: {result.get('ip', 'N/A')}\n")
                            f.write(f"Port: {result.get('port', 'N/A')}\n")
                            f.write(f"Organization: {result.get('organization', 'N/A')}\n")
                            f.write(f"Location: {result.get('city', 'N/A')}, {result.get('country', 'N/A')}\n")
                            
                            domains = result.get('domains', [])
                            domain_str = ', '.join(domains) if domains else 'None'
                            f.write(f"Domains: {domain_str}\n")
                            
                            hostnames = result.get('hostnames', [])
                            hostname_str = ', '.join(hostnames) if hostnames else 'None'
                            f.write(f"Hostnames: {hostname_str}\n")
                            
                            f.write("-" * 60 + "\n")
                        except UnicodeEncodeError:
                            f.write(f"IP: {result.get('ip', 'N/A')} [Data contains non-displayable characters]\n")
                            f.write("-" * 60 + "\n")
                            
            print(f"{Fore.GREEN}[✓] Results saved to {full_filename}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving file: {e}{Style.RESET_ALL}")
            try:
                fallback_filename = f"{filename}_{timestamp}_fallback.txt"
                with open(fallback_filename, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(f"# Shodan Scan Results (Fallback) - {timestamp}\n")
                    f.write(f"# Total Results: {len(self.results)}\n\n")
                    for i, result in enumerate(self.results, 1):
                        f.write(f"Result #{i}: {result.get('ip', 'N/A')}:{result.get('port', 'N/A')}\n")
                print(f"{Fore.YELLOW}[!] Saved fallback version to {fallback_filename}{Style.RESET_ALL}")
            except Exception as fallback_error:
                print(f"{Fore.RED}[!] Fallback save also failed: {fallback_error}{Style.RESET_ALL}")
            
    def display_stats(self):
        """Display real-time statistics"""
        print(f"\n{Fore.CYAN}╭─ SCAN STATISTICS ─╮{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Total Results: {Fore.GREEN}{len(self.results):<8}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Unique IPs: {Fore.BLUE}{len(self.unique_ips):<11}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Success Rate: {Fore.GREEN}{(self.stats['successful_queries']/(self.stats['successful_queries']+self.stats['failed_queries'])*100) if (self.stats['successful_queries']+self.stats['failed_queries']) > 0 else 0:.1f}%{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ API Switches: {Fore.YELLOW}{self.stats['api_switches']:<8}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╰─────────────────────╯{Style.RESET_ALL}")
        
    def interactive_search(self):
        try:
            print(f"\n{Fore.CYAN}[+] Starting Interactive Shodan Search{Style.RESET_ALL}")
            
            query = input(f"{Fore.BLUE}Enter search query: {Style.RESET_ALL}").strip()
            if not query:
                print(f"{Fore.RED}[!] Query cannot be empty{Style.RESET_ALL}")
                return
                
            try:
                max_results = input(f"{Fore.BLUE}Maximum results (0 for unlimited): {Style.RESET_ALL}").strip()
                max_results = int(max_results) if max_results and max_results != '0' else None
            except ValueError:
                max_results = None

            print(f"\n{Fore.CYAN}Available formats: {', '.join(self.output_formats)}{Style.RESET_ALL}")
            output_format = input(f"{Fore.BLUE}Output format (default: csv): {Style.RESET_ALL}").strip().lower()
            if output_format not in self.output_formats:
                output_format = 'csv'
                
            filename = input(f"{Fore.BLUE}Output filename (without extension): {Style.RESET_ALL}").strip()
            if not filename:
                filename = f"shodan_results_{query.replace(' ', '_')}"
                
            print(f"\n{Fore.GREEN}[+] Starting search...{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Query: {query}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Max Results: {max_results if max_results else 'Unlimited'}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Format: {output_format}{Style.RESET_ALL}")
            

            start_time = time.time()
            results = self.search_with_retry(query, limit=max_results)
            
            print(f"\n{Fore.GREEN}[✓] Search completed in {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")
            

            for banner in results:
                ip_info = self.extract_ip_info(banner)
                self.results.append(ip_info)
                self.unique_ips.add(ip_info['ip'])
                

                if len(self.results) % 50 == 0:
                    print(f"{Fore.CYAN}[+] Processed {len(self.results)} results, {len(self.unique_ips)} unique IPs{Style.RESET_ALL}")
                    

            self.display_stats()
            

            if self.results:
                save_choice = input(f"\n{Fore.BLUE}Save results? (Y/n): {Style.RESET_ALL}").strip().lower()
                if save_choice != 'n':
                    self.save_results(filename, output_format)
                    
                    additional = input(f"{Fore.BLUE}Save in additional formats? (y/N): {Style.RESET_ALL}").strip().lower()
                    if additional == 'y':
                        for fmt in self.output_formats:
                            if fmt != output_format:
                                save_fmt = input(f"{Fore.BLUE}Save as {fmt}? (y/N): {Style.RESET_ALL}").strip().lower()
                                if save_fmt == 'y':
                                    self.save_results(filename, fmt)
            else:
                print(f"{Fore.YELLOW}[!] No results found for the given query{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Search interrupted by user{Style.RESET_ALL}")
            if self.results:
                save_choice = input(f"{Fore.BLUE}Save partial results? (y/N): {Style.RESET_ALL}").strip().lower()
                if save_choice == 'y':
                    self.save_results(f"partial_{filename}", output_format)
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Search failed: {e}{Style.RESET_ALL}")
            
    def run(self):
        self.display_banner()
        
        try:
            self.load_api_keys()
            
            if not self.api_keys:
                print(f"{Fore.RED}[!] No valid API keys available. Exiting.{Style.RESET_ALL}")
                return
                
            print(f"{Fore.GREEN}[✓] Loaded {len(self.api_keys)} API key(s){Style.RESET_ALL}")
            
            while True:
                print(f"\n{Fore.CYAN}╭─ MAIN MENU ─╮{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 1. Start Search{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 2. Manage API Keys{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 3. View Statistics{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 4. Exit{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╰──────────────╯{Style.RESET_ALL}")
                
                choice = input(f"{Fore.BLUE}Select option: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    self.interactive_search()
                elif choice == '2':
                    self.setup_api_keys()
                elif choice == '3':
                    self.display_stats()
                elif choice == '4':
                    print(f"{Fore.GREEN}[+] Thanks for using Advanced Shodan Scanner! 🚀{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
                    
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Program interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")

def main():
    scanner = S012()
    scanner.run()

if __name__ == "__main__":
    main()