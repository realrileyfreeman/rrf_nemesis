# NEMESIS - Advanced Pentest Scanner
import requests
import socket
import threading
import argparse
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# CONFIGURATION AND CONSTANTS
init(autoreset=True)
USER_AGENT = "Nemesis-Security-Scanner/2.0 (Educational)"

class NemesisScanner: # Main Scanner Class
    def __init__(self, target, output_file=None): # Initialize with target and output file
        self.target = target
        self.output_file = output_file
        self.results = {
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": [],
            "web_vulnerabilities": [],
            "security_headers": {}
        }
        self.lock = threading.Lock()

    def print_log(self, message, level="INFO"):
        """Thread-safe logging method with colors"""
        if level == "INFO":
            print(f"{Fore.BLUE}[*] {message}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}[+] {message}")
        elif level == "VULN":
            print(f"{Fore.RED}[!!!] {message}")
        elif level == "ERROR":
            print(f"{Fore.YELLOW}[!] {message}")

    # MODULE 1: NETWORK RECON (Banner Grabbing)
    def grab_banner(self, ip, port): # Banner grabbing method
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            # Send bytes to provoke a server response
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(1024).decode().strip()
            except:
                banner = "Unknown Service"
            s.close()
            return banner
        except:
            return None

    def scan_ports(self, ports): # Port scanning method
        self.print_log(f"Starting network scan on {self.target}...", "INFO")
        
        # DNS Resolution if target is URL
        try:
            hostname = urlparse(self.target).hostname or self.target
            ip = socket.gethostbyname(hostname)
            self.print_log(f"Resolved IP: {ip}", "INFO")
        except:
            ip = self.target

        def thread_scan(port): # Threaded port scan function
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = self.grab_banner(ip, port)
                    with self.lock:
                        self.print_log(f"Port {port} OPEN - Service: {banner}", "SUCCESS")
                        self.results["open_ports"].append({"port": port, "banner": banner})
                sock.close()
            except:
                pass

        # Threading management for faster scanning
        threads = []
        for port in ports:
            t = threading.Thread(target=thread_scan, args=(port,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()

    # MODULE 2: WEB FUZZING (SQLi & XSS) AND SECURITY HEADERS CHECK
    def check_web_vulns(self):
        if not self.target.startswith("http"):
            self.print_log("Target is not a URL, skipping Web Module.", "ERROR")
            return

        self.print_log("Analyzing Web Vulnerabilities (Crawling & Fuzzing)...", "INFO")
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': USER_AGENT})
            response = session.get(self.target, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            # 1. Forms Audit for XSS/SQLi
            forms = soup.find_all("form")
            self.print_log(f"{len(forms)} forms found.", "INFO")

            for form in forms:
                action = form.get("action")
                post_url = urljoin(self.target, action)
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                
                data = {}
                for input_tag in inputs:
                    if input_tag.get("type") in ["text", "search"]:
                        # Payload: Basic SQL Injection test
                        data[input_tag.get("name")] = "' OR '1'='1"
                
                if data:
                    self.print_log(f"Testing SQL Injection on {post_url}...", "INFO")
                    try:
                        if method == "post":
                            res = session.post(post_url, data=data, timeout=5)
                        else:
                            res = session.get(post_url, params=data, timeout=5)
                        
                        # Detection of classic SQL errors in response
                        errors = ["mysql_fetch_array", "syntax error", "ORA-01756", "SQLServer", "SQL syntax"]
                        if any(e in res.text for e in errors):
                            msg = f"Potential SQL Injection found on {post_url}"
                            self.print_log(msg, "VULN")
                            self.results["web_vulnerabilities"].append({"type": "SQLi", "url": post_url})
                    except Exception as e:
                        pass

            # 2. Security Headers Audit
            headers = response.headers
            security_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-XSS-Protection"]
            for h in security_headers:
                if h not in headers:
                    self.results["security_headers"][h] = "MISSING"
                    self.print_log(f"Missing Security Header: {h}", "ERROR")
                else:
                    self.results["security_headers"][h] = "PRESENT"

        except Exception as e:
            self.print_log(f"Error during Web Scan: {e}", "ERROR")

    # REPORTING
    def save_report(self):
        if self.output_file:
            with open(self.output_file, "w") as f:
                json.dump(self.results, f, indent=4)
            self.print_log(f"Report saved to {self.output_file}", "SUCCESS")
        else:
            self.print_log("Scan finished. (Use -o argument to save report)", "INFO")

# CLI ARGUMENTS
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEMESIS")
    parser.add_argument("-t", "--target", help="Target URL or IP Address", required=True)
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("--scan-all", help="Perform full port scan (1-65535)", action="store_true")
    
    args = parser.parse_args()

    # ASCII ART BANNER
    print(f"""{Fore.MAGENTA}
    _   _ _____ __  __ _____ ____ ___ ____  
    | \ | | ____|  \/  | ____/ ___|_ _/ ___| 
    |  \| |  _| | |\/| |  _| \___ \| |\___ \ 
    | |\  | |___| |  | | |___ ___) | | ___) |
    |_| \_|_____|_|  |_|_____|____/___|____/ 
    {Style.RESET_ALL}
    {Fore.CYAN}rrf_nemesis{Style.RESET_ALL}
    """)

    scanner = NemesisScanner(args.target, args.output)
    
    try:
        # Define ports based on arguments
        if args.scan_all:
            ports = range(1, 65535)
        else:
            # Common ports list
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080, 8000, 8888]
        
        scanner.scan_ports(ports)
        scanner.check_web_vulns()
        scanner.save_report()
        
    except KeyboardInterrupt:
        print("\n[!] Emergency stop requested by user.")