# RRF NEMESIS - Pentest Scanner
import requests
import socket
import threading
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm

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
            "security_headers": {},
            "discovered_paths": [],
            "technologies": []
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

        # ThreadPoolExecutor for controlled concurrency
        ports = list(ports)
        with ThreadPoolExecutor(max_workers=200) as executor:
            list(tqdm(
                executor.map(thread_scan, ports),
                total=len(ports),
                desc="Scanning ports",
                unit="port"
            ))

    # MODULE 2: WEB FUZZING (SQLi & XSS) AND SECURITY HEADERS CHECK (HEADLESS)
    def check_web_vulns(self):
        if not self.target.startswith("http"):
            self.print_log("Target is not a URL, skipping Web Module.", "ERROR")
            return

        self.print_log("Analyzing Web Vulnerabilities (Headless Playwright)...", "INFO")
        
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(user_agent=USER_AGENT)
                
                # Intercept headers for Security Check
                security_headers_checked = False
                
                def handle_response(response):
                    nonlocal security_headers_checked
                    if not security_headers_checked and response.url.rstrip("/") == self.target.rstrip("/"):
                        headers = response.headers
                        security_headers = ["x-frame-options", "content-security-policy", "strict-transport-security", "x-xss-protection"]
                        for h in security_headers:
                            if h not in headers:
                                self.results["security_headers"][h.upper()] = "MISSING"
                                self.print_log(f"Missing Security Header: {h.upper()}", "ERROR")
                            else:
                                self.results["security_headers"][h.upper()] = "PRESENT"
                        security_headers_checked = True

                page.on("response", handle_response)
                
                # Navigate to target
                try:
                    self.print_log("Loading page in Headless Browser...", "INFO")
                    page.goto(self.target, timeout=15000, wait_until="networkidle")
                except Exception as e:
                    self.print_log(f"Playwright navigation timeout (may still render partially).", "ERROR")

                html_content = page.content()
                browser.close()

            # Now parse the JS-rendered HTML with BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            
            # 1. Forms Audit for XSS/SQLi
            forms = soup.find_all("form")
            self.print_log(f"{len(forms)} forms found in rendered DOM.", "INFO")

            session = requests.Session()
            session.headers.update({'User-Agent': USER_AGENT})

            for form in forms:
                action = form.get("action")
                post_url = urljoin(self.target, action) if action else self.target
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                
                data_keys = [input_tag.get("name") or "q" for input_tag in inputs if input_tag.get("type") in ["text", "search", "password", "email", None]]
                
                if data_keys:
                    # SQL Injection Fuzzing
                    sqli_payloads = [
                        "' OR '1'='1",
                        "admin' --",
                        "1' ORDER BY 1--+",
                        "1' UNION SELECT null,null--+",
                        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)" # Time-based
                    ]
                    
                    self.print_log(f"Fuzzing SQL Injection on {post_url}...", "INFO")
                    for payload in sqli_payloads:
                        data = {k: payload for k in data_keys}
                        try:
                            start_time = time.time()
                            if method == "post":
                                res = session.post(post_url, data=data, timeout=10)
                            else:
                                res = session.get(post_url, params=data, timeout=10)
                            elapsed_time = time.time() - start_time

                            # Detection of classic SQL errors
                            errors = ["mysql_fetch_array", "syntax error", "ORA-01756", "SQLServer", "SQL syntax", "Unclosed quotation mark"]
                            if any(e in res.text for e in errors):
                                self.print_log(f"Potential Error-Based SQLi found on {post_url}", "VULN")
                                self.results["web_vulnerabilities"].append({"type": f"SQLi (Error)", "url": post_url})
                                break # Move to next form if found
                            
                            # Detection of Time-Based SQLi
                            if elapsed_time > 4.5 and "SLEEP" in payload:
                                self.print_log(f"Potential Time-Based SQLi found on {post_url}", "VULN")
                                self.results["web_vulnerabilities"].append({"type": f"SQLi (Time-Based)", "url": post_url})
                                break
                        except Exception:
                            pass

                    # XSS Fuzzing
                    xss_payloads = [
                        "<script>alert('NEMESIS_XSS')</script>",
                        "\"><script>alert('NEMESIS_XSS')</script>",
                        "<img src=x onerror=alert('NEMESIS_XSS')>",
                        "javascript:alert('NEMESIS_XSS')",
                        "'-alert('NEMESIS_XSS')-'"
                    ]
                    
                    self.print_log(f"Fuzzing XSS on {post_url}...", "INFO")
                    for payload in xss_payloads:
                        data = {k: payload for k in data_keys}
                        try:
                            if method == "post":
                                res = session.post(post_url, data=data, timeout=5)
                            else:
                                res = session.get(post_url, params=data, timeout=5)

                            if payload in res.text:
                                self.print_log(f"Potential Reflected XSS found on {post_url}", "VULN")
                                self.results["web_vulnerabilities"].append({"type": f"XSS", "url": post_url})
                                break # Move to next form if found
                        except Exception:
                            pass

        except Exception as e:
            self.print_log(f"Error during Web Scan: {e}", "ERROR")

    # MODULE 3: TECHNOLOGY FINGERPRINTING
    def fingerprint_tech(self):
        if not self.target.startswith("http"):
            self.print_log("Target is not a URL, skipping Fingerprinting.", "ERROR")
            return

        self.print_log("Fingerprinting technologies...", "INFO")
        detected = []

        try:
            session = requests.Session()
            session.headers.update({"User-Agent": USER_AGENT})
            response = session.get(self.target, timeout=5)
            headers = response.headers
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            cookies = {c.name for c in session.cookies}

            # --- HTTP Headers ---
            header_signatures = {
                "Server":       lambda v: v,
                "X-Powered-By": lambda v: v,
                "X-Generator":  lambda v: v,
                "X-Drupal-Cache": lambda _: "Drupal",
            }
            for header, fn in header_signatures.items():
                val = headers.get(header)
                if val:
                    detected.append({"category": "Server", "name": fn(val), "source": f"Header: {header}"})

            # --- Cookies ---
            cookie_signatures = {
                "PHPSESSID":     "PHP",
                "csrftoken":     "Django",
                "sessionid":     "Django",
                "JSESSIONID":    "Java / Tomcat",
                "ASP.NET_SessionId": "ASP.NET",
                "wp-settings-1": "WordPress",
                "laravel_session": "Laravel",
            }
            for cookie, tech in cookie_signatures.items():
                if cookie in cookies:
                    detected.append({"category": "Framework", "name": tech, "source": f"Cookie: {cookie}"})

            # --- HTML Body ---
            html_signatures = [
                ("WordPress",   'wp-content',           "HTML body"),
                ("WordPress",   'wp-includes',          "HTML body"),
                ("Joomla",      '/components/com_',     "HTML body"),
                ("Drupal",      'Drupal.settings',      "HTML body"),
                ("Laravel",     'laravel',               "HTML meta"),
                ("React",       'react-root',           "HTML body"),
                ("Vue.js",      'data-v-',              "HTML body"),
                ("Angular",     'ng-version',           "HTML body"),
                ("Bootstrap",   'bootstrap.min.css',    "HTML asset"),
                ("jQuery",      'jquery.min.js',        "HTML asset"),
            ]
            for tech, marker, source in html_signatures:
                if marker in html:
                    detected.append({"category": "CMS/Framework", "name": tech, "source": source})

            # --- Meta generator tag ---
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            if meta_gen and meta_gen.get("content"):
                detected.append({"category": "Generator", "name": meta_gen["content"], "source": "Meta generator"})

            # Deduplicate by name
            seen = set()
            unique = []
            for item in detected:
                if item["name"] not in seen:
                    seen.add(item["name"])
                    unique.append(item)
                    self.print_log(f"[{item['category']}] {item['name']}  ← {item['source']}", "SUCCESS")

            self.results["technologies"] = unique
            if not unique:
                self.print_log("No technologies identified.", "INFO")

        except Exception as e:
            self.print_log(f"Error during fingerprinting: {e}", "ERROR")

    # MODULE 4: DIRECTORY BRUTEFORCING
    DEFAULT_WORDLIST = [
        # Common admin & config
        "admin", "administrator", "login", "dashboard", "panel",
        "config", "configuration", "settings", "setup", "install",
        # Sensitive files
        ".env", ".git", ".htaccess", ".htpasswd", "web.config",
        "config.php", "config.yml", "config.json", "database.yml",
        # Backup & logs
        "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql",
        "logs", "log", "error.log", "access.log",
        # Common paths
        "api", "api/v1", "api/v2", "uploads", "upload", "files",
        "images", "static", "assets", "css", "js",
        "wp-admin", "wp-login.php", "wp-config.php",
        "phpmyadmin", "pma", "mysql", "adminer.php",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "readme.txt", "README.md", "CHANGELOG.md", "LICENSE",
        "server-status", "server-info",
    ]

    def brute_force_dirs(self, wordlist=None):
        if not self.target.startswith("http"):
            self.print_log("Target is not a URL, skipping Directory Bruteforce.", "ERROR")
            return

        paths = wordlist if wordlist else self.DEFAULT_WORDLIST
        base_url = self.target.rstrip("/")
        self.print_log(f"Starting directory bruteforce ({len(paths)} paths)...", "INFO")

        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})

        def check_path(path):
            url = f"{base_url}/{path}"
            try:
                res = session.get(url, timeout=5, allow_redirects=False)
                if res.status_code in (200, 201, 301, 302, 403):
                    status = res.status_code
                    with self.lock:
                        color = Fore.GREEN if status == 200 else Fore.YELLOW
                        print(f"{color}[+] [{status}] {url}")
                        self.results["discovered_paths"].append({"url": url, "status": status})
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            list(tqdm(
                executor.map(check_path, paths),
                total=len(paths),
                desc="Bruteforcing dirs",
                unit="path"
            ))

        found = len(self.results["discovered_paths"])
        self.print_log(f"Directory bruteforce complete. {found} path(s) found.", "SUCCESS" if found else "INFO")

    # REPORTING
    def save_report(self):
        if not self.output_file:
            self.print_log("Scan finished. (Use -o argument to save report)", "INFO")
            return

        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        self.print_log(f"Report saved to {self.output_file}", "SUCCESS")

# CLI ARGUMENTS
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEMESIS")
    parser.add_argument("-t", "--target", help="Target URL or IP Address", required=True)
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("--scan-all", help="Perform full port scan (1-65535)", action="store_true")
    parser.add_argument("--wordlist", help="Path to a custom wordlist file for directory bruteforce")
    
    args = parser.parse_args()

    # ASCII ART BANNER
    print(f"""{Fore.MAGENTA}
  ____  ____  _____   _   _ _____ __  __ _____ ____ ___ ____
 |  _ \|  _ \|  ___| | \ | | ____|  \/  | ____/ ___|_ _/ ___|
 | |_) | |_) | |_    |  \| |  _| | |\/| |  _| \___ \| |\___ \
 |  _ <|  _ <|  _|   | |\  | |___| |  | | |___ ___) | | ___) |
 |_| \_\_| \_\_|     |_| \_|_____|_|  |_|_____|____/___|____/
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
        scanner.fingerprint_tech()
        scanner.check_web_vulns()

        # Load custom wordlist if provided, otherwise use built-in default
        custom_wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, "r") as f:
                    custom_wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[!] Could not load wordlist: {e}")
        scanner.brute_force_dirs(custom_wordlist)

        scanner.save_report()
        
    except KeyboardInterrupt:
        print("\n[!] Emergency stop requested by user.")