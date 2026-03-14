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
                    except Exception:
                        pass

                    # XSS Test: inject a unique marker and check if it's reflected unescaped
                    XSS_PAYLOAD = "<script>alert('NEMESIS_XSS')</script>"
                    xss_data = {k: XSS_PAYLOAD for k in data}
                    self.print_log(f"Testing XSS on {post_url}...", "INFO")
                    try:
                        if method == "post":
                            res = session.post(post_url, data=xss_data, timeout=5)
                        else:
                            res = session.get(post_url, params=xss_data, timeout=5)

                        if XSS_PAYLOAD in res.text:
                            msg = f"Potential Reflected XSS found on {post_url}"
                            self.print_log(msg, "VULN")
                            self.results["web_vulnerabilities"].append({"type": "XSS", "url": post_url})
                    except Exception:
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

        if self.output_file.endswith(".html"):
            self._save_html_report()
        else:
            with open(self.output_file, "w") as f:
                json.dump(self.results, f, indent=4)
            self.print_log(f"Report saved to {self.output_file}", "SUCCESS")

    def _save_html_report(self):
        r = self.results
        vuln_count = len(r["web_vulnerabilities"])
        port_count = len(r["open_ports"])
        path_count = len(r["discovered_paths"])
        missing_headers = [h for h, v in r["security_headers"].items() if v == "MISSING"]

        def _ports_rows():
            if not r["open_ports"]:
                return '<tr><td colspan="2" class="empty">No open ports found</td></tr>'
            return "".join(
                f'<tr><td><span class="badge badge-open">{p["port"]}</span></td>'
                f'<td class="banner">{p["banner"] or "—"}</td></tr>'
                for p in r["open_ports"]
            )

        def _vulns_rows():
            if not r["web_vulnerabilities"]:
                return '<tr><td colspan="2" class="empty">No vulnerabilities found</td></tr>'
            return "".join(
                f'<tr><td><span class="badge badge-vuln">{v["type"]}</span></td>'
                f'<td class="banner">{v["url"]}</td></tr>'
                for v in r["web_vulnerabilities"]
            )

        def _headers_rows():
            if not r["security_headers"]:
                return '<tr><td colspan="2" class="empty">No data</td></tr>'
            return "".join(
                f'<tr><td>{h}</td>'
                f'<td><span class="badge {"badge-open" if v == "PRESENT" else "badge-vuln"}">{v}</span></td></tr>'
                for h, v in r["security_headers"].items()
            )

        def _tech_rows():
            if not r["technologies"]:
                return '<tr><td colspan="3" class="empty">No technologies identified</td></tr>'
            return "".join(
                f'<tr><td><span class="badge badge-warn">{t["category"]}</span></td>'
                f'<td>{t["name"]}</td>'
                f'<td class="banner">{t["source"]}</td></tr>'
                for t in r["technologies"]
            )

        def _paths_rows():
            if not r["discovered_paths"]:
                return '<tr><td colspan="2" class="empty">No paths found</td></tr>'
            color_map = {200: "badge-open", 403: "badge-warn", 301: "badge-warn", 302: "badge-warn", 201: "badge-open"}
            return "".join(
                f'<tr><td><span class="badge {color_map.get(p["status"], "badge-warn")}">{p["status"]}</span></td>'
                f'<td class="banner">{p["url"]}</td></tr>'
                for p in r["discovered_paths"]
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NEMESIS Report — {r["target"]}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }}
    header {{ background: linear-gradient(135deg, #6e40c9, #1f6feb); padding: 2rem; text-align: center; }}
    header h1 {{ font-size: 2rem; letter-spacing: 4px; color: #fff; }}
    header p {{ margin-top: .4rem; color: #ccc; font-size: .9rem; }}
    .summary {{ display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }}
    .card {{ flex: 1; min-width: 150px; background: #161b22; border: 1px solid #30363d;
             border-radius: 8px; padding: 1.2rem; text-align: center; }}
    .card .num {{ font-size: 2.2rem; font-weight: 700; }}
    .card .label {{ font-size: .8rem; color: #8b949e; margin-top: .3rem; text-transform: uppercase; }}
    .num.danger {{ color: #f85149; }}
    .num.warn {{ color: #e3b341; }}
    .num.ok {{ color: #3fb950; }}
    section {{ margin: 0 2rem 2rem; }}
    section h2 {{ font-size: 1rem; text-transform: uppercase; letter-spacing: 2px;
                  color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: .5rem; margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22;
             border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
    th {{ background: #21262d; color: #8b949e; font-size: .75rem; text-transform: uppercase;
          letter-spacing: 1px; padding: .7rem 1rem; text-align: left; }}
    td {{ padding: .65rem 1rem; border-top: 1px solid #21262d; font-size: .875rem; }}
    td.banner {{ font-family: monospace; word-break: break-all; color: #a5d6ff; }}
    td.empty {{ text-align: center; color: #484f58; padding: 1.5rem; }}
    .badge {{ display: inline-block; padding: .2em .6em; border-radius: 4px;
              font-size: .78rem; font-weight: 600; font-family: monospace; }}
    .badge-open {{ background: #1f4b2e; color: #3fb950; }}
    .badge-vuln {{ background: #3d1c1c; color: #f85149; }}
    .badge-warn {{ background: #3d2e00; color: #e3b341; }}
    footer {{ text-align: center; padding: 1.5rem; color: #484f58; font-size: .8rem; }}
  </style>
</head>
<body>
  <header>
    <h1>N E M E S I S</h1>
    <p>Security Audit Report &nbsp;|&nbsp; Target: <strong>{r["target"]}</strong> &nbsp;|&nbsp; {r["scan_time"]}</p>
  </header>

  <div class="summary">
    <div class="card"><div class="num {'danger' if port_count else 'ok'}">{port_count}</div><div class="label">Open Ports</div></div>
    <div class="card"><div class="num {'danger' if vuln_count else 'ok'}">{vuln_count}</div><div class="label">Vulnerabilities</div></div>
    <div class="card"><div class="num {'warn' if missing_headers else 'ok'}">{len(missing_headers)}</div><div class="label">Missing Headers</div></div>
    <div class="card"><div class="num {'warn' if path_count else 'ok'}">{path_count}</div><div class="label">Exposed Paths</div></div>
  </div>

  <section>
    <h2>Open Ports</h2>
    <table><thead><tr><th>Port</th><th>Banner</th></tr></thead>
    <tbody>{_ports_rows()}</tbody></table>
  </section>

  <section>
    <h2>Technologies Detected</h2>
    <table><thead><tr><th>Category</th><th>Technology</th><th>Source</th></tr></thead>
    <tbody>{_tech_rows()}</tbody></table>
  </section>

  <section>
    <h2>Web Vulnerabilities</h2>
    <table><thead><tr><th>Type</th><th>URL</th></tr></thead>
    <tbody>{_vulns_rows()}</tbody></table>
  </section>

  <section>
    <h2>Security Headers</h2>
    <table><thead><tr><th>Header</th><th>Status</th></tr></thead>
    <tbody>{_headers_rows()}</tbody></table>
  </section>

  <section>
    <h2>Discovered Paths</h2>
    <table><thead><tr><th>Code</th><th>URL</th></tr></thead>
    <tbody>{_paths_rows()}</tbody></table>
  </section>

  <footer>Generated by NEMESIS Security Scanner — Educational use only</footer>
</body>
</html>"""

        with open(self.output_file, "w") as f:
            f.write(html)
        self.print_log(f"HTML report saved to {self.output_file}", "SUCCESS")

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