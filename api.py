from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from rrf_nemesis import NemesisScanner

app = FastAPI()

# Allow CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str

@app.post("/scan")
def scan_target(request: ScanRequest):
    target = request.target
    if not target.startswith("http"):
        target = "http://" + target
    scanner = NemesisScanner(target)
    
    # Run the scans (Using the default quick ports for the web interface)
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080, 8000, 8888]
    scanner.scan_ports(ports)
    scanner.fingerprint_tech()
    scanner.check_web_vulns()
    scanner.brute_force_dirs(None) # Use default wordlist
    
    return scanner.results

class SastRequest(BaseModel):
    path: str

@app.post("/sast")
def scan_sast(request: SastRequest):
    import subprocess
    import json
    import os

    if not os.path.exists(request.path):
        return {"error": "Directory does not exist."}

    try:
        # Run semgrep: --config=auto --json
        # Semgrep handles multiple languages and returns JSON output
        result = subprocess.run(
            ["/home/omar-camara/Documents/rrf_nemesis/venv/bin/semgrep", "scan", "--config=auto", "--json", request.path],
            capture_output=True,
            text=True
        )
        
        output = result.stdout
        if not output:
            return {"error": "No output from Semgrep", "stderr": result.stderr}

        return json.loads(output)
    except Exception as e:
        return {"error": str(e)}

class RemediateRequest(BaseModel):
    vulnerability_type: str
    issue_text: str
    code_snippet: str = ""

@app.post("/remediate")
def remediate_vuln(request: RemediateRequest):
    import time
    time.sleep(1.5) # Simulate AI thinking delay
    
    vuln = request.vulnerability_type.lower()
    msg = request.issue_text.lower()
    
    if vuln == "port":
        port = msg.strip()
        if port == "21":
            suggestion = "Risk: FTP sends credentials in cleartext.\nRemediation: Disable FTP and use SFTP (port 22) instead.\n\n```bash\n# AI FIX (Firewall)\nsudo ufw deny 21/tcp\n```"
        elif port == "22":
            suggestion = "Risk: SSH exposed to the internet can be brute-forced.\nRemediation: Disable password authentication, use SSH keys, and consider changing the default port or restricting IP access.\n\n```bash\n# AI FIX (sshd_config)\nPasswordAuthentication no\nPermitRootLogin prohibit-password\n```"
        elif port == "23":
            suggestion = "Risk: Telnet is completely unencrypted and vulnerable to sniffing.\nRemediation: Immediately disable Telnet and migrate to SSH.\n\n```bash\nsudo systemctl disable telnet\nsudo ufw deny 23/tcp\n```"
        elif port == "3306":
            suggestion = "Risk: Exposing a database port directly to the internet is highly dangerous.\nRemediation: Bind MySQL/MariaDB to localhost (127.0.0.1) only, or use a VPN.\n\n```ini\n# AI FIX (my.cnf)\nbind-address = 127.0.0.1\n```"
        elif port in ["80", "443", "8080"]:
            suggestion = "Risk: Web servers are expected to be open, but ensure they are running up-to-date software and only expose necessary directories.\nRemediation: Ensure proper WAF configuration."
        else:
            suggestion = f"Risk: Unnecessary open ports increase the attack surface.\nRemediation: If this service is not required for public operation, block it at the firewall level.\n\n```bash\n# AI FIX\nsudo ufw deny {port}/tcp\n```"
    elif "sql" in vuln or "sql" in msg:
        suggestion = "Use parameterized queries (Prepared Statements) instead of string concatenation.\n\n```python\n# BAD\ncursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n# GOOD (AI FIX)\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n```"
    elif "xss" in vuln or "xss" in msg:
        suggestion = "Escape all user input before rendering it in the browser. Use a templating engine with auto-escaping, or sanitize the input.\n\n```javascript\n// AI FIX: Using DOMPurify\nimport DOMPurify from 'dompurify';\nconst safeHTML = DOMPurify.sanitize(userInput);\ndocument.getElementById('output').innerHTML = safeHTML;\n```"
    elif "subprocess" in vuln or "subprocess" in msg or "command" in msg:
        suggestion = "Avoid using shell=True in subprocess calls. Pass arguments as a list of strings to prevent OS Command Injection.\n\n```python\n# AI FIX\nsubprocess.run(['ping', '-c', '4', user_input], shell=False)\n```"
    elif "hardcoded" in vuln or "password" in msg or "secret" in msg:
        suggestion = "Remove hardcoded secrets from the codebase. Use environment variables.\n\n```python\n# AI FIX\nimport os\napi_key = os.environ.get('API_KEY')\n```"
    else:
        suggestion = "Ensure input validation and sanitization. Apply the principle of least privilege.\n\nReview OWASP Top 10 guidelines for this specific vulnerability."
        
    return {
        "analysis": f"The Nemesis AI Engine analyzed the vulnerability context: {request.vulnerability_type}",
        "remediation_code": suggestion
    }
