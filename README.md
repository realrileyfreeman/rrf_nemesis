# RRF NEMESIS - Advanced Pentest Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

**NEMESIS** is a modular security auditing tool designed for reconnaissance and vulnerability scanning. It combines network scanning, banner grabbing, and web fuzzing into a single object-oriented framework.

## Disclaimer
This tool is intended for **educational purposes** and **authorized security audits only**. I am not responsible for any isuse.

## Features
* **Network Recon**: Multi-threaded port scanning with service banner grabbing.
* **Web Fuzzing**: Automated detection of basic SQL Injections (SQLi).
* **Security Audit**: Checks for missing HTTP security headers (XSS, Clickjacking protection).
* **Reporting**: Generates full JSON reports for analysis.

## Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/realrileyfreeman/rrf_nemesis.git](https://github.com/realrileyfreeman/rrf_nemesis.git)
   cd nemesis

2. Install dependencies:
   ```bash
   pip install -t requirements.txt

**Usage**
Basic Scan:

python3 nemesis.py -t [http://target.com](http://target.com)
Full Port Scan & Output to JSON:

Bash
python3 nemesis.py -t 192.168.1.15 --scan-all -o report.json

**Modules Structure**
The tool is built with a modular OOP architecture:
NemesisScanner Class: Core engine.
scan_ports(): Threaded TCP connect scan.
check_web_vulns(): Beautiful Soup crawling & fuzzing.# rrf_nemesis
# rrf_nemesis
# rrf_nemesis
