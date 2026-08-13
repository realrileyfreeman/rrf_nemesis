# RRF Nemesis Master Edition 🛡️

**RRF Nemesis** has evolved from a simple Python CLI scanner into a **Full-Spectrum Application Security Platform**. It now includes both **DAST** (Dynamic Application Security Testing) and **SAST** (Static Application Security Testing) capabilities, all wrapped in a sleek, modern, and highly professional React Dashboard.

This project is tailored for advanced Cybersecurity / GRC environments.

## ✨ Key Features

### 1. Dynamic Web Scanning (DAST)
- **Headless Browser Engine (Playwright):** Capable of auditing modern Single Page Applications (React, Vue, Angular) by rendering full JavaScript before scanning.
- **Intelligent Fuzzing:** Contextual payload injection for advanced evasion, including Time-Based Blind SQLi detection (`SELECT(SLEEP(5))`) and DOM-based XSS bypasses.
- **Port Scanning & Fingerprinting:** Deep technology stack identification based on HTTP headers and DOM signatures.

### 2. Static Code Analysis (SAST)
- **Universal Scanning (Semgrep):** Replaced basic linters with Semgrep, the industry-standard SAST engine. Capable of finding hardcoded secrets, dangerous functions, and structural vulnerabilities across multiple languages.
- **Local Directory Audit:** Scans local codebases securely before deployment.

### 3. AI-Powered Auto-Fix 🤖
- **Heuristic Remediation Engine:** Finds a vulnerability? Click **"✨ Auto-Fix"**. Nemesis will instantly generate the exact code snippet (Python, JS, SQL, or Bash) required to fix the vulnerability (e.g., Prepared Statements, DOMPurify, Firewall rules).

### 4. GRC Executive Reporting
- **PDF Export:** Transforms the technical "hacker-themed" dashboard into a clean, professional, white-label Executive Report ready to be handed to a CISO or board of directors. Includes high-level KPIs and risk posture analysis.

## 🚀 Installation & Usage

### Prerequisites
- Python 3.12+
- Node.js & npm (for the frontend)
- Chromium browsers for Playwright

### Backend Setup (FastAPI)
```bash
# Clone the repository
git clone https://github.com/realrileyfreeman/rrf_nemesis.git
cd rrf_nemesis

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies (Playwright, Semgrep, FastAPI, etc.)
pip install -r requirements.txt # Or install manually if no requirements.txt is provided yet
playwright install chromium

# Run the API
PYTHONPATH=. uvicorn api:app --host 0.0.0.0 --port 8001
```

### Frontend Setup (React + Vite)
```bash
# In a new terminal
cd rrf_nemesis/frontend
npm install
npm run dev
```
The dashboard will be available at `http://localhost:5174`.

## 🛠️ Tech Stack
- **Backend:** Python 3.12, FastAPI, Playwright, Semgrep, BeautifulSoup4, Requests.
- **Frontend:** React (TypeScript), Vite, TailwindCSS v4, Lucide-React, Recharts.

## 📝 Disclaimer
This tool is intended for educational purposes and authorized auditing only. Usage of RRF Nemesis for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws.
