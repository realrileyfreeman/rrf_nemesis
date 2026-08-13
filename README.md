# RRF Nemesis Master Edition 🛡️

*🇬🇧 English version below.*

**RRF Nemesis** a évolué d'un simple scanner en ligne de commande Python vers une **Plateforme de Sécurité Applicative Complète**. Il intègre désormais des capacités **DAST** (Tests de Sécurité Applicative Dynamique) et **SAST** (Analyse Statique de Code), le tout centralisé dans un Dashboard React moderne et professionnel.

Ce projet a été pensé pour des environnements avancés en Cybersécurité et GRC (Gouvernance, Risques et Conformité).

## ✨ Fonctionnalités Principales (FR)

### 1. Scan Web Dynamique (DAST)
- **Moteur Navigateur Headless (Playwright) :** Capable d'auditer les applications modernes (Single Page Applications - React, Vue, Angular) en rendant l'intégralité du JavaScript avant l'analyse.
- **Fuzzing Intelligent :** Injection contextuelle de payloads pour contourner les défenses, incluant la détection de Blind SQLi temporelles (`SELECT(SLEEP(5))`) et de failles XSS basées sur le DOM.
- **Scan de Ports & Fingerprinting :** Identification profonde des technologies de la cible via l'analyse des en-têtes HTTP et du DOM.

### 2. Analyse de Code Statique (SAST)
- **Scan Universel (Semgrep) :** Intégration de Semgrep, le standard industriel de l'analyse statique. Capable de trouver des secrets en dur, des fonctions cryptographiques obsolètes et des failles structurelles à travers de multiples langages de programmation.
- **Audit Local :** Analyse sécurisée du code source en local avant son déploiement.

### 3. Remédiation IA (Auto-Fix) 🤖
- **Moteur Heuristique :** Lorsqu'une vulnérabilité est trouvée, un simple clic sur le bouton **"✨ Auto-Fix"** génère le snippet de code exact (Python, JS, SQL ou Bash) nécessaire pour la corriger (ex: Requêtes préparées, DOMPurify, règles de Pare-feu).

### 4. Reporting Exécutif GRC
- **Export PDF :** Transforme le tableau de bord technique en un rapport exécutif épuré, structuré et professionnel, prêt à être présenté à un RSSI (CISO) ou un comité de direction. Inclut des KPIs de haut niveau et une analyse de la posture de risque.

## 🚀 Installation & Utilisation

### Prérequis
- Python 3.12+
- Node.js & npm (pour le frontend)
- Navigateur Chromium (via Playwright)

### Démarrer le Backend (FastAPI)
```bash
git clone https://github.com/realrileyfreeman/rrf_nemesis.git
cd rrf_nemesis

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium

PYTHONPATH=. uvicorn api:app --host 0.0.0.0 --port 8001
```

### Démarrer le Frontend (React + Vite)
```bash
cd rrf_nemesis/frontend
npm install
npm run dev
```
Le dashboard sera accessible sur `http://localhost:5174`.

---

# RRF Nemesis Master Edition 🛡️ (English)

**RRF Nemesis** has evolved from a simple Python CLI scanner into a **Full-Spectrum Application Security Platform**. It now includes both **DAST** (Dynamic Application Security Testing) and **SAST** (Static Application Security Testing) capabilities, all wrapped in a sleek, modern, and highly professional React Dashboard.

This project is tailored for advanced Cybersecurity / GRC environments.

## ✨ Key Features (EN)

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
git clone https://github.com/realrileyfreeman/rrf_nemesis.git
cd rrf_nemesis

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium

PYTHONPATH=. uvicorn api:app --host 0.0.0.0 --port 8001
```

### Frontend Setup (React + Vite)
```bash
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
