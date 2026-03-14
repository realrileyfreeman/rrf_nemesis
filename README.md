# RRF NEMESIS — Advanced Pentest Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Educational](https://img.shields.io/badge/Use-Educational%20Only-red)

---

> **FR** — Outil de reconnaissance et d'audit de sécurité modulaire, conçu à des fins éducatives.
> **EN** — Modular security reconnaissance and auditing tool, designed for educational purposes.

---

## Disclaimer / Avertissement

**FR** : Cet outil est destiné **uniquement** à des fins éducatives et à des audits de sécurité **autorisés**. L'utilisation sur des systèmes sans autorisation explicite est illégale. L'auteur décline toute responsabilité en cas d'utilisation abusive.

**EN** : This tool is intended **exclusively** for educational purposes and **authorized** security audits. Using it against systems without explicit permission is illegal. The author takes no responsibility for any misuse.

---

## Fonctionnalités / Features

| Module | FR | EN |
|---|---|---|
| **Scan de ports** | Scan TCP multi-threadé (ThreadPoolExecutor) avec banner grabbing | Multi-threaded TCP port scan with banner grabbing |
| **Fingerprinting** | Détection de technologies (serveur, CMS, frameworks, cookies) | Technology detection (server, CMS, frameworks, cookies) |
| **Web Fuzzing** | Détection SQLi et XSS réfléchi sur les formulaires | SQLi and reflected XSS detection on forms |
| **Headers Audit** | Vérification des headers de sécurité HTTP | HTTP security headers audit |
| **Dir Bruteforce** | Recherche de fichiers/dossiers cachés avec wordlist | Hidden files/directories discovery with wordlist |
| **Rapport HTML/JSON** | Export du rapport en HTML (dark theme) ou JSON | Report export in HTML (dark theme) or JSON |

---

## Installation

```bash
git clone https://github.com/realrileyfreeman/rrf_nemesis.git
cd rrf_nemesis
pip install -r requirements.txt
```

---

## Utilisation / Usage

**Scan basique / Basic scan :**
```bash
python3 rrf_nemesis.py -t http://target.com
```

**Scan complet avec rapport HTML / Full scan with HTML report :**
```bash
python3 rrf_nemesis.py -t http://target.com --scan-all -o report.html
```

**Avec wordlist personnalisée / With custom wordlist :**
```bash
python3 rrf_nemesis.py -t http://target.com --wordlist /path/to/wordlist.txt -o report.json
```

### Arguments

| Argument | Description |
|---|---|
| `-t`, `--target` | URL ou adresse IP cible / Target URL or IP |
| `-o`, `--output` | Fichier de sortie `.json` ou `.html` / Output file `.json` or `.html` |
| `--scan-all` | Scan complet des ports 1–65535 / Full port scan 1–65535 |
| `--wordlist` | Wordlist personnalisée pour le bruteforce / Custom wordlist for bruteforce |

---

## Architecture

```
NemesisScanner
├── scan_ports()          — TCP scan (ThreadPoolExecutor, max 200 workers)
├── fingerprint_tech()    — Détection de technologies
├── check_web_vulns()     — SQLi + XSS + Security Headers
├── brute_force_dirs()    — Directory bruteforce (max 20 workers)
└── save_report()         — Export JSON ou HTML
```

---

## Dépendances / Dependencies

```
requests
beautifulsoup4
colorama
tqdm
```

---

## Licence / License

MIT — Free to use for educational and authorized testing purposes.
