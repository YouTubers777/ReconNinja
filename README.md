<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
```

**v3.0** · Python · MIT License

⚡ Automated recon framework for pentesters & bug bounty hunters.  
Chains 13 phases: subdomain enum → fast port scan → Nmap → httpx → dir brute → Nuclei → AI threat analysis → HTML report.

![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.0.0-blueviolet?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

> ⚠️ **For authorized penetration testing only. Unauthorized use is illegal.**

</div>

---

## What is ReconNinja?

ReconNinja is a modular, fully automated recon framework that chains every phase of a real-world engagement into a single command. Built for bug bounty hunters and pentesters who want speed, structure, and professional-grade output without stitching together ten different tools manually.

It starts passive, gets active, finds web services, bruteforces directories, runs vuln templates, and finishes with an AI-generated threat summary — all in one run.

---

## Features

| | |
|---|---|
| 🔍 **Passive Recon** | subfinder, amass, assetfinder, crt.sh (pure Python, no install needed) |
| ⚡ **Fast Port Scan** | RustScan pre-sweep feeds discovered ports directly into Nmap |
| 🔬 **Deep Analysis** | Nmap concurrent scanning with per-target subdirectories |
| 🌍 **Web Detection** | httpx live probing with status, title, tech stack, server |
| 📂 **Dir Brute Force** | feroxbuster → ffuf → dirsearch (auto-fallback chain) |
| 🧬 **Tech Fingerprint** | WhatWeb + httpx combined |
| 🛡️ **Vuln Scanning** | Nuclei medium/high/critical templates with structured JSON output |
| 📸 **Screenshots** | Aquatone with gowitness fallback |
| 🤖 **AI Analysis** | Rule-based threat summary — no API key required |
| ⚙️ **Plugin System** | Drop any `.py` into `plugins/` to extend automatically |
| 📊 **Reports** | JSON + dark HTML dashboard + Markdown |

---

## Pipeline

```
Target (domain / IP / CIDR / list.txt)
        │
        ▼
┌─────────────────────────────────────┐
│  Phase 1   Passive Recon            │  subfinder · amass · crt.sh
│  Phase 2   Fast Port Discovery      │  RustScan
│  Phase 3   Masscan Sweep            │  (optional, root required)
│  Phase 4   Deep Service Analysis    │  Nmap (concurrent)
│  Phase 5   Live Web Detection       │  httpx
│  Phase 6   Directory Brute Force    │  feroxbuster / ffuf / dirsearch
│  Phase 7   Tech Fingerprinting      │  WhatWeb
│  Phase 8   Web Vulnerability Scan   │  Nikto
│  Phase 9   Nuclei Templates         │  medium · high · critical
│  Phase 10  Screenshots              │  Aquatone / gowitness
│  Phase 11  AI Threat Analysis       │  built-in engine
│  Phase 12  Plugins                  │  auto-discovered
│  Phase 13  Reports                  │  JSON · HTML · Markdown
└─────────────────────────────────────┘
```

---

## Installation

```bash
git clone https://github.com/YouTubers777/ReconNinja/
cd ReconNinja
pip install pip install -r requirements.txt
```

That's it. `rich` is the **only required dependency**. Every external tool is optional — ReconNinja gracefully skips anything not installed.

### Recommended tools (install as many as you have)

```bash
# Core
sudo apt install nmap masscan nikto whatweb

# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Rust
cargo install rustscan

# Screenshots
go install github.com/sensepost/gowitness@latest
```

---

## Usage

### Interactive mode
```bash
python reconninja.py
```
Walks you through target, profile, and module selection with prompts.

### CLI mode

```bash
# Standard scan
python reconninja.py -t example.com -p standard -y

# Full automated suite
python reconninja.py -t example.com -p full_suite -y

# Web-only (no port scan)
python reconninja.py -t example.com -p web_only -y

# All ports with AI analysis
python reconninja.py -t 10.0.0.1 --all-ports --ai -y

# Scan from a target list
python reconninja.py -t targets.txt -p standard --threads 10 -y

# CIDR range
python reconninja.py -t 192.168.1.0/24 -p fast -y

# Check which tools are installed
python reconninja.py --check-tools
```

### All flags

```
-t / --target          Domain, IP, CIDR, or path to list file
-p / --profile         fast · standard · thorough · stealth · custom · full_suite · web_only · port_only
--all-ports            Scan all 65535 ports
--top-ports N          Scan top N ports (default: 1000)
--timing T1-T5         Nmap timing template (default: T4)
--threads N            Parallel nmap workers (default: 20)
--subdomains           Enable subdomain enumeration
--rustscan             Enable RustScan pre-scan
--httpx                Enable httpx web detection
--ferox                Enable directory brute force
--masscan              Enable Masscan sweep (root required)
--nuclei               Enable Nuclei vuln scan
--nikto                Enable Nikto web scan
--whatweb              Enable WhatWeb fingerprinting
--aquatone             Enable screenshot capture
--ai                   Enable AI threat analysis
--wordlist-size        small · medium · large (default: medium)
--masscan-rate N       Masscan packets/sec (default: 5000)
--output DIR           Output directory (default: reports/)
-y / --yes             Skip permission confirmation (for automation)
```

---

## Profiles

| Profile | Ports | Scripts | Speed | Best For |
|---|---|---|---|---|
| `fast` | top 100 | ✗ | ⚡⚡⚡ | Quick sweep |
| `standard` | top 1000 | ✅ | ⚡⚡ | Most engagements |
| `thorough` | all 65535 | ✅ + OS | ⚡ | Deep dives |
| `stealth` | top 1000 | ✗ | ⚡ | Low-noise testing |
| `web_only` | top 1000 | ✅ | ⚡⚡ | Web app focus |
| `port_only` | all | ✗ | ⚡⚡ | Network mapping |
| `full_suite` | configurable | ✅ | varies | Full engagement |
| `custom` | your choice | your choice | — | Manual control |

---

## Output

```
reports/
└── example.com/
    └── 20240101_120000/
        ├── scan_config.json
        ├── scan.log
        ├── report.json          ← full structured results
        ├── report.html          ← dark dashboard (open in browser)
        ├── report.md            ← markdown summary
        ├── subdomains/
        ├── nmap/
        ├── httpx/
        ├── nuclei/
        ├── dirscan/
        └── aquatone/
```

The HTML report is a self-contained dark dashboard with a stats bar, port table, web service table, vuln findings sorted by severity, and the AI analysis section — no server needed, just open it in a browser.

---

## Plugin System

ReconNinja auto-discovers any `.py` file dropped into the `plugins/` folder. The contract is minimal:

```python
PLUGIN_NAME    = "my_plugin"
PLUGIN_VERSION = "1.0"

def run(target, out_folder, result, config):
    # result is a ReconResult — mutate it directly
    # Append to result.nuclei_findings, result.errors, etc.
    pass
```

A working example (`plugins/cve_banner_check.py`) ships with the project — it matches open port banners against a list of known-vulnerable version strings and injects `VulnFinding` objects into the results.

---

## v3 vs v2.1

| | v2.1 | v3.0 |
|---|---|---|
| Fast port pre-scan | ✗ | ✅ RustScan |
| Live web detection | ✗ | ✅ httpx |
| crt.sh passive recon | ✗ | ✅ pure Python |
| Dir scanner fallbacks | 2 | 3 (+ dirsearch) |
| Screenshot fallback | aquatone only | ✅ + gowitness |
| Vuln findings | raw text | ✅ structured (severity, CVE, target) |
| AI analysis | ✗ | ✅ |
| Plugin system | ✗ | ✅ |
| CIDR / list input | ✗ | ✅ |
| Web-only / Port-only profiles | ✗ | ✅ |
| Per-scan log file | ✗ | ✅ |
| Nuclei output | plain text | ✅ JSON-parsed |

---

## Legal

This tool is intended for **authorized security assessments only**. Always obtain written permission before scanning any target. The authors are not responsible for misuse or damage caused by this tool.

Using ReconNinja against targets without explicit permission is **illegal** and may result in criminal prosecution.

---

<div align="center">
Built for the community · Use responsibly
</div>
