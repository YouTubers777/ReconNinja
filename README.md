<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:00d4ff,100:7c3aed&height=200&section=header&text=ReconNinja&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=v3.0%20%E2%80%94%20Elite%20Recon%20Framework&descSize=20&descAlignY=60&descColor=00d4ff&animation=fadeIn" />

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.1.0-00d4ff?style=for-the-badge&logo=buffer&logoColor=white)](https://github.com/YouTubers777/ReconNinja)
[![License](https://img.shields.io/badge/License-MIT-7c3aed?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](https://github.com/YouTubers777/ReconNinja/blob/main/LICENSE)
[![Stars](https://img.shields.io/github/stars/YouTubers777/ReconNinja?style=for-the-badge&logo=github&color=ff6b6b&logoColor=white)](https://github.com/YouTubers777/ReconNinja/stargazers)
[![Status](https://img.shields.io/badge/Status-Active-22c55e?style=for-the-badge&logo=statuspage&logoColor=white)](https://github.com/YouTubers777/ReconNinja)

<br/>

> **⚡ Automated recon framework for pentesters & bug bounty hunters.**
> Chains 13 phases: subdomain enum → fast port scan → Nmap → httpx → dir brute → Nuclei → AI threat analysis → HTML report.

<br/>

```
⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠️
Unauthorized use against systems you don't own is illegal.
```

<br/>

</div>

---

<div align="center">

## ╔══ WHAT IT DOES ══╗

</div>

<br/>

```
TARGET INPUT
    │
    ▼
╔═══════════════════════════════════════════════════════════════════════╗
║              THE 13-PHASE RECON PIPELINE                             ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║   PHASE 01  ░  Passive Recon       subfinder · amass · crt.sh        ║
║   PHASE 02  ░  Fast Port Scan      RustScan (ulimit 5000)            ║
║   PHASE 03  ░  Masscan Sweep       65535 ports at wire speed         ║
║   PHASE 04  ░  Deep Nmap           Concurrent · per-target dirs      ║
║   PHASE 05  ░  Live Web Detection  httpx · status · tech stack       ║
║   PHASE 06  ░  Dir Brute Force     feroxbuster → ffuf → dirsearch    ║
║   PHASE 07  ░  Tech Fingerprint    WhatWeb + httpx combined          ║
║   PHASE 08  ░  Nikto Web Scan      Headers · misconfigs · CVEs       ║
║   PHASE 09  ░  Nuclei Templates    medium · high · critical          ║
║   PHASE 10  ░  Screenshots         Aquatone → gowitness fallback     ║
║   PHASE 11  ░  AI Threat Analysis  No API key required               ║
║   PHASE 12  ░  Plugins             Auto-discovered from plugins/     ║
║   PHASE 13  ░  Reports             JSON · HTML Dashboard · Markdown  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
    │
    ▼
OUTPUT (reports/target/timestamp/)
```

---

<div align="center">

## ╔══ FEATURE MATRIX ══╗

</div>

<br/>

<div align="center">

| 🔍 Recon | ⚡ Speed | 🛡️ Vuln | 📊 Output |
|:---:|:---:|:---:|:---:|
| subfinder | RustScan | Nuclei JSON | Dark HTML Dashboard |
| amass | Masscan | Nikto | Structured JSON |
| assetfinder | Concurrent Nmap | CVE Banner Check | Markdown Report |
| crt.sh (pure Python) | 20 parallel workers | Plugin Vulns | per-scan scan.log |
| DNS verification | Auto -Pn retry | AI Risk Summary | Live progress bars |
| httpx live probe | Per-target timeout | CVSS severity sort | Color-coded terminal |

</div>

---

<div align="center">

## ╔══ INSTALLATION ══╗

</div>

<br/>

```bash
# Clone the repo
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja

# Install the ONLY required dependency
pip install rich

# Check what's installed
python reconninja.py --check-tools
```

> `rich` is the **only hard requirement**. ReconNinja gracefully skips any tool not found on your system.

<br/>

<details>
<summary><b>⚙️ Install recommended external tools (click to expand)</b></summary>

<br/>

```bash
# ── Core system tools ──────────────────────────────────────────────
sudo apt install nmap masscan nikto whatweb

# ── ProjectDiscovery suite ─────────────────────────────────────────
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── Fuzzing ────────────────────────────────────────────────────────
go install github.com/ffuf/ffuf/v2@latest
pip install dirsearch

# ── Speed ──────────────────────────────────────────────────────────
cargo install rustscan

# ── Passive recon ──────────────────────────────────────────────────
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@master

# ── Screenshots ────────────────────────────────────────────────────
go install github.com/sensepost/gowitness@latest

# ── SecLists (highly recommended) ─────────────────────────────────
sudo apt install seclists
# or: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

</details>

---

<div align="center">

## ╔══ USAGE ══╗

</div>

<br/>

### 🖥️ Interactive Mode

```bash
python reconninja.py
```
Full guided menu — pick your profile, target, and modules interactively.

<br/>

### ⚡ CLI Mode

```bash
# ── Common runs ────────────────────────────────────────────────────────────

# Standard scan (most common)
python reconninja.py -t example.com -p standard -y

# Full automated suite — the whole pipeline
python reconninja.py -t example.com -p full_suite -y

# Web-only (no port scan overhead)
python reconninja.py -t example.com -p web_only -y

# Full ports with AI threat analysis
python reconninja.py -t 10.0.0.1 --all-ports --ai -y

# Scan an entire subnet
python reconninja.py -t 192.168.1.0/24 -p fast -y

# Scan from a list of targets
python reconninja.py -t targets.txt -p standard --threads 10 -y

# Stealth SYN scan (root required)
python reconninja.py -t example.com -p stealth -y

# Thorough — all ports, OS detection, scripts
python reconninja.py -t example.com -p thorough --ai -y
```

<br/>

### 🎛️ All Flags

```
TARGET & PROFILE
  -t / --target          Domain · IP · CIDR · /path/to/list.txt
  -p / --profile         fast · standard · thorough · stealth
                         custom · full_suite · web_only · port_only

NMAP TUNING
  --all-ports            Scan all 65535 ports (-p-)
  --top-ports N          Top N ports (default: 1000)
  --timing T1-T5         Nmap timing (default: T4)
  --threads N            Parallel workers (default: 20)

FEATURE TOGGLES
  --subdomains           Subdomain enumeration
  --rustscan             RustScan pre-sweep
  --httpx                httpx live web detection
  --ferox                Directory brute force
  --masscan              Masscan sweep (root required)
  --nuclei               Nuclei vuln templates
  --nikto                Nikto web scan
  --whatweb              WhatWeb fingerprinting
  --aquatone             Screenshot capture
  --ai                   AI threat analysis

OTHER
  --wordlist-size        small · medium · large (default: medium)
  --masscan-rate N       Packets/sec (default: 5000)
  --output DIR           Output directory (default: reports/)
  --check-tools          Show installed tool status and exit
  -y / --yes             Skip permission prompt (automation mode)
```

---

<div align="center">

## ╔══ SCAN PROFILES ══╗

</div>

<br/>

<div align="center">

| Profile | Ports | Scripts | Noise | Best For |
|:---:|:---:|:---:|:---:|:---:|
| `fast` | top 100 | ✗ | 🟢 Low | Quick triage |
| `standard` | top 1000 | ✅ | 🟡 Medium | Most engagements |
| `thorough` | all 65535 | ✅ + OS | 🔴 High | Deep dives |
| `stealth` | top 1000 | ✗ | 🟢 Minimal | IDS evasion |
| `web_only` | top 1000 | ✅ | 🟡 Medium | Web app testing |
| `port_only` | all | ✗ | 🟡 Medium | Network mapping |
| `full_suite` | configurable | ✅ | 🔴 High | Full engagement |
| `custom` | your choice | your choice | — | Manual control |

</div>

---

<div align="center">

## ╔══ OUTPUT STRUCTURE ══╗

</div>

<br/>

```
📁 reports/
└── 📁 example.com/
    └── 📁 20240101_120000/
        │
        ├── 📄 report.html          ← 🌐 Dark dashboard — open in browser
        ├── 📄 report.json          ← 🤖 Full structured results
        ├── 📄 report.md            ← 📝 Markdown summary
        ├── 📄 scan.log             ← 📋 Full debug log
        ├── 📄 scan_config.json     ← ⚙️  Exact scan settings used
        │
        ├── 📁 subdomains/
        │   ├── subs_subfinder.txt
        │   ├── subs_crt.sh.txt
        │   └── subdomains_merged.txt
        │
        ├── 📁 nmap/
        │   └── 📁 api_example_com/
        │       ├── nmap_*.xml
        │       └── nmap_*.txt
        │
        ├── 📁 httpx/
        ├── 📁 nuclei/
        ├── 📁 dirscan/
        └── 📁 aquatone/            ← or gowitness/
```

The HTML report is a **self-contained dark dashboard** — stats bar, port table, web services, vuln findings sorted by severity, AI analysis section. No server needed. Just open it.

---

<div align="center">

## ╔══ PLUGIN SYSTEM ══╗

</div>

<br/>

ReconNinja auto-discovers every `.py` file inside `plugins/`. Zero config.

```python
# plugins/my_plugin.py

PLUGIN_NAME    = "my_plugin"
PLUGIN_VERSION = "1.0"

def run(target, out_folder, result, config):
    # `result` is a ReconResult — mutate it directly
    # Append to result.nuclei_findings, result.errors, etc.

    from utils.models import VulnFinding
    result.nuclei_findings.append(VulnFinding(
        tool     = PLUGIN_NAME,
        severity = "high",
        title    = "Custom Finding",
        target   = target,
        details  = "Detected by my plugin",
        cve      = "CVE-2024-XXXXX",
    ))
```

A working example ships with the project: `plugins/cve_banner_check.py` — matches live port banners against known-vulnerable version strings.

---

<div align="center">

## ╔══ v2.1 → v3.0 ══╗

</div>

<br/>

<div align="center">

| Feature | v2.1 | v3.0 |
|:---|:---:|:---:|
| Fast port pre-scan | ✗ | ✅ RustScan |
| Live web detection | ✗ | ✅ httpx |
| crt.sh passive recon | ✗ | ✅ pure Python |
| Dir scanner chain | feroxbuster → ffuf | + dirsearch fallback |
| Screenshot fallback | aquatone only | ✅ + gowitness |
| Vuln findings format | raw text lines | ✅ structured (severity · CVE · target) |
| Nuclei output | plain text | ✅ JSON-parsed |
| AI threat analysis | ✗ | ✅ |
| Plugin system | ✗ | ✅ |
| CIDR / list input | ✗ | ✅ |
| Web-only / Port-only profiles | ✗ | ✅ |
| Per-scan log file | ✗ | ✅ scan.log |
| Phase display | ✗ | ✅ named banners |
| Web findings linked to hosts | ✗ | ✅ HostResult.web_urls |

</div>

---

<div align="center">

## ╔══ LEGAL ══╗

</div>

<br/>

<div align="center">

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   This tool is for AUTHORIZED security assessments ONLY.       │
│                                                                 │
│   Always obtain WRITTEN PERMISSION before scanning.            │
│   The authors accept NO liability for misuse or damage.        │
│                                                                 │
│   Scanning without permission is ILLEGAL and may result        │
│   in criminal prosecution under computer fraud laws.           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7c3aed,50:00d4ff,100:0d0d0d&height=120&section=footer" />

**[⭐ Star this repo](https://github.com/YouTubers777/ReconNinja)** · **[🐛 Report a bug](https://github.com/YouTubers777/ReconNinja/issues)** · **[🔧 Submit a plugin](https://github.com/YouTubers777/ReconNinja/pulls)**

*Built for the community · Use responsibly*

</div>
