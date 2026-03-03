<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:00d4ff,100:7c3aed&height=200&section=header&text=ReconNinja&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=v3.1%20%E2%80%94%20Elite%20Recon%20Framework&descSize=20&descAlignY=60&descColor=00d4ff&animation=fadeIn" />

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.1.0-00d4ff?style=for-the-badge&logo=buffer&logoColor=white)](https://github.com/YouTubers777/ReconNinja)
[![License](https://img.shields.io/badge/License-MIT-7c3aed?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](https://github.com/YouTubers777/ReconNinja/blob/main/LICENSE)
[![Stars](https://img.shields.io/github/stars/YouTubers777/ReconNinja?style=for-the-badge&logo=github&color=ff6b6b&logoColor=white)](https://github.com/YouTubers777/ReconNinja/stargazers)
[![Status](https://img.shields.io/badge/Status-Active-22c55e?style=for-the-badge&logo=statuspage&logoColor=white)](https://github.com/YouTubers777/ReconNinja)

<br/>

> **⚡ Automated recon framework for pentesters & bug bounty hunters.**
> Chains 14 phases: subdomain enum → **async TCP scan** → RustScan → Nmap → httpx → dir brute → Nuclei → AI threat analysis → HTML report.

<br/>

```
⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠️
Unauthorized use against systems you don't own is illegal.
```

<br/>

</div>

---

<div align="center">

## ╔══ WHAT'S NEW IN v3.1 ══╗

</div>

<br/>

<div align="center">

| | Feature | Details |
|:---:|:---|:---|
| 🆕 | **Built-in Async TCP Scanner** | Pure Python asyncio — no root, no external tools needed |
| 🆕 | **Banner Grabbing** | Instant service hints on open ports before Nmap runs |
| 🆕 | **Surgical Nmap** | Nmap only deep-scans confirmed-open ports — dramatically faster |
| 🆕 | **`--async-concurrency`** | Tune simultaneous TCP probes (default: 1000) |
| 🆕 | **`--async-timeout`** | Per-connect timeout in seconds (default: 1.5s) |
| 🔧 | **RustScan now merges** | Union of async + RustScan results for maximum coverage |
| 🐛 | **Masscan rate crash fixed** | `int("y")` ValueError on non-numeric input |
| 🐛 | **Full Suite nmap builder** | No longer triggers confusing custom nmap prompt |

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
║              THE 14-PHASE RECON PIPELINE                              ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║   PHASE 01  ░  Passive Recon         subfinder · amass · crt.sh       ║
║   PHASE 02  ░  Async TCP Scan  🆕    asyncio · banner grab · no root  ║
║   PHASE 02 ░  RustScan               merges with async results        ║
║   PHASE 03  ░  Masscan Sweep          65535 ports at wire speed       ║
║   PHASE 04  ░  Deep Nmap              surgical · confirmed ports only ║
║   PHASE 05  ░  Live Web Detection     httpx · status · tech stack     ║
║   PHASE 06  ░  Dir Brute Force        feroxbuster → ffuf → dirsearch  ║
║   PHASE 07  ░  Tech Fingerprint       WhatWeb + httpx combined        ║
║   PHASE 08  ░  Nikto Web Scan         Headers · misconfigs · CVEs     ║
║   PHASE 09  ░  Nuclei Templates       medium · high · critical        ║
║   PHASE 10  ░  Screenshots            Aquatone → gowitness fallback   ║
║   PHASE 11  ░  AI Threat Analysis     No API key required             ║
║   PHASE 12  ░  Plugins                Auto-discovered from plugins/   ║
║   PHASE 13  ░  Reports                JSON · HTML Dashboard · MD      ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
    │
    ▼
OUTPUT (reports/target/timestamp/)
```

---

<div align="center">

## ╔══ HOW THE ASYNC SCANNER WORKS ══╗

</div>

<br/>

```
For each port (up to 1000 concurrent via asyncio.Semaphore):

  asyncio.open_connection(host, port)   ← full TCP 3-way handshake
    │
    ├── Connection succeeds   →  OPEN      →  banner grab (SSH/HTTP/etc)
    ├── ConnectionRefusedError →  CLOSED   →  RST received, skip
    └── asyncio.TimeoutError  →  FILTERED  →  silently dropped

  Results feed directly into Nmap:
  nmap -sC -sV -p22,80,443,...   ← only confirmed-open ports
  instead of:
  nmap -sC -sV --top-ports 1000  ← scanning hundreds of closed ports
```

> No root required — unlike `-sS` SYN scan which needs raw sockets.
> Equivalent to `nmap -sT` but implemented in pure asyncio for maximum speed.

---

<div align="center">

## ╔══ FEATURE MATRIX ══╗

</div>

<br/>

<div align="center">

| 🔍 Recon | ⚡ Speed | 🛡️ Vuln | 📊 Output |
|:---:|:---:|:---:|:---:|
| subfinder | **Async TCP Scanner** 🆕 | Nuclei JSON | Dark HTML Dashboard |
| amass | RustScan (merged) | Nikto | Structured JSON |
| assetfinder | Masscan | CVE Banner Check | Markdown Report |
| crt.sh (pure Python) | Concurrent Nmap | Plugin Vulns | per-scan scan.log |
| DNS verification | **Banner Grabbing** 🆕 | AI Risk Summary | Live progress bars |
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

# chmod the install.sh file
chmod +x install.sh

# run the install.sh to install
./install.sh
```

> `rich` is the **only hard requirement**. The async TCP scanner is pure Python — zero external tools needed to start scanning.

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

# Tune async scanner for unstable/high-latency networks
python reconninja.py -t 10.0.0.1 --async-concurrency 200 --async-timeout 3.0 -y
```

<br/>

### 🎛️ All Flags

```
TARGET & PROFILE
  -t / --target            Domain · IP · CIDR · /path/to/list.txt
  -p / --profile           fast · standard · thorough · stealth
                           custom · full_suite · web_only · port_only

NMAP TUNING
  --all-ports              Scan all 65535 ports (-p-)
  --top-ports N            Top N ports (default: 1000)
  --timing T1-T5           Nmap timing (default: T4)
  --threads N              Parallel workers (default: 20)

ASYNC TCP SCANNER  🆕
  --async-concurrency N    Simultaneous TCP probes (default: 1000)
  --async-timeout SECS     Connect timeout per port (default: 1.5)

FEATURE TOGGLES
  --subdomains             Subdomain enumeration
  --rustscan               RustScan sweep (merged with async results)
  --httpx                  httpx live web detection
  --ferox                  Directory brute force
  --masscan                Masscan sweep (root required)
  --nuclei                 Nuclei vuln templates
  --nikto                  Nikto web scan
  --whatweb                WhatWeb fingerprinting
  --aquatone               Screenshot capture
  --ai                     AI threat analysis

OTHER
  --wordlist-size          small · medium · large (default: medium)
  --masscan-rate N         Packets/sec (default: 5000)
  --output DIR             Output directory (default: reports/)
  --check-tools            Show installed tool status and exit
  -y / --yes               Skip permission prompt (automation mode)
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
        ├── 📄 report.html            ← 🌐 Dark dashboard — open in browser
        ├── 📄 report.json            ← 🤖 Full structured results
        ├── 📄 report.md              ← 📝 Markdown summary
        ├── 📄 scan.log               ← 📋 Full debug log
        ├── 📄 scan_config.json       ← ⚙️  Exact scan settings used
        │
        ├── 📁 async_scan/  🆕
        │   └── async_scan.txt        ← open ports · banners · timing
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
        └── 📁 aquatone/              ← or gowitness/
```

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

## ╔══ CHANGELOG ══╗

</div>

<br/>

<div align="center">

### v3.1.0

| | Feature | Details |
|:---:|:---|:---|
| 🆕 | Built-in AsyncTCPScanner | asyncio TCP connect scan, equivalent to `nmap -sT` |
| 🆕 | Banner grabbing | SSH, HTTP, FTP, Redis + more — instant service hints |
| 🆕 | Surgical Nmap | Feeds only confirmed-open ports → massive speed boost |
| 🆕 | `--async-concurrency` | Tune probe parallelism for your network |
| 🆕 | `--async-timeout` | Per-connect timeout tuning for high-latency targets |
| 🔧 | RustScan merged | Union of async + RustScan for maximum port coverage |
| 🐛 | Masscan rate crash | Fixed `ValueError: int("y")` on bad input |
| 🐛 | Full Suite nmap | No longer triggers confusing custom nmap builder |

### v3.0.0 → v2.1

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
