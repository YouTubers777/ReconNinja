# ⚡ ReconNinja v3.0

> Elite all-in-one reconnaissance framework.  
> **⚠ Use ONLY against targets you own or have explicit written permission to test.**

---

## What's New in v3

| Feature | v2.1 | v3.0 |
|---|---|---|
| Fast port scan | ✗ | ✅ RustScan |
| Live web detection | ✗ | ✅ httpx |
| Passive subdomain source | subfinder/amass | + crt.sh (no dep) |
| Dir scanners | feroxbuster/ffuf | + dirsearch fallback |
| Screenshot tools | aquatone | + gowitness fallback |
| Vuln findings | raw text | ✅ Structured (severity, CVE, target) |
| AI analysis | ✗ | ✅ Rule-based threat summary |
| Plugin system | ✗ | ✅ Drop .py into plugins/ |
| CIDR / list input | ✗ | ✅ |
| Per-scan log file | ✗ | ✅ scan.log |
| Web/Port-Only profiles | ✗ | ✅ |
| Phase display | ✗ | ✅ Named phase banners |

---

## Installation

```bash
# Python dependency (only required)
pip install rich

# Recommended external tools (install as many as you have)
# Kali / ParrotOS:
sudo apt install nmap masscan nikto whatweb
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/RustScan/RustScan@latest
cargo install rustscan
```

---

## Usage

### Interactive (recommended)
```bash
python reconninja.py
```

### CLI
```bash
# Quick scan
python reconninja.py -t example.com -p standard -y

# Full suite
python reconninja.py -t example.com -p full_suite -y

# Web only
python reconninja.py -t example.com -p web_only --httpx --nuclei -y

# All ports + AI analysis
python reconninja.py -t 10.0.0.1 --all-ports --ai -y

# Scan from list
python reconninja.py -t targets.txt -p standard --threads 10 -y

# Check installed tools
python reconninja.py --check-tools
```

---

## Pipeline

```
Target Input (domain / IP / CIDR / list.txt)
   ↓
Phase 1:  Passive Recon    (subfinder, amass, assetfinder, crt.sh)
   ↓
Phase 2:  Fast Port Scan   (RustScan)
   ↓
Phase 3:  Masscan Sweep    (optional, root required)
   ↓
Phase 4:  Deep Nmap        (concurrent, per-target subdirs)
   ↓
Phase 5:  Web Detection    (httpx)
   ↓
Phase 6:  Dir Brute Force  (feroxbuster → ffuf → dirsearch)
   ↓
Phase 7:  Tech Fingerprint (whatweb)
   ↓
Phase 8:  Nikto Web Scan
   ↓
Phase 9:  Nuclei Templates (medium/high/critical)
   ↓
Phase 10: Screenshots      (aquatone → gowitness)
   ↓
Phase 11: AI Analysis      (rule-based threat summary)
   ↓
Phase 12: Plugins          (auto-discover plugins/*.py)
   ↓
Phase 13: Reports          (JSON + HTML + Markdown)
```

---

## Plugin System

Drop any `.py` file into `plugins/` with this contract:

```python
PLUGIN_NAME    = "my_plugin"
PLUGIN_VERSION = "1.0"

def run(target, out_folder, result, config):
    # target:     str          — scan target
    # out_folder: Path         — scan output directory
    # result:     ReconResult  — mutate in-place
    # config:     ScanConfig   — read-only scan configuration
    pass
```

See `plugins/cve_banner_check.py` for a working example.

---

## Output Structure

```
reports/
└── example.com/
    └── 20240101_120000/
        ├── scan_config.json
        ├── scan.log
        ├── report.json        ← machine-readable full results
        ├── report.html        ← dark dashboard (open in browser)
        ├── report.md          ← markdown summary
        ├── subdomains/
        │   ├── subs_subfinder.txt
        │   ├── subs_crt.sh.txt
        │   └── subdomains_merged.txt
        ├── nmap/
        │   └── api_example_com/
        │       ├── nmap_*.xml
        │       └── nmap_*.txt
        ├── httpx/
        ├── nuclei/
        ├── dirscan/
        └── aquatone/  (or gowitness/)
```

---

## Profiles

| Profile | Ports | Scripts | Speed | Extras |
|---|---|---|---|---|
| fast | top 100 | ✗ | ⚡⚡⚡ | — |
| standard | top 1000 | ✅ | ⚡⚡ | — |
| thorough | all 65535 | ✅ OS | ⚡ | OS detect |
| stealth | top 1000 | ✗ | ⚡ | SYN scan |
| web_only | top 1000 | ✅ | ⚡⚡ | httpx+nuclei |
| port_only | all | ✗ | ⚡⚡ | rustscan+masscan |
| full_suite | configurable | ✅ | varies | everything |
| custom | your choice | your choice | — | — |

---

## Legal

This tool is for **authorized security testing only**.  
Unauthorized scanning is illegal. The authors accept no liability.
