<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:00d4ff,100:7c3aed&height=200&section=header&text=ReconNinja&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=v3.2.1%20%E2%80%94%20Elite%20Recon%20Framework&descSize=20&descAlignY=60&descColor=00d4ff&animation=fadeIn" />

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.2.1-00d4ff?style=for-the-badge&logo=buffer&logoColor=white)](https://github.com/YouTubers777/ReconNinja/releases)
[![Tests](https://img.shields.io/badge/Tests-262%20passing-22c55e?style=for-the-badge&logo=checkmarx&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT-7c3aed?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Stars](https://img.shields.io/github/stars/YouTubers777/ReconNinja?style=for-the-badge&logo=github&color=ff6b6b&logoColor=white)](https://github.com/YouTubers777/ReconNinja/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/YouTubers777/ReconNinja/python-package-conda.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/YouTubers777/ReconNinja/actions)

<br/>

> **⚡ Automated all-in-one recon framework for pentesters & bug bounty hunters.**
> 14-phase pipeline: subdomain enum → async TCP → RustScan → Nmap service scan →
> CVE lookup → httpx → dir brute → Nuclei → AI threat analysis → HTML report.

<br/>

```
⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠️
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal. The author is not responsible for misuse.
```

</div>

---

## 📋 Table of Contents

- [What's New in v3.2.1](#-whats-new-in-v321)
- [Features](#-features)
- [Pipeline](#-pipeline)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [AI Analysis](#-ai-analysis)
- [CVE Lookup](#-cve-lookup)
- [HTML Reports](#-html-reports)
- [Resume Scans](#-resume-scans)
- [Self-Update](#-self-update)
- [Scan Profiles](#-scan-profiles)
- [All CLI Flags](#-all-cli-flags)
- [Testing](#-testing)
- [File Structure](#-file-structure)
- [Changelog](#-changelog)
- [Legal](#-legal)

---

## 🆕 What's New in v3.2.1

> Bug fix release. All v3.2.0 features are intact — these are correctness fixes only.

| Fix | Description |
|---|---|
| 🤖 **AI Analysis actually works** | `--ai` flag now correctly calls Groq/Ollama/Gemini/OpenAI via `core/ai_analysis.py`. Previously it silently used a rule-based fallback instead of the real LLM. |
| 🔍 **`--cve` flag added** | README documented `--cve` but argparse only accepted `--cve-lookup`. Both flags now work. CVE lookup phase also now **actually executes** in the pipeline. |
| 🔑 **`--nvd-key` wired** | `--nvd-key` was in the README but missing from argparse and never passed to the CVE lookup module. Now fully wired end-to-end. |
| 💾 **`--resume` no longer crashes** | `orchestrate()` signature mismatch caused an immediate crash on every resume attempt. Fixed — resume now correctly restores state and skips completed phases. |
| ⏱️ **NVD rate limit fixed** | CVE lookup `delay` corrected from `0.7s` → `6.5s`. The old value fired 43 req/30s against a 5 req/30s limit — caused silent 403 failures after the 5th port. |
| 🏷️ **Version banner corrected** | Internal docstring and banner said `v3.0` while `VERSION = "3.2.0"`. Now consistent at `3.2.1`. |
| 🧪 **Tests updated** | All 5 fixed files now have corresponding test coverage. 262 tests, 0 failures. From v3.2.1 onwards: every code change ships with updated tests. |

---

## ✨ Features

<table>
<tr>
<td>

**🔎 Reconnaissance**
- Subdomain enumeration (subfinder, amass, assetfinder, crt.sh)
- DNS brute force with 100 concurrent threads
- Certificate Transparency passive lookup

</td>
<td>

**🔌 Port Scanning**
- **RustScan** — primary full-range scanner (65535 ports)
- **Async TCP** — pure Python fallback, no root required
- **Nmap** — service + version fingerprinting only
- **Masscan** — optional high-speed sweep

</td>
</tr>
<tr>
<td>

**🌐 Web Analysis**
- httpx — live host detection + tech fingerprinting
- WhatWeb — CMS, framework, server detection
- Nikto — web server vulnerability scanner
- feroxbuster / ffuf / dirsearch — directory brute force

</td>
<td>

**🚨 Vulnerability Detection**
- Nuclei — 9000+ vulnerability templates
- **CVE Lookup** — NVD API, free, no key required (`--cve`)
- **AI Analysis** — Groq / Ollama / Gemini / OpenAI (`--ai`)
- Screenshots via gowitness / aquatone

</td>
</tr>
<tr>
<td>

**📊 Reporting**
- **HTML report** — dark-mode dashboard, auto-generated
- JSON export — machine-readable structured data
- Markdown report — for documentation
- Per-scan log file

</td>
<td>

**⚙️ Quality of Life**
- **--resume** — checkpoint-based scan recovery
- **--update** — self-update from GitHub
- Plugin system — drop `.py` into `plugins/`
- Interactive mode + full CLI mode
- CIDR and target list file support

</td>
</tr>
</table>

---

## 🔄 Pipeline

```
Target Input
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1  │  Subdomain Enumeration (subfinder, amass, crt.sh)   │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2  │  RustScan — ALL 65535 ports (PRIMARY)               │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2b │  Async TCP — gap fill / fallback (no root)          │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3  │  Masscan — optional high-speed sweep                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 4  │  Nmap — service analysis on confirmed open ports    │
├─────────────────────────────────────────────────────────────────┤
│  Phase 4b │  CVE Lookup — NVD API for each service+version      │  ← fixed v3.2.1
├─────────────────────────────────────────────────────────────────┤
│  Phase 5  │  httpx — live web detection + tech stack            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 6  │  Directory Brute Force (feroxbuster/ffuf/dirsearch) │
├─────────────────────────────────────────────────────────────────┤
│  Phase 7  │  WhatWeb — technology fingerprinting                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 8  │  Nikto — web vulnerability scan                     │
├─────────────────────────────────────────────────────────────────┤
│  Phase 9  │  Nuclei — 9000+ vuln templates                      │
├─────────────────────────────────────────────────────────────────┤
│  Phase 10 │  Screenshots (gowitness / aquatone)                  │
├─────────────────────────────────────────────────────────────────┤
│  Phase 11 │  AI Threat Analysis (Groq / Ollama / Gemini)        │  ← fixed v3.2.1
├─────────────────────────────────────────────────────────────────┤
│  Phase 12 │  Plugins                                            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 13 │  HTML + JSON + Markdown Report Generation           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Requirements

### System Requirements

| Tool | Purpose | Required |
|---|---|---|
| Python 3.10+ | Runtime | ✅ Required |
| nmap | Service fingerprinting | ✅ Required |
| rustscan | Primary port scanner | ⭐ Recommended |
| subfinder | Subdomain enumeration | ⭐ Recommended |
| httpx | Web detection | ⭐ Recommended |
| nuclei | Vulnerability scan | ⭐ Recommended |
| masscan | Fast port sweep | Optional |
| feroxbuster | Directory brute force | Optional |
| ffuf | Directory brute force fallback | Optional |
| nikto | Web vulnerability scan | Optional |
| whatweb | Tech fingerprinting | Optional |
| gowitness | Screenshots | Optional |

### Python Dependencies

```
rich>=13.0.0
```

---

## 🚀 Installation

### One-Line Install (Recommended)

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
chmod +x install.sh
./install.sh
```

**Activate the alias:**
```bash
source ~/.bashrc    # bash
source ~/.zshrc     # zsh
```

**Then just run:**
```bash
ReconNinja
```

### Manual Install

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
pip install rich
python3 reconninja.py --check-tools
```

### Verify Install

```bash
ReconNinja --check-tools
ReconNinja --version
```

---

## 💻 Usage

### Interactive Mode

```bash
ReconNinja
```

### CLI Mode

```bash
# Standard scan
ReconNinja -t example.com

# Full suite scan
ReconNinja -t example.com --profile full_suite

# With AI analysis (Groq — free)
ReconNinja -t example.com --ai --ai-provider groq --ai-key gsk_xxx

# With CVE lookup
ReconNinja -t example.com --cve

# Everything
ReconNinja -t example.com --profile full_suite --ai --cve --ai-provider groq --ai-key gsk_xxx

# Resume a crashed scan (auto-detect latest checkpoint)
ReconNinja -t example.com --resume

# Resume from a specific state file
ReconNinja --resume reports/example.com/20240115_143022/state.json

# Skip confirmation (for scripts/automation)
ReconNinja -t example.com --profile standard -y
```

---

## 🤖 AI Analysis

AI analysis is **completely optional** — only activates when you pass `--ai`.

### Supported Providers

| Provider | Free | Speed | Setup |
|---|---|---|---|
| `groq` | ✅ Free tier | ⚡⚡⚡ Fastest | [console.groq.com](https://console.groq.com) |
| `ollama` | ✅ Free (local) | ⚡ Local speed | [ollama.ai](https://ollama.ai) |
| `gemini` | ✅ Free tier | ⚡⚡ Fast | [ai.google.dev](https://ai.google.dev) |
| `openai` | 💳 Paid | ⚡⚡ Fast | [platform.openai.com](https://platform.openai.com) |

```bash
# Groq (recommended — free)
ReconNinja -t target.com --ai --ai-provider groq --ai-key gsk_xxxxxxxxxxxx

# Or set env var (key never appears in shell history)
export GROQ_API_KEY="gsk_xxxxxxxxxxxx"
ReconNinja -t target.com --ai

# Ollama (local — no internet required)
ollama pull llama3
ReconNinja -t target.com --ai --ai-provider ollama

# Gemini (free tier)
export GEMINI_API_KEY="AIzaxxxxxxxxxx"
ReconNinja -t target.com --ai --ai-provider gemini
```

---

## 🔍 CVE Lookup

Automatically queries the [NVD](https://nvd.nist.gov) for CVEs matching every service version Nmap detects.

```bash
# Enable CVE lookup (free, no key needed)
ReconNinja -t target.com --cve

# With optional NVD API key (50 req/30s instead of 5 req/30s)
# Free key: nvd.nist.gov/developers/request-an-api-key
ReconNinja -t target.com --cve --nvd-key YOUR_NVD_KEY
```

> **Note:** Without an API key, the NVD rate limit is 5 requests per 30 seconds. ReconNinja enforces a 6.5 second delay between requests to stay within this limit.

---

## 📊 HTML Reports

Generated automatically after every scan — no extra flags needed.

```
reports/
└── example.com_2024-01-15_143022/
    ├── report.html       ← open in browser
    ├── report.json
    ├── report.md
    ├── state.json        ← resume checkpoint
    └── scan.log
```

---

## 💾 Resume Scans

State is saved after **every phase**. If a scan crashes, resume from exactly where it stopped.

```bash
# Auto-detect latest checkpoint for target
ReconNinja -t example.com --resume

# Point at a specific state file
ReconNinja --resume reports/example.com/20240115_143022/state.json
```

---

## ⬆️ Self-Update

```bash
ReconNinja --update
ReconNinja --update --update-branch dev
ReconNinja --update --force-update
```

---

## 🎯 Scan Profiles

| Profile | Ports | Features | Use Case |
|---|---|---|---|
| `fast` | Top 100 | No scripts | Quick triage |
| `standard` | Top 1000 | Scripts + versions | Default |
| `thorough` | All 65535 | OS + scripts + versions | Deep dive |
| `stealth` | Top 1000 | SYN scan, T2 timing | Evasion |
| `web_only` | — | httpx + dirs + nuclei | Web targets |
| `port_only` | All | RustScan + Masscan + Nmap | Port recon only |
| `full_suite` | All 65535 | Everything | Full pentest |
| `custom` | User defined | User defined | Flexible |

---

## 🚩 All CLI Flags

```
TARGET & PROFILE
  -t, --target          Target: domain, IP, CIDR, or path/to/list.txt
  -p, --profile         fast|standard|thorough|stealth|custom|full_suite|web_only|port_only

NMAP / PORT SCANNING
  --all-ports           Scan all 65535 ports (-p-)
  --top-ports N         Scan top N ports (default: 1000)
  --timing              T1-T5 nmap timing (default: T4)
  --async-concurrency N Async TCP scanner coroutines (default: 1000)
  --async-timeout F     Async TCP connect timeout in seconds (default: 1.5)

FEATURE FLAGS
  --subdomains          Enable subdomain enumeration
  --rustscan            Enable RustScan
  --ferox               Enable feroxbuster directory scan
  --masscan             Enable masscan sweep
  --httpx               Enable httpx web detection
  --nuclei              Enable Nuclei vulnerability scan
  --nikto               Enable Nikto web scan
  --whatweb             Enable WhatWeb fingerprinting
  --aquatone            Enable screenshots

AI ANALYSIS
  --ai                  Enable AI threat analysis
  --ai-provider         groq|ollama|gemini|openai (default: groq)
  --ai-key              API key (or set GROQ_API_KEY / GEMINI_API_KEY env var)
  --ai-model            Override AI model name

CVE LOOKUP
  --cve                 Enable NVD CVE lookup for detected services
  --cve-lookup          Alias for --cve (backwards compatibility)
  --nvd-key             Optional NVD API key — raises rate limit from 5 to 50 req/30s
                        Free key: nvd.nist.gov/developers/request-an-api-key

RESUME
  --resume [STATE_FILE] Resume interrupted scan. Omit path to auto-detect latest
                        checkpoint for --target, or pass exact path to state.json

SELF-UPDATE
  --update              Update to latest version from GitHub
  --update-branch       Branch to pull from (default: main)
  --force-update        Update even if already on latest version

OUTPUT
  --output DIR          Output directory (default: reports)
  --no-html-report      Skip HTML report generation
  --wordlist-size       small|medium|large (default: medium)

MISC
  --threads N           Worker threads (default: 20)
  --masscan-rate N      Masscan packets/sec (default: 5000)
  --check-tools         Show which tools are installed
  --yes, -y             Skip permission confirmation (for automation)
```

---

## 🧪 Testing

ReconNinja ships with a comprehensive test suite covering all core modules. **No external tools required** — all tests mock network calls and tool execution.

### Run Tests

```bash
# With pytest (recommended)
pip install pytest
pytest tests/ -v

# Without pytest
python3 -m unittest discover tests/
```

### Test Coverage

| File | Tests | Covers |
|---|---|---|
| `tests/test_models.py` | 105 | `ScanConfig`, `PortInfo`, `HostResult`, `ReconResult`, all dataclasses including all v3.2.1 fields |
| `tests/test_resume.py` | 83 | `save_state`, `load_state`, full round-trips for all v3.2.1 fields, backward-compat with old `state.json` |
| `tests/test_cve_lookup.py` | 47 | `CVEResult`, NVD API parsing, rate limit enforcement (≥6.0s), function name regression |
| `tests/test_ai_analysis.py` | — | AI providers, prompt building, JSON parsing, error handling |
| `tests/test_report_html.py` | — | HTML report structure, badge generation, full/empty result rendering |
| **Total** | **262** | **0 failures** |

### Test Policy

> **Every code change ships with updated tests. No exceptions.**

The standing rule for every ReconNinja update:

1. Fix the source file
2. Run existing tests — confirm nothing broke
3. Update the relevant test file — new fields get new tests, bug fixes get regression tests
4. Run all tests again — must pass before delivery
5. Source files **and** test files shipped together, always

This policy was formalized in v3.2.1 after multiple bugs shipped in v3.2.0 that a basic test run would have caught.

### Notable Regression Tests

These tests exist to prevent fixed bugs from returning:

```python
# Catches the v3.2.0 NVD rate limit bug (0.7s → 403 errors)
def test_default_delay_at_least_6_seconds(self):
    assert delay >= 6.0

# Catches the v3.2.0 wrong function name in orchestrator
def test_wrong_function_name_does_not_exist(self):
    assert not hasattr(module, "lookup_cves_for_hosts")

# Catches the v3.2.0 field-drop on resume
def test_missing_new_fields_get_defaults(self):
    cfg2 = _dict_to_config({"target": "old.com", "profile": "standard", "nmap_opts": {}})
    assert cfg2.run_cve_lookup is False
    assert cfg2.ai_provider    == "groq"
```

---

## 📁 File Structure

```
ReconNinja/
├── reconninja.py           # Main entry point + CLI
├── install.sh              # Installer (all OS except Windows)
├── requirements.txt        # Python dependencies
├── environment.yml         # Conda environment
├── pytest.ini              # Test config
│
├── core/
│   ├── orchestrator.py     # Phase-based pipeline engine
│   ├── ports.py            # RustScan + Async TCP + Nmap
│   ├── subdomains.py       # Subdomain enumeration
│   ├── web.py              # httpx, WhatWeb, Nikto, dir scan
│   ├── vuln.py             # Nuclei, aquatone, gowitness
│   ├── ai_analysis.py      # AI threat analysis — Groq/Ollama/Gemini/OpenAI
│   ├── cve_lookup.py       # NVD CVE lookup
│   ├── resume.py           # Checkpoint / resume
│   └── updater.py          # Self-update from GitHub
│
├── output/
│   ├── report_html.py      # HTML report generator
│   └── reports.py          # JSON + Markdown reports
│
├── utils/
│   ├── models.py           # Dataclasses (ScanConfig, PortInfo, etc.)
│   ├── helpers.py          # Utility functions
│   └── logger.py           # Rich terminal logger
│
├── plugins/                # Drop .py files here to extend ReconNinja
│
└── tests/
    ├── conftest.py         # Shared fixtures (updated v3.2.1)
    ├── test_models.py      # 105 tests (updated v3.2.1)
    ├── test_resume.py      # 83 tests (updated v3.2.1)
    ├── test_cve_lookup.py  # 47 tests (updated v3.2.1)
    ├── test_ai_analysis.py # AI provider tests
    ├── test_ports.py       # Port scanning tests
    └── test_report_html.py # HTML report tests
```

---

## 📝 Changelog

### v3.2.1 — Bug Fix Release
- ✅ **AI Analysis fixed** — `--ai` now calls the real LLM. v3.2.0 used a silent rule-based fallback for all users.
- ✅ **`--cve` flag fixed** — both `--cve` and `--cve-lookup` now accepted. CVE phase now executes in the pipeline.
- ✅ **`--nvd-key` fixed** — was in README but missing from argparse and never passed to CVE module.
- ✅ **`--resume` fixed** — `orchestrate()` signature mismatch caused immediate crash on every resume.
- ✅ **NVD rate limit fixed** — `delay` corrected from `0.7s` → `6.5s` (was firing 43 req/30s vs a 5 req/30s limit).
- ✅ **Version banner corrected** — internal docstring said v3.0. Now consistent at v3.2.1.
- ✅ **262 tests, 0 failures** — `test_models.py`, `test_resume.py`, `test_cve_lookup.py`, `conftest.py` all updated. Test-with-every-update policy formalized.

### v3.2.0
- ✅ AI Analysis — Groq (free), Ollama (local), Gemini, OpenAI via `--ai`
- ✅ CVE Lookup — NVD API auto-queries after nmap `-sV` via `--cve`
- ✅ --resume — JSON checkpoint saves after every phase
- ✅ --update — self-update from GitHub with backup
- ✅ HTML Reports — auto-generated dark-mode dashboard every scan

### v3.1.0
- ✅ Built-in AsyncTCPScanner — pure Python, no root required
- ✅ Async scan feeds confirmed ports to nmap (`-p<ports>`)
- ✅ RustScan + async results merged for max coverage
- ✅ Nmap only scans confirmed-open ports — dramatically faster

### v3.0.0
- ✅ RustScan integration
- ✅ httpx for live web service detection
- ✅ crt.sh Certificate Transparency subdomain source
- ✅ Plugin system
- ✅ Phase-based orchestration

---

## ⚖️ Legal

> **This tool is for authorized security testing only.**
>
> - ✅ Authorized penetration testing engagements
> - ✅ Your own systems and infrastructure
> - ✅ Bug bounty programs where you have permission
> - ❌ Systems you do not own or have explicit written permission to test
> - ❌ Any illegal or unauthorized use
>
> The author assumes no liability and is not responsible for any misuse or damage caused by this tool.

---

<div align="center">

**Made by [YouTubers777](https://github.com/YouTubers777)**

⭐ If this tool helped you, please give it a star!

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7c3aed,50:00d4ff,100:0d0d0d&height=100&section=footer" />

</div>
