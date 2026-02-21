Copy🥷 ReconNinja v2.1

⚔️ All-in-One Automated Reconnaissance Framework for Penetration Testers & Security Researchers

ReconNinja is a powerful Python-based reconnaissance automation framework that streamlines the full recon workflow — from subdomain discovery to vulnerability detection and professional report generation.

⚠️ Legal Notice
ReconNinja is strictly intended for use against systems you own or have explicit written permission to test.
Unauthorized scanning is illegal and unethical. Always get written authorization before scanning any target.

🆕 What's New in v2.1
Fix / ImprovementDetails🐛 File collision fixEach nmap worker now writes to its own subdirectory — no more concurrent timestamp collisions🔐 Shell injection removedAquatone no longer uses /bin/sh -c — stdin piped directly via subprocess🧬 Config mutation fixnmap_opts deep-copied before masscan port injection — orchestrate() is now safe to call multiple times🪣 Error propagationparse_nmap_xml errors now surface in result.errors and the JSON report instead of being silently dropped⚡ Cached tool detectiontool_exists() and detect_seclists() use @lru_cache — no repeated filesystem/PATH scans🌊 Streaming wordlist_dns_brute now streams wordlists line-by-line — safe for 100k+ entry lists✅ Config validationNmapOptions validates timing template and port values at construction time🧹 CleanupRemoved unused imports (Live, Syntax, Text, time)

🚀 Features
🌐 Subdomain Discovery

🔎 Subfinder — fast passive enumeration
🛰 Amass — comprehensive OSINT enumeration
⚡ Assetfinder — quick asset discovery
💣 FFUF — active brute-force via HTTP probing
🧠 Built-in DNS brute fallback — streaming wordlist resolver, no external deps
✅ Live DNS verification — multi-threaded resolution check on all discovered subdomains


🔓 Port Scanning

🛠 Nmap (required) — scripts, version & OS detection
⚡ Masscan → Nmap pipeline — masscan finds open ports fast, nmap does deep inspection
🔁 Automatic -Pn retry — seamlessly handles firewalled / ICMP-blocked hosts
🏷 Risk classification — ports auto-tagged as Critical / High / Medium / Info


📂 Web Enumeration

🚀 Feroxbuster — recursive directory brute-forcing
⚡ FFUF fallback — used when feroxbuster is unavailable
🔎 WhatWeb — technology fingerprinting
🛡 Nikto — classic web vulnerability scanner
💥 Nuclei — template-based vulnerability detection (medium/high/critical)
📸 Aquatone — automated screenshots of discovered hosts


📊 Reporting Engine

📁 JSON — machine-readable, full structured output
🌑 HTML — dark-themed standalone dashboard with stats bar
📝 Markdown — clean human-readable summary
📋 Rich terminal table — live open ports summary in the console


⚡ Performance

🧵 Concurrent Nmap scanning with isolated per-target output directories
🧠 Multi-threaded subdomain DNS verification (50 workers)
🔐 Thread-safe console output and result accumulation
🌊 Generator-based wordlist streaming (no full-file memory load)
🧩 Graceful tool degradation — missing tools are skipped, not fatal
📉 Per-target timeout with worst-case wall time shown before scan starts


🧠 Scan Profiles
ProfileDescription⚡ FASTTop 100 ports, no scripts — quick sweep🟢 STANDARDTop 1000 ports + scripts + version detection🔥 THOROUGHAll 65535 ports + OS + version + scripts🕵️ STEALTHSYN scan + T2 timing, no scripts🎛 CUSTOMFully user-defined via interactive prompts🚀 FULL SUITERuns everything: subs → dirs → masscan → nmap → nuclei → screenshots

🛠 Tech Stack
Language: Python 3.10+
Python Dependency:
rich>=13.0.0
External Tools (optional except nmap):
ToolRoleRequirednmapPort scanning✅ YessubfinderSubdomain enumerationNoamassSubdomain enumerationNoassetfinderSubdomain enumerationNoffufSubdomain/dir brute-forceNoferoxbusterDirectory scanningNomasscanFast port sweepNowhatwebTech fingerprintingNoniktoWeb vulnerability scanningNonucleiTemplate-based vuln detectionNoaquatoneScreenshotsNo
Everything else uses the Python standard library.

📦 Installation
1️⃣ Clone the Repository
bashgit clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
2️⃣ Install Python Dependency
bashpip install -r requirements.txt
3️⃣ Install Nmap (Required)
Arch / Manjaro:
bashsudo pacman -S nmap
Debian / Ubuntu / Kali:
bashsudo apt install nmap
macOS:
bashbrew install nmap
4️⃣ Install Optional Tools (Recommended)
The more tools you install, the more capability ReconNinja has. On Kali Linux most are pre-installed.
bash# Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf/v2@latest

# Apt
sudo apt install amass feroxbuster whatweb nikto masscan

# Aquatone
go install github.com/michenriksen/aquatone@latest
5️⃣ Install SecLists (Recommended for Wordlists)
bash# Kali / Debian
sudo apt install seclists

# Manual
git clone https://github.com/danielmiessler/SecLists.git ~/seclists

▶️ Usage
🖥 Interactive Mode
bashpython3 ReconNinja.py
Launches the full interactive menu:

Tool availability table
Scan profile selection
Target input + permission confirmation
Module toggles (subdomains, dir scan, nuclei, etc.)


🤖 CLI Mode (Automation Friendly)
Standard scan:
bashpython3 ReconNinja.py -t example.com
Full suite with all modules:
bashpython3 ReconNinja.py -t example.com --profile full_suite --subdomains --nuclei --ferox --whatweb -y
Thorough scan, all ports:
bashpython3 ReconNinja.py -t example.com --profile thorough --all-ports
Stealth scan:
bashsudo python3 ReconNinja.py -t example.com --profile stealth
Check which tools are installed:
bashpython3 ReconNinja.py --check-tools

📋 CLI Reference
FlagDescriptionDefault-t, --targetTarget domain or IP(required in CLI mode)-p, --profileScan profilestandard--all-portsScan all 65535 portsOff--top-ports NScan top N ports1000--timingNmap timing (T1–T5)T4--threads NMax concurrent nmap workers20--subdomainsEnable subdomain enumerationOff--feroxEnable directory scanningOff--masscanEnable masscan pre-sweep (needs root)Off--nucleiEnable nuclei scanningOff--niktoEnable nikto scanningOff--whatwebEnable WhatWeb fingerprintingOff--aquatoneEnable Aquatone screenshotsOff--wordlist-sizesmall / medium / largemedium--check-toolsShow tool availability and exit—-y, --yesSkip permission prompt (automation)Off

📁 Output Structure
reports/
└── example.com/
    └── 20240615_143022/
        ├── scan_config.json          # Scan parameters
        ├── subdomains_merged.txt     # All live subdomains
        ├── dirscan.txt               # Directory findings
        ├── masscan.txt               # Masscan raw output
        ├── whatweb.txt               # WhatWeb output
        ├── nikto.txt                 # Nikto output
        ├── nuclei.txt                # Nuclei findings
        ├── report.json               # Full structured report
        ├── report.html               # Dark-themed HTML dashboard
        ├── report.md                 # Markdown summary
        ├── api_example_com/          # Per-subdomain nmap output
        │   ├── nmap_20240615_143045.xml
        │   └── nmap_20240615_143045.txt
        └── aquatone/                 # Screenshots (if enabled)

🔒 Risk Classification
ReconNinja automatically classifies open ports by risk level:
LevelPorts🔴 CriticalFTP, SSH, Telnet, SMTP, DNS, RPC, NetBIOS, IMAP, SNMP, LDAP, SMB, rsh, rlogin🟠 HighHTTP, HTTPS, MySQL, RDP, PostgreSQL, VNC, Redis, HTTP-alt, MSSQL, MongoDB🟡 MediumHTTP-alt, Elasticsearch, Memcached⚪ InfoAll other ports

🧩 Architecture Notes

Orchestration is handled by orchestrate() which runs each phase sequentially and passes results forward (e.g. masscan ports feed into nmap's port list)
Concurrency uses ThreadPoolExecutor — safe because the GIL is released during subprocess and I/O calls
Thread safety — all console output goes through safe_print() (print lock), result mutations through _RESULT_LOCK
Tool degradation — every external tool check is gated with tool_exists() (cached); missing tools produce a warning, not a crash


🤝 Contributing
Pull requests welcome. Please test against a local lab (e.g. HackTheBox, TryHackMe, or your own VMs) before submitting.

📄 License
MIT License — see LICENSE for details.

Generated by ReconNinja v2.1 — For authorized testing only.
