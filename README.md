# 🥷 ReconNinja v2.1

> ⚔️ All-in-One Automated Reconnaissance Framework for Penetration Testers & Security Researchers

ReconNinja is a powerful Python-based reconnaissance automation framework that streamlines the full recon workflow — from subdomain discovery to vulnerability detection and professional report generation.

---

## ⚠️ Legal Notice

ReconNinja is strictly intended for use against systems you own or have **explicit written permission** to test.  
Unauthorized scanning is illegal and unethical. Always obtain written authorization before scanning any target.

---

# 🆕 What's New in v2.1

| Fix / Improvement | Details |
|-------------------|----------|
| 🐛 File collision fix | Each Nmap worker writes to its own subdirectory — no more concurrent timestamp collisions |
| 🔐 Shell injection removed | Aquatone no longer uses `/bin/sh -c` — stdin piped directly via subprocess |
| 🧬 Config mutation fix | `nmap_opts` deep-copied before masscan injection — `orchestrate()` safe for multiple runs |
| 🪣 Error propagation | `parse_nmap_xml` errors now surface in `result.errors` and JSON report |
| ⚡ Cached tool detection | `tool_exists()` and `detect_seclists()` use `@lru_cache` |
| 🌊 Streaming wordlist | `_dns_brute` streams wordlists line-by-line (safe for 100k+ entries) |
| ✅ Config validation | `NmapOptions` validates timing templates & port values |
| 🧹 Cleanup | Removed unused imports |

---

# 🚀 Features

## 🌐 Subdomain Discovery
- 🔎 Subfinder — fast passive enumeration  
- 🛰 Amass — comprehensive OSINT enumeration  
- ⚡ Assetfinder — quick asset discovery  
- 💣 FFUF — active brute-force via HTTP probing  
- 🧠 Built-in DNS brute fallback — streaming resolver  
- ✅ Live DNS verification — multi-threaded resolution  

---

## 🔓 Port Scanning
- 🛠 Nmap (required) — scripts, version & OS detection  
- ⚡ Masscan → Nmap pipeline  
- 🔁 Automatic `-Pn` retry for blocked hosts  
- 🏷 Risk classification (Critical / High / Medium / Info)  

---

## 📂 Web Enumeration
- 🚀 Feroxbuster  
- ⚡ FFUF fallback  
- 🔎 WhatWeb  
- 🛡 Nikto  
- 💥 Nuclei (medium/high/critical)  
- 📸 Aquatone screenshots  

---

## 📊 Reporting Engine
- 📁 JSON (structured output)  
- 🌑 HTML dashboard (dark theme, standalone)  
- 📝 Markdown summary  
- 📋 Rich terminal open-port table  

---

# ⚡ Performance

- 🧵 Concurrent Nmap workers with isolated output directories  
- 🧠 50-thread DNS verification  
- 🔐 Thread-safe console & result accumulation  
- 🌊 Generator-based wordlist streaming  
- 🧩 Graceful tool degradation  
- 📉 Per-target timeout with worst-case time estimate  

---

# 🧠 Scan Profiles

| Profile | Description |
|----------|-------------|
| ⚡ FAST | Top 100 ports, no scripts |
| 🟢 STANDARD | Top 1000 ports + scripts + version detection |
| 🔥 THOROUGH | All 65535 ports + OS + version + scripts |
| 🕵️ STEALTH | SYN scan + T2 timing |
| 🎛 CUSTOM | Fully user-defined |
| 🚀 FULL SUITE | Subdomains → dirs → masscan → nmap → nuclei → screenshots |

---

# 🛠 Tech Stack

**Language:** Python 3.10+  
**Dependency:**  
```
rich>=13.0.0
```

## External Tools (Optional except Nmap)

| Tool | Role | Required |
|------|------|----------|
| nmap | Port scanning | ✅ Yes |
| subfinder | Subdomain enumeration | No |
| amass | Subdomain enumeration | No |
| assetfinder | Subdomain enumeration | No |
| ffuf | Subdomain / dir brute-force | No |
| feroxbuster | Directory scanning | No |
| masscan | Fast port sweep | No |
| whatweb | Tech fingerprinting | No |
| nikto | Web vulnerability scanning | No |
| nuclei | Template-based vuln detection | No |
| aquatone | Screenshots | No |

Everything else uses Python’s standard library.

---

# 📦 Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
```

## 2️⃣ Install Python Dependency

```bash
pip install -r requirements.txt
```

## 3️⃣ Install Nmap (Required)

### Arch / Manjaro
```bash
sudo pacman -S nmap
```

### Debian / Ubuntu / Kali
```bash
sudo apt install nmap
```

### macOS
```bash
brew install nmap
```

---

## 4️⃣ Optional Tools (Recommended)

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/michenriksen/aquatone@latest

# Apt
sudo apt install amass feroxbuster whatweb nikto masscan
```

---

## 5️⃣ Install SecLists (Recommended)

```bash
sudo apt install seclists
# OR
git clone https://github.com/danielmiessler/SecLists.git ~/seclists
```

---

# ▶️ Usage

## 🖥 Interactive Mode

```bash
python3 ReconNinja.py
```

Includes:
- Tool availability table  
- Scan profile selection  
- Target input & permission confirmation  
- Module toggles  

---

## 🤖 CLI Mode

Standard:
```bash
python3 ReconNinja.py -t example.com
```

Full suite:
```bash
python3 ReconNinja.py -t example.com --profile full_suite --subdomains --nuclei --ferox --whatweb -y
```

Thorough:
```bash
python3 ReconNinja.py -t example.com --profile thorough --all-ports
```

Stealth:
```bash
sudo python3 ReconNinja.py -t example.com --profile stealth
```

Check tools:
```bash
python3 ReconNinja.py --check-tools
```

---

# 📁 Output Structure

```
reports/
└── example.com/
    └── YYYYMMDD_HHMMSS/
        ├── scan_config.json
        ├── subdomains_merged.txt
        ├── dirscan.txt
        ├── masscan.txt
        ├── whatweb.txt
        ├── nikto.txt
        ├── nuclei.txt
        ├── report.json
        ├── report.html
        ├── report.md
        ├── api_example_com/
        │   ├── nmap_TIMESTAMP.xml
        │   └── nmap_TIMESTAMP.txt
        └── aquatone/
```

---

# 🔒 Risk Classification

| Level | Example Ports |
|-------|--------------|
| 🔴 Critical | FTP, SSH, Telnet, SMTP, DNS, RPC, NetBIOS, IMAP, SNMP, LDAP, SMB |
| 🟠 High | HTTP, HTTPS, MySQL, RDP, PostgreSQL, VNC, Redis, MSSQL |
| 🟡 Medium | Elasticsearch, Memcached |
| ⚪ Info | All others |

---

# 🧩 Architecture Notes

- `orchestrate()` controls scan flow  
- Masscan ports feed directly into Nmap  
- `ThreadPoolExecutor` handles concurrency  
- `safe_print()` ensures thread-safe output  
- `tool_exists()` cached for performance  
- Missing tools = warning, not crash  

---

# 🤝 Contributing

Pull requests welcome.  
Please test in a lab (HackTheBox, TryHackMe, or your own VMs) before submitting.

---

# 📄 License

MIT License — see LICENSE file.

---

⭐ Generated by ReconNinja v2.1 — For authorized testing only.# 🥷 ReconNinja v2.1

> ⚔️ All-in-One Automated Reconnaissance Framework for Penetration Testers & Security Researchers

ReconNinja is a powerful Python-based reconnaissance automation framework that streamlines the full recon workflow — from subdomain discovery to vulnerability detection and professional report generation.

---

## ⚠️ Legal Notice

ReconNinja is strictly intended for use against systems you own or have **explicit written permission** to test.  
Unauthorized scanning is illegal and unethical. Always obtain written authorization before scanning any target.

---

# 🆕 What's New in v2.1

| Fix / Improvement | Details |
|-------------------|----------|
| 🐛 File collision fix | Each Nmap worker writes to its own subdirectory — no more concurrent timestamp collisions |
| 🔐 Shell injection removed | Aquatone no longer uses `/bin/sh -c` — stdin piped directly via subprocess |
| 🧬 Config mutation fix | `nmap_opts` deep-copied before masscan injection — `orchestrate()` safe for multiple runs |
| 🪣 Error propagation | `parse_nmap_xml` errors now surface in `result.errors` and JSON report |
| ⚡ Cached tool detection | `tool_exists()` and `detect_seclists()` use `@lru_cache` |
| 🌊 Streaming wordlist | `_dns_brute` streams wordlists line-by-line (safe for 100k+ entries) |
| ✅ Config validation | `NmapOptions` validates timing templates & port values |
| 🧹 Cleanup | Removed unused imports |

---

# 🚀 Features

## 🌐 Subdomain Discovery
- 🔎 Subfinder — fast passive enumeration  
- 🛰 Amass — comprehensive OSINT enumeration  
- ⚡ Assetfinder — quick asset discovery  
- 💣 FFUF — active brute-force via HTTP probing  
- 🧠 Built-in DNS brute fallback — streaming resolver  
- ✅ Live DNS verification — multi-threaded resolution  

---

## 🔓 Port Scanning
- 🛠 Nmap (required) — scripts, version & OS detection  
- ⚡ Masscan → Nmap pipeline  
- 🔁 Automatic `-Pn` retry for blocked hosts  
- 🏷 Risk classification (Critical / High / Medium / Info)  

---

## 📂 Web Enumeration
- 🚀 Feroxbuster  
- ⚡ FFUF fallback  
- 🔎 WhatWeb  
- 🛡 Nikto  
- 💥 Nuclei (medium/high/critical)  
- 📸 Aquatone screenshots  

---

## 📊 Reporting Engine
- 📁 JSON (structured output)  
- 🌑 HTML dashboard (dark theme, standalone)  
- 📝 Markdown summary  
- 📋 Rich terminal open-port table  

---

# ⚡ Performance

- 🧵 Concurrent Nmap workers with isolated output directories  
- 🧠 50-thread DNS verification  
- 🔐 Thread-safe console & result accumulation  
- 🌊 Generator-based wordlist streaming  
- 🧩 Graceful tool degradation  
- 📉 Per-target timeout with worst-case time estimate  

---

# 🧠 Scan Profiles

| Profile | Description |
|----------|-------------|
| ⚡ FAST | Top 100 ports, no scripts |
| 🟢 STANDARD | Top 1000 ports + scripts + version detection |
| 🔥 THOROUGH | All 65535 ports + OS + version + scripts |
| 🕵️ STEALTH | SYN scan + T2 timing |
| 🎛 CUSTOM | Fully user-defined |
| 🚀 FULL SUITE | Subdomains → dirs → masscan → nmap → nuclei → screenshots |

---

# 🛠 Tech Stack

**Language:** Python 3.10+  
**Dependency:**  
```
rich>=13.0.0
```

## External Tools (Optional except Nmap)

| Tool | Role | Required |
|------|------|----------|
| nmap | Port scanning | ✅ Yes |
| subfinder | Subdomain enumeration | No |
| amass | Subdomain enumeration | No |
| assetfinder | Subdomain enumeration | No |
| ffuf | Subdomain / dir brute-force | No |
| feroxbuster | Directory scanning | No |
| masscan | Fast port sweep | No |
| whatweb | Tech fingerprinting | No |
| nikto | Web vulnerability scanning | No |
| nuclei | Template-based vuln detection | No |
| aquatone | Screenshots | No |

Everything else uses Python’s standard library.

---

# 📦 Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
```

## 2️⃣ Install Python Dependency

```bash
pip install -r requirements.txt
```

## 3️⃣ Install Nmap (Required)

### Arch / Manjaro
```bash
sudo pacman -S nmap
```

### Debian / Ubuntu / Kali
```bash
sudo apt install nmap
```

### macOS
```bash
brew install nmap
```

---

## 4️⃣ Optional Tools (Recommended)

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/michenriksen/aquatone@latest

# Apt
sudo apt install amass feroxbuster whatweb nikto masscan
```

---

## 5️⃣ Install SecLists (Recommended)

```bash
sudo apt install seclists
# OR
git clone https://github.com/danielmiessler/SecLists.git ~/seclists
```

---

# ▶️ Usage

## 🖥 Interactive Mode

```bash
python3 ReconNinja.py
```

Includes:
- Tool availability table  
- Scan profile selection  
- Target input & permission confirmation  
- Module toggles  

---

## 🤖 CLI Mode

Standard:
```bash
python3 ReconNinja.py -t example.com
```

Full suite:
```bash
python3 ReconNinja.py -t example.com --profile full_suite --subdomains --nuclei --ferox --whatweb -y
```

Thorough:
```bash
python3 ReconNinja.py -t example.com --profile thorough --all-ports
```

Stealth:
```bash
sudo python3 ReconNinja.py -t example.com --profile stealth
```

Check tools:
```bash
python3 ReconNinja.py --check-tools
```

---

# 📁 Output Structure

```
reports/
└── example.com/
    └── YYYYMMDD_HHMMSS/
        ├── scan_config.json
        ├── subdomains_merged.txt
        ├── dirscan.txt
        ├── masscan.txt
        ├── whatweb.txt
        ├── nikto.txt
        ├── nuclei.txt
        ├── report.json
        ├── report.html
        ├── report.md
        ├── api_example_com/
        │   ├── nmap_TIMESTAMP.xml
        │   └── nmap_TIMESTAMP.txt
        └── aquatone/
```

---

# 🔒 Risk Classification

| Level | Example Ports |
|-------|--------------|
| 🔴 Critical | FTP, SSH, Telnet, SMTP, DNS, RPC, NetBIOS, IMAP, SNMP, LDAP, SMB |
| 🟠 High | HTTP, HTTPS, MySQL, RDP, PostgreSQL, VNC, Redis, MSSQL |
| 🟡 Medium | Elasticsearch, Memcached |
| ⚪ Info | All others |

---

# 🧩 Architecture Notes

- `orchestrate()` controls scan flow  
- Masscan ports feed directly into Nmap  
- `ThreadPoolExecutor` handles concurrency  
- `safe_print()` ensures thread-safe output  
- `tool_exists()` cached for performance  
- Missing tools = warning, not crash  

---

# 🤝 Contributing

Pull requests welcome.  
Please test in a lab (HackTheBox, TryHackMe, or your own VMs) before submitting.

---

# 📄 License

MIT License — see LICENSE file.

---

⭐ Generated by ReconNinja v2.1 — For authorized testing only.
