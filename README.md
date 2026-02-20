# 🥷 ReconNinja v2.0

> ⚔️ All-in-One Automated Reconnaissance Framework for Penetration Testers & Security Researchers

ReconNinja is a powerful Python-based reconnaissance automation framework that streamlines the full recon workflow — from subdomain discovery to vulnerability detection and professional report generation.

---

## ⚠️ Legal Notice

ReconNinja is strictly intended for use against systems you own or have **explicit written permission** to test.  
Unauthorized scanning is illegal.

---

# 🚀 Features

## 🌐 Subdomain Discovery
- 🔎 Subfinder
- 🛰 Amass
- ⚡ Assetfinder
- 💣 FFUF brute-force
- 🧠 Built-in DNS brute fallback
- ✅ Live DNS verification (multi-threaded)

---

## 🔓 Port Scanning
- 🛠 Nmap (required)
- ⚡ Masscan → Nmap deep pipeline
- 🖥 OS detection
- 🔍 Service & version detection
- 📜 Script scanning
- 🔁 Automatic `-Pn` retry for firewalled hosts

---

## 📂 Directory & Web Enumeration
- 🚀 Feroxbuster
- ⚡ FFUF fallback
- 🔎 WhatWeb fingerprinting
- 🛡 Nikto scanning
- 💥 Nuclei vulnerability detection
- 📸 Aquatone screenshots

---

## 📊 Reporting Engine
- 📁 JSON report (machine-readable)
- 🌑 Dark-themed standalone HTML dashboard
- 📝 Clean Markdown report
- 📋 Rich terminal summary table

---

## ⚡ Performance Optimizations
- 🧵 Concurrent Nmap scanning
- 🧠 Multi-threaded subdomain verification
- 🔐 Thread-safe console output
- 🧩 Graceful tool degradation
- ⚡ Masscan → Nmap hybrid pipeline

---

# 🧠 Scan Profiles

| Profile | Description |
|----------|-------------|
| ⚡ FAST | Top 100 ports |
| 🟢 STANDARD | Top 1000 ports + scripts |
| 🔥 THOROUGH | All 65535 ports + OS detection |
| 🕵️ STEALTH | SYN scan + low timing |
| 🎛 CUSTOM | Fully user-defined |
| 🚀 FULL_SUITE | Runs everything |

---

# 🛠 Tech Stack

**Language:** Python 3.10+  
**Python Dependency:**  
- `rich`

**External Tools (Optional except Nmap):**
- nmap
- subfinder
- amass
- assetfinder
- ffuf
- feroxbuster
- masscan
- whatweb
- nikto
- nuclei
- aquatone

All other functionality uses Python standard library modules.

---

# 📦 Installation

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
```

---

## 2️⃣ Install Python Dependency

```bash
pip install rich
```

---

## 3️⃣ Install Required Tool

Minimum requirement:

```bash
sudo pacman -S nmap
```

⚡ Optional tools increase capability (subfinder, amass, ffuf, nuclei, etc.)

---

# ▶ Usage

## 🖥 Interactive Mode

```bash
python recon_ninja.py
```

Displays:

- 🏴 ASCII banner  
- 📊 Profile selection  
- ⚖ Permission confirmation  
- 🧩 Module selection  

---

## 🤖 CLI Mode (Automation Friendly)

Example:

```bash
python recon_ninja.py -t example.com --profile full_suite --subdomains --nuclei --ferox -y
```

This runs:
- 🚀 Full suite profile  
- 🌐 Subdomain enumeration  
- 💥 Nuclei scanning  
- 📂 Directory scan  
- ⚡ Skips permission prompt (for automation)
