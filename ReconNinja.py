#!/usr/bin/env python3
"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝

ReconNinja v2.0 — Professional All-in-One Recon Framework
  ⚠  Use ONLY against targets you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Generator, Optional
from urllib.parse import urlparse

# ─── Dependency check ──────────────────────────────────────────────────────────
try:
    from rich import print as rprint
    from rich.console import Console
    from rich.live import Live
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
except ImportError:
    print("ERROR: 'rich' library not found.  Run: pip install rich", file=sys.stderr)
    sys.exit(1)

# ─── Console / Logging ─────────────────────────────────────────────────────────

THEME = Theme(
    {
        "info": "bold cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "danger": "bold red",
        "header": "bold magenta",
        "dim": "dim white",
        "port.open": "bold green",
        "port.filtered": "yellow",
        "port.closed": "red",
    }
)

console = Console(theme=THEME)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, show_path=False, markup=True)],
)
log = logging.getLogger("recon_ninja")

# ─── Constants ─────────────────────────────────────────────────────────────────

VERSION = "2.0.0"
APP_NAME = "ReconNinja"
REPORTS_DIR = Path("reports")
MAX_THREADS = 20
NMAP_TIMEOUT = 3600  # 1-hour hard cap per nmap run

SECLISTS_CANDIDATES = [
    "/usr/share/seclists",
    "/usr/local/share/seclists",
    Path.home() / "seclists",
]

WORDLISTS = {
    "sub": {
        "small": "Discovery/DNS/subdomains-top1million-5000.txt",
        "medium": "Discovery/DNS/subdomains-top1million-110000.txt",
        "large": "Discovery/DNS/subdomains-top1million.txt",
    },
    "dir": {
        "small": "Discovery/Web-Content/common.txt",
        "medium": "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "large": "Discovery/Web-Content/directory-list-2.3-big.txt",
    },
}

SEVERITY_PORTS = {
    "critical": {21, 22, 23, 25, 53, 111, 135, 139, 143, 161, 389, 445, 512, 513, 514},
    "high": {80, 443, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017},
    "medium": {8000, 8081, 8888, 9200, 9300, 11211},
}


# ─── Dataclasses ───────────────────────────────────────────────────────────────


class ScanProfile(Enum):
    FAST = "fast"
    STANDARD = "standard"
    THOROUGH = "thorough"
    STEALTH = "stealth"
    CUSTOM = "custom"
    FULL_SUITE = "full_suite"


@dataclass
class NmapOptions:
    all_ports: bool = False
    top_ports: int = 1000
    scripts: bool = True
    version_detection: bool = True
    os_detection: bool = False
    aggressive: bool = False
    stealth: bool = False
    timing: str = "T4"
    extra_flags: list[str] = field(default_factory=list)
    script_args: Optional[str] = None

    def as_nmap_args(self) -> list[str]:
        args: list[str] = []
        if self.stealth:
            args += ["-sS"]
        if self.aggressive:
            args += ["-A"]
        else:
            if self.os_detection:
                args += ["-O"]
            if self.scripts:
                args += ["-sC"]
            if self.version_detection:
                args += ["-sV"]
        if self.script_args:
            args += [f"--script-args={self.script_args}"]
        args += [f"-{self.timing}"]
        if self.all_ports:
            args += ["-p-"]
        elif self.top_ports:
            args += ["--top-ports", str(self.top_ports)]
        args += self.extra_flags
        return args


@dataclass
class ScanConfig:
    target: str
    profile: ScanProfile
    nmap_opts: NmapOptions = field(default_factory=NmapOptions)
    run_subdomains: bool = False
    run_feroxbuster: bool = False
    run_masscan: bool = False
    run_aquatone: bool = False
    run_whatweb: bool = False
    run_nikto: bool = False
    run_nuclei: bool = False
    masscan_rate: int = 5000
    threads: int = MAX_THREADS
    wordlist_size: str = "medium"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["profile"] = self.profile.value
        return d


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        for sev, ports in SEVERITY_PORTS.items():
            if self.port in ports:
                return sev
        return "info"

    @property
    def display_state(self) -> str:
        colors = {"open": "port.open", "filtered": "port.filtered", "closed": "port.closed"}
        return f"[{colors.get(self.state, 'dim')}]{self.state}[/]"


@dataclass
class HostResult:
    ip: str
    mac: str = ""
    hostnames: list[str] = field(default_factory=list)
    os_guess: str = ""
    os_accuracy: str = ""
    ports: list[PortInfo] = field(default_factory=list)
    scan_time: str = ""
    source_subdomain: str = ""

    @property
    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ReconResult:
    target: str
    start_time: str
    end_time: str = ""
    subdomains: list[str] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    ferox_findings: list[str] = field(default_factory=list)
    masscan_ports: list[str] = field(default_factory=list)
    nikto_findings: list[str] = field(default_factory=list)
    whatweb_findings: list[str] = field(default_factory=list)
    nuclei_findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─── Utilities ─────────────────────────────────────────────────────────────────


def timestamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    return datetime.now().strftime(fmt)


def ensure_dir(path: Path | str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def detect_seclists() -> Optional[Path]:
    for candidate in SECLISTS_CANDIDATES:
        p = Path(candidate)
        if p.exists():
            return p
    return None


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def is_valid_target(target: str) -> bool:
    """Validate that target is a domain or IP address."""
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(target)
        return True
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(target))


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def run_cmd(
    cmd: list[str],
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
) -> tuple[int, str, str]:
    """
    Execute a command and return (returncode, stdout, stderr).
    Returns (127, '', err) if binary not found.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ.copy(),
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as e:
        return 1, "", str(e)


def stream_cmd(cmd: list[str]) -> Generator[str, None, None]:
    """Stream stdout of a subprocess line-by-line."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:  # type: ignore[union-attr]
            yield line.rstrip()
        proc.wait()
    except FileNotFoundError:
        yield f"[ERROR] Command not found: {cmd[0]}"
    except Exception as e:
        yield f"[ERROR] {e}"


_LOCK = threading.Lock()


def safe_print(*args, **kwargs):
    with _LOCK:
        console.print(*args, **kwargs)


# ─── Nmap ──────────────────────────────────────────────────────────────────────


def build_nmap_cmd(target: str, opts: NmapOptions, xml_out: Path, normal_out: Path) -> list[str]:
    cmd = ["nmap"] + opts.as_nmap_args()
    cmd += ["-oX", str(xml_out), "-oN", str(normal_out), target]
    return cmd


def parse_nmap_xml(xml_text: str) -> list[HostResult]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.warning(f"XML parse error: {exc}")
        return []

    hosts: list[HostResult] = []
    for host_el in root.findall("host"):
        # --- addresses ---
        ip = ""
        mac = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")

        # --- hostnames ---
        hostnames: list[str] = []
        hn_el = host_el.find("hostnames")
        if hn_el is not None:
            hostnames = [h.get("name", "") for h in hn_el.findall("hostname") if h.get("name")]

        # --- OS ---
        os_guess, os_acc = "", ""
        os_el = host_el.find("os")
        if os_el is not None:
            matches = os_el.findall("osmatch")
            if matches:
                os_guess = matches[0].get("name", "")
                os_acc = matches[0].get("accuracy", "")

        # --- ports ---
        ports: list[PortInfo] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""

                svc = port_el.find("service")
                svc_name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                extra = svc.get("extrainfo", "") if svc is not None else ""

                # script output
                script_data: dict[str, str] = {}
                for s in port_el.findall("script"):
                    script_data[s.get("id", "")] = s.get("output", "")

                ports.append(
                    PortInfo(
                        port=int(port_el.get("portid", 0)),
                        protocol=port_el.get("protocol", "tcp"),
                        state=state,
                        service=svc_name,
                        product=product,
                        version=version,
                        extra_info=extra,
                        scripts=script_data,
                    )
                )

        # --- timing ---
        times_el = host_el.find("times")
        scan_time = times_el.get("elapsed", "") if times_el is not None else ""

        hosts.append(
            HostResult(
                ip=ip,
                mac=mac,
                hostnames=hostnames,
                os_guess=os_guess,
                os_accuracy=os_acc,
                ports=ports,
                scan_time=scan_time,
            )
        )
    return hosts


def run_nmap(
    target: str, opts: NmapOptions, out_folder: Path
) -> tuple[list[HostResult], Path, Path]:
    ensure_dir(out_folder)
    stamp = timestamp()
    xml_out = out_folder / f"nmap_{stamp}.xml"
    normal_out = out_folder / f"nmap_{stamp}.txt"

    cmd = build_nmap_cmd(target, opts, xml_out, normal_out)
    safe_print(f"[info]▶ Nmap:[/] {' '.join(cmd)}")

    rc, stdout, stderr = run_cmd(cmd, timeout=NMAP_TIMEOUT)

    # Auto-retry with -Pn if host appears down
    combined = stdout + stderr
    if "Host seems down" in combined and "-Pn" not in cmd:
        safe_print("[warning]Host seems down — retrying with -Pn[/]")
        opts_pn = NmapOptions(**{**asdict(opts), "extra_flags": opts.extra_flags + ["-Pn"]})
        stamp = timestamp()
        xml_out = out_folder / f"nmap_{stamp}_pn.xml"
        normal_out = out_folder / f"nmap_{stamp}_pn.txt"
        cmd = build_nmap_cmd(target, opts_pn, xml_out, normal_out)
        rc, stdout, stderr = run_cmd(cmd, timeout=NMAP_TIMEOUT)

    xml_text = xml_out.read_text(encoding="utf-8", errors="ignore") if xml_out.exists() else ""
    hosts = parse_nmap_xml(xml_text)
    return hosts, xml_out, normal_out


# ─── Subdomain Enumeration ─────────────────────────────────────────────────────


def _subfinder(target: str, out_file: Path) -> bool:
    if not tool_exists("subfinder"):
        return False
    rc, _, _ = run_cmd(["subfinder", "-d", target, "-silent", "-all", "-o", str(out_file)])
    return rc == 0 and out_file.exists() and out_file.stat().st_size > 0


def _amass(target: str, out_file: Path) -> bool:
    if not tool_exists("amass"):
        return False
    rc, _, _ = run_cmd(["amass", "enum", "-passive", "-d", target, "-o", str(out_file)], timeout=300)
    return rc == 0 and out_file.exists() and out_file.stat().st_size > 0


def _assetfinder(target: str, out_file: Path) -> bool:
    if not tool_exists("assetfinder"):
        return False
    rc, out, _ = run_cmd(["assetfinder", "--subs-only", target])
    if rc == 0 and out:
        out_file.write_text(out)
        return True
    return False


def _ffuf_subdomain(target: str, wordlist: Path, out_file: Path, threads: int = 50) -> bool:
    if not tool_exists("ffuf"):
        return False
    csv_tmp = out_file.with_suffix(".csv")
    cmd = [
        "ffuf", "-w", str(wordlist),
        "-u", f"https://FUZZ.{target}",
        "-mc", "200,204,301,302,307,401,403,405",
        "-t", str(threads),
        "-o", str(csv_tmp), "-of", "csv",
        "-timeout", "10",
    ]
    rc, _, _ = run_cmd(cmd, timeout=600)
    if csv_tmp.exists():
        found: set[str] = set()
        with csv_tmp.open(errors="ignore") as f:
            for row in csv.reader(f):
                if not row:
                    continue
                url = row[0]
                try:
                    host = urlparse(url).netloc
                    if host and (host.endswith("." + target) or host == target):
                        found.add(host)
                except Exception:
                    pass
        if found:
            out_file.write_text("\n".join(sorted(found)))
            return True
    return False


def _dns_brute(target: str, wordlist: Path, out_file: Path) -> bool:
    """Minimal DNS brute using `host` — last resort fallback."""
    found: set[str] = set()
    with wordlist.open(errors="ignore") as wl:
        lines = [l.strip() for l in wl if l.strip()]
    safe_print(f"[dim]DNS brute: testing {len(lines):,} names...[/]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as prog:
        task = prog.add_task("Brute-forcing...", total=len(lines))
        for name in lines:
            fqdn = f"{name}.{target}"
            if resolve_host(fqdn):
                found.add(fqdn)
            prog.advance(task)
    out_file.write_text("\n".join(sorted(found)))
    return bool(found)


def subdomain_enum(target: str, out_folder: Path, wordlist_size: str = "medium") -> list[str]:
    ensure_dir(out_folder)
    merged_file = out_folder / "subdomains_merged.txt"
    all_subs: set[str] = set()

    def _try(label: str, fn, *args):
        tmp = out_folder / f"subs_{label}.txt"
        safe_print(f"[info]  → Trying {label}...[/]")
        try:
            ok = fn(*args, tmp)
            if ok and tmp.exists():
                lines = {l.strip() for l in tmp.read_text().splitlines() if l.strip()}
                safe_print(f"[success]  ✔ {label}: {len(lines)} subs[/]")
                all_subs.update(lines)
                return True
        except Exception as e:
            log.debug(f"{label} error: {e}")
        safe_print(f"[dim]  ✘ {label} produced no results[/]")
        return False

    safe_print(Panel.fit("[header]Subdomain Enumeration[/]"))

    _try("subfinder", _subfinder, target)
    _try("amass", _amass, target)
    _try("assetfinder", _assetfinder, target)

    if not all_subs:
        seclists = detect_seclists()
        if seclists:
            wl_rel = WORDLISTS["sub"].get(wordlist_size, WORDLISTS["sub"]["medium"])
            wl = seclists / wl_rel
            if not wl.exists():
                wl = seclists / WORDLISTS["sub"]["small"]
            if wl.exists():
                if not _try("ffuf", _ffuf_subdomain, target, wl):
                    _try("dns-brute", _dns_brute, target, wl)
        else:
            internal_wl = out_folder / "_internal_subs.txt"
            internal_wl.write_text(
                "\n".join([
                    "www","dev","test","stage","staging","api","mail","vpn","admin","beta",
                    "ns1","ns2","ftp","ssh","portal","dashboard","auth","login","app","cdn",
                ])
            )
            _try("dns-brute-internal", _dns_brute, target, internal_wl)

    # Filter to only resolvable subs (live check)
    if all_subs:
        safe_print(f"[info]Verifying {len(all_subs)} subdomains (DNS resolution check)...[/]")
        live: set[str] = set()
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(resolve_host, s): s for s in all_subs}
            for f in as_completed(futures):
                s = futures[f]
                if f.result() is not None:
                    live.add(s)
        all_subs = live

    merged_file.write_text("\n".join(sorted(all_subs)))
    safe_print(f"[success]✔ {len(all_subs)} live subdomains → {merged_file}[/]")
    return sorted(all_subs)


# ─── Directory Brute (Feroxbuster / ffuf fallback) ─────────────────────────────


def run_dir_scan(target_url: str, out_folder: Path, wordlist_size: str = "small") -> Optional[Path]:
    ensure_dir(out_folder)
    out_file = out_folder / "dirscan.txt"
    seclists = detect_seclists()

    wl: Optional[Path] = None
    if seclists:
        wl_rel = WORDLISTS["dir"].get(wordlist_size, WORDLISTS["dir"]["small"])
        candidate = seclists / wl_rel
        if candidate.exists():
            wl = candidate

    if tool_exists("feroxbuster"):
        cmd = [
            "feroxbuster", "-u", target_url,
            "--no-recursion", "-q",
            "-t", "50", "-o", str(out_file),
        ]
        if wl:
            cmd += ["-w", str(wl)]
        safe_print(f"[info]▶ feroxbuster on {target_url}[/]")
        run_cmd(cmd, timeout=600)
        if out_file.exists():
            safe_print(f"[success]✔ feroxbuster → {out_file}[/]")
            return out_file

    if tool_exists("ffuf") and wl:
        ffuf_out = out_folder / "ffuf_dir.csv"
        cmd = [
            "ffuf", "-w", str(wl),
            "-u", f"{target_url.rstrip('/')}/FUZZ",
            "-mc", "200,204,301,302,307,401,403",
            "-t", "50", "-o", str(ffuf_out), "-of", "csv",
            "-timeout", "10",
        ]
        safe_print(f"[info]▶ ffuf dir-scan on {target_url}[/]")
        run_cmd(cmd, timeout=600)
        if ffuf_out.exists():
            findings = []
            with ffuf_out.open(errors="ignore") as f:
                for row in csv.reader(f):
                    if row:
                        findings.append(row[0])
            out_file.write_text("\n".join(findings))
            safe_print(f"[success]✔ ffuf dir-scan → {out_file}[/]")
            return out_file

    safe_print("[warning]No directory scanning tool available (feroxbuster/ffuf)[/]")
    return None


# ─── Masscan ───────────────────────────────────────────────────────────────────


def run_masscan(target: str, out_folder: Path, rate: int = 5000) -> tuple[Optional[Path], set[int]]:
    if not tool_exists("masscan"):
        safe_print("[warning]masscan not installed — skipping[/]")
        return None, set()

    ensure_dir(out_folder)
    out_file = out_folder / "masscan.txt"
    cmd = ["masscan", target, "-p", "1-65535", "--rate", str(rate), "-oL", str(out_file)]
    safe_print(f"[info]▶ Masscan (rate={rate})[/]")
    rc, _, err = run_cmd(cmd, timeout=600)

    open_ports: set[int] = set()
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            parts = line.split()
            # masscan -oL format: open tcp PORT IP timestamp
            if len(parts) >= 3 and parts[0] == "open":
                with contextlib.suppress(ValueError):
                    open_ports.add(int(parts[2]))
        safe_print(f"[success]✔ Masscan: {len(open_ports)} open ports → {out_file}[/]")
    return out_file, open_ports


# ─── Whatweb ───────────────────────────────────────────────────────────────────


def run_whatweb(target_url: str, out_folder: Path) -> Optional[Path]:
    if not tool_exists("whatweb"):
        safe_print("[dim]whatweb not found — skipping[/]")
        return None
    out_file = out_folder / "whatweb.txt"
    rc, out, _ = run_cmd(["whatweb", "--color=never", "--log-verbose", str(out_file), target_url], timeout=120)
    if out_file.exists():
        safe_print(f"[success]✔ whatweb → {out_file}[/]")
        return out_file
    return None


# ─── Nikto ─────────────────────────────────────────────────────────────────────


def run_nikto(target_url: str, out_folder: Path) -> Optional[Path]:
    if not tool_exists("nikto"):
        safe_print("[dim]nikto not found — skipping[/]")
        return None
    out_file = out_folder / "nikto.txt"
    cmd = ["nikto", "-h", target_url, "-output", str(out_file), "-Format", "txt", "-nointeractive"]
    safe_print(f"[info]▶ Nikto on {target_url}[/]")
    rc, out, _ = run_cmd(cmd, timeout=600)
    if out_file.exists():
        safe_print(f"[success]✔ Nikto → {out_file}[/]")
        return out_file
    return None


# ─── Nuclei ────────────────────────────────────────────────────────────────────


def run_nuclei(target: str, out_folder: Path) -> Optional[Path]:
    if not tool_exists("nuclei"):
        safe_print("[dim]nuclei not found — skipping[/]")
        return None
    out_file = out_folder / "nuclei.txt"
    cmd = [
        "nuclei", "-u", target,
        "-severity", "medium,high,critical",
        "-silent",
        "-o", str(out_file),
    ]
    safe_print(f"[info]▶ Nuclei on {target}[/]")
    rc, _, _ = run_cmd(cmd, timeout=1800)
    if out_file.exists() and out_file.stat().st_size > 0:
        safe_print(f"[success]✔ Nuclei → {out_file}[/]")
        return out_file
    return None


# ─── Aquatone ──────────────────────────────────────────────────────────────────


def run_aquatone(hosts_file: Path, out_folder: Path) -> Optional[Path]:
    if not tool_exists("aquatone"):
        safe_print("[dim]aquatone not found — skipping screenshots[/]")
        return None
    aq_dir = out_folder / "aquatone"
    ensure_dir(aq_dir)
    cmd_str = f"cat {hosts_file} | aquatone -out {aq_dir} -quiet"
    rc, _, err = run_cmd(["/bin/sh", "-c", cmd_str], timeout=600)
    if rc == 0:
        safe_print(f"[success]✔ Aquatone screenshots → {aq_dir}[/]")
        return aq_dir
    safe_print(f"[warning]Aquatone failed: {err[:200]}[/]")
    return None


# ─── Reporting ─────────────────────────────────────────────────────────────────


def _severity_badge(sev: str) -> str:
    colors = {"critical": "bold red", "high": "orange1", "medium": "yellow", "info": "dim"}
    return f"[{colors.get(sev, 'white')}]{sev.upper()}[/]"


def render_open_ports_table(hosts: list[HostResult]) -> Table:
    table = Table(
        title="[bold]Open Ports Summary[/]",
        show_lines=True,
        highlight=True,
        border_style="blue",
    )
    table.add_column("Host / IP", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right")
    table.add_column("Proto", justify="center")
    table.add_column("State", justify="center")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Risk", justify="center")
    table.add_column("Script Output", max_width=40, overflow="fold")

    for host in hosts:
        label = ", ".join(host.hostnames) if host.hostnames else host.ip
        for p in host.open_ports:
            ver = " ".join(filter(None, [p.product, p.version, p.extra_info]))
            script_out = "; ".join(f"{k}: {v[:60]}" for k, v in p.scripts.items())
            table.add_row(
                label,
                str(p.port),
                p.protocol,
                p.display_state,
                p.service or "-",
                ver or "-",
                _severity_badge(p.severity),
                script_out or "-",
            )

    return table


def generate_json_report(result: ReconResult, path: Path):
    def default(o):
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)

    with path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "target": result.target,
                "start": result.start_time,
                "end": result.end_time,
                "subdomains": result.subdomains,
                "hosts": [
                    {
                        "ip": h.ip,
                        "mac": h.mac,
                        "hostnames": h.hostnames,
                        "os": h.os_guess,
                        "os_accuracy": h.os_accuracy,
                        "ports": [
                            {
                                "port": p.port,
                                "protocol": p.protocol,
                                "state": p.state,
                                "service": p.service,
                                "product": p.product,
                                "version": p.version,
                                "severity": p.severity,
                                "scripts": p.scripts,
                            }
                            for p in h.ports
                        ],
                        "source_subdomain": h.source_subdomain,
                    }
                    for h in result.hosts
                ],
                "ferox_findings": result.ferox_findings,
                "nikto_findings": result.nikto_findings,
                "whatweb_findings": result.whatweb_findings,
                "nuclei_findings": result.nuclei_findings,
                "errors": result.errors,
            },
            f,
            indent=2,
            default=default,
        )


def generate_html_report(result: ReconResult, config: ScanConfig, path: Path):
    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    port_rows = ""
    for host in result.hosts:
        label = esc(", ".join(host.hostnames) if host.hostnames else host.ip)
        for p in host.open_ports:
            sev_colors = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#ffd700", "info": "#aaa"}
            sev_color = sev_colors.get(p.severity, "#aaa")
            ver = esc(" ".join(filter(None, [p.product, p.version, p.extra_info])))
            script_out = esc("; ".join(f"{k}: {v[:80]}" for k, v in p.scripts.items()))
            port_rows += f"""
            <tr>
                <td>{label}</td>
                <td><strong>{p.port}</strong></td>
                <td>{esc(p.protocol)}</td>
                <td style="color:#2ecc71">{esc(p.state)}</td>
                <td>{esc(p.service)}</td>
                <td>{ver}</td>
                <td><span style="color:{sev_color};font-weight:bold">{p.severity.upper()}</span></td>
                <td style="font-size:0.8em">{script_out}</td>
            </tr>"""

    sub_items = "".join(f"<li><code>{esc(s)}</code></li>" for s in result.subdomains)
    ferox_items = "".join(f"<li>{esc(f)}</li>" for f in result.ferox_findings[:200])
    nikto_items = "".join(f"<li>{esc(f)}</li>" for f in result.nikto_findings)
    nuclei_items = "".join(f"<li>{esc(f)}</li>" for f in result.nuclei_findings)

    total_open = sum(len(h.open_ports) for h in result.hosts)
    critical_ports = sum(
        1 for h in result.hosts for p in h.open_ports if p.severity == "critical"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconNinja Report — {esc(result.target)}</title>
<style>
  :root {{
    --bg: #0d0d0d; --surface: #1a1a2e; --accent: #00d4ff;
    --text: #e0e0e0; --dim: #888; --border: #333;
    --success: #2ecc71; --danger: #e74c3c; --warn: #f39c12;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; }}
  header {{ background: linear-gradient(135deg,#16213e,#0f3460,#533483);
            padding: 2rem; text-align: center; border-bottom: 2px solid var(--accent); }}
  header h1 {{ font-size: 2.5rem; color: var(--accent); letter-spacing: 4px; }}
  header .meta {{ color: var(--dim); margin-top: .5rem; }}
  .stats-bar {{ display: flex; gap: 1rem; padding: 1rem 2rem; background: var(--surface); flex-wrap: wrap; }}
  .stat {{ background: #111; border: 1px solid var(--border); border-radius: 8px;
           padding: .8rem 1.5rem; flex: 1; min-width: 150px; text-align: center; }}
  .stat .val {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
  .stat .lbl {{ font-size: .8rem; color: var(--dim); }}
  main {{ padding: 2rem; max-width: 1400px; margin: auto; }}
  section {{ margin-bottom: 2rem; }}
  h2 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: .5rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
  th {{ background: #16213e; color: var(--accent); padding: .6rem .8rem; text-align: left; }}
  td {{ padding: .5rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #1a2040; }}
  code {{ background: #111; padding: .1rem .4rem; border-radius: 4px; color: #7dd3fc; }}
  ul {{ padding-left: 1.5rem; }}
  li {{ margin: .3rem 0; color: var(--dim); }}
  .tag-crit {{ color: #ff4444; font-weight: bold; }}
  .tag-high {{ color: #ff8c00; font-weight: bold; }}
  .tag-med  {{ color: #ffd700; font-weight: bold; }}
  footer {{ text-align: center; padding: 2rem; color: var(--dim); font-size: .8rem; }}
</style>
</head>
<body>
<header>
  <h1>⚡ RECONNJA</h1>
  <div class="meta">Target: <strong>{esc(result.target)}</strong> &nbsp;|&nbsp; {esc(result.start_time)} → {esc(result.end_time)}</div>
</header>

<div class="stats-bar">
  <div class="stat"><div class="val">{len(result.subdomains)}</div><div class="lbl">Subdomains</div></div>
  <div class="stat"><div class="val">{len(result.hosts)}</div><div class="lbl">Hosts</div></div>
  <div class="stat"><div class="val">{total_open}</div><div class="lbl">Open Ports</div></div>
  <div class="stat"><div class="val" style="color:#ff4444">{critical_ports}</div><div class="lbl">High-Risk Ports</div></div>
  <div class="stat"><div class="val">{len(result.ferox_findings)}</div><div class="lbl">Dir Findings</div></div>
  <div class="stat"><div class="val">{len(result.nuclei_findings)}</div><div class="lbl">Nuclei Findings</div></div>
</div>

<main>

{"<section><h2>🌐 Subdomains</h2><ul>" + sub_items + "</ul></section>" if result.subdomains else ""}

<section>
  <h2>🔍 Open Ports</h2>
  {"<p style='color:var(--dim)'>No open ports found.</p>" if not port_rows else f'''
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th>
    <th>Service</th><th>Version</th><th>Risk</th><th>Scripts</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>'''}
</section>

{"<section><h2>📁 Directory Scan Findings</h2><ul>" + ferox_items + "</ul></section>" if result.ferox_findings else ""}
{"<section><h2>🧪 Nikto Findings</h2><ul>" + nikto_items + "</ul></section>" if result.nikto_findings else ""}
{"<section><h2>🚨 Nuclei Vulnerabilities</h2><ul>" + nuclei_items + "</ul></section>" if result.nuclei_findings else ""}

</main>
<footer>Generated by {APP_NAME} v{VERSION} &nbsp;•&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
<em>⚠ For authorized testing only.</em></footer>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")


def generate_markdown_report(result: ReconResult, path: Path):
    lines = [
        f"# ReconNinja Report — {result.target}",
        f"",
        f"**Scan Start:** {result.start_time}  ",
        f"**Scan End:** {result.end_time}  ",
        f"**Subdomains Found:** {len(result.subdomains)}  ",
        f"**Hosts Scanned:** {len(result.hosts)}  ",
        f"",
    ]
    if result.subdomains:
        lines += ["## Subdomains", ""]
        lines += [f"- {s}" for s in result.subdomains]
        lines += [""]
    lines += ["## Open Ports", ""]
    lines += ["| Host | Port | Proto | State | Service | Version | Risk |", "|-|-|-|-|-|-|-|"]
    for host in result.hosts:
        label = ", ".join(host.hostnames) if host.hostnames else host.ip
        for p in host.open_ports:
            ver = " ".join(filter(None, [p.product, p.version]))
            lines.append(f"| {label} | {p.port} | {p.protocol} | {p.state} | {p.service} | {ver} | {p.severity.upper()} |")
    if result.nuclei_findings:
        lines += ["", "## Nuclei Vulnerabilities", ""]
        lines += [f"- {f}" for f in result.nuclei_findings]
    if result.errors:
        lines += ["", "## Errors", ""]
        lines += [f"- {e}" for e in result.errors]
    path.write_text("\n".join(lines), encoding="utf-8")


# ─── Tool availability check ───────────────────────────────────────────────────


def print_tool_status():
    tools = [
        ("nmap", True),
        ("subfinder", False),
        ("amass", False),
        ("assetfinder", False),
        ("ffuf", False),
        ("feroxbuster", False),
        ("masscan", False),
        ("whatweb", False),
        ("nikto", False),
        ("nuclei", False),
        ("aquatone", False),
    ]
    table = Table(title="Tool Availability", border_style="blue", show_lines=False)
    table.add_column("Tool", style="cyan")
    table.add_column("Required", justify="center")
    table.add_column("Status", justify="center")
    for name, required in tools:
        found = tool_exists(name)
        status = "[success]✔ FOUND[/]" if found else ("[danger]✘ MISSING[/]" if required else "[dim]– not found[/]")
        req_label = "[danger]yes[/]" if required else "no"
        table.add_row(name, req_label, status)
    console.print(table)
    seclists = detect_seclists()
    console.print(f"[info]SecLists:[/] {seclists or '[warning]NOT FOUND[/]'}")
    console.print()


# ─── Interactive menus ─────────────────────────────────────────────────────────


def prompt_nmap_opts(profile: ScanProfile) -> NmapOptions:
    if profile == ScanProfile.FAST:
        return NmapOptions(top_ports=100, scripts=False, version_detection=False, timing="T4")
    if profile == ScanProfile.STANDARD:
        return NmapOptions(top_ports=1000, scripts=True, version_detection=True, timing="T4")
    if profile == ScanProfile.THOROUGH:
        return NmapOptions(all_ports=True, scripts=True, version_detection=True, os_detection=True, timing="T3")
    if profile == ScanProfile.STEALTH:
        return NmapOptions(top_ports=1000, stealth=True, scripts=False, version_detection=False, timing="T2")

    # CUSTOM
    console.print(Panel.fit("[header]Custom Scan Builder[/]"))
    all_ports = Confirm.ask("Scan ALL ports (-p-)?", default=False)
    top_ports = 0
    if not all_ports:
        top_ports = int(Prompt.ask("Top ports to scan", default="1000"))
    return NmapOptions(
        all_ports=all_ports,
        top_ports=top_ports,
        scripts=Confirm.ask("Use default scripts (-sC)?", default=True),
        version_detection=Confirm.ask("Version detection (-sV)?", default=True),
        os_detection=Confirm.ask("OS detection (-O)?", default=False),
        aggressive=Confirm.ask("Aggressive mode (-A)?", default=False),
        stealth=Confirm.ask("Stealth SYN scan (-sS, needs root)?", default=False),
        timing=Prompt.ask("Timing template", choices=["T1","T2","T3","T4","T5"], default="T4"),
        extra_flags=[f for f in Prompt.ask("Extra nmap flags (space-separated, or blank)", default="").split() if f],
    )


def build_config_interactive() -> Optional[ScanConfig]:
    console.print(Panel.fit(
        f"[bold green]{APP_NAME} v{VERSION}[/]\n[dim]All-in-one recon framework — authorized use only[/]",
        border_style="green",
    ))

    console.print(Rule("[dim]Select Scan Profile[/]"))
    console.print("""
  [1] Fast          — top 100 ports, no scripts, quick sweep
  [2] Standard      — top 1000 ports, scripts + versions  [default]
  [3] Thorough      — all ports, OS/version/scripts
  [4] Stealth       — SYN scan, low timing, no scripts
  [5] Custom        — build your own
  [6] Full Suite    — subs → dir-scan → masscan → nmap → nuclei → screenshots
  [0] Exit
""")

    choice = Prompt.ask("Choice", choices=["0","1","2","3","4","5","6"], default="2")
    if choice == "0":
        return None

    profile_map = {
        "1": ScanProfile.FAST, "2": ScanProfile.STANDARD, "3": ScanProfile.THOROUGH,
        "4": ScanProfile.STEALTH, "5": ScanProfile.CUSTOM, "6": ScanProfile.FULL_SUITE,
    }
    profile = profile_map[choice]

    target = Prompt.ask("\n[bold]Target[/] (domain or IP)").strip()
    if not target:
        console.print("[danger]No target provided.[/]")
        return None
    if not is_valid_target(target):
        console.print(f"[danger]'{target}' does not look like a valid domain or IP.[/]")
        if not Confirm.ask("Continue anyway?", default=False):
            return None

    if not Confirm.ask(
        f"\n[danger bold]⚠  You confirm you have written permission to scan {target}?[/]",
        default=False,
    ):
        console.print("[danger]Aborted — permission not confirmed.[/]")
        return None

    nmap_opts = prompt_nmap_opts(profile)
    wordlist_size = "medium"

    cfg = ScanConfig(target=target, profile=profile, nmap_opts=nmap_opts)

    if profile == ScanProfile.FULL_SUITE:
        console.print(Rule("[dim]Full Suite Options[/]"))
        cfg.run_subdomains = Confirm.ask("Subdomain enumeration?", default=True)
        cfg.run_feroxbuster = Confirm.ask("Directory scan (feroxbuster/ffuf)?", default=True)
        cfg.run_masscan = Confirm.ask("Masscan port sweep (requires root)?", default=False)
        cfg.run_whatweb = Confirm.ask("WhatWeb fingerprinting?", default=True)
        cfg.run_nikto = Confirm.ask("Nikto web scanner?", default=False)
        cfg.run_nuclei = Confirm.ask("Nuclei vulnerability templates?", default=True)
        cfg.run_aquatone = Confirm.ask("Aquatone screenshots?", default=False)
        if cfg.run_masscan:
            cfg.masscan_rate = int(Prompt.ask("Masscan rate (pps)", default="5000"))
        wl_choice = Prompt.ask("Wordlist size", choices=["small","medium","large"], default="medium")
        cfg.wordlist_size = wl_choice
        wordlist_size = wl_choice

    return cfg


# ─── Core scan orchestration ───────────────────────────────────────────────────


def nmap_worker(subdomain: str, opts: NmapOptions, out_folder: Path) -> tuple[str, list[HostResult]]:
    """Thread worker: run nmap on one subdomain."""
    hosts, _, _ = run_nmap(subdomain, opts, out_folder)
    for h in hosts:
        h.source_subdomain = subdomain
    return subdomain, hosts


def orchestrate(cfg: ScanConfig) -> ReconResult:
    stamp = timestamp()
    out_folder = ensure_dir(REPORTS_DIR / cfg.target / stamp)

    # Save config
    config_file = out_folder / "scan_config.json"
    config_file.write_text(json.dumps(cfg.to_dict(), indent=2, default=str))

    result = ReconResult(target=cfg.target, start_time=stamp)
    console.print(f"\n[success]Output folder: {out_folder}[/]\n")

    # ── 1. Subdomain enumeration ─────────────────────────────────────────────
    if cfg.run_subdomains:
        result.subdomains = subdomain_enum(cfg.target, out_folder, cfg.wordlist_size)

    # ── 2. Directory scan ────────────────────────────────────────────────────
    if cfg.run_feroxbuster:
        ferox_file = run_dir_scan(f"https://{cfg.target}", out_folder, cfg.wordlist_size)
        if ferox_file and ferox_file.exists():
            result.ferox_findings = [
                l for l in ferox_file.read_text().splitlines() if l.strip()
            ][:500]

    # ── 3. Masscan ───────────────────────────────────────────────────────────
    masscan_ports: set[int] = set()
    if cfg.run_masscan:
        _, masscan_ports = run_masscan(cfg.target, out_folder, cfg.masscan_rate)
        # Feed discovered ports back into nmap opts as targeted port list
        if masscan_ports:
            port_str = ",".join(str(p) for p in sorted(masscan_ports))
            cfg.nmap_opts.extra_flags.append(f"-p{port_str}")
            cfg.nmap_opts.all_ports = False
            cfg.nmap_opts.top_ports = 0

    # ── 4. WhatWeb ───────────────────────────────────────────────────────────
    if cfg.run_whatweb:
        ww_file = run_whatweb(f"https://{cfg.target}", out_folder)
        if ww_file and ww_file.exists():
            result.whatweb_findings = ww_file.read_text().splitlines()

    # ── 5. Nikto ─────────────────────────────────────────────────────────────
    if cfg.run_nikto:
        nk_file = run_nikto(f"https://{cfg.target}", out_folder)
        if nk_file and nk_file.exists():
            result.nikto_findings = [l for l in nk_file.read_text().splitlines() if l.strip()]

    # ── 6. Nuclei ────────────────────────────────────────────────────────────
    if cfg.run_nuclei:
        nc_file = run_nuclei(f"https://{cfg.target}", out_folder)
        if nc_file and nc_file.exists():
            result.nuclei_findings = [l for l in nc_file.read_text().splitlines() if l.strip()]

    # ── 7. Nmap ──────────────────────────────────────────────────────────────
    targets_to_scan: list[str] = result.subdomains if result.subdomains else [cfg.target]
    console.print(Panel.fit(f"[header]Nmap scanning {len(targets_to_scan)} target(s)[/]"))

    all_hosts: list[HostResult] = []
    workers = min(cfg.threads, len(targets_to_scan))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Nmap scans...", total=len(targets_to_scan))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures: dict[Future, str] = {
                ex.submit(nmap_worker, t, cfg.nmap_opts, out_folder): t
                for t in targets_to_scan
            }
            for fut in as_completed(futures):
                sd = futures[fut]
                try:
                    sd, hosts = fut.result()
                    all_hosts.extend(hosts)
                    open_c = sum(len(h.open_ports) for h in hosts)
                    safe_print(f"[success]  ✔ {sd} — {open_c} open port(s)[/]")
                except Exception as e:
                    result.errors.append(f"{sd}: {e}")
                    safe_print(f"[warning]  ✘ {sd}: {e}[/]")
                progress.advance(task)

    result.hosts = all_hosts

    # ── 8. Aquatone ──────────────────────────────────────────────────────────
    if cfg.run_aquatone and result.subdomains:
        sub_file = out_folder / "subdomains_merged.txt"
        if sub_file.exists():
            run_aquatone(sub_file, out_folder)

    # ── 9. Reports ───────────────────────────────────────────────────────────
    result.end_time = timestamp()
    console.print(Rule("[header]Generating Reports[/]"))

    json_path = out_folder / "report.json"
    html_path = out_folder / "report.html"
    md_path = out_folder / "report.md"

    generate_json_report(result, json_path)
    generate_html_report(result, cfg, html_path)
    generate_markdown_report(result, md_path)

    console.print(f"[info]  JSON:[/] {json_path}")
    console.print(f"[info]  HTML:[/] {html_path}")
    console.print(f"[info]  MD:[/]   {md_path}")
    console.print()

    # ── 10. Terminal summary ─────────────────────────────────────────────────
    if result.hosts:
        console.print(render_open_ports_table(result.hosts))

    total_open = sum(len(h.open_ports) for h in result.hosts)
    crit = sum(1 for h in result.hosts for p in h.open_ports if p.severity == "critical")
    console.print(
        Panel.fit(
            f"[success]✔ Scan complete[/]\n"
            f"Subdomains: [cyan]{len(result.subdomains)}[/]  |  "
            f"Hosts: [cyan]{len(result.hosts)}[/]  |  "
            f"Open Ports: [cyan]{total_open}[/]  |  "
            f"High-Risk: [danger]{crit}[/]  |  "
            f"Nuclei: [yellow]{len(result.nuclei_findings)}[/]\n"
            f"Reports → [dim]{out_folder}[/]",
            border_style="green",
        )
    )

    if result.errors:
        console.print(f"[warning]{len(result.errors)} error(s) occurred — see report.json[/]")

    return result


# ─── CLI / Entry point ─────────────────────────────────────────────────────────


def parse_args() -> Optional[argparse.Namespace]:
    parser = argparse.ArgumentParser(
        prog="recon_ninja",
        description=f"{APP_NAME} v{VERSION} — All-in-one recon framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use ONLY against targets you own or have explicit written permission to test.",
    )
    parser.add_argument("--target", "-t", help="Target domain or IP")
    parser.add_argument(
        "--profile", "-p",
        choices=["fast","standard","thorough","stealth","custom","full_suite"],
        default=None,
    )
    parser.add_argument("--all-ports", action="store_true")
    parser.add_argument("--top-ports", type=int, default=1000)
    parser.add_argument("--timing", default="T4", choices=["T1","T2","T3","T4","T5"])
    parser.add_argument("--threads", type=int, default=MAX_THREADS)
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--ferox", action="store_true")
    parser.add_argument("--masscan", action="store_true")
    parser.add_argument("--nuclei", action="store_true")
    parser.add_argument("--nikto", action="store_true")
    parser.add_argument("--whatweb", action="store_true")
    parser.add_argument("--aquatone", action="store_true")
    parser.add_argument("--wordlist-size", choices=["small","medium","large"], default="medium")
    parser.add_argument("--check-tools", action="store_true", help="Show tool availability and exit")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip permission confirmation")

    # If no CLI args given → interactive mode
    if len(sys.argv) == 1:
        return None
    return parser.parse_args()


def build_config_from_args(args: argparse.Namespace) -> Optional[ScanConfig]:
    if args.check_tools:
        print_tool_status()
        return None

    if not args.target:
        console.print("[danger]--target is required in CLI mode[/]")
        return None

    if not args.yes:
        if not Confirm.ask(
            f"[danger]⚠  You confirm written permission to scan {args.target}?[/]",
            default=False,
        ):
            console.print("[danger]Aborted.[/]")
            return None

    profile = ScanProfile(args.profile) if args.profile else ScanProfile.STANDARD
    nmap_opts = NmapOptions(
        all_ports=args.all_ports,
        top_ports=args.top_ports,
        timing=args.timing,
        scripts=True,
        version_detection=True,
    )
    return ScanConfig(
        target=args.target,
        profile=profile,
        nmap_opts=nmap_opts,
        run_subdomains=args.subdomains,
        run_feroxbuster=args.ferox,
        run_masscan=args.masscan,
        run_whatweb=args.whatweb,
        run_nikto=args.nikto,
        run_nuclei=args.nuclei,
        run_aquatone=args.aquatone,
        threads=args.threads,
        wordlist_size=args.wordlist_size,
    )


def main():
    # Graceful Ctrl+C
    def _sigint(sig, frame):
        console.print("\n[danger]Interrupted.[/]")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    args = parse_args()

    if args is None:
        # Interactive mode
        print_tool_status()
        cfg = build_config_interactive()
    else:
        cfg = build_config_from_args(args)

    if cfg is None:
        return

    orchestrate(cfg)


if __name__ == "__main__":
    main()
