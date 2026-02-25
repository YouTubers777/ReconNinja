"""
ReconNinja v3 — Port Scanning
RustScan (fast discovery) → Nmap (deep analysis) + Masscan (optional sweep).
"""

from __future__ import annotations

import contextlib
import copy
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from utils.helpers import run_cmd, tool_exists, ensure_dir, sanitize_dirname, timestamp
from utils.logger import safe_print, log
from utils.models import PortInfo, HostResult, NmapOptions

NMAP_PER_TARGET_TIMEOUT = 1800   # 30 min per target


# ─── RustScan ─────────────────────────────────────────────────────────────────

def run_rustscan(target: str, out_folder: Path) -> set[int]:
    """
    Ultra-fast port discovery with RustScan.
    Returns set of open ports to feed into nmap.
    """
    if not tool_exists("rustscan"):
        safe_print("[dim]rustscan not found — skipping fast sweep[/]")
        return set()

    ensure_dir(out_folder)
    out_file = out_folder / "rustscan.txt"

    cmd = [
        "rustscan",
        "-a", target,
        "--ulimit", "5000",
        "--range", "1-65535",
        "--", "-sV",  # pass-through to nmap for quick version
        "-oN", str(out_file),
    ]
    safe_print(f"[info]▶ RustScan → {target}[/]")
    rc, stdout, stderr = run_cmd(cmd, timeout=300)

    open_ports: set[int] = set()
    combined = stdout + stderr
    for line in combined.splitlines():
        line = line.strip()
        if line.startswith("Open") and ":" in line:
            with contextlib.suppress(ValueError):
                port = int(line.split(":")[-1].strip())
                open_ports.add(port)

    if open_ports:
        safe_print(f"[success]✔ RustScan: {len(open_ports)} open ports[/]")
    else:
        safe_print("[dim]RustScan: no open ports found[/]")

    return open_ports


# ─── Nmap XML Parsing ─────────────────────────────────────────────────────────

def parse_nmap_xml(xml_text: str) -> tuple[list[HostResult], list[str]]:
    """Parse nmap XML → (hosts, errors)."""
    if not xml_text.strip():
        return [], []

    parse_errors: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        msg = f"Nmap XML parse error: {exc}"
        log.warning(msg)
        return [], [msg]

    hosts: list[HostResult] = []
    for host_el in root.findall("host"):
        try:
            ip = mac = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "")

            hostnames: list[str] = []
            hn_el = host_el.find("hostnames")
            if hn_el is not None:
                hostnames = [
                    h.get("name", "")
                    for h in hn_el.findall("hostname")
                    if h.get("name")
                ]

            os_guess = os_acc = ""
            os_el = host_el.find("os")
            if os_el is not None:
                matches = os_el.findall("osmatch")
                if matches:
                    os_guess = matches[0].get("name", "")
                    os_acc   = matches[0].get("accuracy", "")

            ports: list[PortInfo] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    state    = state_el.get("state", "") if state_el is not None else ""
                    svc      = port_el.find("service")
                    script_data: dict[str, str] = {
                        s.get("id", ""): s.get("output", "")
                        for s in port_el.findall("script")
                    }
                    ports.append(PortInfo(
                        port       = int(port_el.get("portid", 0)),
                        protocol   = port_el.get("protocol", "tcp"),
                        state      = state,
                        service    = svc.get("name", "")    if svc is not None else "",
                        product    = svc.get("product", "")  if svc is not None else "",
                        version    = svc.get("version", "")  if svc is not None else "",
                        extra_info = svc.get("extrainfo", "") if svc is not None else "",
                        scripts    = script_data,
                    ))

            times_el = host_el.find("times")
            scan_time = times_el.get("elapsed", "") if times_el is not None else ""

            hosts.append(HostResult(
                ip=ip, mac=mac, hostnames=hostnames,
                os_guess=os_guess, os_accuracy=os_acc,
                ports=ports, scan_time=scan_time,
            ))
        except Exception as exc:
            msg = f"Error parsing host element: {exc}"
            log.debug(msg)
            parse_errors.append(msg)

    return hosts, parse_errors


# ─── Nmap ─────────────────────────────────────────────────────────────────────

def build_nmap_cmd(
    target: str, opts: NmapOptions, xml_out: Path, normal_out: Path
) -> list[str]:
    return ["nmap"] + opts.as_nmap_args() + [
        "-oX", str(xml_out), "-oN", str(normal_out), target
    ]


def run_nmap(
    target: str, opts: NmapOptions, out_folder: Path
) -> tuple[list[HostResult], Path, Path, list[str]]:
    """Returns (hosts, xml_path, txt_path, errors)."""
    ensure_dir(out_folder)
    stamp      = timestamp()
    xml_out    = out_folder / f"nmap_{stamp}.xml"
    normal_out = out_folder / f"nmap_{stamp}.txt"

    cmd = build_nmap_cmd(target, opts, xml_out, normal_out)
    safe_print(f"[info]▶ Nmap: {' '.join(cmd)}[/]")

    rc, stdout, stderr = run_cmd(cmd, timeout=NMAP_PER_TARGET_TIMEOUT)

    combined = stdout + stderr
    if "Host seems down" in combined and "-Pn" not in cmd:
        safe_print("[warning]Host seems down — retrying with -Pn[/]")
        opts_pn = NmapOptions(**{**asdict(opts), "extra_flags": opts.extra_flags + ["-Pn"]})
        stamp      = timestamp()
        xml_out    = out_folder / f"nmap_{stamp}_pn.xml"
        normal_out = out_folder / f"nmap_{stamp}_pn.txt"
        cmd = build_nmap_cmd(target, opts_pn, xml_out, normal_out)
        rc, stdout, stderr = run_cmd(cmd, timeout=NMAP_PER_TARGET_TIMEOUT)

    xml_text = xml_out.read_text(encoding="utf-8", errors="ignore") if xml_out.exists() else ""
    hosts, errors = parse_nmap_xml(xml_text)
    if rc == 124:
        errors.append(f"nmap timed out scanning {target}")

    return hosts, xml_out, normal_out, errors


# ─── Nmap worker (threaded) ───────────────────────────────────────────────────

def nmap_worker(
    subdomain: str, opts: NmapOptions, base_out: Path
) -> tuple[str, list[HostResult], list[str]]:
    """
    Per-subdomain worker. Each gets its own output sub-directory to prevent
    timestamp collisions when workers run concurrently.
    """
    worker_dir = ensure_dir(base_out / sanitize_dirname(subdomain))
    hosts, _, _, errors = run_nmap(subdomain, opts, worker_dir)
    for h in hosts:
        h.source_subdomain = subdomain
    return subdomain, hosts, errors


# ─── Masscan ──────────────────────────────────────────────────────────────────

def run_masscan(
    target: str, out_folder: Path, rate: int = 5000
) -> tuple[Optional[Path], set[int]]:
    if not tool_exists("masscan"):
        safe_print("[dim]masscan not installed — skipping[/]")
        return None, set()

    ensure_dir(out_folder)
    out_file = out_folder / "masscan.txt"
    cmd = [
        "masscan", target, "-p", "1-65535",
        "--rate", str(rate), "-oL", str(out_file),
    ]
    safe_print(f"[info]▶ Masscan (rate={rate})[/]")
    run_cmd(cmd, timeout=600)

    open_ports: set[int] = set()
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "open":
                with contextlib.suppress(ValueError):
                    open_ports.add(int(parts[2]))
        safe_print(f"[success]✔ Masscan: {len(open_ports)} open ports → {out_file}[/]")
    return out_file, open_ports
