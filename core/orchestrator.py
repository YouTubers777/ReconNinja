"""
ReconNinja v3.1 — Core Orchestration Engine
Drives the full recon pipeline: passive → async TCP scan → nmap → web → vuln → report.
"""

from __future__ import annotations

import copy
import json
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import asdict
from pathlib import Path

from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table

from utils.helpers import ensure_dir, timestamp, sanitize_dirname
from utils.logger import safe_print, log, console, _RESULT_LOCK
from utils.models import (
    ReconResult, ScanConfig, ScanProfile, HostResult, PortInfo,
    NmapOptions, SEVERITY_PORTS,
)
from core.subdomains import subdomain_enum
from core.ports import (
    async_port_scan, run_rustscan, run_nmap, run_masscan,
    nmap_worker, NMAP_PER_TARGET_TIMEOUT,
)
from core.web import run_httpx, run_whatweb, run_nikto, run_dir_scan, enrich_hosts_with_web
from core.vuln import run_nuclei, run_aquatone, run_gowitness
from output.reports import generate_json_report, generate_html_report, generate_markdown_report
from plugins import discover_plugins, run_plugins

REPORTS_DIR = Path("reports")


# ─── Terminal display helpers ─────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    colors = {
        "critical": "bold red", "high": "orange1",
        "medium": "yellow",     "info": "dim",
    }
    return f"[{colors.get(sev, 'white')}]{sev.upper()}[/]"


def render_open_ports_table(hosts: list[HostResult]) -> Table:
    table = Table(
        title="[bold]Open Ports Summary[/]",
        show_lines=True, highlight=True, border_style="blue",
    )
    table.add_column("Host / IP",     style="cyan",  no_wrap=True)
    table.add_column("Port",          justify="right")
    table.add_column("Proto",         justify="center")
    table.add_column("State",         justify="center")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Risk",          justify="center")
    table.add_column("Script Output", max_width=40, overflow="fold")
    for host in hosts:
        label = ", ".join(host.hostnames) if host.hostnames else host.ip
        for p in host.open_ports:
            ver        = " ".join(filter(None, [p.product, p.version, p.extra_info]))
            script_out = "; ".join(f"{k}: {v[:60]}" for k, v in p.scripts.items())
            table.add_row(
                label, str(p.port), p.protocol, p.display_state,
                p.service or "-", ver or "-",
                _severity_badge(p.severity), script_out or "-",
            )
    return table


def print_tool_status() -> None:
    from utils.helpers import tool_exists, detect_seclists
    tools = [
        ("nmap",         True),
        ("rustscan",     False),
        ("subfinder",    False),
        ("amass",        False),
        ("assetfinder",  False),
        ("ffuf",         False),
        ("httpx",        False),
        ("feroxbuster",  False),
        ("dirsearch",    False),
        ("masscan",      False),
        ("whatweb",      False),
        ("nikto",        False),
        ("nuclei",       False),
        ("aquatone",     False),
        ("gowitness",    False),
    ]
    table = Table(title="Tool Availability", border_style="blue", show_lines=False)
    table.add_column("Tool",     style="cyan")
    table.add_column("Required", justify="center")
    table.add_column("Status",   justify="center")
    for name, required in tools:
        found = tool_exists(name)
        status = (
            "[success]✔ FOUND[/]" if found
            else ("[danger]✘ MISSING[/]" if required else "[dim]– optional[/]")
        )
        table.add_row(name, "[danger]yes[/]" if required else "no", status)
    console.print(table)
    seclists = detect_seclists()
    console.print(f"[info]SecLists:[/] {seclists or '[warning]NOT FOUND[/]'}")
    console.print()


# ─── Main orchestrator ────────────────────────────────────────────────────────

def orchestrate(cfg: ScanConfig) -> ReconResult:
    stamp      = timestamp()
    out_folder = ensure_dir(REPORTS_DIR / sanitize_dirname(cfg.target) / stamp)
    log_path   = out_folder / "scan.log"

    from utils.logger import setup_file_logger
    setup_file_logger(log_path)

    (out_folder / "scan_config.json").write_text(
        json.dumps(cfg.to_dict(), indent=2, default=str)
    )

    result = ReconResult(target=cfg.target, start_time=stamp)
    console.print(f"\n[success]📁 Output folder: {out_folder}[/]\n")

    # ── Phase 1: Passive Recon ─────────────────────────────────────────────
    if cfg.run_subdomains:
        console.print(Panel.fit("[phase] PHASE 1 — Passive Recon [/]"))
        sub_dir = out_folder / "subdomains"
        result.subdomains = subdomain_enum(cfg.target, sub_dir, cfg.wordlist_size)
        result.phases_completed.append("passive_recon")

    # ─────────────────────────────────────────────────────────────────────
    # PORT DISCOVERY & SERVICE ANALYSIS (v3.2):
    #
    #   Phase 2  : RustScan  — PRIMARY port scanner, all 65535 ports
    #   Phase 2b : Async TCP — fallback/gap-filler (pure Python, no root)
    #   Phase 3  : Masscan   — optional extra sweep, merged into port set
    #   Phase 4  : Nmap      — SERVICE ANALYSIS ONLY on confirmed-open ports
    #                          nmap -sT -Pn -sV -sC -p<port_list>
    #                          NEVER sweeps — only fingerprints known-open ports
    # ─────────────────────────────────────────────────────────────────────
    nmap_opts      = copy.deepcopy(cfg.nmap_opts)
    all_open_ports: set[int] = set()

    # ── Phase 2: RustScan — primary port discovery ─────────────────────
    console.print(Panel.fit("[phase] PHASE 2 — RustScan Port Discovery [/]"))
    rustscan_ports = run_rustscan(cfg.target, out_folder / "rustscan")
    all_open_ports |= rustscan_ports
    result.phases_completed.append("rustscan")

    # ── Phase 2b: Async TCP — fallback / gap-filler ────────────────────
    if not rustscan_ports:
        console.print(Panel.fit("[phase] PHASE 2b — Async TCP Scan (RustScan fallback) [/]"))
    else:
        console.print(Panel.fit("[phase] PHASE 2b — Async TCP Scan (gap-fill) [/]"))

    async_out = ensure_dir(out_folder / "async_scan")
    async_top_n = None if nmap_opts.all_ports else (nmap_opts.top_ports or 1000)
    async_port_infos, _ = async_port_scan(
        target          = cfg.target,
        top_n           = async_top_n,
        concurrency     = cfg.async_concurrency,
        connect_timeout = cfg.async_timeout,
        out_folder      = async_out,
    )
    async_ports = {p.port for p in async_port_infos}
    new_from_async = async_ports - all_open_ports
    if new_from_async:
        safe_print(f"[info]Async scan found {len(new_from_async)} extra port(s): "
                   f"{', '.join(str(p) for p in sorted(new_from_async))}[/]")
    all_open_ports |= async_ports
    result.phases_completed.append("async_tcp_scan")

    # ── Phase 3: Masscan — optional extra sweep ────────────────────────
    if cfg.run_masscan:
        console.print(Panel.fit("[phase] PHASE 3 — Masscan Sweep [/]"))
        _, masscan_ports = run_masscan(cfg.target, out_folder / "masscan", cfg.masscan_rate)
        if masscan_ports:
            result.masscan_ports = sorted(masscan_ports)
            new_from_masscan = masscan_ports - all_open_ports
            if new_from_masscan:
                safe_print(f"[info]Masscan added {len(new_from_masscan)} extra port(s)[/]")
            all_open_ports |= masscan_ports
        result.phases_completed.append("masscan")

    if all_open_ports:
        safe_print(
            f"[success]✔ Confirmed open ports ({len(all_open_ports)}): "
            f"{', '.join(str(p) for p in sorted(all_open_ports))}[/]"
        )
    else:
        safe_print("[warning]No open ports found — skipping Nmap service analysis[/]")

    # ── Phase 4: Nmap service analysis — confirmed ports only ──────────
    console.print(Panel.fit("[phase] PHASE 4 — Nmap Service Analysis [/]"))
    targets_to_scan = result.subdomains if result.subdomains else [cfg.target]
    all_hosts: list[HostResult] = []

    if not all_open_ports:
        safe_print("[dim]No ports to analyse — skipping[/]")
    else:
        console.print(
            f"[dim]{len(targets_to_scan)} target(s) | "
            f"ports: {','.join(str(p) for p in sorted(all_open_ports))} | "
            f"{min(cfg.threads, len(targets_to_scan))} workers[/]"
        )
        workers = min(cfg.threads, len(targets_to_scan))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Nmap service scans...", total=len(targets_to_scan))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                nmap_out = ensure_dir(out_folder / "nmap")
                futures: dict[Future, str] = {
                    ex.submit(
                        nmap_worker, t, all_open_ports, nmap_out,
                        nmap_opts.scripts, nmap_opts.version_detection, nmap_opts.timing,
                    ): t
                    for t in targets_to_scan
                }
                for fut in as_completed(futures):
                    sd = futures[fut]
                    try:
                        _, hosts, errs = fut.result()
                        with _RESULT_LOCK:
                            all_hosts.extend(hosts)
                            result.errors.extend(errs)
                        svc_c = sum(len(h.ports) for h in hosts)
                        safe_print(f"[success]  ✔ {sd} — {svc_c} service(s) identified[/]")
                    except Exception as e:
                        with _RESULT_LOCK:
                            result.errors.append(f"{sd}: {e}")
                        safe_print(f"[warning]  ✘ {sd}: {e}[/]")
                    progress.advance(task)

    result.hosts = all_hosts
    result.phases_completed.append("nmap")

    # ── Phase 5: Web Service Detection (httpx) ────────────────────────────
    web_targets: list[str] = []
    if cfg.run_httpx:
        console.print(Panel.fit("[phase] PHASE 5 — Web Service Detection [/]"))
        # Build web targets from subdomains + hosts with web ports
        web_targets = list(result.subdomains) if result.subdomains else [cfg.target]
        for host in result.hosts:
            for p in host.web_ports:
                scheme = "https" if p.port in {443, 8443} else "http"
                url = f"{scheme}://{host.ip}:{p.port}"
                if url not in web_targets:
                    web_targets.append(url)

        result.web_findings = run_httpx(web_targets, out_folder / "httpx")
        enrich_hosts_with_web(result.hosts, result.web_findings)
        result.phases_completed.append("httpx")

    # ── Phase 6: Directory Brute Force ────────────────────────────────────
    if cfg.run_feroxbuster:
        console.print(Panel.fit("[phase] PHASE 6 — Directory Discovery [/]"))
        dir_targets = [wf.url for wf in result.web_findings] or [f"https://{cfg.target}"]
        for url in dir_targets[:10]:  # cap to avoid runaway
            dir_file = run_dir_scan(url, out_folder / "dirscan" / sanitize_dirname(url), cfg.wordlist_size)
            if dir_file and dir_file.exists():
                result.dir_findings += [
                    l for l in dir_file.read_text().splitlines() if l.strip()
                ]
        result.dir_findings = result.dir_findings[:1000]
        result.phases_completed.append("directory_scan")

    # ── Phase 7: Tech Fingerprinting ──────────────────────────────────────
    if cfg.run_whatweb:
        console.print(Panel.fit("[phase] PHASE 7 — Tech Fingerprinting [/]"))
        ww_file = run_whatweb(f"https://{cfg.target}", out_folder / "whatweb")
        if ww_file and ww_file.exists():
            result.whatweb_findings = ww_file.read_text().splitlines()
        result.phases_completed.append("whatweb")

    # ── Phase 8: Web Vulnerability Scan (Nikto) ───────────────────────────
    if cfg.run_nikto:
        console.print(Panel.fit("[phase] PHASE 8 — Nikto Web Scan [/]"))
        nk_file = run_nikto(f"https://{cfg.target}", out_folder / "nikto")
        if nk_file and nk_file.exists():
            result.nikto_findings = [l for l in nk_file.read_text().splitlines() if l.strip()]
        result.phases_completed.append("nikto")

    # ── Phase 9: Nuclei Vulnerability Templates ───────────────────────────
    if cfg.run_nuclei:
        console.print(Panel.fit("[phase] PHASE 9 — Nuclei Vulnerability Scan [/]"))
        nuclei_targets = [wf.url for wf in result.web_findings] or [f"https://{cfg.target}"]
        for t in nuclei_targets[:20]:
            result.nuclei_findings += run_nuclei(t, out_folder / "nuclei" / sanitize_dirname(t))
        result.phases_completed.append("nuclei")

    # ── Phase 10: Screenshots ─────────────────────────────────────────────
    if cfg.run_aquatone and result.subdomains:
        console.print(Panel.fit("[phase] PHASE 10 — Screenshots [/]"))
        sub_file = out_folder / "subdomains" / "subdomains_merged.txt"
        if sub_file.exists():
            if not run_aquatone(sub_file, out_folder):
                # Try gowitness as fallback
                url_file = out_folder / "_screenshot_urls.txt"
                url_file.write_text("\n".join(wf.url for wf in result.web_findings))
                run_gowitness(url_file, out_folder)
        result.phases_completed.append("screenshots")

    # ── Phase 11: AI Analysis ─────────────────────────────────────────────
    if cfg.run_ai_analysis:
        console.print(Panel.fit("[phase] PHASE 11 — AI Analysis [/]"))
        result.ai_analysis = _generate_ai_analysis(result)
        result.phases_completed.append("ai_analysis")

    # ── Phase 12: Plugins ─────────────────────────────────────────────────
    plugins = discover_plugins()
    if plugins:
        run_plugins(plugins, cfg.target, out_folder, result, cfg)
        result.phases_completed.append("plugins")

    # ── Phase 13: Reports ─────────────────────────────────────────────────
    result.end_time = timestamp()
    console.print(Rule("[header]Generating Reports[/]"))

    json_path = out_folder / "report.json"
    html_path = out_folder / "report.html"
    md_path   = out_folder / "report.md"

    generate_json_report(result, json_path)
    generate_html_report(result, html_path)
    generate_markdown_report(result, md_path)

    console.print(f"[info]  JSON: {json_path}[/]")
    console.print(f"[info]  HTML: {html_path}[/]")
    console.print(f"[info]  MD:   {md_path}[/]")

    # ── Terminal summary ──────────────────────────────────────────────────
    if result.hosts:
        console.print(render_open_ports_table(result.hosts))

    total_open = sum(len(h.open_ports) for h in result.hosts)
    crit       = sum(1 for h in result.hosts for p in h.open_ports if p.severity == "critical")
    vuln_c     = sum(1 for v in result.nuclei_findings if v.severity in ("critical", "high"))

    console.print(Panel.fit(
        f"[success]✔ ReconNinja v3 Complete[/]\n"
        f"Subdomains [cyan]{len(result.subdomains)}[/]  |  "
        f"Hosts [cyan]{len(result.hosts)}[/]  |  "
        f"Open Ports [cyan]{total_open}[/]  |  "
        f"Web Services [cyan]{len(result.web_findings)}[/]  |  "
        f"High-Risk Ports [danger]{crit}[/]  |  "
        f"Vulns [danger]{vuln_c}[/]\n"
        f"Reports → [dim]{out_folder}[/]",
        border_style="green",
    ))

    if result.errors:
        console.print(f"[warning]{len(result.errors)} error(s) — see report.json[/]")

    return result


# ─── AI Analysis ─────────────────────────────────────────────────────────────

def _generate_ai_analysis(result: ReconResult) -> str:
    """
    Rule-based AI analysis (no external API required).
    Examines findings and produces a plain-English threat summary.
    Future: swap this for an LLM call.
    """
    lines: list[str] = ["=== ReconNinja AI Analysis ===", ""]

    total_open = sum(len(h.open_ports) for h in result.hosts)
    crit_ports = [
        (h, p) for h in result.hosts
        for p in h.open_ports if p.severity == "critical"
    ]
    high_vulns = [v for v in result.nuclei_findings if v.severity in ("critical", "high")]

    # Risk level
    risk = "LOW"
    if crit_ports or high_vulns:
        risk = "CRITICAL" if (len(crit_ports) > 3 or len(high_vulns) > 2) else "HIGH"
    elif total_open > 20 or result.nuclei_findings:
        risk = "MEDIUM"

    lines.append(f"Overall Risk Level: {risk}")
    lines.append("")

    # Exposure summary
    lines.append("Attack Surface Summary:")
    lines.append(f"  • {len(result.subdomains)} subdomains discovered")
    lines.append(f"  • {total_open} open ports across {len(result.hosts)} hosts")
    lines.append(f"  • {len(result.web_findings)} live web services")
    lines.append(f"  • {len(result.nuclei_findings)} vulnerability findings")
    lines.append("")

    # High-risk ports
    if crit_ports:
        lines.append("High-Risk Ports (immediate attention):")
        for host, port in crit_ports[:10]:
            label = host.hostnames[0] if host.hostnames else host.ip
            lines.append(f"  ⚠ {label}:{port.port} ({port.service}) — {port.severity.upper()}")
        lines.append("")

    # CVE findings
    if high_vulns:
        lines.append("Critical/High Vulnerabilities:")
        for v in high_vulns[:10]:
            cve = f" [{v.cve}]" if v.cve else ""
            lines.append(f"  ✗ [{v.severity.upper()}] {v.title}{cve} @ {v.target}")
        lines.append("")

    # Recommendations
    lines.append("Recommendations:")
    if any(p.port in {21, 23} for h in result.hosts for p in h.open_ports):
        lines.append("  • Disable plaintext protocols (FTP/Telnet) — use SFTP/SSH")
    if any(p.port == 22 for h in result.hosts for p in h.open_ports):
        lines.append("  • Review SSH configuration: disable root login, use key auth only")
    if any(p.port in {3306, 5432, 27017} for h in result.hosts for p in h.open_ports):
        lines.append("  • Database ports exposed — restrict to internal network only")
    if any(p.port in {445, 139} for h in result.hosts for p in h.open_ports):
        lines.append("  • SMB exposed — patch EternalBlue/MS17-010 if unpatched")
    if len(result.subdomains) > 20:
        lines.append("  • Large subdomain footprint — review for forgotten/shadow IT assets")
    if result.dir_findings:
        lines.append(f"  • {len(result.dir_findings)} directory findings — review for sensitive paths")
    if not lines[-1].startswith("  •"):
        lines.append("  • No critical issues detected — continue with manual testing")

    lines.append("")
    lines.append("This analysis is automated. Manual review recommended before reporting.")

    return "\n".join(lines)
