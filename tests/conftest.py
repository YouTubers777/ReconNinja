"""
tests/conftest.py — ReconNinja v3.2
Shared fixtures for all test modules.
"""
import pytest
import sys
import tempfile
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.models import (
    ScanConfig, ScanProfile, NmapOptions,
    PortInfo, HostResult, WebFinding, VulnFinding, ReconResult,
)


# ── Basic objects ─────────────────────────────────────────────────────────────

@pytest.fixture
def basic_port():
    return PortInfo(port=80, protocol="tcp", state="open", service="http",
                    product="Apache", version="2.4.52")

@pytest.fixture
def ssh_port():
    return PortInfo(port=22, protocol="tcp", state="open", service="ssh",
                    product="OpenSSH", version="8.9p1")

@pytest.fixture
def basic_host(basic_port, ssh_port):
    return HostResult(
        ip="192.168.1.100",
        hostnames=["example.com"],
        os_guess="Linux 5.x",
        os_accuracy="95",
        ports=[basic_port, ssh_port,
               PortInfo(port=443, protocol="tcp", state="closed")],
    )

@pytest.fixture
def basic_web_finding():
    return WebFinding(url="http://example.com", status_code=200,
                      title="Home Page", technologies=["Apache","PHP 8.1"],
                      server="Apache/2.4.52", content_length=4096)

@pytest.fixture
def basic_vuln():
    return VulnFinding(tool="nuclei", severity="high",
                       title="Apache Path Traversal",
                       target="http://example.com",
                       details="CVE-2021-41773 path traversal",
                       cve="CVE-2021-41773")

@pytest.fixture
def basic_result(basic_host, basic_web_finding, basic_vuln):
    return ReconResult(
        target="example.com",
        start_time="2024-01-15 12:00:00",
        end_time="2024-01-15 13:00:00",
        subdomains=["www.example.com", "mail.example.com", "dev.example.com"],
        hosts=[basic_host],
        web_findings=[basic_web_finding],
        nuclei_findings=[basic_vuln],
        phases_completed=["subdomains","ports","web","vuln"],
    )

@pytest.fixture
def basic_config():
    return ScanConfig(
        target="example.com",
        profile=ScanProfile.STANDARD,
        nmap_opts=NmapOptions(),
    )

@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)
