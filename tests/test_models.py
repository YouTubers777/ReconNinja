"""
tests/test_models.py
Unit tests for utils/models.py
Covers: ScanProfile, NmapOptions, PortInfo, ScanConfig, VulnFinding, constants
"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.models import (
    ScanProfile, NmapOptions, PortInfo, ScanConfig,
    VulnFinding, SEVERITY_PORTS, WEB_PORTS, VALID_TIMINGS,
)


class TestScanProfile:
    def test_all_profiles_exist(self):
        values = [p.value for p in ScanProfile]
        for name in ["fast","standard","thorough","stealth",
                     "custom","full_suite","web_only","port_only"]:
            assert name in values

    def test_from_string(self):
        assert ScanProfile("fast")       == ScanProfile.FAST
        assert ScanProfile("full_suite") == ScanProfile.FULL_SUITE

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            ScanProfile("hacker_mode")


class TestNmapOptions:
    def test_defaults(self):
        o = NmapOptions()
        assert o.all_ports         is False
        assert o.top_ports         == 1000
        assert o.scripts           is True
        assert o.version_detection is True
        assert o.timing            == "T4"
        assert o.extra_flags       == []

    def test_invalid_timing_raises(self):
        with pytest.raises(ValueError):
            NmapOptions(timing="T9")

    def test_all_valid_timings(self):
        for t in VALID_TIMINGS:
            assert NmapOptions(timing=t).timing == t

    def test_negative_ports_raises(self):
        with pytest.raises(ValueError):
            NmapOptions(top_ports=-1)

    def test_normal_uses_sT(self):
        assert "-sT" in NmapOptions().as_nmap_args()

    def test_stealth_uses_sS_not_sT(self):
        args = NmapOptions(stealth=True, timing="T2").as_nmap_args()
        assert "-sS" in args
        assert "-sT" not in args

    def test_aggressive_uses_A_not_sT(self):
        args = NmapOptions(aggressive=True).as_nmap_args()
        assert "-A"  in args
        assert "-sT" not in args

    def test_never_both_sT_and_sS(self):
        for o in [NmapOptions(),
                  NmapOptions(stealth=True, timing="T2"),
                  NmapOptions(aggressive=True)]:
            a = o.as_nmap_args()
            assert not ("-sT" in a and "-sS" in a)

    def test_scripts_on_off(self):
        assert "-sC" in     NmapOptions(scripts=True).as_nmap_args()
        assert "-sC" not in NmapOptions(scripts=False).as_nmap_args()

    def test_version_on_off(self):
        assert "-sV" in     NmapOptions(version_detection=True).as_nmap_args()
        assert "-sV" not in NmapOptions(version_detection=False).as_nmap_args()

    def test_all_ports_flag(self):
        args = NmapOptions(all_ports=True).as_nmap_args()
        assert "-p-"         in args
        assert "--top-ports" not in args

    def test_top_ports_flag(self):
        args = NmapOptions(top_ports=500).as_nmap_args()
        assert "--top-ports" in args
        assert "500"         in args

    def test_timing_flag(self):
        for t in ["T1","T2","T3","T4","T5"]:
            assert f"-{t}" in NmapOptions(timing=t).as_nmap_args()

    def test_extra_flags_passed(self):
        args = NmapOptions(extra_flags=["--open","-v"]).as_nmap_args()
        assert "--open" in args
        assert "-v"     in args


class TestPortInfo:
    def test_construction(self):
        p = PortInfo(port=80, protocol="tcp", state="open", service="http")
        assert p.port == 80
        assert p.state == "open"

    def test_critical_ports(self):
        for port in [21, 22, 23, 25, 139, 445]:
            sev = PortInfo(port=port, protocol="tcp", state="open").severity
            assert sev == "critical", f"Port {port} got {sev}"

    def test_high_ports(self):
        for port in [80, 443, 3306, 3389]:
            sev = PortInfo(port=port, protocol="tcp", state="open").severity
            assert sev == "high", f"Port {port} got {sev}"

    def test_unknown_is_info(self):
        assert PortInfo(port=54321, protocol="tcp", state="open").severity == "info"

    def test_is_web_port_true(self):
        for port in WEB_PORTS:
            assert PortInfo(port=port, protocol="tcp", state="open").is_web_port is True

    def test_is_web_port_false(self):
        assert PortInfo(port=22, protocol="tcp", state="open").is_web_port is False

    def test_empty_defaults(self):
        p = PortInfo(port=443, protocol="tcp", state="open")
        assert p.product == "" and p.version == "" and p.scripts == {}


class TestScanConfig:
    def test_target_stored(self):
        assert ScanConfig(target="192.168.1.1").target == "192.168.1.1"

    def test_default_profile(self):
        assert ScanConfig(target="x").profile == ScanProfile.STANDARD

    def test_heavy_features_off_by_default(self):
        cfg = ScanConfig(target="x")
        for attr in ("run_subdomains","run_masscan","run_aquatone",
                     "run_nikto","run_ai_analysis"):
            assert getattr(cfg, attr) is False, f"{attr} should be False"

    def test_standard_features_on_by_default(self):
        cfg = ScanConfig(target="x")
        for attr in ("run_rustscan","run_httpx","run_nuclei",
                     "run_whatweb","run_feroxbuster"):
            assert getattr(cfg, attr) is True, f"{attr} should be True"

    def test_async_defaults(self):
        cfg = ScanConfig(target="x")
        assert cfg.async_concurrency == 1000
        assert cfg.async_timeout     == 1.5

    def test_nmap_opts_type(self):
        assert isinstance(ScanConfig(target="x").nmap_opts, NmapOptions)

    def test_to_dict(self):
        d = ScanConfig(target="10.0.0.1").to_dict()
        assert d["target"] == "10.0.0.1"

    def test_thread_default(self):
        assert ScanConfig(target="x").threads == 20

    def test_masscan_rate_default(self):
        assert ScanConfig(target="x").masscan_rate == 5000


class TestVulnFinding:
    def test_construction(self):
        v = VulnFinding(tool="nuclei", severity="high", title="RCE",
                        target="http://x.com", cve="CVE-2024-1")
        assert v.tool == "nuclei" and v.severity == "high"

    def test_all_severities(self):
        for sev in ("critical","high","medium","low","info"):
            assert VulnFinding(tool="t", severity=sev,
                               title="x", target="x").severity == sev

    def test_cve_default_empty(self):
        assert VulnFinding(tool="t", severity="low",
                           title="x", target="x").cve == ""

    def test_details_default_empty(self):
        assert VulnFinding(tool="t", severity="low",
                           title="x", target="x").details == ""


class TestConstants:
    def test_severity_keys(self):
        for k in ("critical","high","medium"):
            assert k in SEVERITY_PORTS

    def test_critical_ports(self):
        assert 22  in SEVERITY_PORTS["critical"]
        assert 445 in SEVERITY_PORTS["critical"]

    def test_high_ports(self):
        assert 80  in SEVERITY_PORTS["high"]
        assert 443 in SEVERITY_PORTS["high"]

    def test_web_ports(self):
        for p in [80, 443, 8080, 8443]:
            assert p in WEB_PORTS

    def test_valid_timings(self):
        assert VALID_TIMINGS == {"T1","T2","T3","T4","T5"}
