"""
tests/test_resume.py — ReconNinja v3.2
Tests for core/resume.py — save/load/find state.
"""
import pytest
import sys
import json
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.resume import (
    save_state, load_state, find_latest_state,
    _sanitize, _result_to_dict, _dict_to_result, _dict_to_config,
    STATE_FILE,
)
from utils.models import (
    ScanConfig, ScanProfile, NmapOptions,
    PortInfo, HostResult, WebFinding, VulnFinding, ReconResult,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_result(target="example.com"):
    return ReconResult(
        target=target,
        start_time="2024-01-15 12:00:00",
        end_time="2024-01-15 13:00:00",
        subdomains=["www.example.com","mail.example.com"],
        hosts=[HostResult(ip="192.168.1.1", ports=[
            PortInfo(port=22, protocol="tcp", state="open",
                     service="ssh", product="OpenSSH", version="8.9p1"),
            PortInfo(port=80, protocol="tcp", state="open",
                     service="http", product="Apache", version="2.4.52"),
        ])],
        web_findings=[WebFinding(url="http://example.com", status_code=200,
                                  title="Home", technologies=["Apache","PHP"])],
        nuclei_findings=[
            VulnFinding(tool="nuclei", severity="high", title="RCE",
                        target="http://example.com", cve="CVE-2021-41773"),
        ],
        errors=["nmap timeout on port 9999"],
        phases_completed=["subdomains","ports","web","vuln"],
    )

def make_config(target="example.com"):
    return ScanConfig(
        target=target,
        profile=ScanProfile.FULL_SUITE,
        nmap_opts=NmapOptions(timing="T4", scripts=True, version_detection=True),
        run_subdomains=True, run_rustscan=True, run_nuclei=True,
        threads=20, masscan_rate=5000,
    )


# ═══════════════════════════════════════════════
# _sanitize
# ═══════════════════════════════════════════════
class TestSanitize:
    def test_normal_string_unchanged(self):  assert _sanitize("example.com") == "example.com"
    def test_spaces_replaced(self):          assert " " not in _sanitize("hello world")
    def test_slashes_replaced(self):         assert "/" not in _sanitize("path/to/file")
    def test_backslash_replaced(self):       assert "\\" not in _sanitize("path\\file")
    def test_colon_replaced(self):           assert ":" not in _sanitize("http://x.com")
    def test_angle_brackets_replaced(self):  assert "<" not in _sanitize("<tag>")
    def test_pipe_replaced(self):            assert "|" not in _sanitize("a|b")
    def test_question_mark_replaced(self):   assert "?" not in _sanitize("a?b=c")
    def test_asterisk_replaced(self):        assert "*" not in _sanitize("a*b")
    def test_returns_string(self):           assert isinstance(_sanitize("test"), str)
    def test_ip_unchanged(self):
        result = _sanitize("192.168.1.1")
        assert result == "192.168.1.1"
    def test_url_cleaned(self):
        result = _sanitize("https://example.com/path")
        assert "/" not in result and ":" not in result


# ═══════════════════════════════════════════════
# _result_to_dict / _dict_to_result
# ═══════════════════════════════════════════════
class TestResultSerialization:
    def test_result_to_dict_returns_dict(self):
        assert isinstance(_result_to_dict(make_result()), dict)

    def test_round_trip_target(self):
        r = make_result()
        d = _result_to_dict(r)
        r2 = _dict_to_result(d)
        assert r2.target == "example.com"

    def test_round_trip_start_time(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert r2.start_time == r.start_time

    def test_round_trip_end_time(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert r2.end_time == r.end_time

    def test_round_trip_subdomains(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert r2.subdomains == r.subdomains

    def test_round_trip_hosts_count(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert len(r2.hosts) == len(r.hosts)

    def test_round_trip_host_ip(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert r2.hosts[0].ip == "192.168.1.1"

    def test_round_trip_ports_count(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert len(r2.hosts[0].ports) == len(r.hosts[0].ports)

    def test_round_trip_port_number(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        ports = [p.port for p in r2.hosts[0].ports]
        assert 22 in ports and 80 in ports

    def test_round_trip_port_product(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        port = next(p for p in r2.hosts[0].ports if p.port == 80)
        assert port.product == "Apache"

    def test_round_trip_web_findings(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert len(r2.web_findings) == 1
        assert r2.web_findings[0].url == "http://example.com"

    def test_round_trip_nuclei_findings(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert len(r2.nuclei_findings) == 1
        assert r2.nuclei_findings[0].cve == "CVE-2021-41773"

    def test_round_trip_phases_completed(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert r2.phases_completed == r.phases_completed

    def test_round_trip_errors(self):
        r = make_result()
        r2 = _dict_to_result(_result_to_dict(r))
        assert r2.errors == r.errors

    def test_dict_to_result_missing_optional_fields(self):
        d = {"target":"x.com", "start_time":"t"}
        r = _dict_to_result(d)
        assert r.target == "x.com"
        assert r.hosts  == []
        assert r.subdomains == []


# ═══════════════════════════════════════════════
# _dict_to_config
# ═══════════════════════════════════════════════
class TestConfigDeserialization:
    def test_round_trip_target(self):
        cfg = make_config()
        d = cfg.to_dict()
        cfg2 = _dict_to_config(d)
        assert cfg2.target == "example.com"

    def test_round_trip_profile(self):
        cfg = make_config()
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.profile == ScanProfile.FULL_SUITE

    def test_round_trip_run_subdomains(self):
        cfg = make_config()
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.run_subdomains is True

    def test_round_trip_run_rustscan(self):
        cfg = make_config()
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.run_rustscan is True

    def test_round_trip_threads(self):
        cfg = make_config()
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.threads == 20

    def test_round_trip_nmap_timing(self):
        cfg = make_config()
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.nmap_opts.timing == "T4"

    def test_round_trip_nmap_scripts(self):
        cfg = make_config()
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.nmap_opts.scripts is True

    def test_all_profiles_deserialize(self):
        for p in ScanProfile:
            cfg = ScanConfig(target="x", profile=p)
            cfg2 = _dict_to_config(cfg.to_dict())
            assert cfg2.profile == p


# ═══════════════════════════════════════════════
# save_state / load_state
# ═══════════════════════════════════════════════
class TestSaveLoadState:
    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            assert (out / STATE_FILE).exists()

    def test_save_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            data = json.loads((out / STATE_FILE).read_text())
            assert isinstance(data, dict)

    def test_save_contains_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            data = json.loads((out / STATE_FILE).read_text())
            assert "version" in data

    def test_save_contains_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            data = json.loads((out / STATE_FILE).read_text())
            assert "config" in data

    def test_save_contains_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            data = json.loads((out / STATE_FILE).read_text())
            assert "result" in data

    def test_load_returns_tuple(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            loaded = load_state(out / STATE_FILE)
            assert isinstance(loaded, tuple) and len(loaded) == 3

    def test_load_recovers_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result("mysite.com"), make_config("mysite.com"), out)
            result, cfg, folder = load_state(out / STATE_FILE)
            assert result.target == "mysite.com"
            assert cfg.target    == "mysite.com"

    def test_load_recovers_subdomains(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert "www.example.com" in result.subdomains

    def test_load_recovers_phases_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert "subdomains" in result.phases_completed
            assert "ports"      in result.phases_completed

    def test_load_recovers_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert len(result.hosts) == 1
            assert result.hosts[0].ip == "192.168.1.1"

    def test_load_recovers_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            ports = [p.port for p in result.hosts[0].ports]
            assert 22 in ports and 80 in ports

    def test_load_recovers_vuln_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert len(result.nuclei_findings) == 1
            assert result.nuclei_findings[0].cve == "CVE-2021-41773"

    def test_load_recovers_out_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            _, _, folder = load_state(out / STATE_FILE)
            assert isinstance(folder, Path)

    def test_load_missing_file_returns_none(self):
        assert load_state(Path("/nonexistent/path/state.json")) is None

    def test_load_corrupt_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / STATE_FILE
            bad.write_text("NOT VALID JSON {{{{")
            assert load_state(bad) is None

    def test_overwrite_state_preserves_new_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            out  = Path(tmp)
            r1   = make_result()
            save_state(r1, make_config(), out)
            r2   = make_result()
            r2.phases_completed.append("ai_analysis")
            save_state(r2, make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert "ai_analysis" in result.phases_completed


# ═══════════════════════════════════════════════
# find_latest_state
# ═══════════════════════════════════════════════
class TestFindLatestState:
    def test_returns_none_when_no_reports_dir(self):
        assert find_latest_state("example.com", Path("/nonexistent/path")) is None

    def test_returns_none_when_no_matching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            (reports / "other_target").mkdir()
            assert find_latest_state("example.com", reports) is None

    def test_returns_path_when_state_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports   = Path(tmp)
            target_dir = reports / "example.com" / "20240115_120000"
            target_dir.mkdir(parents=True)
            state_file = target_dir / STATE_FILE
            save_state(make_result(), make_config(), target_dir)
            result = find_latest_state("example.com", reports)
            assert result is not None
            assert isinstance(result, Path)

    def test_returns_most_recent_when_multiple(self):
        with tempfile.TemporaryDirectory() as tmp:
            import time
            reports = Path(tmp)
            for ts in ["20240115_120000","20240116_120000"]:
                d = reports / "example.com" / ts
                d.mkdir(parents=True)
                save_state(make_result(), make_config(), d)
                time.sleep(0.01)   # ensure different mtime
            result = find_latest_state("example.com", reports)
            assert result is not None

    def test_returns_none_when_target_dir_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports   = Path(tmp)
            target_dir = reports / "example.com" / "20240115_120000"
            target_dir.mkdir(parents=True)
            # No state.json written
            assert find_latest_state("example.com", reports) is None
