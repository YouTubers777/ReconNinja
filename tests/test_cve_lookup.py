"""
tests/test_cve_lookup.py — ReconNinja v3.2
Tests for core/cve_lookup.py — pure logic only, no real HTTP calls.
"""
import pytest
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cve_lookup import (
    CVEResult, _build_search_term, lookup_cves_for_ports,
    lookup_cves_for_host_result, _nvd_search, _CACHE,
)
from utils.models import PortInfo, HostResult, VulnFinding


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_port(port=80, service="http", product="Apache", version="2.4.52", state="open"):
    return PortInfo(port=port, protocol="tcp", state=state,
                    service=service, product=product, version=version)

def make_cve(cve_id="CVE-2021-41773", score=7.5, severity="HIGH"):
    return CVEResult(cve_id=cve_id, description="Path traversal",
                     severity=severity, cvss_score=score,
                     published="2021-10-05", references=["https://nvd.nist.gov"])

def make_nvd_response(cves: list) -> bytes:
    """Build a fake NVD API JSON response."""
    vulns = []
    for c in cves:
        vulns.append({
            "cve": {
                "id": c["id"],
                "descriptions": [{"lang":"en","value": c.get("desc","Test CVE")}],
                "published": c.get("published","2024-01-01T00:00:00.000"),
                "references": [{"url": u} for u in c.get("refs",[])],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": c.get("score", 5.0),
                            "baseSeverity": c.get("severity","MEDIUM"),
                        }
                    }]
                }
            }
        })
    return json.dumps({"vulnerabilities": vulns, "totalResults": len(vulns)}).encode()


# ═══════════════════════════════════════════════
# CVEResult dataclass
# ═══════════════════════════════════════════════
class TestCVEResult:
    def test_construction(self):
        c = make_cve()
        assert c.cve_id     == "CVE-2021-41773"
        assert c.cvss_score == 7.5
        assert c.severity   == "HIGH"

    def test_references_default_empty(self):
        c = CVEResult(cve_id="CVE-X", description="d", severity="LOW",
                      cvss_score=2.0, published="2024-01-01")
        assert c.references == []

    def test_to_vuln_finding(self):
        c = make_cve()
        vf = c.to_vuln_finding("192.168.1.1:80")
        assert isinstance(vf, VulnFinding)
        assert vf.cve      == "CVE-2021-41773"
        assert vf.target   == "192.168.1.1:80"
        assert vf.tool     == "nvd"
        assert "7.5"       in vf.title

    def test_to_vuln_finding_severity_lowercased(self):
        c = make_cve(severity="HIGH")
        vf = c.to_vuln_finding("x:80")
        assert vf.severity == "high"

    def test_to_vuln_finding_critical(self):
        c = make_cve(severity="CRITICAL", score=9.8)
        vf = c.to_vuln_finding("x:443")
        assert vf.severity == "critical"

    def test_to_vuln_finding_description_truncated(self):
        long_desc = "A" * 500
        c = CVEResult(cve_id="CVE-X", description=long_desc, severity="LOW",
                      cvss_score=2.0, published="2024-01-01")
        vf = c.to_vuln_finding("x:80")
        assert len(vf.details) <= 300

    def test_to_vuln_finding_custom_tool(self):
        c = make_cve()
        vf = c.to_vuln_finding("x:80", tool="nvd_custom")
        assert vf.tool == "nvd_custom"


# ═══════════════════════════════════════════════
# _build_search_term
# ═══════════════════════════════════════════════
class TestBuildSearchTerm:
    def test_product_and_version(self):
        p = make_port(product="Apache", version="2.4.52")
        assert _build_search_term(p) == "Apache 2.4.52"

    def test_product_only(self):
        p = make_port(product="OpenSSH", version="")
        assert _build_search_term(p) == "OpenSSH"

    def test_version_only_uses_service(self):
        p = make_port(product="", service="http", version="2.4.52")
        assert _build_search_term(p) == "http 2.4.52"

    def test_service_only(self):
        p = make_port(product="", service="ssh", version="")
        assert _build_search_term(p) == "ssh"

    def test_no_info_returns_none(self):
        p = make_port(product="", service="", version="")
        assert _build_search_term(p) is None

    def test_product_takes_priority_over_service(self):
        p = make_port(product="nginx", service="http", version="1.18.0")
        result = _build_search_term(p)
        assert "nginx" in result
        assert "1.18.0" in result

    def test_returns_string_or_none(self):
        p = make_port(product="Apache", version="2.4")
        result = _build_search_term(p)
        assert result is None or isinstance(result, str)

    def test_spaces_trimmed(self):
        p = make_port(product="Apache", version="2.4.52")
        result = _build_search_term(p)
        assert not result.startswith(" ")
        assert not result.endswith(" ")


# ═══════════════════════════════════════════════
# _nvd_search (mocked HTTP)
# ═══════════════════════════════════════════════
class TestNvdSearch:
    def setup_method(self):
        _CACHE.clear()

    def _mock_urlopen(self, response_data: bytes):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_resp.read      = MagicMock(return_value=response_data)
        return mock_resp

    def test_returns_list(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("Apache 2.4.49")
        assert isinstance(results, list)

    def test_parses_cve_id(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("Apache 2.4.49")
        assert results[0].cve_id == "CVE-2021-41773"

    def test_parses_score(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("Apache 2.4.49")
        assert results[0].cvss_score == 7.5

    def test_parses_severity(self):
        data = make_nvd_response([{"id":"CVE-X","score":9.8,"severity":"CRITICAL"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("test 1.0")
        assert results[0].severity == "CRITICAL"

    def test_parses_description(self):
        data = make_nvd_response([{"id":"CVE-X","score":5.0,"severity":"MEDIUM","desc":"Path traversal vuln"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("test")
        assert "Path traversal" in results[0].description

    def test_sorted_by_score_descending(self):
        data = make_nvd_response([
            {"id":"CVE-LOW","score":2.0,"severity":"LOW"},
            {"id":"CVE-CRIT","score":9.8,"severity":"CRITICAL"},
            {"id":"CVE-MED","score":5.5,"severity":"MEDIUM"},
        ])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("test sorting")
        scores = [r.cvss_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_empty_response_returns_empty_list(self):
        data = json.dumps({"vulnerabilities":[],"totalResults":0}).encode()
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("nonexistent_xyz_123")
        assert results == []

    def test_network_error_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("Network error")):
            results = _nvd_search("Apache 2.4.52")
        assert results == []

    def test_caching_second_call_no_http(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock) as m:
            _nvd_search("Apache cached")
            _nvd_search("Apache cached")
            assert m.call_count == 1  # second call uses cache

    def test_multiple_cves_returned(self):
        data = make_nvd_response([
            {"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"},
            {"id":"CVE-2021-42013","score":9.8,"severity":"CRITICAL"},
        ])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("Apache 2.4.49")
        assert len(results) == 2

    def test_publishes_date_parsed(self):
        data = make_nvd_response([{"id":"CVE-X","score":5.0,"severity":"MEDIUM",
                                    "published":"2024-03-15T12:00:00.000"}])
        mock = self._mock_urlopen(data)
        with patch("urllib.request.urlopen", return_value=mock):
            results = _nvd_search("test date")
        assert results[0].published == "2024-03-15"


# ═══════════════════════════════════════════════
# lookup_cves_for_ports (mocked)
# ═══════════════════════════════════════════════
class TestLookupCvesForPorts:
    def setup_method(self):
        _CACHE.clear()

    def test_returns_list(self):
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            result = lookup_cves_for_ports([make_port()], "example.com")
        assert isinstance(result, list)

    def test_no_results_when_no_product(self):
        p = make_port(product="", service="", version="")
        with patch("core.cve_lookup._nvd_search", return_value=[]) as m:
            result = lookup_cves_for_ports([p], "example.com")
        m.assert_not_called()
        assert result == []

    def test_returns_vuln_findings(self):
        cve = make_cve()
        with patch("core.cve_lookup._nvd_search", return_value=[cve]):
            result = lookup_cves_for_ports([make_port()], "example.com")
        assert all(isinstance(r, VulnFinding) for r in result)

    def test_target_includes_port(self):
        cve = make_cve()
        with patch("core.cve_lookup._nvd_search", return_value=[cve]):
            result = lookup_cves_for_ports([make_port(port=8080)], "10.0.0.1")
        assert "8080" in result[0].target

    def test_deduplication_same_product(self):
        p1 = make_port(port=80,  product="Apache", version="2.4.52")
        p2 = make_port(port=443, product="Apache", version="2.4.52")
        cve = make_cve()
        with patch("core.cve_lookup._nvd_search", return_value=[cve]) as m:
            lookup_cves_for_ports([p1, p2], "example.com", delay=0)
        assert m.call_count == 1  # same product, only queried once

    def test_different_products_queried_separately(self):
        p1 = make_port(port=80,   product="Apache", version="2.4")
        p2 = make_port(port=3306, product="MySQL",  version="8.0")
        with patch("core.cve_lookup._nvd_search", return_value=[]) as m:
            lookup_cves_for_ports([p1, p2], "example.com", delay=0)
        assert m.call_count == 2

    def test_sorted_critical_first(self):
        crit = make_cve("CVE-CRIT", score=9.8, severity="CRITICAL")
        low  = make_cve("CVE-LOW",  score=2.0, severity="LOW")
        with patch("core.cve_lookup._nvd_search", side_effect=[[crit], [low]]):
            p1 = make_port(port=80,   product="Apache", version="2.4")
            p2 = make_port(port=8080, product="nginx",  version="1.18")
            result = lookup_cves_for_ports([p1, p2], "x.com", delay=0)
        severities = [r.severity for r in result]
        assert severities.index("critical") < severities.index("low")

    def test_empty_ports_list(self):
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            result = lookup_cves_for_ports([], "example.com")
        assert result == []


# ═══════════════════════════════════════════════
# lookup_cves_for_host_result (mocked)
# ═══════════════════════════════════════════════
class TestLookupCvesForHostResult:
    def setup_method(self):
        _CACHE.clear()

    def test_returns_list(self):
        host = HostResult(ip="10.0.0.1", ports=[make_port()])
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            result = lookup_cves_for_host_result(host, "10.0.0.1")
        assert isinstance(result, list)

    def test_only_open_ports_queried(self):
        open_p   = make_port(port=80,  product="Apache", version="2.4", state="open")
        closed_p = make_port(port=443, product="nginx",  version="1.18",state="closed")
        host = HostResult(ip="10.0.0.1", ports=[open_p, closed_p])
        with patch("core.cve_lookup._nvd_search", return_value=[]) as m:
            lookup_cves_for_ports(host.open_ports, "10.0.0.1", delay=0)
        # closed port should NOT be queried
        for call in m.call_args_list:
            assert "nginx" not in str(call)

    def test_empty_host_returns_empty(self):
        host = HostResult(ip="10.0.0.1")
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            result = lookup_cves_for_host_result(host, "10.0.0.1")
        assert result == []
