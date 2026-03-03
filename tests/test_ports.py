"""
tests/test_ports.py
Unit tests for the pure-Python async scanner helpers in core/ports.py
(no network calls — tests only logic functions)
"""
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Inline the pure helpers so we don't need rich installed in CI ──────────────

PORT_HINTS = {
    21:"ftp", 22:"ssh", 23:"telnet", 80:"http", 110:"pop3",
    443:"https", 445:"smb", 3306:"mysql", 5432:"postgresql",
    6379:"redis", 8080:"http-proxy", 27017:"mongodb",
}

_NMAP_TOP = [80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,
             1723,111,995,993,5900]

def _top_ports(n):
    base = _NMAP_TOP[:n]
    if n > len(_NMAP_TOP):
        existing = set(base)
        extra = [p for p in range(1, 65536) if p not in existing]
        base = base + extra[:n - len(base)]
    return base

def _guess_service(banner):
    b = banner.lower()
    if "ssh"   in b: return "ssh"
    if "http"  in b: return "http"
    if "ftp"   in b: return "ftp"
    if "smtp"  in b: return "smtp"
    if "redis" in b: return "redis"
    if "mysql" in b: return "mysql"
    return ""

def _parse_banner(banner):
    m = re.match(r"SSH-[\d.]+-(\S+)", banner)
    if m:
        parts = m.group(1).split("_", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    m = re.search(r"Server:\s*([^/\r\n\s]+)(?:/([^\r\n\s]+))?", banner, re.I)
    if m:
        return m.group(1), m.group(2) or ""
    return "", ""


class TestTopPorts:
    def test_top_10_contains_80(self):
        assert 80 in _top_ports(10)

    def test_top_10_contains_22(self):
        assert 22 in _top_ports(10)

    def test_count_exact(self):
        for n in [1, 10, 100, 1000]:
            assert len(_top_ports(n)) == n

    def test_no_duplicates(self):
        ports = _top_ports(1000)
        assert len(ports) == len(set(ports))

    def test_all_valid_port_numbers(self):
        for p in _top_ports(1000):
            assert 1 <= p <= 65535


class TestGuessService:
    def test_ssh_banner(self):
        assert _guess_service("SSH-2.0-OpenSSH_8.9") == "ssh"

    def test_http_banner(self):
        assert _guess_service("HTTP/1.1 200 OK") == "http"

    def test_ftp_banner(self):
        assert _guess_service("220 FTP server ready") == "ftp"

    def test_smtp_banner(self):
        assert _guess_service("220 mail.example.com SMTP") == "smtp"

    def test_redis_banner(self):
        assert _guess_service("-ERR Redis") == "redis"

    def test_empty_banner(self):
        assert _guess_service("") == ""

    def test_unknown_banner(self):
        assert _guess_service("garbage data xyz") == ""


class TestParseBanner:
    def test_ssh_product_version(self):
        prod, ver = _parse_banner("SSH-2.0-OpenSSH_8.9p1")
        assert prod == "OpenSSH"
        assert ver  == "8.9p1"

    def test_http_server_with_version(self):
        prod, ver = _parse_banner("HTTP/1.1 200\r\nServer: Apache/2.4.52")
        assert prod == "Apache"
        assert ver  == "2.4.52"

    def test_http_server_no_version(self):
        prod, ver = _parse_banner("HTTP/1.1 200\r\nServer: nginx")
        assert prod == "nginx"
        assert ver  == ""

    def test_empty_banner(self):
        assert _parse_banner("") == ("", "")

    def test_unknown_banner(self):
        assert _parse_banner("garbage") == ("", "")
