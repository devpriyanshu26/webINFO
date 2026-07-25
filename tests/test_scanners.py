import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.scanners.dns_scanner import DNSScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.tech_scanner import TechScanner
from app.scanners.port_scanner import PortScanner
from app.scanners.email_scanner import EmailSecurityScanner
from app.scanners.performance import PerformanceScanner
from app.utils.helpers import calculate_security_score, get_grade


class TestHelpers:
    def test_security_score_perfect(self):
        assert calculate_security_score([]) == 100

    def test_security_score_critical(self):
        score = calculate_security_score([{"severity": "Critical"}, {"severity": "High"}])
        assert score == 60

    def test_security_score_mixed(self):
        score = calculate_security_score([
            {"severity": "Critical"}, {"severity": "High"},
            {"severity": "Medium"}, {"severity": "Low"},
        ])
        assert score == 49

    def test_get_grade(self):
        assert get_grade(95) == "A+"
        assert get_grade(85) == "A"
        assert get_grade(75) == "B"
        assert get_grade(65) == "C"
        assert get_grade(50) == "D"
        assert get_grade(30) == "F"


class TestDNSScanner:
    def test_init(self):
        scanner = DNSScanner("example.com")
        assert scanner.hostname == "example.com"


class TestSSLScanner:
    def test_init(self):
        scanner = SSLScanner("example.com")
        assert scanner.hostname == "example.com"


class TestPortScanner:
    def test_init(self):
        scanner = PortScanner("127.0.0.1")
        assert scanner.hostname == "127.0.0.1"


class TestTechScanner:
    def test_init(self):
        scanner = TechScanner("https://example.com")
        assert scanner.url == "https://example.com"


class TestEmailSecurityScanner:
    def test_init(self):
        scanner = EmailSecurityScanner("example.com")
        assert scanner.hostname == "example.com"


class TestPerformanceScanner:
    def test_init(self):
        scanner = PerformanceScanner("https://example.com")
        assert scanner.url == "https://example.com"
