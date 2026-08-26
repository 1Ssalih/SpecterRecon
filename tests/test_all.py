"""
Automated unit and integration test suite for the Recon & Security Scanner.
"""

import os
import sys
import unittest
from core.models import (
    HostInfo, PortInfo, ServiceDetail, VulnerabilityInfo, DirFuzzFinding, CompleteScanReport
)
from core.storage import (
    save_hosts, load_hosts, save_ports, load_ports,
    save_services, load_services, save_vulns, load_vulns, save_findings, load_json
)
from modules.discovery import parse_targets
from modules.portscan import parse_port_specs
from modules.banner import extract_version_from_text
from modules.vuln_match import match_offline_cves, cvss_to_severity
from modules.dirfuzz import load_wordlist
from modules.report import build_complete_report, generate_html_report


class TestReconTool(unittest.TestCase):

    def setUp(self):
        os.makedirs("output/test", exist_ok=True)

    def test_target_parsing(self):
        # Single IP
        self.assertEqual(parse_targets("127.0.0.1"), ["127.0.0.1"])
        # IP Range
        range_ips = parse_targets("192.168.1.1-192.168.1.3")
        self.assertEqual(range_ips, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])
        # Short range
        range_short = parse_targets("10.0.0.1-3")
        self.assertEqual(range_short, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_port_parsing(self):
        top_20 = parse_port_specs("top-20")
        self.assertEqual(len(top_20), 20)
        self.assertIn(80, top_20)
        self.assertIn(443, top_20)

        custom = parse_port_specs("80,443,8000-8002")
        self.assertEqual(custom, [80, 443, 8000, 8001, 8002])

    def test_storage_and_models(self):
        test_host = HostInfo(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:FF", discovery_method="arp")
        save_hosts([test_host], "output/test/hosts.json")
        loaded = load_hosts("output/test/hosts.json")
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].ip, "192.168.1.50")
        self.assertEqual(loaded[0].mac, "AA:BB:CC:DD:EE:FF")

    def test_banner_version_extraction(self):
        s_name, s_desc, ver = extract_version_from_text("Apache/2.4.49 (Unix) OpenSSL/1.1.1l")
        self.assertEqual(s_name, "http")
        self.assertEqual(ver, "2.4.49")

        s_name2, _, ver2 = extract_version_from_text("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.assertEqual(s_name2, "ssh")
        self.assertEqual(ver2, "8.9p1")

        s_name3, _, ver3 = extract_version_from_text("220 (vsFTPd 2.3.4)")
        self.assertEqual(s_name3, "ftp")
        self.assertEqual(ver3, "2.3.4")

    def test_cve_matching(self):
        svc = ServiceDetail(
            ip="192.168.1.10",
            port=80,
            service_name="http",
            service_description="Apache httpd",
            service_version="2.4.49"
        )
        vulns = match_offline_cves(svc)
        self.assertTrue(any(v.cve_id == "CVE-2021-41773" for v in vulns))
        self.assertEqual(cvss_to_severity(9.8), "CRITICAL")
        self.assertEqual(cvss_to_severity(7.5), "HIGH")

    def test_wordlist_loading(self):
        words = load_wordlist("wordlists/common.txt")
        self.assertGreater(len(words), 10)
        self.assertIn("admin", words)
        self.assertIn("api", words)

    def test_report_generation(self):
        host = HostInfo(ip="127.0.0.1", discovery_method="tcp_ping")
        port = PortInfo(ip="127.0.0.1", port=80, service_name="http")
        svc = ServiceDetail(ip="127.0.0.1", port=80, service_name="http", service_version="2.4.49")
        vuln = VulnerabilityInfo(
            cve_id="CVE-2021-41773",
            cvss_score=7.5,
            severity="HIGH",
            description="Path traversal",
            affected_service="http (127.0.0.1:80)",
            affected_version="2.4.49"
        )
        finding = DirFuzzFinding(
            url="http://127.0.0.1:80/admin",
            path="/admin",
            status_code=200,
            content_length=512,
            is_sensitive=False
        )

        report = build_complete_report(
            target="127.0.0.1",
            hosts=[host],
            ports=[port],
            services=[svc],
            vulns=[vuln],
            findings=[finding],
            duration_seconds=1.23
        )

        out_path = generate_html_report(report, output_path="output/test/test_report.html")
        self.assertTrue(os.path.exists(out_path))
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("127.0.0.1", content)
            self.assertIn("CVE-2021-41773", content)
            self.assertIn("/admin", content)


if __name__ == "__main__":
    unittest.main()
