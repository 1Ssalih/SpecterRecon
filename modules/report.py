"""
Module 6: Report Generator
Combines all scan artifacts (hosts, ports, services, vulnerabilities, directory findings)
and renders an HTML security assessment report using Jinja2.
"""

import os
import uuid
from datetime import datetime
from typing import Optional, List, Dict
from jinja2 import Environment, FileSystemLoader
from core.models import (
    CompleteScanReport, HostScanReport, HostInfo, PortInfo, ServiceDetail,
    VulnerabilityInfo, DirFuzzFinding
)
from core.storage import (
    load_hosts, load_ports, load_services, load_vulns, load_json
)
from core.logger import log_info, log_success, log_warning, log_error, log_audit


def build_complete_report(
    target: str,
    hosts: Optional[List[HostInfo]] = None,
    ports: Optional[List[PortInfo]] = None,
    services: Optional[List[ServiceDetail]] = None,
    vulns: Optional[List[VulnerabilityInfo]] = None,
    findings: Optional[List[DirFuzzFinding]] = None,
    duration_seconds: float = 0.0
) -> CompleteScanReport:
    """Consolidate all component artifacts into a unified CompleteScanReport."""
    if hosts is None:
        hosts = load_hosts()
    if ports is None:
        ports = load_ports()
    if services is None:
        services = load_services()
    if vulns is None:
        vulns = load_vulns()
    if findings is None:
        raw_dirs = load_json("output/dirs.json")
        findings = [DirFuzzFinding(**item) for item in raw_dirs] if isinstance(raw_dirs, list) else []

    # Map ports, services, vulns, and findings to each host
    host_reports: List[HostScanReport] = []
    
    # If no explicit hosts were discovered but ports exist, create dummy host entry
    if not hosts and ports:
        unique_ips = set(p.ip for p in ports)
        hosts = [HostInfo(ip=ip, discovery_method="direct") for ip in unique_ips]

    for h in hosts:
        h_ports = [p for p in ports if p.ip == h.ip]
        h_services = [s for s in services if s.ip == h.ip]
        
        # Match vulns to this host
        h_vulns = [v for v in vulns if h.ip in v.affected_service]
        # Match findings to this host
        h_findings = [f for f in findings if h.ip in f.url]

        host_reports.append(
            HostScanReport(
                host=h,
                ports=h_ports,
                services=h_services,
                vulnerabilities=h_vulns,
                dir_findings=h_findings
            )
        )

    # Count breakdown
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        sev = v.severity.upper() if v.severity else "UNKNOWN"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return CompleteScanReport(
        scan_id=str(uuid.uuid4())[:8],
        target=target,
        scan_date=datetime.utcnow().isoformat(),
        duration_seconds=round(duration_seconds, 2),
        hosts=host_reports,
        total_hosts=len(host_reports),
        total_open_ports=len(ports),
        total_vulns=len(vulns),
        total_findings=len(findings),
        severity_breakdown=severity_counts
    )


def generate_html_report(
    report: CompleteScanReport,
    template_dir: str = "templates",
    template_name: str = "report.html.j2",
    output_path: str = "output/report.html"
) -> str:
    """Render Jinja2 template and write report to output path."""
    log_info(f"HTML Raporu üretiliyor: '{output_path}'...")
    log_audit("REPORT_GENERATION_START", report.target, f"output={output_path}")

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_name)
    
    html_content = template.render(report=report)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    log_success(f"HTML Raporu başarıyla oluşturuldu: [bold underline]{output_path}[/bold underline]")
    log_audit("REPORT_GENERATION_COMPLETE", report.target, f"output={output_path}")

    return output_path
