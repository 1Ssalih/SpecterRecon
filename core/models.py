"""
Data models for Recon & Scanning Tool using Pydantic.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class HostInfo(BaseModel):
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    discovery_method: str = "tcp_ping"  # arp, icmp, tcp_ping
    latency_ms: Optional[float] = None
    state: str = "alive"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class PortInfo(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered
    service_name: Optional[str] = "unknown"
    response_time_ms: Optional[float] = None


class ServiceDetail(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    service_description: Optional[str] = None
    service_version: Optional[str] = None
    banner_raw: Optional[str] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    http_technologies: List[str] = Field(default_factory=list)
    ssl_enabled: bool = False
    ssl_info: Optional[Dict[str, Any]] = None
    state: str = "open"


class VulnerabilityInfo(BaseModel):
    cve_id: str
    cvss_score: float = 0.0
    severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    description: str = ""
    affected_service: str = ""
    affected_version: Optional[str] = None
    published_date: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    mitigation: Optional[str] = None


class DirFuzzFinding(BaseModel):
    url: str
    path: str
    status_code: int
    content_length: int = 0
    redirect_location: Optional[str] = None
    title: Optional[str] = None
    response_time_ms: Optional[float] = None
    is_sensitive: bool = False


class HostScanReport(BaseModel):
    host: HostInfo
    ports: List[PortInfo] = Field(default_factory=list)
    services: List[ServiceDetail] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = Field(default_factory=list)
    dir_findings: List[DirFuzzFinding] = Field(default_factory=list)


class CompleteScanReport(BaseModel):
    scan_id: str
    target: str
    scan_date: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_seconds: float = 0.0
    hosts: List[HostScanReport] = Field(default_factory=list)
    total_hosts: int = 0
    total_open_ports: int = 0
    total_vulns: int = 0
    total_findings: int = 0
    severity_breakdown: Dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    )
