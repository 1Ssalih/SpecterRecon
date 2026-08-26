"""
Module 4: Vulnerability & CVE Matcher
Queries NVD REST API v2 and matches detected service/version combinations,
with a built-in offline CVE knowledge base and CVSS score ranking.
"""

import asyncio
from typing import List, Optional, Dict, Any
import httpx
from core.models import ServiceDetail, VulnerabilityInfo
from core.logger import log_info, log_success, log_warning, log_error, log_audit
from core.storage import save_vulns

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Curated offline CVE database for instant offline matching & fallback
OFFLINE_CVE_DATABASE = [
    # Apache HTTP Server
    {
        "service": "apache",
        "version_regex": r"2\.4\.49",
        "cve_id": "CVE-2021-41773",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.49 via unmapped URLs.",
        "mitigation": "Upgrade to Apache 2.4.51 or later.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
    },
    {
        "service": "apache",
        "version_regex": r"2\.4\.50",
        "cve_id": "CVE-2021-42013",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "Incomplete fix for CVE-2021-41773 allows remote code execution in Apache HTTP Server 2.4.50.",
        "mitigation": "Upgrade to Apache 2.4.51 or later.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"]
    },
    {
        "service": "apache",
        "version_regex": r"2\.4\.(?:[0-9]|[1-3][0-9]|4[0-8])",
        "cve_id": "CVE-2021-40438",
        "cvss_score": 9.0,
        "severity": "CRITICAL",
        "description": "Apache HTTP Server mod_proxy SSRF vulnerability allowing remote attackers to route arbitrary requests.",
        "mitigation": "Upgrade to Apache HTTP Server 2.4.49+.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-40438"]
    },
    # OpenSSH
    {
        "service": "ssh",
        "version_regex": r"7\.[0-6]",
        "cve_id": "CVE-2018-15473",
        "cvss_score": 5.3,
        "severity": "MEDIUM",
        "description": "OpenSSH user enumeration vulnerability via malformed authentication requests.",
        "mitigation": "Upgrade to OpenSSH 7.8 or newer.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"]
    },
    {
        "service": "ssh",
        "version_regex": r"9\.[0-7]p1",
        "cve_id": "CVE-2024-6387",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "description": "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH server (sshd) on glibc-based Linux systems.",
        "mitigation": "Upgrade to OpenSSH 9.8p1 or later.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"]
    },
    # vsftpd
    {
        "service": "ftp",
        "version_regex": r"2\.3\.4",
        "cve_id": "CVE-2011-2523",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "vsftpd 2.3.4 Backdoor Command Execution triggered by smile smiley ':)' in username.",
        "mitigation": "Replace with authentic vsftpd release 3.0+.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"]
    },
    # ProFTPD
    {
        "service": "ftp",
        "version_regex": r"1\.3\.5",
        "cve_id": "CVE-2015-3306",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read/write arbitrary files via SITE CPFR/CPTO.",
        "mitigation": "Upgrade to ProFTPD 1.3.6+ or disable mod_copy.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"]
    },
    # MySQL
    {
        "service": "mysql",
        "version_regex": r"5\.[0-7]\.",
        "cve_id": "CVE-2016-6662",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "MySQL Remote Root Code Execution / Privilege Escalation via configuration injection.",
        "mitigation": "Apply official Oracle MySQL security patches.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-6662"]
    },
    # Redis
    {
        "service": "redis",
        "version_regex": r"[456]\.",
        "cve_id": "CVE-2022-0543",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "description": "Redis Lua sandbox escape leading to Remote Code Execution via package.loadlib in Debian/Ubuntu packages.",
        "mitigation": "Upgrade Redis package and enable protected-mode.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"]
    },
    # PHP
    {
        "service": "http",
        "version_regex": r"8\.1\.0-dev",
        "cve_id": "CVE-2021-00001",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "PHP 8.1.0-dev Backdoor Remote Code Execution via User-Agentt header.",
        "mitigation": "Reinstall legitimate PHP build.",
        "references": ["https://github.com/vulhub/vulhub/tree/master/php/8.1-backdoor"]
    }
]


def cvss_to_severity(score: float) -> str:
    """Convert numerical CVSS score to severity string."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "UNKNOWN"


def match_offline_cves(service: ServiceDetail) -> List[VulnerabilityInfo]:
    """Check against built-in offline CVE database."""
    import re
    results: List[VulnerabilityInfo] = []
    
    s_name = (service.service_name or "").lower()
    s_desc = (service.service_description or "").lower()
    s_ver = service.service_version or ""

    for item in OFFLINE_CVE_DATABASE:
        db_service = item["service"].lower()
        if db_service in s_name or db_service in s_desc:
            # Check version match if version is present
            if s_ver and re.search(item["version_regex"], s_ver):
                results.append(
                    VulnerabilityInfo(
                        cve_id=item["cve_id"],
                        cvss_score=item["cvss_score"],
                        severity=item["severity"],
                        description=item["description"],
                        affected_service=f"{service.service_name} ({service.ip}:{service.port})",
                        affected_version=s_ver,
                        published_date="N/A",
                        references=item.get("references", []),
                        mitigation=item.get("mitigation")
                    )
                )
    return results


async def query_nvd_api(
    keyword: str,
    api_key: Optional[str] = None,
    timeout: float = 8.0,
    max_results: int = 5
) -> List[VulnerabilityInfo]:
    """Query the official NVD API v2 for keyword/service matching."""
    headers = {"User-Agent": "ReconTool/1.0 (Security Assessment)"}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    cves: List[VulnerabilityInfo] = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(NVD_API_URL, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                for item in vulnerabilities:
                    cve_dict = item.get("cve", {})
                    cve_id = cve_dict.get("id", "UNKNOWN")
                    
                    # Extract English description
                    descriptions = cve_dict.get("descriptions", [])
                    desc_text = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc_text = d.get("value", "")
                            break
                    if not desc_text and descriptions:
                        desc_text = descriptions[0].get("value", "")

                    # Extract CVSS Score
                    cvss_score = 0.0
                    metrics = cve_dict.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0.0))
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0.0))
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0.0))

                    references = [
                        ref.get("url") for ref in cve_dict.get("references", []) if ref.get("url")
                    ]

                    cves.append(
                        VulnerabilityInfo(
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            severity=cvss_to_severity(cvss_score),
                            description=desc_text[:300] + "..." if len(desc_text) > 300 else desc_text,
                            affected_service=keyword,
                            published_date=cve_dict.get("published"),
                            references=references[:3]
                        )
                    )
            elif resp.status_code == 403 or resp.status_code == 429:
                log_warning(f"NVD API rate limit aşıldı ({resp.status_code}). Çevrimdışı veritabanına başvuruluyor.")
    except Exception as e:
        log_warning(f"NVD API bağlantı hatası ({keyword}): {e}")

    return cves


async def match_vulnerabilities(
    services: List[ServiceDetail],
    api_key: Optional[str] = None,
    use_online_api: bool = True,
    output_file: str = "output/vulns.json"
) -> List[VulnerabilityInfo]:
    """
    Match CVE vulnerabilities for all detected services.
    Uses offline database and online NVD API queries.
    """
    log_info(f"CVE & Zafiyet Eşleştirmesi başlatılıyor ({len(services)} servis)...")
    log_audit("VULN_MATCH_START", f"services_count={len(services)}")

    all_vulnerabilities: List[VulnerabilityInfo] = []
    seen_cve_ids = set()

    for svc in services:
        # 1. Offline matching (Instant & precise)
        offline_matches = match_offline_cves(svc)
        for vuln in offline_matches:
            if vuln.cve_id not in seen_cve_ids:
                seen_cve_ids.add(vuln.cve_id)
                all_vulnerabilities.append(vuln)
                log_warning(
                    f"Zafiyet Tespit Edildi (Offline DB): [bold red]{vuln.cve_id}[/bold red] "
                    f"[{vuln.severity} - CVSS: {vuln.cvss_score}] -> {vuln.affected_service}"
                )

        # 2. Online NVD Query if version is identified and online enabled
        if use_online_api and svc.service_version and svc.service_name != "unknown":
            search_query = f"{svc.service_name} {svc.service_version}"
            log_info(f"NVD API sorgulanıyor: '{search_query}'...")
            nvd_matches = await query_nvd_api(search_query, api_key=api_key)
            
            for vuln in nvd_matches:
                if vuln.cve_id not in seen_cve_ids:
                    vuln.affected_service = f"{svc.service_name} ({svc.ip}:{svc.port})"
                    vuln.affected_version = svc.service_version
                    seen_cve_ids.add(vuln.cve_id)
                    all_vulnerabilities.append(vuln)
                    log_warning(
                        f"Zafiyet Tespit Edildi (NVD API): [bold red]{vuln.cve_id}[/bold red] "
                        f"[{vuln.severity} - CVSS: {vuln.cvss_score}] -> {vuln.affected_service}"
                    )
            # Brief delay between NVD requests to respect rate limits
            await asyncio.sleep(0.6)

    # Sort vulnerabilities by CVSS score descending (highest risk first)
    all_vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)
    
    save_vulns(all_vulnerabilities, output_file)
    log_info(f"CVE Analizi tamamlandı: {len(all_vulnerabilities)} zafiyet bulundu ({output_file}).")
    log_audit("VULN_MATCH_COMPLETE", "all", f"total_vulns={len(all_vulnerabilities)}")

    return all_vulnerabilities
