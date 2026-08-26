"""
Module 3: Banner Grabbing & Service / Version Detection
Extracts raw socket banners, analyzes HTTP/HTTPS headers and HTML titles,
and matches service signatures using regex.
"""

import asyncio
import ssl
import re
import socket
from typing import List, Optional, Tuple, Dict, Any
import httpx
from core.models import PortInfo, ServiceDetail
from core.logger import log_info, log_success, log_warning, log_error, log_audit
from core.storage import save_services

SERVICE_REGEXES = [
    # SSH
    (r"SSH-([\d\.]+)-OpenSSH_([^\s]+)", "ssh", "OpenSSH", lambda m: f"{m.group(2)}"),
    (r"SSH-([\d\.]+)-([^\r\n]+)", "ssh", "SSH Server", lambda m: f"{m.group(2)}"),
    
    # HTTP Servers
    (r"Apache/([\d\.]+)(?:\s*\(([^\)]+)\))?", "http", "Apache HTTP Server", lambda m: f"{m.group(1)}"),
    (r"nginx/([\d\.]+)", "http", "nginx", lambda m: f"{m.group(1)}"),
    (r"Microsoft-IIS/([\d\.]+)", "http", "Microsoft IIS", lambda m: f"{m.group(1)}"),
    (r"lighttpd/([\d\.]+)", "http", "lighttpd", lambda m: f"{m.group(1)}"),
    (r"Caddy(?:/v?([\d\.]+))?", "http", "Caddy", lambda m: m.group(1) or ""),
    (r"Werkzeug/([\d\.]+)", "http", "Werkzeug (Python)", lambda m: f"{m.group(1)}"),
    (r"Node\.js", "http", "Node.js", lambda m: ""),
    (r"Express", "http", "Express.js", lambda m: ""),
    (r"PHP/([\d\.]+)", "http", "PHP", lambda m: f"{m.group(1)}"),
    (r"gunicorn/([\d\.]+)", "http", "Gunicorn", lambda m: f"{m.group(1)}"),
    (r"uvicorn", "http", "Uvicorn", lambda m: ""),
    (r"Tomcat/([\d\.]+)", "http", "Apache Tomcat", lambda m: f"{m.group(1)}"),

    # FTP
    (r"vsFTPd\s+([\d\.]+)", "ftp", "vsftpd", lambda m: f"{m.group(1)}"),
    (r"ProFTPD\s+([\d\.]+)", "ftp", "ProFTPD", lambda m: f"{m.group(1)}"),
    (r"Pure-FTPd", "ftp", "Pure-FTPd", lambda m: ""),
    (r"220[- ].*FileZilla Server ([\d\.]+)", "ftp", "FileZilla Server", lambda m: f"{m.group(1)}"),

    # SMTP / Mail
    (r"220[- ].*Postfix", "smtp", "Postfix SMTP", lambda m: ""),
    (r"220[- ].*Exim\s+([\d\.]+)", "smtp", "Exim SMTP", lambda m: f"{m.group(1)}"),
    (r"220[- ].*Sendmail\s+([\d\.]+)", "smtp", "Sendmail", lambda m: f"{m.group(1)}"),

    # Databases
    (r"([\d\.]+)-MariaDB", "mysql", "MariaDB", lambda m: f"{m.group(1)}"),
    (r"([\d\.]+(?:-[a-zA-Z0-9]+)?)\x00.*mysql", "mysql", "MySQL", lambda m: f"{m.group(1)}"),
    (r"5\.[\d\.]+-log", "mysql", "MySQL", lambda m: m.group(0)),
    (r"8\.[\d\.]+", "mysql", "MySQL", lambda m: m.group(0)),
    (r"redis_version:([\d\.]+)", "redis", "Redis", lambda m: f"{m.group(1)}"),
    (r"-ERR unknown command", "redis", "Redis Server", lambda m: ""),
]

HTTP_PORTS = {80, 81, 88, 3000, 4000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
HTTPS_PORTS = {443, 8443, 9443, 10443}


def extract_version_from_text(text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Search text for known service banners.
    Returns (service_name, service_description, version)
    """
    for pattern, s_name, s_desc, ver_func in SERVICE_REGEXES:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            version = ver_func(match) if ver_func else None
            return s_name, s_desc, version if version else None
    return None, None, None


async def grab_raw_socket_banner(ip: str, port: int, timeout: float = 2.5) -> Tuple[str, Optional[str]]:
    """Connect to raw socket and read initial greeting or probe response."""
    banner_raw = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        
        # Try reading immediate banner (SSH, FTP, SMTP send greeting automatically)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.2)
            banner_raw = data.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            pass

        # If nothing received, send generic probe
        if not banner_raw:
            try:
                probe = b"\r\n\r\n"
                if port in [21, 25, 587]:
                    probe = b"EHLO recon.local\r\n"
                elif port in [6379]:
                    probe = b"INFO\r\n"
                    
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.2)
                banner_raw = data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass

    return banner_raw, None


async def probe_http_service(
    ip: str, port: int, is_ssl: bool = False, timeout: float = 3.5
) -> Dict[str, Any]:
    """Probe HTTP/HTTPS service for headers, title, and web technologies."""
    proto = "https" if is_ssl else "http"
    url = f"{proto}://{ip}:{port}/"
    result = {
        "is_http": False,
        "server": None,
        "title": None,
        "technologies": [],
        "banner": ""
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ReconTool/1.0"
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            result["is_http"] = True
            
            # Server header
            server = resp.headers.get("server")
            x_powered = resp.headers.get("x-powered-by")
            via = resp.headers.get("via")

            result["server"] = server or x_powered
            
            # Extract HTML title
            match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                result["title"] = match.group(1).strip()[:100]

            technologies = []
            if server:
                technologies.append(f"Server: {server}")
            if x_powered:
                technologies.append(f"PoweredBy: {x_powered}")
            if via:
                technologies.append(f"Via: {via}")
            if "wordpress" in resp.text.lower() or "wp-content" in resp.text.lower():
                technologies.append("WordPress")
            if "drupal" in resp.text.lower():
                technologies.append("Drupal")
            if "joomla" in resp.text.lower():
                technologies.append("Joomla")
            if "react" in resp.text.lower() or "root" in resp.text.lower() and "react" in resp.headers.get("content-type", ""):
                technologies.append("React")
                
            result["technologies"] = technologies
            result["banner"] = f"HTTP {resp.status_code} | Server: {server or 'Unknown'}"
    except Exception:
        pass

    return result


async def inspect_ssl_cert(ip: str, port: int, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Retrieve SSL certificate metadata."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
        )
        ssl_obj = writer.get_extra_info('ssl_object')
        cert = ssl_obj.getpeercert(binary_form=False)
        cipher = ssl_obj.cipher()
        
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return {
            "cipher": cipher[0] if cipher else None,
            "version": ssl_obj.version(),
            "subject": cert.get("subject") if cert else None
        }
    except Exception:
        return None


async def analyze_service(port_info: PortInfo, timeout: float = 3.0) -> ServiceDetail:
    """Analyze a single open port to identify service details and versions."""
    ip = port_info.ip
    port = port_info.port
    
    service_name = port_info.service_name or "unknown"
    service_desc = None
    service_version = None
    banner_raw = ""
    http_title = None
    http_server = None
    http_techs = []
    ssl_enabled = False
    ssl_info = None

    # Check SSL / HTTPS first
    if port in HTTPS_PORTS or port == 443:
        ssl_info = await inspect_ssl_cert(ip, port, timeout=timeout)
        if ssl_info:
            ssl_enabled = True

    # 1. HTTP Probe
    is_likely_http = port in HTTP_PORTS or port in HTTPS_PORTS or "http" in service_name
    http_res = await probe_http_service(ip, port, is_ssl=ssl_enabled or port in HTTPS_PORTS, timeout=timeout)
    
    if not http_res["is_http"] and not is_likely_http:
        # Try HTTP anyway if generic
        http_res = await probe_http_service(ip, port, is_ssl=False, timeout=2.0)

    if http_res["is_http"]:
        service_name = "https" if (ssl_enabled or port in HTTPS_PORTS) else "http"
        http_title = http_res.get("title")
        http_server = http_res.get("server")
        http_techs = http_res.get("technologies", [])
        banner_raw = http_res.get("banner", "")
        
        if http_server:
            s_name, s_desc, s_ver = extract_version_from_text(http_server)
            if s_name:
                service_desc = s_desc
                service_version = s_ver

    # 2. Raw Socket Banner Probe (if not HTTP or if version not yet found)
    if not service_version:
        raw_banner, _ = await grab_raw_socket_banner(ip, port, timeout=timeout)
        if raw_banner:
            banner_raw = raw_banner if not banner_raw else f"{banner_raw} | {raw_banner}"
            s_name, s_desc, s_ver = extract_version_from_text(raw_banner)
            if s_name:
                service_name = s_name
                service_desc = s_desc
                service_version = s_ver

    # Fallback descriptions
    if not service_desc and service_name:
        service_desc = f"{service_name.upper()} Service"

    return ServiceDetail(
        ip=ip,
        port=port,
        protocol=port_info.protocol,
        service_name=service_name,
        service_description=service_desc,
        service_version=service_version,
        banner_raw=banner_raw[:255] if banner_raw else None,
        http_title=http_title,
        http_server=http_server,
        http_technologies=http_techs,
        ssl_enabled=ssl_enabled,
        ssl_info=ssl_info,
        state="open"
    )


async def grab_banners_and_services(
    ports: List[PortInfo],
    concurrency: int = 30,
    timeout: float = 3.5,
    output_file: str = "output/services.json"
) -> List[ServiceDetail]:
    """
    Perform banner grabbing & service detection across all open ports.
    """
    log_info(f"Banner Grabbing & Servis Tespiti başlatılıyor ({len(ports)} açık port)...")
    log_audit("SERVICE_DETECTION_START", f"ports_count={len(ports)}", f"concurrency={concurrency}")

    semaphore = asyncio.Semaphore(concurrency)
    services: List[ServiceDetail] = []

    async def worker(p: PortInfo):
        async with semaphore:
            svc = await analyze_service(p, timeout=timeout)
            services.append(svc)
            ver_str = f" v{svc.service_version}" if svc.service_version else ""
            log_success(
                f"Servis Tanımlandı: {svc.ip}:{svc.port} -> [bold]{svc.service_name}[/bold]{ver_str} "
                f"({svc.service_description or 'Genel'})"
            )

    tasks = [worker(p) for p in ports]
    await asyncio.gather(*tasks)

    services.sort(key=lambda s: (s.ip, s.port))
    save_services(services, output_file)
    log_info(f"Servis Tespiti tamamlandı: {len(services)} servis kaydedildi ({output_file}).")
    log_audit("SERVICE_DETECTION_COMPLETE", "all", f"detected_services={len(services)}")

    return services
