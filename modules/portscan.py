"""
Module 2: Port & Service Scanner
Asynchronous TCP connect scanner with concurrency control and port list presets.
"""

import asyncio
import time
from typing import List, Union, Optional
from core.models import PortInfo
from core.logger import log_info, log_success, log_warning, log_error, log_audit
from core.storage import save_ports

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 
    179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 591, 631, 636, 873, 902, 989, 990, 993, 
    995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 
    2222, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4000, 4443, 5000, 5432, 5672, 5900, 5985, 
    5986, 6000, 6379, 7001, 7077, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9092, 
    9200, 9300, 9418, 9999, 10000, 11211, 27017, 27018, 50000
]

COMMON_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http-alt",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
    2049: "nfs", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl", 3000: "http-dev",
    3306: "mysql", 3389: "ms-wbt-server", 5000: "http-dev", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 5985: "wsman", 6379: "redis", 7001: "weblogic", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"
}


def parse_port_specs(port_str: str) -> List[int]:
    """
    Parse port specification strings:
    - 'top-20', 'top-100', 'top-1000'
    - '80,443,8080'
    - '1-1000'
    - '80,443,8000-8080'
    """
    port_str = str(port_str).strip().lower()
    
    if port_str == "top-20":
        return sorted(list(set(TOP_20_PORTS)))
    elif port_str in ["top-100", "default", "common"]:
        return sorted(list(set(TOP_100_PORTS)))
    elif port_str in ["top-1000", "all-common"]:
        # Top 1000 commonly used ports (1..1024 + high common ports)
        ports = set(range(1, 1025))
        ports.update(TOP_100_PORTS)
        ports.update([1433, 1521, 2082, 2083, 2087, 3000, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017])
        return sorted(list(ports))
    elif port_str in ["full", "all", "1-65535"]:
        return list(range(1, 65536))

    ports_set = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start_p, end_p = map(int, part.split('-'))
                ports_set.update(range(max(1, start_p), min(65535, end_p) + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports_set.add(p)
            except ValueError:
                continue

    return sorted(list(ports_set)) or TOP_100_PORTS


async def scan_single_port(ip: str, port: int, timeout: float = 1.5) -> Optional[PortInfo]:
    """Scan a single TCP port using async connect."""
    start_time = time.perf_counter()
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        response_time = (time.perf_counter() - start_time) * 1000.0
        
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        service_name = COMMON_SERVICE_NAMES.get(port, "unknown")
        return PortInfo(
            ip=ip,
            port=port,
            protocol="tcp",
            state="open",
            service_name=service_name,
            response_time_ms=round(response_time, 2)
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


async def scan_target_ports(
    ip: str,
    ports: Union[List[int], str] = "top-100",
    concurrency: int = 100,
    timeout: float = 1.5,
    output_file: str = "output/ports.json"
) -> List[PortInfo]:
    """
    Asynchronously scan a list of ports for a single host.
    """
    if isinstance(ports, str):
        port_list = parse_port_specs(ports)
    else:
        port_list = ports

    log_info(f"Port Taraması başlatılıyor: Hedef='{ip}', Port Sayısı={len(port_list)}, Eşzamanlılık={concurrency}")
    log_audit("PORT_SCAN_START", ip, f"total_ports={len(port_list)}, timeout={timeout}")

    semaphore = asyncio.Semaphore(concurrency)
    open_ports: List[PortInfo] = []

    async def worker(port: int):
        async with semaphore:
            res = await scan_single_port(ip, port, timeout=timeout)
            if res:
                open_ports.append(res)
                log_success(f"Açık Port Bulundu: {ip}:{res.port} ({res.service_name}) [{res.response_time_ms}ms]")

    tasks = [worker(p) for p in port_list]
    await asyncio.gather(*tasks)

    open_ports.sort(key=lambda x: x.port)
    save_ports(open_ports, output_file)
    log_info(f"Port Taraması tamamlandı: {len(open_ports)} açık port tespit edildi ({output_file}).")
    log_audit("PORT_SCAN_COMPLETE", ip, f"open_ports_count={len(open_ports)}")

    return open_ports


async def scan_multiple_hosts(
    ips: List[str],
    ports: Union[List[int], str] = "top-100",
    concurrency: int = 100,
    timeout: float = 1.5,
    output_file: str = "output/ports.json"
) -> List[PortInfo]:
    """Scan open ports for multiple target IPs."""
    all_open_ports: List[PortInfo] = []
    for ip in ips:
        ports_found = await scan_target_ports(
            ip, ports=ports, concurrency=concurrency, timeout=timeout, output_file=output_file
        )
        all_open_ports.extend(ports_found)
    
    save_ports(all_open_ports, output_file)
    return all_open_ports
