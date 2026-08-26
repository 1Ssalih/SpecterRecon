"""
Module 1: Host Discovery
Performs ARP scanning for local subnets, ICMP ping sweeps, and TCP ping probes.
"""

import asyncio
import ipaddress
import socket
import time
import subprocess
import re
from typing import List, Optional
from core.models import HostInfo
from core.logger import log_info, log_success, log_warning, log_error, log_audit
from core.storage import save_hosts

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Try importing Scapy
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def parse_targets(target_str: str) -> List[str]:
    """Parse CIDR, range, hostname, or single IP into a list of IP strings."""
    target_str = target_str.strip()
    
    # Check if target is a hostname (not IP/CIDR)
    if not any(char in target_str for char in ['/', '-']) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', target_str):
        try:
            ip = socket.gethostbyname(target_str)
            return [ip]
        except socket.gaierror:
            return [target_str]

    # Handle IP Range (e.g. 192.168.1.1-192.168.1.50 or 192.168.1.1-50)
    if '-' in target_str:
        parts = target_str.split('-')
        start_ip_str = parts[0].strip()
        end_part = parts[1].strip()
        
        start_ip = ipaddress.IPv4Address(start_ip_str)
        if '.' in end_part:
            end_ip = ipaddress.IPv4Address(end_part)
        else:
            # e.g., 192.168.1.1-50
            prefix = '.'.join(start_ip_str.split('.')[:-1])
            end_ip = ipaddress.IPv4Address(f"{prefix}.{end_part}")
            
        start_int = int(start_ip)
        end_int = int(end_ip)
        return [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]

    # Handle CIDR (e.g. 192.168.1.0/24 or single IP 192.168.1.1/32)
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        # Return all host IPs in the subnet
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Fallback to single target
        return [target_str]


def arp_scan_scapy(target_cidr: str, timeout: float = 2.0) -> List[HostInfo]:
    """Perform ARP scan using Scapy for local network."""
    if not SCAPY_AVAILABLE:
        return []
    
    alive_hosts: List[HostInfo] = []
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_cidr),
            timeout=timeout,
            verbose=False
        )
        for _, rcv in ans:
            alive_hosts.append(
                HostInfo(
                    ip=rcv.psrc,
                    mac=rcv.hwsrc,
                    discovery_method="arp",
                    state="alive"
                )
            )
    except Exception as e:
        log_warning(f"Scapy ARP scan hatası (fallback kullanılacak): {e}")
    
    return alive_hosts


def get_arp_table() -> dict:
    """Read system ARP cache across Windows, Linux, and macOS as a fallback."""
    arp_map = {}
    try:
        if os.name == "nt":
            output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode("latin-1", errors="ignore")
            for line in output.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)", line)
                if match:
                    ip, mac, _type = match.groups()
                    arp_map[ip] = mac.replace("-", ":").lower()
        else:
            # Linux / macOS
            output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            for line in output.splitlines():
                match = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F:]{17})", line)
                if match:
                    ip, mac = match.groups()
                    arp_map[ip] = mac.lower()
    except Exception:
        pass
    return arp_map


async def async_tcp_ping(ip: str, port: int, timeout: float = 1.0) -> Optional[float]:
    """Check if host responds to TCP connect on a specific port."""
    start_time = time.perf_counter()
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        latency = (time.perf_counter() - start_time) * 1000.0
        return round(latency, 2)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # ConnectionRefusedError means the HOST is alive (sent RST packet)
        return round((time.perf_counter() - start_time) * 1000.0, 2)
    except Exception:
        return None


async def async_icmp_ping(ip: str, timeout: float = 1.5) -> Optional[float]:
    """Ping host using OS system ping asynchronously (Windows, Linux, macOS)."""
    start_time = time.perf_counter()
    try:
        if os.name == "nt":
            # Windows: ping -n 1 -w timeout_ms ip
            timeout_ms = int(timeout * 1000)
            ping_cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        elif sys.platform == "darwin":
            # macOS: ping -c 1 -t timeout_sec ip
            ping_cmd = ["ping", "-c", "1", "-t", str(max(1, int(timeout))), ip]
        else:
            # Linux: ping -c 1 -W timeout_sec ip
            ping_cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

        proc = await asyncio.create_subprocess_exec(
            *ping_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        stdout_upper = stdout.upper()
        if proc.returncode == 0 and (b"TTL=" in stdout_upper or b"BYTES FROM" in stdout_upper):
            latency = (time.perf_counter() - start_time) * 1000.0
            return round(latency, 2)
    except Exception:
        pass
    return None


async def probe_single_host(
    ip: str,
    common_ports: List[int],
    timeout: float = 1.5,
    arp_map: Optional[dict] = None
) -> Optional[HostInfo]:
    """Probe a single IP with ICMP ping sweep and TCP ping probes."""
    # 1. ICMP Ping check
    icmp_latency = await async_icmp_ping(ip, timeout=timeout)
    if icmp_latency is not None:
        mac = arp_map.get(ip) if arp_map else None
        return HostInfo(
            ip=ip,
            mac=mac,
            discovery_method="icmp",
            latency_ms=icmp_latency,
            state="alive"
        )
    
    # 2. TCP Ping check across common ports
    for port in common_ports:
        latency = await async_tcp_ping(ip, port, timeout=min(timeout, 1.0))
        if latency is not None:
            mac = arp_map.get(ip) if arp_map else None
            return HostInfo(
                ip=ip,
                mac=mac,
                discovery_method=f"tcp_ping:{port}",
                latency_ms=latency,
                state="alive"
            )
            
    return None


async def discover_hosts(
    target: str,
    common_ports: Optional[List[int]] = None,
    timeout: float = 2.0,
    concurrency: int = 50,
    output_file: str = "output/hosts.json"
) -> List[HostInfo]:
    """
    Main host discovery function.
    Tries ARP scan for local CIDRs, otherwise runs async ICMP/TCP ping sweeps.
    """
    if common_ports is None:
        common_ports = [80, 443, 22, 445, 8080, 3389, 21, 23, 25, 53]
        
    log_info(f"Host Discovery başlatılıyor: Hedef='{target}'")
    log_audit("HOST_DISCOVERY_START", target, f"timeout={timeout}, concurrency={concurrency}")
    
    ip_list = parse_targets(target)
    log_info(f"Taranacak toplam hedef IP adresi sayısı: {len(ip_list)}")

    discovered_hosts: List[HostInfo] = []
    seen_ips = set()

    # 1. ARP Scan if target is a CIDR/local network
    if "/" in target and SCAPY_AVAILABLE:
        try:
            log_info("Yerel ağ için ARP taraması deneniyor...")
            arp_results = arp_scan_scapy(target, timeout=timeout)
            for h in arp_results:
                if h.ip not in seen_ips:
                    seen_ips.add(h.ip)
                    discovered_hosts.append(h)
                    log_success(f"Host bulundu (ARP): {h.ip} [{h.mac or 'No MAC'}]")
        except Exception as e:
            log_warning(f"ARP taraması atlandı: {e}")

    # 2. Fallback / Remote Ping Sweeps for remaining IPs
    remaining_ips = [ip for ip in ip_list if ip not in seen_ips]
    if remaining_ips:
        arp_cache = get_arp_table()
        semaphore = asyncio.Semaphore(concurrency)

        async def worker(ip: str):
            async with semaphore:
                res = await probe_single_host(ip, common_ports, timeout=timeout, arp_map=arp_cache)
                if res and res.ip not in seen_ips:
                    seen_ips.add(res.ip)
                    discovered_hosts.append(res)
                    log_success(f"Host bulundu ({res.discovery_method}): {res.ip} (Latency: {res.latency_ms}ms)")

        tasks = [worker(ip) for ip in remaining_ips]
        await asyncio.gather(*tasks)

    # Sort hosts by IP address
    try:
        discovered_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
    except Exception:
        pass

    save_hosts(discovered_hosts, output_file)
    log_info(f"Host Discovery tamamlandı. Toplam {len(discovered_hosts)} canlı host kaydedildi: {output_file}")
    log_audit("HOST_DISCOVERY_COMPLETE", target, f"found_hosts={len(discovered_hosts)}")
    
    return discovered_hosts
