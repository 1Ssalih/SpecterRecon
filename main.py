"""
Recon & Security Scanner — Main CLI Entry Point
Built with Typer and Rich.
"""

import asyncio
import time
import os
import sys
import logging
from typing import Optional

# Suppress scapy warning messages before module imports
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
os.environ["SCAPY_USE_PCAPDNET"] = "False"

import typer
from rich.prompt import Confirm
from rich.table import Table

from core.logger import (
    console, print_banner, log_info, log_success, log_warning, log_error, log_step, log_audit,
    print_hosts_table, print_ports_table, print_services_table, print_vulns_table, print_dir_findings_table
)
from core.storage import ensure_output_dir, load_hosts, load_ports, load_services, load_vulns
from modules.discovery import discover_hosts
from modules.portscan import scan_target_ports, scan_multiple_hosts
from modules.banner import grab_banners_and_services
from modules.vuln_match import match_vulnerabilities
from modules.dirfuzz import run_dir_fuzzing, fuzz_target_service, load_wordlist
from modules.report import build_complete_report, generate_html_report

app = typer.Typer(
    name="recon-tool",
    help="Ağ Reconnaissance, Port Tarama, Servis Tespiti, CVE Eşleştirme ve Raporlama Aracı.",
    add_completion=False
)


def verify_scope_permission(authorized: bool, target: str) -> bool:
    """Ensure user has verified legal authorization to scan the target."""
    if authorized:
        return True
    
    console.print(
        "\n[bold yellow]⚠️  YASAL UYARI & GÜVENLİK GUARDRAIL'I:[/bold yellow]\n"
        f"[white]Bu araç yalnızca yetkili olduğunuz sistemler (lab, CTF, izinli pentest) içindir.\n"
        f"Hedef: [bold cyan]{target}[/bold cyan][/white]\n"
    )
    
    is_confirmed = Confirm.ask("Bu hedefi taramak için yasal izniniz olduğunu onaylıyor musunuz?")
    if not is_confirmed:
        log_error("Kullanıcı izni onaylamadı. İşlem durduruldu.")
        sys.exit(1)
    
    return True


@app.command(name="scan")
def full_scan_pipeline(
    target: str = typer.Argument(..., help="Hedef IP, CIDR subnet (192.168.1.0/24) veya domain adı"),
    authorized: bool = typer.Option(False, "--authorized", "--i-have-permission", help="Hedef için tarama yetkinizin olduğunu onaylar"),
    ports: str = typer.Option("top-100", "--ports", "-p", help="Taranacak portlar: 'top-20', 'top-100', 'top-1000', '1-1024', '80,443'"),
    threads: int = typer.Option(50, "--threads", "-t", help="Eşzamanlı bağlantı limiti"),
    delay: int = typer.Option(0, "--delay", "-d", help="İstekler arası gecikme (ms) — Stealth modu"),
    skip_dirfuzz: bool = typer.Option(False, "--skip-dirfuzz", help="Dizin fuzzing adımını atla"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln", help="CVE zafiyet eşleştirme adımını atla"),
    output_dir: str = typer.Option("output", "--output-dir", "-o", help="Çıktı klasörü")
):
    """
    Tüm adımları (Discovery -> Port Scan -> Banner Grab -> CVE Match -> Dir Fuzz -> Report) sırasıyla çalıştırır.
    """
    print_banner()
    verify_scope_permission(authorized, target)
    ensure_output_dir(output_dir)

    start_time = time.perf_counter()
    log_audit("FULL_PIPELINE_START", target, f"ports={ports}, threads={threads}")

    async def _run():
        # Step 1: Host Discovery
        log_step("Adım 1 / 6: Host Discovery")
        hosts = await discover_hosts(target, concurrency=threads, output_file=f"{output_dir}/hosts.json")
        
        if not hosts:
            log_warning(f"'{target}' için canlı host tespit edilemedi. Doğrudan hedefe bağlanmayı deniyoruz...")
            from core.models import HostInfo
            hosts = [HostInfo(ip=target, discovery_method="direct")]

        print_hosts_table(hosts)

        # Step 2: Port Scanning
        log_step("Adım 2 / 6: Port & Servis Taraması")
        target_ips = [h.ip for h in hosts]
        ports_found = await scan_multiple_hosts(
            target_ips, ports=ports, concurrency=threads, output_file=f"{output_dir}/ports.json"
        )

        if not ports_found:
            log_warning("Hiçbir açık port tespit edilemedi. Tarama sonlandırılıyor.")
            report = build_complete_report(target, hosts=hosts, ports=[], services=[], vulns=[], findings=[], duration_seconds=time.perf_counter()-start_time)
            generate_html_report(report, output_path=f"{output_dir}/report.html")
            return

        print_ports_table(ports_found)

        # Step 3: Banner Grabbing & Service Detection
        log_step("Adım 3 / 6: Banner Grabbing & Versiyon Tespiti")
        services = await grab_banners_and_services(
            ports_found, concurrency=min(30, threads), output_file=f"{output_dir}/services.json"
        )
        print_services_table(services)

        # Step 4: Vulnerability / CVE Matching
        vulns = []
        if not skip_vuln:
            log_step("Adım 4 / 6: CVE & Zafiyet Eşleştirmesi")
            vulns = await match_vulnerabilities(
                services, output_file=f"{output_dir}/vulns.json"
            )
            print_vulns_table(vulns)
        else:
            log_info("CVE eşleştirme adımı atlandı (--skip-vuln).")

        # Step 5: Directory & File Bruteforce
        findings = []
        if not skip_dirfuzz:
            log_step("Adım 5 / 6: Web Dizin & Dosya Fuzzing")
            findings = await run_dir_fuzzing(
                services,
                concurrency=min(25, threads),
                delay_ms=delay,
                output_json=f"{output_dir}/dirs.json",
                output_txt=f"{output_dir}/findings.txt"
            )
            print_dir_findings_table(findings)
        else:
            log_info("Web dizin fuzzing adımı atlandı (--skip-dirfuzz).")

        # Step 6: Reporting
        log_step("Adım 6 / 6: Raporlama")
        duration = time.perf_counter() - start_time
        report = build_complete_report(
            target, hosts=hosts, ports=ports_found, services=services, vulns=vulns, findings=findings, duration_seconds=duration
        )
        report_path = generate_html_report(report, output_path=f"{output_dir}/report.html")

        # Display Final Summary Table
        console.print("\n")
        table = Table(title="📊 SpecterRecon Tarama Özeti", border_style="cyan", header_style="bold cyan")
        table.add_column("Metrik", style="bold white")
        table.add_column("Değer", style="bold green")
        table.add_row("Taranan Hedef", target)
        table.add_row("Keşfedilen Hostlar", str(len(hosts)))
        table.add_row("Açık Portlar", str(len(ports_found)))
        table.add_row("Tespit Edilen Zafiyetler", f"[bold red]{len(vulns)}[/bold red]" if vulns else "0")
        table.add_row("Web Dizin Bulguları", str(len(findings)))
        table.add_row("Toplam Süre", f"{duration:.2f} saniye")
        table.add_row("HTML Rapor Dosyası", f"[bold underline]{report_path}[/bold underline]")
        console.print(table)

    asyncio.run(_run())


@app.command(name="discover")
def cmd_discover(
    target: str = typer.Argument(..., help="Subnet CIDR veya hedef (örn: 192.168.1.0/24)"),
    authorized: bool = typer.Option(False, "--authorized", "--i-have-permission"),
    timeout: float = typer.Option(2.0, "--timeout", "-t"),
    output: str = typer.Option("output/hosts.json", "--output", "-o")
):
    """Sadece Host Keşfi (ARP/ICMP/TCP ping) çalıştırır."""
    print_banner()
    verify_scope_permission(authorized, target)
    async def _discover():
        hosts = await discover_hosts(target, timeout=timeout, output_file=output)
        print_hosts_table(hosts)
    asyncio.run(_discover())


@app.command(name="portscan")
def cmd_portscan(
    target: str = typer.Argument(..., help="Hedef IP veya Hostname"),
    authorized: bool = typer.Option(False, "--authorized", "--i-have-permission"),
    ports: str = typer.Option("top-100", "--ports", "-p"),
    threads: int = typer.Option(100, "--threads", "-t"),
    output: str = typer.Option("output/ports.json", "--output", "-o")
):
    """Hedef üzerinde TCP Connect port taraması yapar."""
    print_banner()
    verify_scope_permission(authorized, target)
    async def _scan():
        ports_found = await scan_target_ports(target, ports=ports, concurrency=threads, output_file=output)
        print_ports_table(ports_found)
    asyncio.run(_scan())


@app.command(name="banner")
def cmd_banner(
    input_ports_file: str = typer.Option("output/ports.json", "--input", "-i", help="Açık portlar JSON dosyası"),
    output: str = typer.Option("output/services.json", "--output", "-o")
):
    """Açık portlar için banner grabbing ve versiyon tespiti yapar."""
    print_banner()
    ports = load_ports(input_ports_file)
    if not ports:
        log_error(f"Port listesi bulunamadı veya boş: {input_ports_file}")
        return
    async def _banner():
        services = await grab_banners_and_services(ports, output_file=output)
        print_services_table(services)
    asyncio.run(_banner())


@app.command(name="vuln")
def cmd_vuln(
    input_services_file: str = typer.Option("output/services.json", "--input", "-i", help="Servisler JSON dosyası"),
    output: str = typer.Option("output/vulns.json", "--output", "-o")
):
    """Servis listesi için CVE zafiyet eşleştirmesi yapar."""
    print_banner()
    services = load_services(input_services_file)
    if not services:
        log_error(f"Servis listesi bulunamadı: {input_services_file}")
        return
    async def _vuln():
        vulns = await match_vulnerabilities(services, output_file=output)
        print_vulns_table(vulns)
    asyncio.run(_vuln())


@app.command(name="dirfuzz")
def cmd_dirfuzz(
    url: str = typer.Argument(..., help="Hedef URL (örn: http://127.0.0.1:8080)"),
    authorized: bool = typer.Option(False, "--authorized", "--i-have-permission"),
    wordlist: str = typer.Option("wordlists/common.txt", "--wordlist", "-w"),
    threads: int = typer.Option(25, "--threads", "-t"),
    delay: int = typer.Option(0, "--delay", "-d", help="Gecikme (ms)"),
    output_json: str = typer.Option("output/dirs.json", "--output-json"),
    output_txt: str = typer.Option("output/findings.txt", "--output-txt")
):
    """Web hedefinde dizin/dosya fuzzing çalıştırır."""
    print_banner()
    verify_scope_permission(authorized, url)
    
    words = load_wordlist(wordlist)
    if not words:
        log_error(f"Wordlist boş veya bulunamadı: {wordlist}")
        return
        
    async def _fuzz():
        findings = await fuzz_target_service(
            base_url=url, wordlist=words, concurrency=threads, delay_ms=delay
        )
        from core.storage import save_findings
        save_findings(findings, output_json, output_txt)
        print_dir_findings_table(findings)
        log_success(f"Dizin taraması bitti: {len(findings)} yol bulundu.")
        
    asyncio.run(_fuzz())


@app.command(name="report")
def cmd_report(
    target: str = typer.Option("Target Network", "--target", "-t"),
    output: str = typer.Option("output/report.html", "--output", "-o")
):
    """Mevcut JSON çıktılarından HTML raporu üretir."""
    print_banner()
    report = build_complete_report(target=target)
    generate_html_report(report, output_path=output)


if __name__ == "__main__":
    app()
