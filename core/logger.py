import os
import sys
import logging
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False)

AUDIT_LOG_PATH = "output/audit.log"


def init_audit_logger(log_path: str = AUDIT_LOG_PATH) -> logging.Logger:
    """Initialize persistent audit logger for ethical/compliance recording."""
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    
    logger = logging.getLogger("recon_audit")
    logger.setLevel(logging.INFO)
    
    # Check if handlers already exist to avoid duplicate logs
    if not logger.handlers:
        handler = logging.FileHandler(log_path, encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


audit_logger = init_audit_logger()


def log_audit(action: str, target: str, details: str = "", status: str = "SUCCESS") -> None:
    """Record an audit trail event."""
    msg = f"ACTION={action} | TARGET={target} | STATUS={status} | DETAILS={details}"
    audit_logger.info(msg)


def print_banner(app_name: str = "SpecterRecon", version: str = "1.0.0") -> None:
    """Display visually appealing ASCII banner."""
    banner_text = f"""
[bold cyan]  ____                  _             ____                     [/bold cyan]
[bold cyan] / ___| _ __   ___  ___| |_ ___ _ __ |  _ \ ___  ___ ___  _ __ [/bold cyan]
[bold cyan] \___ \| '_ \ / _ \/ __| __/ _ \ '__|| |_) / _ \/ __/ _ \| '_ \ [/bold cyan]
[bold cyan]  ___) | |_) |  __/ (__| ||  __/ |   |  _ <  __/ (_| (_) | | | |[/bold cyan]
[bold cyan] |____/| .__/ \___|\___|\__\___|_|   |_| \_\___|\___\___/|_| |_|[/bold cyan]
[bold cyan]       |_|                                                     [/bold cyan]
[bold white]   -- Fast, Modular Network Recon & Vulnerability Scanner v{version} --[/bold white]
[dim]                 Yetkilendirilmis Guvenlik ve Lab Test Platformu[/dim]
"""
    console.print(Panel(banner_text.strip(), border_style="cyan", expand=False))


def log_info(msg: str) -> None:
    console.print(f"[bold blue][*][/bold blue] {msg}")


def log_success(msg: str) -> None:
    console.print(f"[bold green][+][/bold green] {msg}")


def log_warning(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def log_error(msg: str) -> None:
    console.print(f"[bold red][-][/bold red] {msg}")


def log_step(step_name: str) -> None:
    console.print(f"\n[bold magenta]========= [ {step_name.upper()} ] =========[/bold magenta]")


def print_hosts_table(hosts) -> None:
    """Print discovered hosts in a clean Rich table."""
    if not hosts:
        return
    table = Table(title="🌐 Keşfedilen Hostlar", border_style="cyan", header_style="bold cyan")
    table.add_column("IP Adresi", style="bold white")
    table.add_column("MAC Adresi", style="dim")
    table.add_column("Yöntem", style="cyan")
    table.add_column("Gecikme (Latency)", style="green")
    table.add_column("Durum", style="bold green")

    for h in hosts:
        lat = f"{h.latency_ms} ms" if h.latency_ms is not None else "-"
        table.add_row(
            h.ip,
            h.mac or "-",
            h.discovery_method,
            lat,
            h.state.upper()
        )
    console.print(table)


def print_ports_table(ports) -> None:
    """Print open ports in a clean Rich table."""
    if not ports:
        return
    table = Table(title="🔌 Açık Portlar", border_style="blue", header_style="bold blue")
    table.add_column("IP Adresi", style="white")
    table.add_column("Port/Protokol", style="bold green")
    table.add_column("Servis", style="bold yellow")
    table.add_column("Durum", style="green")
    table.add_column("Yanıt Süresi", style="dim")

    for p in ports:
        resp = f"{p.response_time_ms} ms" if p.response_time_ms is not None else "-"
        table.add_row(
            p.ip,
            f"{p.port}/{p.protocol.upper()}",
            p.service_name or "unknown",
            p.state.upper(),
            resp
        )
    console.print(table)


def print_services_table(services) -> None:
    """Print detected services & banners in a clean Rich table."""
    if not services:
        return
    table = Table(title="🏷️ Tanımlanan Servisler & Versiyonlar", border_style="green", header_style="bold green")
    table.add_column("Hedef", style="white")
    table.add_column("Servis", style="bold cyan")
    table.add_column("Versiyon / Başlık", style="bold yellow")
    table.add_column("Açıklama / Banner", style="dim")
    table.add_column("SSL", style="magenta")

    for s in services:
        ver = s.service_version or s.http_title or "-"
        banner = s.banner_raw[:45] + "..." if (s.banner_raw and len(s.banner_raw) > 45) else (s.banner_raw or s.service_description or "-")
        ssl_str = "🔒 Evet" if s.ssl_enabled else "Hayır"
        table.add_row(
            f"{s.ip}:{s.port}",
            s.service_name.upper(),
            ver,
            banner,
            ssl_str
        )
    console.print(table)


def print_vulns_table(vulns) -> None:
    """Print detected CVE vulnerabilities in a clean Rich table."""
    if not vulns:
        console.print("[bold green]✅ Taranan servislerde bilinen kritik CVE zafiyeti bulunamadı.[/bold green]")
        return
    table = Table(title="🛡️ Tespit Edilen Zafiyetler & CVE'ler", border_style="red", header_style="bold red")
    table.add_column("CVE ID", style="bold white")
    table.add_column("CVSS", style="bold")
    table.add_column("Şiddet", style="bold")
    table.add_column("Etkilenen Servis", style="cyan")
    table.add_column("Zafiyet Açıklaması", style="white")

    for v in vulns:
        # Color coding for severity
        if v.severity == "CRITICAL":
            sev_styled = "[bold white on red] CRITICAL [/]"
            cvss_styled = f"[bold red]{v.cvss_score}[/bold red]"
        elif v.severity == "HIGH":
            sev_styled = "[bold black on yellow] HIGH [/]"
            cvss_styled = f"[bold yellow]{v.cvss_score}[/bold yellow]"
        elif v.severity == "MEDIUM":
            sev_styled = "[bold black on cyan] MEDIUM [/]"
            cvss_styled = f"[cyan]{v.cvss_score}[/cyan]"
        else:
            sev_styled = f"[dim]{v.severity}[/dim]"
            cvss_styled = f"[dim]{v.cvss_score}[/dim]"

        desc = v.description[:70] + "..." if len(v.description) > 70 else v.description
        table.add_row(
            v.cve_id,
            cvss_styled,
            sev_styled,
            v.affected_service,
            desc
        )
    console.print(table)


def print_dir_findings_table(findings) -> None:
    """Print web fuzzing directory findings in a clean Rich table."""
    if not findings:
        return
    table = Table(title="📁 Web Dizin & Dosya Bulguları (Fuzzer)", border_style="yellow", header_style="bold yellow")
    table.add_column("Durum Kodu", style="bold")
    table.add_column("URL / Yol", style="bold white")
    table.add_column("Boyut", style="cyan")
    table.add_column("Başlık / Yönlendirme", style="dim")
    table.add_column("Kritiklik", style="bold")

    for f in findings:
        # Status code color
        if f.status_code == 200:
            status_str = f"[bold green]{f.status_code} OK[/bold green]"
        elif f.status_code in [301, 302, 307]:
            status_str = f"[bold yellow]{f.status_code} REDIR[/bold yellow]"
        elif f.status_code in [401, 403]:
            status_str = f"[bold cyan]{f.status_code} AUTH[/bold cyan]"
        else:
            status_str = f"{f.status_code}"

        info = f.title or (f"➜ {f.redirect_location}" if f.redirect_location else "-")
        tag = "[bold red]⚠️ HASSAS DOSYA[/bold red]" if f.is_sensitive else "[dim]Standart[/dim]"

        table.add_row(
            status_str,
            f.url,
            f"{f.content_length} B",
            info[:35],
            tag
        )
    console.print(table)
