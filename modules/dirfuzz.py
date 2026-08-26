"""
Module 5: Web Directory & File Bruteforce (Fuzzer)
Asynchronous web directory scanner with rate limiting, response filtering,
and sensitive path detection.
"""

import asyncio
import os
import time
import re
from typing import List, Optional, Set
import httpx
from core.models import DirFuzzFinding, ServiceDetail
from core.logger import log_info, log_success, log_warning, log_error, log_audit
from core.storage import save_findings

DEFAULT_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403, 405, 500}
SENSITIVE_KEYWORDS = {".env", ".git", ".bak", "config", "backup", "sql", "id_rsa", "password", "secret", "private"}


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist lines from file, ignoring comments and empty lines."""
    if not os.path.exists(filepath):
        log_warning(f"Wordlist dosyası bulunamadı: {filepath}")
        return []
    
    words = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w.lstrip("/"))
    return words


async def fuzz_single_url(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    status_codes: Set[int],
    delay_ms: int = 0
) -> Optional[DirFuzzFinding]:
    """Fuzz a single endpoint path on the target base URL."""
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000.0)

    url = f"{base_url.rstrip('/')}/{path}"
    start_time = time.perf_counter()

    try:
        resp = await client.get(url, follow_redirects=False)
        response_time = (time.perf_counter() - start_time) * 1000.0

        if resp.status_code in status_codes:
            # Extract title if HTML
            title = None
            if "text/html" in resp.headers.get("content-type", ""):
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()[:60]

            redirect_loc = resp.headers.get("location")
            is_sensitive = any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)

            return DirFuzzFinding(
                url=url,
                path=f"/{path}",
                status_code=resp.status_code,
                content_length=len(resp.content),
                redirect_location=redirect_loc,
                title=title,
                response_time_ms=round(response_time, 2),
                is_sensitive=is_sensitive
            )
    except Exception:
        pass

    return None


async def fuzz_target_service(
    base_url: str,
    wordlist: List[str],
    status_codes: Set[int] = DEFAULT_STATUS_CODES,
    concurrency: int = 25,
    delay_ms: int = 0,
    timeout: float = 4.0
) -> List[DirFuzzFinding]:
    """Fuzz a single base URL using given wordlist."""
    log_info(f"Dizin Taraması başlatılıyor: Hedef='{base_url}', Kelime Sayısı={len(wordlist)}")
    log_audit("DIR_FUZZ_START", base_url, f"words={len(wordlist)}, concurrency={concurrency}")

    semaphore = asyncio.Semaphore(concurrency)
    findings: List[DirFuzzFinding] = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ReconTool/1.0"
    }

    async with httpx.AsyncClient(verify=False, timeout=timeout, headers=headers) as client:
        async def worker(path: str):
            async with semaphore:
                res = await fuzz_single_url(client, base_url, path, status_codes, delay_ms=delay_ms)
                if res:
                    findings.append(res)
                    status_color = "green" if res.status_code == 200 else ("yellow" if res.status_code in [301, 302, 307] else "cyan")
                    tag = " [bold red][KRİTİK DOSYA][/bold red]" if res.is_sensitive else ""
                    log_success(
                        f"Dizin Bulundu: [{status_color}][{res.status_code}][/{status_color}] "
                        f"{res.url} (Boyut: {res.content_length}B){tag}"
                    )

        tasks = [worker(w) for w in wordlist]
        await asyncio.gather(*tasks)

    findings.sort(key=lambda f: f.path)
    return findings


async def run_dir_fuzzing(
    services: List[ServiceDetail],
    wordlist_path: str = "wordlists/common.txt",
    sensitive_wordlist_path: str = "wordlists/sensitive.txt",
    concurrency: int = 25,
    delay_ms: int = 0,
    output_json: str = "output/dirs.json",
    output_txt: str = "output/findings.txt"
) -> List[DirFuzzFinding]:
    """
    Run directory fuzzing on all identified HTTP/HTTPS services.
    """
    words = load_wordlist(wordlist_path)
    sensitive_words = load_wordlist(sensitive_wordlist_path)
    
    # Merge and deduplicate
    combined_words = []
    seen = set()
    for w in sensitive_words + words:
        if w not in seen:
            seen.add(w)
            combined_words.append(w)

    all_findings: List[DirFuzzFinding] = []

    # Filter only HTTP / HTTPS services
    http_services = [
        s for s in services if s.service_name in ["http", "https", "http-alt", "http-proxy"] or s.port in [80, 443, 8080, 8443, 3000, 5000, 8000]
    ]

    if not http_services:
        log_info("Dizin taraması için açık HTTP/HTTPS servisi tespit edilmedi.")
        save_findings([], output_json, output_txt)
        return []

    log_info(f"Toplam {len(http_services)} HTTP/HTTPS servisi taranacak.")

    for svc in http_services:
        proto = "https" if svc.ssl_enabled or svc.port in [443, 8443] else "http"
        base_url = f"{proto}://{svc.ip}:{svc.port}"
        
        svc_findings = await fuzz_target_service(
            base_url=base_url,
            wordlist=combined_words,
            concurrency=concurrency,
            delay_ms=delay_ms
        )
        all_findings.extend(svc_findings)

    save_findings(all_findings, output_json, output_txt)
    log_info(f"Dizin Taraması tamamlandı: {len(all_findings)} bulgu kaydedildi ({output_json} & {output_txt}).")
    log_audit("DIR_FUZZ_COMPLETE", "all", f"total_findings={len(all_findings)}")

    return all_findings
