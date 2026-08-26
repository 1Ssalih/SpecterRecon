"""
Storage helper functions for reading and writing scan data in JSON format.
"""

import json
import os
from typing import List, Any, Dict, Optional
from pydantic import BaseModel
from core.models import HostInfo, PortInfo, ServiceDetail, VulnerabilityInfo, DirFuzzFinding, CompleteScanReport


def ensure_output_dir(output_dir: str = "output") -> str:
    """Ensure output directory exists and return absolute path."""
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def save_json(data: Any, filepath: str) -> None:
    """Save Pydantic models or standard dictionaries to JSON."""
    directory = os.path.dirname(filepath)
    if directory:
        os.makedirs(directory, exist_ok=True)
    
    with open(filepath, "w", encoding="utf-8") as f:
        if isinstance(data, BaseModel):
            f.write(data.model_dump_json(indent=2))
        elif isinstance(data, list):
            serialized_list = [
                item.model_dump() if isinstance(item, BaseModel) else item
                for item in data
            ]
            json.dump(serialized_list, f, indent=2, ensure_ascii=False)
        elif isinstance(data, dict):
            json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            f.write(str(data))


def load_json(filepath: str) -> Any:
    """Load raw JSON from file."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_hosts(hosts: List[HostInfo], filepath: str = "output/hosts.json") -> None:
    save_json(hosts, filepath)


def load_hosts(filepath: str = "output/hosts.json") -> List[HostInfo]:
    data = load_json(filepath)
    return [HostInfo(**item) for item in data] if isinstance(data, list) else []


def save_ports(ports: List[PortInfo], filepath: str = "output/ports.json") -> None:
    save_json(ports, filepath)


def load_ports(filepath: str = "output/ports.json") -> List[PortInfo]:
    data = load_json(filepath)
    return [PortInfo(**item) for item in data] if isinstance(data, list) else []


def save_services(services: List[ServiceDetail], filepath: str = "output/services.json") -> None:
    save_json(services, filepath)


def load_services(filepath: str = "output/services.json") -> List[ServiceDetail]:
    data = load_json(filepath)
    return [ServiceDetail(**item) for item in data] if isinstance(data, list) else []


def save_vulns(vulns: List[VulnerabilityInfo], filepath: str = "output/vulns.json") -> None:
    save_json(vulns, filepath)


def load_vulns(filepath: str = "output/vulns.json") -> List[VulnerabilityInfo]:
    data = load_json(filepath)
    return [VulnerabilityInfo(**item) for item in data] if isinstance(data, list) else []


def save_findings(findings: List[DirFuzzFinding], filepath_json: str = "output/dirs.json", filepath_txt: str = "output/findings.txt") -> None:
    save_json(findings, filepath_json)
    if filepath_txt:
        directory = os.path.dirname(filepath_txt)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(filepath_txt, "w", encoding="utf-8") as f:
            for item in findings:
                f.write(f"[{item.status_code}] {item.url} (size: {item.content_length} bytes)\n")
