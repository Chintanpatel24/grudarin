from __future__ import annotations

import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sanitize_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("._") or "grudarin_report"


def ensure_directory(path: str | os.PathLike[str]) -> Path:
    directory = Path(path).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _is_link_family(family: Any) -> bool:
    text = str(family)
    return "AF_LINK" in text or "AF_PACKET" in text or text == "-1"


def discover_interfaces() -> list[dict[str, Any]]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    interfaces: list[dict[str, Any]] = []

    for name, addr_list in addrs.items():
        stat = stats.get(name)
        item: dict[str, Any] = {
            "name": name,
            "is_up": bool(stat.isup) if stat else False,
            "speed_mbps": getattr(stat, "speed", 0) if stat else 0,
            "mtu": getattr(stat, "mtu", 0) if stat else 0,
            "mac": "",
            "ips": [],
        }

        for addr in addr_list:
            if _is_link_family(addr.family):
                if addr.address and addr.address != "00:00:00:00:00:00":
                    item["mac"] = addr.address
            else:
                address = getattr(addr, "address", "")
                if address:
                    item["ips"].append(address)

        item["ips"] = sorted(dict.fromkeys(item["ips"]))
        interfaces.append(item)

    interfaces.sort(key=lambda value: value["name"].lower())
    return interfaces


def get_interface_details(name: str) -> dict[str, Any] | None:
    for item in discover_interfaces():
        if item["name"] == name:
            return item
    return None


def local_identity_for_interface(name: str) -> dict[str, set[str]]:
    details = get_interface_details(name) or {}
    macs = {details.get("mac", "")} if details.get("mac") else set()
    ips = set(details.get("ips", []))
    return {"macs": macs, "ips": ips}


def compact_label(device: dict[str, Any]) -> str:
    if device.get("display_name"):
        return str(device["display_name"])
    if device.get("names"):
        return str(device["names"][0])
    if device.get("ips"):
        return str(device["ips"][0])
    if device.get("mac"):
        return str(device["mac"])
    return str(device.get("id", "unknown"))


def resolve_report_name(base_name: str, output_dir: Path) -> Path:
    candidate = output_dir / f"{sanitize_filename(base_name)}.md"
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    index = 1
    while True:
        numbered = output_dir / f"{stem}_{index}{suffix}"
        if not numbered.exists():
            return numbered
        index += 1


def safe_lookup_host(ip_address: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        return host
    except Exception:
        return None
