from __future__ import annotations

from typing import Any


INSECURE_PORTS = {
    21: "FTP",
    23: "TELNET",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
}

NOISY_DISCOVERY_PORTS = {
    5353: "mDNS",
    5355: "LLMNR",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
}


def generate_findings(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    packet_count = max(1, int(snapshot.get("packet_count", 0)))
    devices = snapshot.get("devices", [])
    changes = snapshot.get("changes", [])
    protocol_counts = snapshot.get("protocol_counts", {})
    broadcast_ratio = float(snapshot.get("broadcast_packets", 0)) / float(packet_count)

    insecure_hits: list[str] = []
    for device in devices:
        labels = set(device.get("service_labels", []))
        ports = set(device.get("service_ports", []))
        for port_value, label in INSECURE_PORTS.items():
            if port_value in ports or label in labels:
                insecure_hits.append(f"{device.get('display_name', device.get('id', 'unknown'))} uses {label} ({port_value})")

    if insecure_hits:
        findings.append(
            {
                "severity": "high",
                "title": "Unencrypted or legacy application protocols observed",
                "detail": "; ".join(insecure_hits[:10]),
            }
        )

    if any(change.get("code") == "IP_CONFLICT" for change in changes):
        findings.append(
            {
                "severity": "high",
                "title": "Potential IP conflict or MAC reassignment observed",
                "detail": "Multiple MAC addresses were observed for the same IP address during capture. Validate DHCP reservations, static assignments, and ARP stability.",
            }
        )

    if broadcast_ratio >= 0.25 and packet_count >= 100:
        findings.append(
            {
                "severity": "medium",
                "title": "High broadcast or multicast ratio detected",
                "detail": f"Broadcast or multicast traffic represented {broadcast_ratio:.1%} of captured traffic. Investigate discovery storms, loops, and chatty service announcements.",
            }
        )

    arp_count = int(protocol_counts.get("ARP", 0))
    if arp_count >= max(40, packet_count // 3):
        findings.append(
            {
                "severity": "medium",
                "title": "Heavy ARP activity detected",
                "detail": f"ARP frames accounted for {arp_count} packets. Review ARP churn, duplicate addressing, and switch behavior if this persists.",
            }
        )

    noisy_devices: list[str] = []
    for device in devices:
        ports = set(device.get("service_ports", []))
        hits = [name for value, name in NOISY_DISCOVERY_PORTS.items() if value in ports]
        if hits:
            noisy_devices.append(f"{device.get('display_name', device.get('id', 'unknown'))}: {', '.join(hits)}")

    if noisy_devices:
        findings.append(
            {
                "severity": "low",
                "title": "Discovery-heavy services present on the network",
                "detail": "; ".join(noisy_devices[:10]),
            }
        )

    wide_service_exposure: list[str] = []
    for device in devices:
        ports = list(device.get("service_ports", []))
        if len(ports) >= 10:
            wide_service_exposure.append(
                f"{device.get('display_name', device.get('id', 'unknown'))} exposed or used {len(ports)} distinct service ports"
            )

    if wide_service_exposure:
        findings.append(
            {
                "severity": "medium",
                "title": "Hosts with broad service exposure or activity observed",
                "detail": "; ".join(wide_service_exposure[:10]),
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "info",
                "title": "No major passive hygiene issues stood out in this capture",
                "detail": "This is an observational result only. Passive monitoring cannot confirm absence of risk.",
            }
        )

    return findings
