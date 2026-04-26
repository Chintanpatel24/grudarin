from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .helpers import ensure_directory, format_duration, resolve_report_name


SEVERITY_STYLES = {
    "high": "color:red;font-size:1.15em;font-weight:bold;",
    "medium": "color:#b45309;font-size:1.05em;font-weight:bold;",
    "low": "color:#1d4ed8;font-weight:bold;",
    "info": "font-weight:bold;",
}


def write_markdown_report(
    snapshot: dict[str, Any],
    findings: list[dict[str, str]],
    output_dir: str,
    report_name: str,
) -> Path:
    directory = ensure_directory(output_dir)
    report_path = resolve_report_name(report_name, directory)
    report_text = build_markdown(snapshot, findings, report_path.stem)
    report_path.write_text(report_text, encoding="utf-8")
    return report_path


def build_markdown(snapshot: dict[str, Any], findings: list[dict[str, str]], title: str) -> str:
    devices = snapshot.get("devices", [])
    flows = snapshot.get("flows", [])
    protocol_counts = snapshot.get("protocol_counts", {})
    changes = snapshot.get("changes", [])
    total_bytes = int(snapshot.get("total_bytes", 0))

    lines: list[str] = []
    lines.append(f"# {escape(title)}")
    lines.append("")
    lines.append("> Grudarin passive network observability report")
    lines.append("")
    lines.append("## Capture metadata")
    lines.append("")
    lines.append(f"- Interface: `{escape(str(snapshot.get('interface', 'unknown')))}`")
    lines.append(f"- Started: `{escape(str(snapshot.get('started_at', 'unknown')))}`")
    lines.append(f"- Ended: `{escape(str(snapshot.get('ended_at', 'unknown')))}`")
    lines.append(f"- Duration: `{format_duration(float(snapshot.get('duration_seconds', 0)))}`")
    lines.append(f"- Packets captured: `{int(snapshot.get('packet_count', 0))}`")
    lines.append(f"- Broadcast or multicast packets: `{int(snapshot.get('broadcast_packets', 0))}`")
    lines.append(f"- Total bytes observed: `{total_bytes}`")
    lines.append(f"- Devices observed: `{len(devices)}`")
    lines.append(f"- Conversations observed: `{len(flows)}`")
    lines.append("")

    lines.append("## Protocol summary")
    lines.append("")
    if protocol_counts:
        lines.append("| Protocol | Count |")
        lines.append("|---|---:|")
        for name, count in sorted(protocol_counts.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"| {escape(str(name))} | {int(count)} |")
    else:
        lines.append("No protocol data was collected.")
    lines.append("")

    lines.append("## Devices")
    lines.append("")
    if devices:
        lines.append("| Display name | MAC | IPs | Service ports | Packets | Bytes | Local |")
        lines.append("|---|---|---|---|---:|---:|---|")
        for device in devices:
            ports = ", ".join(str(value) for value in device.get("service_ports", [])) or "-"
            ips = ", ".join(device.get("ips", [])) or "-"
            mac = device.get("mac") or "-"
            local_text = "yes" if device.get("is_local") else "no"
            lines.append(
                f"| {escape(str(device.get('display_name', device.get('id', 'unknown'))))} "
                f"| {escape(str(mac))} "
                f"| {escape(ips)} "
                f"| {escape(ports)} "
                f"| {int(device.get('packet_count', 0))} "
                f"| {int(device.get('byte_count', 0))} "
                f"| {local_text} |"
            )
    else:
        lines.append("No devices were observed.")
    lines.append("")

    lines.append("## Top conversations")
    lines.append("")
    if flows:
        device_lookup = {device.get("id"): device.get("display_name", device.get("id")) for device in devices}
        lines.append("| Source | Destination | Protocols | Services | Packets | Bytes | Last seen |")
        lines.append("|---|---|---|---|---:|---:|---|")
        for flow in flows[:30]:
            protocols = ", ".join(sorted(flow.get("protocols", {}).keys())) or "-"
            services = ", ".join(flow.get("services", [])) or "-"
            src_label = device_lookup.get(flow.get("src_id"), flow.get("src_id"))
            dst_label = device_lookup.get(flow.get("dst_id"), flow.get("dst_id"))
            lines.append(
                f"| {escape(str(src_label))} "
                f"| {escape(str(dst_label))} "
                f"| {escape(protocols)} "
                f"| {escape(services)} "
                f"| {int(flow.get('packets', 0))} "
                f"| {int(flow.get('bytes', 0))} "
                f"| {escape(str(flow.get('last_seen', '')))} |"
            )
    else:
        lines.append("No conversations were recorded.")
    lines.append("")

    lines.append("## Network changes observed during capture")
    lines.append("")
    if changes:
        for change in changes[:200]:
            severity = str(change.get("severity", "info")).upper()
            time_value = escape(str(change.get("time", "")))
            message = escape(str(change.get("message", "")))
            lines.append(f"- [{severity}] `{time_value}` {message}")
    else:
        lines.append("No notable changes were recorded.")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["info"])
        title_html = escape(str(finding.get("title", "Untitled finding")))
        detail_html = escape(str(finding.get("detail", "")))
        lines.append(f"<div style=\"{style}\">{severity.upper()} - {title_html}</div>")
        if detail_html:
            lines.append("")
            lines.append(detail_html)
        lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append("This report is based on passive observation from the selected local interface. It does not perform active scanning, exploitation, password attacks, or intrusive validation.")
    lines.append("")
    return "\n".join(lines)


def escape(value: str) -> str:
    return html.escape(value, quote=False)
