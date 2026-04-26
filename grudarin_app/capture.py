from __future__ import annotations

import ipaddress
import threading
import time
from collections import Counter
from typing import Any, Callable

from scapy.all import ARP, AsyncSniffer, DNS, Ether, IP, IPv6, TCP, UDP  # type: ignore

from .helpers import local_identity_for_interface, utc_now_iso


KNOWN_PORTS: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NETBIOS",
    138: "NETBIOS",
    139: "NETBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SUBMISSION",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5353: "MDNS",
    5355: "LLMNR",
    5432: "POSTGRESQL",
    5900: "VNC",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


class PacketProcessor:
    def __init__(self, interface: str, logger: Callable[[str], None] | None = None) -> None:
        self.interface = interface
        self.logger = logger or (lambda message: None)
        self.lock = threading.Lock()
        self.started_at = time.time()
        self.started_at_iso = utc_now_iso()
        identity = local_identity_for_interface(interface)
        self.local_macs = {value.lower() for value in identity["macs"] if value}
        self.local_ips = {value for value in identity["ips"] if value}

        self.packet_count = 0
        self.broadcast_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self.devices: dict[str, dict[str, Any]] = {}
        self.flows: dict[tuple[str, str], dict[str, Any]] = {}
        self.changes: list[dict[str, Any]] = []
        self.ip_to_mac: dict[str, str] = {}
        self.local_ids: set[str] = set()

    def handle_packet(self, packet: Any) -> None:
        details = self._extract_packet_details(packet)
        if not details:
            return

        now_iso = utc_now_iso()
        packet_bytes = int(getattr(packet, "wirelen", 0) or len(packet))

        with self.lock:
            self.packet_count += 1
            self.total_bytes += packet_bytes
            self.protocol_counts[details["protocol"]] += 1
            if details["broadcast"]:
                self.broadcast_packets += 1

            self._register_device(
                node_id=details["src_id"],
                mac=details["src_mac"],
                ip_address=details["src_ip"],
                timestamp=now_iso,
                packet_bytes=packet_bytes,
            )
            self._register_device(
                node_id=details["dst_id"],
                mac=details["dst_mac"],
                ip_address=details["dst_ip"],
                timestamp=now_iso,
                packet_bytes=packet_bytes,
            )

            if details["service_port"] is not None and details["service_owner"] is not None:
                owner_id = details["src_id"] if details["service_owner"] == "src" else details["dst_id"]
                self._register_service(owner_id, details["service_port"], details["service_label"], now_iso)

            flow_key = tuple(sorted((details["src_id"], details["dst_id"])))
            flow = self.flows.get(flow_key)
            if flow is None:
                flow = {
                    "src_id": flow_key[0],
                    "dst_id": flow_key[1],
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "packets": 0,
                    "bytes": 0,
                    "protocols": Counter(),
                    "services": set(),
                    "recent_ports": set(),
                }
                self.flows[flow_key] = flow
                self._record_change(
                    code="NEW_FLOW",
                    severity="info",
                    message=(
                        f"New conversation observed between {details['src_id']} and {details['dst_id']} "
                        f"using {details['protocol']}"
                    ),
                )

            flow["last_seen"] = now_iso
            flow["packets"] += 1
            flow["bytes"] += packet_bytes
            flow["protocols"][details["protocol"]] += 1
            if details["service_label"]:
                flow["services"].add(details["service_label"])
            for port_value in (details["src_port"], details["dst_port"]):
                if port_value is not None:
                    flow["recent_ports"].add(port_value)

    def _register_device(
        self,
        node_id: str,
        mac: str | None,
        ip_address: str | None,
        timestamp: str,
        packet_bytes: int,
    ) -> None:
        device = self.devices.get(node_id)
        if device is None:
            device = {
                "id": node_id,
                "mac": mac or "",
                "ips": set(),
                "names": set(),
                "service_ports": set(),
                "service_labels": set(),
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "is_local": False,
            }
            self.devices[node_id] = device
            self._record_change(
                code="NEW_DEVICE",
                severity="info",
                message=f"New device discovered: {node_id}",
            )

        device["packet_count"] += 1
        device["byte_count"] += packet_bytes
        device["last_seen"] = timestamp

        normalized_mac = (mac or "").lower()
        if normalized_mac and not device["mac"]:
            device["mac"] = normalized_mac

        if ip_address and ip_address not in device["ips"]:
            device["ips"].add(ip_address)
            self._record_change(
                code="NEW_IP",
                severity="info",
                message=f"Device {node_id} is associated with IP {ip_address}",
            )

        if ip_address and normalized_mac:
            previous_mac = self.ip_to_mac.get(ip_address)
            if previous_mac and previous_mac != normalized_mac:
                self._record_change(
                    code="IP_CONFLICT",
                    severity="high",
                    message=(
                        f"Potential IP conflict or MAC change detected for {ip_address}: "
                        f"{previous_mac} and {normalized_mac}"
                    ),
                )
            else:
                self.ip_to_mac[ip_address] = normalized_mac

        if normalized_mac in self.local_macs or (ip_address and ip_address in self.local_ips):
            device["is_local"] = True
            self.local_ids.add(node_id)

    def _register_service(self, device_id: str, port_value: int, label: str | None, timestamp: str) -> None:
        device = self.devices.get(device_id)
        if device is None:
            return

        if port_value not in device["service_ports"]:
            device["service_ports"].add(port_value)
            self._record_change(
                code="NEW_SERVICE_PORT",
                severity="info",
                message=f"Device {device_id} exposed or used service port {port_value}",
            )

        if label and label not in device["service_labels"]:
            device["service_labels"].add(label)
            self._record_change(
                code="NEW_SERVICE_LABEL",
                severity="info",
                message=f"Device {device_id} is associated with {label}",
            )

        device["last_seen"] = timestamp

    def _record_change(self, code: str, severity: str, message: str) -> None:
        entry = {
            "time": utc_now_iso(),
            "code": code,
            "severity": severity,
            "message": message,
        }
        self.changes.append(entry)
        self.logger(f"[{severity.upper()}] {message}")

    def _extract_packet_details(self, packet: Any) -> dict[str, Any] | None:
        src_mac = None
        dst_mac = None
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = "OTHER"

        if packet.haslayer(Ether):
            eth_layer = packet[Ether]
            src_mac = str(getattr(eth_layer, "src", "") or "").lower() or None
            dst_mac = str(getattr(eth_layer, "dst", "") or "").lower() or None

        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            protocol = "ARP"
            src_ip = str(getattr(arp_layer, "psrc", "") or "") or None
            dst_ip = str(getattr(arp_layer, "pdst", "") or "") or None
            src_mac = str(getattr(arp_layer, "hwsrc", src_mac or "") or "").lower() or src_mac
            dst_mac = str(getattr(arp_layer, "hwdst", dst_mac or "") or "").lower() or dst_mac
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
            protocol = "IPv6"
            src_ip = str(getattr(ip_layer, "src", "") or "") or None
            dst_ip = str(getattr(ip_layer, "dst", "") or "") or None
        elif packet.haslayer(IP):
            ip_layer = packet[IP]
            protocol = "IP"
            src_ip = str(getattr(ip_layer, "src", "") or "") or None
            dst_ip = str(getattr(ip_layer, "dst", "") or "") or None

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = int(getattr(tcp_layer, "sport", 0) or 0) or None
            dst_port = int(getattr(tcp_layer, "dport", 0) or 0) or None
            protocol = "TCP"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = int(getattr(udp_layer, "sport", 0) or 0) or None
            dst_port = int(getattr(udp_layer, "dport", 0) or 0) or None
            protocol = "UDP"

        if packet.haslayer(DNS):
            protocol = "DNS"

        if not any([src_mac, dst_mac, src_ip, dst_ip]):
            return None

        is_broadcast = self._is_broadcast(dst_mac, dst_ip)
        src_id = self._node_id(src_mac, src_ip, fallback="unknown-source")
        dst_id = "broadcast" if is_broadcast else self._node_id(dst_mac, dst_ip, fallback="unknown-destination")
        if dst_id == "broadcast":
            dst_mac = dst_mac or "ff:ff:ff:ff:ff:ff"

        service_port, service_label, service_owner = self._select_service_owner(src_port, dst_port)

        return {
            "src_id": src_id,
            "dst_id": dst_id,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "broadcast": is_broadcast,
            "service_port": service_port,
            "service_label": service_label,
            "service_owner": service_owner,
        }

    @staticmethod
    def _node_id(mac: str | None, ip_address: str | None, fallback: str) -> str:
        if mac and mac != "00:00:00:00:00:00":
            return mac.lower()
        if ip_address:
            return ip_address
        return fallback

    @staticmethod
    def _select_service_owner(
        src_port: int | None,
        dst_port: int | None,
    ) -> tuple[int | None, str | None, str | None]:
        if dst_port in KNOWN_PORTS:
            return dst_port, KNOWN_PORTS[dst_port], "dst"
        if src_port in KNOWN_PORTS:
            return src_port, KNOWN_PORTS[src_port], "src"
        if dst_port is not None and dst_port <= 1024:
            return dst_port, KNOWN_PORTS.get(dst_port, f"PORT-{dst_port}"), "dst"
        if src_port is not None and src_port <= 1024:
            return src_port, KNOWN_PORTS.get(src_port, f"PORT-{src_port}"), "src"
        return None, None, None

    @staticmethod
    def _is_broadcast(mac: str | None, ip_address: str | None) -> bool:
        if mac and mac.lower() == "ff:ff:ff:ff:ff:ff":
            return True
        if not ip_address:
            return False
        lowered = ip_address.lower()
        if lowered == "255.255.255.255":
            return True
        try:
            parsed = ipaddress.ip_address(ip_address)
            return parsed.is_multicast
        except ValueError:
            return False

    def get_snapshot(self) -> dict[str, Any]:
        with self.lock:
            devices_out: list[dict[str, Any]] = []
            for device in self.devices.values():
                ips = sorted(device["ips"])
                names = sorted(device["names"])
                display_name = self._display_name(device["id"], ips, names, device["mac"])
                devices_out.append(
                    {
                        "id": device["id"],
                        "mac": device["mac"],
                        "ips": ips,
                        "names": names,
                        "display_name": display_name,
                        "service_ports": sorted(device["service_ports"]),
                        "service_labels": sorted(device["service_labels"]),
                        "packet_count": device["packet_count"],
                        "byte_count": device["byte_count"],
                        "first_seen": device["first_seen"],
                        "last_seen": device["last_seen"],
                        "is_local": device["is_local"],
                    }
                )

            flows_out: list[dict[str, Any]] = []
            for flow in self.flows.values():
                top_protocol = ""
                if flow["protocols"]:
                    top_protocol = flow["protocols"].most_common(1)[0][0]
                flows_out.append(
                    {
                        "src_id": flow["src_id"],
                        "dst_id": flow["dst_id"],
                        "packets": flow["packets"],
                        "bytes": flow["bytes"],
                        "first_seen": flow["first_seen"],
                        "last_seen": flow["last_seen"],
                        "protocols": dict(flow["protocols"]),
                        "services": sorted(flow["services"]),
                        "recent_ports": sorted(flow["recent_ports"]),
                        "top_protocol": top_protocol,
                    }
                )

            devices_out.sort(key=lambda item: (-item["packet_count"], item["display_name"]))
            flows_out.sort(key=lambda item: (-item["packets"], item["src_id"], item["dst_id"]))

            return {
                "interface": self.interface,
                "started_at": self.started_at_iso,
                "ended_at": utc_now_iso(),
                "duration_seconds": max(0.0, time.time() - self.started_at),
                "packet_count": self.packet_count,
                "broadcast_packets": self.broadcast_packets,
                "total_bytes": self.total_bytes,
                "protocol_counts": dict(self.protocol_counts),
                "devices": devices_out,
                "flows": flows_out,
                "changes": list(self.changes),
                "local_ids": sorted(self.local_ids),
            }

    @staticmethod
    def _display_name(device_id: str, ips: list[str], names: list[str], mac: str) -> str:
        if device_id == "broadcast":
            return "Broadcast"
        if names:
            return names[0]
        if ips:
            return ips[0]
        if mac:
            return mac
        return device_id

    def status_summary(self) -> str:
        snapshot = self.get_snapshot()
        return (
            f"packets={snapshot['packet_count']} "
            f"devices={len(snapshot['devices'])} "
            f"flows={len(snapshot['flows'])} "
            f"protocols={len(snapshot['protocol_counts'])}"
        )


class LiveCaptureSession:
    def __init__(
        self,
        interface: str,
        processor: PacketProcessor,
        promisc: bool = True,
    ) -> None:
        self.interface = interface
        self.processor = processor
        self.promisc = promisc
        self.sniffer: AsyncSniffer | None = None

    def start(self) -> None:
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            store=False,
            prn=self.processor.handle_packet,
            promisc=self.promisc,
        )
        self.sniffer.start()

    def stop(self) -> None:
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
