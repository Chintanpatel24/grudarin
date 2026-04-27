"""
grudarin.core.alerts
Real-time network anomaly detection.
Detects: new devices, ARP spoofing, port scans, unusual protocols,
         MAC address changes, DHCP exhaustion, excessive broadcasts.

All detection is passive and local. No external calls.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Dict, Optional
from collections import defaultdict, deque
from enum import Enum


class Severity(Enum):
    INFO = "INFO"
    WARN = "WARN"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    severity: Severity
    title: str
    detail: str
    mac: str = ""
    ip: str = ""
    timestamp: float = field(default_factory=time.time)
    rule: str = ""

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] {self.severity.value:8} {self.title} - {self.detail}"


class AlertEngine:
    """
    Monitors topology and packet events for anomalies.
    Thread-safe. Calls registered callbacks when alerts are raised.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[Alert], None]] = []
        self._alerts: List[Alert] = []

        # State for each detection rule
        self._known_macs: set = set()
        self._mac_to_ip: Dict[str, str] = {}            # last known MAC->IP mapping
        self._ip_to_mac: Dict[str, str] = {}            # last known IP->MAC mapping (for ARP spoof)

        # Port scan detection: track SYN packets per source
        self._syn_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._syn_dst_ports: Dict[str, set] = defaultdict(set)

        # Broadcast storm detection
        self._broadcast_counter: deque = deque(maxlen=1000)

        # DHCP exhaustion
        self._dhcp_discovers: deque = deque(maxlen=500)

        # Recently alerted to avoid duplicates
        self._alerted_keys: Dict[str, float] = {}
        self._alert_cooldown = 60.0  # seconds between same alert type per host

    def add_callback(self, fn: Callable[[Alert], None]):
        self._callbacks.append(fn)

    def get_alerts(self) -> List[Alert]:
        with self._lock:
            return list(self._alerts)

    def _raise(self, alert: Alert):
        # Deduplicate: same rule+mac within cooldown window
        key = f"{alert.rule}:{alert.mac}"
        now = time.time()
        with self._lock:
            last = self._alerted_keys.get(key, 0)
            if now - last < self._alert_cooldown:
                return
            self._alerted_keys[key] = now
            self._alerts.append(alert)
            # Keep last 500 alerts in memory
            if len(self._alerts) > 500:
                self._alerts.pop(0)

        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    # ---- Topology event handlers ----

    def on_device_added(self, mac: str, ip: str, vendor: str):
        """Called when a new device appears on the network."""
        with self._lock:
            is_new = mac not in self._known_macs
            self._known_macs.add(mac)
            if ip:
                self._mac_to_ip[mac] = ip
                self._ip_to_mac[ip] = mac

        if is_new:
            self._raise(Alert(
                severity=Severity.INFO,
                title="New Device",
                detail=f"MAC {mac} | IP {ip or 'unknown'} | Vendor: {vendor or 'unknown'}",
                mac=mac,
                ip=ip,
                rule="new_device",
            ))

    def on_ip_change(self, mac: str, old_ip: str, new_ip: str):
        """Called when a device changes its IP address."""
        self._raise(Alert(
            severity=Severity.WARN,
            title="IP Address Change",
            detail=f"MAC {mac} changed IP: {old_ip} -> {new_ip}",
            mac=mac,
            ip=new_ip,
            rule="ip_change",
        ))

    def on_mac_change(self, ip: str, old_mac: str, new_mac: str):
        """Called when an IP's MAC changes - possible ARP spoofing."""
        self._raise(Alert(
            severity=Severity.CRITICAL,
            title="Possible ARP Spoofing",
            detail=(
                f"IP {ip} was answered by {old_mac} "
                f"and is now answered by {new_mac}. "
                f"This may indicate ARP cache poisoning."
            ),
            mac=new_mac,
            ip=ip,
            rule="arp_spoof",
        ))

    # ---- Packet event handlers ----

    def on_packet(self, event: dict):
        """Process a raw packet event for anomaly detection."""
        proto = event.get("protocol", "")
        src_mac = event.get("src_mac", "")
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dst_port", 0)
        src_port = event.get("src_port", 0)
        flags = event.get("tcp_flags", 0)
        now = time.time()

        # ARP consistency check (MAC-IP binding)
        if src_mac and src_ip:
            with self._lock:
                old_mac = self._ip_to_mac.get(src_ip)
                old_ip = self._mac_to_ip.get(src_mac)

            if old_mac and old_mac != src_mac and not self._is_multicast(src_mac):
                self.on_mac_change(src_ip, old_mac, src_mac)
                with self._lock:
                    self._ip_to_mac[src_ip] = src_mac

            if old_ip and old_ip != src_ip:
                self.on_ip_change(src_mac, old_ip, src_ip)
                with self._lock:
                    self._mac_to_ip[src_mac] = src_ip

        # Port scan detection: many destination ports from one source in short window
        if proto in ("TCP", "SYN") and dst_port > 0 and src_ip:
            self._syn_tracker[src_ip].append(now)
            self._syn_dst_ports[src_ip].add(dst_port)

            # Look at packets in the last 10 seconds
            window_start = now - 10.0
            recent = [t for t in self._syn_tracker[src_ip] if t > window_start]
            recent_ports = len(self._syn_dst_ports[src_ip])

            if len(recent) >= 20 and recent_ports >= 15:
                self._raise(Alert(
                    severity=Severity.ALERT,
                    title="Port Scan Detected",
                    detail=(
                        f"{src_ip} sent {len(recent)} packets to {recent_ports} "
                        f"unique ports in 10s. Possible port scan."
                    ),
                    mac=src_mac,
                    ip=src_ip,
                    rule="port_scan",
                ))
                # Reset after alerting
                with self._lock:
                    self._syn_dst_ports[src_ip].clear()

        # Broadcast storm detection
        dst_mac = event.get("dst_mac", "")
        if dst_mac == "ff:ff:ff:ff:ff:ff":
            self._broadcast_counter.append(now)
            window_start = now - 1.0
            recent_broadcasts = sum(1 for t in self._broadcast_counter if t > window_start)
            if recent_broadcasts >= 100:
                self._raise(Alert(
                    severity=Severity.WARN,
                    title="Broadcast Storm",
                    detail=f"{recent_broadcasts} broadcast packets/sec detected. Network may be unstable.",
                    mac="ff:ff:ff:ff:ff:ff",
                    rule="broadcast_storm",
                ))

        # Telnet detection (cleartext credentials risk)
        if dst_port == 23 or src_port == 23:
            self._raise(Alert(
                severity=Severity.WARN,
                title="Telnet Traffic",
                detail=f"Telnet (cleartext) detected: {src_ip} -> {dst_ip}. Consider using SSH.",
                mac=src_mac,
                ip=src_ip,
                rule="telnet",
            ))

        # DHCP exhaustion: many DISCOVER messages in short time
        if proto == "DHCP-Server" or dst_port == 67:
            self._dhcp_discovers.append(now)
            window_start = now - 5.0
            recent_dhcp = sum(1 for t in self._dhcp_discovers if t > window_start)
            if recent_dhcp >= 30:
                self._raise(Alert(
                    severity=Severity.ALERT,
                    title="DHCP Exhaustion Attempt",
                    detail=f"{recent_dhcp} DHCP requests in 5 seconds. Possible DHCP starvation attack.",
                    mac=src_mac,
                    rule="dhcp_exhaustion",
                ))

        # Suspicious outbound ports
        suspicious_ports = {4444, 31337, 1337, 12345, 54321, 6667, 6697}
        if dst_port in suspicious_ports or src_port in suspicious_ports:
            port = dst_port if dst_port in suspicious_ports else src_port
            self._raise(Alert(
                severity=Severity.ALERT,
                title="Suspicious Port Activity",
                detail=(
                    f"Traffic on port {port} from {src_ip} -> {dst_ip}. "
                    f"Associated with malware/backdoor activity."
                ),
                mac=src_mac,
                ip=src_ip,
                rule="suspicious_port",
            ))

    def _is_multicast(self, mac: str) -> bool:
        if not mac:
            return False
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x01)

    def clear(self):
        with self._lock:
            self._alerts.clear()
            self._alerted_keys.clear()
