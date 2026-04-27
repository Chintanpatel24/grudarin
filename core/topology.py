"""
grudarin.core.topology
Manages the live network topology graph.
Nodes = devices. Edges = observed communication links.
Thread-safe for concurrent read/write from capture and GUI threads.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


@dataclass
class Device:
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    node_type: str = "host"          # gateway, host, unknown
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    open_ports: List[int] = field(default_factory=list)
    protocols_seen: Set[str] = field(default_factory=set)
    tags: List[str] = field(default_factory=list)

    def update_seen(self):
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "node_type": self.node_type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "protocols_seen": list(self.protocols_seen),
            "tags": self.tags,
        }


@dataclass
class Link:
    src_mac: str
    dst_mac: str
    protocol: str = "unknown"
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def key(self) -> Tuple[str, str]:
        # Normalize: always put smaller MAC first for undirected dedup
        a, b = sorted([self.src_mac, self.dst_mac])
        return (a, b)

    def to_dict(self) -> dict:
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class TopologyGraph:
    """
    Thread-safe graph of devices and links discovered on the network.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._devices: Dict[str, Device] = {}   # keyed by MAC
        self._ip_to_mac: Dict[str, str] = {}    # fast reverse lookup
        self._links: Dict[Tuple[str, str], Link] = {}
        self._change_callbacks = []
        self._gateway_mac: Optional[str] = None

    def add_change_callback(self, fn):
        self._change_callbacks.append(fn)

    def _notify_change(self, event: str, data: dict):
        for cb in self._change_callbacks:
            try:
                cb(event, data)
            except Exception:
                pass

    # ---- Device management ----

    def upsert_device(self, mac: str, ip: str = "", hostname: str = "",
                      vendor: str = "", os_guess: str = "", node_type: str = "host") -> Device:
        with self._lock:
            if mac in self._devices:
                dev = self._devices[mac]
                dev.update_seen()
                changed = False
                if ip and dev.ip != ip:
                    dev.ip = ip
                    changed = True
                if hostname and dev.hostname in ("", ip):
                    dev.hostname = hostname
                    changed = True
                if vendor and not dev.vendor:
                    dev.vendor = vendor
                if os_guess and not dev.os_guess:
                    dev.os_guess = os_guess
                if node_type != "host" and dev.node_type == "host":
                    dev.node_type = node_type
                if ip:
                    self._ip_to_mac[ip] = mac
                return dev
            else:
                dev = Device(
                    mac=mac,
                    ip=ip,
                    hostname=hostname or ip,
                    vendor=vendor,
                    os_guess=os_guess,
                    node_type=node_type,
                )
                self._devices[mac] = dev
                if ip:
                    self._ip_to_mac[ip] = mac
                self._notify_change("device_added", dev.to_dict())
                return dev

    def get_device_by_mac(self, mac: str) -> Optional[Device]:
        with self._lock:
            return self._devices.get(mac)

    def get_device_by_ip(self, ip: str) -> Optional[Device]:
        with self._lock:
            mac = self._ip_to_mac.get(ip)
            if mac:
                return self._devices.get(mac)
            return None

    def set_gateway(self, mac: str):
        with self._lock:
            self._gateway_mac = mac
            if mac in self._devices:
                self._devices[mac].node_type = "gateway"
                self._devices[mac].tags.append("gateway")

    def record_packet(self, src_mac: str, dst_mac: str, size: int, protocol: str):
        with self._lock:
            if src_mac in self._devices:
                self._devices[src_mac].packets_sent += 1
                self._devices[src_mac].bytes_sent += size
                self._devices[src_mac].protocols_seen.add(protocol)
                self._devices[src_mac].update_seen()
            if dst_mac in self._devices:
                self._devices[dst_mac].packets_received += 1
                self._devices[dst_mac].bytes_received += size
                self._devices[dst_mac].update_seen()

    # ---- Link management ----

    def upsert_link(self, src_mac: str, dst_mac: str,
                    protocol: str, size: int) -> Link:
        key = tuple(sorted([src_mac, dst_mac]))
        with self._lock:
            if key in self._links:
                link = self._links[key]
                link.packet_count += 1
                link.byte_count += size
                link.last_seen = time.time()
                if link.protocol == "unknown" and protocol != "unknown":
                    link.protocol = protocol
                return link
            else:
                link = Link(
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    protocol=protocol,
                    packet_count=1,
                    byte_count=size,
                )
                self._links[key] = link
                self._notify_change("link_added", link.to_dict())
                return link

    # ---- Snapshot for GUI rendering ----

    def snapshot(self) -> Tuple[List[Device], List[Link]]:
        with self._lock:
            devices = list(self._devices.values())
            links = list(self._links.values())
        return devices, links

    def device_count(self) -> int:
        with self._lock:
            return len(self._devices)

    def link_count(self) -> int:
        with self._lock:
            return len(self._links)

    def all_devices(self) -> List[Device]:
        with self._lock:
            return list(self._devices.values())

    def all_links(self) -> List[Link]:
        with self._lock:
            return list(self._links.values())

    def gateway_mac(self) -> Optional[str]:
        return self._gateway_mac
