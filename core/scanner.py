"""
grudarin.core.scanner
ARP-based device discovery and passive fingerprinting.
No external network calls. All operations are local only.
"""

import socket
import struct
import threading
import time
import subprocess
import platform
import re
from typing import Optional


def get_interfaces() -> list:
    """Return list of available network interface names."""
    interfaces = []
    try:
        import scapy.all as scapy
        for iface in scapy.get_if_list():
            interfaces.append(iface)
    except Exception:
        # Fallback using socket
        try:
            import netifaces
            interfaces = netifaces.interfaces()
        except Exception:
            # Last resort
            try:
                result = subprocess.run(
                    ["ip", "link", "show"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    m = re.match(r"^\d+:\s+(\S+):", line)
                    if m:
                        name = m.group(1)
                        if name != "lo":
                            interfaces.append(name)
            except Exception:
                interfaces = ["eth0", "wlan0"]
    return interfaces


def list_interfaces():
    """Print all available interfaces with basic info."""
    ifaces = get_interfaces()
    print("\n  Available network interfaces:\n")
    for iface in ifaces:
        ip = get_interface_ip(iface)
        mac = get_interface_mac(iface)
        print(f"    {iface:<15} IP: {ip:<18} MAC: {mac}")
    print()


def get_interface_ip(iface: str) -> str:
    """Get the IP address of a local interface."""
    try:
        import scapy.all as scapy
        return scapy.get_if_addr(iface) or "N/A"
    except Exception:
        pass
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]["addr"]
    except Exception:
        pass
    return "N/A"


def get_interface_mac(iface: str) -> str:
    """Get the MAC address of a local interface."""
    try:
        import scapy.all as scapy
        return scapy.get_if_hwaddr(iface) or "N/A"
    except Exception:
        pass
    try:
        path = f"/sys/class/net/{iface}/address"
        with open(path) as f:
            return f.read().strip()
    except Exception:
        pass
    return "N/A"


def get_subnet(iface: str) -> Optional[str]:
    """Determine the subnet for the interface in CIDR notation."""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            addr_info = addrs[netifaces.AF_INET][0]
            ip = addr_info["addr"]
            netmask = addr_info.get("netmask", "255.255.255.0")
            cidr = netmask_to_cidr(netmask)
            network = ip_to_network(ip, netmask)
            return f"{network}/{cidr}"
    except Exception:
        pass
    return None


def netmask_to_cidr(netmask: str) -> int:
    return sum(bin(int(x)).count("1") for x in netmask.split("."))


def ip_to_network(ip: str, netmask: str) -> str:
    ip_parts = [int(x) for x in ip.split(".")]
    mask_parts = [int(x) for x in netmask.split(".")]
    network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
    return ".".join(str(x) for x in network_parts)


def arp_scan(iface: str, subnet: str, callback) -> list:
    """
    Perform an ARP scan on the subnet.
    callback(mac, ip, hostname) is called for each discovered host.
    Returns list of (mac, ip, hostname) tuples.
    """
    results = []
    try:
        import scapy.all as scapy
        answered, _ = scapy.arping(subnet, iface=iface, timeout=2, verbose=False)
        for sent, received in answered:
            mac = received.hwsrc
            ip = received.psrc
            hostname = resolve_hostname(ip)
            results.append((mac, ip, hostname))
            callback(mac, ip, hostname)
    except Exception as e:
        print(f"[grudarin] ARP scan error: {e}")
    return results


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup with timeout."""
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return ip


def passive_os_fingerprint(ttl: int, window: int) -> str:
    """
    Rough OS fingerprinting from TTL and TCP window size.
    This is passive and heuristic only.
    """
    if ttl >= 128 and ttl <= 132:
        if window == 65535:
            return "Windows (likely)"
        return "Windows"
    if ttl >= 64 and ttl <= 68:
        if window in (5840, 29200, 65535):
            return "Linux"
        return "Linux/macOS"
    if ttl >= 254:
        return "Cisco/Network Device"
    if ttl >= 200:
        return "Solaris/AIX"
    return "Unknown"


def get_vendor_from_mac(mac: str) -> str:
    """
    Look up vendor from MAC OUI prefix.
    Uses a small embedded table for common vendors.
    For a full database, users can add manuf file from Wireshark.
    """
    oui_table = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:1A:11": "Google",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "E4:5F:01": "Raspberry Pi Foundation",
        "00:1B:63": "Apple",
        "00:23:DF": "Apple",
        "3C:15:C2": "Apple",
        "A4:5E:60": "Apple",
        "00:1A:2B": "Cisco",
        "00:00:0C": "Cisco",
        "70:F3:95": "Cisco",
        "00:1D:70": "Netgear",
        "C0:FF:D4": "TP-Link",
        "50:C7:BF": "TP-Link",
        "18:D6:C7": "TP-Link",
        "00:90:F5": "D-Link",
        "1C:BD:B9": "D-Link",
        "18:31:BF": "Xiaomi",
        "00:EC:0A": "Xiaomi",
        "28:6C:07": "Samsung",
        "54:88:0E": "Samsung",
        "AC:37:43": "HTC",
        "98:01:A7": "Google (Pixel)",
        "00:15:5D": "Microsoft Hyper-V",
        "00:03:FF": "Microsoft",
    }

    mac_upper = mac.upper()
    prefix = ":".join(mac_upper.split(":")[:3])
    return oui_table.get(prefix, "Unknown Vendor")


class ContinuousARPScanner:
    """Runs ARP scans repeatedly in a background thread."""

    def __init__(self, iface: str, interval: int = 30):
        self.iface = iface
        self.interval = interval
        self.running = False
        self.thread = None
        self.callbacks = []
        self.subnet = get_subnet(iface)

    def add_callback(self, fn):
        self.callbacks.append(fn)

    def start(self):
        if self.subnet is None:
            print(f"[grudarin] Could not determine subnet for {self.iface}, skipping ARP scans")
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _run(self):
        while self.running:
            def notify(mac, ip, hostname):
                for cb in self.callbacks:
                    cb(mac, ip, hostname)
            arp_scan(self.iface, self.subnet, notify)
            time.sleep(self.interval)
