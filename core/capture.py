"""
grudarin.core.capture
Live packet capture using Scapy. Parses each packet into topology events.
No payload logging. Only metadata: MACs, IPs, protocol, size, port, flags.
Privacy-respecting: does not capture or store payload content.
"""

import threading
import time
from typing import Optional, Callable

from core.topology import TopologyGraph
from core.scanner import get_vendor_from_mac, passive_os_fingerprint, resolve_hostname, ContinuousARPScanner


# Broadcast and multicast MAC prefixes to skip
IGNORE_MACS = {
    "ff:ff:ff:ff:ff:ff",   # Ethernet broadcast
    "01:00:5e",             # IPv4 multicast prefix
    "33:33",                # IPv6 multicast prefix
    "01:80:c2",             # STP multicast
}

PROTOCOL_MAP = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

PORT_SERVICE_MAP = {
    20:   "FTP-Data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP-Server",
    68:   "DHCP-Client",
    80:   "HTTP",
    110:  "POP3",
    123:  "NTP",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    443:  "HTTPS",
    445:  "SMB",
    514:  "Syslog",
    993:  "IMAPS",
    3389: "RDP",
    5353: "mDNS",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
}


def is_broadcast_or_multicast(mac: str) -> bool:
    mac_lower = mac.lower()
    if mac_lower == "ff:ff:ff:ff:ff:ff":
        return True
    prefix2 = mac_lower[:5]
    prefix3 = mac_lower[:8]
    if prefix2 in ("01:00", "33:33") or prefix3 in ("01:00:5e", "01:80:c2"):
        return True
    return False


class PacketCapture:
    """
    Sniffs packets on the given interface and populates the topology graph.
    Runs in a background thread.
    """

    def __init__(self, iface: str, topology: TopologyGraph,
                 packet_callback: Optional[Callable] = None):
        self.iface = iface
        self.topology = topology
        self.packet_callback = packet_callback
        self.running = False
        self.thread = None
        self.packets_processed = 0
        self.arp_scanner = ContinuousARPScanner(iface, interval=60)
        self.arp_scanner.add_callback(self._on_arp_discover)
        self._gateway_discovered = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        self.arp_scanner.start()
        print(f"[grudarin] Capture started on {self.iface}")

    def stop(self):
        self.running = False
        self.arp_scanner.stop()
        print(f"[grudarin] Capture stopped. Packets processed: {self.packets_processed}")

    def _on_arp_discover(self, mac: str, ip: str, hostname: str):
        vendor = get_vendor_from_mac(mac)
        self.topology.upsert_device(mac=mac, ip=ip, hostname=hostname, vendor=vendor)

    def _capture_loop(self):
        try:
            import scapy.all as scapy
            scapy.sniff(
                iface=self.iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            print("[grudarin] ERROR: Packet capture requires root/administrator privileges.")
            print("           Run with: sudo python grudarin.py ...")
        except Exception as e:
            print(f"[grudarin] Capture error: {e}")

    def _process_packet(self, pkt):
        try:
            import scapy.all as scapy
            self.packets_processed += 1

            # ---- Layer 2: Ethernet ----
            if not pkt.haslayer(scapy.Ether):
                return

            src_mac = pkt[scapy.Ether].src.lower()
            dst_mac = pkt[scapy.Ether].dst.lower()
            pkt_size = len(pkt)

            # ---- ARP: discover devices ----
            if pkt.haslayer(scapy.ARP):
                self._handle_arp(pkt, src_mac)

            # ---- IP layer ----
            src_ip = ""
            dst_ip = ""
            protocol = "Ethernet"
            ttl = 0
            tcp_window = 0

            if pkt.haslayer(scapy.IP):
                src_ip = pkt[scapy.IP].src
                dst_ip = pkt[scapy.IP].dst
                proto_num = pkt[scapy.IP].proto
                protocol = PROTOCOL_MAP.get(proto_num, f"IP/{proto_num}")
                ttl = pkt[scapy.IP].ttl

            elif pkt.haslayer(scapy.IPv6):
                src_ip = pkt[scapy.IPv6].src
                dst_ip = pkt[scapy.IPv6].dst
                protocol = "IPv6"

            # ---- TCP / UDP port enrichment ----
            src_port = 0
            dst_port = 0

            if pkt.haslayer(scapy.TCP):
                src_port = pkt[scapy.TCP].sport
                dst_port = pkt[scapy.TCP].dport
                tcp_window = pkt[scapy.TCP].window
                service = PORT_SERVICE_MAP.get(dst_port) or PORT_SERVICE_MAP.get(src_port)
                if service:
                    protocol = service

            elif pkt.haslayer(scapy.UDP):
                src_port = pkt[scapy.UDP].sport
                dst_port = pkt[scapy.UDP].dport
                service = PORT_SERVICE_MAP.get(dst_port) or PORT_SERVICE_MAP.get(src_port)
                if service:
                    protocol = service

            # ---- DNS: hostname resolution ----
            if pkt.haslayer(scapy.DNSRR):
                self._handle_dns(pkt)

            # ---- DHCP: hostname extraction ----
            if pkt.haslayer(scapy.DHCP):
                self._handle_dhcp(pkt, src_mac)

            # ---- mDNS: local hostname discovery ----
            if dst_port == 5353 or src_port == 5353:
                self._handle_mdns(pkt, src_mac, src_ip)

            # ---- Skip pure broadcast/multicast for topology edges ----
            skip_edge = is_broadcast_or_multicast(dst_mac)

            # ---- Update source device ----
            if not is_broadcast_or_multicast(src_mac) and src_mac:
                vendor = get_vendor_from_mac(src_mac)
                os_guess = ""
                if ttl > 0:
                    os_guess = passive_os_fingerprint(ttl, tcp_window)
                self.topology.upsert_device(
                    mac=src_mac, ip=src_ip, vendor=vendor, os_guess=os_guess
                )
                if src_ip:
                    self.topology.record_packet(src_mac, dst_mac if not skip_edge else src_mac,
                                                pkt_size, protocol)

            # ---- Update destination device ----
            if not skip_edge and dst_mac:
                vendor = get_vendor_from_mac(dst_mac)
                self.topology.upsert_device(mac=dst_mac, ip=dst_ip, vendor=vendor)
                self.topology.upsert_link(src_mac, dst_mac, protocol, pkt_size)

            # ---- Detect gateway (usually first hop, lowest IP or DHCP server) ----
            if not self._gateway_discovered and dst_port == 67:
                # DHCP server = gateway candidate
                if not is_broadcast_or_multicast(dst_mac) and dst_mac:
                    self.topology.set_gateway(dst_mac)
                    self._gateway_discovered = True

            # ---- Notify packet listener ----
            if self.packet_callback:
                event = {
                    "time": time.time(),
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "size": pkt_size,
                    "ttl": ttl,
                }
                self.packet_callback(event)

        except Exception:
            pass  # Never crash the capture thread

    def _handle_arp(self, pkt, src_mac: str):
        import scapy.all as scapy
        arp = pkt[scapy.ARP]
        if arp.op == 2:  # ARP reply = device announcing itself
            ip = arp.psrc
            mac = arp.hwsrc.lower()
            vendor = get_vendor_from_mac(mac)
            self.topology.upsert_device(mac=mac, ip=ip, vendor=vendor)

            # Try to guess if this is the gateway (first ARP reply we see)
            if not self._gateway_discovered:
                # Very rough: if IP ends in .1 or .254 it is likely the gateway
                last_octet = int(ip.split(".")[-1]) if ip else 0
                if last_octet in (1, 254):
                    self.topology.set_gateway(mac)
                    self._gateway_discovered = True

    def _handle_dns(self, pkt):
        import scapy.all as scapy
        try:
            layer = pkt[scapy.DNSRR]
            while layer:
                if layer.type == 1:  # A record
                    ip = layer.rdata
                    name = layer.rrname.decode().rstrip(".")
                    dev = self.topology.get_device_by_ip(ip)
                    if dev and dev.hostname in ("", ip):
                        dev.hostname = name
                layer = layer.payload if hasattr(layer, "payload") else None
                if not hasattr(layer, "type"):
                    break
        except Exception:
            pass

    def _handle_dhcp(self, pkt, src_mac: str):
        import scapy.all as scapy
        try:
            options = pkt[scapy.DHCP].options
            hostname = None
            requested_ip = None
            for opt in options:
                if isinstance(opt, tuple):
                    if opt[0] == "hostname":
                        hostname = opt[1].decode() if isinstance(opt[1], bytes) else opt[1]
                    if opt[0] == "requested_addr":
                        requested_ip = opt[1]
            if hostname and src_mac:
                dev = self.topology.get_device_by_mac(src_mac)
                if dev and dev.hostname in ("", dev.ip):
                    dev.hostname = hostname
        except Exception:
            pass

    def _handle_mdns(self, pkt, src_mac: str, src_ip: str):
        import scapy.all as scapy
        try:
            if pkt.haslayer(scapy.DNSQR):
                qname = pkt[scapy.DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode().rstrip(".")
                # .local names are mDNS hostnames
                if qname.endswith(".local") and src_mac:
                    dev = self.topology.get_device_by_mac(src_mac)
                    if dev and dev.hostname in ("", src_ip):
                        dev.hostname = qname
        except Exception:
            pass


def start_headless(iface: str, output_dir: str, duration: int):
    """Run capture with no GUI, just logging."""
    from core.topology import TopologyGraph
    from core.logger import SessionLogger

    topology = TopologyGraph()
    logger = SessionLogger(output_dir, iface)

    def on_packet(event):
        logger.log_packet(event)

    def on_topology_change(event_type, data):
        logger.log_topology_event(event_type, data)

    topology.add_change_callback(on_topology_change)

    capture = PacketCapture(iface, topology, on_packet)
    capture.start()
    logger.start()

    try:
        if duration > 0:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[grudarin] Stopping...")
    finally:
        capture.stop()
        logger.stop(topology)
        print(f"[grudarin] Session saved to: {output_dir}")
