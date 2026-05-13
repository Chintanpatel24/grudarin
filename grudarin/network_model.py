"""
Grudarin - Network Model with per-device behavioral tracking.
Tracks real behavioral data from packet inspection:
  - Websites visited (HTTP host + path, TLS SNI, DNS queries)
  - Search queries (Google, etc.)
  - Connection duration per device
  - App/service identification
"""
import threading
import time
from collections import defaultdict
from datetime import datetime


class Device:
    """Represents a discovered network device with behavioral tracking."""

    def __init__(self, mac=None, ip=None):
        self.mac = mac or "unknown"
        self.ip = ip or "unknown"
        self.ips = set()
        if ip and ip != "unknown":
            self.ips.add(ip)
        self.hostname = ""
        self.vendor = ""
        self.os_hint = ""
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.is_gateway = False

        # Behavioral tracking
        self.websites = {}       # hostname -> first_seen, last_seen, count
        self.searches = []       # (timestamp, query)
        self.dns_queries = []    # (timestamp, domain)
        self.connections = []    # (timestamp, dst_ip, dst_port, proto)
        self.active_since = time.time()
        self.total_active_time = 0.0
        self.last_activity = time.time()

    def record_website(self, hostname):
        now = time.time()
        if hostname not in self.websites:
            self.websites[hostname] = {"first": now, "last": now, "count": 1}
        else:
            self.websites[hostname]["last"] = now
            self.websites[hostname]["count"] += 1

    def record_search(self, query):
        self.searches.append((time.time(), query))
        if len(self.searches) > 200:
            self.searches = self.searches[-200:]

    def record_dns(self, domain):
        self.dns_queries.append((time.time(), domain))
        if len(self.dns_queries) > 500:
            self.dns_queries = self.dns_queries[-500:]

    def record_connection(self, dst_ip, dst_port, proto):
        self.connections.append((time.time(), dst_ip, dst_port, proto))
        if len(self.connections) > 500:
            self.connections = self.connections[-500:]

    def get_active_duration(self):
        if self.last_activity > self.active_since:
            return self.last_activity - self.active_since
        return 0

    def get_current_site(self):
        if not self.websites:
            return ""
        return max(self.websites, key=lambda h: self.websites[h]["last"])

    def is_active(self, threshold=30):
        return (time.time() - self.last_activity) < threshold

    def to_dict(self):
        return {
            "mac": self.mac, "ip": self.ip, "all_ips": list(self.ips),
            "hostname": self.hostname, "vendor": self.vendor,
            "os_hint": self.os_hint,
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent, "bytes_received": self.bytes_received,
            "is_gateway": self.is_gateway,
            "websites": {k: v for k, v in sorted(self.websites.items(),
                        key=lambda x: x[1]["count"], reverse=True)[:50]},
            "searches": [{"time": datetime.fromtimestamp(t).isoformat(), "q": q}
                        for t, q in self.searches[-20:]],
            "active_duration": self.get_active_duration(),
        }

    def get_label(self):
        if self.hostname:
            return self.hostname
        if self.ip and self.ip != "unknown":
            return self.ip
        return self.mac[:11] if self.mac else "?"


class Connection:
    """Represents a connection between two devices."""

    def __init__(self, src_key, dst_key):
        self.src_key = src_key
        self.dst_key = dst_key
        self.packet_count = 0
        self.byte_count = 0
        self.protocols = set()
        self.ports = set()
        self.first_seen = time.time()
        self.last_seen = time.time()

    def to_dict(self):
        return {
            "source": self.src_key, "destination": self.dst_key,
            "packet_count": self.packet_count, "byte_count": self.byte_count,
            "protocols": sorted(list(self.protocols)),
            "ports": sorted(list(self.ports)),
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
        }


class PacketRecord:
    """Stores metadata about a captured packet."""

    def __init__(self):
        self.timestamp = 0.0
        self.src_mac = ""
        self.dst_mac = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.protocol = ""
        self.src_port = 0
        self.dst_port = 0
        self.length = 0
        self.info = ""
        self.ttl = 0
        self.flags = ""
        self.activity = ""

    def to_dict(self):
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "src_mac": self.src_mac, "dst_mac": self.dst_mac,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "protocol": self.protocol, "src_port": self.src_port,
            "dst_port": self.dst_port, "length": self.length,
            "info": self.info, "ttl": self.ttl,
            "flags": self.flags, "activity": self.activity,
        }


class NetworkModel:
    """
    Thread-safe model with per-device behavioral tracking.
    All data comes from real packet inspection, never random/fake.
    """

    OUI_VENDORS = {
        "00:50:56": "VMware", "00:0c:29": "VMware",
        "00:1a:11": "Google", "00:1e:65": "Intel",
        "3c:22:fb": "Apple", "ac:de:48": "Apple",
        "f8:ff:c2": "Apple", "a4:83:e7": "Apple",
        "00:25:00": "Apple", "d8:bb:c1": "Apple",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi", "00:15:5d": "Microsoft Hyper-V",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
        "00:1a:2b": "Cisco", "00:1b:44": "Cisco",
        "00:24:d7": "Intel", "00:26:c6": "Intel",
        "3c:97:0e": "Intel", "4c:eb:42": "Intel",
        "00:e0:4c": "Realtek", "00:0a:cd": "Realtek",
        "48:5b:39": "ASUSTek", "1c:87:2c": "ASUSTek",
        "00:23:cd": "TP-Link", "30:b5:c2": "TP-Link",
        "50:c7:bf": "TP-Link", "c0:25:e9": "TP-Link",
        "00:1f:1f": "D-Link", "28:10:7b": "D-Link",
        "f0:9f:c2": "Ubiquiti", "24:a4:3c": "Ubiquiti",
        "68:d7:9a": "Ubiquiti", "44:d9:e7": "Ubiquiti",
        "fc:15:b4": "HP", "9c:b6:d0": "HP",
        "00:17:a4": "Samsung", "a8:f2:74": "Samsung",
        "c0:97:27": "Samsung", "b0:83:fe": "Dell",
        "18:a9:9b": "Dell",
    }

    TTL_OS_HINTS = {
        64: "Linux/macOS/Unix", 128: "Windows",
        255: "Cisco/Network Device", 254: "Solaris/AIX",
    }

    def __init__(self):
        self.lock = threading.Lock()
        self.devices = {}
        self.connections = {}
        self.packet_log = []
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.protocol_counts = defaultdict(int)
        self.dns_cache = {}
        self.activity_log = []
        self._max_packet_log = 30000
        self._max_activity_log = 2000

    def _device_key(self, mac, ip):
        if mac and mac != "unknown" and mac != "ff:ff:ff:ff:ff:ff":
            return mac.lower()
        if ip and ip != "unknown":
            return ip
        return mac.lower() if mac else "unknown"

    def _get_or_create_device(self, mac, ip):
        key = self._device_key(mac, ip)
        if key not in self.devices:
            dev = Device(mac=mac, ip=ip)
            dev.vendor = self._lookup_vendor(mac)
            dev.is_gateway = self._is_likely_gateway(ip)
            self.devices[key] = dev
        return self.devices[key]

    def _lookup_vendor(self, mac):
        if not mac or mac == "unknown":
            return ""
        prefix = mac[:8].lower()
        return self.OUI_VENDORS.get(prefix, "")

    def _is_likely_gateway(self, ip):
        if ip and ip != "unknown":
            parts = ip.split(".")
            if len(parts) == 4 and parts[3] == "1":
                return True
        return False

    def _guess_os(self, ttl):
        if ttl <= 0: return ""
        nearest = min(self.TTL_OS_HINTS.keys(), key=lambda x: abs(x - ttl))
        if abs(nearest - ttl) <= 10:
            return self.TTL_OS_HINTS[nearest]
        return ""

    def ingest_from_c_engine(self, json_line):
        """Parse JSON from C capture engine and update model.
        All data is tagged with provenance: 'direct' or 'mitm' (ARP poison).
        """
        import json
        try:
            data = json.loads(json_line)
        except json.JSONDecodeError:
            return
        t = data.get("t")
        tag = data.get("tag", "direct")
        source_label = "CERTAIN" if tag == "direct" else "MITM"

        if t == "dev":
            dev = self._get_or_create_device(data.get("mac", ""), data.get("ip", ""))
            dev.last_seen = time.time()
        elif t == "dns":
            src = data.get("src", "")
            q = data.get("q", "")
            if src and q:
                self.add_dns_mapping_info(src, q)
                self.add_activity(src, q, "dns_query", f"[{source_label}] DNS: {q}")
                dev = self._get_device_by_ip(src)
                if dev:
                    dev.record_dns(q)
                    dev.last_activity = time.time()
                    hostname = self._extract_hostname(q)
                    if hostname:
                        dev.record_website(hostname)
        elif t == "tls":
            src = data.get("src", "")
            sni = data.get("sni", "")
            if src and sni:
                self.add_activity(src, sni, "tls_sni", f"[{source_label}] TLS: {sni}")
                dev = self._get_device_by_ip(src)
                if dev:
                    dev.record_website(sni)
                    dev.last_activity = time.time()
        elif t == "http":
            src = data.get("src", "")
            host = data.get("host", "")
            path = data.get("path", "")
            ua = data.get("ua", "")
            if src and host:
                url = f"http://{host}{path}"
                details = f"[{source_label}] HTTP: {host}{path[:60]}"
                if ua:
                    details += f" | UA: {ua[:40]}"
                self.add_activity(src, url, "http_request", details)
                dev = self._get_device_by_ip(src)
                if dev:
                    dev.record_website(host)
                    dev.last_activity = time.time()
                    self._extract_search_from_url(src, host, path)
        elif t == "conn":
            src = data.get("src", "")
            dst = data.get("dst", "")
            sport = data.get("sport", 0)
            dport = data.get("dport", 0)
            if src and dst:
                dev = self._get_device_by_ip(src)
                if dev:
                    dev.record_connection(dst, dport, "TCP")
                    dev.last_activity = time.time()
        elif t == "stat":
            self.total_packets = int(data.get("pkts", self.total_packets))
            self.total_bytes = int(data.get("bytes", self.total_bytes))
        elif t == "info":
            msg = data.get("msg", "")
            if msg:
                self.add_activity("system", msg, "info", f"[{source_label}] {msg}")

    def _get_device_by_ip(self, ip):
        for dev in self.devices.values():
            if ip in dev.ips or dev.ip == ip:
                return dev
        return None

    def _extract_hostname(self, domain):
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def _extract_search_from_url(self, src_ip, host, path):
        query = ""
        if "google" in host and "q=" in path:
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            if "q" in params:
                query = f"Google: {params['q'][0]}"
        elif "bing" in host and "q=" in path:
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            if "q" in params:
                query = f"Bing: {params['q'][0]}"
        elif "youtube" in host and "search_query=" in path:
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            if "search_query" in params:
                query = f"YouTube: {params['search_query'][0]}"
        if query:
            self.add_activity(src_ip, query, "search", f"Searching: {query}")
            dev = self._get_device_by_ip(src_ip)
            if dev:
                dev.record_search(query)

    def add_packet(self, record):
        with self.lock:
            self.total_packets += 1
            self.total_bytes += record.length
            self.protocol_counts[record.protocol] += 1
            if len(self.packet_log) < self._max_packet_log:
                self.packet_log.append(record)

            src_dev = self._get_or_create_device(record.src_mac, record.src_ip)
            src_dev.last_seen = time.time()
            src_dev.last_activity = time.time()
            src_dev.packets_sent += 1
            src_dev.bytes_sent += record.length
            if record.src_ip and record.src_ip != "unknown":
                src_dev.ips.add(record.src_ip)
                if src_dev.ip == "unknown":
                    src_dev.ip = record.src_ip
            if record.ttl > 0:
                src_dev.ttl_values.add(record.ttl)
                if not src_dev.os_hint:
                    src_dev.os_hint = self._guess_os(record.ttl)

            dst_dev = self._get_or_create_device(record.dst_mac, record.dst_ip)
            dst_dev.last_seen = time.time()
            dst_dev.packets_received += 1
            dst_dev.bytes_received += record.length
            if record.dst_ip and record.dst_ip != "unknown":
                dst_dev.ips.add(record.dst_ip)
                if dst_dev.ip == "unknown":
                    dst_dev.ip = record.dst_ip

            src_key = self._device_key(record.src_mac, record.src_ip)
            dst_key = self._device_key(record.dst_mac, record.dst_ip)
            if src_key != dst_key:
                conn_key = (src_key, dst_key)
                if conn_key not in self.connections:
                    rev = (dst_key, src_key)
                    if rev in self.connections:
                        conn_key = rev
                if conn_key not in self.connections:
                    conn = Connection(src_key, dst_key)
                    self.connections[conn_key] = conn
                conn = self.connections[conn_key]
                conn.packet_count += 1
                conn.byte_count += record.length
                conn.last_seen = time.time()
                if record.protocol:
                    conn.protocols.add(record.protocol)

    def add_dns_mapping_info(self, ip, hostname):
        with self.lock:
            self.dns_cache[ip] = hostname
            for dev in self.devices.values():
                if ip in dev.ips and not dev.hostname:
                    dev.hostname = hostname

    def add_activity(self, source_ip, target, event_type, details=""):
        if not target:
            return
        with self.lock:
            self.activity_log.append({
                "time": datetime.now().isoformat(),
                "source_ip": source_ip or "unknown", "target": target,
                "event_type": event_type or "activity", "details": details or "",
            })
            if len(self.activity_log) > self._max_activity_log:
                self.activity_log = self.activity_log[-self._max_activity_log:]

    def get_activity_since(self, start_index=0):
        with self.lock:
            total = len(self.activity_log)
            if start_index < 0: start_index = 0
            if start_index > total: start_index = total
            return list(self.activity_log[start_index:]), total

    def get_recent_packets(self, limit=30):
        with self.lock:
            tail = self.packet_log[-max(1, int(limit)):]
            return [pkt.to_dict() for pkt in tail]

    def get_snapshot(self):
        with self.lock:
            devices_snapshot = {}
            for key, dev in self.devices.items():
                websites = dict(sorted(dev.websites.items(),
                    key=lambda x: x[1]["count"], reverse=True)[:20])
                current_site = dev.get_current_site()
                is_active = dev.is_active()
                active_dur = dev.get_active_duration()
                dns_list = [d for t, d in dev.dns_queries[-10:]]
                search_list = [q for t, q in dev.searches[-10:]]
                devices_snapshot[key] = {
                    "key": key, "label": dev.get_label(),
                    "ip": dev.ip, "mac": dev.mac,
                    "vendor": dev.vendor, "hostname": dev.hostname,
                    "os_hint": dev.os_hint, "is_gateway": dev.is_gateway,
                    "packets_sent": dev.packets_sent,
                    "packets_received": dev.packets_received,
                    "bytes_sent": dev.bytes_sent,
                    "bytes_received": dev.bytes_received,
                    "websites": list(websites.keys()),
                    "current_site": current_site,
                    "is_active": is_active,
                    "active_duration": int(active_dur),
                    "recent_dns": dns_list,
                    "recent_searches": search_list,
                }
            connections_snapshot = []
            for (src, dst), conn in self.connections.items():
                connections_snapshot.append({
                    "src": src, "dst": dst,
                    "packet_count": conn.packet_count,
                    "byte_count": conn.byte_count,
                    "protocols": list(conn.protocols),
                })
            return devices_snapshot, connections_snapshot

    def get_stats(self):
        with self.lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_devices": len(self.devices),
                "total_connections": len(self.connections),
                "uptime": time.time() - self.start_time,
                "protocol_counts": dict(self.protocol_counts),
                "recent_activity": list(self.activity_log[-30:]),
            }

    def get_full_data(self):
        with self.lock:
            return {
                "session": {
                    "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "duration_seconds": round(time.time() - self.start_time, 2),
                    "total_packets": self.total_packets,
                    "total_bytes": self.total_bytes,
                    "protocol_distribution": dict(self.protocol_counts),
                },
                "devices": {k: v.to_dict() for k, v in self.devices.items()},
                "connections": [c.to_dict() for c in self.connections.values()],
                "dns_cache": dict(self.dns_cache),
                "activity_log": list(self.activity_log),
            }
