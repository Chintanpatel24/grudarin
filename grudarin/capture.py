"""
Grudarin - Packet Capture Engine
Uses C engine (grudarin_capture) for high-speed capture, falls back to Scapy.
All data is extracted from real network packets — never random or fake.
"""
import os
import subprocess
import threading
import time

from grudarin.network_model import PacketRecord

C_ENGINE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "bin", "grudarin_capture"
)


class PacketCapture:
    """
    Captures packets using the C engine when available, Scapy fallback otherwise.
    Feeds real behavioral data into NetworkModel.
    """

    def __init__(self, interface, network_model, notes_writer,
                 stop_event, promisc=True, bpf_filter=None,
                 target_ip=None, gateway_ip=None):
        self.interface = interface
        self.model = network_model
        self.notes = notes_writer
        self.stop_event = stop_event
        self.promisc = promisc
        self.bpf_filter = bpf_filter
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self._packet_count = 0
        self._activity_cache = {}
        self._use_c_engine = os.path.isfile(C_ENGINE_PATH) and os.access(C_ENGINE_PATH, os.X_OK)

    def start(self):
        """Start capture using C engine or Scapy fallback."""
        if self._use_c_engine:
            print(f"  [engine] C capture engine: {C_ENGINE_PATH}")
            self._start_c_engine()
        else:
            print("  [engine] Python Scapy capture (C engine not compiled)")
            self._start_scapy()

    def _start_c_engine(self):
        """Run C capture engine as subprocess and parse JSON line output."""
        try:
            cmd = [C_ENGINE_PATH, self.interface]
            if self.target_ip and self.gateway_ip:
                cmd += [self.target_ip, self.gateway_ip]
            elif self.bpf_filter:
                cmd.append(self.bpf_filter)
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=1, text=False
            )
            read_thread = threading.Thread(
                target=self._read_c_output, args=(proc,), daemon=True
            )
            read_thread.start()
            while not self.stop_event.is_set():
                try:
                    proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    continue
                break
            proc.terminate()
            proc.wait(timeout=3)
        except Exception as e:
            print(f"\n  [error] C engine failed: {e}")
            print("  [engine] Falling back to Scapy...")
            self._use_c_engine = False
            self._start_scapy()

    def _read_c_output(self, proc):
        """Read JSON lines from C engine stdout and feed into model."""
        try:
            for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                self.model.ingest_from_c_engine(line)
                self._packet_count += 1
        except Exception:
            pass

    def _start_scapy(self):
        """Python Scapy fallback capture."""
        try:
            from scapy.all import sniff
        except ImportError:
            print("  Error: scapy required. Install: pip install scapy")
            self.stop_event.set()
            return

        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=self.interface, prn=self._process_packet,
                    stop_filter=lambda p: self.stop_event.is_set(),
                    store=False, promisc=self.promisc, filter=self.bpf_filter,
                )
                if not self.stop_event.is_set():
                    time.sleep(0.4)
            except PermissionError:
                print("\n  Error: Permission denied. Run with sudo.")
                self.stop_event.set()
                return
            except OSError as e:
                print(f"\n  Error: {e}")
                if self.stop_event.is_set():
                    return
                print("  Retrying in 2s... Ctrl+C to stop.")
                time.sleep(2)
            except Exception as e:
                print(f"\n  Error: {e}")
                if self.stop_event.is_set():
                    return
                time.sleep(2)

    def _remember_activity(self, source_ip, target, event_type, details=""):
        if not target:
            return
        now = time.time()
        key = (source_ip or "unknown", target, event_type)
        if now - self._activity_cache.get(key, 0.0) < 2.5:
            return
        self._activity_cache[key] = now
        self.model.add_activity(source_ip, target, event_type, details)

    def _extract_http_activity(self, payload):
        try:
            text = payload[:4096].decode("utf-8", errors="ignore")
        except Exception:
            return "", "", ""
        if not text: return "", "", ""
        lines = text.splitlines()
        first_line = lines[0]
        if not first_line.startswith(
            ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
        ):
            return "", "", ""
        host = ""
        user_agent = ""
        referer = ""
        for line in lines[1:60]:
            low = line.lower()
            if low.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif low.startswith("user-agent:"):
                user_agent = line.split(":", 1)[1].strip()
            elif low.startswith("referer:"):
                referer = line.split(":", 1)[1].strip()
        if not host:
            return "", "", ""
        path = first_line.split(" ")[1] if " " in first_line else "/"
        search_query = ""
        if "google" in host and "q=" in path:
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            if "q" in params:
                search_query = f"Searching: {params['q'][0]}"
        elif "bing" in host and "q=" in path:
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            if "q" in params:
                search_query = f"Searching Bing: {params['q'][0]}"
        elif "youtube" in host and "search_query=" in path:
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            if "search_query" in params:
                search_query = f"Searching YouTube: {params['search_query'][0]}"
        details = f"UA: {user_agent[:40]}" if user_agent else ""
        if referer: details += f" | Ref: {referer[:30]}"
        if search_query:
            details = f"{search_query} | {details}" if details else search_query
        return host, path, details

    def _extract_tls_sni(self, payload):
        try:
            if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
                return ""
            pos = 9 + 2 + 32
            if len(payload) < pos + 1: return ""
            sid_len = payload[pos]
            pos += 1 + sid_len
            if len(payload) < pos + 2: return ""
            ciph_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + ciph_len
            if len(payload) < pos + 1: return ""
            comp_len = payload[pos]
            pos += 1 + comp_len
            if len(payload) < pos + 2: return ""
            ext_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            end = min(len(payload), pos + ext_len)
            while pos + 4 <= end:
                ext_type = int.from_bytes(payload[pos:pos+2], "big")
                ext_size = int.from_bytes(payload[pos+2:pos+4], "big")
                pos += 4
                ext_end = min(end, pos + ext_size)
                if ext_type == 0 and pos + 2 <= ext_end:
                    list_len = int.from_bytes(payload[pos:pos+2], "big")
                    pos += 2
                    lend = min(ext_end, pos + list_len)
                    while pos + 3 <= lend:
                        nt = payload[pos]
                        nl = int.from_bytes(payload[pos+1:pos+3], "big")
                        pos += 3
                        if nt == 0 and pos + nl <= lend:
                            host = payload[pos:pos+nl].decode("utf-8", errors="ignore").strip().rstrip(".")
                            if host: return host
                            return ""
                        pos += nl
                    return ""
                pos = ext_end
        except Exception:
            return ""
        return ""

    def _process_packet(self, pkt):
        """Process a single captured packet via Scapy (Python fallback)."""
        try:
            from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR, Raw, Dot11
        except ImportError:
            return

        if self.stop_event.is_set():
            return

        record = PacketRecord()
        record.timestamp = time.time()

        if pkt.haslayer(Ether):
            record.src_mac = pkt[Ether].src
            record.dst_mac = pkt[Ether].dst
        if pkt.haslayer(Dot11):
            try:
                record.src_mac = pkt[Dot11].addr2 or ""
                record.dst_mac = pkt[Dot11].addr1 or ""
            except Exception:
                pass

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            record.protocol = "ARP"
            record.src_ip = arp.psrc or ""
            record.dst_ip = arp.pdst or ""
            if not record.src_mac: record.src_mac = arp.hwsrc or ""
            if not record.dst_mac: record.dst_mac = arp.hwdst or ""
            record.info = f"Is at {arp.hwsrc}" if arp.op == 2 else f"Who has {arp.pdst}?"
            record.length = len(pkt)
            self.model.add_packet(record)
            self._packet_count += 1
            return

        if pkt.haslayer(IP):
            ip = pkt[IP]
            record.src_ip = ip.src
            record.dst_ip = ip.dst
            record.ttl = ip.ttl
            record.length = ip.len or len(pkt)

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.protocol = "TCP"
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                if tcp.flags.P: flags.append("PSH")
                record.flags = ",".join(flags)
                ports = {tcp.sport, tcp.dport}
                if 80 in ports or 8080 in ports: record.protocol = "HTTP"
                elif 443 in ports or 8443 in ports: record.protocol = "HTTPS"
                elif 22 in ports: record.protocol = "SSH"
                elif 21 in ports: record.protocol = "FTP"
                elif 25 in ports or 587 in ports: record.protocol = "SMTP"
                elif 3389 in ports: record.protocol = "RDP"
                elif 445 in ports: record.protocol = "SMB"
                record.info = f"{record.src_ip}:{tcp.sport} -> {record.dst_ip}:{tcp.dport} [{record.flags}]"

                # Real data extraction from payload
                if pkt.haslayer(Raw):
                    try:
                        raw = bytes(pkt[Raw].load[:4096])
                        text = raw.decode("utf-8", errors="ignore")

                        # FTP credential capture (real)
                        if tcp.dport == 21 or tcp.sport == 21:
                            if "USER " in text:
                                user = text.split("USER ")[1].split("\r\n")[0].strip()
                                self._remember_activity(record.src_ip, f"FTP login: {user}", "ftp_login", "FTP USER captured")
                                dev = self._get_dev(record.src_ip)
                                if dev: dev.record_search(f"FTP-USER: {user}")
                            elif "PASS " in text:
                                self._remember_activity(record.src_ip, "FTP password", "ftp_login", "FTP PASS captured")

                        # HTTP request extraction (real)
                        host, path, summary = self._extract_http_activity(raw)
                        if host:
                            activity = f"http://{host}{path}"
                            record.activity = activity
                            self._remember_activity(record.src_ip, activity, "http_request", summary)
                            dev = self._get_dev(record.src_ip)
                            if dev:
                                dev.record_website(host)
                        elif tcp.dport in (443, 8443):
                            tls_host = self._extract_tls_sni(raw)
                            if tls_host:
                                record.activity = f"tls://{tls_host}"
                                self._remember_activity(record.src_ip, tls_host, "tls_sni", f"TLS: {tls_host}")
                                dev = self._get_dev(record.src_ip)
                                if dev:
                                    dev.record_website(tls_host)
                    except Exception:
                        pass

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.protocol = "UDP"
                record.src_port = udp.sport
                record.dst_port = udp.dport
                ports = {udp.sport, udp.dport}
                if 53 in ports: record.protocol = "DNS"
                elif 67 in ports or 68 in ports: record.protocol = "DHCP"
                elif 123 in ports: record.protocol = "NTP"
                elif 161 in ports or 162 in ports: record.protocol = "SNMP"
                elif 5353 in ports: record.protocol = "mDNS"
                record.info = f"{record.src_ip}:{udp.sport} -> {record.dst_ip}:{udp.dport}"

            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                record.protocol = "ICMP"
                names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
                record.info = f"{record.src_ip} -> {record.dst_ip} {names.get(icmp.type, f'Type {icmp.type}')}"

            # DNS query extraction (real)
            if pkt.haslayer(DNS):
                try:
                    dns = pkt[DNS]
                    if getattr(dns, "qd", None):
                        qname = dns.qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore")
                        qname = str(qname).rstrip(".")
                        if qname:
                            record.activity = f"dns://{qname}"
                            if int(getattr(dns, "qr", 0)) == 0:
                                self._remember_activity(record.src_ip, qname, "dns_query", f"DNS: {qname}")
                                dev = self._get_dev(record.src_ip)
                                if dev:
                                    dev.record_dns(qname)
                except Exception:
                    pass

            # DNS response - map hostnames
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
                try:
                    dns = pkt[DNS]
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if hasattr(rr, "rdata") and hasattr(rr, "rrname"):
                            rdata = rr.rdata
                            rrname = rr.rrname
                            if isinstance(rdata, bytes): rdata = rdata.decode("utf-8", errors="ignore")
                            if isinstance(rrname, bytes): rrname = rrname.decode("utf-8", errors="ignore")
                            if rrname.endswith("."): rrname = rrname[:-1]
                            parts = str(rdata).split(".")
                            if len(parts) == 4:
                                try:
                                    if all(0 <= int(p) <= 255 for p in parts):
                                        self.model.add_dns_mapping_info(str(rdata), rrname)
                                except ValueError: pass
                except Exception:
                    pass

        elif pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            record.src_ip = ipv6.src
            record.dst_ip = ipv6.dst
            record.protocol = "IPv6"
            record.length = len(pkt)
            record.info = f"{ipv6.src} -> {ipv6.dst}"
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.protocol = "TCPv6"
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.protocol = "UDPv6"
                record.src_port = udp.sport
                record.dst_port = udp.dport
        else:
            record.protocol = "Other"
            record.length = len(pkt)
            record.info = pkt.summary()

        self.model.add_packet(record)
        self._packet_count += 1

        # Track connections for behavioral analysis
        if record.src_ip and record.dst_ip and record.protocol not in ("ARP", "Other"):
            dev = self._get_dev(record.src_ip)
            if dev:
                dev.record_connection(record.dst_ip, record.dst_port or 0, record.protocol)

    def _get_dev(self, ip):
        for dev in self.model.devices.values():
            if ip in dev.ips or dev.ip == ip:
                return dev
        return None
