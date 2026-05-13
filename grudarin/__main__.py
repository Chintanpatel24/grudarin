"""
Grudarin - Terminal Network Spy
Spy on any network without connecting. Deep packet inspection.
sudo grudarin --list
sudo grudarin --scan wlan0 --monitor Pixel
"""
import argparse
import difflib
import os
import sys
import signal
import subprocess
import threading
import time
import tempfile
from datetime import datetime

from grudarin import __version__
from grudarin.capture import PacketCapture
from grudarin.network_model import NetworkModel
from grudarin.notes import NotesWriter
from grudarin.tui import SpyTUI
from grudarin.vuln_analyzer import VulnAnalyzer

def discover_wifi_networks():
    """Scan for available WiFi networks using system tools."""
    networks = []
    try:
        if sys.platform == "linux":
            try:
                out = subprocess.check_output(
                    ["iwlist", "scan"], stderr=subprocess.DEVNULL, timeout=15
                ).decode("utf-8", errors="ignore")
                ssid = None
                for line in out.splitlines():
                    line = line.strip()
                    if "ESSID:" in line:
                        ssid = line.split("ESSID:")[1].strip().strip('"')
                    if "Address:" in line:
                        bssid = line.split("Address:")[1].strip()
                        if ssid:
                            networks.append({"ssid": ssid, "bssid": bssid})
                            ssid = None
            except Exception:
                pass
            if not networks:
                try:
                    out = subprocess.check_output(
                        ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
                        stderr=subprocess.DEVNULL, timeout=15
                    ).decode("utf-8", errors="ignore")
                    for line in out.strip().splitlines():
                        # nmcli -t escapes colons with backslash; unescape them
                        unescaped = line.replace("\\:", "\x00")
                        parts = unescaped.split(":")
                        parts = [p.replace("\x00", ":") for p in parts]
                        if len(parts) >= 4 and parts[0].strip():
                            networks.append({
                                "ssid": parts[0].strip(), "bssid": parts[1].strip(),
                                "signal": parts[2].strip(), "security": parts[3].strip(),
                            })
                except Exception:
                    pass
        elif sys.platform == "darwin":
            try:
                out = subprocess.check_output([
                    "/System/Library/PrivateFrameworks/Apple80211.framework/"
                    "Versions/Current/Resources/airport", "-s"
                ], stderr=subprocess.DEVNULL, timeout=15).decode("utf-8", errors="ignore")
                for line in out.strip().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        networks.append({"ssid": parts[0], "bssid": parts[1]})
            except Exception:
                pass
        elif sys.platform == "win32":
            try:
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    stderr=subprocess.DEVNULL, timeout=15
                ).decode("utf-8", errors="ignore")
                ssid = None
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("SSID") and "BSSID" not in line:
                        ssid = line.split(":")[1].strip() if ":" in line else None
                    if line.startswith("BSSID"):
                        bssid = line.split(":")[1].strip() if ":" in line else ""
                        if ssid:
                            networks.append({"ssid": ssid, "bssid": bssid})
            except Exception:
                pass
    except Exception:
        pass
    return networks

def list_interfaces():
    """List available network interfaces and WiFi networks."""
    try:
        from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, conf
    except ImportError:
        print("  [error] scapy is required. Install with: pip install scapy")
        sys.exit(1)

    interfaces = get_if_list()
    print("\n  AVAILABLE NETWORK INTERFACES")
    print("  " + "-" * 60)
    print(f"  {'Interface':<18} {'IP Address':<18} {'MAC Address':<20} {'Status'}")
    print("  " + "-" * 60)
    for iface in interfaces:
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "N/A"
        try:
            mac = get_if_hwaddr(iface)
        except Exception:
            mac = "N/A"
        status = "UP" if addr and addr != "0.0.0.0" else "DOWN"
        print(f"  {iface:<18} {addr:<18} {mac:<20} {status}")

    print("\n  DETECTED WIFI NETWORKS")
    print("  " + "-" * 60)
    wifi_nets = discover_wifi_networks()
    if wifi_nets:
        print(f"  {'SSID':<25} {'BSSID':<20} {'Signal':<8} {'Security'}")
        print("  " + "-" * 60)
        for net in wifi_nets:
            print(
                f"  {net.get('ssid','?'):<25} "
                f"{net.get('bssid','?'):<20} "
                f"{net.get('signal','?'):<8} "
                f"{net.get('security','?')}"
            )
    else:
        print("  No WiFi networks found (may need root or wireless tools)")

    print("\n  CONNECTED LAN / GATEWAY INFO")
    print("  " + "-" * 60)
    try:
        gw = conf.route.route("0.0.0.0")
        if gw:
            print(f"  Default Gateway  : {gw[2]}")
            print(f"  Output Interface : {gw[0]}")
    except Exception:
        print("  Could not detect gateway")
    print()

def _get_interfaces():
    try:
        from scapy.all import get_if_list
        return list(get_if_list())
    except Exception:
        return []

def _normalize_interface_guess(value):
    raw = (value or "").strip()
    if not raw:
        return raw
    if raw.lower().endswith("o"):
        return raw[:-1] + "0"
    return raw

def _suggest_interface(user_value, interfaces=None):
    raw = (user_value or "").strip()
    if not raw:
        return None
    interfaces = interfaces or _get_interfaces()
    if not interfaces:
        return None
    lowered = {iface.lower(): iface for iface in interfaces}
    normalized = _normalize_interface_guess(raw).lower()
    if normalized in lowered:
        return lowered[normalized]
    matches = difflib.get_close_matches(raw.lower(), list(lowered.keys()), n=1, cutoff=0.55)
    if matches:
        return lowered[matches[0]]
    return None

def _resolve_scan_interface(user_value):
    raw = (user_value or "").strip()
    if not raw:
        return None
    interfaces = _get_interfaces()
    iface_map = {i.lower(): i for i in interfaces}
    if raw.lower() in iface_map:
        return iface_map[raw.lower()]
    normalized_guess = _normalize_interface_guess(raw)
    if normalized_guess.lower() in iface_map:
        return iface_map[normalized_guess.lower()]
    if sys.platform == "linux":
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,ACTIVE,SSID", "dev", "wifi"],
                stderr=subprocess.DEVNULL, timeout=8
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) < 3:
                    continue
                dev = parts[0].strip()
                active = parts[1].strip().lower()
                ssid = ":".join(parts[2:]).strip()
                if active == "yes" and ssid.lower() == raw.lower():
                    if dev in interfaces:
                        return dev
                    if dev.lower() in iface_map:
                        return iface_map[dev.lower()]
        except Exception:
            pass
        try:
            nets = discover_wifi_networks()
            if any(str(n.get("ssid", "")).lower() == raw.lower() for n in nets):
                wifi_devices = []
                try:
                    out = subprocess.check_output(
                        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev", "status"],
                        stderr=subprocess.DEVNULL, timeout=8
                    ).decode("utf-8", errors="ignore")
                    for line in out.splitlines():
                        parts = line.split(":")
                        if len(parts) < 3:
                            continue
                        dev = parts[0].strip()
                        typ = parts[1].strip().lower()
                        state = parts[2].strip().lower()
                        if typ == "wifi" and dev:
                            if dev in interfaces or dev.lower() in iface_map:
                                mapped = dev if dev in interfaces else iface_map[dev.lower()]
                                if state == "connected":
                                    return mapped
                                wifi_devices.append(mapped)
                except Exception:
                    wifi_devices = []
                if wifi_devices:
                    return wifi_devices[0]
                for candidate in interfaces:
                    low = candidate.lower()
                    if low.startswith(("wlan", "wl", "wlp", "wifi")):
                        return candidate
        except Exception:
            pass
    return None

def _validate_interface_exists(iface):
    return iface in _get_interfaces()

def parse_args():
    argv = list(sys.argv[1:])
    # Convert: --scan wlan0 Pixel -> --scan wlan0 --ssid Pixel
    for idx, tok in enumerate(argv):
        if tok == "--scan" and idx + 2 < len(argv):
            iface = argv[idx + 1]
            maybe_ssid = argv[idx + 2]
            if iface and not iface.startswith("-") and maybe_ssid and not maybe_ssid.startswith("-"):
                argv = argv[:idx] + ["--scan", iface, "--ssid", maybe_ssid] + argv[idx + 3:]
            break
    # Convert: --monitor Pixel -> --monitor --ssid Pixel (when no --scan with trailing name)
    for idx, tok in enumerate(argv):
        if tok == "--monitor" and idx + 1 < len(argv):
            nxt = argv[idx + 1]
            if nxt and not nxt.startswith("-") and "--ssid" not in argv:
                argv = argv[:idx] + ["--monitor", "--ssid", nxt] + argv[idx + 2:]
            break
    sys.argv[1:] = argv

    parser = argparse.ArgumentParser(
        prog="grudarin",
        description="Grudarin - Network Spy: Monitor any network, capture deep intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WORKFLOW:
  1. sudo grudarin --list                        List interfaces and WiFi networks
  2. sudo grudarin --scan wlan0                  Spy on all local traffic (passive)
  3. sudo grudarin --scan wlan0 --stealth        Anonymous: randomizes MAC, clears traces
  4. sudo grudarin --scan eth0 --target-ip 192.168.1.10  ARP MITM: intercept target's full traffic
  5. sudo grudarin --scan wlan0 --monitor Pixel  Spy on specific WiFi network
  6. sudo grudarin -s example.com                Site recon scan with graph UI

EXAMPLES:
  sudo grudarin --scan wlan0
  sudo grudarin --scan wlan0 --stealth
  sudo grudarin --scan eth0 --target-ip 192.168.1.10 --gateway-ip 192.168.1.1
  sudo grudarin --scan wlan0 --monitor "Pixel"
  sudo grudarin -s example.com

NOTES:
  --stealth   : Randomizes MAC, clears ARP cache, suppresses logs (OpSec)
  --target-ip : Enables ARP MITM to intercept ALL traffic from a specific device
  Ctrl+C      : Stop session, restore original MAC, generate report
  Reports     : Saved to grudarin_output/ directory
"""
    )
    parser.add_argument("--scan", metavar="INTERFACE", type=str, default=None,
                        help="Start spy session on interface (e.g., wlan0, eth0)")
    parser.add_argument("--ssid", type=str, default=None,
                        help="Target WiFi SSID label")
    parser.add_argument("--monitor", action="store_true",
                        help="Enable monitor mode (Linux) - spy without connecting")
    parser.add_argument("-s", "--scan-site", "--site", metavar="DOMAIN", type=str, default=None,
                        help="Scan a website/domain (e.g., example.com)")
    parser.add_argument("--list", "-l", action="store_true", help="List interfaces and networks")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output directory")
    parser.add_argument("--name", "-n", type=str, default=None, help="Session name")
    parser.add_argument("--duration", "-d", type=int, default=0, help="Auto-stop after N seconds")
    parser.add_argument("--no-graph", action="store_true", help="Disable TUI (headless)")
    parser.add_argument("--ports", type=str, default="1-1024", help="Port range for vuln scan")
    parser.add_argument("--targets", type=str, default=None, help="Comma-separated IPs to scan")
    parser.add_argument("--no-scan", action="store_true", help="Skip vulnerability scanning")
    parser.add_argument("--promisc", action="store_true", default=True, help="Promiscuous mode (default: on)")
    parser.add_argument("--filter", "-f", type=str, default=None, help="BPF filter")
    parser.add_argument("--export-graph", type=str, default="none", choices=["none", "json", "csv", "both"],
                        help="Export graph data as JSON/CSV")
    parser.add_argument("--privacy-mode", action="store_true", help="Mask IPs in reports")
    parser.add_argument("--stealth", action="store_true", help="Enable anonymity: randomize MAC, suppress logs")
    parser.add_argument("--target-ip", type=str, default=None, help="Specific target IP for ARP MITM interception")
    parser.add_argument("--gateway-ip", type=str, default=None, help="Gateway IP for ARP spoofing")
    return parser.parse_args()

def print_banner():
    print("""
    ================================================================
                      G R U D A R I N
                Network Spy & Intelligence Tool
                            v%s
    ================================================================
    """ % __version__)

def _resolve_output_base_dir(requested_dir=None):
    candidates = []
    if requested_dir:
        candidates.append(os.path.abspath(os.path.expanduser(requested_dir)))
    else:
        candidates.append(os.path.join(os.getcwd(), "grudarin_output"))
    home = os.path.expanduser("~")
    candidates.append(os.path.join(home, ".local", "share", "grudarin_output"))
    candidates.append(os.path.join(tempfile.gettempdir(), "grudarin_output"))
    last_err = None
    for base in candidates:
        try:
            os.makedirs(base, exist_ok=True)
            test_file = os.path.join(base, ".grudarin_write_test")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test_file)
            return base
        except Exception as e:
            last_err = e
    print(f"  [error] No writable output directory found: {last_err}")
    sys.exit(1)

def _set_monitor_mode(iface, enabled=True):
    if sys.platform != "linux":
        return False
    try:
        mode = "monitor" if enabled else "managed"
        print(f"  [monitor] Setting {iface} to {mode} mode...")
        subprocess.check_call(["ip", "link", "set", iface, "down"])
        subprocess.check_call(["iw", "dev", iface, "set", "type", mode])
        subprocess.check_call(["ip", "link", "set", iface, "up"])
        return True
    except Exception as e:
        print(f"  [error] Failed to set monitor mode: {e}")
        return False

def check_privileges():
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0

def interactive_mode():
    print_banner()
    if not check_privileges():
        print("  [warn] Not running as root. Run with sudo for full capture.\n")
    list_interfaces()
    print("  To spy on a network, use:")
    print("    sudo grudarin --scan <interface> --monitor <SSID>")
    print()
    iface = input("  Enter interface to scan (or press Enter to exit): ").strip()
    if not iface:
        print("  Exiting.")
        sys.exit(0)
    output_dir = input("  Enter path to save notes [./grudarin_output]: ").strip()
    output_dir = _resolve_output_base_dir(output_dir) if output_dir else _resolve_output_base_dir(None)
    scan_name = input("  Enter a name for this scan [session]: ").strip() or "session"
    return iface, output_dir, scan_name

def _fmt_bytes(n):
    if n < 1024: return f"{n} B"
    elif n < 1048576: return f"{n/1024:.1f} KB"
    elif n < 1073741824: return f"{n/1048576:.1f} MB"
    return f"{n/1073741824:.2f} GB"

def run_scan(iface, output_dir, scan_name, args):
    output_dir = _resolve_output_base_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan_name)
    session_dir = os.path.join(output_dir, f"grudarin_{safe_name}_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)

    print(f"\n  Interface   : {iface}")
    target_str = args.ssid or "ALL TRAFFIC"
    print(f"  Target      : {target_str}")
    print(f"  Output      : {session_dir}")
    print(f"  Scan Name   : {scan_name}")
    print(f"  Duration    : {'Unlimited' if args.duration == 0 else str(args.duration) + 's'}")
    print(f"  TUI         : {'Disabled' if args.no_graph else 'Enabled'}")
    c_engine = os.path.isfile(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "grudarin_capture"))
    print(f"  C Engine    : {'Ready' if c_engine else 'Not compiled (Scapy fallback)'}")

    # Stealth mode: MAC randomization
    original_mac = None
    if args.stealth:
        from grudarin.anonymous import change_mac, get_original_mac, clear_arp_cache, clear_logs
        original_mac = get_original_mac(iface)
        new_mac = change_mac(iface)
        if new_mac:
            print(f"  Stealth     : MAC randomized to {new_mac}")
        else:
            print("  Stealth     : MAC randomization failed (run as root)")
        clear_arp_cache()
        clear_logs()
    else:
        print("  Stealth     : Disabled (use --stealth for anonymous mode)")

    # ARP spoofing setup
    target_ip = args.target_ip
    gateway_ip = args.gateway_ip
    arp_mode = bool(target_ip)
    if arp_mode:
        from grudarin.anonymous import clear_arp_cache
        print(f"  ARP MITM    : Intercepting {target_ip} via gateway {gateway_ip or '(auto)'}")
        clear_arp_cache()

    print("  Notice      : Authorized security testing only")
    print()

    network_model = NetworkModel()
    notes_writer = NotesWriter(session_dir)
    stop_event = threading.Event()

    capture = PacketCapture(
        interface=iface, network_model=network_model, notes_writer=notes_writer,
        stop_event=stop_event, promisc=args.promisc, bpf_filter=args.filter,
        target_ip=target_ip, gateway_ip=gateway_ip
    )
    vuln_analyzer = VulnAnalyzer(network_model=network_model, session_dir=session_dir)

    def on_signal(sig, frame):
        print("\n\n  Stopping Grudarin...")
        stop_event.set()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    capture_thread = threading.Thread(target=capture.start, daemon=True)
    capture_thread.start()
    print("  [live] Spy session started on", iface)
    print("  [live] Capturing packets, DNS, HTTP, TLS, and activity in real-time")
    print("  [live] Press Ctrl+C to stop and generate intelligence report")
    print()

    def console_printer():
        while not stop_event.is_set():
            stats = network_model.get_stats()
            line = (
                f"\r  [scanning] Packets: {stats['total_packets']}  "
                f"Devices: {stats['total_devices']}  "
                f"Links: {stats['total_connections']}  "
                f"Data: {_fmt_bytes(stats['total_bytes'])}  "
                f"Uptime: {int(stats['uptime'])}s    "
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.8)
    printer_thread = threading.Thread(target=console_printer, daemon=True)
    printer_thread.start()

    def activity_printer():
        last_index = 0
        while not stop_event.is_set():
            events, last_index = network_model.get_activity_since(last_index)
            for ev in events:
                target = ev.get("target", "-")
                source_ip = ev.get("source_ip", "-")
                event_type = ev.get("event_type", "activity")
                details = ev.get("details", "")
                msg = f"\n  [spy] {source_ip} -> {target} [{event_type}]"
                if details:
                    msg += f" {details}"
                print(msg[:260])
            time.sleep(0.4)
    activity_thread = threading.Thread(target=activity_printer, daemon=True)
    activity_thread.start()

    if not args.no_graph:
        tui = SpyTUI(
            network_model=network_model, stop_event=stop_event,
            interface=iface, target_ssid=args.ssid or "",
            arp_mode=bool(args.target_ip)
        )
        tui.run()
    else:
        try:
            if args.duration > 0:
                deadline = time.time() + args.duration
                while not stop_event.is_set() and time.time() < deadline:
                    time.sleep(0.5)
                stop_event.set()
            else:
                while not stop_event.is_set():
                    time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()

    stop_event.set()
    capture_thread.join(timeout=5)
    print("\n")
    findings_data = []
    if not args.no_scan:
        print("  [analysis] Running vulnerability analysis...")
        scan_targets = [t.strip() for t in args.targets.split(",")] if args.targets else None
        findings = vuln_analyzer.analyze(scan_targets=scan_targets, port_range=args.ports)
        findings_data = vuln_analyzer.get_findings_dicts()
        if findings:
            print("\n  SECURITY FINDINGS")
            print("  " + "=" * 60)
            for f in findings:
                sev = f.severity.upper()
                print(f"  [{sev:<8}] {f.title}")
                print(f"             {f.description[:80]}")
                if f.affected:
                    print(f"             Affected: {f.affected}")
                print()
    print("  [report] Writing intelligence reports...")
    notes_writer.write_final_report(network_model, findings_data, privacy_mode=args.privacy_mode, export_graph=args.export_graph)
    print(f"\n  Reports saved to: {session_dir}")
    print("    session_report.md")
    print("    session_data.json")
    print("    packets.log")
    print()
    stats = network_model.get_stats()
    print("  Spy Session Summary:")
    print(f"    Total Packets  : {stats['total_packets']}")
    print(f"    Devices Found  : {stats['total_devices']}")
    print(f"    Connections    : {stats['total_connections']}")
    print(f"    Data Captured  : {_fmt_bytes(stats['total_bytes'])}")
    print(f"    Findings       : {len(findings_data)}")
    if args.stealth and original_mac:
        from grudarin.anonymous import restore_mac
        restore_mac(iface, original_mac)
        print(f"  [opsec] Original MAC restored: {original_mac}")
    print("\n  Grudarin spy session complete.\n")

def run_site_scan(domain, output_dir, scan_name, args):
    from grudarin.graph_window import GraphWindow
    from grudarin.site_scan import SiteGraphModel, SiteScanner

    output_dir = _resolve_output_base_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan_name)
    session_dir = os.path.join(output_dir, f"grudarin_site_{safe_name}_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)

    print(f"\n  Site Target  : {domain}")
    print(f"  Output       : {session_dir}")
    print(f"  Graph        : {'Disabled' if args.no_graph else 'Enabled'}")
    print()

    model = SiteGraphModel()
    local_net_model = NetworkModel()
    stop_event = threading.Event()
    from scapy.all import conf
    default_iface = conf.iface
    capture = None
    if default_iface:
        from grudarin.notes import NotesWriter as DummyNotesWriter
        capture = PacketCapture(
            interface=str(default_iface), network_model=local_net_model,
            notes_writer=DummyNotesWriter(tempfile.gettempdir()), stop_event=stop_event
        )
        threading.Thread(target=capture.start, daemon=True).start()

    notes_writer = NotesWriter(session_dir)
    scanner = SiteScanner(model=model, domain=domain, stop_event=stop_event, network_model=local_net_model)

    def on_signal(_sig, _frame):
        print("\n\n  Stopping site scan...")
        stop_event.set()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    scan_thread = threading.Thread(target=scanner.run, daemon=True)
    scan_thread.start()

    def scan_site_node(target_ip):
        issues = []
        open_ports = []
        vuln = VulnAnalyzer(network_model=model, session_dir=session_dir)
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(target_ip)
            if ip_obj.version == 4:
                ports = vuln.run_python_scanner(target_ip, port_start=1, port_end=1024, threads=40, timeout=0.35)
                for p in ports:
                    pn = int(p.get("port", 0))
                    if pn > 0:
                        open_ports.append(pn)
                    if pn in vuln.DANGEROUS_PORTS:
                        svc, sev, risk = vuln.DANGEROUS_PORTS[pn]
                        issues.append({"severity": sev, "text": f"{svc} on {pn}: {risk}"})
        except Exception as e:
            issues.append({"severity": "medium", "text": str(e)})
        return {"ip": target_ip, "port_range": "1-1024", "open_ports": sorted(set(open_ports)), "issues": issues}

    if not args.no_graph:
        graph_window = GraphWindow(
            network_model=model, stop_event=stop_event, notes_writer=notes_writer,
            session_dir=session_dir, scan_callback=scan_site_node
        )
        if args.duration and args.duration > 0:
            def timer_stop():
                deadline = time.time() + args.duration
                while not stop_event.is_set() and time.time() < deadline:
                    time.sleep(0.5)
                stop_event.set()
            threading.Thread(target=timer_stop, daemon=True).start()
        graph_window.run()
    else:
        try:
            if args.duration > 0:
                deadline = time.time() + args.duration
                while not stop_event.is_set() and time.time() < deadline:
                    time.sleep(0.5)
                stop_event.set()
            else:
                while not stop_event.is_set():
                    if not scan_thread.is_alive():
                        break
                    time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()

    stop_event.set()
    scan_thread.join(timeout=5)
    findings_data = []
    if not args.no_scan:
        print("  [analysis] Running site vulnerability analysis...")
        vuln_analyzer = VulnAnalyzer(network_model=model, session_dir=session_dir)
        findings = vuln_analyzer.analyze(scan_targets=None, port_range=args.ports)
        findings_data = vuln_analyzer.get_findings_dicts()
        if findings:
            print("\n  SITE SECURITY FINDINGS")
            print("  " + "=" * 60)
            for finding in findings:
                sev = finding.severity.upper()
                print(f"  [{sev:<8}] {finding.title}")
                print(f"             {finding.description[:80]}")
                if finding.affected:
                    print(f"             Affected: {finding.affected}")
                print()
    site_data = model.get_full_data()
    for key, dev in site_data.get("devices", {}).items():
        if dev.get("node_type") != "VULNERABILITY":
            continue
        findings_data.append({
            "severity": (dev.get("severity") or "info").lower(),
            "title": dev.get("label", dev.get("hostname", key)),
            "description": dev.get("description", dev.get("label", key)),
            "affected": dev.get("ip", ""),
            "recommendation": dev.get("recommendation", "Review the exposed endpoint and restrict access."),
        })
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_data.sort(key=lambda item: severity_order.get(str(item.get("severity", "info")).lower(), 99))
    print("\n  [report] Writing reports...")
    notes_writer.write_final_report(model, findings_data, privacy_mode=args.privacy_mode, export_graph=args.export_graph)
    stats = model.get_stats()
    print(f"\n  Reports saved to: {session_dir}")
    print("  Site Scan Summary:")
    print(f"    Entities Found : {stats['total_devices']}")
    print(f"    Relationships  : {stats['total_connections']}")
    print(f"    Events         : {stats['total_packets']}")
    print(f"    Data Processed : {_fmt_bytes(stats['total_bytes'])}")
    print("\n  Grudarin site scan complete.\n")

def main():
    if os.environ.get("XDG_SESSION_TYPE") == "wayland":
        if "GDK_BACKEND" not in os.environ:
            os.environ["GDK_BACKEND"] = "x11"
        if "QT_QPA_PLATFORM" not in os.environ:
            os.environ["QT_QPA_PLATFORM"] = "xcb"

    args = parse_args()

    if args.list:
        print_banner()
        if not check_privileges():
            print("  [warn] Run with sudo for full interface/WiFi info")
        list_interfaces()
        sys.exit(0)

    if args.scan:
        print_banner()
        requested_scan = args.scan

        if args.monitor:
            if sys.platform == "linux":
                if not check_privileges():
                    print("  [!] Root required for monitor mode.")
                    sys.exit(1)
                if args.ssid:
                    print(f"  [monitor] Hunting for SSID '{args.ssid}' on {requested_scan}...")
                    target_channel = None
                    try:
                        networks = discover_wifi_networks()
                        for net in networks:
                            if str(net.get('ssid')).lower() == args.ssid.lower():
                                out = subprocess.check_output(
                                    ["iw", "dev", requested_scan, "scan"], stderr=subprocess.DEVNULL
                                ).decode("utf-8")
                                found_this = False
                                for line in out.splitlines():
                                    if f"SSID: {args.ssid}" in line:
                                        found_this = True
                                    if found_this and "DS Parameter set: channel" in line:
                                        target_channel = line.split("channel")[1].strip()
                                        break
                                if target_channel:
                                    break
                    except Exception:
                        pass
                    _set_monitor_mode(requested_scan, True)
                    if target_channel:
                        print(f"  [monitor] Locking {requested_scan} to channel {target_channel}")
                        subprocess.call(["iw", "dev", requested_scan, "set", "channel", target_channel])
                    else:
                        print("  [monitor] Monitor mode active, scanning all channels")
                else:
                    _set_monitor_mode(requested_scan, True)
            else:
                print("  [warn] Monitor mode only supported on Linux")

        resolved_iface = _resolve_scan_interface(requested_scan)
        if not resolved_iface:
            suggested = _suggest_interface(requested_scan)
            print(f"  [error] Interface not found: {requested_scan}")
            if suggested:
                print(f"  [hint] Did you mean: {suggested}")
            print("  [hint] Run: sudo grudarin --list")
            sys.exit(1)
        if not _validate_interface_exists(resolved_iface):
            print(f"  [error] Interface not available: {resolved_iface}")
            sys.exit(1)
        if resolved_iface != requested_scan:
            print(f"  [info] Resolved '{requested_scan}' -> '{resolved_iface}'")

        if not check_privileges():
            print("  [!] Root required for network monitoring.")
            sys.exit(1)

        output_dir = _resolve_output_base_dir(args.output)
        scan_name = args.name or "session"
        run_scan(resolved_iface, output_dir, scan_name, args)
    elif args.scan_site:
        from grudarin.graph_window import GraphWindow
        from grudarin.site_scan import SiteGraphModel, SiteScanner
        print_banner()
        output_dir = _resolve_output_base_dir(args.output)
        scan_name = args.name or args.scan_site
        run_site_scan(args.scan_site, output_dir, scan_name, args)
    else:
        iface, output_dir, scan_name = interactive_mode()
        args.duration = 0
        args.ports = "1-1024"
        args.targets = None
        args.no_scan = False
        args.no_graph = False
        args.promisc = True
        args.filter = None
        args.stealth = False
        args.target_ip = None
        args.gateway_ip = None
        run_scan(iface, output_dir, scan_name, args)

if __name__ == "__main__":
    main()
