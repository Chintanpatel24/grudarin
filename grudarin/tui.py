"""
Grudarin - Spy TUI
Real-time behavioral surveillance interface.
Shows captured data with provenance tags: CERTAIN (direct) / MITM (ARP poison).
Every data point sourced from real packet inspection.
"""
import time
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box
from rich.align import Align
from grudarin import __version__

class SpyTUI:
    def __init__(self, network_model, stop_event, interface="", target_ssid="", arp_mode=False):
        self.model = network_model
        self.stop_event = stop_event
        self.interface = interface
        self.target_ssid = target_ssid or "ALL"
        self.arp_mode = arp_mode
        self.console = Console()
        self.start_time = time.time()

    def _fmt_bytes(self, n):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if n < 1024: return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3)
        )
        layout["body"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=2)
        )
        layout["left"].split_column(
            Layout(name="activity", ratio=3),
            Layout(name="packets", ratio=2)
        )
        layout["right"].split_column(
            Layout(name="devices", ratio=2),
            Layout(name="stats", size=10),
            Layout(name="intel", ratio=1)
        )
        return layout

    def generate_header(self) -> Panel:
        status = "[bold green]\u25cf SPYING[/bold green]" if not self.stop_event.is_set() else "[bold red]\u25cf STOPPED[/bold red]"
        uptime = int(time.time() - self.start_time)
        mode_str = "ARP-MITM" if self.arp_mode else "PASSIVE"
        h = Text()
        h.append(f" GRUDARIN v{__version__} ", style="bold green")
        h.append(f"\u2502 {mode_str} ", style="bold yellow" if self.arp_mode else "white")
        h.append(f"\u2502 {self.interface} ", style="white")
        h.append(f"\u2502 TARGET: {self.target_ssid} ", style="cyan")
        h.append(f"\u2502 UPTIME: {uptime}s ", style="yellow")
        h.append(f"\u2502 {status}", style="bold green")
        return Panel(h, style="black on dark_green", box=box.HEAVY)

    def generate_activity(self) -> Panel:
        table = Table(expand=True, box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("Time", width=10)
        table.add_column("Source", width=15, style="green")
        table.add_column("Type", width=8, style="yellow")
        table.add_column("Detail", style="white")

        activity, _ = self.model.get_activity_since(0)
        for item in activity[-25:]:
            t = item.get("time", "")[-8:]
            src = item.get("source_ip", "?")[:15]
            et = item.get("event_type", "?")[:8]
            det = str(item.get("details", "") or item.get("target", ""))
            if "CERTAIN" in det:
                det = det.replace("[CERTAIN]", "")
                conf = "[bold green]C[/bold green]"
            elif "MITM" in det:
                det = det.replace("[MITM]", "")
                conf = "[bold yellow]M[/bold yellow]"
            else:
                conf = ""
            if "Searching:" in det or "SEARCH" in det.upper():
                det = f"[bold red]{det}[/bold red]"
            elif "HTTP:" in det:
                det = f"[cyan]{det}[/cyan]"
            elif "TLS:" in det or "DNS:" in det:
                det = f"[blue]{det}[/blue]"
            elif "FTP" in det or "PASS" in det:
                det = f"[bold red]{det}[/bold red]"
            table.add_row(t, src, f"{conf}", det[:120])
        return Panel(table, title="[bold]REAL-TIME SURVEILLANCE FEED[/bold]", box=box.ROUNDED, border_style="green")

    def generate_packets(self) -> Panel:
        table = Table(expand=True, box=box.SIMPLE, show_header=True, header_style="bold blue")
        table.add_column("Proto", width=7)
        table.add_column("Source \u2192 Destination", style="white")
        table.add_column("Info", style="dim white")
        packets = self.model.get_recent_packets(limit=10)
        for p in packets:
            proto = p.get("protocol", "IP")
            src = p.get("src_ip", "-")
            dst = p.get("dst_ip", "-")
            info = p.get("info", "")
            table.add_row(proto, f"{src} \u2192 {dst}", info[:80])
        return Panel(table, title="[bold]RAW PACKET STREAM[/bold]", box=box.ROUNDED, border_style="blue")

    def generate_devices(self) -> Panel:
        table = Table(expand=True, box=box.SIMPLE, show_header=True, header_style="bold magenta")
        table.add_column("Device", width=14, style="green")
        table.add_column("IP", width=15, style="cyan")
        table.add_column("Status", width=7)
        table.add_column("Activity", width=30, style="white")

        devices, _ = self.model.get_snapshot()
        sorted_devs = sorted(
            devices.values(),
            key=lambda x: x.get('packets_sent', 0) + x.get('packets_received', 0),
            reverse=True
        )
        for d in sorted_devs[:6]:
            label = d.get('hostname') or d.get('label') or d.get('ip') or "?"
            ip = d.get('ip', '?')
            is_active = d.get('is_active', False)
            status = "[green]ONLINE[/green]" if is_active else "[dim]OFF[/dim]"
            site = d.get('current_site', '') or d.get('hostname', '') or '-'
            table.add_row(label[:14], ip[:15], status, site[:30])
        return Panel(table, title="[bold]TARGET DEVICES[/bold]", box=box.ROUNDED, border_style="magenta")

    def generate_stats(self) -> Panel:
        stats = self.model.get_stats()
        text = Text()
        text.append(f" Packets: {stats.get('total_packets', 0)}\n", style="bold white")
        text.append(f" Volume:  {self._fmt_bytes(stats.get('total_bytes', 0))}\n", style="white")
        text.append(f" Devices: {stats.get('total_devices', 0)}\n", style="cyan")
        text.append(f" Links:   {stats.get('total_connections', 0)}\n", style="yellow")
        proto_counts = stats.get("protocol_counts", {})
        top_protos = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for p, c in top_protos:
            text.append(f" {p}: {c}\n", style="dim white")
        return Panel(text, title="[bold]SESSION STATS[/bold]", box=box.ROUNDED, border_style="yellow")

    def generate_intel(self) -> Panel:
        activity, _ = self.model.get_activity_since(0)
        interesting = []
        for item in activity:
            det = str(item.get("details", ""))
            tgt = str(item.get("target", ""))
            src = item.get("source_ip", "?")
            if "Searching:" in det or "SEARCH" in det.upper():
                interesting.append((src, "SEARCH", det))
            elif "FTP" in det or "PASS" in det:
                interesting.append((src, "CRED", det))
            elif "LOGIN" in det.upper() or "auth" in tgt.lower() or "signin" in tgt.lower():
                interesting.append((src, "LOGIN", tgt[:80]))
        text = Text()
        if interesting:
            for src, typ, det in interesting[-10:]:
                text.append(f" {src} ", style="cyan")
                text.append(f"[{typ}] ", style="bold yellow")
                text.append(f"{det[:80]}\n", style="bold red")
        else:
            text.append(" Awaiting intelligence...\n", style="dim white")
            text.append(" Data appears when target browses the web\n", style="dim white")
        return Panel(text, title="[bold red]EXTRACTED INTELLIGENCE[/bold red]", box=box.ROUNDED, border_style="red")

    def generate_footer(self) -> Panel:
        return Panel(
            Align.center("[bold white][CTRL+C] Stop & Generate Report | [C]ERTAIN | [M]ITM | All data sourced from live packets[/bold white]"),
            style="black on red", box=box.ASCII
        )

    def run(self):
        layout = self.make_layout()
        with Live(layout, refresh_per_second=4, screen=True):
            while not self.stop_event.is_set():
                layout["header"].update(self.generate_header())
                layout["activity"].update(self.generate_activity())
                layout["packets"].update(self.generate_packets())
                layout["devices"].update(self.generate_devices())
                layout["stats"].update(self.generate_stats())
                layout["intel"].update(self.generate_intel())
                layout["footer"].update(self.generate_footer())
                time.sleep(0.25)
