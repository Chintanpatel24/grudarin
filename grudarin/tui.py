"""
Grudarin - Terminal User Interface (Rich)
Powerful hacker-style console interface for real-time network spying.
"""

import time
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box

from grudarin import __version__

class SpyTUI:
    """Live TUI for network monitoring."""

    def __init__(self, network_model, stop_event, interface="", target_ssid=""):
        self.model = network_model
        self.stop_event = stop_event
        self.interface = interface
        self.target_ssid = target_ssid or "ANY"
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
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        layout["left"].split_column(
            Layout(name="activity", ratio=2),
            Layout(name="packets", ratio=1)
        )
        layout["right"].split_column(
            Layout(name="stats", size=8),
            Layout(name="targets", ratio=1)
        )
        return layout

    def generate_header(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)

        status = "[bold red]● SPYING[/bold red]" if not self.stop_event.is_set() else "[bold yellow]OFFLINE[/bold yellow]"
        grid.add_row(
            f" [bold cyan]GRUDARIN v{__version__}[/bold cyan]",
            f"[bold white]INTERFACE: {self.interface} | SSID: {self.target_ssid}[/bold white]",
            f"{status}  "
        )
        return Panel(grid, style="white on black", box=box.ASCII)

    def generate_activity(self) -> Panel:
        table = Table(expand=True, box=box.SIMPLE, show_header=True, header_style="bold magenta")
        table.add_column("Time", width=10)
        table.add_column("Source IP", width=15, style="cyan")
        table.add_column("Type", width=12, style="yellow")
        table.add_column("Details", style="green")

        activity, _ = self.model.get_activity_since(0)
        for item in activity[-15:]:
            t = item.get("time", "")[-8:]
            src = item.get("source_ip", "unknown")
            et = item.get("event_type", "activity")
            det = item.get("details", "")
            table.add_row(t, src, et, det[:80])

        return Panel(table, title="[bold green]LIVE ACTIVITY FEED[/bold green]", box=box.ROUNDED, border_style="green")

    def generate_packets(self) -> Panel:
        table = Table(expand=True, box=box.SIMPLE, show_header=True, header_style="bold blue")
        table.add_column("Proto", width=8)
        table.add_column("Source -> Destination", style="white")
        table.add_column("Info", style="dim white")

        packets = self.model.get_recent_packets(limit=10)
        for p in packets:
            proto = p.get("protocol", "IP")
            src = p.get("src_ip", "-")
            dst = p.get("dst_ip", "-")
            info = p.get("info", "")
            table.add_row(proto, f"{src} -> {dst}", info[:70])

        return Panel(table, title="[bold blue]RAW PACKET STREAM[/bold blue]", box=box.ROUNDED, border_style="blue")

    def generate_stats(self) -> Panel:
        stats = self.model.get_stats()
        uptime = int(time.time() - self.start_time)

        text = Text()
        text.append(f" Packets Captured : {stats.get('total_packets', 0)}\n", style="white")
        text.append(f" Data Volume      : {self._fmt_bytes(stats.get('total_bytes', 0))}\n", style="white")
        text.append(f" Active Devices   : {stats.get('total_devices', 0)}\n", style="white")
        text.append(f" Network Links    : {stats.get('total_connections', 0)}\n", style="white")
        text.append(f" Session Uptime   : {uptime}s\n", style="white")

        return Panel(text, title="[bold yellow]SESSION STATS[/bold yellow]", box=box.ROUNDED, border_style="yellow")

    def generate_targets(self) -> Panel:
        table = Table(expand=True, box=box.SIMPLE)
        table.add_column("Device", style="cyan")
        table.add_column("Pkts", justify="right")

        devices, _ = self.model.get_snapshot()
        sorted_devs = sorted(devices.values(), key=lambda x: x.get('packets_sent',0), reverse=True)

        for d in sorted_devs[:12]:
            label = d.get('label') or d.get('ip') or d.get('mac') or "?"
            pkts = d.get('packets_sent', 0) + d.get('packets_received', 0)
            table.add_row(label[:20], str(pkts))

        return Panel(table, title="[bold cyan]TOP TALKERS[/bold cyan]", box=box.ROUNDED, border_style="cyan")

    def generate_footer(self) -> Panel:
        return Panel(
            "[bold white]Press Ctrl+C to Stop Spy Session and Generate Report[/bold white]",
            style="black on red", box=box.ASCII, justify="center"
        )

    def run(self):
        layout = self.make_layout()
        with Live(layout, refresh_per_second=4, screen=True):
            while not self.stop_event.is_set():
                layout["header"].update(self.generate_header())
                layout["activity"].update(self.generate_activity())
                layout["packets"].update(self.generate_packets())
                layout["stats"].update(self.generate_stats())
                layout["targets"].update(self.generate_targets())
                layout["footer"].update(self.generate_footer())
                time.sleep(0.2)
