"""
grudarin.gui.dashboard
Side panel with live packet feed, device list, and session statistics.
"""

import time
from collections import deque
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QTabWidget, QTextEdit, QFrame, QSplitter,
    QSizePolicy, QScrollArea, QPushButton
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPalette, QTextCursor

from core.topology import TopologyGraph, Device


FONT_MONO = QFont("Courier New", 9)
FONT_MONO_SMALL = QFont("Courier New", 8)
FONT_HEADER = QFont("Courier New", 10, QFont.Weight.Bold)

COLOR_PANEL_BG = "#0d1117"
COLOR_SECTION_BG = "#10161f"
COLOR_BORDER = "#1e2d45"
COLOR_ACCENT = "#2d82e6"
COLOR_GATEWAY = "#ffb428"
COLOR_TEXT = "#c8d3e6"
COLOR_DIM = "#5a6678"
COLOR_ALERT = "#e64444"
COLOR_SUCCESS = "#28c87a"


PANEL_STYLE = f"""
QWidget {{
    background: {COLOR_PANEL_BG};
    color: {COLOR_TEXT};
    font-family: "Courier New";
    font-size: 9pt;
}}
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    background: {COLOR_PANEL_BG};
}}
QTabBar::tab {{
    background: {COLOR_SECTION_BG};
    color: {COLOR_DIM};
    padding: 5px 14px;
    border: 1px solid {COLOR_BORDER};
    font-family: "Courier New";
    font-size: 9pt;
}}
QTabBar::tab:selected {{
    background: {COLOR_PANEL_BG};
    color: {COLOR_TEXT};
    border-bottom: 2px solid {COLOR_ACCENT};
}}
QListWidget {{
    background: {COLOR_PANEL_BG};
    border: none;
    color: {COLOR_TEXT};
    font-family: "Courier New";
    font-size: 8pt;
}}
QListWidget::item:selected {{
    background: {COLOR_ACCENT}33;
    color: #ffffff;
}}
QListWidget::item:hover {{
    background: {COLOR_SECTION_BG};
}}
QTextEdit {{
    background: {COLOR_PANEL_BG};
    color: {COLOR_TEXT};
    border: none;
    font-family: "Courier New";
    font-size: 8pt;
}}
QScrollBar:vertical {{
    background: {COLOR_SECTION_BG};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {COLOR_BORDER};
    min-height: 20px;
    border-radius: 4px;
}}
QPushButton {{
    background: {COLOR_SECTION_BG};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
    padding: 4px 10px;
    font-family: "Courier New";
    font-size: 9pt;
}}
QPushButton:hover {{
    background: {COLOR_ACCENT}33;
    border-color: {COLOR_ACCENT};
}}
"""


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


class StatLabel(QLabel):
    def __init__(self, name: str, value: str = "0"):
        super().__init__()
        self._name = name
        self._value = value
        self._refresh()
        self.setFont(FONT_MONO_SMALL)

    def set_value(self, value: str):
        self._value = value
        self._refresh()

    def _refresh(self):
        self.setText(f"{self._name:<14} {self._value}")


class StatsPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(10, 10, 10, 10)

        header = QLabel("SESSION STATISTICS")
        header.setFont(FONT_HEADER)
        header.setStyleSheet(f"color: {COLOR_ACCENT};")
        layout.addWidget(header)

        layout.addWidget(self._sep())

        self.stat_duration = StatLabel("Duration")
        self.stat_devices = StatLabel("Devices")
        self.stat_links = StatLabel("Links")
        self.stat_packets = StatLabel("Packets")
        self.stat_bytes = StatLabel("Data")
        self.stat_pps = StatLabel("Pkts/sec")
        self.stat_interface = StatLabel("Interface")
        self.stat_output = StatLabel("Output")

        for w in [
            self.stat_duration, self.stat_devices, self.stat_links,
            self.stat_packets, self.stat_bytes, self.stat_pps,
            self._sep(),
            self.stat_interface, self.stat_output,
        ]:
            layout.addWidget(w)

        layout.addStretch()

    def _sep(self) -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color: {COLOR_BORDER};")
        return line

    def update_stats(self, topology, logger, iface: str, output_dir: str, start_time: float):
        elapsed = int(time.time() - start_time)
        h = elapsed // 3600
        m = (elapsed % 3600) // 60
        s = elapsed % 60
        self.stat_duration.set_value(f"{h:02d}:{m:02d}:{s:02d}")
        self.stat_devices.set_value(str(topology.device_count()))
        self.stat_links.set_value(str(topology.link_count()))
        pkt = logger.get_packet_count()
        self.stat_packets.set_value(str(pkt))
        self.stat_bytes.set_value(fmt_bytes(logger.get_byte_count()))
        pps = round(pkt / max(elapsed, 1), 1)
        self.stat_pps.set_value(str(pps))
        self.stat_interface.set_value(iface)
        self.stat_output.set_value(output_dir[-24:] if len(output_dir) > 24 else output_dir)


class DevicePanel(QWidget):
    device_selected = pyqtSignal(object)

    def __init__(self, topology: TopologyGraph):
        super().__init__()
        self.topology = topology
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QLabel("  DEVICES")
        header.setFont(FONT_HEADER)
        header.setStyleSheet(f"color: {COLOR_ACCENT}; padding: 8px 0;")
        layout.addWidget(header)

        self.list = QListWidget()
        self.list.itemClicked.connect(self._on_item_click)
        layout.addWidget(self.list)

        self._mac_to_row: dict = {}

    def refresh(self):
        devices = self.topology.all_devices()
        self.list.clear()
        self._mac_to_row.clear()

        for dev in sorted(devices, key=lambda d: d.ip or d.mac):
            label = self._device_label(dev)
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, dev.mac)
            if dev.node_type == "gateway":
                item.setForeground(QColor(COLOR_GATEWAY))
            self.list.addItem(item)

    def _device_label(self, dev: Device) -> str:
        name = dev.hostname.split(".")[0] if dev.hostname else dev.ip or dev.mac[-8:]
        ip = dev.ip or "???.???.???.???"
        tag = "[GW]" if dev.node_type == "gateway" else "    "
        return f"{tag} {ip:<16} {name[:18]}"

    def _on_item_click(self, item: QListWidgetItem):
        mac = item.data(Qt.ItemDataRole.UserRole)
        dev = self.topology.get_device_by_mac(mac)
        self.device_selected.emit(dev)

    def highlight_device(self, mac: str):
        for i in range(self.list.count()):
            item = self.list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == mac:
                self.list.setCurrentItem(item)
                break


class PacketFeedPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QLabel("  LIVE PACKET FEED")
        header.setFont(FONT_HEADER)
        header.setStyleSheet(f"color: {COLOR_ACCENT}; padding: 8px 0;")
        layout.addWidget(header)

        self.feed = QTextEdit()
        self.feed.setReadOnly(True)
        self.feed.setFont(FONT_MONO_SMALL)
        self.feed.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.feed)

        self._paused = False
        self._buffer = deque(maxlen=2000)

        pause_btn = QPushButton("Pause Feed")
        pause_btn.clicked.connect(self._toggle_pause)
        self._pause_btn = pause_btn
        layout.addWidget(pause_btn)

    def _toggle_pause(self):
        self._paused = not self._paused
        self._pause_btn.setText("Resume Feed" if self._paused else "Pause Feed")

    def add_packet(self, event: dict):
        self._buffer.append(event)
        if not self._paused:
            self._flush()

    def _flush(self):
        if not self._buffer:
            return
        lines = []
        while self._buffer:
            ev = self._buffer.popleft()
            ts = fmt_time(ev.get("time", time.time()))
            proto = ev.get("protocol", "?")
            src_ip = ev.get("src_ip", ev.get("src_mac", "?"))
            dst_ip = ev.get("dst_ip", ev.get("dst_mac", "?"))
            size = ev.get("size", 0)
            src_port = ev.get("src_port", 0)
            dst_port = ev.get("dst_port", 0)

            if src_port or dst_port:
                src_str = f"{src_ip}:{src_port}" if src_port else src_ip
                dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
            else:
                src_str = src_ip
                dst_str = dst_ip

            line = f"{ts}  {proto:<10}  {src_str:<24} -> {dst_str:<24}  {size}B"
            lines.append(line)

        combined = "\n".join(lines)
        self.feed.moveCursor(QTextCursor.MoveOperation.End)
        self.feed.insertPlainText(combined + "\n")
        self.feed.moveCursor(QTextCursor.MoveOperation.End)

        # Trim document if too long
        doc = self.feed.document()
        if doc.blockCount() > 3000:
            cursor = self.feed.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(
                QTextCursor.MoveOperation.Down,
                QTextCursor.MoveMode.KeepAnchor,
                500
            )
            cursor.removeSelectedText()


class DeviceDetailPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        header = QLabel("DEVICE DETAIL")
        header.setFont(FONT_HEADER)
        header.setStyleSheet(f"color: {COLOR_ACCENT};")
        layout.addWidget(header)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFont(FONT_MONO_SMALL)
        layout.addWidget(self.detail)

        self.show_empty()

    def show_empty(self):
        self.detail.setPlainText("Click a device in the graph\nor the device list to inspect.")

    def show_device(self, dev: Device):
        if dev is None:
            self.show_empty()
            return

        protocols = ", ".join(sorted(dev.protocols_seen)) or "-"
        first_seen = fmt_time(dev.first_seen)
        last_seen = fmt_time(dev.last_seen)

        text = f"""MAC Address   : {dev.mac}
IP Address    : {dev.ip or 'unknown'}
Hostname      : {dev.hostname or 'unknown'}
Vendor        : {dev.vendor or 'unknown'}
OS Guess      : {dev.os_guess or 'unknown'}
Node Type     : {dev.node_type}

First Seen    : {first_seen}
Last Seen     : {last_seen}

Packets TX    : {dev.packets_sent}
Packets RX    : {dev.packets_received}
Bytes TX      : {fmt_bytes(dev.bytes_sent)}
Bytes RX      : {fmt_bytes(dev.bytes_received)}

Protocols     : {protocols}
Tags          : {', '.join(dev.tags) or '-'}
"""
        self.detail.setPlainText(text)


class DashboardPanel(QWidget):
    """
    Right-hand panel with tabs: Devices, Packets, Detail, Stats.
    """

    def __init__(self, topology: TopologyGraph, logger, iface: str,
                 output_dir: str, start_time: float):
        super().__init__()
        self.topology = topology
        self.logger = logger
        self.iface = iface
        self.output_dir = output_dir
        self.start_time = start_time

        self.setStyleSheet(PANEL_STYLE)
        self.setMinimumWidth(340)
        self.setMaximumWidth(500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Title bar
        title = QLabel("  grudarin")
        title.setFont(QFont("Courier New", 12, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {COLOR_ACCENT}; padding: 10px 0 6px 0;")
        layout.addWidget(title)

        sub = QLabel("  Network Intelligence Monitor")
        sub.setFont(FONT_MONO_SMALL)
        sub.setStyleSheet(f"color: {COLOR_DIM}; padding-bottom: 6px;")
        layout.addWidget(sub)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {COLOR_BORDER};")
        layout.addWidget(sep)

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.device_panel = DevicePanel(topology)
        self.packet_panel = PacketFeedPanel()
        self.detail_panel = DeviceDetailPanel()
        self.stats_panel = StatsPanel()

        self.tabs.addTab(self.device_panel, "Devices")
        self.tabs.addTab(self.packet_panel, "Packets")
        self.tabs.addTab(self.detail_panel, "Detail")
        self.tabs.addTab(self.stats_panel, "Stats")

        # Auto-refresh timer
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh_timer.start(1000)

        # Fast timer for packet panel
        self._packet_timer = QTimer()
        self._packet_timer.timeout.connect(self.packet_panel._flush)
        self._packet_timer.start(200)

    def _refresh(self):
        self.device_panel.refresh()
        self.stats_panel.update_stats(
            self.topology, self.logger, self.iface, self.output_dir, self.start_time
        )

    def on_packet(self, event: dict):
        self.packet_panel.add_packet(event)

    def on_node_selected(self, dev):
        self.detail_panel.show_device(dev)
        if dev:
            self.device_panel.highlight_device(dev.mac)
            self.tabs.setCurrentWidget(self.detail_panel)

    def on_device_selected(self, dev):
        self.detail_panel.show_device(dev)
        self.tabs.setCurrentWidget(self.detail_panel)
