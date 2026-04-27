"""
grudarin.gui.app
Main application window. Wires together the force-directed graph,
the dashboard panel, the packet capture engine, and the logger.
"""

import sys
import time
import threading

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout,
    QSplitter, QStatusBar, QLabel, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon

from core.topology import TopologyGraph
from core.capture import PacketCapture
from core.logger import SessionLogger
from gui.graph_window import ForceGraph
from gui.dashboard import DashboardPanel


class PacketEventRelay(QObject):
    """Thread-safe relay: moves packet events from capture thread to Qt main thread."""
    packet_ready = pyqtSignal(dict)
    topology_event = pyqtSignal(str, dict)


WINDOW_STYLE = """
QMainWindow {
    background: #0a0c12;
}
QStatusBar {
    background: #0d1117;
    color: #5a6678;
    font-family: "Courier New";
    font-size: 8pt;
    border-top: 1px solid #1e2d45;
}
QSplitter::handle {
    background: #1e2d45;
    width: 2px;
}
"""


def launch_app(iface: str, output_dir: str, duration: int):
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("grudarin")
    app.setOrganizationName("grudarin")

    # Dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(10, 12, 18))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(200, 210, 230))
    palette.setColor(QPalette.ColorRole.Base, QColor(13, 17, 23))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(16, 22, 31))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(20, 26, 40))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(200, 210, 230))
    palette.setColor(QPalette.ColorRole.Text, QColor(200, 210, 230))
    palette.setColor(QPalette.ColorRole.Button, QColor(16, 22, 31))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(200, 210, 230))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(45, 130, 230))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)

    window = MainWindow(iface, output_dir, duration)
    window.show()

    sys.exit(app.exec())


class MainWindow(QMainWindow):

    def __init__(self, iface: str, output_dir: str, duration: int):
        super().__init__()
        self.iface = iface
        self.output_dir = output_dir
        self.duration = duration
        self.start_time = time.time()

        self.setWindowTitle(f"grudarin  |  {iface}  |  {output_dir}")
        self.setMinimumSize(1100, 650)
        self.resize(1400, 800)
        self.setStyleSheet(WINDOW_STYLE)

        # Core objects
        self.topology = TopologyGraph()
        self.logger = SessionLogger(output_dir, iface)

        # Event relay
        self.relay = PacketEventRelay()
        self.relay.packet_ready.connect(self._on_packet_qt)
        self.relay.topology_event.connect(self._on_topology_event_qt)

        # Topology callbacks
        self.topology.add_change_callback(
            lambda ev, data: self.relay.topology_event.emit(ev, data)
        )

        # Build UI
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root_layout.addWidget(splitter)

        # Graph
        self.graph = ForceGraph(self.topology)
        self.graph.node_selected.connect(self._on_node_selected)
        splitter.addWidget(self.graph)

        # Dashboard
        self.dashboard = DashboardPanel(
            self.topology, self.logger, iface, output_dir, self.start_time
        )
        self.dashboard.device_panel.device_selected.connect(
            self.dashboard.on_device_selected
        )
        splitter.addWidget(self.dashboard)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([950, 420])

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self._status_iface = QLabel(f"Interface: {iface}")
        self._status_packets = QLabel("Packets: 0")
        self._status_devices = QLabel("Devices: 0")
        self._status_msg = QLabel("Initializing capture...")
        self.status_bar.addWidget(self._status_iface)
        self.status_bar.addWidget(self._sep())
        self.status_bar.addWidget(self._status_devices)
        self.status_bar.addWidget(self._sep())
        self.status_bar.addWidget(self._status_packets)
        self.status_bar.addPermanentWidget(self._status_msg)

        # Start capture
        self.capture = PacketCapture(
            iface=iface,
            topology=self.topology,
            packet_callback=lambda ev: self.relay.packet_ready.emit(ev),
        )
        self.logger.start()
        self.capture.start()
        self._status_msg.setText("Capturing...")

        # Duration timer
        if duration > 0:
            QTimer.singleShot(duration * 1000, self._on_duration_expired)

        # Status bar update timer
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_timer.start(1000)

    def _sep(self) -> QLabel:
        lbl = QLabel("  |  ")
        lbl.setStyleSheet("color: #1e2d45;")
        return lbl

    def _on_packet_qt(self, event: dict):
        self.dashboard.on_packet(event)
        self.logger.log_packet(event)
        src_mac = event.get("src_mac", "")
        dst_mac = event.get("dst_mac", "")
        if src_mac:
            self.graph.mark_activity(src_mac)
        if dst_mac:
            self.graph.mark_activity(dst_mac)

    def _on_topology_event_qt(self, event_type: str, data: dict):
        self.logger.log_topology_event(event_type, data)

    def _on_node_selected(self, dev):
        self.dashboard.on_node_selected(dev)

    def _update_status_bar(self):
        self._status_devices.setText(f"Devices: {self.topology.device_count()}")
        self._status_packets.setText(f"Packets: {self.logger.get_packet_count()}")

    def _on_duration_expired(self):
        self._status_msg.setText("Duration complete. Saving report...")
        self._shutdown()
        QMessageBox.information(
            self, "grudarin",
            f"Monitoring session complete.\nReport saved to:\n{self.output_dir}"
        )

    def closeEvent(self, event):
        self._shutdown()
        event.accept()

    def _shutdown(self):
        self._status_timer.stop()
        self.capture.stop()
        self.logger.stop(self.topology)
