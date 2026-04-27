"""
grudarin.gui.alert_panel
Live alert feed widget. Shows severity-colored rows for each detected anomaly.
"""

import time
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QPushButton, QFrame, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont, QBrush

from core.alerts import Alert, Severity, AlertEngine


FONT_MONO = QFont("Courier New", 9)
FONT_MONO_SMALL = QFont("Courier New", 8)
FONT_HEADER = QFont("Courier New", 10, QFont.Weight.Bold)

SEVERITY_COLORS = {
    Severity.INFO:     QColor(80,  160, 255),
    Severity.WARN:     QColor(255, 180, 40),
    Severity.ALERT:    QColor(255, 100, 60),
    Severity.CRITICAL: QColor(230, 40,  60),
}

SEVERITY_BG = {
    Severity.INFO:     QColor(80,  160, 255, 20),
    Severity.WARN:     QColor(255, 180, 40,  25),
    Severity.ALERT:    QColor(255, 100, 60,  30),
    Severity.CRITICAL: QColor(230, 40,  60,  40),
}

PANEL_STYLE = """
QWidget {
    background: #0d1117;
    color: #c8d3e6;
    font-family: "Courier New";
    font-size: 9pt;
}
QListWidget {
    background: #0a0c12;
    border: none;
    color: #c8d3e6;
}
QListWidget::item {
    border-bottom: 1px solid #1a2030;
    padding: 3px 6px;
}
QListWidget::item:selected {
    background: #1e2d45;
}
QTextEdit {
    background: #0a0c12;
    color: #c8d3e6;
    border: none;
    font-family: "Courier New";
    font-size: 8pt;
}
QPushButton {
    background: #10161f;
    color: #c8d3e6;
    border: 1px solid #1e2d45;
    padding: 3px 10px;
    font-family: "Courier New";
    font-size: 8pt;
}
QPushButton:hover {
    background: #1e2d45;
}
"""


class AlertSignalRelay(QObject):
    """Thread-safe relay for alert events into Qt main thread."""
    new_alert = pyqtSignal(object)


class AlertPanel(QWidget):
    """
    Full alert panel: live list + detail view + stats bar.
    """

    alert_count_changed = pyqtSignal(int)

    def __init__(self, alert_engine: AlertEngine):
        super().__init__()
        self.alert_engine = alert_engine
        self.setStyleSheet(PANEL_STYLE)

        self._relay = AlertSignalRelay()
        self._relay.new_alert.connect(self._on_alert_received)
        alert_engine.add_callback(lambda a: self._relay.new_alert.emit(a))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header_row = QHBoxLayout()
        header_row.setContentsMargins(8, 8, 8, 6)
        title = QLabel("ALERTS")
        title.setFont(FONT_HEADER)
        title.setStyleSheet("color: #e64444;")
        header_row.addWidget(title)
        header_row.addStretch()

        self._count_label = QLabel("0 alerts")
        self._count_label.setFont(FONT_MONO_SMALL)
        self._count_label.setStyleSheet("color: #5a6678;")
        header_row.addWidget(self._count_label)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear)
        header_row.addWidget(clear_btn)

        layout.addLayout(header_row)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #1e2d45;")
        layout.addWidget(sep)

        # Severity filter bar
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(6, 4, 6, 4)
        filter_row.setSpacing(4)
        self._filters = {}
        for sev in Severity:
            btn = QPushButton(sev.value)
            btn.setCheckable(True)
            btn.setChecked(True)
            color = SEVERITY_COLORS[sev].name()
            btn.setStyleSheet(
                f"QPushButton {{ color: {color}; border: 1px solid {color}44; }}"
                f"QPushButton:checked {{ background: {color}22; border-color: {color}; }}"
            )
            btn.clicked.connect(self._apply_filter)
            self._filters[sev] = btn
            filter_row.addWidget(btn)
        layout.addLayout(filter_row)

        # Alert list
        self._list = QListWidget()
        self._list.setFont(FONT_MONO_SMALL)
        self._list.currentItemChanged.connect(self._on_item_changed)
        layout.addWidget(self._list, stretch=3)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("color: #1e2d45;")
        layout.addWidget(sep2)

        # Detail view
        detail_label = QLabel("  DETAIL")
        detail_label.setFont(FONT_MONO_SMALL)
        detail_label.setStyleSheet("color: #5a6678; padding: 4px 0;")
        layout.addWidget(detail_label)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(110)
        layout.addWidget(self._detail, stretch=1)

        # Stats footer
        self._stats_label = QLabel("  No alerts yet.")
        self._stats_label.setFont(FONT_MONO_SMALL)
        self._stats_label.setStyleSheet("color: #5a6678; padding: 4px 0;")
        layout.addWidget(self._stats_label)

        self._all_alerts = []
        self._stats = {sev: 0 for sev in Severity}

    def _on_alert_received(self, alert: Alert):
        self._all_alerts.append(alert)
        self._stats[alert.severity] += 1
        self._add_to_list(alert)
        self._update_stats()
        self.alert_count_changed.emit(len(self._all_alerts))

    def _add_to_list(self, alert: Alert):
        sev = alert.severity
        if not self._filters[sev].isChecked():
            return

        ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
        text = f"[{ts}] {sev.value:<8}  {alert.title}"

        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, alert)
        item.setForeground(QBrush(SEVERITY_COLORS[sev]))
        item.setBackground(QBrush(SEVERITY_BG[sev]))
        self._list.addItem(item)
        self._list.scrollToBottom()

    def _on_item_changed(self, current, previous):
        if current is None:
            self._detail.clear()
            return
        alert = current.data(Qt.ItemDataRole.UserRole)
        if alert:
            ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            text = (
                f"Time     : {ts}\n"
                f"Severity : {alert.severity.value}\n"
                f"Rule     : {alert.rule}\n"
                f"Title    : {alert.title}\n"
                f"MAC      : {alert.mac or '-'}\n"
                f"IP       : {alert.ip or '-'}\n"
                f"\nDetail:\n{alert.detail}"
            )
            self._detail.setPlainText(text)

    def _apply_filter(self):
        self._list.clear()
        for alert in self._all_alerts:
            if self._filters[alert.severity].isChecked():
                self._add_to_list(alert)

    def _clear(self):
        self._list.clear()
        self._detail.clear()
        self._all_alerts.clear()
        self._stats = {sev: 0 for sev in Severity}
        self._update_stats()
        self.alert_count_changed.emit(0)

    def _update_stats(self):
        total = len(self._all_alerts)
        parts = []
        for sev in Severity:
            c = self._stats[sev]
            if c > 0:
                parts.append(f"{sev.value}: {c}")
        self._count_label.setText(f"{total} alert{'s' if total != 1 else ''}")
        self._stats_label.setText("  " + "  |  ".join(parts) if parts else "  No alerts yet.")
