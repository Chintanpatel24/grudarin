"""
grudarin.gui.graph_window
Force-directed graph visualization of the live network topology.
Renders in a PyQt6 window with physics simulation (Barnes-Hut inspired).
No external rendering deps - pure Python canvas drawing.
"""

import math
import time
import random
import threading

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QFrame
from PyQt6.QtCore import Qt, QTimer, QPointF, QRectF, pyqtSignal, QObject
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QRadialGradient,
    QLinearGradient, QPainterPath, QFontMetrics
)

from core.topology import TopologyGraph, Device, Link


# ---- Color palette ----
COLOR_BG = QColor(10, 12, 18)
COLOR_BG_GRID = QColor(20, 24, 35)
COLOR_NODE_HOST = QColor(45, 130, 230)
COLOR_NODE_GATEWAY = QColor(255, 180, 40)
COLOR_NODE_UNKNOWN = QColor(90, 90, 110)
COLOR_NODE_HIGHLIGHT = QColor(80, 220, 160)
COLOR_EDGE = QColor(60, 80, 120)
COLOR_EDGE_ACTIVE = QColor(80, 160, 255)
COLOR_LABEL = QColor(200, 210, 230)
COLOR_LABEL_DIM = QColor(100, 110, 130)
COLOR_TOOLTIP_BG = QColor(20, 26, 40, 230)
COLOR_TOOLTIP_BORDER = QColor(60, 90, 150)
COLOR_PULSE = QColor(80, 200, 255, 80)

# Font
FONT_NODE = QFont("Courier New", 8)
FONT_NODE_BOLD = QFont("Courier New", 8, QFont.Weight.Bold)
FONT_TOOLTIP = QFont("Courier New", 9)

NODE_RADIUS_HOST = 14
NODE_RADIUS_GATEWAY = 20
REPULSION = 8000.0
ATTRACTION = 0.04
DAMPING = 0.85
CENTER_GRAVITY = 0.008
MIN_DISTANCE = 60.0
MAX_VELOCITY = 120.0
SIMULATION_STEPS_PER_FRAME = 3


class GraphNode:
    def __init__(self, mac: str, device: Device, x: float, y: float):
        self.mac = mac
        self.device = device
        self.x = x
        self.y = y
        self.vx = random.uniform(-2, 2)
        self.vy = random.uniform(-2, 2)
        self.fx = 0.0
        self.fy = 0.0
        self.pinned = False
        self.radius = NODE_RADIUS_GATEWAY if device.node_type == "gateway" else NODE_RADIUS_HOST
        self.pulse_phase = random.uniform(0, math.pi * 2)
        self.activity_glow = 0.0  # 0..1, decays

    def label(self) -> str:
        dev = self.device
        if dev.hostname and dev.hostname != dev.ip:
            name = dev.hostname.split(".")[0]
            return name[:14]
        if dev.ip:
            return dev.ip
        return dev.mac[-8:]

    def color(self) -> QColor:
        if self.device.node_type == "gateway":
            return COLOR_NODE_GATEWAY
        if self.activity_glow > 0.3:
            return COLOR_NODE_HIGHLIGHT.lighter(int(100 + self.activity_glow * 30))
        return COLOR_NODE_HOST


class GraphEdge:
    def __init__(self, src_mac: str, dst_mac: str, link: Link):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.link = link
        self.activity = 0.0  # 0..1, decays


class ForceGraph(QWidget):
    """
    Custom widget that renders and simulates the force-directed graph.
    """

    node_selected = pyqtSignal(object)  # emits Device or None

    def __init__(self, topology: TopologyGraph, parent=None):
        super().__init__(parent)
        self.topology = topology
        self.setMinimumSize(700, 500)

        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[tuple, GraphEdge] = {}
        self._lock = threading.Lock()

        self._selected_mac = None
        self._hover_mac = None
        self._drag_mac = None
        self._drag_offset = QPointF(0, 0)

        self._pan_x = 0.0
        self._pan_y = 0.0
        self._zoom = 1.0
        self._panning = False
        self._pan_start = None

        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        self._sim_timer = QTimer(self)
        self._sim_timer.timeout.connect(self._step)
        self._sim_timer.start(33)  # ~30fps

        self._sync_timer = QTimer(self)
        self._sync_timer.timeout.connect(self._sync_topology)
        self._sync_timer.start(500)  # sync with topology every 500ms

        self._frame_count = 0
        self._last_fps_time = time.time()
        self._fps = 0.0

    # ---- Topology sync ----

    def _sync_topology(self):
        devices, links = self.topology.snapshot()
        cx = self.width() / 2
        cy = self.height() / 2

        with self._lock:
            # Add new nodes
            for dev in devices:
                if dev.mac not in self._nodes:
                    angle = random.uniform(0, math.pi * 2)
                    radius = random.uniform(80, 200)
                    node = GraphNode(
                        mac=dev.mac,
                        device=dev,
                        x=cx + math.cos(angle) * radius,
                        y=cy + math.sin(angle) * radius,
                    )
                    self._nodes[dev.mac] = node
                else:
                    self._nodes[dev.mac].device = dev

            # Add new edges
            for link in links:
                key = tuple(sorted([link.src_mac, link.dst_mac]))
                if key not in self._edges:
                    edge = GraphEdge(link.src_mac, link.dst_mac, link)
                    self._edges[key] = edge
                else:
                    old_count = self._edges[key].link.packet_count
                    new_count = link.packet_count
                    if new_count > old_count:
                        self._edges[key].activity = 1.0
                    self._edges[key].link = link

    def mark_activity(self, mac: str):
        with self._lock:
            if mac in self._nodes:
                self._nodes[mac].activity_glow = 1.0

    # ---- Physics simulation ----

    def _step(self):
        for _ in range(SIMULATION_STEPS_PER_FRAME):
            self._simulate()
        self._decay_effects()
        self.update()

        # FPS counter
        self._frame_count += 1
        now = time.time()
        if now - self._last_fps_time >= 1.0:
            self._fps = self._frame_count / (now - self._last_fps_time)
            self._frame_count = 0
            self._last_fps_time = now

    def _simulate(self):
        with self._lock:
            nodes = list(self._nodes.values())
            edges = list(self._edges.values())

        if not nodes:
            return

        cx = self.width() / 2 + self._pan_x
        cy = self.height() / 2 + self._pan_y

        # Reset forces
        for node in nodes:
            node.fx = 0.0
            node.fy = 0.0

        # Repulsion: O(n^2), acceptable for < 500 nodes
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                a = nodes[i]
                b = nodes[j]
                dx = a.x - b.x
                dy = a.y - b.y
                dist2 = max(dx * dx + dy * dy, 1.0)
                dist = math.sqrt(dist2)
                if dist < MIN_DISTANCE:
                    dist = MIN_DISTANCE
                force = REPULSION / dist2
                fx = force * dx / dist
                fy = force * dy / dist
                a.fx += fx
                a.fy += fy
                b.fx -= fx
                b.fy -= fy

        # Attraction: spring forces along edges
        node_map = {n.mac: n for n in nodes}
        for edge in edges:
            a = node_map.get(edge.src_mac)
            b = node_map.get(edge.dst_mac)
            if a is None or b is None:
                continue
            dx = b.x - a.x
            dy = b.y - a.y
            dist = max(math.sqrt(dx * dx + dy * dy), 1.0)
            target = 150.0
            force = ATTRACTION * (dist - target)
            fx = force * dx / dist
            fy = force * dy / dist
            a.fx += fx
            a.fy += fy
            b.fx -= fx
            b.fy -= fy

        # Center gravity
        for node in nodes:
            node.fx += (cx - node.x) * CENTER_GRAVITY
            node.fy += (cy - node.y) * CENTER_GRAVITY

        # Integrate
        for node in nodes:
            if node.pinned or node.mac == self._drag_mac:
                continue
            node.vx = (node.vx + node.fx) * DAMPING
            node.vy = (node.vy + node.fy) * DAMPING
            speed = math.sqrt(node.vx ** 2 + node.vy ** 2)
            if speed > MAX_VELOCITY:
                scale = MAX_VELOCITY / speed
                node.vx *= scale
                node.vy *= scale
            node.x += node.vx
            node.y += node.vy

    def _decay_effects(self):
        with self._lock:
            for node in self._nodes.values():
                if node.activity_glow > 0:
                    node.activity_glow = max(0.0, node.activity_glow - 0.05)
                node.pulse_phase += 0.05
            for edge in self._edges.values():
                if edge.activity > 0:
                    edge.activity = max(0.0, edge.activity - 0.04)

    # ---- Rendering ----

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.fillRect(self.rect(), COLOR_BG)
        self._draw_grid(painter)

        with self._lock:
            nodes = dict(self._nodes)
            edges = dict(self._edges)

        if not nodes:
            self._draw_empty_state(painter)
            painter.end()
            return

        # Transform
        painter.save()
        painter.translate(self.width() / 2 + self._pan_x, self.height() / 2 + self._pan_y)
        painter.scale(self._zoom, self._zoom)
        painter.translate(-self.width() / 2, -self.height() / 2)

        self._draw_edges(painter, nodes, edges)
        self._draw_nodes(painter, nodes)

        painter.restore()

        # Overlay HUD
        self._draw_hud(painter, nodes, edges)

        # Tooltip for hovered node
        if self._hover_mac and self._hover_mac in nodes:
            self._draw_tooltip(painter, nodes[self._hover_mac])

        painter.end()

    def _draw_grid(self, painter: QPainter):
        spacing = 40
        pen = QPen(COLOR_BG_GRID)
        pen.setWidth(1)
        painter.setPen(pen)
        for x in range(0, self.width(), spacing):
            painter.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), spacing):
            painter.drawLine(0, y, self.width(), y)

    def _draw_edges(self, painter: QPainter, nodes: dict, edges: dict):
        for edge in edges.values():
            src = nodes.get(edge.src_mac)
            dst = nodes.get(edge.dst_mac)
            if src is None or dst is None:
                continue

            is_active = edge.activity > 0.1
            is_selected = (
                self._selected_mac in (edge.src_mac, edge.dst_mac)
            )

            if is_active:
                color = QColor(
                    int(COLOR_EDGE_ACTIVE.red() * edge.activity + COLOR_EDGE.red() * (1 - edge.activity)),
                    int(COLOR_EDGE_ACTIVE.green() * edge.activity + COLOR_EDGE.green() * (1 - edge.activity)),
                    int(COLOR_EDGE_ACTIVE.blue() * edge.activity + COLOR_EDGE.blue() * (1 - edge.activity)),
                )
            elif is_selected:
                color = COLOR_EDGE_ACTIVE
            else:
                color = COLOR_EDGE

            width = max(1, min(3, 1 + math.log10(max(edge.link.packet_count, 1))))
            pen = QPen(color, width)
            painter.setPen(pen)
            painter.drawLine(int(src.x), int(src.y), int(dst.x), int(dst.y))

            # Protocol label on edge midpoint
            mx = (src.x + dst.x) / 2
            my = (src.y + dst.y) / 2
            if is_selected or is_active:
                painter.setFont(FONT_NODE)
                painter.setPen(QPen(COLOR_LABEL_DIM))
                painter.drawText(QPointF(mx + 4, my - 4), edge.link.protocol)

    def _draw_nodes(self, painter: QPainter, nodes: dict):
        for node in nodes.values():
            x, y = int(node.x), int(node.y)
            r = node.radius
            color = node.color()
            is_selected = node.mac == self._selected_mac
            is_hover = node.mac == self._hover_mac

            # Activity pulse ring
            if node.activity_glow > 0.1:
                pulse_r = int(r + 10 * node.activity_glow)
                pulse_color = QColor(COLOR_PULSE)
                pulse_color.setAlpha(int(80 * node.activity_glow))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QBrush(pulse_color))
                painter.drawEllipse(QPointF(node.x, node.y), pulse_r, pulse_r)

            # Selection ring
            if is_selected:
                pen = QPen(COLOR_NODE_HIGHLIGHT, 3)
                painter.setPen(pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawEllipse(QPointF(node.x, node.y), r + 5, r + 5)

            # Hover ring
            if is_hover and not is_selected:
                pen = QPen(color.lighter(150), 2)
                painter.setPen(pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawEllipse(QPointF(node.x, node.y), r + 4, r + 4)

            # Node body with gradient
            gradient = QRadialGradient(
                QPointF(node.x - r * 0.3, node.y - r * 0.3),
                r * 1.5
            )
            gradient.setColorAt(0, color.lighter(140))
            gradient.setColorAt(1, color.darker(140))
            painter.setBrush(QBrush(gradient))

            border_color = color.lighter(160) if is_selected or is_hover else color.lighter(120)
            painter.setPen(QPen(border_color, 1.5))
            painter.drawEllipse(QPointF(node.x, node.y), r, r)

            # Gateway inner dot
            if node.device.node_type == "gateway":
                painter.setBrush(QBrush(QColor(255, 255, 255, 120)))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(QPointF(node.x, node.y), 4, 4)

            # Label below node
            font = FONT_NODE_BOLD if is_selected else FONT_NODE
            painter.setFont(font)
            label = node.label()
            fm = QFontMetrics(font)
            lw = fm.horizontalAdvance(label)
            painter.setPen(QPen(COLOR_LABEL if is_selected or is_hover else COLOR_LABEL_DIM))
            painter.drawText(
                QPointF(node.x - lw / 2, node.y + r + 13),
                label
            )

    def _draw_tooltip(self, painter: QPainter, node: GraphNode):
        dev = node.device
        lines = [
            f"MAC      : {dev.mac}",
            f"IP       : {dev.ip or 'unknown'}",
            f"Hostname : {dev.hostname or 'unknown'}",
            f"Vendor   : {dev.vendor or 'unknown'}",
            f"OS       : {dev.os_guess or 'unknown'}",
            f"Type     : {dev.node_type}",
            f"TX Pkts  : {dev.packets_sent}",
            f"RX Pkts  : {dev.packets_received}",
            f"TX Bytes : {dev.bytes_sent}",
            f"RX Bytes : {dev.bytes_received}",
            f"Protocols: {', '.join(sorted(dev.protocols_seen)) or '-'}",
        ]

        fm = QFontMetrics(FONT_TOOLTIP)
        line_h = fm.height() + 3
        w = max(fm.horizontalAdvance(l) for l in lines) + 20
        h = len(lines) * line_h + 16

        # Position tooltip near cursor but keep in bounds
        cx = self.mapFromGlobal(self.cursor().pos())
        tx = cx.x() + 20
        ty = cx.y() - h // 2
        tx = max(4, min(tx, self.width() - w - 4))
        ty = max(4, min(ty, self.height() - h - 4))

        rect = QRectF(tx, ty, w, h)
        painter.setBrush(QBrush(COLOR_TOOLTIP_BG))
        painter.setPen(QPen(COLOR_TOOLTIP_BORDER, 1))
        painter.drawRoundedRect(rect, 4, 4)

        painter.setFont(FONT_TOOLTIP)
        painter.setPen(QPen(COLOR_LABEL))
        for i, line in enumerate(lines):
            painter.drawText(
                QPointF(tx + 10, ty + 12 + i * line_h + fm.ascent()),
                line
            )

    def _draw_hud(self, painter: QPainter, nodes: dict, edges: dict):
        painter.setFont(FONT_NODE)
        painter.setPen(QPen(COLOR_LABEL_DIM))
        hud = (
            f"Devices: {len(nodes)}   Links: {len(edges)}   "
            f"FPS: {self._fps:.0f}   Zoom: {self._zoom:.1f}x"
        )
        painter.drawText(QPointF(10, self.height() - 10), hud)

        # Controls hint
        hint = "Drag nodes | Scroll to zoom | Right-drag to pan | Click to inspect"
        fm = QFontMetrics(FONT_NODE)
        painter.drawText(
            QPointF(self.width() - fm.horizontalAdvance(hint) - 10, self.height() - 10),
            hint
        )

    def _draw_empty_state(self, painter: QPainter):
        painter.setFont(QFont("Courier New", 13))
        painter.setPen(QPen(COLOR_LABEL_DIM))
        lines = [
            "grudarin",
            "",
            "Waiting for network data...",
            "Ensure the interface is active and you have root privileges.",
        ]
        fm = QFontMetrics(painter.font())
        total_h = len(lines) * (fm.height() + 6)
        start_y = (self.height() - total_h) / 2
        for i, line in enumerate(lines):
            w = fm.horizontalAdvance(line)
            painter.drawText(
                QPointF((self.width() - w) / 2, start_y + i * (fm.height() + 6)),
                line
            )

    # ---- Input handling ----

    def _screen_to_graph(self, pos: QPointF) -> QPointF:
        """Convert screen coordinates to graph coordinates."""
        gx = (pos.x() - self.width() / 2 - self._pan_x) / self._zoom + self.width() / 2
        gy = (pos.y() - self.height() / 2 - self._pan_y) / self._zoom + self.height() / 2
        return QPointF(gx, gy)

    def _node_at(self, gpos: QPointF) -> str:
        """Return MAC of node at graph position, or None."""
        with self._lock:
            nodes = list(self._nodes.values())
        best = None
        best_dist = float("inf")
        for node in nodes:
            dx = node.x - gpos.x()
            dy = node.y - gpos.y()
            dist = math.sqrt(dx * dx + dy * dy)
            if dist <= node.radius + 4 and dist < best_dist:
                best_dist = dist
                best = node.mac
        return best

    def mousePressEvent(self, event):
        gpos = self._screen_to_graph(QPointF(event.pos()))
        hit_mac = self._node_at(gpos)

        if event.button() == Qt.MouseButton.LeftButton:
            if hit_mac:
                self._drag_mac = hit_mac
                with self._lock:
                    node = self._nodes.get(hit_mac)
                if node:
                    self._drag_offset = QPointF(node.x - gpos.x(), node.y - gpos.y())
                self._selected_mac = hit_mac
                with self._lock:
                    dev = self._nodes[hit_mac].device if hit_mac in self._nodes else None
                self.node_selected.emit(dev)
            else:
                self._selected_mac = None
                self.node_selected.emit(None)

        elif event.button() == Qt.MouseButton.RightButton:
            self._panning = True
            self._pan_start = event.pos()

    def mouseMoveEvent(self, event):
        gpos = self._screen_to_graph(QPointF(event.pos()))

        if self._drag_mac:
            with self._lock:
                node = self._nodes.get(self._drag_mac)
            if node:
                node.x = gpos.x() + self._drag_offset.x()
                node.y = gpos.y() + self._drag_offset.y()
                node.vx = 0
                node.vy = 0

        elif self._panning and self._pan_start:
            dx = event.pos().x() - self._pan_start.x()
            dy = event.pos().y() - self._pan_start.y()
            self._pan_x += dx
            self._pan_y += dy
            self._pan_start = event.pos()

        else:
            hit = self._node_at(gpos)
            self._hover_mac = hit

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_mac = None
        elif event.button() == Qt.MouseButton.RightButton:
            self._panning = False
            self._pan_start = None

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        factor = 1.1 if delta > 0 else 0.9
        self._zoom = max(0.2, min(5.0, self._zoom * factor))

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Space:
            # Reset view
            self._pan_x = 0
            self._pan_y = 0
            self._zoom = 1.0
        elif event.key() == Qt.Key.Key_Escape:
            self._selected_mac = None
            self.node_selected.emit(None)
