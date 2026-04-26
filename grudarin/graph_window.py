"""
Grudarin - Force-Directed Graph Visualization Window
Real-time network topology rendered with Pygame.
Shows device names, IPs, MACs, open ports under each node.
Graph updates live as packets are captured.
"""

import math
import random
import time
import os

try:
    import pygame
except ImportError:
    pygame = None


class GraphNode:
    """A node in the force-directed graph."""

    def __init__(self, key, label, x, y):
        self.key = key
        self.label = label
        self.x = x
        self.y = y
        self.vx = 0.0
        self.vy = 0.0
        self.fx = 0.0
        self.fy = 0.0
        self.radius = 14
        self.color = (0, 180, 220)
        self.is_gateway = False
        self.is_broadcast = False
        self.pinned = False
        self.info = {}


class GraphEdge:
    """An edge in the force-directed graph."""

    def __init__(self, src_key, dst_key):
        self.src_key = src_key
        self.dst_key = dst_key
        self.weight = 1
        self.protocols = []


class ForceDirectedLayout:
    """
    Force-directed graph layout engine.
    Coulomb repulsion + Hooke spring attraction + center gravity.
    """

    def __init__(self):
        self.repulsion = 5000.0
        self.spring_k = 0.01
        self.spring_len = 160.0
        self.damping = 0.85
        self.gravity = 0.02
        self.max_vel = 8.0

    def step(self, nodes, edges, cx, cy):
        """Perform one simulation step."""
        nlist = list(nodes.values())
        n = len(nlist)
        if n == 0:
            return

        for nd in nlist:
            nd.fx = 0.0
            nd.fy = 0.0

        # Repulsion (all pairs)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = nlist[i], nlist[j]
                dx = a.x - b.x
                dy = a.y - b.y
                dsq = dx * dx + dy * dy
                if dsq < 1.0:
                    dx = random.uniform(-1, 1)
                    dy = random.uniform(-1, 1)
                    dsq = max(0.01, dx * dx + dy * dy)
                d = math.sqrt(dsq)
                f = self.repulsion / dsq
                fx = (dx / d) * f
                fy = (dy / d) * f
                a.fx += fx
                a.fy += fy
                b.fx -= fx
                b.fy -= fy

        # Spring attraction along edges
        for edge in edges:
            if edge.src_key not in nodes or edge.dst_key not in nodes:
                continue
            a = nodes[edge.src_key]
            b = nodes[edge.dst_key]
            dx = b.x - a.x
            dy = b.y - a.y
            d = math.sqrt(dx * dx + dy * dy)
            if d < 0.01:
                continue
            disp = d - self.spring_len
            wf = min(edge.weight / 10.0, 3.0)
            strength = self.spring_k * (1.0 + wf * 0.3)
            f = strength * disp
            fx = (dx / d) * f
            fy = (dy / d) * f
            a.fx += fx
            a.fy += fy
            b.fx -= fx
            b.fy -= fy

        # Center gravity
        for nd in nlist:
            nd.fx += (cx - nd.x) * self.gravity
            nd.fy += (cy - nd.y) * self.gravity

        # Integrate
        for nd in nlist:
            if nd.pinned:
                nd.vx = nd.vy = 0
                continue
            nd.vx = (nd.vx + nd.fx) * self.damping
            nd.vy = (nd.vy + nd.fy) * self.damping
            spd = math.sqrt(nd.vx * nd.vx + nd.vy * nd.vy)
            if spd > self.max_vel:
                nd.vx = (nd.vx / spd) * self.max_vel
                nd.vy = (nd.vy / spd) * self.max_vel
            nd.x += nd.vx
            nd.y += nd.vy


class GraphWindow:
    """
    Pygame window showing live force-directed network graph.
    Updates in real time as new devices and connections appear.
    Shows IP, MAC, hostname, open ports under each node.
    """

    # Colors
    BG = (18, 18, 24)
    GRID = (28, 28, 36)
    TEXT = (200, 210, 220)
    DIM = (90, 100, 110)
    EDGE_CLR = (55, 65, 85)
    EDGE_ACT = (75, 125, 175)
    ND_DEF = (0, 155, 200)
    ND_GW = (220, 160, 30)
    ND_BC = (100, 100, 120)
    ND_SEL = (255, 75, 75)
    ND_VULN = (200, 50, 50)
    PANEL = (22, 24, 32)
    BORDER = (48, 52, 66)
    ACCENT = (0, 200, 150)
    HDR = (22, 26, 36)
    WARN = (200, 60, 60)

    TITLE = "Grudarin - Live Network Graph"
    FPS = 30

    def __init__(self, network_model, stop_event, notes_writer, session_dir):
        self.model = network_model
        self.stop_event = stop_event
        self.notes = notes_writer
        self.session_dir = session_dir
        self.nodes = {}
        self.edges = []
        self.layout = ForceDirectedLayout()
        self.w = 1280
        self.h = 800
        self.cam_x = 0.0
        self.cam_y = 0.0
        self.zoom = 1.0
        self.drag_node = None
        self.sel_node = None
        self.panning = False
        self.pan_start = None
        self.cam_start = None
        self.paused = False
        self.show_labels = True
        self.show_stats = True
        self.show_mac = True
        self.last_sync = 0.0
        self.snap_count = 0

    def _w2s(self, wx, wy):
        sx = (wx - self.cam_x) * self.zoom + self.w / 2
        sy = (wy - self.cam_y) * self.zoom + self.h / 2
        return int(sx), int(sy)

    def _s2w(self, sx, sy):
        wx = (sx - self.w / 2) / self.zoom + self.cam_x
        wy = (sy - self.h / 2) / self.zoom + self.cam_y
        return wx, wy

    def _hit(self, sx, sy):
        wx, wy = self._s2w(sx, sy)
        best = None
        best_d = 1e9
        for nd in self.nodes.values():
            dx = nd.x - wx
            dy = nd.y - wy
            d = math.sqrt(dx * dx + dy * dy)
            hr = nd.radius / self.zoom + 8
            if d < hr and d < best_d:
                best = nd
                best_d = d
        return best

    def _sync(self):
        now = time.time()
        if now - self.last_sync < 0.4:
            return
        self.last_sync = now
        devs, conns = self.model.get_snapshot()
        cx, cy = self.w / 2, self.h / 2

        for key, info in devs.items():
            if key not in self.nodes:
                a = random.uniform(0, 2 * math.pi)
                r = random.uniform(60, 220)
                nd = GraphNode(key, info["label"], cx + math.cos(a) * r, cy + math.sin(a) * r)
                self.nodes[key] = nd
            nd = self.nodes[key]
            nd.label = info["label"]
            nd.is_gateway = info.get("is_gateway", False)
            nd.is_broadcast = info.get("is_broadcast", False)
            nd.info = info

            if nd.is_gateway:
                nd.color = self.ND_GW
            elif nd.is_broadcast:
                nd.color = self.ND_BC
            else:
                tp = info.get("packets_sent", 0) + info.get("packets_received", 0)
                if tp > 1000:
                    nd.color = (0, 220, 120)
                elif tp > 100:
                    nd.color = (0, 175, 200)
                elif tp > 10:
                    nd.color = (75, 135, 200)
                else:
                    nd.color = self.ND_DEF

            tot = info.get("packets_sent", 0) + info.get("packets_received", 0)
            nd.radius = max(10, min(32, 10 + int(math.log2(tot + 1)) * 2))

        self.edges = []
        for c in conns:
            s, d = c["src"], c["dst"]
            if s in self.nodes and d in self.nodes:
                e = GraphEdge(s, d)
                e.weight = c.get("packet_count", 1)
                e.protocols = c.get("protocols", [])
                self.edges.append(e)

    def _draw_grid(self, sf):
        gs = int(80 * self.zoom)
        if gs < 8:
            return
        ox = int((-self.cam_x * self.zoom + self.w / 2) % gs)
        oy = int((-self.cam_y * self.zoom + self.h / 2) % gs)
        for x in range(ox, self.w, gs):
            pygame.draw.line(sf, self.GRID, (x, 0), (x, self.h), 1)
        for y in range(oy, self.h, gs):
            pygame.draw.line(sf, self.GRID, (0, y), (self.w, y), 1)

    def _draw_edges(self, sf):
        for e in self.edges:
            if e.src_key not in self.nodes or e.dst_key not in self.nodes:
                continue
            a = self.nodes[e.src_key]
            b = self.nodes[e.dst_key]
            p1 = self._w2s(a.x, a.y)
            p2 = self._w2s(b.x, b.y)
            th = max(1, min(4, int(math.log2(e.weight + 1))))
            clr = self.EDGE_ACT if e.weight > 5 else self.EDGE_CLR
            pygame.draw.line(sf, clr, p1, p2, th)

            # Protocol label on edge (at midpoint)
            if self.zoom > 0.5 and e.protocols:
                mx = (p1[0] + p2[0]) // 2
                my = (p1[1] + p2[1]) // 2
                proto = e.protocols[0] if e.protocols else ""
                if proto and self._font_tiny:
                    ts = self._font_tiny.render(proto, True, self.DIM)
                    sf.blit(ts, (mx - ts.get_width() // 2, my - 6))

    def _draw_nodes(self, sf):
        for nd in self.nodes.values():
            sx, sy = self._w2s(nd.x, nd.y)
            r = max(4, int(nd.radius * self.zoom))
            if sx < -80 or sx > self.w + 80 or sy < -80 or sy > self.h + 80:
                continue

            clr = nd.color
            if nd == self.drag_node or (self.sel_node and nd.key == self.sel_node.key):
                clr = self.ND_SEL

            # Glow
            if r > 5:
                pygame.draw.circle(sf, (clr[0] // 5, clr[1] // 5, clr[2] // 5), (sx, sy), r + 5)
            # Body
            pygame.draw.circle(sf, clr, (sx, sy), r)
            # Border
            brd = (min(255, clr[0] + 55), min(255, clr[1] + 55), min(255, clr[2] + 55))
            pygame.draw.circle(sf, brd, (sx, sy), r, 2)
            # Gateway double ring
            if nd.is_gateway:
                pygame.draw.circle(sf, self.ND_GW, (sx, sy), r + 7, 2)

            # Labels below node
            if self.show_labels and self.zoom > 0.3 and self._font_sm:
                info = nd.info
                yoff = sy + r + 8

                # Line 1: hostname or IP
                lbl = nd.label
                if len(lbl) > 20:
                    lbl = lbl[:18] + ".."
                ts = self._font_sm.render(lbl, True, self.TEXT)
                sf.blit(ts, (sx - ts.get_width() // 2, yoff))
                yoff += 13

                # Line 2: MAC address
                if self.show_mac and self.zoom > 0.5:
                    mac = info.get("mac", "")
                    if mac and mac != "unknown":
                        ts = self._font_tiny.render(mac, True, self.DIM)
                        sf.blit(ts, (sx - ts.get_width() // 2, yoff))
                        yoff += 11

                # Line 3: vendor
                if self.zoom > 0.7:
                    vendor = info.get("vendor", "")
                    if vendor:
                        ts = self._font_tiny.render(vendor, True, self.DIM)
                        sf.blit(ts, (sx - ts.get_width() // 2, yoff))
                        yoff += 11

                # Line 4: top ports
                if self.zoom > 0.6:
                    ports = info.get("open_ports", [])
                    if ports:
                        ptxt = ",".join(str(p) for p in ports[:5])
                        if len(ports) > 5:
                            ptxt += "..."
                        ts = self._font_tiny.render("ports:" + ptxt, True, self.DIM)
                        sf.blit(ts, (sx - ts.get_width() // 2, yoff))

    def _draw_hud(self, sf, clock):
        stats = self.model.get_stats()
        # Top bar
        pygame.draw.rect(sf, self.HDR, (0, 0, self.w, 36))
        pygame.draw.line(sf, self.BORDER, (0, 36), (self.w, 36), 1)

        ts = self._font_main.render("GRUDARIN", True, self.ACCENT)
        sf.blit(ts, (12, 8))

        items = [
            f"Pkts:{stats['total_packets']}",
            f"Dev:{stats['total_devices']}",
            f"Links:{stats['total_connections']}",
            f"Data:{self._fb(stats['total_bytes'])}",
            f"FPS:{int(clock.get_fps())}",
        ]
        xo = 150
        for it in items:
            s = self._font_sm.render(it, True, self.DIM)
            sf.blit(s, (xo, 11))
            xo += s.get_width() + 18

        # Live/Paused
        stxt = "PAUSED" if self.paused else "LIVE"
        sclr = self.WARN if self.paused else (0, 200, 120)
        ss = self._font_sm.render(stxt, True, sclr)
        sf.blit(ss, (self.w - ss.get_width() - 12, 11))

        # Bottom bar
        pygame.draw.rect(sf, self.HDR, (0, self.h - 26, self.w, 26))
        pygame.draw.line(sf, self.BORDER, (0, self.h - 26), (self.w, self.h - 26), 1)
        ctrl = (
            "Scroll:Zoom | Drag:Move | RClick:Details | "
            "P:Pause | S:Snap | R:Reset | M:MAC | L:Labels | Q:Quit"
        )
        cs = self._font_tiny.render(ctrl, True, self.DIM)
        sf.blit(cs, (10, self.h - 20))

    def _draw_detail(self, sf):
        if not self.sel_node or not self.sel_node.info:
            return
        info = self.sel_node.info
        pw, ph = 310, 420
        px = self.w - pw - 10
        py = 46
        ps = pygame.Surface((pw, ph))
        ps.set_alpha(230)
        ps.fill(self.PANEL)
        sf.blit(ps, (px, py))
        pygame.draw.rect(sf, self.BORDER, (px, py, pw, ph), 1)

        y = py + 8
        x = px + 10

        def line(lab, val, clr=None):
            nonlocal y
            if clr is None:
                clr = self.TEXT
            sf.blit(self._font_tiny.render(f"{lab}:", True, self.DIM), (x, y))
            sf.blit(self._font_sm.render(str(val), True, clr), (x + 95, y))
            y += 17

        sf.blit(self._font_main.render("Device Details", True, self.ACCENT), (x, y))
        y += 24
        line("IP", info.get("ip", "?"))
        line("MAC", info.get("mac", "?"))
        if info.get("hostname"):
            line("Hostname", info["hostname"])
        if info.get("vendor"):
            line("Vendor", info["vendor"])
        if info.get("os_hint"):
            line("OS Hint", info["os_hint"])
        if info.get("is_gateway"):
            line("Role", "Gateway/Router", self.ND_GW)
        y += 4
        line("Pkts Sent", info.get("packets_sent", 0))
        line("Pkts Recv", info.get("packets_received", 0))
        line("Data Sent", self._fb(info.get("bytes_sent", 0)))
        line("Data Recv", self._fb(info.get("bytes_received", 0)))
        y += 4
        protos = info.get("protocols", [])
        if protos:
            line("Protocols", ", ".join(protos[:6]))
        svcs = info.get("services", [])
        if svcs:
            line("Services", ", ".join(svcs[:6]))
        ports = info.get("open_ports", [])
        if ports:
            line("Ports", ", ".join(str(p) for p in ports[:10]))

    def _draw_proto(self, sf):
        if not self.show_stats:
            return
        stats = self.model.get_stats()
        pc = stats.get("protocol_counts", {})
        if not pc:
            return
        sp = sorted(pc.items(), key=lambda x: x[1], reverse=True)[:6]
        tot = sum(v for _, v in sp) or 1
        px, py = 10, 46
        pw = 185
        ph = 16 + len(sp) * 17
        ps = pygame.Surface((pw, ph))
        ps.set_alpha(200)
        ps.fill(self.PANEL)
        sf.blit(ps, (px, py))
        pygame.draw.rect(sf, self.BORDER, (px, py, pw, ph), 1)
        colors = [
            (0, 200, 150), (0, 155, 220), (220, 155, 30),
            (200, 75, 75), (145, 95, 220), (95, 175, 95),
        ]
        y = py + 6
        for i, (nm, ct) in enumerate(sp):
            pct = ct / tot
            bw = int(pct * 75)
            c = colors[i % len(colors)]
            pygame.draw.rect(sf, c, (px + 6, y + 2, bw, 9))
            lb = self._font_tiny.render(f"{nm}:{ct}", True, self.DIM)
            sf.blit(lb, (px + 88, y))
            y += 17

    @staticmethod
    def _fb(n):
        if n < 1024:
            return f"{n}B"
        if n < 1048576:
            return f"{n/1024:.1f}KB"
        if n < 1073741824:
            return f"{n/1048576:.1f}MB"
        return f"{n/1073741824:.2f}GB"

    def run(self):
        """Main render loop."""
        if pygame is None:
            print("  [error] pygame required for graph. Install: pip install pygame")
            print("  [info] Falling back to headless mode.")
            while not self.stop_event.is_set():
                time.sleep(1)
            return

        pygame.init()
        sf = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE)
        pygame.display.set_caption(self.TITLE)
        clock = pygame.time.Clock()

        try:
            self._font_main = pygame.font.SysFont("monospace", 16, bold=True)
            self._font_sm = pygame.font.SysFont("monospace", 12)
            self._font_tiny = pygame.font.SysFont("monospace", 10)
        except Exception:
            self._font_main = pygame.font.Font(None, 18)
            self._font_sm = pygame.font.Font(None, 14)
            self._font_tiny = pygame.font.Font(None, 11)

        running = True
        while running and not self.stop_event.is_set():
            for ev in pygame.event.get():
                if ev.type == pygame.QUIT:
                    running = False
                elif ev.type == pygame.KEYDOWN:
                    if ev.key in (pygame.K_q, pygame.K_ESCAPE):
                        running = False
                    elif ev.key == pygame.K_p:
                        self.paused = not self.paused
                    elif ev.key == pygame.K_s:
                        self.snap_count += 1
                        fn = f"graph_snapshot_{self.snap_count}.png"
                        self.notes.save_graph_snapshot(sf, fn)
                    elif ev.key == pygame.K_r:
                        for nd in self.nodes.values():
                            nd.x = self.w / 2 + random.uniform(-200, 200)
                            nd.y = self.h / 2 + random.uniform(-200, 200)
                            nd.vx = nd.vy = 0
                        self.cam_x = self.cam_y = 0
                        self.zoom = 1.0
                    elif ev.key == pygame.K_l:
                        self.show_labels = not self.show_labels
                    elif ev.key == pygame.K_m:
                        self.show_mac = not self.show_mac
                    elif ev.key == pygame.K_TAB:
                        self.show_stats = not self.show_stats
                elif ev.type == pygame.MOUSEBUTTONDOWN:
                    if ev.button == 1:
                        nd = self._hit(*ev.pos)
                        if nd:
                            self.drag_node = nd
                            nd.pinned = True
                            self.sel_node = nd
                        else:
                            self.panning = True
                            self.pan_start = ev.pos
                            self.cam_start = (self.cam_x, self.cam_y)
                            self.sel_node = None
                    elif ev.button == 3:
                        nd = self._hit(*ev.pos)
                        self.sel_node = nd
                    elif ev.button == 4:
                        self.zoom = min(5.0, self.zoom * 1.15)
                    elif ev.button == 5:
                        self.zoom = max(0.1, self.zoom / 1.15)
                elif ev.type == pygame.MOUSEBUTTONUP:
                    if ev.button == 1:
                        if self.drag_node:
                            self.drag_node.pinned = False
                            self.drag_node = None
                        self.panning = False
                elif ev.type == pygame.MOUSEMOTION:
                    if self.drag_node:
                        wx, wy = self._s2w(*ev.pos)
                        self.drag_node.x = wx
                        self.drag_node.y = wy
                    elif self.panning and self.pan_start:
                        dx = (ev.pos[0] - self.pan_start[0]) / self.zoom
                        dy = (ev.pos[1] - self.pan_start[1]) / self.zoom
                        self.cam_x = self.cam_start[0] - dx
                        self.cam_y = self.cam_start[1] - dy
                elif ev.type == pygame.MOUSEWHEEL:
                    if ev.y > 0:
                        self.zoom = min(5.0, self.zoom * 1.15)
                    elif ev.y < 0:
                        self.zoom = max(0.1, self.zoom / 1.15)
                elif ev.type == pygame.VIDEORESIZE:
                    self.w = ev.w
                    self.h = ev.h
                    sf = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE)

            # Real-time sync from capture engine
            self._sync()

            # Physics (runs every frame for smooth animation)
            if not self.paused:
                self.layout.step(self.nodes, self.edges, self.w / 2, self.h / 2)

            # Render
            sf.fill(self.BG)
            self._draw_grid(sf)
            self._draw_edges(sf)
            self._draw_nodes(sf)
            self._draw_hud(sf, clock)
            self._draw_proto(sf)
            self._draw_detail(sf)
            pygame.display.flip()
            clock.tick(self.FPS)

        self.stop_event.set()
        pygame.quit()
