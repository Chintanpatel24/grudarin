from __future__ import annotations

import math
import random
import time
import tkinter as tk
from importlib.resources import files
from typing import Any, Callable


class ForceGraphWindow:
    def __init__(
        self,
        snapshot_provider: Callable[[], dict[str, Any]],
        title: str,
        stop_callback: Callable[[], None] | None = None,
        duration_seconds: int | None = None,
    ) -> None:
        self.snapshot_provider = snapshot_provider
        self.stop_callback = stop_callback
        self.duration_seconds = duration_seconds
        self.window_started = time.time()
        self.closed = False

        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("1180x760")
        self.root.configure(bg="#0f172a")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self._set_icon()

        header = tk.Frame(self.root, bg="#111827")
        header.pack(fill="x")

        self.title_label = tk.Label(
            header,
            text=title,
            fg="#e5e7eb",
            bg="#111827",
            font=("Consolas", 13, "bold"),
            anchor="w",
            padx=10,
            pady=8,
        )
        self.title_label.pack(fill="x")

        self.canvas = tk.Canvas(
            self.root,
            bg="#f8fafc",
            highlightthickness=0,
        )
        self.canvas.pack(fill="both", expand=True)

        self.status_label = tk.Label(
            self.root,
            text="Waiting for packets",
            fg="#e5e7eb",
            bg="#111827",
            font=("Consolas", 11),
            anchor="w",
            padx=10,
            pady=8,
        )
        self.status_label.pack(fill="x")

        self.positions: dict[str, list[float]] = {}
        self.velocities: dict[str, list[float]] = {}
        self.node_radius = 18.0

    def _set_icon(self) -> None:
        try:
            icon_path = files("grudarin_app").joinpath("assets/grudarin_logo.ppm")
            icon_image = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, icon_image)
            self.root._icon_ref = icon_image
        except Exception:
            pass

    def run(self) -> None:
        self._tick()
        self.root.mainloop()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.stop_callback is not None:
            try:
                self.stop_callback()
            except Exception:
                pass
        self.root.destroy()

    def _tick(self) -> None:
        if self.closed:
            return

        if self.duration_seconds is not None:
            elapsed = time.time() - self.window_started
            if elapsed >= self.duration_seconds:
                self.close()
                return

        snapshot = self.snapshot_provider()
        self._sync_nodes(snapshot)
        self._apply_physics(snapshot)
        self._draw(snapshot)
        self.root.after(80, self._tick)

    def _sync_nodes(self, snapshot: dict[str, Any]) -> None:
        width = max(900, self.canvas.winfo_width() or 0)
        height = max(600, self.canvas.winfo_height() or 0)
        node_ids = {device["id"] for device in snapshot.get("devices", [])}

        for node_id in node_ids:
            if node_id not in self.positions:
                self.positions[node_id] = [
                    random.uniform(width * 0.25, width * 0.75),
                    random.uniform(height * 0.25, height * 0.75),
                ]
                self.velocities[node_id] = [0.0, 0.0]

        stale_ids = [node_id for node_id in self.positions if node_id not in node_ids]
        for node_id in stale_ids:
            self.positions.pop(node_id, None)
            self.velocities.pop(node_id, None)

    def _apply_physics(self, snapshot: dict[str, Any]) -> None:
        devices = snapshot.get("devices", [])
        flows = snapshot.get("flows", [])
        if not devices:
            return

        width = max(900, self.canvas.winfo_width() or 0)
        height = max(600, self.canvas.winfo_height() or 0)
        center_x = width / 2.0
        center_y = height / 2.0
        device_lookup = {device["id"]: device for device in devices}
        node_ids = [device["id"] for device in devices]

        for node_id in node_ids:
            velocity = self.velocities.setdefault(node_id, [0.0, 0.0])
            velocity[0] *= 0.88
            velocity[1] *= 0.88

        repulsion_strength = 26000.0
        for index, first_id in enumerate(node_ids):
            for second_id in node_ids[index + 1 :]:
                first_position = self.positions[first_id]
                second_position = self.positions[second_id]
                delta_x = first_position[0] - second_position[0]
                delta_y = first_position[1] - second_position[1]
                distance_sq = max(60.0, delta_x * delta_x + delta_y * delta_y)
                distance = math.sqrt(distance_sq)
                force = repulsion_strength / distance_sq
                force_x = force * (delta_x / distance)
                force_y = force * (delta_y / distance)
                self.velocities[first_id][0] += force_x
                self.velocities[first_id][1] += force_y
                self.velocities[second_id][0] -= force_x
                self.velocities[second_id][1] -= force_y

        spring_strength = 0.012
        preferred_length = 150.0
        for flow in flows:
            src_id = flow.get("src_id")
            dst_id = flow.get("dst_id")
            if src_id not in self.positions or dst_id not in self.positions:
                continue
            source_position = self.positions[src_id]
            target_position = self.positions[dst_id]
            delta_x = target_position[0] - source_position[0]
            delta_y = target_position[1] - source_position[1]
            distance = max(1.0, math.hypot(delta_x, delta_y))
            stretch = distance - preferred_length
            force = spring_strength * stretch
            force_x = force * (delta_x / distance)
            force_y = force * (delta_y / distance)
            self.velocities[src_id][0] += force_x
            self.velocities[src_id][1] += force_y
            self.velocities[dst_id][0] -= force_x
            self.velocities[dst_id][1] -= force_y

        gravity_strength = 0.0025
        for node_id in node_ids:
            position = self.positions[node_id]
            velocity = self.velocities[node_id]
            velocity[0] += (center_x - position[0]) * gravity_strength
            velocity[1] += (center_y - position[1]) * gravity_strength

            max_speed = 10.0
            speed = math.hypot(velocity[0], velocity[1])
            if speed > max_speed:
                scale = max_speed / speed
                velocity[0] *= scale
                velocity[1] *= scale

            position[0] += velocity[0]
            position[1] += velocity[1]

            margin = 50.0
            if position[0] < margin:
                position[0] = margin
                velocity[0] *= -0.4
            elif position[0] > width - margin:
                position[0] = width - margin
                velocity[0] *= -0.4

            if position[1] < margin:
                position[1] = margin
                velocity[1] *= -0.4
            elif position[1] > height - margin:
                position[1] = height - margin
                velocity[1] *= -0.4

            if device_lookup[node_id].get("is_local"):
                velocity[0] *= 0.92
                velocity[1] *= 0.92

    def _draw(self, snapshot: dict[str, Any]) -> None:
        devices = snapshot.get("devices", [])
        flows = snapshot.get("flows", [])
        self.canvas.delete("all")

        width = max(900, self.canvas.winfo_width() or 0)
        height = max(600, self.canvas.winfo_height() or 0)
        self.canvas.create_rectangle(0, 0, width, height, fill="#f8fafc", outline="")

        if not devices:
            self.canvas.create_text(
                width / 2,
                height / 2,
                text="Waiting for packets on the selected interface",
                fill="#334155",
                font=("Consolas", 16, "bold"),
            )
            return

        device_lookup = {device["id"]: device for device in devices}
        for flow in flows:
            src_id = flow.get("src_id")
            dst_id = flow.get("dst_id")
            if src_id not in self.positions or dst_id not in self.positions:
                continue
            src_x, src_y = self.positions[src_id]
            dst_x, dst_y = self.positions[dst_id]
            packets = max(1, int(flow.get("packets", 0)))
            width_value = min(5.0, 1.0 + math.log10(packets + 1))
            self.canvas.create_line(
                src_x,
                src_y,
                dst_x,
                dst_y,
                fill="#94a3b8",
                width=width_value,
            )

        for device in devices:
            node_id = device["id"]
            pos_x, pos_y = self.positions[node_id]
            is_local = bool(device.get("is_local"))
            is_broadcast = node_id == "broadcast"
            fill = "#2563eb" if is_local else "#10b981"
            outline = "#1e293b"
            if is_broadcast:
                fill = "#64748b"

            radius = self.node_radius + (4.0 if is_local else 0.0)
            self.canvas.create_oval(
                pos_x - radius,
                pos_y - radius,
                pos_x + radius,
                pos_y + radius,
                fill=fill,
                outline=outline,
                width=2,
            )

            label = self._build_label(device)
            self.canvas.create_text(
                pos_x,
                pos_y + radius + 20,
                text=label,
                fill="#0f172a",
                font=("Consolas", 9),
                justify="center",
            )

        legend_x = 12
        legend_y = 12
        self.canvas.create_rectangle(legend_x, legend_y, legend_x + 245, legend_y + 84, fill="#ffffff", outline="#cbd5e1")
        self.canvas.create_oval(legend_x + 12, legend_y + 12, legend_x + 28, legend_y + 28, fill="#2563eb", outline="#1e293b")
        self.canvas.create_text(legend_x + 42, legend_y + 20, text="Local interface host", anchor="w", font=("Consolas", 9), fill="#0f172a")
        self.canvas.create_oval(legend_x + 12, legend_y + 34, legend_x + 28, legend_y + 50, fill="#10b981", outline="#1e293b")
        self.canvas.create_text(legend_x + 42, legend_y + 42, text="Observed peer", anchor="w", font=("Consolas", 9), fill="#0f172a")
        self.canvas.create_oval(legend_x + 12, legend_y + 56, legend_x + 28, legend_y + 72, fill="#64748b", outline="#1e293b")
        self.canvas.create_text(legend_x + 42, legend_y + 64, text="Broadcast or multicast", anchor="w", font=("Consolas", 9), fill="#0f172a")

        elapsed = int(time.time() - self.window_started)
        self.status_label.configure(
            text=(
                f"Packets {int(snapshot.get('packet_count', 0))}    "
                f"Devices {len(devices)}    "
                f"Flows {len(flows)}    "
                f"Protocols {len(snapshot.get('protocol_counts', {}))}    "
                f"Elapsed {elapsed}s"
            )
        )

    @staticmethod
    def _build_label(device: dict[str, Any]) -> str:
        display = str(device.get("display_name", device.get("id", "unknown")))
        ips = device.get("ips", [])
        mac = device.get("mac", "")
        service_ports = device.get("service_ports", [])

        lines = [display]
        if ips:
            lines.append(ips[0])
        if mac:
            lines.append(mac)
        if service_ports:
            visible_ports = ",".join(str(value) for value in service_ports[:4])
            if len(service_ports) > 4:
                visible_ports += ",..."
            lines.append(f"ports {visible_ports}")
        return "\n".join(lines[:4])
