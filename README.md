
# clone

```
git clone --branch <full-python> --single-branch https://github.com/Chintanpatel24/grudarin.git
```

# grudarin

**Network Intelligence Monitor with Force-Directed Graph Visualization**

grudarin is an open-source, privacy-first network monitoring tool. It captures and analyzes
live network traffic, builds a real-time topology map using a force-directed graph, and saves
structured session notes to your chosen location. No telemetry. No cloud. Everything runs locally.

---

## Features

- Live packet capture using raw sockets (powered by Scapy)
- Force-directed graph: visualizes all devices and connections in real time
- Passive device discovery via ARP scanning and packet metadata
- Extracts: MAC addresses, IP addresses, hostnames, vendors, OS fingerprints, protocols, ports
- Structured session reports: Markdown and JSON, saved to your specified directory
- Interactive graph window: zoom, pan, drag nodes, click to inspect
- Live packet feed with protocol breakdown
- Device detail panel: per-device traffic stats and protocol history
- Continuous ARP scanning to detect new devices joining the network
- mDNS, DHCP, and DNS hostname resolution
- No emojis. No dependencies on cloud services. No tracking.

---

## Requirements

- Python 3.10 or newer
- Linux or macOS (raw socket capture requires root privileges)
- Windows: supported with Npcap installed (run as Administrator)

### Python dependencies

```
pip install -r requirements.txt
```

Dependencies:
- `scapy` - packet capture and parsing
- `PyQt6` - GUI framework
- `netifaces` - interface and subnet detection

---

## Installation

```bash
git clone https://github.com/Chintanpatel24/grudarin.git
cd grudarin
pip install -r requirements.txt
```

---

## Usage

### Interactive setup (recommended for first run)

```bash
sudo python grudarin.py
```

grudarin will ask you to select a network interface and output directory.

### Command-line arguments

```bash
sudo python grudarin.py --interface eth0 --output /home/user/network_logs
```

Options:

| Flag | Description |
|---|---|
| `--interface`, `-i` | Network interface to monitor (e.g. eth0, wlan0) |
| `--output`, `-o` | Directory to save session notes and reports |
| `--duration`, `-d` | Monitoring duration in seconds (default: run until stopped) |
| `--list-interfaces` | List all available interfaces and exit |
| `--no-gui` | Headless mode: capture and log only, no graph window |

### Examples

```bash
# Monitor Wi-Fi with GUI
sudo python grudarin.py -i wlan0 -o ~/grudarin_sessions

# Monitor Ethernet for 1 hour, headless
sudo python grudarin.py -i eth0 -o /var/log/grudarin --duration 3600 --no-gui

# List interfaces
sudo python grudarin.py --list-interfaces
```

---

## Graph Window Controls

| Action | Control |
|---|---|
| Select/inspect device | Left-click on node |
| Drag node | Left-click and drag |
| Pan view | Right-click and drag |
| Zoom | Scroll wheel |
| Reset view | Spacebar |
| Deselect | Escape |

Node colors:
- Blue: standard host
- Gold/Yellow: detected gateway
- Bright green: recently active device

Edge thickness increases with traffic volume between two devices.

---

## Output Files

Each session creates a folder inside your output directory named `grudarin_YYYYMMDD_HHMMSS/`:

| File | Description |
|---|---|
| `report.md` | Human-readable Markdown report with all discovered devices, links, protocol stats |
| `report.json` | Machine-readable JSON report with the same data |
| `events.jsonl` | Line-delimited JSON log of all topology events (device added, link added, etc.) |
| `packets.jsonl` | Line-delimited JSON log of captured packet metadata (no payload content) |

Note: grudarin does not log payload content. Only packet metadata is stored
(source/destination MACs, IPs, ports, protocol, size, TTL).

---

## Privacy and Security

- All data stays on your machine. No network calls are made by grudarin itself.
- Payload content is never stored or logged.
- The tool requires elevated privileges (root/sudo) only because raw socket capture requires it.
- No analytics, no crash reporting, no update checks.

---

## Architecture

```
grudarin/
    grudarin.py          Entry point, CLI, interactive setup
    core/
        capture.py       Scapy packet sniffer, protocol parsing
        topology.py      Thread-safe graph model (devices and links)
        scanner.py       ARP scanning, interface utilities, vendor lookup
        logger.py        Session note writer (Markdown + JSON)
    gui/
        app.py           Main Qt window, orchestration
        graph_window.py  Force-directed graph renderer (pure Qt canvas)
        dashboard.py     Side panel: device list, packet feed, stats
    requirements.txt
    README.md
```

---

#
## Disclaimer

grudarin is intended for use on networks you own or have explicit permission to monitor.
Unauthorized network monitoring may violate local laws. The authors take no responsibility
for misuse.
