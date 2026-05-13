<div align=center>
<img width="300" alt="grudarin-logo" src="public/images/grudarin-logo.png" />

![Grudarin](https://img.shields.io/badge/version-1.2.0-red?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)

</div>

---

# Grudarin - The Powerful Network Spy
> **Grudarin** is a high-performance, open-source network monitoring and "spy" tool designed for deep traffic analysis, visitor tracking, and security auditing. It allows you to observe your network in real-time, extracting sensitive metadata and mapping activity without being actively connected to the targets.

## 🕵️ Spy Capabilities
- **Passive Sniffing**: Capture traffic in "Spy Mode" using monitor mode (`--monitor`).
- **Visitor Tracking**: Automatically identify local devices visiting specific domains/sites.
- **Deep Metadata Extraction**: Extract User-Agents, Referrers, and hostnames from HTTP and TLS SNI.
- **Real-time Activity Feed**: Live stream of DNS queries, HTTP requests, and protocol events.
- **Network Activity Map**: Visual representation of network topology and data flow.
- **Automated Recon**: Fast site scanning and asset discovery with `-s`.

## 🚀 Commands & Usage

Grudarin is designed for both interactive and CLI-heavy workflows.

### Core Commands

| Command | Description |
|---------|-------------|
| `sudo grudarin --list` | List all available network interfaces and WiFi networks. |
| `sudo grudarin --scan <iface>` | Start the live monitoring dashboard (Spy Mode). |
| `sudo grudarin --scan <iface> --monitor` | Enable **Monitor Mode** for passive sniffing. |
| `grudarin -s <domain>` | **Site Scan**: Recon a domain and track local visitors to it. |
| `sudo grudarin --scan <iface> --view graph` | Start with the **Network Activity Map** view. |
| `sudo grudarin --scan <iface> -o ~/logs` | Save detailed Markdown & JSON reports to a specific directory. |

### Advanced Options

```bash
# Filter for specific traffic (BPF filter)
sudo grudarin --scan eth0 -f "tcp port 80 or tcp port 443"

# Scan specific ports on discovered devices
sudo grudarin --scan wlan0 --ports 1-65535

# Run headless (no GUI) for a set duration
sudo grudarin --scan wlan0 --no-graph --duration 300

# Mask sensitive details in reports
sudo grudarin --scan wlan0 --privacy-mode
```

## 🛠️ Installation

### Linux / macOS

```bash
git clone https://github.com/Chintanpatel24/grudarin.git
cd grudarin
chmod +x install.sh
sudo ./install.sh
```

### Quick Run (without global install)
```bash
chmod +x grudarin.sh
./grudarin.sh --list
```

## 📊 Reporting
Grudarin saves everything. After every session, a timestamped directory is created containing:
- `session_report.md`: A detailed Markdown report with "Visitor Activity" and "Security Findings".
- `session_data.json`: Machine-readable data for further analysis.
- `packets.log`: Raw event stream of the entire capture.

## ⚖️ Ethical Use
Grudarin is for **ethical and educational use only**. Use it only on networks you own or have explicit permission to monitor. Unauthorized interception of data is illegal and unethical.

---
*Built with ❤️ for the security community.*
