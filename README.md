<div align=center>
<img width="300" alt="grudarin-logo" src="public/images/grudarin-logo.png" />

![Grudarin](https://img.shields.io/badge/version-1.8.1-red?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)

</div>

---

# Grudarin - The Powerful Network Spy 🕵️‍♂️
**Grudarin** is a high-performance network monitoring and "spy" tool designed for deep traffic analysis, visitor tracking, and security auditing. It allows you to observe your network in real-time, extracting sensitive metadata and mapping activity without being actively connected to the targets.

Built for security professionals and ethical hackers, Grudarin provides a "BlackArch" style interface that puts the power of network surveillance in your hands.

## 🕵️ Key Capabilities
- **Spy Mode**: Passive traffic sniffing without an active connection.
- **Monitor Mode Support**: Put your wireless interface into monitor mode directly (`--monitor`).
- **Visitor Tracking**: Automatically identify and log local devices visiting specific domains.
- **Metadata Extraction**: Grab User-Agents, Referrers, and even cleartext credentials (FTP/Telnet).
- **Network Activity Map**: Visual topology showing data flow and device relationships.
- **Site Recon**: Rapidly scan domains and track visitor interactions with `-s`.

## 🚀 Working Commands

Grudarin features a powerful CLI. Always run with root/sudo for monitoring.

| Command | Action |
|---------|--------|
| `sudo grudarin --list` | List all available network interfaces and detected WiFi networks. |
| `sudo grudarin --scan wlan0` | Start the live monitoring dashboard (Spy Mode). |
| `sudo grudarin --scan wlan0 --monitor` | Enable **Monitor Mode** for true passive sniffing. |
| `grudarin -s google.com` | **Site Scan**: Recon a domain and track which local devices visit it. |
| `sudo grudarin --scan eth0 --view graph` | Start directly with the **Network Activity Map** visualization. |
| `sudo grudarin --scan wlan0 -o ~/logs` | Specify a custom directory to save session reports and logs. |
| `sudo grudarin --scan wlan0 --privacy-mode` | Mask sensitive IP details in all generated reports. |
| `sudo grudarin --scan eth0 -f "tcp port 80"` | Apply a custom BPF filter to capture only specific traffic. |

## 🛠️ Installation

Grudarin is now a streamlined Python-based tool.

```bash
# Clone the repository
git clone https://github.com/Chintanpatel24/grudarin.git
cd grudarin

# Run the installer (supports Arch, CachyOS, Debian, Ubuntu, Fedora, etc.)
chmod +x install.sh
sudo ./install.sh
```

## 🤝 Contributing
We welcome contributions from the developer community!

1. **Fork** the repo and create your branch.
2. **Implement** your feature or fix (ensure it fits the "Network Spy" identity).
3. **Verify** your changes with a smoke test.
4. **Submit** a Pull Request with a clear description of your work.

Special thanks to all contributors who help make Grudarin more powerful!

## ⚖️ Ethical Use
Grudarin is for **ethical and educational use only**. Unauthorized interception of data is illegal. Use it only on networks you own or have explicit, written permission to monitor.

---
*Developed with a focus on power and simplicity.*
