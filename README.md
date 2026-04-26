<div align=center>
<img width="500" alt="grudarin" src="https://github.com/user-attachments/assets/b05eb60d-5abf-4351-bb8b-c6ad9fe15cb7" />
</div>

---

- **Network Monitor + Vulnerability Scanner + Force-Directed Graph**
- **Grudarin** is an open-source cybersecurity tool that monitors networks in real time,
discovers devices, scans for vulnerabilities and misconfigurations, visualizes the
network topology as a live force-directed graph, and saves detailed reports in
Markdown with security findings highlighted in red bold text.

## Languages Used

| Language | Component | Purpose |
|----------|-----------|---------|
| **Python** | Core engine (`grudarin/`) | Packet capture (Scapy), data model, CLI, orchestration |
| **C++** | Port scanner (`scanner/scanner.cpp`) | Multi-threaded TCP port scanning, banner grabbing, CVE detection |
| **Go** | Network probe (`netprobe/netprobe.go`) | Concurrent host discovery, ARP table lookup, TCP fingerprinting |
| **Lua** | Rules engine (`lua_rules/security_rules.lua`) | Extensible security rules, misconfig detection, anomaly analysis |
| **Bash** | Install/Update/Uninstall (`*.sh`) | Cross-distro system setup, compilation, dependency management |
| **Batch** | Windows installer (`install.bat`) | Windows setup with MSVC/MinGW support |
| **Python (Pygame)** | Graph window (`graph_window.py`) | Real-time force-directed graph with physics engine |

## Features

- **Real-time packet capture** with protocol analysis (TCP, UDP, ICMP, ARP, DNS, DHCP, HTTP, HTTPS, SSH, FTP, SMB, RDP, SNMP, and more)
- **Live force-directed graph** that updates as devices appear and communicate
- **Node labels** showing IP, MAC address, vendor, hostname, and open ports under each device
- **Protocol labels** on graph edges showing what protocols flow between devices
- **C++ port scanner** with 38 vulnerability signatures and 34 dangerous port definitions
- **Go network probe** for fast concurrent host discovery across entire subnets
- **Lua security rules** with 12 rule categories (extensible with custom rules)
- **WiFi network discovery** showing available SSIDs, BSSIDs, signal strength
- **LAN detection** showing connected interfaces, gateways, and routes
- **ARP spoofing detection** (multiple MACs claiming same IP)
- **Broadcast storm detection** (excessive broadcast traffic ratios)
- **DNS anomaly detection** (potential tunneling or exfiltration)
- **Outdated software detection** (old SSH, Apache, nginx, PHP, IIS versions)
- **Known backdoor detection** (vsFTPd 2.3.4, ProFTPD 1.3.3)
- **Markdown reports** with security findings in red bold HTML at the end
- **JSON data export** for machine processing
- **Zero tracking, zero telemetry** - completely offline and private

## Installation

### Linux / macOS / WSL

```bash
git clone https://github.com/Chintanpatel24/grudarin.git
cd grudarin
chmod +x install.sh
sudo ./install.sh
```

### Windows

```
1. Install Python 3.8+ from python.org (check "Add to PATH")
2. Install Npcap from nmap.org/npcap (check "WinPcap compatible")
3. Open Command Prompt as Administrator
4. cd grudarin
5. install.bat
```

### Manual (any OS)

```bash
pip install scapy pygame
g++ -std=c++17 -O2 -Wall -pthread -o bin/grudarin_scanner scanner/scanner.cpp -lpthread
cd netprobe && go build -o ../bin/grudarin_netprobe netprobe.go && cd ..
```

## Workflow

```
Step 1: List available networks
  $ sudo grudarin --list

Step 2: Start scanning
  $ sudo grudarin --scan wlan0

Step 3: Tool asks for save path and note name
  Enter path to save notes: ~/my_reports
  Enter a name for this scan: home_network

Step 4: Live monitoring begins
  - Terminal shows real-time packet counts, device counts, data volume
  - Graph window opens showing network topology
  - Devices appear as nodes, connections as edges
  - Labels show IP, MAC, vendor, ports under each node

Step 5: Stop with Ctrl+C or Q in graph window
  - Vulnerability scan runs on discovered devices
  - Security rules analyze traffic patterns
  - Markdown report saved with findings in RED
```

## Usage

```bash
# Interactive mode (guides you through everything)
sudo grudarin

# List interfaces, WiFi networks, connected LANs
sudo grudarin --list

# Scan a specific interface
sudo grudarin --scan wlan0

# Scan with output path and session name
sudo grudarin --scan eth0 -o ~/reports --name office_scan

# Scan all 65535 ports on specific targets
sudo grudarin --scan wlan0 --ports 1-65535 --targets 192.168.1.1,192.168.1.100

# Headless mode (no graph, terminal only)
sudo grudarin --scan eth0 --no-graph -d 120

# Capture only, no vuln scanning
sudo grudarin --scan wlan0 --no-scan

# With BPF filter
sudo grudarin --scan wlan0 -f "tcp port 80 or tcp port 443"

# Full help
grudarin --help
```

## Graph Controls

| Action | Function |
|--------|----------|
| Mouse Wheel | Zoom in/out |
| Left Click + Drag Node | Move device node |
| Left Click + Drag Background | Pan camera |
| Right Click Node | Show device details panel |
| `P` | Pause/resume physics simulation |
| `S` | Save graph as PNG snapshot |
| `R` | Reset graph layout |
| `L` | Toggle label visibility |
| `M` | Toggle MAC address display |
| `Tab` | Toggle protocol stats panel |
| `Q` / `Esc` | Quit and save report |

## Output Files

```
grudarin_output/
  grudarin_home_network_20240101_120000/
    session_report.md       # Full report, security findings in RED at bottom
    session_data.json       # Complete machine-readable data
    packets.log             # Raw packet capture log
    graph_snapshot_1.png    # Graph screenshots
```

## Security Rules

The tool checks for these categories of issues:

| Category | Severity | What it Detects |
|----------|----------|-----------------|
| Insecure Protocols | CRITICAL-MEDIUM | Telnet, FTP, unencrypted HTTP, SNMP, SMB |
| Dangerous Ports | CRITICAL-HIGH | Redis, MongoDB, Metasploit, ADB, VNC exposed |
| ARP Spoofing | CRITICAL | Multiple MACs on same IP (MITM attack) |
| Broadcast Storm | HIGH | Excessive broadcast traffic ratios |
| DNS Anomalies | HIGH | Possible DNS tunneling or exfiltration |
| Rogue DHCP | HIGH | Excessive DHCP traffic (rogue server) |
| Outdated Software | CRITICAL-MEDIUM | Old SSH, Apache, nginx, PHP, IIS versions |
| Known Backdoors | CRITICAL | vsFTPd 2.3.4, ProFTPD 1.3.3 |
| Exposed Databases | CRITICAL-HIGH | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| Gateway Issues | HIGH-MEDIUM | Multiple gateways, missing gateway |
| Unknown Devices | MEDIUM | Unidentified devices on network |
| Excessive Ports | HIGH | Devices with too many open ports |

### Custom Rules

Add rules in `lua_rules/security_rules.lua`:

```lua
rules.my_rule = function(data)
    local ports = data.devices["some_device"].open_ports
    if contains(ports, 4444) then
        add_finding("critical", "Backdoor Detected", "Port 4444 open", "192.168.1.5", "Investigate now")
    end
end
```

## Management Scripts

```bash
# Install
sudo ./install.sh       # Linux/macOS
install.bat             # Windows (Run as Admin)

# Update (pulls from git, recompiles everything)
sudo ./update.sh

# Uninstall (removes binaries, keeps your reports)
sudo ./uninstall.sh
```

## Architecture

```
grudarin/
  install.sh              Bash installer (apt/dnf/pacman/brew/apk)
  install.bat             Windows batch installer
  uninstall.sh            Clean removal script
  update.sh               Git pull + recompile updater
  grudarin.sh             Runtime launcher (auto-created)
  requirements.txt        Python: scapy, pygame
  setup.py                pip package configuration
  scanner/
    scanner.cpp           C++ multi-threaded TCP port scanner (24KB)
  netprobe/
    netprobe.go           Go concurrent network host probe
  lua_rules/
    security_rules.lua    Lua security rules engine (12 rules)
  bin/                    Compiled binaries (auto-created)
    grudarin_scanner      C++ binary
    grudarin_netprobe     Go binary
  grudarin/               Python package
    __init__.py           Package metadata
    __main__.py           CLI entry point, workflow orchestration
    capture.py            Scapy packet capture engine
    network_model.py      Thread-safe network topology data model
    graph_window.py       Pygame force-directed graph (real-time)
    notes.py              Markdown + JSON report generator
    vuln_analyzer.py      Vulnerability analysis orchestrator
```

## Privacy

- No telemetry
- No tracking
- No phone-home
- No cloud dependencies
- No external API calls
- All processing is local
- Open source - audit every line

## Disclaimer

- This tool is for authorized network monitoring and security assessment only.
Ensure you have proper authorization before monitoring any network.
Unauthorized network monitoring may violate local laws.
