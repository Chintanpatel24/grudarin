<div align=center>
<img width="300" alt="grudarin" src="https://github.com/user-attachments/assets/b05eb60d-5abf-4351-bb8b-c6ad9fe15cb7" />
</div>

---

# Grudarin v1.0.0

Grudarin is a GPL-3.0 licensed network and site reconnaissance tool with:
- real-time packet monitoring
- node-level vulnerability scanning
- built-in graph dashboard (native GUI)
- markdown + JSON reporting

## Key Capabilities

- Real-time LAN topology graph with smooth force simulation
- Native built-in graph view (no external graph framework)
- Flat orange/red nodes on a black dashboard
- Live edge relation labels and per-node connection labels
- Node inspector with:
  - IP, MAC, hostname, vendor, OS hint
  - protocols, services, open ports
  - packets/bytes and connected peers
- One-click node scan and scan-all-visible-nodes
- Live dashboard charts:
  - protocol distribution
  - node type distribution
  - relation/link type counts
  - top talkers
  - realtime timeline (nodes/events/bytes)
- Site scan mode with graph entities:
  - DNS_NAME, IP_ADDRESS, IP_RANGE, OPEN_TCP_PORT
  - URL, EMAIL_ADDRESS, STORAGE_BUCKET
  - ORG_STUB, USER_STUB
  - TECHNOLOGY, VULNERABILITY

## Tech Stack

| Language | Component | Purpose |
|----------|-----------|---------|
| **Python** | Core engine (`grudarin/`) | Packet capture (Scapy), data model, CLI, orchestration |
| **C++** | Port scanner (`scanner/scanner.cpp`) | Multi-threaded TCP port scanning, banner grabbing, CVE detection |
| **Go** | Network probe (`netprobe/netprobe.go`) | Concurrent host discovery, ARP table lookup, TCP fingerprinting |
| **Lua** | Rules engine (`lua_rules/security_rules.lua`) | Extensible security rules, misconfig detection, anomaly analysis |
| **Bash** | Install/Update/Uninstall (`*.sh`) | Cross-distro system setup, compilation, dependency management |
| **Batch** | Windows installer (`install.bat`) | Windows setup with MSVC/MinGW support |

## Installation

### Linux/macOS/WSL

```bash
git clone https://github.com/Chintanpatel24/grudarin.git
cd grudarin
chmod +x install.sh
sudo ./install.sh
```

### Windows

```text
1. Install Python 3.8+
2. Install Npcap (WinPcap compatibility mode)
3. Open CMD as Administrator
4. cd grudarin
5. install.bat
```

### Manual (any OS)

```bash
pip install scapy pygame
g++ -std=c++17 -O2 -Wall -pthread -o bin/grudarin_scanner scanner/scanner.cpp -lpthread
cd netprobe && go build -o ../bin/grudarin_netprobe netprobe.go && cd ..
```


## Usage

```bash
# interactive mode
sudo grudarin

# list interfaces and wifi
sudo grudarin --list

# live network scan (graph GUI)
sudo grudarin --scan wlan0

# headless network scan
sudo grudarin --scan eth0 --no-graph -d 120

# site/domain scan (live graph entities)
grudarin --scan-site example.com

# compatibility shorthand also works
grudarin --scan -site tesla.com
```

## Built-in Graph Controls

- Left click node: select and inspect full details
- Left drag node: move node
- Left drag background: pan graph
- Mouse wheel: zoom in/out
- Scan Selected Node: targeted node scan
- Scan All Visible Nodes: bulk node scan
- Ctrl+C or close window: stop scan

## Reports and Output

Each scan session writes output to a timestamped folder under `grudarin_output/`:

- `session_report.md` (human-readable report)
- `session_data.json` (machine-readable report)
- `packets.log` (capture/recon event stream)

When scan is closed, Grudarin prints the session output path in terminal.

## Security Rules

Custom rules can be added in:
- `lua_rules/security_rules.lua`


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


## Privacy

- No telemetry
- No tracking
- No phone-home
- No cloud dependencies
- No external API calls
- All processing is local
- Open source - audit every line


## Disclaimer

Use only on networks and assets you are authorized to test.


- **Network Monitor + Vulnerability Scanner + Force-Directed Graph**
- **Grudarin** is an open-source cybersecurity tool that monitors networks in real time,
discovers devices, scans for vulnerabilities and misconfigurations, visualizes the
network topology as a live force-directed graph, and saves detailed reports in
Markdown with security findings highlighted in red bold text.
