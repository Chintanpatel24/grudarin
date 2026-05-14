# Grudarin v2.0 — Network Spy & Intelligence Tool

Real-time network surveillance with per-device behavioral tracking.  
Captures and extracts intelligence from live network traffic — DNS queries, TLS SNI, HTTP requests, search queries, and more. All data sourced directly from packet inspection.

## Architecture

```
┌─────────────────────┐     JSON lines       ┌────────────────┐     TUI     ┌──────────┐
│  C Capture Engine   │────────────────────▶│ Python Model   │──────────▶ │  Rich    │
│  (libpcap + ARP)    │  real-time stream    │ (behavioral)   │             │  TUI     │
└─────────────────────┘                      └────────────────┘             └──────────┘
         │                                                                         │ 
         └── Scapy fallback if C engine not compiled ──────────────────────────────┘
```

## Capabilities

- **Packet Capture**: libpcap (C) or Scapy (Python) engine
- **DNS Tracking**: Every DNS query from every device
- **TLS SNI**: HTTPS hostnames (encrypted content stays encrypted)
- **HTTP Extraction**: URLs, User-Agents, search queries
- **Search Capture**: Google/Bing/YouTube searches in real-time
- **Per-Device Behavior**: Websites visited, active/idle status, data usage
- **ARP MITM**: Redirect target device traffic through your machine (`--target-ip`)
- **Stealth Mode**: MAC randomization, trace suppression (`--stealth`)
- **Device Discovery**: MAC OUI vendor detection, OS fingerprinting
- **Vulnerability Analysis**: Port scanning, dangerous service detection
- **Full Reports**: Markdown + JSON + packet logs

## Quick Start

```bash
# List interfaces and WiFi networks
sudo grudarin --list

# Spy on all local traffic (passive)
sudo grudarin --scan wlan0

# Anonymous mode — randomizes MAC, suppresses logs
sudo grudarin --scan wlan0 --stealth

# Intercept a specific device (ARP MITM)
sudo grudarin --scan eth0 --target-ip 192.168.1.10 --gateway-ip 192.168.1.1

# Spy on a specific WiFi network (monitor mode)
sudo grudarin --scan wlan0 --monitor Pixel

# Site reconnaissance (keeps desktop graph)
grudarin -s example.com
```

## Data Provenance

Every data point is tagged with its source:

| Tag | Meaning |
|-----|---------|
| `[CERTAIN]` | Data extracted directly from packet bytes |
| `[MITM]` | Data captured via ARP spoofing (intercepted) |

No random or synthetic data is ever generated. All output comes from real packet inspection.

## OpSec / Anonymity

- `--stealth`: Randomizes MAC address, clears ARP cache, removes bash history
- Original MAC is restored on exit
- Reports stored in `grudarin_output/` directory
- `--privacy-mode`: Masks IP addresses in reports

## Requirements

- Linux (with libpcap)
- Python 3.8+
- `scapy`, `rich` (Python packages)
- `gcc`, `libpcap-dev` (to compile C engine)
- Root privileges for packet capture

## Build

```bash
# The C engine is compiled automatically:
make -C bin  # or
gcc -O3 -o bin/grudarin_capture bin/grudarin_capture.c -lpcap -lpthread
```

Without the C engine, the tool falls back to Scapy (slower but functional).

## Output

Reports are saved to `grudarin_output/`:
- `session_report.md` — Full Markdown report with findings
- `session_data.json` — Machine-readable data dump
- `packets.log` — Raw packet log

## License

GPL-3.0
