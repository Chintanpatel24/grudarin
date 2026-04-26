# Grudarin

Grudarin is a local-first, passive network observability tool for environments you own or are explicitly authorized to monitor. It captures packet metadata from a selected local interface, renders a live force-directed graph in a desktop window, and writes a structured Markdown report at the end of the session.

# clone

git clone --branch <branch name> --single-branch https://github.com/Chintanpatel24/flint.git

## Important scope

This starter implementation is intentionally defensive and passive.

It does:
- monitor a local interface that exists on the current machine
- build a live force-directed graph of observed peers and conversations
- write a Markdown note with devices, protocols, flows, and notable changes
- produce basic passive hygiene findings such as IP conflicts, excessive broadcast traffic, and legacy plaintext protocols

It does not:
- actively scan arbitrary nearby Wi-Fi networks or access points
- brute force, exploit, or bypass network security
- perform intrusive port scanning against hosts
- claim to discover every vulnerability on a network

This keeps the tool suitable for open-source defensive use.

## Topology caveat

The live graph reflects observed communication relationships on the selected local interface. A passive sniffer alone cannot guarantee exact physical topology, room placement, or full switch-level path accuracy. To reach that level in an authorized environment, you would typically combine passive traffic data with switch, router, and access point telemetry.

## Features

- Pure Python implementation for the core application
- Live force-directed graph desktop window built with Tkinter
- Passive packet capture through Scapy
- Structured Markdown report generation
- Cross-platform CLI flow
- Install scripts with visible step-by-step progress
- Update and uninstall helper scripts
- Local-first operation with no telemetry and no outbound tracking

## Requirements

- Python 3.10 or newer
- Administrator or root privileges for packet capture on most systems
- A supported interface visible to the local operating system
- On Windows, Npcap is commonly required for packet capture support

## Installation

### Linux and macOS

```sh
chmod +x install.sh
./install.sh
```

After installation:

```sh
./.venv/bin/grudarin --help
./.venv/bin/grudarin interfaces
./.venv/bin/grudarin scan
```

### Windows

Run:

```bat
install.bat
```

After installation:

```bat
grudarin.bat --help
grudarin.bat interfaces
grudarin.bat scan
```

## Usage

### Show help

```sh
grudarin --help
```

### List local interfaces

```sh
grudarin interfaces
```

### Start passive live monitoring

```sh
grudarin scan --iface "Wi-Fi" --output ./reports --name home_capture
```

If `--iface`, `--output`, or `--name` are omitted, Grudarin asks for them interactively.

### Run for a fixed duration

```sh
grudarin scan --iface eth0 --output ./reports --name office_segment --seconds 120
```

### Run without the live graph window

```sh
grudarin scan --iface eth0 --output ./reports --name headless_run --no-gui
```

## Report contents

Each session produces a Markdown report containing:
- capture metadata
- packet and byte counts
- protocol summary
- observed devices with MAC addresses and IPs when available
- top conversations
- timeline of network changes observed during capture
- passive findings section with highlighted higher-severity observations

## Project layout

- `grudarin.py` - top-level launcher
- `grudarin_app/cli.py` - command-line interface
- `grudarin_app/capture.py` - passive packet capture and state tracking
- `grudarin_app/ui.py` - live force-directed graph desktop window
- `grudarin_app/report.py` - Markdown report generation
- `grudarin_app/diagnostics.py` - passive hygiene checks
- `grudarin_app/assets/grudarin_logo.ppm` - bundled icon asset for the desktop window

## Privacy model

Grudarin is local-first.

- no telemetry
- no cloud dependency
- no tracking
- no external analytics

Everything stays on the machine unless you decide to store the generated Markdown report elsewhere.

## Notes on permissions

Packet capture typically requires elevated permissions.

- On Linux, use `sudo` or grant capture capabilities appropriately.
- On Windows, run the terminal as Administrator when needed and install Npcap if Scapy cannot see interfaces.
- On macOS, grant required permissions and use a compatible capture setup.

## Updating

```sh
chmod +x update.sh
./update.sh
```

## Uninstalling local environment helpers

```sh
chmod +x uninstall.sh
./uninstall.sh
```

## Future hardening ideas

If you want to extend Grudarin further for your own authorized environment, good next steps are:
- signed release artifacts
- reproducible builds
- unit tests around packet parsing
- optional offline PCAP analysis mode
- role-based labeling for routers, printers, and servers
- export of companion JSON snapshots
- desktop packaging for system app menus
