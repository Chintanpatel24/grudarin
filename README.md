# Grudarin

**Network Monitoring + Force-Directed Graph + Vulnerability Scanner**

Grudarin is an open-source cybersecurity tool that passively monitors network traffic,
visualizes the network topology with a live force-directed graph, scans for
vulnerabilities and misconfigurations, and saves detailed reports in Markdown format
with security findings highlighted in red.

## Features

- **Live force-directed graph** showing real-time network topology
- **Passive packet capture** with protocol analysis (TCP, UDP, ICMP, ARP, DNS, DHCP, etc.)
- **Vulnerability scanning** with C++ multi-threaded port scanner
- **Misconfiguration detection** via Lua security rules engine
- **Structured Markdown reports** with security findings in bold red
- **Device fingerprinting** (MAC vendor, OS detection, service identification)
- **DNS hostname resolution** captured from live traffic

## Disclaimer

This tool is intended for authorized network monitoring and educational purposes only.
Always ensure you have proper authorization before monitoring any network.
Unauthorized network monitoring may violate local laws and regulations.
