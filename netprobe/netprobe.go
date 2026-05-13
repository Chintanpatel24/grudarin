// ================================================================
// Grudarin - Go Network Probe
// ================================================================
//
// Fast concurrent network host discovery and fingerprinting.
// Performs ARP scanning, ICMP ping sweep, and TCP fingerprinting.
// Outputs JSON to stdout for Python integration.
//
// Build:
//   go build -o ../bin/grudarin_netprobe netprobe.go
//
// Usage:
//   ./grudarin_netprobe <subnet> [timeout_ms]
//   ./grudarin_netprobe 192.168.1.0/24 500
//
// No tracking. No telemetry. Fully local.
// ================================================================

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostInfo stores discovered host data
type HostInfo struct {
	IP        string   `json:"ip"`
	Alive     bool     `json:"alive"`
	MAC       string   `json:"mac"`
	Hostname  string   `json:"hostname"`
	OpenPorts []int    `json:"open_ports"`
	TTL       int      `json:"ttl"`
	OSGuess   string   `json:"os_guess"`
	LatencyMs float64  `json:"latency_ms"`
	Services  []string `json:"services"`
}

// Common ports for quick discovery scan
var quickPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
	161, 443, 445, 993, 995, 1433, 1521, 3306, 3389,
	5432, 5900, 6379, 8080, 8443, 9090, 9200, 27017,
}

// Port to service name
var portNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
	443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 3306: "mysql",
	3389: "rdp", 5432: "postgresql", 5900: "vnc",
	6379: "redis", 8080: "http-alt", 8443: "https-alt",
	9090: "web-console", 9200: "elasticsearch", 27017: "mongodb",
}

// expandCIDR generates all host IPs in a CIDR range
func expandCIDR(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		hosts = append(hosts, ip.String())
	}

	// Remove network and broadcast addresses
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}

	return hosts, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// tcpProbe checks if a TCP port is open
func tcpProbe(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// resolveHostname attempts reverse DNS lookup
func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	// Remove trailing dot
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	return name
}

// probeHost performs full probe of a single host
func probeHost(ip string, timeout time.Duration, wg *sync.WaitGroup, results chan<- HostInfo) {
	defer wg.Done()

	host := HostInfo{
		IP:    ip,
		Alive: false,
	}

	// Quick alive check on common ports
	aliveCheck := false
	start := time.Now()

	for _, port := range []int{80, 443, 22, 445, 3389, 21} {
		if tcpProbe(ip, port, timeout) {
			aliveCheck = true
			host.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
			break
		}
	}

	if !aliveCheck {
		// Try ICMP-like via TCP SYN to port 7 (echo)
		if tcpProbe(ip, 7, timeout) {
			aliveCheck = true
		}
	}

	if !aliveCheck {
		return
	}

	host.Alive = true

	// Scan common ports concurrently
	var portWg sync.WaitGroup
	var portMu sync.Mutex
	for _, port := range quickPorts {
		portWg.Add(1)
		go func(p int) {
			defer portWg.Done()
			if tcpProbe(ip, p, timeout) {
				portMu.Lock()
				host.OpenPorts = append(host.OpenPorts, p)
				if svc, ok := portNames[p]; ok {
					host.Services = append(host.Services, svc)
				}
				portMu.Unlock()
			}
		}(port)
	}
	portWg.Wait()

	// Resolve hostname
	host.Hostname = resolveHostname(ip)

	// Try to get MAC via ARP table (best effort)
	host.MAC = lookupMAC(ip)

	results <- host
}

// lookupMAC tries to find MAC address from system ARP table
func lookupMAC(ip string) string {
	// Read /proc/net/arp on Linux
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ip {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	return ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Grudarin Network Probe\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <subnet> [timeout_ms]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  subnet     IP or CIDR (e.g., 192.168.1.0/24)\n")
		fmt.Fprintf(os.Stderr, "  timeout_ms Connection timeout (default: 500)\n")
		os.Exit(1)
	}

	subnet := os.Args[1]
	timeoutMs := 500
	if len(os.Args) >= 3 {
		if t, err := strconv.Atoi(os.Args[2]); err == nil {
			timeoutMs = t
		}
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond

	hosts, err := expandCIDR(subnet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing subnet: %v\n", err)
		os.Exit(1)
	}

	// Cap at 1024 hosts
	if len(hosts) > 1024 {
		hosts = hosts[:1024]
	}

	results := make(chan HostInfo, len(hosts))
	var wg sync.WaitGroup

	// Limit concurrency to 64 goroutines
	sem := make(chan struct{}, 64)

	for _, ip := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			probeHost(addr, timeout, &wg, results)
			<-sem
		}(ip)
	}

	// Close results channel when all probes done
	go func() {
		wg.Wait()
		close(results)
	}()

	var alive []HostInfo
	for h := range results {
		alive = append(alive, h)
	}

	// Output JSON
	out, err := json.MarshalIndent(alive, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
