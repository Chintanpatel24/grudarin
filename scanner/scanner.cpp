/*
 * ================================================================
 *  Grudarin - C++ Fast Port Scanner and Network Probe
 * ================================================================
 *
 * High-performance TCP port scanner with:
 *   - Multi-threaded SYN/connect scanning
 *   - Service banner grabbing
 *   - Vulnerability signature detection
 *   - JSON output for Python integration
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -pthread -o grudarin_scanner scanner.cpp -lpthread
 *
 * Usage:
 *   ./grudarin_scanner <target_ip> [port_range] [threads] [timeout_ms]
 *   ./grudarin_scanner 192.168.1.1 1-1024 50 500
 *   ./grudarin_scanner 192.168.1.0/24 1-65535 100 300
 *
 * Output: JSON to stdout
 *
 * No tracking. No telemetry. All local.
 * ================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <functional>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

// ----------------------------------------------------------------
// Data Structures
// ----------------------------------------------------------------

struct PortResult {
    int port;
    bool open;
    std::string service;
    std::string banner;
    std::string vulnerability;
    std::string severity;  // "critical", "high", "medium", "low", "info"
};

struct HostResult {
    std::string ip;
    bool alive;
    std::vector<PortResult> ports;
    std::string os_guess;
    int ttl;
    double scan_time_ms;
};

struct ScanConfig {
    std::vector<std::string> targets;
    int port_start;
    int port_end;
    int threads;
    int timeout_ms;
    bool grab_banner;
    bool check_vulns;
};

// ----------------------------------------------------------------
// Known Vulnerable Service Signatures
// ----------------------------------------------------------------

struct VulnSignature {
    std::string pattern;
    std::string vuln_name;
    std::string severity;
    std::string description;
};

static const std::vector<VulnSignature> VULN_SIGNATURES = {
    // SSH vulnerabilities
    {"SSH-1.0",           "SSHv1 Protocol",          "critical", "SSHv1 is broken. Upgrade to SSHv2 immediately."},
    {"SSH-1.5",           "SSHv1.5 Protocol",        "critical", "SSHv1.5 is insecure. Upgrade to SSHv2."},
    {"OpenSSH_4",         "Outdated OpenSSH 4.x",    "high",     "OpenSSH 4.x has multiple known CVEs."},
    {"OpenSSH_5",         "Outdated OpenSSH 5.x",    "high",     "OpenSSH 5.x has known vulnerabilities."},
    {"OpenSSH_6",         "Outdated OpenSSH 6.x",    "medium",   "OpenSSH 6.x is outdated. Update recommended."},
    {"OpenSSH_7.0",       "OpenSSH 7.0",             "medium",   "Known CVEs in OpenSSH 7.0. Update recommended."},
    {"dropbear_0.",       "Outdated Dropbear SSH",    "high",     "Old Dropbear version with known vulnerabilities."},

    // FTP vulnerabilities
    {"220 ProFTPD 1.3.3", "ProFTPD 1.3.3",          "critical", "ProFTPD 1.3.3 backdoor vulnerability (CVE-2010-4221)."},
    {"vsFTPd 2.3.4",      "vsFTPd 2.3.4 Backdoor",  "critical", "vsFTPd 2.3.4 contains a known backdoor."},
    {"220 FileZilla",     "FileZilla FTP",           "low",      "FileZilla FTP server detected."},
    {"Pure-FTPd",         "Pure-FTPd",               "info",     "Pure-FTPd server detected."},

    // HTTP vulnerabilities
    {"Apache/2.2",        "Outdated Apache 2.2",     "high",     "Apache 2.2 is EOL. Multiple known CVEs."},
    {"Apache/2.0",        "Outdated Apache 2.0",     "critical", "Apache 2.0 is ancient. Dozens of known CVEs."},
    {"nginx/1.0",         "Outdated nginx 1.0",      "high",     "nginx 1.0 has known vulnerabilities."},
    {"nginx/0.",          "Ancient nginx",           "critical", "Extremely outdated nginx version."},
    {"Microsoft-IIS/5",   "IIS 5.x",                "critical", "IIS 5.x has critical remote code execution vulns."},
    {"Microsoft-IIS/6",   "IIS 6.x",                "critical", "IIS 6.x has known RCE (CVE-2017-7269)."},
    {"Microsoft-IIS/7.0", "IIS 7.0",                "high",     "IIS 7.0 has multiple known CVEs."},
    {"PHP/5.2",           "Outdated PHP 5.2",        "critical", "PHP 5.2 is dangerously outdated."},
    {"PHP/5.3",           "Outdated PHP 5.3",        "critical", "PHP 5.3 is EOL with known RCEs."},
    {"PHP/5.4",           "Outdated PHP 5.4",        "high",     "PHP 5.4 is EOL. Update immediately."},
    {"PHP/5.5",           "Outdated PHP 5.5",        "high",     "PHP 5.5 is EOL. Update recommended."},
    {"PHP/5.6",           "Outdated PHP 5.6",        "medium",   "PHP 5.6 is EOL. Upgrade to PHP 8.x."},

    // Mail
    {"Postfix",           "Postfix SMTP",            "info",     "Postfix SMTP server detected."},
    {"Exim 4.8",          "Outdated Exim",           "high",     "Exim 4.8x has known RCE vulnerabilities."},
    {"Sendmail",          "Sendmail",                "medium",   "Sendmail detected. Often misconfigured."},

    // Database
    {"MySQL",             "MySQL Exposed",           "high",     "MySQL port exposed to network. Restrict access."},
    {"MariaDB",           "MariaDB Exposed",         "high",     "MariaDB port exposed. Restrict access."},
    {"PostgreSQL",        "PostgreSQL Exposed",      "medium",   "PostgreSQL port exposed. Verify auth config."},
    {"MongoDB",           "MongoDB Exposed",         "critical", "MongoDB often runs without authentication."},
    {"Redis",             "Redis Exposed",           "critical", "Redis often runs without authentication. RCE risk."},

    // SMB
    {"SMBv1",             "SMBv1 Protocol",          "critical", "SMBv1 is vulnerable to EternalBlue/WannaCry."},
    {"Samba 3.",          "Outdated Samba 3.x",      "high",     "Samba 3.x has known remote code execution vulns."},

    // TLS
    {"TLSv1.0",          "TLS 1.0",                 "medium",   "TLS 1.0 is deprecated. Use TLS 1.2+."},
    {"SSLv3",            "SSL 3.0",                  "critical", "SSL 3.0 is broken (POODLE attack). Disable immediately."},
    {"SSLv2",            "SSL 2.0",                  "critical", "SSL 2.0 is completely broken. Disable immediately."},
};

// ----------------------------------------------------------------
// Known dangerous/suspicious ports
// ----------------------------------------------------------------

struct DangerousPort {
    int port;
    std::string service;
    std::string risk;
    std::string severity;
};

static const std::vector<DangerousPort> DANGEROUS_PORTS = {
    {21,    "FTP",         "Cleartext protocol. Credentials sent unencrypted.",       "high"},
    {23,    "Telnet",      "Cleartext remote shell. Extremely dangerous.",            "critical"},
    {25,    "SMTP",        "Open mail relay possible. Can be used for spam.",          "medium"},
    {69,    "TFTP",        "Trivial FTP has no authentication.",                      "high"},
    {111,   "RPCbind",     "RPC portmapper. Information disclosure.",                 "medium"},
    {135,   "MSRPC",       "Microsoft RPC. Frequently exploited.",                    "high"},
    {137,   "NetBIOS-NS",  "NetBIOS name service. Information leakage.",              "medium"},
    {138,   "NetBIOS-DGM", "NetBIOS datagram. Can leak host info.",                   "medium"},
    {139,   "NetBIOS-SSN", "NetBIOS session. SMB over NetBIOS.",                      "high"},
    {161,   "SNMP",        "Default community strings often unchanged.",              "high"},
    {445,   "SMB",         "SMB direct. EternalBlue, WannaCry attack surface.",       "critical"},
    {512,   "rexec",       "Remote execution. No encryption.",                        "critical"},
    {513,   "rlogin",      "Remote login. No encryption.",                            "critical"},
    {514,   "rsh",         "Remote shell. No encryption. No auth.",                   "critical"},
    {1433,  "MSSQL",       "Microsoft SQL Server exposed.",                           "high"},
    {1521,  "Oracle",      "Oracle DB listener exposed.",                             "high"},
    {2049,  "NFS",         "Network File System. Check export permissions.",          "high"},
    {3306,  "MySQL",       "MySQL exposed to network.",                               "high"},
    {3389,  "RDP",         "Remote Desktop. Brute force target.",                     "high"},
    {4444,  "Metasploit",  "Default Metasploit handler port. Possible backdoor.",     "critical"},
    {5432,  "PostgreSQL",  "PostgreSQL exposed to network.",                          "medium"},
    {5555,  "ADB",         "Android Debug Bridge. Full device access.",               "critical"},
    {5900,  "VNC",         "VNC remote desktop. Often weak/no auth.",                 "high"},
    {5901,  "VNC-1",       "VNC display :1. Often weak/no auth.",                     "high"},
    {6379,  "Redis",       "Redis usually has no auth. RCE risk.",                    "critical"},
    {6667,  "IRC",         "IRC. Sometimes used as C2 channel.",                      "medium"},
    {8080,  "HTTP-Alt",    "Alternative HTTP. Often admin panels.",                   "medium"},
    {8443,  "HTTPS-Alt",   "Alternative HTTPS.",                                     "low"},
    {8888,  "HTTP-Alt2",   "Alternative HTTP. Jupyter notebooks, admin panels.",      "medium"},
    {9090,  "WebConsole",  "Web management console.",                                "medium"},
    {9200,  "Elasticsearch","Elasticsearch API. Often unauthenticated.",              "critical"},
    {11211, "Memcached",   "Memcached. No auth. DDoS amplification.",                "critical"},
    {27017, "MongoDB",     "MongoDB. Often no authentication.",                       "critical"},
    {27018, "MongoDB-Shard","MongoDB shard server.",                                  "high"},
    {50000, "SAP",         "SAP management console.",                                "high"},
};

// ----------------------------------------------------------------
// Globals
// ----------------------------------------------------------------

static std::mutex g_mutex;
static std::atomic<int> g_scanned_count{0};
static std::atomic<int> g_total_ports{0};

// ----------------------------------------------------------------
// Port-to-service name mapping
// ----------------------------------------------------------------

static std::string get_service_name(int port) {
    static const std::map<int, std::string> services = {
        {20,"ftp-data"},{21,"ftp"},{22,"ssh"},{23,"telnet"},
        {25,"smtp"},{53,"dns"},{67,"dhcp-server"},{68,"dhcp-client"},
        {69,"tftp"},{80,"http"},{110,"pop3"},{111,"rpcbind"},
        {119,"nntp"},{123,"ntp"},{135,"msrpc"},{137,"netbios-ns"},
        {138,"netbios-dgm"},{139,"netbios-ssn"},{143,"imap"},
        {161,"snmp"},{162,"snmp-trap"},{179,"bgp"},{389,"ldap"},
        {443,"https"},{445,"smb"},{465,"smtps"},{514,"syslog"},
        {515,"lpd"},{587,"smtp-submission"},{631,"ipp"},
        {636,"ldaps"},{993,"imaps"},{995,"pop3s"},
        {1080,"socks"},{1433,"mssql"},{1521,"oracle"},
        {1723,"pptp"},{2049,"nfs"},{2082,"cpanel"},
        {2083,"cpanel-ssl"},{2181,"zookeeper"},{3306,"mysql"},
        {3389,"rdp"},{4444,"metasploit"},{5432,"postgresql"},
        {5555,"adb"},{5672,"amqp"},{5900,"vnc"},{5901,"vnc-1"},
        {6379,"redis"},{6667,"irc"},{8080,"http-alt"},
        {8443,"https-alt"},{8888,"http-alt2"},{9090,"web-console"},
        {9200,"elasticsearch"},{9300,"elasticsearch-cluster"},
        {11211,"memcached"},{27017,"mongodb"},{27018,"mongodb-shard"},
        {50000,"sap"},
    };
    auto it = services.find(port);
    if (it != services.end()) return it->second;
    return "unknown";
}

// ----------------------------------------------------------------
// Network Utility Functions
// ----------------------------------------------------------------

static std::vector<std::string> expand_cidr(const std::string& cidr) {
    std::vector<std::string> hosts;

    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        hosts.push_back(cidr);
        return hosts;
    }

    std::string ip_str = cidr.substr(0, slash_pos);
    int prefix = std::stoi(cidr.substr(slash_pos + 1));

    if (prefix < 0 || prefix > 32) {
        hosts.push_back(ip_str);
        return hosts;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return hosts;
    }

    uint32_t ip_num = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    uint32_t network = ip_num & mask;
    uint32_t broadcast = network | ~mask;

    // Skip network and broadcast addresses
    for (uint32_t h = network + 1; h < broadcast; h++) {
        struct in_addr a;
        a.s_addr = htonl(h);
        hosts.push_back(inet_ntoa(a));
    }

    return hosts;
}

static bool is_host_alive(const std::string& ip, int timeout_ms) {
    // Quick TCP connect probe on common ports
    int probe_ports[] = {80, 443, 22, 21, 445, 3389};

    for (int port : probe_ports) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Set non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

        connect(sock, (struct sockaddr*)&sa, sizeof(sa));

        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;

        int ret = poll(&pfd, 1, timeout_ms);
        close(sock);

        if (ret > 0 && (pfd.revents & POLLOUT)) {
            return true;
        }
    }
    return false;
}

// ----------------------------------------------------------------
// TCP Connect Scanner
// ----------------------------------------------------------------

static PortResult scan_port(const std::string& ip, int port, int timeout_ms, bool grab_banner) {
    PortResult result;
    result.port = port;
    result.open = false;
    result.service = get_service_name(port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return result;

    // Non-blocking connect
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    int conn_ret = connect(sock, (struct sockaddr*)&sa, sizeof(sa));

    if (conn_ret < 0 && errno != EINPROGRESS) {
        close(sock);
        return result;
    }

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;

    int poll_ret = poll(&pfd, 1, timeout_ms);

    if (poll_ret > 0 && (pfd.revents & POLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);

        if (err == 0) {
            result.open = true;

            // Banner grabbing
            if (grab_banner) {
                // Set blocking with timeout for recv
                fcntl(sock, F_SETFL, flags);  // restore blocking

                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = timeout_ms * 1000;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                // Some services send banner immediately
                char buf[1024];
                memset(buf, 0, sizeof(buf));
                ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);

                if (n <= 0) {
                    // Try sending HTTP request for web servers
                    if (port == 80 || port == 8080 || port == 8888 || port == 9090) {
                        const char* http_req = "HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n";
                        send(sock, http_req, strlen(http_req), 0);
                        n = recv(sock, buf, sizeof(buf) - 1, 0);
                    }
                    // Try HTTPS ports too (will get gibberish but might reveal server)
                    else if (port == 443 || port == 8443) {
                        const char* probe = "\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00";
                        send(sock, probe, 10, 0);
                        n = recv(sock, buf, sizeof(buf) - 1, 0);
                    }
                }

                if (n > 0) {
                    // Clean the banner (remove non-printable chars)
                    std::string raw(buf, n);
                    std::string clean;
                    for (char c : raw) {
                        if (c >= 32 && c < 127) {
                            clean += c;
                        } else if (c == '\n' || c == '\r') {
                            if (!clean.empty() && clean.back() != ' ')
                                clean += ' ';
                        }
                    }
                    // Truncate
                    if (clean.length() > 256) {
                        clean = clean.substr(0, 256);
                    }
                    result.banner = clean;
                }
            }

            // Check dangerous ports
            for (const auto& dp : DANGEROUS_PORTS) {
                if (dp.port == port) {
                    if (result.vulnerability.empty() ||
                        dp.severity == "critical") {
                        result.vulnerability = dp.risk;
                        result.severity = dp.severity;
                    }
                    break;
                }
            }

            // Check banner against vulnerability signatures
            if (!result.banner.empty()) {
                for (const auto& sig : VULN_SIGNATURES) {
                    if (result.banner.find(sig.pattern) != std::string::npos) {
                        // Prefer higher severity
                        if (result.severity.empty() ||
                            sig.severity == "critical" ||
                            (sig.severity == "high" && result.severity != "critical")) {
                            result.vulnerability = sig.description;
                            result.severity = sig.severity;
                        }
                    }
                }
            }
        }
    }

    close(sock);
    g_scanned_count++;
    return result;
}

// ----------------------------------------------------------------
// Worker Thread
// ----------------------------------------------------------------

struct ScanTask {
    std::string ip;
    int port;
};

static std::queue<ScanTask> g_task_queue;
static std::mutex g_queue_mutex;
static std::vector<PortResult> g_results;
static std::mutex g_results_mutex;

static void worker(int timeout_ms, bool grab_banner) {
    while (true) {
        ScanTask task;
        {
            std::lock_guard<std::mutex> lock(g_queue_mutex);
            if (g_task_queue.empty()) return;
            task = g_task_queue.front();
            g_task_queue.pop();
        }

        PortResult res = scan_port(task.ip, task.port, timeout_ms, grab_banner);

        if (res.open) {
            std::lock_guard<std::mutex> lock(g_results_mutex);
            g_results.push_back(res);
        }
    }
}

// ----------------------------------------------------------------
// JSON Output
// ----------------------------------------------------------------

static std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c >= 32 && c < 127) {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string results_to_json(const HostResult& host) {
    std::ostringstream js;
    js << "{\n";
    js << "  \"ip\": \"" << escape_json(host.ip) << "\",\n";
    js << "  \"alive\": " << (host.alive ? "true" : "false") << ",\n";
    js << "  \"os_guess\": \"" << escape_json(host.os_guess) << "\",\n";
    js << "  \"ttl\": " << host.ttl << ",\n";
    js << "  \"scan_time_ms\": " << host.scan_time_ms << ",\n";
    js << "  \"open_ports\": [\n";

    for (size_t i = 0; i < host.ports.size(); i++) {
        const auto& p = host.ports[i];
        js << "    {\n";
        js << "      \"port\": " << p.port << ",\n";
        js << "      \"service\": \"" << escape_json(p.service) << "\",\n";
        js << "      \"banner\": \"" << escape_json(p.banner) << "\",\n";
        js << "      \"vulnerability\": \"" << escape_json(p.vulnerability) << "\",\n";
        js << "      \"severity\": \"" << escape_json(p.severity) << "\"\n";
        js << "    }";
        if (i < host.ports.size() - 1) js << ",";
        js << "\n";
    }

    js << "  ]\n";
    js << "}";
    return js.str();
}

// ----------------------------------------------------------------
// Main
// ----------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Grudarin Port Scanner\n";
        std::cerr << "Usage: " << argv[0] << " <target> [port_range] [threads] [timeout_ms]\n";
        std::cerr << "\n";
        std::cerr << "  target      IP address or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)\n";
        std::cerr << "  port_range  Port range (default: 1-1024). Format: start-end\n";
        std::cerr << "  threads     Number of threads (default: 50)\n";
        std::cerr << "  timeout_ms  Connection timeout in ms (default: 500)\n";
        std::cerr << "\n";
        std::cerr << "Output: JSON to stdout\n";
        return 1;
    }

    std::string target = argv[1];
    int port_start = 1, port_end = 1024;
    int thread_count = 50;
    int timeout_ms = 500;

    if (argc >= 3) {
        std::string range = argv[2];
        auto dash = range.find('-');
        if (dash != std::string::npos) {
            port_start = std::stoi(range.substr(0, dash));
            port_end = std::stoi(range.substr(dash + 1));
        }
    }

    if (argc >= 4) {
        thread_count = std::stoi(argv[3]);
    }

    if (argc >= 5) {
        timeout_ms = std::stoi(argv[4]);
    }

    // Clamp values
    port_start = std::max(1, std::min(port_start, 65535));
    port_end = std::max(port_start, std::min(port_end, 65535));
    thread_count = std::max(1, std::min(thread_count, 500));
    timeout_ms = std::max(50, std::min(timeout_ms, 10000));

    // Expand target
    std::vector<std::string> hosts = expand_cidr(target);

    // Begin JSON array output
    std::cout << "[\n";

    bool first_host = true;
    for (const auto& ip : hosts) {
        auto host_start = std::chrono::steady_clock::now();

        // Check if alive first (quick probe)
        bool alive = is_host_alive(ip, timeout_ms);

        HostResult host;
        host.ip = ip;
        host.alive = alive;
        host.ttl = 0;
        host.os_guess = "";

        if (alive) {
            // Populate task queue
            {
                std::lock_guard<std::mutex> lock(g_queue_mutex);
                while (!g_task_queue.empty()) g_task_queue.pop();
            }
            {
                std::lock_guard<std::mutex> lock(g_results_mutex);
                g_results.clear();
            }
            g_scanned_count = 0;
            g_total_ports = port_end - port_start + 1;

            {
                std::lock_guard<std::mutex> lock(g_queue_mutex);
                for (int p = port_start; p <= port_end; p++) {
                    g_task_queue.push({ip, p});
                }
            }

            // Launch workers
            int actual_threads = std::min(thread_count, g_total_ports.load());
            std::vector<std::thread> threads;
            threads.reserve(actual_threads);

            for (int t = 0; t < actual_threads; t++) {
                threads.emplace_back(worker, timeout_ms, true);
            }

            for (auto& t : threads) {
                t.join();
            }

            // Collect results
            {
                std::lock_guard<std::mutex> lock(g_results_mutex);
                host.ports = g_results;
            }

            // Sort by port number
            std::sort(host.ports.begin(), host.ports.end(),
                [](const PortResult& a, const PortResult& b) {
                    return a.port < b.port;
                });
        }

        auto host_end = std::chrono::steady_clock::now();
        host.scan_time_ms = std::chrono::duration<double, std::milli>(
            host_end - host_start).count();

        // Output
        if (!first_host) std::cout << ",\n";
        first_host = false;
        std::cout << results_to_json(host);
    }

    std::cout << "\n]\n";

    return 0;
}
