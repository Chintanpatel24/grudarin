-- ================================================================
--  Grudarin - Lua Security Rules Engine
-- ================================================================
--
-- This file defines security rules that analyze network data and
-- detect misconfigurations, vulnerabilities, and suspicious activity.
--
-- Each rule is a function that receives the network data as a Lua table
-- and returns a list of findings.
--
-- Finding format:
--   { severity="critical|high|medium|low|info",
--     title="Short title",
--     description="Detailed explanation",
--     affected="IP or MAC or port",
--     recommendation="What to do about it" }
--
-- No external dependencies. Pure Lua 5.4.
-- ================================================================

local rules = {}
local findings = {}

-- Helper: add a finding
local function add_finding(severity, title, desc, affected, recommendation)
    findings[#findings + 1] = {
        severity = severity,
        title = title,
        description = desc,
        affected = affected or "",
        recommendation = recommendation or ""
    }
end

-- ================================================================
-- RULE: Detect insecure protocols in use
-- ================================================================
rules.check_insecure_protocols = function(data)
    local insecure = {
        Telnet  = { sev="critical", desc="Telnet transmits everything in cleartext including passwords.",
                     rec="Replace Telnet with SSH on all systems." },
        FTP     = { sev="high",     desc="FTP transmits credentials in cleartext.",
                     rec="Replace FTP with SFTP or FTPS." },
        HTTP    = { sev="medium",   desc="HTTP traffic is unencrypted. Sensitive data may be exposed.",
                     rec="Migrate all HTTP services to HTTPS with valid TLS certificates." },
        SNMP    = { sev="high",     desc="SNMP often uses default community strings (public/private).",
                     rec="Use SNMPv3 with authentication and encryption." },
        SMTP    = { sev="medium",   desc="SMTP on port 25 may allow open relay.",
                     rec="Restrict SMTP relay. Use port 587 with STARTTLS." },
        Syslog  = { sev="medium",   desc="Syslog sends logs in cleartext over UDP.",
                     rec="Use TLS-encrypted syslog (RFC 5425)." },
        RDP     = { sev="high",     desc="RDP exposed to network. Brute-force and BlueKeep risk.",
                     rec="Enable NLA. Use VPN. Restrict RDP access by IP." },
        SMB     = { sev="high",     desc="SMB exposed. EternalBlue/WannaCry attack surface.",
                     rec="Disable SMBv1. Restrict SMB to internal trusted subnets only." },
    }

    local protocols = data.protocol_counts or {}
    for proto, info in pairs(insecure) do
        if protocols[proto] and protocols[proto] > 0 then
            add_finding(
                info.sev,
                "Insecure Protocol: " .. proto,
                info.desc .. " (Detected " .. protocols[proto] .. " packets)",
                "Network-wide",
                info.rec
            )
        end
    end
end

-- ================================================================
-- RULE: Detect dangerous open ports
-- ================================================================
rules.check_dangerous_ports = function(data)
    local dangerous = {
        [23]    = { sev="critical", name="Telnet",       rec="Disable Telnet. Use SSH." },
        [21]    = { sev="high",     name="FTP",          rec="Replace with SFTP/FTPS." },
        [69]    = { sev="high",     name="TFTP",         rec="Disable TFTP. No authentication." },
        [135]   = { sev="high",     name="MS-RPC",       rec="Block port 135 at firewall." },
        [139]   = { sev="high",     name="NetBIOS",      rec="Disable NetBIOS. Block externally." },
        [445]   = { sev="critical", name="SMB",          rec="Disable SMBv1. Restrict access." },
        [512]   = { sev="critical", name="rexec",        rec="Disable rexec. Use SSH." },
        [513]   = { sev="critical", name="rlogin",       rec="Disable rlogin. Use SSH." },
        [514]   = { sev="critical", name="rsh",          rec="Disable rsh immediately." },
        [1433]  = { sev="high",     name="MSSQL",        rec="Restrict database access. Use firewall." },
        [3306]  = { sev="high",     name="MySQL",        rec="Bind to localhost or use firewall rules." },
        [3389]  = { sev="high",     name="RDP",          rec="Enable NLA. Use VPN. Restrict by IP." },
        [4444]  = { sev="critical", name="Metasploit",   rec="Investigate immediately. Possible backdoor." },
        [5432]  = { sev="medium",   name="PostgreSQL",   rec="Verify pg_hba.conf. Restrict network access." },
        [5555]  = { sev="critical", name="ADB",          rec="Disable ADB over network immediately." },
        [5900]  = { sev="high",     name="VNC",          rec="Use VNC with strong password and SSH tunnel." },
        [6379]  = { sev="critical", name="Redis",        rec="Enable Redis AUTH. Bind to localhost." },
        [9200]  = { sev="critical", name="Elasticsearch", rec="Enable X-Pack security. Restrict access." },
        [11211] = { sev="critical", name="Memcached",    rec="Bind to localhost. Disable UDP." },
        [27017] = { sev="critical", name="MongoDB",      rec="Enable MongoDB authentication. Restrict access." },
    }

    local devices = data.devices or {}
    for dev_key, dev in pairs(devices) do
        local ports = dev.open_ports or {}
        for _, port in ipairs(ports) do
            local d = dangerous[port]
            if d then
                add_finding(
                    d.sev,
                    "Dangerous Port Open: " .. port .. " (" .. d.name .. ")",
                    d.name .. " service detected on port " .. port .. " on device " .. (dev.ip or dev_key) .. ".",
                    dev.ip or dev_key,
                    d.rec
                )
            end
        end
    end
end

-- ================================================================
-- RULE: Detect devices with too many open ports
-- ================================================================
rules.check_excessive_ports = function(data)
    local devices = data.devices or {}
    for dev_key, dev in pairs(devices) do
        local ports = dev.open_ports or {}
        if #ports > 20 then
            add_finding(
                "high",
                "Excessive Open Ports: " .. #ports .. " ports",
                "Device " .. (dev.ip or dev_key) .. " has " .. #ports ..
                " open ports. This increases attack surface significantly.",
                dev.ip or dev_key,
                "Close unnecessary ports. Apply principle of least privilege."
            )
        elseif #ports > 10 then
            add_finding(
                "medium",
                "Many Open Ports: " .. #ports .. " ports",
                "Device " .. (dev.ip or dev_key) .. " has " .. #ports ..
                " open ports. Review if all are necessary.",
                dev.ip or dev_key,
                "Audit running services. Disable unused ones."
            )
        end
    end
end

-- ================================================================
-- RULE: Detect potential ARP spoofing
-- ================================================================
rules.check_arp_spoofing = function(data)
    local devices = data.devices or {}
    -- Check if multiple MACs claim the same IP
    local ip_to_macs = {}
    for dev_key, dev in pairs(devices) do
        local ips = dev.all_ips or {}
        for _, ip in ipairs(ips) do
            if not ip_to_macs[ip] then
                ip_to_macs[ip] = {}
            end
            if dev.mac and dev.mac ~= "unknown" and dev.mac ~= "ff:ff:ff:ff:ff:ff" then
                local found = false
                for _, m in ipairs(ip_to_macs[ip]) do
                    if m == dev.mac then found = true; break end
                end
                if not found then
                    ip_to_macs[ip][#ip_to_macs[ip] + 1] = dev.mac
                end
            end
        end
    end

    for ip, macs in pairs(ip_to_macs) do
        if #macs > 1 then
            local mac_list = table.concat(macs, ", ")
            add_finding(
                "critical",
                "Possible ARP Spoofing Detected",
                "IP " .. ip .. " is associated with multiple MAC addresses: " ..
                mac_list .. ". This may indicate an ARP spoofing/MITM attack.",
                ip,
                "Investigate immediately. Use static ARP entries for critical devices. Deploy ARP spoofing detection."
            )
        end
    end
end

-- ================================================================
-- RULE: Detect IP address conflicts
-- ================================================================
rules.check_ip_conflicts = function(data)
    local devices = data.devices or {}
    local mac_to_ips = {}

    for dev_key, dev in pairs(devices) do
        if dev.mac and dev.mac ~= "unknown" and dev.mac ~= "ff:ff:ff:ff:ff:ff" then
            local ips = dev.all_ips or {}
            if #ips > 3 then
                add_finding(
                    "medium",
                    "Device Using Multiple IPs",
                    "Device " .. dev.mac .. " (" .. (dev.ip or "?") ..
                    ") is using " .. #ips .. " different IP addresses. " ..
                    "This could indicate DHCP issues or NAT misconfiguration.",
                    dev.mac,
                    "Check DHCP lease configuration. Verify if this is expected behavior."
                )
            end
        end
    end
end

-- ================================================================
-- RULE: Detect gateway misconfiguration
-- ================================================================
rules.check_gateway_issues = function(data)
    local devices = data.devices or {}
    local gateway_count = 0

    for dev_key, dev in pairs(devices) do
        if dev.is_gateway then
            gateway_count = gateway_count + 1
        end
    end

    if gateway_count > 1 then
        add_finding(
            "high",
            "Multiple Gateways Detected",
            gateway_count .. " devices appear to be acting as gateways. " ..
            "This may cause routing conflicts and network instability.",
            "Network-wide",
            "Verify network topology. Ensure only one default gateway per subnet."
        )
    end

    if gateway_count == 0 then
        add_finding(
            "medium",
            "No Gateway Detected",
            "No device was identified as a gateway/router. " ..
            "This could mean the gateway is not responding to traffic or the scan duration was too short.",
            "Network-wide",
            "Verify router is functioning. Extend scan duration."
        )
    end
end

-- ================================================================
-- RULE: Detect unencrypted sensitive traffic
-- ================================================================
rules.check_cleartext_sensitive = function(data)
    local protocols = data.protocol_counts or {}

    -- HTTP without HTTPS is a concern
    local http_count = protocols["HTTP"] or 0
    local https_count = protocols["HTTPS"] or 0

    if http_count > 0 and https_count == 0 then
        add_finding(
            "high",
            "No HTTPS Traffic Detected",
            "All web traffic (" .. http_count .. " packets) is unencrypted HTTP. " ..
            "No HTTPS was observed.",
            "Network-wide",
            "Deploy HTTPS on all web services. Use HSTS headers."
        )
    elseif http_count > 0 and http_count > https_count * 2 then
        add_finding(
            "medium",
            "Mostly Unencrypted Web Traffic",
            http_count .. " HTTP packets vs " .. https_count .. " HTTPS packets. " ..
            "Significant portion of web traffic is unencrypted.",
            "Network-wide",
            "Migrate remaining HTTP services to HTTPS."
        )
    end

    -- FTP without SFTP
    local ftp_count = protocols["FTP"] or 0
    if ftp_count > 0 then
        add_finding(
            "high",
            "FTP Traffic Detected",
            ftp_count .. " FTP packets captured. Credentials may be exposed in cleartext.",
            "Network-wide",
            "Replace FTP with SFTP or FTPS immediately."
        )
    end

    -- Telnet
    local telnet_count = protocols["Telnet"] or 0
    if telnet_count > 0 then
        add_finding(
            "critical",
            "Telnet Traffic Detected",
            telnet_count .. " Telnet packets captured. " ..
            "All data including passwords is transmitted in cleartext.",
            "Network-wide",
            "Disable Telnet on all devices. Replace with SSH."
        )
    end
end

-- ================================================================
-- RULE: Detect broadcast storms or excessive broadcasts
-- ================================================================
rules.check_broadcast_volume = function(data)
    local devices = data.devices or {}
    local total_packets = data.total_packets or 0
    local broadcast_packets = 0

    for dev_key, dev in pairs(devices) do
        if dev.is_broadcast then
            broadcast_packets = broadcast_packets + (dev.packets_received or 0)
        end
    end

    if total_packets > 100 and broadcast_packets > total_packets * 0.5 then
        add_finding(
            "high",
            "Excessive Broadcast Traffic",
            "Broadcast traffic is " .. math.floor(broadcast_packets / total_packets * 100) ..
            "% of total traffic (" .. broadcast_packets .. "/" .. total_packets .. " packets). " ..
            "This may indicate a broadcast storm or misconfigured devices.",
            "Network-wide",
            "Check for switching loops. Verify STP configuration. Look for misconfigured DHCP."
        )
    elseif total_packets > 100 and broadcast_packets > total_packets * 0.3 then
        add_finding(
            "medium",
            "High Broadcast Ratio",
            "Broadcast traffic is " .. math.floor(broadcast_packets / total_packets * 100) ..
            "% of total traffic. This is higher than normal.",
            "Network-wide",
            "Investigate source of broadcast traffic. Consider VLAN segmentation."
        )
    end
end

-- ================================================================
-- RULE: Detect outdated or vulnerable OS
-- ================================================================
rules.check_os_vulnerabilities = function(data)
    local devices = data.devices or {}

    for dev_key, dev in pairs(devices) do
        local os = dev.os_hint or ""
        local ttls = dev.ttl_values or {}

        -- Very low TTL can indicate many hops or misconfiguration
        for _, ttl in ipairs(ttls) do
            if ttl <= 5 then
                add_finding(
                    "medium",
                    "Suspicious Low TTL Value",
                    "Device " .. (dev.ip or dev_key) .. " has TTL=" .. ttl ..
                    ". This could indicate the traffic is passing through many routers " ..
                    "or the device is misconfigured.",
                    dev.ip or dev_key,
                    "Verify the routing path to this device."
                )
            end
        end
    end
end

-- ================================================================
-- RULE: Detect DHCP-related issues
-- ================================================================
rules.check_dhcp_issues = function(data)
    local protocols = data.protocol_counts or {}
    local dhcp_count = protocols["DHCP"] or 0

    -- Excessive DHCP traffic might indicate rogue DHCP server
    if dhcp_count > 100 then
        add_finding(
            "high",
            "Excessive DHCP Traffic",
            dhcp_count .. " DHCP packets detected. " ..
            "This may indicate a rogue DHCP server or DHCP exhaustion attack.",
            "Network-wide",
            "Enable DHCP snooping on switches. Verify legitimate DHCP servers."
        )
    end
end

-- ================================================================
-- RULE: Detect DNS anomalies
-- ================================================================
rules.check_dns_anomalies = function(data)
    local protocols = data.protocol_counts or {}
    local dns_count = protocols["DNS"] or 0
    local total = data.total_packets or 0

    if total > 100 and dns_count > total * 0.4 then
        add_finding(
            "high",
            "Excessive DNS Traffic",
            "DNS is " .. math.floor(dns_count / total * 100) .. "% of all traffic. " ..
            "This may indicate DNS tunneling, exfiltration, or a DDoS amplification attack.",
            "Network-wide",
            "Analyze DNS queries for suspicious domains. Consider DNS monitoring tools."
        )
    end
end

-- ================================================================
-- RULE: Detect devices with no identified OS
-- ================================================================
rules.check_unknown_devices = function(data)
    local devices = data.devices or {}
    local unknown_count = 0

    for dev_key, dev in pairs(devices) do
        if (not dev.vendor or dev.vendor == "") and
           (not dev.hostname or dev.hostname == "") and
           (not dev.is_broadcast) then
            unknown_count = unknown_count + 1
        end
    end

    if unknown_count > 3 then
        add_finding(
            "medium",
            "Multiple Unknown Devices",
            unknown_count .. " devices on the network could not be identified " ..
            "(no vendor, no hostname). These may be unauthorized devices.",
            "Network-wide",
            "Implement 802.1X port authentication. Use MAC address filtering."
        )
    end
end

-- ================================================================
-- RULE: Check for scan results (from C++ scanner)
-- ================================================================
rules.check_scan_results = function(data)
    local scan = data.scan_results or {}

    for _, host in ipairs(scan) do
        if host.alive then
            for _, port in ipairs(host.open_ports or {}) do
                if port.vulnerability and port.vulnerability ~= "" then
                    add_finding(
                        port.severity or "medium",
                        "Vulnerability: " .. port.service .. " (port " .. port.port .. ")",
                        port.vulnerability,
                        host.ip or "unknown",
                        "Patch or upgrade the service. Restrict access if not needed."
                    )
                end

                if port.banner and port.banner ~= "" then
                    add_finding(
                        "info",
                        "Service Banner: " .. port.service .. " (port " .. port.port .. ")",
                        "Banner: " .. port.banner,
                        host.ip or "unknown",
                        "Remove version information from service banners to reduce information disclosure."
                    )
                end
            end
        end
    end
end

-- ================================================================
-- MAIN: Execute all rules
-- ================================================================

-- This function is called from Python with the network data
function run_all_rules(data)
    findings = {}

    for name, rule_fn in pairs(rules) do
        local ok, err = pcall(rule_fn, data)
        if not ok then
            add_finding(
                "info",
                "Rule Error: " .. name,
                "Rule failed to execute: " .. tostring(err),
                "",
                "Check Lua rule syntax."
            )
        end
    end

    -- Sort findings by severity
    local severity_order = { critical=1, high=2, medium=3, low=4, info=5 }
    table.sort(findings, function(a, b)
        local sa = severity_order[a.severity] or 99
        local sb = severity_order[b.severity] or 99
        return sa < sb
    end)

    return findings
end

-- ================================================================
-- Standalone test mode
-- ================================================================
if arg and arg[0] then
    -- Running standalone for testing
    local test_data = {
        protocol_counts = {
            HTTP = 150,
            HTTPS = 20,
            Telnet = 5,
            DNS = 300,
            FTP = 10,
            TCP = 500,
        },
        total_packets = 1000,
        devices = {
            ["aa:bb:cc:dd:ee:ff"] = {
                ip = "192.168.1.100",
                mac = "aa:bb:cc:dd:ee:ff",
                open_ports = {22, 80, 445, 3389, 6379, 27017},
                vendor = "",
                hostname = "",
                os_hint = "Windows",
                is_gateway = false,
                is_broadcast = false,
                all_ips = {"192.168.1.100"},
                ttl_values = {128},
            },
            ["11:22:33:44:55:66"] = {
                ip = "192.168.1.1",
                mac = "11:22:33:44:55:66",
                open_ports = {80, 443, 53},
                vendor = "TP-Link",
                hostname = "router",
                os_hint = "Linux/macOS/Unix",
                is_gateway = true,
                is_broadcast = false,
                all_ips = {"192.168.1.1"},
                ttl_values = {64},
            },
        },
        scan_results = {},
    }

    local results = run_all_rules(test_data)

    print("Found " .. #results .. " security findings:")
    print(string.rep("-", 60))
    for i, f in ipairs(results) do
        print(string.format("[%s] %s", string.upper(f.severity), f.title))
        print("  " .. f.description)
        if f.affected ~= "" then
            print("  Affected: " .. f.affected)
        end
        if f.recommendation ~= "" then
            print("  Fix: " .. f.recommendation)
        end
        print("")
    end
end
