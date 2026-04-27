"""
grudarin.core.fingerprint
Passive OS and service fingerprinting from packet metadata only.
No active probing. No network calls. All inference from observed traffic.

References:
  - p0f v3 fingerprint logic (passive SYN analysis)
  - Nmap OS detection heuristics (TTL, window size, options)
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OSFingerprint:
    os_family: str = "Unknown"
    os_detail: str = ""
    confidence: int = 0        # 0-100
    method: str = ""           # how it was determined

    def __str__(self):
        if self.os_detail:
            return f"{self.os_family} ({self.os_detail}) [{self.confidence}%]"
        return f"{self.os_family} [{self.confidence}%]"


# TTL-based OS baseline (before routing decrements)
# These are expected initial TTLs
TTL_PROFILES = [
    (64,  "Linux/macOS/Android"),
    (128, "Windows"),
    (255, "Cisco IOS / Network Device"),
    (200, "Solaris / AIX"),
    (30,  "Network Appliance"),
]

# TCP window size signatures
WINDOW_PROFILES = {
    8192:   ("Windows XP/2003",        70),
    65535:  ("Windows Vista+/macOS",   65),
    16384:  ("macOS",                  65),
    5840:   ("Linux 2.6.x",            75),
    14600:  ("Linux 3.x",              75),
    29200:  ("Linux 4.x/5.x",          80),
    32120:  ("Linux generic",          60),
    4128:   ("Cisco IOS",              80),
    32768:  ("Solaris 10",             70),
    65228:  ("FreeBSD",                70),
    4096:   ("HP-UX",                  65),
}

# TCP option patterns (order matters in p0f-style analysis)
OPTIONS_SIGNATURES = {
    # (mss_present, wscale_present, sack_permitted, timestamp_present)
    (True,  True,  True,  True):  ("Linux",   80),
    (True,  True,  True,  False): ("Linux older / Android", 65),
    (True,  False, False, False): ("Windows XP", 70),
    (True,  True,  True,  False): ("Windows 7+", 70),
    (True,  False, True,  True):  ("macOS",   75),
}

# DHCP fingerprinting: option order reveals OS
# These are the most common DHCP parameter request lists
DHCP_FINGERPRINTS = {
    # Windows 10
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("Windows 10",     85),
    # Windows 7
    "1,3,6,15,31,33,43,44,46,47,121,249,252":     ("Windows 7",      85),
    # Linux / NetworkManager
    "1,28,2,3,15,6,119,12,44,47,26,121,42":       ("Linux",          80),
    # macOS
    "1,121,3,6,15,119,252,95,44,46":              ("macOS",          85),
    # Android DHCP client
    "1,33,3,6,15,28,51,58,59":                    ("Android",        80),
    # iOS
    "1,121,3,6,15,119,252,95,44,46,47":           ("iOS",            80),
}


def fingerprint_from_syn(ttl: int, window: int,
                         options_flags: tuple,
                         df_bit: bool = False) -> OSFingerprint:
    """
    Fingerprint OS from a SYN packet's TTL, window size, and TCP options.
    options_flags = (mss, wscale, sack, timestamp) booleans
    """
    fp = OSFingerprint()

    # Step 1: TTL-based family
    ttl_family = ""
    for baseline, family in TTL_PROFILES:
        # Allow for up to 30 hops of decrement
        if baseline - 30 <= ttl <= baseline:
            ttl_family = family
            fp.os_family = family
            fp.confidence = 40
            fp.method = "TTL"
            break

    # Step 2: Window size refinement
    if window in WINDOW_PROFILES:
        win_name, win_conf = WINDOW_PROFILES[window]
        # If TTL and window agree on family, boost confidence
        if any(f in win_name for f in ["Linux", "macOS", "Windows", "Cisco"]):
            if ttl_family and any(t in ttl_family for t in ["Linux", "macOS", "Windows", "Cisco"]):
                fp.confidence = min(100, fp.confidence + win_conf // 2)
                fp.os_detail = win_name
                fp.method = "TTL+Window"
            else:
                fp.os_family = win_name
                fp.confidence = win_conf
                fp.method = "Window"

    # Step 3: TCP options refinement
    if options_flags in OPTIONS_SIGNATURES:
        opt_name, opt_conf = OPTIONS_SIGNATURES[options_flags]
        if fp.confidence < opt_conf:
            fp.os_family = opt_name
            fp.confidence = opt_conf
            fp.method = "TCPOptions"

    # Step 4: DF bit hint (Windows always sets DF; Linux often does too)
    if df_bit and fp.confidence < 30:
        fp.confidence += 10

    return fp


def fingerprint_from_ttl_only(ttl: int) -> OSFingerprint:
    """Quick fingerprint from TTL alone, for non-TCP packets."""
    fp = OSFingerprint()
    for baseline, family in TTL_PROFILES:
        if baseline - 30 <= ttl <= baseline:
            fp.os_family = family
            fp.confidence = 35
            fp.method = "TTL-only"
            return fp
    fp.os_family = "Unknown"
    fp.confidence = 0
    return fp


def fingerprint_from_dhcp_options(option_order: list) -> OSFingerprint:
    """
    Fingerprint from DHCP parameter request list option order.
    option_order: list of integers (DHCP option numbers in request order)
    """
    key = ",".join(str(x) for x in option_order)
    fp = OSFingerprint()
    if key in DHCP_FINGERPRINTS:
        name, conf = DHCP_FINGERPRINTS[key]
        fp.os_family = name.split()[0]
        fp.os_detail = name
        fp.confidence = conf
        fp.method = "DHCP-options"
    return fp


def classify_device_role(hostname: str, vendor: str, mac: str,
                         open_ports: list, protocols: set) -> str:
    """
    Heuristic device role classification.
    Returns a short role string for the device type label.
    """
    hostname_l = (hostname or "").lower()
    vendor_l = (vendor or "").lower()

    # Network infrastructure
    if any(x in hostname_l for x in ["router", "gateway", "gw", "ap-", "wap-", "switch"]):
        return "Router/AP"
    if any(x in vendor_l for x in ["cisco", "juniper", "ubiquiti", "mikrotik", "netgear", "tp-link", "asus"]):
        if not open_ports or set(open_ports).issubset({22, 23, 80, 443, 161, 179}):
            return "Network Device"

    # Servers
    if any(p in open_ports for p in [80, 443, 8080, 8443]):
        return "Web Server"
    if 22 in open_ports and 3389 not in open_ports:
        return "Linux Server"
    if 3389 in open_ports:
        return "Windows Server"
    if any(p in open_ports for p in [3306, 5432, 1433, 27017]):
        return "Database Server"
    if 25 in open_ports or 993 in open_ports:
        return "Mail Server"
    if 445 in open_ports or 139 in open_ports:
        return "File Server (SMB)"
    if 5900 in open_ports:
        return "Remote Desktop"
    if 9100 in open_ports:
        return "Printer"

    # IoT / embedded
    if any(x in vendor_l for x in ["raspberry", "espressif", "arduino", "tuya"]):
        return "IoT Device"
    if any(x in hostname_l for x in ["cam", "camera", "nvr", "dvr", "print", "tv", "chromecast"]):
        return "IoT/Media"

    # Mobile
    if any(x in vendor_l for x in ["apple", "samsung", "xiaomi", "oneplus", "huawei"]):
        if "mDNS" in protocols or "DHCP" in protocols:
            return "Mobile Device"

    # Workstation
    if any(x in hostname_l for x in ["desktop", "pc-", "workstation", "laptop"]):
        return "Workstation"

    return "Host"


def merge_fingerprints(existing: str, new_fp: OSFingerprint, existing_confidence: int = 0) -> tuple:
    """
    Merge a new fingerprint result with an existing one.
    Returns (os_string, new_confidence).
    Higher confidence wins. Ties keep existing.
    """
    if new_fp.confidence > existing_confidence and new_fp.os_family not in ("Unknown", ""):
        return str(new_fp), new_fp.confidence
    return existing, existing_confidence
