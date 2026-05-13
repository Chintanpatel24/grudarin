"""
Grudarin - Anonymity & OpSec
MAC randomization, trace removal, secure operation.
No identifying information left on target system.
"""
import os
import random
import subprocess
import sys
import time


def random_mac():
    """Generate a random MAC address with a valid OUI."""
    prefixes = [
        "02:00:00", "02:01:00", "02:02:00", "02:03:00",
        "00:05:69", "00:0a:27", "00:1e:68", "00:22:4d",
    ]
    prefix = random.choice(prefixes)
    suffix = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
    return f"{prefix}:{suffix}"


def random_hostname():
    """Generate a random hostname that blends in."""
    prefixes = ["localhost", "android", "iPhone", "linux", "ubuntu", "fedora"]
    return random.choice(prefixes)


def change_mac(interface):
    """Change MAC address of interface to random value."""
    if sys.platform != "linux":
        return False
    new_mac = random_mac()
    try:
        subprocess.check_call(["ip", "link", "set", interface, "down"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(["ip", "link", "set", interface, "address", new_mac],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(["ip", "link", "set", interface, "up"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return new_mac
    except Exception as e:
        return False


def restore_mac(interface, original_mac):
    """Restore original MAC address."""
    if sys.platform != "linux" or not original_mac:
        return False
    try:
        subprocess.check_call(["ip", "link", "set", interface, "down"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(["ip", "link", "set", interface, "address", original_mac],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(["ip", "link", "set", interface, "up"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def clear_arp_cache():
    """Clear system ARP cache."""
    if sys.platform == "linux":
        try:
            subprocess.check_call(["ip", "-s", "-s", "neigh", "flush", "all"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def clear_logs():
    """Clear potential identifying logs from the session."""
    if sys.platform == "linux":
        try:
            histfile = os.path.expanduser("~/.bash_history")
            if os.path.isfile(histfile):
                os.remove(histfile)
        except Exception:
            pass


def get_original_mac(interface):
    """Get current MAC address of interface."""
    try:
        out = subprocess.check_output(
            ["ip", "link", "show", interface],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if "link/ether" in line:
                return line.strip().split()[1]
    except Exception:
        return None
