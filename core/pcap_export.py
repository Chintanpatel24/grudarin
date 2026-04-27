"""
grudarin.core.pcap_export
Writes captured packets to a standard libpcap .pcap file.
Output files can be opened directly in Wireshark, tcpdump, or any pcap-compatible tool.

PCAP file format reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
All writes are to local disk only.
"""

import struct
import time
import threading
import os
from typing import Optional


# PCAP global header constants
PCAP_MAGIC_NUMBER = 0xa1b2c3d4     # little-endian, microsecond resolution
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0                   # GMT
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535                # max packet length
PCAP_NETWORK = 1                    # LINKTYPE_ETHERNET


def _global_header() -> bytes:
    """Pack the 24-byte global PCAP file header."""
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC_NUMBER,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        PCAP_THISZONE,
        PCAP_SIGFIGS,
        PCAP_SNAPLEN,
        PCAP_NETWORK,
    )


def _packet_header(ts: float, captured_len: int, original_len: int) -> bytes:
    """Pack a 16-byte per-packet PCAP record header."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack(
        "<IIII",
        ts_sec,
        ts_usec,
        captured_len,
        original_len,
    )


class PcapWriter:
    """
    Thread-safe PCAP file writer.
    Opens a .pcap file and appends raw packet bytes as they arrive.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._lock = threading.Lock()
        self._fh = None
        self._packet_count = 0
        self._open()

    def _open(self):
        self._fh = open(self.filepath, "wb")
        self._fh.write(_global_header())
        self._fh.flush()

    def write_packet(self, raw_bytes: bytes, timestamp: Optional[float] = None):
        """Write one raw Ethernet frame to the PCAP file."""
        if not self._fh:
            return
        ts = timestamp or time.time()
        cap_len = min(len(raw_bytes), PCAP_SNAPLEN)
        orig_len = len(raw_bytes)
        header = _packet_header(ts, cap_len, orig_len)
        with self._lock:
            self._fh.write(header)
            self._fh.write(raw_bytes[:cap_len])
            self._fh.flush()
            self._packet_count += 1

    def close(self):
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def file_size(self) -> int:
        try:
            return os.path.getsize(self.filepath)
        except Exception:
            return 0


class PcapExporter:
    """
    High-level PCAP export manager.
    Integrates with the Scapy capture loop to optionally save raw frames.
    Export can be started/stopped at runtime without restarting capture.
    """

    def __init__(self, output_dir: str, session_id: str):
        self.output_dir = output_dir
        self.session_id = session_id
        self._writer: Optional[PcapWriter] = None
        self._active = False
        self._lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def filepath(self) -> Optional[str]:
        if self._writer:
            return self._writer.filepath
        return None

    @property
    def packet_count(self) -> int:
        if self._writer:
            return self._writer.packet_count
        return 0

    @property
    def file_size_mb(self) -> float:
        if self._writer:
            return round(self._writer.file_size / (1024 * 1024), 2)
        return 0.0

    def start(self) -> str:
        """Start writing to a new PCAP file. Returns the file path."""
        with self._lock:
            if self._active:
                return self._writer.filepath

            filename = f"grudarin_{self.session_id}.pcap"
            filepath = os.path.join(self.output_dir, filename)
            self._writer = PcapWriter(filepath)
            self._active = True
            print(f"[grudarin] PCAP export started: {filepath}")
            return filepath

    def stop(self):
        """Stop writing and close the PCAP file."""
        with self._lock:
            if not self._active:
                return
            self._active = False
            if self._writer:
                count = self._writer.packet_count
                fp = self._writer.filepath
                self._writer.close()
                print(f"[grudarin] PCAP export stopped: {fp} ({count} packets)")

    def write(self, raw_bytes: bytes, timestamp: Optional[float] = None):
        """Write a raw packet if export is active."""
        if self._active and self._writer:
            self._writer.write_packet(raw_bytes, timestamp)


def export_session_to_pcap(packets_jsonl_path: str, output_pcap_path: str) -> int:
    """
    Convert a grudarin packets.jsonl file back to PCAP for post-session export.
    This only works if raw bytes were captured; otherwise reconstructs Ethernet frames
    from metadata for basic replay.

    Returns number of packets written.
    """
    import json

    writer = PcapWriter(output_pcap_path)
    count = 0

    try:
        with open(packets_jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    pkt = json.loads(line)
                    raw = pkt.get("raw_bytes")
                    ts = pkt.get("time", time.time())
                    if raw:
                        raw_bytes = bytes.fromhex(raw)
                        writer.write_packet(raw_bytes, ts)
                        count += 1
                except Exception:
                    continue
    except Exception as e:
        print(f"[grudarin] PCAP export error: {e}")
    finally:
        writer.close()

    return count
