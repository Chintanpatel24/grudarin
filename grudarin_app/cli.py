from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .capture import LiveCaptureSession, PacketProcessor
from .diagnostics import generate_findings
from .helpers import discover_interfaces, ensure_directory, sanitize_filename
from .report import write_markdown_report
from .ui import ForceGraphWindow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grudarin",
        description=(
            "Passive network observability for interfaces you own or are authorized to monitor. "
            "Grudarin captures local interface traffic metadata, renders a live force-directed graph, "
            "and writes a structured Markdown report."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("interfaces", help="List interfaces visible to the local system")

    scan_parser = subparsers.add_parser("scan", help="Start live passive monitoring on a selected local interface")
    scan_parser.add_argument("--iface", help="Interface name to monitor")
    scan_parser.add_argument("--output", help="Directory where the Markdown note will be saved")
    scan_parser.add_argument("--name", help="Base name for the Markdown note")
    scan_parser.add_argument("--seconds", type=int, default=None, help="Optional capture duration in seconds")
    scan_parser.add_argument("--no-gui", action="store_true", help="Run without the live graph window")
    scan_parser.add_argument("--no-promisc", action="store_true", help="Disable promiscuous mode")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "interfaces":
        list_interfaces()
        return

    if args.command == "scan":
        run_scan(args)
        return

    parser.print_help()


def list_interfaces() -> None:
    interfaces = discover_interfaces()
    if not interfaces:
        print("No interfaces were found.")
        return

    print("Available local interfaces")
    print("=" * 80)
    for item in interfaces:
        ips = ", ".join(item.get("ips", [])) or "-"
        mac = item.get("mac") or "-"
        state = "up" if item.get("is_up") else "down"
        speed = item.get("speed_mbps") or 0
        print(f"Name: {item['name']}")
        print(f"  State : {state}")
        print(f"  MAC   : {mac}")
        print(f"  IPs   : {ips}")
        print(f"  Speed : {speed} Mbps")
        print(f"  MTU   : {item.get('mtu', 0)}")
        print("-" * 80)


def run_scan(args: argparse.Namespace) -> None:
    interface = args.iface or prompt_for_interface()
    output_dir = args.output or input("Enter the directory for the Markdown note: ").strip() or "./reports"
    note_name = args.name or input("Enter the note name: ").strip() or f"grudarin_{int(time.time())}"
    note_name = sanitize_filename(note_name)
    ensure_directory(output_dir)

    print("Grudarin started in passive mode.")
    print("Only monitor networks and interfaces you own or are explicitly authorized to assess.")
    print(f"Interface : {interface}")
    print(f"Output    : {Path(output_dir).expanduser().resolve()}")
    print(f"Note name : {note_name}.md")
    print("Press Ctrl+C to stop if no duration is set.")

    processor = PacketProcessor(interface=interface, logger=lambda message: print(message, flush=True))
    session = LiveCaptureSession(interface=interface, processor=processor, promisc=not args.no_promisc)
    stop_flag = threading.Event()
    status_thread = threading.Thread(target=status_printer, args=(processor, stop_flag), daemon=True)

    try:
        session.start()
        status_thread.start()
    except Exception as exc:
        print(f"Failed to start capture on interface '{interface}': {exc}", file=sys.stderr)
        print("Tip: packet capture usually requires administrator or root privileges.", file=sys.stderr)
        return

    try:
        if args.no_gui:
            run_headless(args.seconds, stop_flag)
        else:
            window = ForceGraphWindow(
                snapshot_provider=processor.get_snapshot,
                title=f"Grudarin live graph - {interface}",
                stop_callback=session.stop,
                duration_seconds=args.seconds,
            )
            try:
                window.run()
            finally:
                stop_flag.set()
        if args.no_gui:
            session.stop()
    except KeyboardInterrupt:
        print("\nStopping capture.")
        stop_flag.set()
        session.stop()
    finally:
        stop_flag.set()
        session.stop()

    snapshot = processor.get_snapshot()
    findings = generate_findings(snapshot)
    report_path = write_markdown_report(snapshot, findings, output_dir, note_name)
    print(f"Markdown report saved to: {report_path}")


def run_headless(duration_seconds: int | None, stop_flag: threading.Event) -> None:
    start_time = time.time()
    while not stop_flag.is_set():
        time.sleep(0.25)
        if duration_seconds is not None and (time.time() - start_time) >= duration_seconds:
            break


def status_printer(processor: PacketProcessor, stop_flag: threading.Event) -> None:
    while not stop_flag.wait(5.0):
        print(f"[STATUS] {processor.status_summary()}", flush=True)


def prompt_for_interface() -> str:
    interfaces = discover_interfaces()
    if not interfaces:
        raise SystemExit("No interfaces are available on this system.")

    print("Select an interface to monitor")
    for index, item in enumerate(interfaces, start=1):
        state = "up" if item.get("is_up") else "down"
        ips = ", ".join(item.get("ips", [])) or "no IPs"
        print(f"  [{index}] {item['name']} ({state}) - {ips}")

    while True:
        raw = input("Enter the interface number: ").strip()
        try:
            selected_index = int(raw)
        except ValueError:
            print("Please enter a number.")
            continue

        if 1 <= selected_index <= len(interfaces):
            return str(interfaces[selected_index - 1]["name"])
        print("Selected value is out of range.")
