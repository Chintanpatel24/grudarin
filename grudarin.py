"""
grudarin - Network Intelligence Monitor
Open-source, private, no tracking.
Author: You
License: MIT
"""

import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(
        prog="grudarin",
        description="grudarin - Network Intelligence Monitor with force-directed graph visualization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python grudarin.py --interface eth0 --output /home/user/network_logs
  python grudarin.py --interface wlan0 --output ./logs --duration 3600
  python grudarin.py --list-interfaces
        """
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        help="Network interface to monitor (e.g. eth0, wlan0)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Directory path where session notes and logs will be saved"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=0,
        help="Monitoring duration in seconds (0 = run until stopped)"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List all available network interfaces and exit"
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Run in headless mode (capture and log only, no graph window)"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        from core.scanner import list_interfaces
        list_interfaces()
        sys.exit(0)

    # Interactive setup if args not provided
    if not args.interface or not args.output:
        args = interactive_setup(args)

    # Validate output directory
    output_dir = os.path.expanduser(args.output)
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            print(f"[grudarin] Created output directory: {output_dir}")
        except PermissionError:
            print(f"[grudarin] ERROR: Cannot create directory: {output_dir}")
            sys.exit(1)

    print(f"""
+--------------------------------------------------+
|                   grudarin                       |
|        Network Intelligence Monitor              |
|        Private  |  Local  |  Open-Source         |
+--------------------------------------------------+
  Interface : {args.interface}
  Output    : {output_dir}
  Duration  : {"Until stopped" if args.duration == 0 else f"{args.duration}s"}
  GUI       : {"Disabled" if args.no_gui else "Force-directed graph window"}
+--------------------------------------------------+
    """)

    if args.no_gui:
        from core.capture import start_headless
        start_headless(args.interface, output_dir, args.duration)
    else:
        from gui.app import launch_app
        launch_app(args.interface, output_dir, args.duration)


def interactive_setup(args):
    from core.scanner import get_interfaces

    print("\n  grudarin - Network Intelligence Monitor")
    print("  ----------------------------------------\n")

    interfaces = get_interfaces()

    if not args.interface:
        print("  Available network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"    [{i}] {iface}")
        choice = input("\n  Select interface (number or name): ").strip()
        try:
            idx = int(choice)
            args.interface = interfaces[idx]
        except (ValueError, IndexError):
            args.interface = choice

    if not args.output:
        default_path = os.path.expanduser("~/grudarin_sessions")
        raw = input(f"\n  Save session notes to [{default_path}]: ").strip()
        args.output = raw if raw else default_path

    return args


if __name__ == "__main__":
    main()
