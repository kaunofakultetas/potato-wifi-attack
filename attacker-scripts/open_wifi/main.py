#!/usr/bin/env python3
"""
main.py — Attacker Inspector launcher.

Starts:
  1. The packet capture engine (Scapy or demo mode)
  2. A CLI logger window (in a separate terminal or inline)
  3. The GUI inspector window

Usage:
  python main.py                   # default (auto-detect interface)
  python main.py --interface eth0  # specific interface
  python main.py --filter "tcp"    # BPF filter
  python main.py --demo            # force demo mode (no root needed)
"""

import argparse
import os
import sys
import queue
import subprocess
import threading
import signal

from packet_engine import PacketEngine, SCAPY_AVAILABLE
from cli_logger import run_cli_logger
from gui_inspector import InspectorGUI


def parse_args():
    p = argparse.ArgumentParser(
        description="Attacker Inspector — Packet capture & analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--interface", default=None,
                   help="Network interface to sniff on (default: auto)")
    p.add_argument("-f", "--filter", default="",
                   help="BPF filter expression (e.g. 'tcp port 80')")
    p.add_argument("--demo", action="store_true",
                   help="Run in demo mode with synthetic traffic")
    p.add_argument("--no-cli", action="store_true",
                   help="Don't open a separate CLI terminal")
    p.add_argument("--cli-only", action="store_true",
                   help="Only run the CLI logger (no GUI)")
    return p.parse_args()


def launch_cli_in_terminal(script_dir: str):
    """Try to open a new terminal window running the CLI logger."""
    cli_script = os.path.join(script_dir, "_cli_runner.py")
    # Write a small runner script
    with open(cli_script, "w") as f:
        f.write(f'''#!/usr/bin/env python3
import sys, os
sys.path.insert(0, {repr(script_dir)})
# This runner is spawned in a new terminal to display CLI logs.
# It connects to the engine via the same process — we import and run inline.
# Since we can't share the queue cross-process easily, this is handled
# by the main process thread.  This script exists purely as a placeholder
# for the terminal title.
print("CLI Logger is running in the main process thread.")
print("This terminal shows the coloured log output.")
print("Press Ctrl+C to stop.")
import time
try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    pass
''')

    terminal_cmds = [
        # Try common Linux terminals
        ["gnome-terminal", "--title=Attacker Inspector — CLI Logger", "--",
         sys.executable, cli_script],
        ["xfce4-terminal", "--title=Attacker Inspector — CLI Logger", "-e",
         f"{sys.executable} {cli_script}"],
        ["konsole", "--new-tab", "-e", sys.executable, cli_script],
        ["xterm", "-title", "Attacker Inspector — CLI Logger", "-e",
         sys.executable, cli_script],
    ]
    for cmd in terminal_cmds:
        try:
            subprocess.Popen(cmd, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            continue
    return False


def main():
    args = parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # ── Force demo mode if scapy is unavailable or not root ──
    use_demo = args.demo
    if not use_demo and SCAPY_AVAILABLE:
        if os.geteuid() != 0:
            print("\033[93m⚠  Not running as root — switching to demo mode.\033[0m")
            print("\033[93m   Run with sudo for real packet capture, or use --demo.\033[0m\n")
            use_demo = True
    elif not SCAPY_AVAILABLE:
        print("\033[93m⚠  Scapy not installed — switching to demo mode.\033[0m")
        print("\033[93m   Install with: pip install scapy\033[0m\n")
        use_demo = True

    # ── Map custom filter shorthand ──
    bpf_filter = args.filter
    # Common HTTP ports: 80 (standard), 8080 (proxy/dev), 8000 (dev), 8081 (dev)
    HTTP_BPF = "tcp port 80 or port 8080 or port 8000 or port 8081"

    if bpf_filter.lower() == "http":
        bpf_filter = HTTP_BPF

    # Handle "filter out" requests
    if bpf_filter.lower() in ("filter out http", "no http", "not http"):
        bpf_filter = f"not ({HTTP_BPF})"

    # ── Create engine ──
    if use_demo:
        engine = PacketEngine()  # demo mode (no interface)
        iface_display = "Demo Mode"
    else:
        engine = PacketEngine(interface=args.interface, bpf_filter=bpf_filter)
        iface_display = args.interface or "Auto"

    # ── Subscribe queues ──
    cli_queue = engine.subscribe()
    gui_queue = engine.subscribe() if not args.cli_only else None

    # ── Stop event ──
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        print("\n\033[93mStopping...\033[0m")
        stop_event.set()
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # ── Start engine ──
    print(f"\033[94mℹ  Configuration:\033[0m")
    print(f"   • Interface : \033[1m{iface_display}\033[0m")
    print(f"   • Filter    : \033[1m{bpf_filter or 'None (Capturing Everything)'}\033[0m\n")

    if use_demo:
        engine._running = True
        engine_thread = threading.Thread(target=engine._demo_loop, daemon=True)
        engine_thread.start()
    else:
        engine.start()

    # ── CLI-only mode ──
    if args.cli_only:
        try:
            run_cli_logger(cli_queue, stop_event)
        except KeyboardInterrupt:
            pass
        finally:
            stop_event.set()
            engine.stop()
        return

    # ── Start CLI logger in background thread (prints to this terminal) ──
    cli_thread = threading.Thread(
        target=run_cli_logger,
        args=(cli_queue, stop_event),
        daemon=True,
    )
    cli_thread.start()

    # ── Start GUI (must run on main thread for tkinter) ──
    gui = InspectorGUI(gui_queue, stop_event, interface=iface_display)
    try:
        gui.run()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        engine.stop()


if __name__ == "__main__":
    main()
