"""
cli_logger.py — Pretty terminal log viewer.

Renders live packet summaries with colour-coded severity, protocol tags,
and credential/image alerts using ANSI escape codes.
"""

import queue
import sys
import os
import threading
from datetime import datetime
from packet_engine import PacketRecord


# ── ANSI colour helpers ─────────────────────────────────────────────────────

class C:
    """ANSI colour constants."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UL      = "\033[4m"

    # Foreground
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    # Bright foreground
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"

    # Background
    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN    = "\033[46m"
    BG_WHITE   = "\033[47m"

    BG_BRED    = "\033[101m"
    BG_BGREEN  = "\033[102m"
    BG_BYELLOW = "\033[103m"


# ── Protocol → colour map ──────────────────────────────────────────────────

PROTO_COLOURS = {
    "TCP":       C.CYAN,
    "UDP":       C.BBLUE,
    "HTTP":      C.BGREEN,
    "TLS/HTTPS": C.GREEN,
    "DNS":       C.BYELLOW,
    "ICMP":      C.MAGENTA,
    "ARP":       C.YELLOW,
    "FTP":       C.BRED,
    "SMTP":      C.BMAGENTA,
}

SEVERITY_STYLE = {
    "info":     ("", ""),
    "warning":  (C.BYELLOW + C.BOLD, C.RESET),
    "critical": (C.BRED + C.BOLD, C.RESET),
}


# ── Pretty-print one packet record ─────────────────────────────────────────

def _format_record(rec: PacketRecord, index: int) -> str:
    """Return a formatted, coloured string for a single PacketRecord."""
    pcol = PROTO_COLOURS.get(rec.protocol, C.WHITE)
    sev_start, sev_end = SEVERITY_STYLE.get(rec.severity, ("", ""))

    # --- Basic line ---
    idx_str = f"{C.DIM}#{index:<5}{C.RESET}"
    ts      = f"{C.DIM}{rec.timestamp}{C.RESET}"
    proto   = f"{pcol}{C.BOLD}{rec.protocol:<10}{C.RESET}"
    src     = f"{C.BWHITE}{rec.src_ip}{C.RESET}"
    dst     = f"{C.BWHITE}{rec.dst_ip}{C.RESET}"
    length  = f"{C.DIM}{rec.length:>5}B{C.RESET}"
    arrow   = f"{C.DIM}→{C.RESET}"

    line = f" {idx_str} {ts}  {proto} {src} {arrow} {dst}  {length}"

    # --- Info ---
    if rec.info:
        line += f"  {C.DIM}{rec.info}{C.RESET}"

    # --- Tags ---
    if rec.tags:
        tag_str = "  ".join(
            f"{C.BG_BLUE}{C.BWHITE} {t} {C.RESET}" if "CRED" not in t and "IMAGE" not in t
            else (f"{C.BG_RED}{C.BWHITE} {t} {C.RESET}" if "CRED" in t
                  else f"{C.BG_MAGENTA}{C.BWHITE} {t} {C.RESET}")
            for t in rec.tags
        )
        line += f"  {tag_str}"

    # --- Credential alert ---
    if rec.credentials:
        cred = rec.credentials
        alert = (
            f"\n          {C.BG_RED}{C.BWHITE}{C.BOLD} ⚠  CREDENTIALS CAPTURED "
            f"{C.RESET}\n"
            f"          {C.BRED}╔══════════════════════════════════════════╗{C.RESET}\n"
            f"          {C.BRED}║{C.RESET}  Method   : {C.BYELLOW}{cred.get('method','?')}{C.RESET}\n"
            f"          {C.BRED}║{C.RESET}  Username : {C.BGREEN}{cred.get('username','?')}{C.RESET}\n"
            f"          {C.BRED}║{C.RESET}  Password : {C.BRED}{cred.get('password','?')}{C.RESET}\n"
            f"          {C.BRED}╚══════════════════════════════════════════╝{C.RESET}"
        )
        line += alert

    # --- Image alert ---
    if rec.image_data:
        img_info = (
            f"\n          {C.BG_MAGENTA}{C.BWHITE}{C.BOLD} 🖼  IMAGE DETECTED "
            f"{C.RESET}  "
            f"{C.BMAGENTA}{rec.image_type} · {len(rec.image_data)} bytes{C.RESET}"
        )
        line += img_info

    return line


# ── Banner ──────────────────────────────────────────────────────────────────

BANNER = f"""
{C.BCYAN}{C.BOLD}
 ┌──────────────────────────────────────────────────────────────────┐
 │      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗          │
 │     ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝          │
 │     ███████║   ██║      ██║   ███████║██║     █████╔╝           │
 │     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗           │
 │     ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗          │
 │     ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝          │
 │                                                                  │
 │     {C.BYELLOW}I N S P E C T O R{C.BCYAN}   —   Packet Logger CLI               │
 └──────────────────────────────────────────────────────────────────┘
{C.RESET}
{C.DIM}  Live packet capture & credential / image detection
  Press Ctrl+C to stop.{C.RESET}
"""


# ── Main loop ──────────────────────────────────────────────────────────────

def run_cli_logger(pkt_queue: queue.Queue, stop_event: threading.Event):
    """Block on *pkt_queue* and print coloured log lines until *stop_event* is set."""
    print(BANNER, flush=True)
    separator = f"{C.DIM}{'─' * 100}{C.RESET}"
    print(separator, flush=True)

    index = 0
    try:
        while not stop_event.is_set():
            try:
                rec: PacketRecord = pkt_queue.get(timeout=0.3)
            except queue.Empty:
                continue
            index += 1
            line = _format_record(rec, index)
            print(line, flush=True)
            # Print a thin separator after critical events
            if rec.severity == "critical":
                print(separator, flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{C.BYELLOW}{C.BOLD}  ■ Logger stopped. {index} packets captured.{C.RESET}\n")
