"""
gui_inspector.py — Modern dark-themed GUI for the Attacker Inspector.

Features:
  • Live packet tree view with colour-coded protocols
  • Collapsible detail panels
  • Credential capture display with warning styling
  • Image preview pane for intercepted images
  • Statistics bar with live counters
  • Smooth colour transitions and hover effects
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk, font as tkfont
import io
import time
from datetime import datetime
from collections import defaultdict
from packet_engine import PacketRecord

try:
    from PIL import Image as PILImage, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# Colour palette (dark mode)
# ═══════════════════════════════════════════════════════════════════════════

COLORS = {
    "bg":              "#0d1117",
    "bg_secondary":    "#161b22",
    "bg_tertiary":     "#1c2333",
    "bg_card":         "#21262d",
    "bg_hover":        "#30363d",
    "border":          "#30363d",
    "border_active":   "#58a6ff",

    "text":            "#e6edf3",
    "text_secondary":  "#8b949e",
    "text_dim":        "#484f58",

    "accent":          "#58a6ff",
    "accent_hover":    "#79c0ff",
    "green":           "#3fb950",
    "green_dim":       "#238636",
    "yellow":          "#d29922",
    "yellow_dim":      "#9e6a03",
    "red":             "#f85149",
    "red_dim":         "#da3633",
    "purple":          "#bc8cff",
    "cyan":            "#39d2c0",
    "orange":          "#f0883e",
    "magenta":         "#f778ba",
    "pink":            "#ff7eb6",

    # Protocol-specific
    "proto_tcp":       "#39d2c0",
    "proto_udp":       "#58a6ff",
    "proto_http":      "#3fb950",
    "proto_https":     "#238636",
    "proto_dns":       "#d29922",
    "proto_icmp":      "#bc8cff",
    "proto_arp":       "#f0883e",
    "proto_ftp":       "#f85149",
    "proto_smtp":      "#f778ba",
}

PROTO_TAG_COLORS = {
    "TCP":       COLORS["proto_tcp"],
    "UDP":       COLORS["proto_udp"],
    "HTTP":      COLORS["proto_http"],
    "TLS/HTTPS": COLORS["proto_https"],
    "DNS":       COLORS["proto_dns"],
    "ICMP":      COLORS["proto_icmp"],
    "ARP":       COLORS["proto_arp"],
    "FTP":       COLORS["proto_ftp"],
    "SMTP":      COLORS["proto_smtp"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Custom Tk styles
# ═══════════════════════════════════════════════════════════════════════════

def configure_styles(root):
    style = ttk.Style(root)
    style.theme_use("clam")

    # General
    style.configure(".", background=COLORS["bg"], foreground=COLORS["text"],
                     borderwidth=0, focuscolor=COLORS["bg"])

    # Treeview
    style.configure(
        "Packet.Treeview",
        background=COLORS["bg_secondary"],
        foreground=COLORS["text"],
        fieldbackground=COLORS["bg_secondary"],
        borderwidth=0,
        rowheight=28,
    )
    style.map("Packet.Treeview",
              background=[("selected", COLORS["bg_hover"])],
              foreground=[("selected", COLORS["accent"])])

    style.configure("Packet.Treeview.Heading",
                     background=COLORS["bg_tertiary"],
                     foreground=COLORS["text_secondary"],
                     borderwidth=0,
                     relief="flat",
                     padding=(8, 6))
    style.map("Packet.Treeview.Heading",
              background=[("active", COLORS["bg_hover"])])

    # Scrollbar
    style.configure("Dark.Vertical.TScrollbar",
                     background=COLORS["bg_tertiary"],
                     troughcolor=COLORS["bg_secondary"],
                     borderwidth=0,
                     arrowsize=0)
    style.map("Dark.Vertical.TScrollbar",
              background=[("active", COLORS["border_active"])])

    # Frames
    style.configure("Card.TFrame", background=COLORS["bg_card"])
    style.configure("Dark.TFrame", background=COLORS["bg"])
    style.configure("Stats.TFrame", background=COLORS["bg_tertiary"])

    # Labels
    style.configure("Title.TLabel", background=COLORS["bg"],
                     foreground=COLORS["accent"], font=("Inter", 18, "bold"))
    style.configure("Subtitle.TLabel", background=COLORS["bg"],
                     foreground=COLORS["text_secondary"], font=("Inter", 10))
    style.configure("Stat.TLabel", background=COLORS["bg_tertiary"],
                     foreground=COLORS["text"], font=("JetBrains Mono", 11))
    style.configure("StatValue.TLabel", background=COLORS["bg_tertiary"],
                     foreground=COLORS["accent"], font=("JetBrains Mono", 14, "bold"))

    # Notebook
    style.configure("Dark.TNotebook", background=COLORS["bg"],
                     borderwidth=0)
    style.configure("Dark.TNotebook.Tab",
                     background=COLORS["bg_tertiary"],
                     foreground=COLORS["text_secondary"],
                     padding=(16, 8),
                     borderwidth=0)
    style.map("Dark.TNotebook.Tab",
              background=[("selected", COLORS["bg_card"])],
              foreground=[("selected", COLORS["accent"])])


# ═══════════════════════════════════════════════════════════════════════════
# Main GUI class
# ═══════════════════════════════════════════════════════════════════════════

class InspectorGUI:
    """Modern dark-themed packet inspector GUI."""

    MAX_TREE_ROWS = 800       # Keep the tree from growing unbounded
    POLL_INTERVAL_MS = 120    # How often we drain the queue

    def __init__(self, pkt_queue: queue.Queue, stop_event: threading.Event, interface: str = "Auto"):
        self.pkt_queue = pkt_queue
        self.stop_event = stop_event
        self.interface_name = interface

        self.root = tk.Tk()
        self.root.title("Attacker Inspector — Packet Analyser")
        self.root.geometry("1340x820")
        self.root.minsize(1000, 600)
        self.root.configure(bg=COLORS["bg"])

        # Try to set dark title-bar on Linux
        try:
            self.root.tk.call("tk", "windowingsystem")
        except Exception:
            pass

        configure_styles(self.root)

        # Fonts
        self.mono = tkfont.Font(family="JetBrains Mono", size=10)
        self.mono_sm = tkfont.Font(family="JetBrains Mono", size=9)
        self.sans = tkfont.Font(family="Inter", size=10)
        self.sans_bold = tkfont.Font(family="Inter", size=10, weight="bold")

        # State
        self._packet_index = 0
        self._records: list[PacketRecord] = []
        self._cred_records: list[PacketRecord] = []
        self._http_records: list[PacketRecord] = []
        self._proto_counts: dict[str, int] = defaultdict(int)
        self._total_bytes = 0
        self._photo_refs: list = []  # prevent GC of PhotoImages
        self.dns_window = None
        import typing
        self.notebook: typing.Any = None
        self.http_tree: typing.Any = None
        self.show_https_var = tk.BooleanVar(value=True)
        self.http_autoscroll_var = tk.BooleanVar(value=True)

        self._build_ui()
        self._poll_queue()

    # ── UI Construction ────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top bar ──
        top = tk.Frame(self.root, bg=COLORS["bg"], padx=16, pady=10)
        top.pack(fill="x")

        # Title row
        title_frame = tk.Frame(top, bg=COLORS["bg"])
        title_frame.pack(fill="x")

        # Icon + Title
        icon_lbl = tk.Label(title_frame, text="🛡", font=("Inter", 24),
                            bg=COLORS["bg"], fg=COLORS["accent"])
        icon_lbl.pack(side="left", padx=(0, 8))

        title_lbl = tk.Label(title_frame, text="Attacker Inspector",
                             font=("Inter", 20, "bold"),
                             bg=COLORS["bg"], fg=COLORS["text"])
        title_lbl.pack(side="left")

        ver_lbl = tk.Label(title_frame, text=f"  v1.0  |  Interface: {self.interface_name}",
                           font=("Inter", 10),
                           bg=COLORS["bg"], fg=COLORS["text_dim"])
        ver_lbl.pack(side="left", pady=(6, 0))

        # Live indicator
        self._live_dot = tk.Label(title_frame, text="●", font=("Inter", 14),
                                  bg=COLORS["bg"], fg=COLORS["green"])
        self._live_dot.pack(side="right", padx=(0, 4))
        live_text = tk.Label(title_frame, text="LIVE",
                             font=("Inter", 10, "bold"),
                             bg=COLORS["bg"], fg=COLORS["green"])
        live_text.pack(side="right")

        # DNS Log window setup & button
        try:
            from custom_view import DNSLogWindow # type: ignore
            self.dns_window = DNSLogWindow(self.root, COLORS)
            dns_win = self.dns_window
            # Add a button to show the window
            if dns_win is not None:
                dns_btn = tk.Button(title_frame, text="DNS Logs", font=("Inter", 9),
                                    bg=COLORS["bg_hover"], fg=COLORS["text"],
                                    borderwidth=0, padx=8, pady=4,
                                    activebackground=COLORS["accent"],
                                    command=dns_win.show)
                dns_btn.pack(side="right", padx=(0, 16))
        except Exception as e:
            print(f"Could not load custom_view: {e}")

        # ── Stats bar ──
        self._build_stats_bar()

        # ── Main content area with Notebook ──
        nb = ttk.Notebook(self.root, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        # Tab 1 — All Packets
        tab_all = tk.Frame(nb, bg=COLORS["bg_secondary"])
        nb.add(tab_all, text="  📡  All Packets  ")
        self._build_packet_tree(tab_all)

        # Tab 2 — Credentials
        tab_creds = tk.Frame(nb, bg=COLORS["bg_secondary"])
        nb.add(tab_creds, text="  🔑  Credentials  ")
        self._build_credentials_tab(tab_creds)

        # Tab 3 — HTTP Access
        tab_http = tk.Frame(nb, bg=COLORS["bg_secondary"])
        nb.add(tab_http, text="  🌐  HTTP Access  ")
        self._build_http_tab(tab_http)

        # Tab 4 — Detail
        tab_detail = tk.Frame(nb, bg=COLORS["bg_secondary"])
        nb.add(tab_detail, text="  📋  Packet Detail  ")
        self._build_detail_tab(tab_detail)
        
        self.notebook = nb

    # ── Stats bar ──────────────────────────────────────────────────────

    def _build_stats_bar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_tertiary"], padx=16, pady=8)
        bar.pack(fill="x", padx=12, pady=(0, 6))

        self._stat_labels = {}
        stats = [
            ("Packets", "0"),
            ("Bytes", "0 B"),
            ("Credentials", "0"),
            ("HTTP Access", "0"),
            ("TCP", "0"),
            ("UDP", "0"),
            ("HTTP", "0"),
            ("DNS", "0"),
        ]
        for i, (name, val) in enumerate(stats):
            frame = tk.Frame(bar, bg=COLORS["bg_tertiary"])
            frame.pack(side="left", padx=(0, 28))
            lbl_name = tk.Label(frame, text=name.upper(),
                                font=("Inter", 8), fg=COLORS["text_dim"],
                                bg=COLORS["bg_tertiary"])
            lbl_name.pack(anchor="w")
            lbl_val = tk.Label(frame, text=val,
                               font=("JetBrains Mono", 13, "bold"),
                               fg=COLORS["accent"], bg=COLORS["bg_tertiary"])
            lbl_val.pack(anchor="w")
            self._stat_labels[name] = lbl_val

    def _update_stats(self):
        self._stat_labels["Packets"].config(text=str(self._packet_index))
        # bytes
        if self._total_bytes < 1024:
            b_str = f"{self._total_bytes} B"
        elif self._total_bytes < 1024 * 1024:
            b_str = f"{self._total_bytes / 1024:.1f} KB"
        else:
            b_str = f"{self._total_bytes / (1024*1024):.2f} MB"
        self._stat_labels["Bytes"].config(text=b_str)
        self._stat_labels["Credentials"].config(
            text=str(len(self._cred_records)),
            fg=COLORS["red"] if self._cred_records else COLORS["accent"])
        self._stat_labels["HTTP Access"].config(text=str(len(self._http_records)))
        for proto in ("TCP", "UDP", "HTTP", "DNS"):
            self._stat_labels[proto].config(text=str(self._proto_counts.get(proto, 0)))

    # ── Tab 1: Packet tree ─────────────────────────────────────────────

    def _build_packet_tree(self, parent):
        container = tk.Frame(parent, bg=COLORS["bg_secondary"])
        container.pack(fill="both", expand=True)

        cols = ("no", "time", "protocol", "source", "destination", "length", "info")
        self.tree = ttk.Treeview(container, columns=cols, show="headings",
                                 style="Packet.Treeview", selectmode="browse")

        col_cfg = {
            "no":          ("No.",       55,  "center"),
            "time":        ("Time",      90,  "center"),
            "protocol":    ("Protocol",  90,  "center"),
            "source":      ("Source",    150, "w"),
            "destination": ("Dest",      150, "w"),
            "length":      ("Length",    70,  "e"),
            "info":        ("Info",      500, "w"),
        }
        for col, (heading, width, anchor) in col_cfg.items():
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, anchor=anchor, minwidth=40)

        # Tag colours for protocols
        for proto, colour in PROTO_TAG_COLORS.items():
            tag_name = f"proto_{proto.replace('/', '_')}"
            self.tree.tag_configure(tag_name, foreground=colour)
        self.tree.tag_configure("critical", foreground=COLORS["red"],
                                font=("JetBrains Mono", 10, "bold"))
        self.tree.tag_configure("warning", foreground=COLORS["yellow"])
        self.tree.tag_configure("row_even", background=COLORS["bg_secondary"])
        self.tree.tag_configure("row_odd", background=COLORS["bg_tertiary"])

        # Scrollbar
        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview,
                             style="Dark.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Bind selection → detail tab
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    # ── Tab 2: Credentials ─────────────────────────────────────────────

    def _build_credentials_tab(self, parent):
        # Header warning
        warn_frame = tk.Frame(parent, bg="#3d1a1a", padx=12, pady=8)
        warn_frame.pack(fill="x", padx=8, pady=(8, 4))
        tk.Label(warn_frame, text="⚠  Intercepted Credentials",
                 font=("Inter", 13, "bold"), bg="#3d1a1a",
                 fg=COLORS["red"]).pack(anchor="w")
        tk.Label(warn_frame,
                 text="Cleartext credentials detected in network traffic. "
                      "These may indicate insecure authentication.",
                 font=("Inter", 9), bg="#3d1a1a",
                 fg=COLORS["text_secondary"]).pack(anchor="w", pady=(2, 0))

        # Credentials treeview
        cols = ("no", "time", "method", "host", "username", "password", "source", "dest")
        self.cred_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                       style="Packet.Treeview", selectmode="browse")
        cred_col_cfg = {
            "no":       ("No.",     45,  "center"),
            "time":     ("Time",    85,  "center"),
            "method":   ("Method",  90,  "center"),
            "host":     ("Host",    160, "w"),
            "username": ("Username",140, "w"),
            "password": ("Password",140, "w"),
            "source":   ("Source",  120, "w"),
            "dest":     ("Dest",    120, "w"),
        }
        for col, (heading, width, anchor) in cred_col_cfg.items():
            self.cred_tree.heading(col, text=heading)
            self.cred_tree.column(col, width=width, anchor=anchor, minwidth=30)

        self.cred_tree.tag_configure("cred_row", foreground=COLORS["red"])
        self.cred_tree.pack(fill="both", expand=True, padx=8, pady=(4, 8))

    # ── Tab 3: HTTP Access ────────────────────────────────────────────────

    def _build_http_tab(self, parent):
        header_frame = tk.Frame(parent, bg=COLORS["bg_secondary"])
        header_frame.pack(fill="x", padx=16, pady=(12, 4))
        
        tk.Label(header_frame, text="Intercepted HTTP(S) Requests", font=("Inter", 12, "bold"),
                 bg=COLORS["bg_secondary"], fg=COLORS["text"]
                 ).pack(side="left")
                 
        tk.Checkbutton(header_frame, text="Auto-scroll", variable=self.http_autoscroll_var,
                       bg=COLORS["bg_secondary"], fg=COLORS["text"],
                       selectcolor=COLORS["bg_tertiary"], activebackground=COLORS["bg_secondary"],
                       activeforeground=COLORS["text"]).pack(side="right", padx=(0, 16))
                       
        tk.Checkbutton(header_frame, text="Show HTTPS", variable=self.show_https_var,
                       command=self._refresh_http_tree,
                       bg=COLORS["bg_secondary"], fg=COLORS["text"],
                       selectcolor=COLORS["bg_tertiary"], activebackground=COLORS["bg_secondary"],
                       activeforeground=COLORS["text"]).pack(side="right")
                 
        cols = ("no", "time", "method", "host", "path", "source")
        self.http_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                      style="Packet.Treeview", selectmode="browse")
                                      
        http_col_cfg = {
            "no":     ("No.",     45,  "center"),
            "time":   ("Time",    85,  "center"),
            "method": ("Method",  70,  "center"),
            "host":   ("Host",    170, "w"),
            "path":   ("Path",    300, "w"),
            "source": ("Source",  130, "w"),
        }
        for col, (heading, width, anchor) in http_col_cfg.items():
            self.http_tree.heading(col, text=heading)
            self.http_tree.column(col, width=width, anchor=anchor, minwidth=30)
            
        # Tag for HTTPS indicating encryption (light green or muted text)
        self.http_tree.tag_configure("https_row", foreground=COLORS["green_dim"])

        self.http_tree.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.http_tree.bind("<<TreeviewSelect>>", self._on_http_select)

    # ── Tab 4: Packet Detail ──────────────────────────────────────────

    def _build_detail_tab(self, parent):
        self._detail_text = tk.Text(
            parent, bg=COLORS["bg_card"], fg=COLORS["text"],
            font=self.mono, wrap="word", borderwidth=0,
            insertbackground=COLORS["accent"], padx=16, pady=12,
            state="disabled",
        )
        self._detail_text.pack(fill="both", expand=True, padx=8, pady=8)

        # Configure tags for detail view
        self._detail_text.tag_configure("heading",
                                         font=("Inter", 13, "bold"),
                                         foreground=COLORS["accent"])
        self._detail_text.tag_configure("subheading",
                                         font=("Inter", 11, "bold"),
                                         foreground=COLORS["cyan"])
        self._detail_text.tag_configure("key",
                                         foreground=COLORS["text_secondary"],
                                         font=self.mono)
        self._detail_text.tag_configure("value",
                                         foreground=COLORS["text"],
                                         font=("JetBrains Mono", 10, "bold"))
        self._detail_text.tag_configure("cred_key",
                                         foreground=COLORS["red"],
                                         font=("JetBrains Mono", 10, "bold"))
        self._detail_text.tag_configure("cred_value",
                                         foreground=COLORS["yellow"],
                                         font=("JetBrains Mono", 11, "bold"))
        self._detail_text.tag_configure("separator",
                                         foreground=COLORS["text_dim"])
        self._detail_text.tag_configure("tag_badge",
                                         foreground=COLORS["bg"],
                                         background=COLORS["accent"],
                                         font=("Inter", 9, "bold"))

    # ── Event handlers ─────────────────────────────────────────────────

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.tree.item(item, "values")
        if not values:
            return
        idx = int(values[0]) - 1
        if 0 <= idx < len(self._records):
            self._show_detail(self._records[idx], idx + 1)
            # Switch to detail tab
            self.notebook.select(3)

    def _refresh_http_tree(self):
        for item in self.http_tree.get_children():
            self.http_tree.delete(item)
        for i, rec in enumerate(self._http_records):
            if not self.show_https_var.get() and rec.protocol == "TLS/HTTPS":
                continue
                
            tag = "https_row" if rec.protocol == "TLS/HTTPS" else ""
            method_display = rec.http_method or (
                "HTTPS" if rec.protocol == "TLS/HTTPS" else "?"
            )
            path_display = rec.http_path or ("<encrypted>" if rec.protocol == "TLS/HTTPS" else "/")

            item_id = self.http_tree.insert("", "end", values=(
                i + 1,
                rec.timestamp,
                method_display,
                rec.http_host or "?",
                path_display,
                rec.src_ip,
            ), tags=(tag,) if tag else ())
            
        # autoscroll after refresh
        if self.http_autoscroll_var.get() and hasattr(self, 'http_tree') and self.http_tree.get_children():
            self.http_tree.see(self.http_tree.get_children()[-1])

    def _on_http_select(self, event):
        sel = self.http_tree.selection()
        if not sel:
            return
        values = self.http_tree.item(sel[0], "values")
        if not values:
            return
        idx = int(values[0]) - 1
        if 0 <= idx < len(self._http_records):
            self._show_detail(self._http_records[idx], int(values[0]))
            self.notebook.select(3)

    def _show_detail(self, rec: PacketRecord, num: int):
        """Populate the detail tab with a pretty breakdown of the packet."""
        t = self._detail_text
        t.config(state="normal")
        t.delete("1.0", "end")

        # Title
        t.insert("end", f"  Packet #{num}\n", "heading")
        t.insert("end", "─" * 60 + "\n\n", "separator")

        # Basic info
        fields = [
            ("Timestamp",    rec.timestamp),
            ("Protocol",     rec.protocol),
            ("Source IP",    rec.src_ip),
            ("Dest IP",     rec.dst_ip),
            ("Source Port",  str(rec.src_port) if rec.src_port else "—"),
            ("Dest Port",   str(rec.dst_port) if rec.dst_port else "—"),
            ("Length",       f"{rec.length} bytes"),
            ("Flags",        rec.flags or "—"),
        ]
        t.insert("end", "  Network Layer\n", "subheading")
        for key, val in fields:
            t.insert("end", f"    {key:<16}", "key")
            t.insert("end", f"  {val}\n", "value")

        # HTTP info
        if rec.http_method or rec.http_host:
            t.insert("end", "\n  HTTP Details\n", "subheading")
            http_fields = [
                ("Method",       rec.http_method or "—"),
                ("Host",         rec.http_host or "—"),
                ("Path",         rec.http_path or "—"),
                ("Content-Type", rec.http_content_type or "—"),
            ]
            for key, val in http_fields:
                t.insert("end", f"    {key:<16}", "key")
                t.insert("end", f"  {val}\n", "value")
            
            # Show Body
            if rec.http_body:
                t.insert("end", "\n    HTTP Body Content\n", "subheading")
                try:
                    body_text = rec.http_body.decode("utf-8", errors="replace")
                    # Clean up for display
                    body_display = body_text.strip()
                    if len(body_display) > 2000:
                        body_display = body_display[:2000] + "\n\n[... content truncated ...]"
                    t.insert("end", f"      {body_display}\n", "value")
                except Exception:
                    t.insert("end", "      <Binary or Malformed Data>\n", "value")

        # DNS
        if rec.dns_query:
            t.insert("end", "\n  DNS Query\n", "subheading")
            t.insert("end", f"    Name            ", "key")
            t.insert("end", f"  {rec.dns_query}\n", "value")

        # Credentials
        if rec.credentials:
            t.insert("end", "\n  ⚠  Credentials Detected\n", "cred_key")
            t.insert("end", "  " + "═" * 40 + "\n", "cred_key")
            for k, v in rec.credentials.items():
                t.insert("end", f"    {k:<16}", "cred_key")
                t.insert("end", f"  {v}\n", "cred_value")
            t.insert("end", "  " + "═" * 40 + "\n", "cred_key")



        # Tags
        if rec.tags:
            t.insert("end", "\n  Tags:  ", "key")
            for tag in rec.tags:
                t.insert("end", f"  {tag}  ", "tag_badge")
                t.insert("end", "  ", "key")
            t.insert("end", "\n")

        # Raw payload (hex dump, first 256 bytes)
        if rec.raw_payload:
            t.insert("end", "\n  Raw Payload (hex)\n", "subheading")
            hex_lines = _hex_dump(rec.raw_payload[:256])
            for line in hex_lines:
                t.insert("end", f"    {line}\n", "key")

        t.config(state="disabled")



    # ── Queue polling & tree updates ──────────────────────────────────

    def _poll_queue(self):
        """Drain the packet queue and update the UI."""
        batch = 0
        autoscroll = True
        try:
            # Check if we should autoscroll (user is near bottom)
            last = self.tree.get_children()
            if last:
                vis = self.tree.yview()
                autoscroll = vis[1] > 0.95
        except Exception:
            pass

        while batch < 40:  # process up to 40 packets per tick
            try:
                rec: PacketRecord = self.pkt_queue.get_nowait()
            except queue.Empty:
                break
            batch += 1
            self._packet_index += 1
            self._records.append(rec)
            self._proto_counts[rec.protocol] += 1
            self._total_bytes += rec.length

            # Determine tags
            tags = []
            proto_tag = f"proto_{rec.protocol.replace('/', '_')}"
            tags.append(proto_tag)
            if rec.severity == "critical":
                tags.append("critical")
            elif rec.severity == "warning":
                tags.append("warning")
            tags.append("row_even" if self._packet_index % 2 == 0 else "row_odd")

            info_text = rec.info
            if rec.tags:
                info_text += "  [" + ", ".join(rec.tags) + "]"

            self.tree.insert("", "end", values=(
                self._packet_index,
                rec.timestamp,
                rec.protocol,
                f"{rec.src_ip}" + (f":{rec.src_port}" if rec.src_port else ""),
                f"{rec.dst_ip}" + (f":{rec.dst_port}" if rec.dst_port else ""),
                rec.length,
                info_text,
            ), tags=tuple(tags))

            # Credentials
            if rec.credentials:
                self._cred_records.append(rec)
                self.cred_tree.insert("", "end", values=(
                    len(self._cred_records),
                    rec.timestamp,
                    rec.credentials.get("method", "?"),
                    rec.http_host or rec.dst_ip,
                    rec.credentials.get("username", "?"),
                    rec.credentials.get("password", "?"),
                    rec.src_ip,
                    rec.dst_ip,
                ), tags=("cred_row",))

            # HTTP Access Log (HTTP / HTTPS)
            if rec.http_method or rec.http_host or rec.protocol == "TLS/HTTPS":
                self._http_records.append(rec)
                
                if self.show_https_var.get() or rec.protocol != "TLS/HTTPS":
                    tag = "https_row" if rec.protocol == "TLS/HTTPS" else ""
                    # Method might be missing for HTTPS / pure Host sniffs
                    method_display = rec.http_method or (
                        "HTTPS" if rec.protocol == "TLS/HTTPS" else "?"
                    )
                    
                    path_display = rec.http_path or ("<encrypted>" if rec.protocol == "TLS/HTTPS" else "/")
                    item_id = self.http_tree.insert("", "end", values=(
                        len(self._http_records),
                        rec.timestamp,
                        method_display,
                        rec.http_host or "?",
                        path_display,
                        rec.src_ip,
                    ), tags=(tag,) if tag else ())
                    
                    if self.http_autoscroll_var.get():
                        self.http_tree.see(item_id)

            # DNS lookups
            if rec.protocol == "DNS" and rec.dns_query:
                dns_win = self.dns_window
                if dns_win is not None:
                    dns_win.add_log(rec.timestamp, rec.src_ip, rec.dns_query)

        # Trim tree if too large
        children = self.tree.get_children()
        if len(children) > self.MAX_TREE_ROWS:
            for item in children[:len(children) - self.MAX_TREE_ROWS]:
                self.tree.delete(item)

        if batch > 0:
            self._update_stats()
            if autoscroll and self.tree.get_children():
                self.tree.see(self.tree.get_children()[-1])

        # Blink the live dot
        if self._packet_index % 4 < 2:
            self._live_dot.config(fg=COLORS["green"])
        else:
            self._live_dot.config(fg=COLORS["green_dim"])

        if not self.stop_event.is_set():
            self.root.after(self.POLL_INTERVAL_MS, self._poll_queue)

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self.stop_event.set()
        self.root.destroy()


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _hex_dump(data: bytes, width: int = 16) -> list[str]:
    """Return a list of hex-dump lines."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return lines
