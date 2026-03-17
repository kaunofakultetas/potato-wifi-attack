import tkinter as tk
from tkinter import ttk

class DNSLogWindow:
    def __init__(self, parent_root, colors):
        self.top = tk.Toplevel(parent_root)
        self.top.title("DNS Lookup Log")
        self.top.geometry("700x400")
        self.top.configure(bg=colors["bg"])
        
        # Header
        lbl = tk.Label(self.top, text="DNS Lookups", font=("Inter", 14, "bold"),
                       bg=colors["bg"], fg=colors["proto_dns"])
        lbl.pack(anchor="w", padx=16, pady=(16, 8))
        
        # Treeview
        container = tk.Frame(self.top, bg=colors["bg_secondary"])
        container.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        
        cols = ("time", "source", "query")
        self.tree = ttk.Treeview(container, columns=cols, show="headings",
                                 style="Packet.Treeview", selectmode="browse")
        
        col_cfg = {
            "time": ("Time", 100, "center"),
            "source": ("Source IP", 150, "w"),
            "query": ("DNS Query", 400, "w"),
        }
        
        for col, (heading, width, anchor) in col_cfg.items():
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, anchor=anchor) # type: ignore
            
        self.tree.tag_configure("dns_row", foreground=colors["proto_dns"])
            
        # Scrollbars
        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview,
                            style="Dark.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        
        # Handle close window to just hide it
        self.top.protocol("WM_DELETE_WINDOW", self.hide)
        
    def add_log(self, timestamp, src_ip, dns_query):
        self.tree.insert("", "end", values=(timestamp, src_ip, dns_query), tags=("dns_row",))
        # Autoscroll
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])
            
    def show(self):
        self.top.deiconify()
        
    def hide(self):
        self.top.withdraw()
