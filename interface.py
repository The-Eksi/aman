#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DNS Spoofer GUI (Python 2.7 & Python 3.x compatibility)
Provides a Tkinter-based interface to the local dns.py DNS spoofing tool.

Requires root privileges (e.g. sudo) to run.
"""
import sys
import threading
import logging
import yaml

# Tkinter compatibility for Python2 & Python3
try:
    import Tkinter as tk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
except ImportError:
    import tkinter as tk
    from tkinter import filedialog, messagebox

# Scapy interface enumeration
from scapy.all import get_if_list

# Import the local DNS spoofer module (dns.py) without colliding with external 'dns' packages
import os, sys
script_dir = os.path.dirname(os.path.abspath(__file__))
dns_path = os.path.join(script_dir, 'dns.py')
if dns_path not in sys.path:
    # ensure local directory on path for direct import
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

try:
    # Try import local dns module
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader('local_dns', dns_path)
    dns_mod = loader.load_module()
    DNSSpoofer = dns_mod.DNSSpoofer
    load_mapping = dns_mod.load_mapping
except Exception as e:
    messagebox.showerror("Import Error", f"Failed to load dns.py: {e}")
    sys.exit(1)

class GUIHandler(logging.Handler):
    """Custom logging handler to redirect logs to a Tkinter Text widget."""
    def __init__(self, text_widget):
        super(GUIHandler, self).__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record) + '\n'
        def append():
            self.text_widget.insert(tk.END, msg)
            self.text_widget.see(tk.END)
        self.text_widget.after(0, append)

class DNSGui(tk.Frame):
    def __init__(self, master=None):
        super(DNSGui, self).__init__(master)
        master.title("DNS Spoofer GUI")
        self.spoofer = None
        self._build_widgets()

    def _build_widgets(self):
        row = 0
        tk.Label(self, text="Interface:").grid(row=row, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        self.iface_menu = tk.OptionMenu(self, self.iface_var, *get_if_list())
        self.iface_menu.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text="Mapping file:").grid(row=row, column=0, sticky='e')
        self.map_path = tk.Entry(self, width=40)
        self.map_path.grid(row=row, column=1)
        tk.Button(self, text="Browse...", command=self._browse_map).grid(row=row, column=2)

        row += 1
        self.relay_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Relay unmatched queries", variable=self.relay_var).grid(row=row, columnspan=3, sticky='w')

        row += 1
        tk.Label(self, text="Upstream DNS:").grid(row=row, column=0, sticky='e')
        self.upstream = tk.Entry(self)
        self.upstream.insert(0, "8.8.8.8")
        self.upstream.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text="TTL (secs):").grid(row=row, column=0, sticky='e')
        self.ttl = tk.Spinbox(self, from_=1, to=3600)
        self.ttl.delete(0, tk.END)
        self.ttl.insert(0, "300")
        self.ttl.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text="BPF filter:").grid(row=row, column=0, sticky='e')
        self.bpf = tk.Entry(self)
        self.bpf.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text="Log level:").grid(row=row, column=0, sticky='e')
        self.log_level = tk.StringVar(value='INFO')
        tk.OptionMenu(self, self.log_level, 'DEBUG', 'INFO', 'ERROR').grid(row=row, column=1, sticky='w')

        row += 1
        self.start_btn = tk.Button(self, text="Start", command=self._start)
        self.start_btn.grid(row=row, column=0)
        self.stop_btn = tk.Button(self, text="Stop", command=self._stop, state='disabled')
        self.stop_btn.grid(row=row, column=1)

        row += 1
        tk.Label(self, text="Log output:").grid(row=row, columnspan=3)
        row += 1
        self.log_text = tk.Text(self, height=15, width=70)
        self.log_text.grid(row=row, columnspan=3)

        self.grid(padx=10, pady=10)

    def _browse_map(self):
        path = filedialog.askopenfilename(filetypes=[('YAML', '*.yml;*.yaml'), ('All files','*.*')])
        if path:
            self.map_path.delete(0, tk.END)
            self.map_path.insert(0, path)

    def _start(self):
        iface = self.iface_var.get()
        if not iface:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        mapfile = self.map_path.get()
        if not mapfile:
            messagebox.showerror("Error", "Please select a YAML mapping file.")
            return
        try:
            from pathlib import Path
            # load_mapping expects a Path object
            mapping = load_mapping(Path(mapfile))
        except Exception as e:
            messagebox.showerror("Mapping Error", str(e))
            return

        level = getattr(logging, self.log_level.get(), logging.INFO)
        logging.basicConfig(level=level, format="%(asctime)s %(message)s")
        handler = GUIHandler(self.log_text)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logging.getLogger().addHandler(handler)

        self.spoofer = DNSSpoofer(
            iface=iface,
            mapping=mapping,
            upstream=self.upstream.get(),
            relay=self.relay_var.get(),
            ttl=int(self.ttl.get()),
            bpf=self.bpf.get() or None,
        )
        self.spoofer.start()

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        logging.info("DNS Spoofer started on %s", iface)

    def _stop(self):
        if self.spoofer:
            self.spoofer.stop()
            logging.info("DNS Spoofer stopping…")
            self.spoofer = None
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

if __name__ == '__main__':
    root = tk.Tk()
    app = DNSGui(master=root)
    app.mainloop()
