#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
interface.py -- DNS Spoofer GUI for Python-2.7
Provides a Tkinter-based interface to the local dnspro.py DNS spoofing tool.
Requires root privileges (e.g. sudo) to run.
"""

import sys
try:
    import Tkinter as tk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
    import tkSimpleDialog as simpledialog
except ImportError:
    sys.exit('Tkinter not found; install python-tk')

import os
import sys as _sys
import logging
from scapy.all import get_if_list

# Ensure dnspro.py is importable
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in _sys.path:
    _sys.path.insert(0, script_dir)

# Import the CLI spoofer module
try:
    import imp
    dns_mod = imp.load_source('dnspro', os.path.join(script_dir, 'dnspro.py'))
    DNSSpoofer = dns_mod.DNSSpoofer
    load_mapping = dns_mod.load_mapping
except Exception as e:
    tk.Tk().withdraw()
    messagebox.showerror('Import Error', 'Failed to load dnspro.py: %s' % e)
    _sys.exit(1)

# Main GUI
class GUIHandler(logging.Handler):
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
    def emit(self, record):
        msg = self.format(record) + '\n'
        def append():
            self.text_widget.insert(tk.END, msg)
            self.text_widget.see(tk.END)
        self.text_widget.after(0, append)

class DNSGui(tk.Frame):
    BPF_PRESETS = [
        'udp or tcp port 53',
        'net 10.0.0.0/8 and udp port 53',
        'dst port 53 and src host 192.168.1.100',
    ]

    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        master.title('DNS Spoofer GUI')
        self.spoofer = None
        self.log_handler = None
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self._build_widgets()

    def _build_widgets(self):
        row = 0
        tk.Label(self, text='Interface:').grid(row=row, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        self.iface_menu = tk.OptionMenu(self, self.iface_var, *get_if_list())
        self.iface_menu.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text='Mapping file:').grid(row=row, column=0, sticky='e')
        self.map_path = tk.Entry(self, width=40)
        self.map_path.grid(row=row, column=1)
        tk.Button(self, text='Browse...', command=self._browse_map).grid(row=row, column=2)

        row += 1
        self.relay_var = tk.BooleanVar()
        tk.Checkbutton(self, text='Relay unmatched queries', variable=self.relay_var).grid(row=row, columnspan=3, sticky='w')

        row += 1
        tk.Label(self, text='Upstream DNS:').grid(row=row, column=0, sticky='e')
        self.upstream = tk.Entry(self)
        self.upstream.insert(0, '8.8.8.8')
        self.upstream.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text='TTL (secs):').grid(row=row, column=0, sticky='e')
        self.ttl = tk.Spinbox(self, from_=1, to=3600)
        self.ttl.delete(0, tk.END)
        self.ttl.insert(0, '300')
        self.ttl.grid(row=row, column=1, sticky='w')

        row += 1
        tk.Label(self, text='BPF filter:').grid(row=row, column=0, sticky='e')
        self.bpf = tk.Entry(self)
        self.bpf.insert(0, self.BPF_PRESETS[0])
        self.bpf.grid(row=row, column=1, sticky='w')
        tk.Button(self, text='⋯', width=2, command=self._choose_bpf).grid(row=row, column=2)

        row += 1
        tk.Label(self, text='Log level:').grid(row=row, column=0, sticky='e')
        self.log_level = tk.StringVar(value='INFO')
        tk.OptionMenu(self, self.log_level, 'DEBUG', 'INFO', 'ERROR').grid(row=row, column=1, sticky='w')

        row += 1
        self.start_btn = tk.Button(self, text='Start', command=self._start)
        self.start_btn.grid(row=row, column=0)
        self.stop_btn = tk.Button(self, text='Stop', command=self._stop, state='disabled')
        self.stop_btn.grid(row=row, column=1)

        row += 1
        tk.Label(self, text='Log output:').grid(row=row, columnspan=3)
        row += 1
        self.log_text = tk.Text(self, height=15, width=70)
        self.log_text.grid(row=row, columnspan=3)

        self.grid(padx=10, pady=10)

    def _browse_map(self):
        path = filedialog.askopenfilename(filetypes=[('YAML','*.yml;*.yaml'),('All','*.*')])
        if path:
            self.map_path.delete(0, tk.END)
            self.map_path.insert(0, path)

    def _choose_bpf(self):
        choice = simpledialog.askstring('BPF Presets',
            'Select or edit filter:',
            initialvalue=self.bpf.get())
        if choice:
            self.bpf.delete(0, tk.END)
            self.bpf.insert(0, choice)

    def _start(self):
        if self.log_handler:
            self.logger.removeHandler(self.log_handler)
        self.log_text.delete('1.0', tk.END)
        level = getattr(logging, self.log_level.get(), logging.INFO)
        self.logger.setLevel(level)
        self.log_handler = GUIHandler(self.log_text)
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(self.log_handler)

        iface = self.iface_var.get()
        if not iface:
            messagebox.showerror('Error','Select an interface')
            return
        mapfile = self.map_path.get()
        if not mapfile:
            messagebox.showerror('Error','Select a mapping file')
            return
        try:
            mapping = load_mapping(mapfile)
        except Exception as e:
            messagebox.showerror('Mapping Error', str(e)); return

        self.spoofer = DNSSpoofer(iface=iface, mapping=mapping,
                                  upstream=self.upstream.get(), relay=self.relay_var.get(),
                                  ttl=int(self.ttl.get()), bpf=self.bpf.get() or None)
        self.spoofer.start()
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.logger.info('Started on %s', iface)

    def _stop(self):
        if self.spoofer:
            self.spoofer.stop()
            self.logger.info('Stopping')
            self.spoofer = None
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

if __name__ == '__main__':
    root = tk.Tk()
    app = DNSGui(master=root)
    app.mainloop()