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
import logging
from scapy.all import get_if_list

# ensure dnspro.py is importable
base = os.path.dirname(os.path.abspath(__file__))
if base not in sys.path:
    sys.path.insert(0, base)

# load backend
try:
    import imp
    dns_mod = imp.load_source('dnspro', os.path.join(base, 'dnspro.py'))
    DNSSpoofer = dns_mod.DNSSpoofer
    load_mapping = dns_mod.load_mapping
except Exception as e:
    tk.Tk().withdraw()
    messagebox.showerror('Import Error', 'Failed to load dnspro.py: %s' % e)
    sys.exit(1)

class GUIHandler(logging.Handler):
    """Send log events to a Tk Text widget."""
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.widget = widget
    def emit(self, record):
        msg = self.format(record) + '\n'
        def write():
            self.widget.insert(tk.END, msg)
            self.widget.see(tk.END)
        self.widget.after(0, write)

class DNSGui(tk.Frame):
    # Removed the 10.0.0.0/8 preset per user request
    BPF_PRESETS = [
        'udp or tcp port 53',
        'dst port 53 and src host 192.168.1.100',
    ]

    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        master.title('DNS Spoofer GUI')
        # allow frame to expand
        self.pack(fill='both', expand=True)
        # configure grid resizing
        self.columnconfigure(1, weight=1)
        # Log text will be at this row
        self._text_row = None

        self.spoofer = None
        self.log_handler = None
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self._build_widgets()

    def _build_widgets(self):
        r = 0
        tk.Label(self, text='Interface:').grid(row=r, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        tk.OptionMenu(self, self.iface_var, *get_if_list()).grid(row=r, column=1, sticky='w')

        r += 1
        tk.Label(self, text='Mapping file:').grid(row=r, column=0, sticky='e')
        self.map_path = tk.Entry(self)
        self.map_path.grid(row=r, column=1, sticky='ew')
        tk.Button(self, text='Browse', command=self._browse_map).grid(row=r, column=2)

        r += 1
        self.relay_var = tk.BooleanVar()
        tk.Checkbutton(self, text='Relay unmatched', variable=self.relay_var).grid(row=r, columnspan=3, sticky='w')

        r += 1
        tk.Label(self, text='Upstream DNS:').grid(row=r, column=0, sticky='e')
        self.upstream = tk.Entry(self)
        self.upstream.insert(0, '8.8.8.8')
        self.upstream.grid(row=r, column=1, sticky='w')

        r += 1
        tk.Label(self, text='TTL (secs):').grid(row=r, column=0, sticky='e')
        self.ttl = tk.Spinbox(self, from_=1, to=3600)
        self.ttl.delete(0, tk.END); self.ttl.insert(0, '300')
        self.ttl.grid(row=r, column=1, sticky='w')

        r += 1
        tk.Label(self, text='BPF filter:').grid(row=r, column=0, sticky='e')
        self.bpf = tk.Entry(self)
        self.bpf.insert(0, self.BPF_PRESETS[0])
        self.bpf.grid(row=r, column=1, sticky='ew')
        tk.Button(self, text='⋯', width=3, command=self._choose_bpf).grid(row=r, column=2)

        r += 1
        tk.Label(self, text='Log level:').grid(row=r, column=0, sticky='e')
        self.log_level = tk.StringVar(value='INFO')
        tk.OptionMenu(self, self.log_level, 'DEBUG', 'INFO', 'ERROR').grid(row=r, column=1, sticky='w')

        r += 1
        self.start_btn = tk.Button(self, text='Start', command=self._start)
        self.start_btn.grid(row=r, column=0)
        self.stop_btn = tk.Button(self, text='Stop', command=self._stop, state='disabled')
        self.stop_btn.grid(row=r, column=1)

        r += 1
        tk.Label(self, text='Log output:').grid(row=r, columnspan=3, sticky='w')

        r += 1
        # record text row for resizing
        self._text_row = r
        self.rowconfigure(self._text_row, weight=1)
        self.log_text = tk.Text(self)
        self.log_text.grid(row=r, column=0, columnspan=3, sticky='nsew')

    def _browse_map(self):
        p = filedialog.askopenfilename(filetypes=[('YAML','*.yml'),('All files','*.*')])
        if p:
            self.map_path.delete(0, tk.END)
            self.map_path.insert(0, p)

    def _choose_bpf(self):
        dlg = tk.Toplevel(self)
        dlg.title('BPF Preset')
        lb = tk.Listbox(dlg, height=len(self.BPF_PRESETS), width=50)
        for it in self.BPF_PRESETS:
            lb.insert(tk.END, it)
        lb.pack(padx=10, pady=5)
        ent = tk.Entry(dlg, width=50)
        ent.insert(0, self.bpf.get())
        ent.pack(padx=10, pady=5)
        def sel(evt):
            v = lb.get(lb.curselection())
            ent.delete(0, tk.END); ent.insert(0, v)
        lb.bind('<Double-Button-1>', sel)
        frm = tk.Frame(dlg); frm.pack(pady=5)
        tk.Button(frm, text='OK', command=lambda: [self.bpf.delete(0, tk.END), self.bpf.insert(0, ent.get()), dlg.destroy()]).pack(side='left', padx=5)
        tk.Button(frm, text='Cancel', command=dlg.destroy).pack(side='left')

    def _start(self):
        if self.log_handler:
            self.logger.removeHandler(self.log_handler)
        self.log_text.delete('1.0', tk.END)
        lvl = getattr(logging, self.log_level.get(), logging.INFO)
        self.logger.setLevel(lvl)
        self.log_handler = GUIHandler(self.log_text)
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(self.log_handler)

        iface = self.iface_var.get()
        if not iface:
            messagebox.showerror('Error', 'Select interface'); return
        mp = self.map_path.get()
        if not mp:
            messagebox.showerror('Error', 'Select mapping'); return
        try:
            m = load_mapping(mp)
        except Exception as e:
            messagebox.showerror('Error', str(e)); return

        self.spoofer = DNSSpoofer(iface=iface, mapping=m,
                                  upstream=self.upstream.get(), relay=self.relay_var.get(),
                                  ttl=int(self.ttl.get()), bpf=self.bpf.get())
        self.spoofer.start()
        self.start_btn.config(state='disabled'); self.stop_btn.config(state='normal')
        # Display configuration
        self.logger.info('Configuration:')
        self.logger.info('  BPF filter: %s', self.bpf.get())
        self.logger.info('  TTL: %s seconds', self.ttl.get())
        self.logger.info('  Relay unmatched: %s', self.relay_var.get())
        self.logger.info('  Upstream DNS: %s', self.upstream.get())
        self.logger.info('  Log level: %s', self.log_level.get())
        self.logger.info('Started on %s', iface)

    def _stop(self):
        if self.spoofer:
            self.spoofer.stop(); self.logger.info('Stopped'); self.spoofer = None
        self.start_btn.config(state='normal'); self.stop_btn.config(state='disabled')

if __name__ == '__main__':
    root = tk.Tk()
    DNSGui(master=root)
    root.mainloop()