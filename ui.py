#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Multi-Tool GUI: DNS Spoofer, ARP Poisoner & SSL Stripper
Compatible with Python 2.7 and Python 3.x
"""
from __future__ import print_function
import threading
import logging
import os

# Tkinter imports across versions
try:
    import Tkinter as tk
    import ttk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
except ImportError:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter import ttk

# Scapy helpers
from scapy.all import get_if_list

# Core modules (ensure dns.py, arpprotocol.py, sslpro.py and sslstrip.py are alongside)
from dns import DNSSpoofer, load_mapping
from arppro import ActivePairSpoofer, FloodSpoofer, SilentResponder, resolve_mac, PoisonManager
import sslpro
import sslstrip

class TextHandler(logging.Handler):
    """Log to a Tk Text widget"""
    def __init__(self, widget):
        super(TextHandler, self).__init__()
        self.widget = widget
    def emit(self, record):
        msg = self.format(record)
        def append():
            self.widget.configure(state='normal')
            self.widget.insert(tk.END, msg + '\n')
            self.widget.configure(state='disabled')
            self.widget.see(tk.END)
        self.widget.after(0, append)

class ToolUI(tk.Frame):
    def __init__(self, master=None):
        super(ToolUI, self).__init__(master)
        self.master = master
        self.grid(padx=10, pady=10)
        self.dns_thread = None
        self.arp_mgr = None
        self.ssl_thread = None
        self.create_widgets()
        self.setup_logging()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        self.dns_tab = ttk.Frame(nb)
        self.arp_tab = ttk.Frame(nb)
        self.ssl_tab = ttk.Frame(nb)
        nb.add(self.dns_tab, text='DNS Spoofer')
        nb.add(self.arp_tab, text='ARP Poisoner')
        nb.add(self.ssl_tab, text='SSL Stripper')
        nb.grid(row=0, column=0, columnspan=3)
        self._build_dns_tab()
        self._build_arp_tab()
        self._build_ssl_tab()
        self._build_log_view()

    # -- DNS Tab --
    def _build_dns_tab(self):
        row=0
        ttk.Label(self.dns_tab, text='Interface:').grid(row=row, column=0, sticky='e')
        ifs = get_if_list()
        self.dns_iface = tk.StringVar(value=ifs[0] if ifs else '')
        ttk.OptionMenu(self.dns_tab, self.dns_iface, self.dns_iface.get(), *ifs).grid(row=row, column=1)
        row+=1
        ttk.Label(self.dns_tab, text='Mapping YAML:').grid(row=row, column=0, sticky='e')
        self.map_path = tk.StringVar()
        ttk.Entry(self.dns_tab, textvariable=self.map_path, width=30).grid(row=row, column=1)
        ttk.Button(self.dns_tab, text='Browse...', command=self._browse_map).grid(row=row, column=2)
        row+=1
        ttk.Label(self.dns_tab, text='Upstream DNS:').grid(row=row, column=0, sticky='e')
        self.upstream = tk.StringVar(value='8.8.8.8')
        ttk.Entry(self.dns_tab, textvariable=self.upstream).grid(row=row, column=1)
        row+=1
        ttk.Label(self.dns_tab, text='TTL:').grid(row=row, column=0, sticky='e')
        self.ttl = tk.IntVar(value=300)
        ttk.Entry(self.dns_tab, textvariable=self.ttl).grid(row=row, column=1)
        row+=1
        self.relay_dns = tk.BooleanVar()
        ttk.Checkbutton(self.dns_tab, text='Relay unmatched', variable=self.relay_dns).grid(row=row, columnspan=2, sticky='w')
        row+=1
        self.verbose_dns = tk.BooleanVar()
        self.quiet_dns = tk.BooleanVar()
        ttk.Checkbutton(self.dns_tab, text='Verbose', variable=self.verbose_dns).grid(row=row, column=0)
        ttk.Checkbutton(self.dns_tab, text='Quiet', variable=self.quiet_dns).grid(row=row, column=1)
        row+=1
        ttk.Label(self.dns_tab, text='BPF filter:').grid(row=row, column=0, sticky='e')
        self.bpf_dns = tk.StringVar()
        ttk.Entry(self.dns_tab, textvariable=self.bpf_dns).grid(row=row, column=1)
        row+=1
        ttk.Button(self.dns_tab, text='Start DNS', command=self.start_dns).grid(row=row, column=0)
        ttk.Button(self.dns_tab, text='Stop DNS', command=self.stop_dns).grid(row=row, column=1)

    # -- ARP Tab --
    def _build_arp_tab(self):
        row=0
        ttk.Label(self.arp_tab, text='Interface:').grid(row=row, column=0, sticky='e')
        ifs = get_if_list()
        self.arp_iface = tk.StringVar(value=ifs[0] if ifs else '')
        ttk.OptionMenu(self.arp_tab, self.arp_iface, self.arp_iface.get(), *ifs).grid(row=row, column=1)
        row+=1
        ttk.Label(self.arp_tab, text='Mode:').grid(row=row, column=0, sticky='e')
        self.mode = tk.StringVar(value='pair')
        ttk.OptionMenu(self.arp_tab, self.mode, 'pair','pair','flood','silent').grid(row=row, column=1)
        row+=1
        ttk.Label(self.arp_tab, text='Victims (CSV):').grid(row=row, column=0, sticky='e')
        self.victims = tk.StringVar()
        ttk.Entry(self.arp_tab, textvariable=self.victims).grid(row=row, column=1)
        row+=1
        ttk.Label(self.arp_tab, text='Gateway IP:').grid(row=row, column=0, sticky='e')
        self.gateway = tk.StringVar()
        ttk.Entry(self.arp_tab, textvariable=self.gateway).grid(row=row, column=1)
        row+=1
        ttk.Label(self.arp_tab, text='CIDR:').grid(row=row, column=0, sticky='e')
        self.cidr = tk.StringVar()
        ttk.Entry(self.arp_tab, textvariable=self.cidr).grid(row=row, column=1)
        row+=1
        ttk.Label(self.arp_tab, text='Interval (s):').grid(row=row, column=0, sticky='e')
        self.interval = tk.DoubleVar(value=10.0)
        ttk.Entry(self.arp_tab, textvariable=self.interval).grid(row=row, column=1)
        row+=1
        self.no_restore = tk.BooleanVar()
        ttk.Checkbutton(self.arp_tab, text='Skip restore', variable=self.no_restore).grid(row=row, columnspan=2, sticky='w')
        row+=1
        ttk.Button(self.arp_tab, text='Start ARP', command=self.start_arp).grid(row=row, column=0)
        ttk.Button(self.arp_tab, text='Stop ARP', command=self.stop_arp).grid(row=row, column=1)

    # -- SSL Tab --
    def _build_ssl_tab(self):
        row=0
        ttk.Label(self.ssl_tab, text='Interface:').grid(row=row, column=0, sticky='e')
        ifs = get_if_list()
        self.ssl_iface = tk.StringVar(value=ifs[0] if ifs else '')
        ttk.OptionMenu(self.ssl_tab, self.ssl_iface, self.ssl_iface.get(), *ifs).grid(row=row, column=1)
        row+=1
        ttk.Label(self.ssl_tab, text='Mode:').grid(row=row, column=0, sticky='e')
        self.ssl_mode = tk.StringVar(value='sslpro')
        ttk.OptionMenu(self.ssl_tab, self.ssl_mode, 'sslpro','sslpro','sslstrip').grid(row=row, column=1)
        row+=1
        ttk.Label(self.ssl_tab, text='BPF filter:').grid(row=row, column=0, sticky='e')
        self.ssl_bpf = tk.StringVar(value='tcp port 80')
        ttk.Entry(self.ssl_tab, textvariable=self.ssl_bpf).grid(row=row, column=1)
        row+=1
        ttk.Label(self.ssl_tab, text='Hosts (CSV):').grid(row=row, column=0, sticky='e')
        self.ssl_hosts = tk.StringVar()
        ttk.Entry(self.ssl_tab, textvariable=self.ssl_hosts).grid(row=row, column=1)
        row+=1
        self.ssl_verbose = tk.BooleanVar()
        self.ssl_quiet   = tk.BooleanVar()
        ttk.Checkbutton(self.ssl_tab, text='Verbose', variable=self.ssl_verbose).grid(row=row, column=0)
        ttk.Checkbutton(self.ssl_tab, text='Quiet',   variable=self.ssl_quiet).grid(row=row, column=1)
        row+=1
        ttk.Button(self.ssl_tab, text='Start SSL Strip', command=self.start_ssl).grid(row=row, column=0)
        ttk.Button(self.ssl_tab, text='Stop SSL Strip',  command=self.stop_ssl).grid(row=row, column=1)

    def _build_log_view(self):
        ttk.Label(self, text='Logs:').grid(row=1, column=0, sticky='nw')
        self.log_text = tk.Text(self, height=15, width=80, state='disabled', wrap='word')
        self.log_text.grid(row=1, column=1, columnspan=2)

    def _browse_map(self):
        path = filedialog.askopenfilename(filetypes=[('YAML','*.yml *.yaml'),('All','*.*')])
        if path: self.map_path.set(path)

    def setup_logging(self):
        handler = TextHandler(self.log_text)
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%H:%M:%S')
        handler.setFormatter(fmt)
        logging.getLogger().addHandler(handler)

    # -- DNS Control --
    def start_dns(self):
        if self.dns_thread: return
        try:
            mapping = load_mapping(self.map_path.get())
        except Exception as e:
            messagebox.showerror('Error', str(e)); return
        self.dns_thread = DNSSpoofer(
            iface=self.dns_iface.get(), mapping=mapping,
            upstream=self.upstream.get(), relay=self.relay_dns.get(),
            ttl=self.ttl.get(), bpf=self.bpf_dns.get() or None
        )
        self.dns_thread.start()
        logging.info('DNS spoofer started on %s', self.dns_iface.get())

    def stop_dns(self):
        if not self.dns_thread: return
        self.dns_thread.stop(); self.dns_thread.join(1); self.dns_thread=None
        logging.info('DNS spoofer stopped')

    # -- ARP Control --
    def start_arp(self):
        if self.arp_mgr: return
        self.arp_mgr = PoisonManager()
        mode = self.mode.get(); iface = self.arp_iface.get()
        victims = [v.strip() for v in self.victims.get().split(',') if v.strip()]
        gw_ip = self.gateway.get(); gw_mac = resolve_mac(gw_ip) if gw_ip else None
        for vip in victims:
            vmac = resolve_mac(vip)
            if mode=='pair': t=ActivePairSpoofer(iface,(vip,vmac),(gw_ip,gw_mac),get_if_list()[0],self.interval.get())
            elif mode=='silent': t=SilentResponder(iface,(vip,vmac),(gw_ip,gw_mac),get_if_list()[0])
            self.arp_mgr.add(t)
        if mode=='flood' and self.cidr.get():
            t=FloodSpoofer(iface,self.cidr.get(),gw_ip,get_if_list()[0],self.interval.get())
            self.arp_mgr.add(t)
        logging.info('ARP poisoning started (mode=%s)', mode)

    def stop_arp(self):
        if not self.arp_mgr: return
        self.arp_mgr.stop_all(); self.arp_mgr=None
        logging.info('ARP poisoning stopped')

    # -- SSL Strip Control --
    def start_ssl(self):
        if self.ssl_thread: return
        iface = self.ssl_iface.get(); mode = self.ssl_mode.get()
        bpf = self.ssl_bpf.get(); hosts = [h.strip() for h in self.ssl_hosts.get().split(',') if h.strip()]
        verbose = self.ssl_verbose.get(); quiet = self.ssl_quiet.get()
        if mode=='sslpro':
            t = threading.Thread(target=sslpro.main, args=(iface, bpf, hosts, verbose, quiet), daemon=True)
        else:
            t = threading.Thread(target=sslstrip.main, args=(iface,), daemon=True)
        self.ssl_thread = t; t.start()
        logging.info('SSL stripper (%s) started on %s', mode, iface)

    def stop_ssl(self):
        # Note: stopping threads gracefully depends on module support
        logging.info('Stopping SSL stripper... (may require Ctrl-C)')
        self.ssl_thread = None

if __name__=='__main__':
    root = tk.Tk(); root.title('Multi-Tool GUI')
    app = ToolUI(master=root)
    app.mainloop()