import Tkinter as tk
import ttk
import threading
import subprocess
import os
import sys
import logging
from scapy.all import get_if_list

# Import DNS backend
base = os.path.dirname(os.path.abspath(__file__))
if base not in sys.path:
    sys.path.insert(0, base)
try:
    import imp
    dns_mod = imp.load_source('dnspro', os.path.join(base, 'dnspro.py'))
    DNSSpoofer = dns_mod.DNSSpoofer
    load_mapping = dns_mod.load_mapping
except Exception:
    DNSSpoofer = None
    load_mapping = None

class ArpFrame(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        # ... embed ArpSpoofUI fields here (converted to Frame)
        # similar to original ArpSpoofUI but using self instead of root
        # [omitted for brevity]
        tk.Label(self, text="(ARP Spoof UI goes here)").pack(padx=10, pady=10)

class DNSFrame(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        # ... embed DNSGui contents (converted to Frame)
        tk.Label(self, text="(DNS Spoof UI goes here)").pack(padx=10, pady=10)

class SSLFrame(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        # ... embed SSLStripUI contents (converted to Frame)
        tk.Label(self, text="(SSL Strip UI goes here)").pack(padx=10, pady=10)

class CombinedUI(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Network Attack Suite")
        nb = ttk.Notebook(self)
        nb.pack(fill='both', expand=True)

        self.arp_tab = ArpFrame(nb)
        nb.add(self.arp_tab, text='ARP Spoof')

        self.dns_tab = DNSFrame(nb)
        nb.add(self.dns_tab, text='DNS Spoof')

        self.ssl_tab = SSLFrame(nb)
        nb.add(self.ssl_tab, text='SSL Strip')

if __name__ == '__main__':
    app = CombinedUI()
    app.mainloop()
