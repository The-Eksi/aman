import Tkinter as tk
import ttk
import threading
import subprocess
import os
import sys
from scapy.all import get_if_list

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

class ArpFrame(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        tk.Label(self, text="ARP Spoof UI").pack(pady=5)
        tk.Button(self, text="Launch ARP UI", command=self.launch_arp).pack(pady=10)

    def launch_arp(self):
        path = os.path.join(SCRIPT_DIR, 'arpui.py')
        threading.Thread(target=lambda: subprocess.call(['sudo', 'python2', path]),
                         daemon=True).start()

class DNSFrame(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        tk.Label(self, text="DNS Spoof UI").pack(pady=5)
        tk.Button(self, text="Launch DNS UI", command=self.launch_dns).pack(pady=10)

    def launch_dns(self):
        path = os.path.join(SCRIPT_DIR, 'dnsui.py')
        threading.Thread(target=lambda: subprocess.call(['sudo', 'python2', path]),
                         daemon=True).start()

class SSLFrame(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        tk.Label(self, text="SSL Strip UI").pack(pady=5)
        tk.Button(self, text="Launch SSL UI", command=self.launch_ssl).pack(pady=10)

    def launch_ssl(self):
        path = os.path.join(SCRIPT_DIR, 'sslui.py')
        threading.Thread(target=lambda: subprocess.call(['sudo', 'python2', path]),
                         daemon=True).start()

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
