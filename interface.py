import Tkinter as tk
import ttk
import threading
import subprocess
import sys
from scapy.all import get_if_list

class ArpSpoofUI(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("ARP Spoofing Tool UI")
        self.process = None

        # Interface selection
        tk.Label(self, text="Interface:").grid(row=0, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        ifaces = get_if_list()
        self.iface_combo = ttk.Combobox(self, textvariable=self.iface_var, values=ifaces)
        self.iface_combo.grid(row=0, column=1, padx=5, pady=5)

        # Mode selection
        tk.Label(self, text="Mode:").grid(row=1, column=0, sticky='e')
        self.mode_var = tk.StringVar(value='pair')
        self.mode_combo = ttk.Combobox(self, textvariable=self.mode_var, values=['pair', 'silent', 'flood'])
        self.mode_combo.grid(row=1, column=1, padx=5, pady=5)
        self.mode_combo.bind('<<ComboboxSelected>>', self.on_mode_change)

        # Victims entry
        tk.Label(self, text="Victims (CSV):").grid(row=2, column=0, sticky='e')
        self.victims_entry = tk.Entry(self)
        self.victims_entry.grid(row=2, column=1, padx=5, pady=5)

        # Gateway entry
        tk.Label(self, text="Gateway IP:").grid(row=3, column=0, sticky='e')
        self.gateway_entry = tk.Entry(self)
        self.gateway_entry.grid(row=3, column=1, padx=5, pady=5)

        # CIDR entry (for flood mode)
        tk.Label(self, text="CIDR:").grid(row=4, column=0, sticky='e')
        self.cidr_entry = tk.Entry(self)
        self.cidr_entry.grid(row=4, column=1, padx=5, pady=5)

        # Interval
        tk.Label(self, text="Interval (s):").grid(row=5, column=0, sticky='e')
        self.interval_entry = tk.Entry(self)
        self.interval_entry.insert(0, '10')
        self.interval_entry.grid(row=5, column=1, padx=5, pady=5)

        # Buttons
        self.start_btn = tk.Button(self, text="Start", command=self.start_attack)
        self.start_btn.grid(row=6, column=0, padx=5, pady=10)
        self.stop_btn = tk.Button(self, text="Stop", state='disabled', command=self.stop_attack)
        self.stop_btn.grid(row=6, column=1, padx=5, pady=10)

        # Log output
        self.log_text = tk.Text(self, height=15, width=60)
        self.log_text.grid(row=7, column=0, columnspan=2, padx=5, pady=5)
        scrollbar = tk.Scrollbar(self, command=self.log_text.yview)
        scrollbar.grid(row=7, column=2, sticky='nsew')
        self.log_text['yscrollcommand'] = scrollbar.set

        # initialize field states
        self.on_mode_change()

    def on_mode_change(self, event=None):
        mode = self.mode_var.get()
        if mode in ('pair', 'silent'):
            self.victims_entry.config(state='normal')
            self.gateway_entry.config(state='normal')
            self.cidr_entry.config(state='disabled')
        else:  # flood
            self.victims_entry.config(state='disabled')
            self.gateway_entry.config(state='normal')
            self.cidr_entry.config(state='normal')

    def start_attack(self):
        # validate inputs
        iface = self.iface_var.get().strip()
        mode = self.mode_var.get()
        interval = self.interval_entry.get().strip()
        gateway = self.gateway_entry.get().strip()
        victims = self.victims_entry.get().strip()
        cidr = self.cidr_entry.get().strip()

        if not iface:
            self._log("Error: Interface not selected.\n")
            return
        if mode in ('pair', 'silent') and (not victims or not gateway):
            self._log("Error: Victims and Gateway are required for this mode.\n")
            return
        if mode == 'flood' and (not cidr or not gateway):
            self._log("Error: CIDR and Gateway are required for flood mode.\n")
            return

        args = ['sudo', 'python2', 'arp_poisoner27.py', '--iface', iface, '--mode', mode, '--interval', interval]
        if mode in ('pair', 'silent'):
            args += ['--victims', victims, '--gateway', gateway]
        else:
            args += ['--cidr', cidr, '--gateway', gateway]

        self._log("Starting: {}\n".format(' '.join(args)))
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

        def run_process():
            self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
                self._log(line)
            self._on_process_end()

        thread = threading.Thread(target=run_process)
        thread.setDaemon(True)
        thread.start()

    def _on_process_end(self):
        self._log("\nProcess ended.\n")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.process = None

    def stop_attack(self):
        if self.process:
            self.process.terminate()
            self._log("\nAttack stopped. Restoring caches...\n")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    def _log(self, message):
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)

if __name__ == '__main__':
    app = ArpSpoofUI()
    app.mainloop()