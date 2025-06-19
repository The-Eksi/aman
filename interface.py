import Tkinter as tk
import ttk
import threading
import subprocess
import sys
from scapy.all import get_if_list

class SSLStripUI(tk.Tk):
    def __init__(self):
        super(SSLStripUI, self).__init__()
        self.title("SSL Strip Tool UI")
        self.process = None

        # Interface selection
        tk.Label(self, text="Interface:").grid(row=0, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        ifaces = get_if_list()
        self.iface_combo = ttk.Combobox(self, textvariable=self.iface_var, values=ifaces)
        self.iface_combo.grid(row=0, column=1, padx=5, pady=5)

        # BPF filter entry
        tk.Label(self, text="BPF Filter:").grid(row=1, column=0, sticky='e')
        self.bpf_entry = tk.Entry(self)
        self.bpf_entry.insert(0, 'tcp port 80')
        self.bpf_entry.grid(row=1, column=1, padx=5, pady=5)

        # Host filter entry
        tk.Label(self, text="Hosts (CSV wildcards):").grid(row=2, column=0, sticky='e')
        self.hosts_entry = tk.Entry(self)
        self.hosts_entry.grid(row=2, column=1, padx=5, pady=5)

        # Verbose / Quiet
        self.verbose_var = tk.BooleanVar()
        self.quiet_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Verbose", variable=self.verbose_var).grid(row=3, column=0)
        tk.Checkbutton(self, text="Quiet", variable=self.quiet_var).grid(row=3, column=1)

        # Buttons
        self.start_btn = tk.Button(self, text="Start", command=self.start_strip)
        self.start_btn.grid(row=4, column=0, padx=5, pady=10)
        self.stop_btn = tk.Button(self, text="Stop", state='disabled', command=self.stop_strip)
        self.stop_btn.grid(row=4, column=1, padx=5, pady=10)

        # Log output
        self.log_text = tk.Text(self, height=15, width=60)
        self.log_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        scrollbar = tk.Scrollbar(self, command=self.log_text.yview)
        scrollbar.grid(row=5, column=2, sticky='nsew')
        self.log_text['yscrollcommand'] = scrollbar.set

    def start_strip(self):
        iface = self.iface_var.get().strip()
        bpf = self.bpf_entry.get().strip()
        hosts = self.hosts_entry.get().strip()
        verbose = self.verbose_var.get()
        quiet = self.quiet_var.get()

        if not iface:
            self._log("Error: Interface must be selected.\n")
            return
        args = ['sudo', 'python2', 'ssl.py', '-i', iface, '--bpf', bpf]
        if hosts:
            args += ['--hosts', hosts]
        if verbose:
            args.append('-v')
        if quiet:
            args.append('-q')

        self._log("Starting: {}\n".format(' '.join(args)))
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

        def run_proc():
            self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for raw in self.process.stdout:
                try:
                    line = raw.decode('utf-8')
                except:
                    line = str(raw)
                self._log(line)
            self._on_end()

        t = threading.Thread(target=run_proc)
        t.setDaemon(True)
        t.start()

    def stop_strip(self):
        if self.process:
            self.process.terminate()
            self._log("\nStopped SSL strip.\n")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    def _on_end(self):
        self._log("\nProcess ended.\n")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.process = None

    def _log(self, msg):
        self.log_text.insert(tk.END, msg)
        self.log_text.see(tk.END)

if __name__ == '__main__':
    app = SSLStripUI()
    app.mainloop()