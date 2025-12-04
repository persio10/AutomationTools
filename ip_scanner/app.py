import asyncio
import csv
import ipaddress
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    123,
    135,
    137,
    139,
    143,
    161,
    389,
    443,
    445,
    465,
    514,
    587,
    631,
    853,
    873,
    993,
    995,
    1433,
    1723,
    2049,
    2181,
    2375,
    2377,
    3306,
    3389,
    4444,
    4789,
    5050,
    5353,
    5357,
    5672,
    5900,
    6379,
    6443,
    8000,
    8080,
    8443,
    9000,
]

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS",
    139: "SMB",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTPS",
    631: "IPP",
    853: "DoT",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    2049: "NFS",
    2181: "Zookeeper",
    2375: "Docker",
    2377: "Docker",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    4789: "VXLAN",
    5050: "Mesos",
    5353: "mDNS",
    5357: "WSD",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    6443: "K8s API",
    8000: "Dev HTTP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9000: "App/API",
}


class DeviceRecord:
    def __init__(self, ip: str):
        self.ip = ip
        self.hostname = ""
        self.mac_address = ""
        self.ports = []
        self.service_hints = ""
        self.latency_ms: float | None = None

    @property
    def port_summary(self) -> str:
        if not self.ports:
            return ""
        return ", ".join(str(p) for p in sorted(self.ports))

    def as_row(self) -> tuple[str, str, str, str, str, str]:
        latency = f"{self.latency_ms:.0f} ms" if self.latency_ms is not None else ""
        return self.ip, self.hostname, self.mac_address, latency, self.port_summary, self.service_hints


class AsyncScanner:
    def __init__(self, network: ipaddress.IPv4Network, semaphore: int = 256, stop_event: threading.Event | None = None):
        self.network = network
        self.semaphore = asyncio.Semaphore(semaphore)
        self.stop_event = stop_event
        self._loop = asyncio.get_event_loop()

    async def run(self, progress_cb):
        tasks = []
        for ip in self.network.hosts():
            if self.stop_event and self.stop_event.is_set():
                break
            tasks.append(asyncio.create_task(self._probe_host(str(ip), progress_cb)))
        if not tasks:
            return
        await asyncio.gather(*tasks)

    async def _probe_host(self, ip: str, progress_cb):
        async with self.semaphore:
            if self.stop_event and self.stop_event.is_set():
                return
            alive, latency = await self._ping(ip)
            progress_cb("ping", ip)
            if not alive or (self.stop_event and self.stop_event.is_set()):
                return
            record = DeviceRecord(ip)
            record.latency_ms = latency
            record.hostname = await self._resolve_hostname(ip)
            record.mac_address = await self._get_mac_address(ip)
            record.ports = await self._scan_ports(ip)
            record.service_hints = self._service_hints(record.ports)
            progress_cb("found", record)

    async def _ping(self, ip: str) -> tuple[bool, float | None]:
        flags = ["-n", "1", "-w", "400"] if os.name == "nt" else ["-c", "1", "-W", "1"]
        start = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            "ping", *flags, ip, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        if proc.returncode == 0:
            latency = (time.perf_counter() - start) * 1000.0
            return True, latency
        return False, None

    async def _resolve_hostname(self, ip: str) -> str:
        loop = asyncio.get_event_loop()
        resolvers = [
            lambda: self._reverse_dns(ip),
            lambda: self._ping_for_hostname(ip) if os.name == "nt" else "",
            lambda: self._nbtstat_lookup(ip) if os.name == "nt" else "",
        ]
        for resolver in resolvers:
            try:
                name = await loop.run_in_executor(None, resolver)
                if name:
                    return name
            except Exception:
                continue
        return ""

    @staticmethod
    def _reverse_dns(ip: str) -> str:
        try:
            result = socket.gethostbyaddr(ip)
            if isinstance(result, tuple) and result:
                return result[0]
        except Exception:
            return ""
        return ""

    @staticmethod
    def _ping_for_hostname(ip: str) -> str:
        # Windows ping -a attempts to resolve hostnames without needing DNS records.
        proc = subprocess.run(
            ["ping", "-a", "-n", "1", "-w", "400", ip], capture_output=True, text=True, check=False
        )
        for line in proc.stdout.splitlines():
            if "Pinging" in line and "[" in line and "]" in line:
                try:
                    left = line.split("Pinging", 1)[1].strip()
                    hostname = left.split(" [", 1)[0].strip()
                    if hostname and hostname != ip:
                        return hostname
                except Exception:
                    continue
        return ""

    @staticmethod
    def _nbtstat_lookup(ip: str) -> str:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, check=False)
        for line in proc.stdout.splitlines():
            if "<00>" in line and "UNIQUE" in line:
                parts = line.split()
                if parts:
                    candidate = parts[0].strip()
                    if candidate and candidate != "<unknown>":
                        return candidate
        return ""

    async def _get_mac_address(self, ip: str) -> str:
        # Windows-friendly ARP lookup after a ping.
        if os.name != "nt":
            return ""
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, self._parse_arp_output, ip)
        except Exception:
            return ""

    @staticmethod
    def _parse_arp_output(ip: str) -> str:
        proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, check=False)
        for line in proc.stdout.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if "-" in part and len(part.split("-")) == 6:
                        return part
        return ""

    async def _scan_ports(self, ip: str) -> list[int]:
        open_ports: list[int] = []
        tasks = [self._try_connect(ip, port) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks)
        for port, is_open in zip(COMMON_PORTS, results):
            if is_open:
                open_ports.append(port)
        return open_ports

    async def _try_connect(self, ip: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    @staticmethod
    def _service_hints(open_ports: list[int]) -> str:
        if not open_ports:
            return ""
        hints = []
        for port in sorted(open_ports):
            if port in SERVICE_NAMES:
                hints.append(f"{port}:{SERVICE_NAMES[port]}")
            else:
                hints.append(str(port))
        return ", ".join(hints)


def detect_default_network(default_prefix: int = 24) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        return f"{local_ip}/{default_prefix}"
    except Exception:
        return f"192.168.1.0/{default_prefix}"


class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LanScope - Advanced IP Scanner")
        self.geometry("1050x600")
        self.resizable(True, True)
        self.configure(bg="#0f172a")

        self.records: dict[str, DeviceRecord] = {}
        self.result_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.stop_event = threading.Event()

        self._build_header()
        self._build_controls()
        self._build_table()
        self._build_footer()

        self.after(150, self._drain_queue)

    def _build_header(self):
        header = tk.Frame(self, bg="#111827")
        header.pack(fill=tk.X, padx=10, pady=(10, 0))
        title = tk.Label(
            header,
            text="LanScope",
            fg="#22d3ee",
            bg="#111827",
            font=("Segoe UI", 18, "bold"),
        )
        title.pack(side=tk.LEFT)
        subtitle = tk.Label(
            header,
            text="Discover and track every device on your network",
            fg="#cbd5e1",
            bg="#111827",
            font=("Segoe UI", 10),
        )
        subtitle.pack(side=tk.LEFT, padx=(10, 0))

    def _build_controls(self):
        panel = tk.Frame(self, bg="#0f172a")
        panel.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(panel, text="Network / CIDR:").pack(side=tk.LEFT, padx=(0, 5))
        self.network_var = tk.StringVar(value=detect_default_network())
        self.network_entry = ttk.Entry(panel, textvariable=self.network_var, width=26)
        self.network_entry.pack(side=tk.LEFT)

        ttk.Label(panel, text="Max concurrency:").pack(side=tk.LEFT, padx=(15, 5))
        self.concurrency_var = tk.IntVar(value=256)
        self.concurrency_spin = ttk.Spinbox(panel, textvariable=self.concurrency_var, from_=16, to=1024, width=6)
        self.concurrency_spin.pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="Idle")
        status_label = ttk.Label(panel, textvariable=self.status_var, width=20)
        status_label.pack(side=tk.RIGHT)

        self.stop_button = ttk.Button(panel, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.start_button = ttk.Button(panel, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.export_button = ttk.Button(panel, text="Export CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_button.pack(side=tk.RIGHT)

    def _build_table(self):
        frame = tk.Frame(self, bg="#0f172a")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("ip", "hostname", "mac", "latency", "ports", "services")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        headings = [
            ("ip", "IP Address", 150),
            ("hostname", "Hostname", 200),
            ("mac", "MAC Address", 160),
            ("latency", "Latency", 90),
            ("ports", "Open Ports", 160),
            ("services", "Service Hints", 230),
        ]
        for col, text, width in headings:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=tk.W)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

    def _build_footer(self):
        footer = tk.Frame(self, bg="#0f172a")
        footer.pack(fill=tk.X, padx=10, pady=(0, 12))

        self.summary_var = tk.StringVar(value="Devices: 0 | Online: 0")
        ttk.Label(footer, textvariable=self.summary_var).pack(side=tk.LEFT)

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        network_value = self.network_var.get().strip()
        try:
            network = ipaddress.ip_network(network_value, strict=False)
        except ValueError:
            messagebox.showerror("Invalid Network", "Please provide a valid CIDR (e.g., 192.168.1.0/24)")
            return

        self.records.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Scanning...")
        self.summary_var.set("Devices: 0 | Online: 0")
        self.stop_event.clear()
        self.export_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        def runner():
            asyncio.run(self._scan_network(network))
            self.result_queue.put(("done", None))

        self.scan_thread = threading.Thread(target=runner, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")

    async def _scan_network(self, network: ipaddress.IPv4Network):
        scanner = AsyncScanner(network, semaphore=self.concurrency_var.get(), stop_event=self.stop_event)

        def progress_cb(event_type, payload):
            if self.stop_event.is_set():
                return
            self.result_queue.put((event_type, payload))

        await scanner.run(progress_cb)

    def _drain_queue(self):
        try:
            while True:
                event, payload = self.result_queue.get_nowait()
                if event == "found" and isinstance(payload, DeviceRecord):
                    self._add_record(payload)
                elif event == "ping":
                    self.status_var.set(f"Pinging {payload}")
                elif event == "done":
                    self._finish_scan()
        except queue.Empty:
            pass
        finally:
            self.after(150, self._drain_queue)

    def _add_record(self, record: DeviceRecord):
        self.records[record.ip] = record
        self.tree.insert("", tk.END, values=record.as_row())
        self._update_summary()

    def _finish_scan(self):
        self.status_var.set("Stopped" if self.stop_event.is_set() else "Completed")
        self.export_button.config(state=tk.NORMAL if self.records else tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def _update_summary(self):
        self.summary_var.set(f"Devices scanned: {len(self.records)} | Online: {len(self.records)}")

    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data", "Run a scan before exporting.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")], title="Export scan results"
        )
        if not filename:
            return
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                ["IP Address", "Hostname", "MAC Address", "Latency", "Open Ports", "Service Hints"]
            )
            for record in self.records.values():
                writer.writerow(record.as_row())
        messagebox.showinfo("Exported", f"Saved {len(self.records)} devices to {filename}")


if __name__ == "__main__":
    app = ScannerApp()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)