import asyncio
import contextlib
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
    67,
    68,
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
    500,
    514,
    515,
    548,
    554,
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
    2483,
    27017,
    27018,
    27019,
    3000,
    3001,
    32400,
    3260,
    3306,
    3389,
    3689,
    4443,
    4444,
    4789,
    5000,
    5001,
    5050,
    51413,
    5353,
    5357,
    5432,
    5555,
    5672,
    5683,
    5900,
    5985,
    5986,
    6000,
    6379,
    6443,
    6481,
    8000,
    8080,
    8200,
    8443,
    8444,
    8500,
    8529,
    8530,
    8531,
    8532,
    8888,
    9000,
    9100,
    9200,
    9300,
    9443,
    10000,
    11211,
]

QUICK_WIFI_PORTS = [80, 443, 8080, 8443, 22, 23, 53, 161, 5000, 8000]

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
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
    500: "IPSec",
    514: "Syslog",
    515: "LPD",
    548: "AFP",
    554: "RTSP",
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
    2483: "Oracle DB",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
    3001: "Node/Dev",
    3000: "Node/Dev",
    32400: "Plex",
    3260: "iSCSI",
    3306: "MySQL",
    3389: "RDP",
    3689: "DAAP",
    4443: "HTTPS-Alt",
    4444: "Metasploit",
    4789: "VXLAN",
    5000: "UPnP/Dev",
    5001: "Synology/HTTPS",
    5050: "Mesos",
    51413: "qBittorrent",
    5353: "mDNS",
    5357: "WSD",
    5432: "Postgres",
    5555: "ADB",
    5672: "AMQP",
    5683: "CoAP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-SSL",
    6000: "X11",
    6379: "Redis",
    6443: "K8s API",
    6481: "MQTT",
    8000: "Dev HTTP",
    8080: "HTTP-Alt",
    8200: "DLNA/UPnP",
    8443: "HTTPS-Alt",
    8444: "HTTPS-Alt",
    8500: "Consul",
    8529: "Emby",
    8530: "Emby",
    8531: "Emby",
    8532: "Emby",
    8888: "Alt HTTPS",
    9000: "App/API",
    9100: "JetDirect",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    9443: "Alt HTTPS",
    10000: "Webmin",
    11211: "Memcached",
}

BANNER_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    443: "https",
    445: "smb",
    502: "modbus",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2375: "docker",
    2377: "docker",
    3000: "http",
    3001: "http",
    32400: "http",
    3389: "rdp",
    4443: "https",
    5000: "http",
    5001: "https",
    5050: "http",
    5357: "wsd",
    5432: "postgres",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    6443: "https",
    8000: "http",
    8080: "http",
    8443: "https",
    8888: "https",
    9000: "http",
    9443: "https",
    10000: "http",
}


class DeviceRecord:
    def __init__(self, ip: str):
        self.ip = ip
        self.hostname = ""
        self.os_guess = ""
        self.mac_address = ""
        self.vendor = ""
        self.ttl: int | None = None
        self.identity_hint = ""
        self.ports = []
        self.service_hints = ""
        self.banner_hints = ""
        self.latency_ms: float | None = None

    @property
    def port_summary(self) -> str:
        if not self.ports:
            return ""
        return ", ".join(str(p) for p in sorted(self.ports))

    def as_row(self) -> tuple[str, ...]:
        latency = f"{self.latency_ms:.0f} ms" if self.latency_ms is not None else ""
        ttl = str(self.ttl) if self.ttl is not None else ""
        return (
            self.ip,
            self.hostname,
            self.os_guess,
            latency,
            ttl,
            self.port_summary,
            self.service_hints,
            self.banner_hints,
            self.identity_hint,
            self.mac_address,
            self.vendor,
        )


class AsyncScanner:
    def __init__(
        self,
        network: ipaddress.IPv4Network,
        semaphore: int = 256,
        stop_event: threading.Event | None = None,
        ports: list[int] | None = None,
        deep_fingerprint: bool = False,
    ):
        self.network = network
        self.semaphore = asyncio.Semaphore(semaphore)
        self.stop_event = stop_event
        self.port_catalog = sorted(set(ports or COMMON_PORTS))
        self.deep_fingerprint = deep_fingerprint
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
            alive, latency, ttl = await self._ping(ip)
            progress_cb("ping", ip)
            if not alive or (self.stop_event and self.stop_event.is_set()):
                return
            record = DeviceRecord(ip)
            record.latency_ms = latency
            record.ttl = ttl
            record.hostname = await self._resolve_hostname(ip)
            record.mac_address = await self._get_mac_address(ip)
            record.ports = await self._scan_ports(ip)
            record.service_hints = self._service_hints(record.ports)
            record.banner_hints = await self._fingerprint_services(ip, record.ports)
            record.os_guess = self._guess_os(ttl, record.ports, record.hostname)
            record.vendor = self._mac_vendor(record.mac_address)
            record.identity_hint = self._identity_hint(record)
            progress_cb("found", record)

    async def _ping(self, ip: str) -> tuple[bool, float | None, int | None]:
        flags = ["-n", "1", "-w", "400"] if os.name == "nt" else ["-c", "1", "-W", "1", "-n"]
        start = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            "ping",
            *flags,
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            latency = (time.perf_counter() - start) * 1000.0
            ttl = self._extract_ttl(stdout.decode(errors="ignore"))
            return True, latency, ttl
        return False, None, None

    @staticmethod
    def _extract_ttl(output: str) -> int | None:
        for line in output.splitlines():
            if "ttl" in line.lower():
                for chunk in line.replace("=", " ").split():
                    if chunk.isdigit():
                        value = int(chunk)
                        if 1 <= value <= 255:
                            return value
                if "ttl" in line.lower():
                    parts = [part for part in line.split() if "ttl" in part.lower()]
                    for part in parts:
                        try:
                            return int(part.lower().split("ttl")[-1].replace("=", ""))
                        except Exception:
                            continue
        return None

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
        tasks = [self._try_connect(ip, port) for port in self.port_catalog]
        results = await asyncio.gather(*tasks)
        for port, is_open in zip(self.port_catalog, results):
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

    async def _fingerprint_services(self, ip: str, open_ports: list[int]) -> str:
        if not self.deep_fingerprint or not open_ports:
            return ""
        hints: list[str] = []
        tasks = []
        for port in open_ports:
            if port in BANNER_PORTS:
                tasks.append(self._banner_grab(ip, port, BANNER_PORTS[port]))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str) and result:
                hints.append(result)
        return " | ".join(hints[:6])

    async def _banner_grab(self, ip: str, port: int, label: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.8)
        except Exception:
            return ""

        payload = b""
        if label in {"http", "https"}:
            payload = b"HEAD / HTTP/1.0\r\nHost: lan-scope\r\n\r\n"
        elif label == "ssh":
            payload = b""
        elif label in {"telnet", "ftp", "smtp"}:
            payload = b"\r\n"
        elif label in {"postgres", "redis", "docker"}:
            payload = b"\n"

        banner = ""
        try:
            if payload:
                writer.write(payload)
                await writer.drain()
            raw = await asyncio.wait_for(reader.read(220), timeout=0.8)
            decoded = raw.decode(errors="ignore")
            banner = self._clean_banner(decoded)
        except Exception:
            banner = ""
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        if not banner:
            return ""
        return f"{label.upper()}: {banner}" if banner else ""

    @staticmethod
    def _clean_banner(text: str) -> str:
        if not text:
            return ""
        line = text.splitlines()[0].strip()
        return line[:120]

    @staticmethod
    def _mac_vendor(mac: str) -> str:
        if not mac or "-" not in mac:
            return ""
        prefix = mac.upper().replace("-", ":").split(":")[:3]
        if len(prefix) < 3:
            return ""
        oui = ":".join(prefix)
        known = {
            "00:1A:2B": "Dell", "00:1B:21": "HP", "00:1C:43": "Apple", "00:1D:D8": "Cisco",
            "00:24:E8": "Ubiquiti", "00:50:56": "VMware", "00:0C:29": "VMware", "00:25:9C": "Hikvision",
            "EC:B1:D7": "Synology", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Google", "3C:5A:B4": "Amazon",
            "F4:0F:24": "Azure/Hyper-V", "F8:32:E4": "Lenovo", "D4:6D:6D": "Juniper", "48:0F:CF": "Netgear",
        }
        return known.get(oui, "")

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

    @staticmethod
    def _guess_os(ttl: int | None, ports: list[int], hostname: str) -> str:
        if hostname and hostname.lower().endswith(".local"):
            return "Apple/Bonjour"
        if ttl is not None:
            if ttl >= 240:
                return "Network gear"
            if ttl >= 128:
                return "Windows"
            if ttl >= 100:
                return "BSD/Network"
            if ttl >= 60:
                return "Linux/Unix"
        if 445 in ports or 3389 in ports:
            return "Windows"
        if 22 in ports or 2222 in ports:
            return "Linux/Unix"
        if 548 in ports:
            return "macOS"
        return ""

    @staticmethod
    def _identity_hint(record: "DeviceRecord") -> str:
        hints = []
        ports = set(record.ports)
        if record.hostname:
            hints.append(record.hostname)
        if record.vendor:
            hints.append(record.vendor)
        if 3389 in ports:
            hints.append("RDP host")
        if 22 in ports:
            hints.append("SSH reachable")
        if 32400 in ports:
            hints.append("Plex Media Server")
        if 9100 in ports:
            hints.append("Printer/JetDirect")
        if 161 in ports:
            hints.append("SNMP device")
        if 5000 in ports or 8200 in ports:
            hints.append("Media/UPnP")
        if 445 in ports or 139 in ports:
            hints.append("SMB fileshare")
        if 5985 in ports or 5986 in ports:
            hints.append("WinRM")
        if 51413 in ports:
            hints.append("Torrent client")
        if 443 in ports and "ssl" in record.banner_hints.lower():
            hints.append("HTTPS exposed")
        if record.banner_hints:
            hints.append(record.banner_hints.split("|")[0].strip())
        if record.os_guess:
            hints.append(record.os_guess)
        if record.ttl:
            hints.append(f"TTL {record.ttl}")
        seen = []
        for hint in hints:
            if hint not in seen:
                seen.append(hint)
        return " · ".join(seen)


def detect_default_network(default_prefix: int = 24) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        return f"{local_ip}/{default_prefix}"
    except Exception:
        return f"192.168.1.0/{default_prefix}"


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def _default_gateways() -> list[str]:
    gateways: list[str] = []
    try:
        if os.name == "nt":
            proc = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, check=False)
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    gateway = parts[2]
                    if _is_valid_ip(gateway):
                        gateways.append(gateway)
        else:
            proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=False)
            for line in proc.stdout.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts) and _is_valid_ip(parts[idx + 1]):
                        gateways.append(parts[idx + 1])
    except Exception:
        return []
    return gateways


def _current_ssid() -> str:
    try:
        if os.name == "nt":
            proc = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, check=False)
            for line in proc.stdout.splitlines():
                if line.strip().startswith("SSID") and ":" in line:
                    return line.split(":", 1)[1].strip()
        else:
            proc = subprocess.run([
                "nmcli",
                "-t",
                "-f",
                "ACTIVE,SSID",
                "dev",
                "wifi",
            ], capture_output=True, text=True, check=False)
            for line in proc.stdout.splitlines():
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[0].lower() in {"yes", "y"}:
                    return parts[1]
    except Exception:
        return ""
    return ""


def discover_wifi_networks() -> list[dict[str, str]]:
    networks: list[dict[str, str]] = []
    current = _current_ssid()
    try:
        if os.name == "nt":
            proc = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, check=False
            )
            ssid = None
            security = ""
            signal = ""
            for line in proc.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("SSID") and ":" in stripped:
                    if ssid is not None:
                        networks.append(
                            {
                                "ssid": ssid or "<hidden>",
                                "security": security or "Unknown",
                                "signal": signal or "",
                                "active": bool(ssid == current),
                            }
                        )
                    ssid = stripped.split(":", 1)[1].strip()
                    security = ""
                    signal = ""
                elif stripped.startswith("Authentication") and ":" in stripped:
                    security = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Signal") and ":" in stripped:
                    signal = stripped.split(":", 1)[1].strip()
            if ssid is not None:
                networks.append(
                    {
                        "ssid": ssid or "<hidden>",
                        "security": security or "Unknown",
                        "signal": signal or "",
                        "active": bool(ssid == current),
                    }
                )
        else:
            proc = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in proc.stdout.splitlines():
                parts = line.split(":")
                if not parts:
                    continue
                ssid = parts[0]
                security = parts[1] if len(parts) > 1 else ""
                signal = parts[2] if len(parts) > 2 else ""
                networks.append(
                    {
                        "ssid": ssid or "<hidden>",
                        "security": security or "Unknown",
                        "signal": signal,
                        "active": bool(ssid == current),
                    }
                )
    except Exception:
        return []
    return networks


def quick_port_scan(host: str, ports: list[int] | None = None) -> list[int]:
    target_ports = ports or QUICK_WIFI_PORTS
    open_ports: list[int] = []
    for port in target_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            try:
                sock.connect((host, port))
                open_ports.append(port)
            except Exception:
                continue
    return open_ports


class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LanScope - Advanced IP Scanner")
        self.geometry("1220x680")
        self.resizable(True, True)
        self.configure(bg="#0b1220")

        self._style()

        self.records: dict[str, DeviceRecord] = {}
        self.result_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.wifi_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.host_count: int | None = None
        self.start_time: float | None = None
        self.filter_var = tk.StringVar()
        self.custom_ports_var = tk.StringVar(value="")
        self.deep_var = tk.BooleanVar(value=True)

        self._build_header()
        self._build_controls()
        self._build_insights()
        self._build_table()
        self._build_footer()

        self.after(150, self._drain_queue)

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        accent = "#22d3ee"
        surface = "#111827"
        style.configure("TLabel", background="#0b1220", foreground="#e2e8f0", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=surface, foreground="#e2e8f0", font=("Segoe UI", 18, "bold"))
        style.configure("Subheader.TLabel", background=surface, foreground="#94a3b8", font=("Segoe UI", 11))
        style.configure("Card.TFrame", background=surface, relief=tk.FLAT)
        style.configure("Accent.TButton", padding=6, background=accent, foreground="#0f172a")
        style.map(
            "Accent.TButton",
            background=[("active", "#38e2ff"), ("disabled", "#1e293b")],
            foreground=[("disabled", "#94a3b8")],
        )
        style.configure("Treeview", background="#0f172a", fieldbackground="#0f172a", foreground="#e2e8f0", rowheight=26)
        style.configure("Treeview.Heading", background=surface, foreground="#e2e8f0", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#1f2937")])

    def _build_header(self):
        header = tk.Frame(self, bg="#111827")
        header.pack(fill=tk.X, padx=12, pady=(12, 4))
        title = ttk.Label(header, text="LanScope", style="Header.TLabel")
        title.pack(side=tk.LEFT)
        subtitle = ttk.Label(
            header,
            text="Discover and track every device on your network",
            style="Subheader.TLabel",
        )
        subtitle.pack(side=tk.LEFT, padx=(10, 0))

        badge = tk.Label(
            header,
            text="Live homelab insights",
            fg="#0b1220",
            bg="#22d3ee",
            padx=10,
            pady=4,
            font=("Segoe UI", 9, "bold"),
        )
        badge.pack(side=tk.RIGHT)

    def _build_controls(self):
        panel = tk.Frame(self, bg="#0b1220")
        panel.pack(fill=tk.X, padx=12, pady=10)

        left = tk.Frame(panel, bg="#0b1220")
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(left, text="Network / CIDR:").pack(side=tk.LEFT, padx=(0, 5))
        self.network_var = tk.StringVar(value=detect_default_network())
        self.network_entry = ttk.Entry(left, textvariable=self.network_var, width=26)
        self.network_entry.pack(side=tk.LEFT)

        ttk.Label(left, text="Max concurrency:").pack(side=tk.LEFT, padx=(15, 5))
        self.concurrency_var = tk.IntVar(value=256)
        self.concurrency_spin = ttk.Spinbox(
            left, textvariable=self.concurrency_var, from_=16, to=1024, width=6
        )
        self.concurrency_spin.pack(side=tk.LEFT)

        ttk.Label(left, text="Custom ports:").pack(side=tk.LEFT, padx=(15, 5))
        self.custom_ports_entry = ttk.Entry(left, textvariable=self.custom_ports_var, width=16)
        self.custom_ports_entry.pack(side=tk.LEFT)

        ttk.Label(left, text="Filter:").pack(side=tk.LEFT, padx=(15, 5))
        self.filter_entry = ttk.Entry(left, textvariable=self.filter_var, width=18)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_var.trace_add("write", lambda *_: self._apply_filter())

        right = tk.Frame(panel, bg="#0b1220")
        right.pack(side=tk.RIGHT)
        self.status_var = tk.StringVar(value="Idle")
        status_label = ttk.Label(right, textvariable=self.status_var, width=22)
        status_label.pack(side=tk.LEFT, padx=(0, 8))

        self.deep_check = ttk.Checkbutton(right, text="Deep fingerprint", variable=self.deep_var)
        self.deep_check.pack(side=tk.LEFT, padx=(0, 8))

        self.export_button = ttk.Button(right, text="Export CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=(0, 5))
        self.stop_button = ttk.Button(right, text="Stop", command=self.stop_scan, state=tk.DISABLED, style="Accent.TButton")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))
        self.wifi_button = ttk.Button(right, text="Wi-Fi Sweep", command=self.start_wifi_sweep)
        self.wifi_button.pack(side=tk.LEFT, padx=(0, 5))
        self.start_button = ttk.Button(right, text="Start Scan", command=self.start_scan, style="Accent.TButton")
        self.start_button.pack(side=tk.LEFT)

    def _build_insights(self):
        bar = tk.Frame(self, bg="#0b1220")
        bar.pack(fill=tk.X, padx=12, pady=(0, 8))

        self.insight_devices = tk.StringVar(value="Devices: 0")
        self.insight_services = tk.StringVar(value="Top service: -")
        self.insight_latency = tk.StringVar(value="Fastest: -")

        for text_var, label in [
            (self.insight_devices, "Inventory"),
            (self.insight_services, "Services"),
            (self.insight_latency, "Performance"),
        ]:
            card = tk.Frame(bar, bg="#111827", padx=14, pady=10)
            card.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
            ttk.Label(card, text=label, style="Subheader.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=text_var, style="Header.TLabel").pack(anchor="w")

    def _build_table(self):
        frame = tk.Frame(self, bg="#0b1220")
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        columns = (
            "ip",
            "hostname",
            "os",
            "latency",
            "ttl",
            "ports",
            "services",
            "banners",
            "identity",
            "mac",
            "vendor",
        )
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        headings = [
            ("ip", "IP Address", 140),
            ("hostname", "Hostname", 200),
            ("os", "OS Hint", 120),
            ("latency", "Latency", 80),
            ("ttl", "TTL", 60),
            ("ports", "Open Ports", 150),
            ("services", "Service Hints", 200),
            ("banners", "Fingerprints", 230),
            ("identity", "Identity Hints", 220),
            ("mac", "MAC Address", 150),
            ("vendor", "Vendor", 140),
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

        self.tree.tag_configure("even", background="#0c182e")
        self.tree.tag_configure("odd", background="#10203a")

        self.menu = tk.Menu(self, tearoff=0, bg="#0f172a", fg="#e2e8f0")
        self.menu.add_command(label="Copy row", command=self._copy_row)
        self.menu.add_command(label="Details…", command=self._show_details)
        self.tree.bind("<Button-3>", self._open_menu)
        self.tree.bind("<Double-1>", lambda _: self._show_details())

    def _build_footer(self):
        footer = tk.Frame(self, bg="#0b1220")
        footer.pack(fill=tk.X, padx=12, pady=(0, 12))

        self.summary_var = tk.StringVar(value="Devices: 0 | Online: 0")
        ttk.Label(footer, textvariable=self.summary_var).pack(side=tk.LEFT)

        self.elapsed_var = tk.StringVar(value="Elapsed: 0.0s")
        ttk.Label(footer, textvariable=self.elapsed_var).pack(side=tk.LEFT, padx=(15, 0))

        self.progress = ttk.Progressbar(footer, length=240, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT)

    def start_wifi_sweep(self):
        if self.wifi_thread and self.wifi_thread.is_alive():
            return
        self.status_var.set("Sweeping Wi-Fi…")
        self.progress.start(12)
        self.wifi_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.DISABLED)

        def worker():
            networks = discover_wifi_networks()
            gateways = _default_gateways()
            gateway_ports = {gw: quick_port_scan(gw) for gw in gateways}
            self.result_queue.put(("wifi_done", (networks, gateways, gateway_ports)))

        self.wifi_thread = threading.Thread(target=worker, daemon=True)
        self.wifi_thread.start()

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        network_value = self.network_var.get().strip()
        try:
            network = ipaddress.ip_network(network_value, strict=False)
        except ValueError:
            messagebox.showerror("Invalid Network", "Please provide a valid CIDR (e.g., 192.168.1.0/24)")
            return

        extra_ports: list[int] = []
        for chunk in self.custom_ports_var.get().split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                value = int(chunk)
                if 1 <= value <= 65535:
                    extra_ports.append(value)
            except ValueError:
                continue
        self.active_ports = sorted(set(COMMON_PORTS + extra_ports))

        self.records.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.host_count = network.num_addresses - 2 if network.prefixlen <= 30 else max(1, network.num_addresses)
        self.start_time = time.time()
        self.status_var.set("Scanning...")
        self.summary_var.set("Devices: 0 | Online: 0")
        self.elapsed_var.set("Elapsed: 0.0s")
        self.stop_event.clear()
        self.export_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start(12)

        def runner():
            asyncio.run(self._scan_network(network))
            self.result_queue.put(("done", None))

        self.scan_thread = threading.Thread(target=runner, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")
        self.progress.stop()

    async def _scan_network(self, network: ipaddress.IPv4Network):
        ports = getattr(self, "active_ports", COMMON_PORTS)
        scanner = AsyncScanner(
            network,
            semaphore=self.concurrency_var.get(),
            stop_event=self.stop_event,
            ports=ports,
            deep_fingerprint=self.deep_var.get(),
        )

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
                elif event == "wifi_done":
                    networks, gateways, gateway_ports = payload
                    self._present_wifi_results(networks, gateways, gateway_ports)
        except queue.Empty:
            pass
        finally:
            if self.start_time and not self.stop_event.is_set():
                self.elapsed_var.set(f"Elapsed: {time.time() - self.start_time:.1f}s")
            self.after(150, self._drain_queue)

    def _add_record(self, record: DeviceRecord):
        self.records[record.ip] = record
        self._insert_record(record)
        self._update_summary()

    def _finish_scan(self):
        self.status_var.set("Stopped" if self.stop_event.is_set() else "Completed")
        self.export_button.config(state=tk.NORMAL if self.records else tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        if self.start_time:
            self.elapsed_var.set(f"Elapsed: {time.time() - self.start_time:.1f}s")

    def _present_wifi_results(self, networks, gateways, gateway_ports):
        self.progress.stop()
        self.status_var.set("Wi-Fi sweep done")
        self.wifi_button.config(state=tk.NORMAL)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if not networks and not gateways:
            messagebox.showinfo("Wi-Fi sweep", "No Wi-Fi data could be collected.")
            return

        window = tk.Toplevel(self)
        window.title("Wi-Fi networks")
        window.configure(bg="#0b1220")
        window.geometry("720x420")

        header = ttk.Label(window, text="Nearby Wi-Fi & reachable gateways", style="Header.TLabel")
        header.pack(anchor="w", padx=12, pady=(10, 6))

        frame = tk.Frame(window, bg="#0b1220")
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        columns = ("ssid", "signal", "security", "ports")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        headings = [
            ("ssid", "SSID", 220),
            ("signal", "Signal", 90),
            ("security", "Security", 140),
            ("ports", "Open ports on gateway", 240),
        ]
        for col, text, width in headings:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=tk.W)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        active_gateway = gateways[0] if gateways else ""
        ports_text = self._format_port_list(gateway_ports.get(active_gateway, [])) if active_gateway else "-"

        for net in networks:
            ssid = net.get("ssid", "<hidden>")
            signal = net.get("signal", "")
            security = net.get("security", "Unknown")
            if net.get("active"):
                label = ports_text if ports_text else "None (gateway reachable)"
            else:
                label = "Connect to scan ports" if active_gateway else "Unavailable while offline"
            tree.insert("", tk.END, values=(ssid, signal, security, label))

        if not networks:
            tree.insert("", tk.END, values=("-", "-", "-", ports_text or "No gateways"))

        if gateways:
            gateway_frame = tk.Frame(window, bg="#0b1220")
            gateway_frame.pack(fill=tk.X, padx=12, pady=(0, 10))
            details = ", ".join(f"{gw} [{self._format_port_list(gateway_ports.get(gw, [])) or 'closed'}]" for gw in gateways)
            ttk.Label(gateway_frame, text=f"Reachable gateways: {details}").pack(anchor="w")

    @staticmethod
    def _format_port_list(ports: list[int]) -> str:
        if not ports:
            return ""
        labels = []
        for port in sorted(ports):
            name = SERVICE_NAMES.get(port)
            labels.append(f"{port} ({name})" if name else str(port))
        return ", ".join(labels)

    def _update_summary(self):
        count = len(self.records)
        scanned_text = f"Devices found: {count}"
        if self.host_count:
            scanned_text += f" / {self.host_count}"
        self.summary_var.set(scanned_text)

        if self.records:
            fastest = min((r.latency_ms for r in self.records.values() if r.latency_ms is not None), default=None)
            fastest_text = f"Fastest: {fastest:.0f} ms" if fastest is not None else "Fastest: -"
            services: dict[str, int] = {}
            for record in self.records.values():
                for hint in record.service_hints.split(","):
                    cleaned = hint.strip()
                    if cleaned:
                        services[cleaned] = services.get(cleaned, 0) + 1
            top_service = "Top service: " + (max(services, key=services.get) if services else "-")
        else:
            fastest_text = "Fastest: -"
            top_service = "Top service: -"

        self.insight_devices.set(f"Devices: {count}")
        self.insight_latency.set(fastest_text)
        self.insight_services.set(top_service)

    def _insert_record(self, record: DeviceRecord):
        filter_text = self.filter_var.get().strip().lower()
        values_text = " ".join(record.as_row()).lower()
        if filter_text and filter_text not in values_text:
            return
        tag = "even" if len(self.tree.get_children()) % 2 == 0 else "odd"
        self.tree.insert("", tk.END, values=record.as_row(), tags=(tag,))

    def _apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        for record in self.records.values():
            self._insert_record(record)

    def _open_menu(self, event):
        try:
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_row(self):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        if not values:
            return
        text = "\t".join(values)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def _show_details(self):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        columns = [
            "IP Address",
            "Hostname",
            "OS Hint",
            "Latency",
            "TTL",
            "Open Ports",
            "Service Hints",
            "Fingerprints",
            "Identity Hints",
            "MAC Address",
            "Vendor",
        ]
        detail_lines = [f"{label}: {val}" for label, val in zip(columns, values)]
        messagebox.showinfo("Device details", "\n".join(detail_lines))

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
                [
                    "IP Address",
                    "Hostname",
                    "OS Hint",
                    "Latency",
                    "TTL",
                    "Open Ports",
                    "Service Hints",
                    "Fingerprints",
                    "Identity Hints",
                    "MAC Address",
                    "Vendor",
                ]
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