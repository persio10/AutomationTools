# Windows 11 Maintenance Automation Script

This repository provides a PowerShell script that bundles the essential maintenance routines needed to keep Windows 11 endpoints healthy and responsive. The script is designed for IT admins who want a repeatable weekly maintenance job that can be deployed across many workstations.

## Features

- **Log-backed execution** with time-stamped records for auditing.
- **Self-healing prerequisites** that elevate automatically (with optional stored credentials) and attempt to upgrade PowerShell to 5.1+ when required.
- **Temporary file cleanup** across system and user temp directories.
- **Storage Sense trigger** to reclaim disk space using the built-in Windows cleanup service.
- **Disk Cleanup automation** using `cleanmgr` with a preconfigured profile.
- **Disk optimization** (`defrag /O`) for all NTFS volumes.
- **Windows Update** detection and installation via the `PSWindowsUpdate` module (optional skip flag).
- **Microsoft Store app refresh** to ensure packaged apps stay current.
- **System File Checker (SFC)** and **DISM** scans for repairing OS components.
- **System health report generation** (Performance Monitor, battery report, hardware/software inventory).
- **Log rotation** to limit growth to the most recent 30 days.
- **Modular skip switches** so scheduled tasks can omit specific operations when needed.

## Usage

1. Copy `windows_11_maintenance.ps1` to a secured location on the endpoint or to a shared network path.
2. (Optional) Edit the **Configuration** block at the top of the script to supply a local administrator username/password if the task must elevate without user interaction.
3. Launch PowerShell (from an elevated session if stored credentials are not provided) and run:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   .\windows_11_maintenance.ps1
   ```
4. Optional parameters let you tailor runs for specific scenarios:
   ```powershell
   .\windows_11_maintenance.ps1 -Silent -SkipWindowsUpdate -SkipDefrag
   ```
5. For weekly automation, create a Windows Task Scheduler job configured to:
   - Run with highest privileges.
   - Use `powershell.exe -ExecutionPolicy Bypass -File "<path>\windows_11_maintenance.ps1" -Silent`.
   - Trigger on the desired cadence (e.g., weekly during off-hours).

## Requirements

- Windows 11.
- PowerShell 5.1 or later (the script will attempt to upgrade automatically if an older host is detected).
- Local administrator credentials supplied either by launching the script from an elevated session or by populating the configuration variables for unattended elevation.
- Internet access for the first run so `PSWindowsUpdate` can install if not already available.

## Unattended elevation

For fully automated deployments where interactive prompts are not acceptable (e.g., Remote Monitoring and Management tooling), set the following variables located near the top of `windows_11_maintenance.ps1`:

```powershell
$script:AdminAutoCredentialUsername = 'Administrator'
$script:AdminAutoCredentialPassword = 'P@ssw0rd!'
```

> **Security note:** The password is stored in plain text inside the script. Restrict access to the file and consider using an alternative secret-delivery mechanism (such as secure parameter injection) in production environments.

## Log Output

Logs and reports are written to a `logs` directory alongside the script:

- `maintenance_<timestamp>.log` – Full chronological log of operations.
- `ComputerInfo_<timestamp>.txt` – Snapshot of system configuration.
- `BatteryReport_<timestamp>.html` – Battery health (on laptops/tablets).
- `SystemDiagnostics_<timestamp>.html` – Performance Monitor health report.

Old logs older than 30 days are pruned automatically each run.

## Customization Ideas

- Adjust the log retention period in `Rotate-Logs` for your compliance needs.
- Extend the script with third-party update tooling or enterprise antivirus scans.
- Plug the script into your RMM or configuration management solution for centralized execution.

## Disclaimer

Run the script at your own risk. Always test within a controlled environment before rolling out widely, and ensure that you have verified backups of critical data.

---

# LanScope – Advanced IP Scanner (Windows 11)

`ip_scanner/app.py` is a Python/Tkinter desktop app for scanning your local network and tracking devices in your homelab. It is designed to build cleanly into a Windows 11 25H2 executable with PyInstaller.

## LanScope features

- Auto-detects the active local subnet (/24 by default) and lets you override with any CIDR.
- Fast, concurrent ping sweep with latency capture plus layered hostname resolution (reverse DNS, `ping -a`, and NetBIOS on Windows for better device labeling).
- TTL parsing, OS guesswork, and MAC-to-vendor mapping to quickly separate Windows, Linux/Unix, network gear, cloud hypervisors, and Bonjour/Apple devices.
- Windows-friendly ARP lookup for MAC addresses after each successful ping.
- Expanded open-port detection against a broader catalog (databases, hypervisors, VPNs, embedded/IoT) with service hints plus optional **deep fingerprinting** (banner grabs on HTTP/SSH/SMB/RDP/WinRM and more).
- Identity hints derived from ports, hostnames, TTL, vendor, and captured banners for razor-fast device recognition.
- Custom port overrides so you can probe homelab-only services without editing code.
- Insight cards showing device counts, fastest responders, and top-seen services during the run.
- Live progress updates, elapsed-time tracking, start/stop controls, global text filter, context-menu copy/details, and export to CSV (including fingerprints and vendors).
- Modern, sleek dark UI built on Tkinter/ttk with alternating row colors and accent buttons.


- Fast, concurrent ping sweep with latency capture plus layered hostname resolution (reverse DNS, `ping -a`, and NetBIOS on Windows for better device labeling).
- TTL parsing and OS guesswork to quickly separate Windows, Linux/Unix, network gear, and Bonjour/Apple devices.
- Windows-friendly ARP lookup for MAC addresses after each successful ping.
- Expanded open-port detection against a richer set of common service ports (media servers, printers, NAS, VPNs, dev ports), with human-friendly service hints alongside the raw port list.
- Identity hints derived from ports, hostnames, and TTL (e.g., "RDP host", "Plex Media Server", "Printer/JetDirect").
- Live progress updates, elapsed-time tracking, start/stop controls, global text filter, and export to CSV.
- Modern, sleek dark UI built on Tkinter/ttk with alternating row colors and accent buttons.

 codex/create-advanced-ip-scanner-for-windows-11-hfmjnp
- Fast, concurrent ping sweep with latency capture plus layered hostname resolution (reverse DNS, `ping -a`, and NetBIOS on Windows for better device labeling).
- Windows-friendly ARP lookup for MAC addresses after each successful ping.
- Expanded open-port detection against a richer set of common service ports, with human-friendly service hints alongside the raw port list.

- Fast, concurrent ping sweep with latency capture and hostname resolution.
- Windows-friendly ARP lookup for MAC addresses after each successful ping.
- Lightweight open-port detection against common service ports (SSH, HTTP/S, SMB, RDP, SQL, etc.).

- Live progress updates, start/stop controls, and export to CSV.
- Modern, clean UI built on Tkinter/ttk for easy operation.


## Run the scanner (Python)

```powershell
python -m pip install --upgrade pip
python -m pip install pyinstaller
python ip_scanner/app.py
```

If you want to adjust the default scan range, set the Network/CIDR field (e.g., `10.0.0.0/24`) before clicking **Start Scan**.

## Build a Windows 11 executable

From a Windows 11 25H2 host with Python 3.11+ installed:

```powershell
python -m pip install --upgrade pip
python -m pip install pyinstaller
pyinstaller --noconfirm --windowed --name LanScope ip_scanner/app.py
```

The executable and supporting files will be placed in `dist\LanScope\`. You can copy that folder anywhere on your Windows machine and run `LanScope.exe` directly.

> Tip: include the `ip_scanner` folder when building so icons and future assets can be bundled easily.
