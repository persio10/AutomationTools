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
