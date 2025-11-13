<#
.SYNOPSIS
    Weekly maintenance script for Windows 11 endpoints.
.DESCRIPTION
    Automates key health and maintenance tasks including temporary file cleanup,
    Windows Update scans, component health checks, disk optimization, and health reporting.
    Designed to run with administrative privileges via Task Scheduler.
#>

param(
    [switch]$Silent,
    [switch]$SkipWindowsUpdate,
    [switch]$SkipSFC,
    [switch]$SkipDISM,
    [switch]$SkipDiskCleanup,
    [switch]$SkipStorageSense,
    [switch]$SkipDefrag,
    [switch]$SkipAppUpdates,
    [switch]$AutoElevationAttempt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Region: Configuration -------------------------------------------------------
# Provide a local administrator credential if the script needs to self-elevate
# without triggering an interactive UAC or credential prompt. Leave these
# values blank when the script will always be launched from an already
# elevated session.
$script:AdminAutoCredentialUsername = ''
$script:AdminAutoCredentialPassword = ''
$script:CachedAdminCredential = $null
$script:AdminCredentialInitialized = $false

# Region: Environment Prep ---------------------------------------------------
$script:LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'logs'
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFile = Join-Path -Path $LogDirectory -ChildPath "maintenance_$timestamp.log"
$script:MinimumPowerShellVersion = [version]'5.1'
$script:CurrentPowerShellPath = (Get-Process -Id $PID).Path
$script:InitialBoundParameters = @{}
foreach ($key in $PSBoundParameters.Keys) {
    $script:InitialBoundParameters[$key] = $PSBoundParameters[$key]
}
$script:InitialUnboundArguments = @($MyInvocation.UnboundArguments)

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $entry = "[$(Get-Date -Format 'u')] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $entry
    if (-not $Silent) {
        Write-Host $entry
    }
}

function Get-StoredAdminCredential {
    if ($script:CachedAdminCredential) {
        return $script:CachedAdminCredential
    }

    if ($script:AdminCredentialInitialized) {
        return $null
    }

    $script:AdminCredentialInitialized = $true

    if ([string]::IsNullOrWhiteSpace($script:AdminAutoCredentialUsername) -or
        [string]::IsNullOrWhiteSpace($script:AdminAutoCredentialPassword)) {
        Write-Log -Message 'No stored administrative credential configured; relying on current execution context.'
        return $null
    }

    try {
        $securePassword = ConvertTo-SecureString -String $script:AdminAutoCredentialPassword -AsPlainText -Force
        $script:CachedAdminCredential = [pscredential]::new($script:AdminAutoCredentialUsername, $securePassword)
        Write-Log -Message 'Stored administrative credentials loaded for unattended elevation.'
    }
    catch {
        Write-Log -Message "Failed to construct stored administrative credentials: $($_.Exception.Message)" -Level 'ERROR'
    }

    return $script:CachedAdminCredential
}

function Get-InvocationArguments {
    param(
        [hashtable]$BoundParameters,
        [string[]]$UnboundArguments
    )

    $arguments = @()
    if ($BoundParameters) {
        foreach ($parameter in $BoundParameters.GetEnumerator()) {
            $name = "-$($parameter.Key)"
            switch ($parameter.Value) {
                { $_ -is [System.Management.Automation.SwitchParameter] } {
                    if ($parameter.Value.IsPresent) {
                        $arguments += $name
                    }
                }
                $null { }
                default {
                    $arguments += $name
                    $arguments += [string]$parameter.Value
                }
            }
        }
    }

    if ($UnboundArguments) {
        $arguments += $UnboundArguments
    }

    return $arguments
}

function ConvertTo-CommandLine {
    param([string[]]$Arguments)

    if (-not $Arguments) {
        return ''
    }

    $escaped = foreach ($argument in $Arguments) {
        if ($null -eq $argument) {
            continue
        }

        $text = [string]$argument
        if ($text -match '^[\w\-\.:\\/]+$') {
            $text
        }
        else {
            '"{0}"' -f ($text.Replace('"','\"'))
        }
    }

    return ($escaped -join ' ')
}

function Restart-ScriptProcess {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [switch]$Elevated,
        [System.Management.Automation.PSCredential]$Credential,
        [string[]]$ScriptArguments
    )

    if (-not $PSCommandPath) {
        throw 'Unable to determine script path for restart.'
    }

    if (-not $ScriptArguments) {
        $ScriptArguments = Get-InvocationArguments -BoundParameters $script:InitialBoundParameters -UnboundArguments $script:InitialUnboundArguments
    }

    $argumentList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    if ($ScriptArguments) {
        $argumentList += $ScriptArguments
    }

    $startProcessSplat = @{
        FilePath     = $Executable
        ArgumentList = $argumentList
    }

    if ($Credential) {
        $taskName = "WinMaintElevate_$([guid]::NewGuid().ToString('N'))"
        $argumentsString = ConvertTo-CommandLine -Arguments $argumentList

        $taskCleanup = {
            param($Name)
            if (-not $Name) {
                return
            }

            try {
                if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                }
            }
            catch {
                Write-Log -Message "Failed to remove temporary scheduled task ${Name}: $($_.Exception.Message)" -Level 'WARN'
            }
        }

        try {
            Write-Log -Message "Launching new PowerShell instance via scheduled task: $Executable"
            Import-Module ScheduledTasks -ErrorAction Stop

            $action = New-ScheduledTaskAction -Execute $Executable -Argument $argumentsString
            $principal = New-ScheduledTaskPrincipal -UserId $Credential.UserName -LogonType Password -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -Compatibility Win8
            $definition = New-ScheduledTask -Action $action -Principal $principal -Settings $settings

            Register-ScheduledTask -TaskName $taskName -InputObject $definition -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName
            Write-Log -Message "Temporary scheduled task $taskName started for elevation."
        }
        catch {
            $taskCleanup.Invoke($taskName)
            Write-Log -Message "Failed to restart script using scheduled task: $($_.Exception.Message)" -Level 'ERROR'
            throw
        }

        Start-Sleep -Seconds 5
        Write-Log -Message "Cleaning up temporary scheduled task $taskName."
        $taskCleanup.Invoke($taskName)
    }
    else {
        $startProcessSplat['UseNewEnvironment'] = $true
        if ($Elevated) {
            $startProcessSplat['Verb'] = 'RunAs'
        }

        Write-Log -Message "Launching new PowerShell instance: $Executable"
        try {
            Start-Process @startProcessSplat | Out-Null
        }
        catch {
            Write-Log -Message "Failed to restart script: $($_.Exception.Message)" -Level 'ERROR'
            throw
        }
    }

    Write-Log -Message 'Restart initiated. Exiting current process.'
    exit
}

function Ensure-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Message 'Administrative privileges confirmed.'
        return
    }

    if ($AutoElevationAttempt) {
        Write-Log -Message 'Administrative privileges could not be confirmed after automatic elevation attempt. Verify stored credentials or launch from an elevated session.' -Level 'ERROR'
        throw 'Administrative privileges required.'
    }

    $storedCredential = Get-StoredAdminCredential
    if ($storedCredential) {
        Write-Log -Message 'Administrative privileges required. Relaunching with stored credentials.'
        $arguments = Get-InvocationArguments -BoundParameters $script:InitialBoundParameters -UnboundArguments $script:InitialUnboundArguments
        if (-not $arguments) {
            $arguments = @()
        }
        if (-not ($arguments -contains '-AutoElevationAttempt')) {
            $arguments += '-AutoElevationAttempt'
        }
        Restart-ScriptProcess -Executable $script:CurrentPowerShellPath -Credential $storedCredential -ScriptArguments $arguments
    }

    Write-Log -Message 'Administrative privileges required but no stored credential is available. Configure AdminAutoCredentialUsername/AdminAutoCredentialPassword or launch the script from an elevated session.' -Level 'ERROR'
    throw 'Administrative privileges required.'
}

function Ensure-MinimumPowerShell {
    if ($PSVersionTable.PSVersion -ge $script:MinimumPowerShellVersion) {
        Write-Log -Message "PowerShell version $($PSVersionTable.PSVersion) meets requirement $script:MinimumPowerShellVersion."
        return
    }

    Write-Log -Message "PowerShell version $($PSVersionTable.PSVersion) below requirement. Attempting upgrade." -Level 'WARN'
    $candidateExecutable = $null

    $systemPowerShell = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    if (Test-Path $systemPowerShell) {
        try {
            $fileVersion = [version](Get-Item $systemPowerShell).VersionInfo.FileVersion
            if ($fileVersion -ge $script:MinimumPowerShellVersion) {
                $candidateExecutable = $systemPowerShell
            }
        }
        catch {
            Write-Log -Message "Unable to evaluate system PowerShell version: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    if (-not $candidateExecutable) {
        $pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($pwshCommand) {
            try {
                $pwshVersionText = & $pwshCommand.Source -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()'
                if ([version]$pwshVersionText -ge $script:MinimumPowerShellVersion) {
                    $candidateExecutable = $pwshCommand.Source
                }
            }
            catch {
                Write-Log -Message "Failed to query PowerShell (pwsh) version: $($_.Exception.Message)" -Level 'WARN'
            }
        }
    }

    if (-not $candidateExecutable) {
        $wingetCommand = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($wingetCommand) {
            Write-Log -Message 'Attempting to install latest PowerShell using winget.'
            try {
                $wingetArgs = @('install','--id','Microsoft.PowerShell','--source','winget','--silent','--accept-package-agreements','--accept-source-agreements')
                Start-Process -FilePath $wingetCommand.Source -ArgumentList $wingetArgs -Wait -ErrorAction Stop | Out-Null
                $pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
                if (-not $pwshCommand) {
                    $defaultPwshPath = Join-Path ${env:ProgramFiles} 'PowerShell\\7\\pwsh.exe'
                    if (Test-Path $defaultPwshPath) {
                        $pwshCommand = Get-Item $defaultPwshPath
                    }
                }
                if ($pwshCommand) {
                    $pwshExecutable = if ($pwshCommand -is [System.IO.FileInfo]) { $pwshCommand.FullName } else { $pwshCommand.Source }
                    $pwshVersionText = & $pwshExecutable -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()'
                    if ([version]$pwshVersionText -ge $script:MinimumPowerShellVersion) {
                        $candidateExecutable = $pwshExecutable
                    }
                }
            }
            catch {
                Write-Log -Message "Automatic installation of PowerShell failed: $($_.Exception.Message)" -Level 'WARN'
            }
        }
        else {
            Write-Log -Message 'winget command not available; unable to automate PowerShell upgrade.' -Level 'WARN'
        }
    }

    if ($candidateExecutable) {
        Write-Log -Message "Restarting script with PowerShell executable: $candidateExecutable"
        $storedCredential = Get-StoredAdminCredential
        if ($storedCredential) {
            Restart-ScriptProcess -Executable $candidateExecutable -Credential $storedCredential
        }
        else {
            Restart-ScriptProcess -Executable $candidateExecutable
        }
    }
    else {
        Write-Log -Message 'Could not locate PowerShell 5.1 or newer automatically.' -Level 'ERROR'
        throw 'PowerShell 5.1 or newer is required.'
    }
}

Write-Log -Message 'Starting Windows 11 maintenance routine.'

Ensure-Administrator
Ensure-MinimumPowerShell

# Region: Utility Functions ---------------------------------------------------
function Invoke-CommandWithLogging {
    param(
        [Parameter(Mandatory)][string]$Command,
        [string]$SuccessMessage,
        [string]$ErrorMessage = 'Operation failed.'
    )
    Write-Log -Message "Executing: $Command"
    try {
        $output = Invoke-Expression $Command
        if ($output) {
            foreach ($item in $output) {
                if ($null -eq $item) {
                    continue
                }

                $text = if ($item -is [string]) { $item } else { ($item | Out-String) }
                if ([string]::IsNullOrWhiteSpace($text)) {
                    continue
                }

                $lines = $text -split "`r?`n"
                foreach ($line in $lines) {
                    $trimmed = $line.TrimEnd()
                    if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                        Write-Log -Message $trimmed
                    }
                }
            }
        }
        if ($SuccessMessage) {
            Write-Log -Message $SuccessMessage
        }
    }
    catch {
        Write-Log -Message "$ErrorMessage`n$($_.Exception.Message)" -Level 'ERROR'
        throw
    }
}

function Clear-TempFiles {
    Write-Log -Message 'Clearing temporary directories.'
    $paths = @(
        $env:TEMP,
        $env:TMP,
        "$env:SystemRoot\Temp",
        "$env:SystemDrive\Windows\Temp",
        "$env:SystemDrive\Users\*\AppData\Local\Temp"
    )

    foreach ($path in $paths) {
        try {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log -Message "Cleared: $path"
        }
        catch {
            Write-Log -Message "Failed to clear: $path - $($_.Exception.Message)" -Level 'WARN'
        }
    }
}

function Run-StorageSense {
    Write-Log -Message 'Running Storage Sense clean-up.'
    try {
        if (Get-Command -Name 'Start-StorageSense' -ErrorAction SilentlyContinue) {
            Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-Command','Start-StorageSense' -Wait -WindowStyle Hidden -ErrorAction Stop
        }
        else {
            Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cleanmgr.exe') -ArgumentList '/autoclean' -Wait -WindowStyle Hidden -ErrorAction Stop
        }
        Write-Log -Message 'Storage Sense completed.'
    }
    catch {
        Write-Log -Message "Storage Sense failed: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Run-WindowsUpdate {
    Write-Log -Message 'Checking for Windows Updates.'
    try {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log -Message "Failed to ensure PSWindowsUpdate module: $($_.Exception.Message)" -Level 'WARN'
    }

    Import-Module PSWindowsUpdate -ErrorAction Stop

    try {
        $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        if ($updates) {
            Write-Log -Message "Retrieved updates: $($updates.KBArticleID -join ', ')"
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop | Out-Null
            Write-Log -Message 'Windows Updates installed. System reboot may be required.'
        }
        else {
            Write-Log -Message 'No updates available.'
        }
    }
    catch {
        Write-Log -Message "Windows Update task failed: $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Run-SFC {
    Write-Log -Message 'Running System File Checker (SFC).' 
    Invoke-CommandWithLogging -Command 'sfc /scannow' -SuccessMessage 'SFC scan completed.' -ErrorMessage 'SFC encountered an error.'
}

function Run-DISM {
    Write-Log -Message 'Running DISM health restore.'
    $commands = @(
        'DISM /Online /Cleanup-Image /CheckHealth',
        'DISM /Online /Cleanup-Image /ScanHealth',
        'DISM /Online /Cleanup-Image /RestoreHealth'
    )
    foreach ($cmd in $commands) {
        Invoke-CommandWithLogging -Command $cmd -SuccessMessage "$cmd completed." -ErrorMessage "$cmd failed."
    }
}

function Initialize-DiskCleanupProfile {
    param([int]$ProfileId = 1337)
    $volumeCachePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $flagName = "StateFlags$ProfileId"
    $categories = @(
        'Temporary Files'
        'Temporary Setup Files'
        'Downloaded Program Files'
        'Delivery Optimization Files'
        'Device Driver Packages'
        'Internet Cache Files'
        'Old ChkDsk Files'
        'Recycle Bin'
        'Service Pack Cleanup'
        'Setup Log Files'
        'System error memory dump files'
        'System error minidump files'
        'Temporary Internet Files'
        'Thumbnail Cache'
        'Update Cleanup'
        'Windows Defender'
    )

    foreach ($category in $categories) {
        $keyPath = Join-Path -Path $volumeCachePath -ChildPath $category
        if (Test-Path $keyPath) {
            try {
                New-ItemProperty -Path $keyPath -Name $flagName -PropertyType DWord -Value 2 -Force | Out-Null
            }
            catch {
                Write-Log -Message "Unable to set Disk Cleanup flag for ${category}: $($_.Exception.Message)" -Level 'WARN'
            }
        }
    }

    return $ProfileId
}

function Run-DiskCleanup {
    Write-Log -Message 'Running Disk Cleanup in unattended mode.'
    $profileId = Initialize-DiskCleanupProfile
    $cleanmgrArgs = "/sagerun:$profileId"

    try {
        Start-Process -FilePath 'cleanmgr.exe' -ArgumentList $cleanmgrArgs -Wait -WindowStyle Hidden -ErrorAction Stop
        Write-Log -Message 'Disk Cleanup completed.'
    }
    catch {
        Write-Log -Message "Disk Cleanup failed: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Run-Defrag {
    Write-Log -Message 'Running storage optimization.'
    $drives = Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemType -eq 'NTFS' }
    foreach ($drive in $drives) {
        $cmd = "defrag $($drive.DriveLetter): /O"
        Invoke-CommandWithLogging -Command $cmd -SuccessMessage "Optimized drive $($drive.DriveLetter):" -ErrorMessage "Failed to optimize drive $($drive.DriveLetter):"
    }
}

function Update-StoreApps {
    Write-Log -Message 'Checking Microsoft Store apps for updates.'
    try {
        $progressPreference = $global:ProgressPreference
        $global:ProgressPreference = 'SilentlyContinue'
        Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile","-Command","Get-AppxPackage | Where-Object { $_.SignatureKind -eq 'Store' } | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register ($_.InstallLocation + '\\AppXManifest.xml') }" -Wait
        Write-Log -Message 'Microsoft Store apps refreshed.'
    }
    catch {
        Write-Log -Message "Store app update failed: $($_.Exception.Message)" -Level 'WARN'
    }
    finally {
        if ($progressPreference) {
            $global:ProgressPreference = $progressPreference
        }
    }
}

function Generate-HealthReport {
    Write-Log -Message 'Gathering system health report.'
    $reportPath = Join-Path -Path $LogDirectory -ChildPath "SystemDiagnostics_$timestamp.html"
    try {
        Get-ComputerInfo | Out-File -FilePath (Join-Path $LogDirectory "ComputerInfo_$timestamp.txt")
        powercfg /batteryreport /output "$LogDirectory\BatteryReport_$timestamp.html" | Out-Null
        perfmon.exe /report "$reportPath" | Out-Null
        Write-Log -Message "System health report generated at $reportPath"
    }
    catch {
        Write-Log -Message "Health report generation failed: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Rotate-Logs {
    $maxAgeDays = 30
    Write-Log -Message "Rotating logs older than $maxAgeDays days."
    Get-ChildItem -Path $LogDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$maxAgeDays) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# Region: Main Execution -----------------------------------------------------
try {
    if (-not $SkipStorageSense) { Run-StorageSense }
    Clear-TempFiles
    if (-not $SkipDiskCleanup) { Run-DiskCleanup }
    if (-not $SkipDefrag) { Run-Defrag }
    if (-not $SkipWindowsUpdate) { Run-WindowsUpdate }
    if (-not $SkipAppUpdates) { Update-StoreApps }
    if (-not $SkipSFC) { Run-SFC }
    if (-not $SkipDISM) { Run-DISM }
    Generate-HealthReport
    Rotate-Logs
    Write-Log -Message 'Maintenance routine complete.'
}
catch {
    Write-Log -Message "Fatal error encountered: $($_.Exception.Message)" -Level 'ERROR'
    throw
}
finally {
    Write-Log -Message 'Script finished.'
}
