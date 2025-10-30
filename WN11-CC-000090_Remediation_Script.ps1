<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-CC-000090 vulnerability is remediated. Enables "Configure registry policy processing" and sets it to
    "Process even if the Group Policy objects have not changed."
    Safe to run multiple times (idempotent), with logging.

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 10/30/2025
    Last Modified   : 10/30/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090

.DESCRIPTION
    Enforces:
        Computer Configuration >> Administrative Templates >> System >> Group Policy >>
        "Configure registry policy processing" = Enabled
        Option: "Process even if the Group Policy objects have not changed" = Checked

    Registry:
        HKLM\Software\Policies\Microsoft\Windows\System\NoGPOListChanges = 0

    Log file:
        C:\Logs\PolicyHardening.log

    STIG check:
        HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
        Name : NoGPOListChanges
        Type : REG_DWORD
        Value: 0

.TESTED ON
    Date(s) Tested  : 10/30/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899
.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000090_Remediation_Script.ps1

#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile = Join-Path $LogDirectory "PolicyHardening.log"

# STIG-mandated registry path and value
$StigGuidPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$ValueName = "NoGPOListChanges"
$DesiredValue = 0

# ---------------------------
# Helpers
# ---------------------------
if (!(Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "$ts - $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $entry
}

# ---------------------------
# Admin check
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-CC-000090 - Configure registry policy processing..."

# ---------------------------
# Ensure registry path exists
# ---------------------------
if (-not (Test-Path $StigGuidPath)) {
    Write-Log "Creating registry path: $StigGuidPath"
    try {
        New-Item -Path $StigGuidPath -Force | Out-Null
        Write-Log "Created registry key successfully." Green
    } catch {
        Write-Log "ERROR creating registry key: $_" Red
        Exit 1
    }
} else {
    Write-Log "Registry path already exists: $StigGuidPath" Cyan
}

# ---------------------------
# Read current value
# ---------------------------
try {
    $current = (Get-ItemProperty -Path $StigGuidPath -Name $ValueName -ErrorAction Stop).$ValueName
    Write-Log "Current value for $ValueName is: $current" Cyan
} catch {
    $current = $null
    Write-Log "Current value for $ValueName not present." Cyan
}

# ---------------------------
# Set the desired value if needed
# ---------------------------
if ($current -ne $DesiredValue) {
    Write-Log "Setting $ValueName to $DesiredValue at $StigGuidPath ..."
    try {
        New-ItemProperty -Path $StigGuidPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
        Write-Log "SUCCESS: $ValueName set to $DesiredValue." Green
    } catch {
        Write-Log "ERROR: Failed to set registry value: $_" Red
        Exit 1
    }
} else {
    Write-Log "No change required: $ValueName already set to $DesiredValue." Cyan
}

# ---------------------------
# Verification read-back
# ---------------------------
try {
    $verify = (Get-ItemProperty -Path $StigGuidPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ($verify -eq $DesiredValue) {
        Write-Log "Verification passed: $ValueName = $verify" Green
    } else {
        Write-Log "Verification FAILED: $ValueName = $verify (expected $DesiredValue)" Red
        Exit 1
    }
} catch {
    Write-Log "Verification FAILED: could not read $ValueName. $_" Red
    Exit 1
}

# ---------------------------
# Refresh Group Policy to force immediate application
# ---------------------------
Write-Log "Refreshing Group Policy (gpupdate /force) ..."
try {
    gpupdate /force | Out-Null
    Write-Log "gpupdate completed." Green
} catch {
    Write-Log "WARNING: gpupdate failed or returned non-zero. $_" Yellow
}

Write-Log "Completed STIG enforcement: WN11-CC-000090" Green
