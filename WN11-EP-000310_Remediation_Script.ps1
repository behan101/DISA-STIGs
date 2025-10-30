<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-EP-000310 vulnerability is remediated. Enforce STIG WN11-EP-000310:
    Configure "Enumeration policy for external devices incompatible with Kernel DMA Protection"
    to Enabled with "Enumeration Policy" = "Block All".

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 10/30/2025
    Last Modified   : 10/30/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-EP-000310

.DESCRIPTION
    Implements required registry value:
      HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection
      DeviceEnumerationPolicy (REG_DWORD) = 0

  Safe to run multiple times. Logs actions to C:\Logs\PolicyHardening.log

.TESTED ON
    Date(s) Tested  : 10/30/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-EP-000310_Remediation_Script.ps1
#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile = Join-Path $LogDirectory "PolicyHardening.log"

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
$ValueName = "DeviceEnumerationPolicy"
$DesiredValue = 0  # 0 = Block All

# ---------------------------
# Helper for logging
# ---------------------------
if (!(Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Entry = "$Timestamp - $Message"
    Write-Host $Entry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Entry
}

# ---------------------------
# Admin check
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-EP-000310 - Kernel DMA Protection enumeration policy..."

# ---------------------------
# Ensure registry path exists
# ---------------------------
if (-not (Test-Path $RegPath)) {
    Write-Log "Creating registry path: $RegPath"
    try {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Log "Created registry key successfully." Green
    } catch {
        Write-Log "ERROR creating registry key: $_" Red
        Exit 1
    }
} else {
    Write-Log "Registry path already exists: $RegPath" Cyan
}

# ---------------------------
# Read current value
# ---------------------------
try {
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    Write-Log "Current value for $ValueName is: $CurrentValue" Cyan
} catch {
    $CurrentValue = $null
    Write-Log "Current value for $ValueName not present." Cyan
}

# ---------------------------
# Apply desired value
# ---------------------------
if ($CurrentValue -ne $DesiredValue) {
    Write-Log "Setting $ValueName to $DesiredValue (Block All)..."
    try {
        New-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
        Write-Log "SUCCESS: $ValueName set to $DesiredValue (Block All)." Green
    } catch {
        Write-Log "ERROR setting registry value: $_" Red
        Exit 1
    }
} else {
    Write-Log "No change required: $ValueName already set to $DesiredValue (Block All)." Cyan
}

# ---------------------------
# Verification read-back
# ---------------------------
try {
    $Verify = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ($Verify -eq $DesiredValue) {
        Write-Log "Verification passed: $ValueName = $Verify" Green
    } else {
        Write-Log "Verification FAILED: $ValueName = $Verify (expected $DesiredValue)" Red
        Exit 1
    }
} catch {
    Write-Log "Verification FAILED: could not read $ValueName. $_" Red
    Exit 1
}

# ---------------------------
# Refresh Group Policy
# ---------------------------
Write-Log "Refreshing Group Policy (gpupdate /force)..."
try {
    gpupdate /force | Out-Null
    Write-Log "gpupdate completed successfully." Green
} catch {
    Write-Log "WARNING: gpupdate failed or returned non-zero. $_" Yellow
}

Write-Log "Completed STIG enforcement: WN11-EP-000310" Green
