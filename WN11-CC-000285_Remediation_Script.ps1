<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-CC-000285 vulnerability is remediated. Enforces STIG WN11-CC-000285:
    Require secure RPC communication for Remote Desktop Session Host.

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 11/03/2025
    Last Modified   : 11/03/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000285

.DESCRIPTION
    Configures registry setting:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    fEncryptRPCTraffic (REG_DWORD) = 1

  The setting enables secure RPC communication for Remote Desktop.
  The script is idempotent, self-verifying, and logs all actions to C:\Logs\PolicyHardening.log.

.TESTED ON
    Date(s) Tested  : 11/03/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000285_Remediation_Script.ps1
#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile = Join-Path $LogDirectory "PolicyHardening.log"

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$ValueName = "fEncryptRPCTraffic"
$DesiredValue = 1  # 1 = Enabled (Require secure RPC communication)

# ---------------------------
# Logging Function
# ---------------------------
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Entry = "$Timestamp - $Message"
    Write-Host $Entry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Entry
}

# ---------------------------
# Admin Privilege Check
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-CC-000285 - Require secure RPC communication..." Cyan

# ---------------------------
# Ensure Registry Path Exists
# ---------------------------
if (-not (Test-Path $RegPath)) {
    Write-Log "Creating registry path: $RegPath"
    try {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Log "Created registry path successfully." Green
    } catch {
        Write-Log "ERROR creating registry path: $_" Red
        Exit 1
    }
} else {
    Write-Log "Registry path already exists: $RegPath" Cyan
}

# ---------------------------
# Read Current Value
# ---------------------------
try {
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    Write-Log "Current value for $ValueName is: $CurrentValue" Cyan
} catch {
    $CurrentValue = $null
    Write-Log "Current value for $ValueName not found." Yellow
}

# ---------------------------
# Set Desired Value (Idempotent)
# ---------------------------
if ($CurrentValue -ne $DesiredValue) {
    Write-Log "Setting $ValueName to $DesiredValue (Require secure RPC communication)..."
    try {
        New-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
        Write-Log "SUCCESS: $ValueName set to $DesiredValue." Green
    } catch {
        Write-Log "ERROR setting registry value: $_" Red
        Exit 1
    }
} else {
    Write-Log "No change needed: $ValueName already set to $DesiredValue." Cyan
}

# ---------------------------
# Verify Setting
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
    Write-Log "Group Policy refreshed successfully." Green
} catch {
    Write-Log "WARNING: gpupdate failed or returned non-zero. $_" Yellow
}

Write-Log "Completed STIG enforcement: WN11-CC-000285" Green
