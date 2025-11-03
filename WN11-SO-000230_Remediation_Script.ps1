<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-SO-000230 vulnerability is remediated. Enforces STIG WN11-SO-000230:
    System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing.

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 11/03/2025
    Last Modified   : 11/03/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000230

.DESCRIPTION
    Configures registry value:
    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy
    Enabled (REG_DWORD) = 1

    This enables FIPS-compliant encryption and hashing algorithms.
    Script is idempotent, verifies compliance, and logs to C:\Logs\PolicyHardening.log.

.TESTED ON
    Date(s) Tested  : 11/03/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-SO-000230_Remediation_Script.ps1
#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile = Join-Path $LogDirectory "PolicyHardening.log"

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
$ValueName = "Enabled"
$DesiredValue = 1

# ---------------------------
# Logging
# ---------------------------
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

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
# Admin Check
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-SO-000230 - Enable FIPS compliant algorithms..." Cyan

# ---------------------------
# Ensure Registry Path Exists
# ---------------------------
if (-not (Test-Path $RegPath)) {
    Write-Log "Creating registry path: $RegPath"
    try {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Log "Registry path created successfully." Green
    } catch {
        Write-Log "ERROR: Failed to create registry path. $_" Red
        Exit 1
    }
} else {
    Write-Log "Registry path exists: $RegPath" Cyan
}

# ---------------------------
# Read Current Value
# ---------------------------
try {
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    Write-Log "Current value for ${ValueName}: $CurrentValue" Cyan
} catch {
    $CurrentValue = $null
    Write-Log "No existing value for ${ValueName} found." Yellow
}

# ---------------------------
# Apply Desired Setting (Idempotent)
# ---------------------------
if ($CurrentValue -ne $DesiredValue) {
    Write-Log "Setting ${ValueName} to $DesiredValue (Enable FIPS compliant algorithms)..."
    try {
        New-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
        Write-Log "SUCCESS: ${ValueName} set to $DesiredValue." Green
    } catch {
        Write-Log "ERROR: Failed to set registry value. $_" Red
        Exit 1
    }
} else {
    Write-Log "No change required: ${ValueName} already set to $DesiredValue." Cyan
}

# ---------------------------
# Verification
# ---------------------------
try {
    $Verify = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ($Verify -eq $DesiredValue) {
        Write-Log "Verification PASSED: ${ValueName} = $Verify" Green
    } else {
        Write-Log "Verification FAILED: ${ValueName} = $Verify (expected $DesiredValue)" Red
        Exit 1
    }
} catch {
    Write-Log "Verification FAILED: Unable to read ${ValueName}. $_" Red
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
    Write-Log "WARNING: gpupdate encountered an issue. $_" Yellow
}

Write-Log "Completed STIG enforcement: WN11-SO-000230" Green
