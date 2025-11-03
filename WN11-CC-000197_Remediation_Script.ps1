<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-CC-000197 vulnerability is remediated. Enforces STIG WN11-CC-000197:
    Turn off Microsoft consumer experiences.

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 11/03/2025
    Last Modified   : 11/03/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.DESCRIPTION
    Configures the policy value:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent
    DisableWindowsConsumerFeatures (REG_DWORD) = 1

    This disables automatic consumer apps and content.
    The script is idempotent, verifies compliance, and logs all actions to C:\Logs\PolicyHardening.log.

.TESTED ON
    Date(s) Tested  : 11/03/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000197_Remediation_Script.ps1
#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile = Join-Path $LogDirectory "PolicyHardening.log"

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$ValueName = "DisableWindowsConsumerFeatures"
$DesiredValue = 1  # 1 = Enabled (Turn off consumer experiences)

# ---------------------------
# Logging Function
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
# Check Admin Privileges
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-CC-000197 - Turn off Microsoft consumer experiences..." Cyan

# ---------------------------
# Ensure Registry Path Exists
# ---------------------------
if (-not (Test-Path $RegPath)) {
    Write-Log "Creating registry path: $RegPath"
    try {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Log "Created registry path successfully." Green
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
# Set Desired Value (Idempotent)
# ---------------------------
if ($CurrentValue -ne $DesiredValue) {
    Write-Log "Setting $ValueName to $DesiredValue (Turn off Microsoft consumer experiences)..."
    try {
        New-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
        Write-Log "SUCCESS: $ValueName set to $DesiredValue." Green
    } catch {
        Write-Log "ERROR: Failed to set $ValueName. $_" Red
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
        Write-Log "Verification PASSED: $ValueName = $Verify" Green
    } else {
        Write-Log "Verification FAILED: $ValueName = $Verify (expected $DesiredValue)" Red
        Exit 1
    }
} catch {
    Write-Log "Verification FAILED: Unable to read $ValueName. $_" Red
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

Write-Log "Completed STIG enforcement: WN11-CC-000197" Green
