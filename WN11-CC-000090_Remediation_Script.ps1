<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-CC-000090 vulnerability is remediated. Enables "Configure registry policy processing" and sets it to
    "Process even if the Group Policy objects have not changed."
    Safe to run multiple times (idempotent), with logging.

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 10/29/2025
    Last Modified   : 10/29/2025
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

# -------------------------------
# Configuration
# -------------------------------
$LogDirectory = "C:\Logs"
$LogFile = "$LogDirectory\PolicyHardening.log"

# Ensure log directory exists
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogEntry
}

Write-Log "Starting policy configuration: Configure registry policy processing (Enabled + Process even if unchanged)..."

# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "ERROR: Script must be run as Administrator." "Red"
    Exit 1
}

# Define registry policy details
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
$ValueName = "NoGPOListChanges"
$DesiredValue = 0  # Enabled + Process even if GPOs unchanged

# Ensure registry path exists
if (!(Test-Path $RegPath)) {
    Write-Log "Creating registry path: $RegPath"
    New-Item -Path $RegPath -Force | Out-Null
}

# Retrieve current value (if exists)
try {
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
} catch {
    $CurrentValue = $null
}

# Compare and apply if needed
if ($CurrentValue -ne $DesiredValue) {
    Write-Log "Updating $RegPath\$ValueName from '$CurrentValue' to '$DesiredValue'..."
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -Type DWord
    Write-Log "SUCCESS: 'Configure registry policy processing' enabled with 'Process even if GPOs have not changed'." "Green"
} else {
    Write-Log "No change needed: policy already set correctly." "Cyan"
}

# Refresh Group Policy
Write-Log "Refreshing Group Policy..."
gpupdate /target:computer /force | Out-Null
Write-Log "Group Policy refreshed successfully." "Green"

Write-Log "Policy configuration completed successfully."
Write-Log "------------------------------------------------------------"
