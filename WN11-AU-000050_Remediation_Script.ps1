<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-AU-000050 vulnerability is remediated. Enables the "Audit Process Creation" policy for Success events.
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
    STIG-ID         : WN11-AU-000050

.DESCRIPTION
    Enforces:
        Computer Configuration >> Windows Settings >> Security Settings >>
        Advanced Audit Policy Configuration >> System Audit Policies >>
        Detailed Tracking >> Audit Process Creation = Success

    This script uses auditpol.exe to set the audit policy and logs actions to:
        C:\Logs\PolicyHardening.log

.TESTED ON
    Date(s) Tested  : 10/30/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-AU-000050_Remediation_Script.ps1
#>

# -------------------------------
# Configuration
# -------------------------------
$LogDirectory = "C:\Logs"
$LogFile = "$LogDirectory\PolicyHardening.log"
$Subcategory = "Process Creation"
$DesiredSetting = "Success"

# Ensure log directory exists
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# Function for timestamped logging
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

Write-Log "Starting policy configuration: Enable 'Audit Process Creation' for Success..."

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "ERROR: Script must be run as Administrator." "Red"
    Exit 1
}

# Get current audit settings for Process Creation
try {
    $CurrentSetting = (auditpol /get /subcategory:"$Subcategory" /r | ForEach-Object { ($_ -split ",")[1].Trim() })
} catch {
    $CurrentSetting = $null
}

Write-Log "Current setting for '$Subcategory': $CurrentSetting"

# Determine if update is needed
if ($CurrentSetting -notmatch $DesiredSetting) {
    Write-Log "Updating audit policy: Setting '$Subcategory' to '$DesiredSetting'..."
    auditpol /set /subcategory:"$Subcategory" /success:enable /failure:disable | Out-Null
    Write-Log "SUCCESS: '$Subcategory' audit policy configured for '$DesiredSetting'." "Green"
} else {
    Write-Log "No change needed: '$Subcategory' already configured for '$DesiredSetting'." "Cyan"
}

# Verify new setting
$VerifySetting = (auditpol /get /subcategory:"$Subcategory" /r | ForEach-Object { ($_ -split ",")[1].Trim() })
Write-Log "Verification result: '$Subcategory' is now set to '$VerifySetting'"

Write-Log "Policy configuration completed successfully."
Write-Log "------------------------------------------------------------"
