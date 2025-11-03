<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-UR-000070 vulnerability is remediated. Enforces STIG WN11-UR-000070:
    Configure 'Deny access to this computer from the network' user right.

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 11/03/2025
    Last Modified   : 11/03/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000070

.DESCRIPTION
  Domain Systems:
    - Enterprise Admins
    - Domain Admins
    - Local account
    - Guests
  All Systems:
    - Guests

  Privileged Access Workstations (PAWs) are exempt from denying Enterprise Admins and Domain Admins.
    Script is idempotent, verifies the setting, and logs all actions to C:\Logs\PolicyHardening.log.

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
    PS C:\> .\WN11-UR-000070_Remediation_Script.ps1
#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile = Join-Path $LogDirectory "PolicyHardening.log"

# Ensure logging directory exists
if (!(Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "$ts - $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $entry
}

# ---------------------------
# Admin check
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-UR-000070 - Deny access to this computer from the network..." Cyan

# ---------------------------
# Determine Domain Membership
# ---------------------------
$IsDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
if ($IsDomainJoined) {
    Write-Log "System is domain-joined." Cyan
} else {
    Write-Log "System is standalone (workgroup)." Cyan
}

# ---------------------------
# Define desired assignments
# ---------------------------
$UserRight = "SeDenyNetworkLogonRight"

if ($IsDomainJoined) {
    $DesiredPrincipals = @(
        "Guests",
        "Local account",
        "Enterprise Admins",
        "Domain Admins"
    )
} else {
    $DesiredPrincipals = @("Guests")
}

# ---------------------------
# Export current Local Security Policy
# ---------------------------
$tempInf = "$env:TEMP\secpol_current.inf"
$tempSdb = "$env:TEMP\secpol.sdb"
Write-Log "Exporting current security policy..."
secedit /export /cfg $tempInf /quiet | Out-Null

if (!(Test-Path $tempInf)) {
    Write-Log "ERROR: Failed to export current security policy." Red
    Exit 1
}

# ---------------------------
# Parse current setting
# ---------------------------
$currentValue = Select-String -Path $tempInf -Pattern "^\s*$UserRight\s*=" | ForEach-Object {
    ($_ -split "=")[1].Trim()
}

if ($currentValue) {
    Write-Log "Current $UserRight = $currentValue" Cyan
    $CurrentPrincipals = $currentValue -split ","
} else {
    Write-Log "Current $UserRight not found; will be created." Yellow
    $CurrentPrincipals = @()
}

# ---------------------------
# Compare and update if necessary
# ---------------------------
$diff = Compare-Object -ReferenceObject ($CurrentPrincipals | Sort-Object) -DifferenceObject ($DesiredPrincipals | Sort-Object)
if ($diff) {
    Write-Log "Updating user right assignment for '$UserRight'..."
    # Create a new INF policy template
    $tempInfNew = "$env:TEMP\secpol_update.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]
$UserRight = $($DesiredPrincipals -join ",")
"@ | Out-File -Encoding ASCII -FilePath $tempInfNew -Force

    # Apply new policy
    Write-Log "Applying updated policy..."
    secedit /configure /db $tempSdb /cfg $tempInfNew /quiet | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Log "SUCCESS: Updated $UserRight assignment applied." Green
    } else {
        Write-Log "ERROR: Failed to apply updated policy (exit code $LASTEXITCODE)." Red
        Exit 1
    }
} else {
    Write-Log "No changes required: $UserRight already set correctly." Cyan
}

# ---------------------------
# Verify applied setting
# ---------------------------
Write-Log "Verifying updated setting..."
secedit /export /cfg $tempInf /quiet | Out-Null
$verifyValue = Select-String -Path $tempInf -Pattern "^\s*$UserRight\s*=" | ForEach-Object {
    ($_ -split "=")[1].Trim()
}

if ($verifyValue) {
    Write-Log "Verification: $UserRight = $verifyValue" Green
    $VerifyPrincipals = $verifyValue -split ","
    $Missing = Compare-Object -ReferenceObject ($DesiredPrincipals | Sort-Object) -DifferenceObject ($VerifyPrincipals | Sort-Object) -PassThru | Where-Object { $_ -in $DesiredPrincipals }
    if ($Missing) {
        Write-Log "Verification FAILED: Missing principals: $($Missing -join ', ')" Red
    } else {
        Write-Log "Verification PASSED: All principals correctly assigned." Green
    }
} else {
    Write-Log "Verification FAILED: No $UserRight line found after apply." Red
}

# ---------------------------
# Refresh Group Policy
# ---------------------------
Write-Log "Refreshing Group Policy..."
gpupdate /force | Out-Null
Write-Log "Group Policy refresh complete." Green

Write-Log "Completed STIG enforcement: WN11-UR-000070" Green
