<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-CC-000315 vulnerability is remediated. Disables the "Always install with elevated privileges" policy.
    Safe to run multiple times (idempotent).

.NOTES
    Author          : Brad Han
    LinkedIn        : https://www.linkedin.com/in/brad-han/
    GitHub          : https://github.com/behan101
    Date Created    : 10/30/2025
    Last Modified   : 10/30/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.DESCRIPTION
    This script enforces:
        Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >>
        "Always install with elevated privileges" = Disabled

    Registry values modified:
        HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 0
        HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 0

.TESTED ON
    Date(s) Tested  : 10/30/2025
    Tested By       : Brad Han
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000315_Remediation_Script.ps1.ps1
#>

# Ensure running as Administrator (required for HKLM)
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    Exit 1
}

# Define policy registry details for both Computer and User scopes
$Policies = @(
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\Installer"; Name = "AlwaysInstallElevated"; DesiredValue = 0 },
    @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\Installer"; Name = "AlwaysInstallElevated"; DesiredValue = 0 }
)

foreach ($Policy in $Policies) {
    $Path = $Policy.Path
    $Name = $Policy.Name
    $DesiredValue = $Policy.DesiredValue

    # Ensure the path exists
    if (!(Test-Path $Path)) {
        Write-Host "Creating registry path: $Path"
        New-Item -Path $Path -Force | Out-Null
    }

    # Read current value
    try {
        $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        $CurrentValue = $null
    }

    # Compare and update if necessary
    if ($CurrentValue -ne $DesiredValue) {
        Write-Host "Setting '$Name' to $DesiredValue at $Path ..."
        Set-ItemProperty -Path $Path -Name $Name -Value $DesiredValue -Type DWord
        Write-Host "Updated successfully: '$Name' set to Disabled (Value: $DesiredValue)" -ForegroundColor Green
    } else {
        Write-Host "No change needed: '$Name' already set to Disabled." -ForegroundColor Cyan
    }
}

# Optional: Refresh Group Policy
Write-Host "Refreshing Group Policy..."
gpupdate /target:computer /force | Out-Null
Write-Host "Group Policy refreshed successfully." -ForegroundColor Green
