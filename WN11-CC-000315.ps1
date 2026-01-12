<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to disable
    the "Always install with elevated privileges" policy in compliance with
    DISA STIG requirement WN11-CC-000315.

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-23
    Last Modified   : 2025-12-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run this script with administrative privileges to disable
    "Always install with elevated privileges" as required by
    DISA STIG WN11-CC-000315.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Output "Disabling 'Always install with elevated privileges'..."

# Registry paths
$machinePolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
$userPolicyPath    = "HKCU:\Software\Policies\Microsoft\Windows\Installer"

# Ensure registry paths exist
if (-not (Test-Path $machinePolicyPath)) {
    New-Item -Path $machinePolicyPath -Force | Out-Null
}

if (-not (Test-Path $userPolicyPath)) {
    New-Item -Path $userPolicyPath -Force | Out-Null
}

# Set policy values to Disabled (0)
Set-ItemProperty -Path $machinePolicyPath -Name "AlwaysInstallElevated" -Type DWord -Value 0
Set-ItemProperty -Path $userPolicyPath    -Name "AlwaysInstallElevated" -Type DWord -Value 0

Write-Output "Verifying configuration..."

# Retrieve values
$machineValue = Get-ItemProperty -Path $machinePolicyPath -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$userValue    = Get-ItemProperty -Path $userPolicyPath -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

Write-Output "Computer Policy Value: $($machineValue.AlwaysInstallElevated)"
Write-Output "User Policy Value    : $($userValue.AlwaysInstallElevated)"

# Confirm compliance
if ($machineValue.AlwaysInstallElevated -eq 0 -and $userValue.AlwaysInstallElevated -eq 0) {
    Write-Output "SUCCESS: 'Always install with elevated privileges' is correctly disabled."
} else {
    Write-Warning "WARNING: Configuration may not have applied correctly."
}

# STIG: WN11-CC-000315
# Requirement: Always install with elevated privileges must be Disabled
