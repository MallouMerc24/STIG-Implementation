<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to require
    secure RPC communication for Remote Desktop Services sessions in compliance
    with DISA STIG requirement WN11-CC-000285.

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-23
    Last Modified   : 2025-12-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000285

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run this script with administrative privileges to enable
    "Require secure RPC communication" for Remote Desktop Services
    as required by DISA STIG WN11-CC-000285.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Output "Configuring 'Require secure RPC communication' for Remote Desktop Services..."

# Registry path for RDS Security policy
$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Enable secure RPC communication
# 1 = Enabled
Set-ItemProperty -Path $regPath -Name "fEncryptRPCTraffic" -Type DWord -Value 1

Write-Output "Verifying configuration..."

# Retrieve policy value
$policyValue = Get-ItemProperty -Path $regPath -Name "fEncryptRPCTraffic" -ErrorAction SilentlyContinue

Write-Output "Registry Value (fEncryptRPCTraffic): $($policyValue.fEncryptRPCTraffic)"

# Confirm compliance
if ($policyValue.fEncryptRPCTraffic -eq 1) {
    Write-Output "SUCCESS: 'Require secure RPC communication' is correctly enabled."
} else {
    Write-Warning "WARNING: Configuration may not have applied correctly."
}

# STIG: WN11-CC-000285
# Requirement: Require secure RPC communication must be Enabled
