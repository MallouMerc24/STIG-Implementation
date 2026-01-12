<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit
    successful Other Logon/Logoff events by enabling the Advanced Audit
    Policy setting for "Audit Other Logon/Logoff Events" in compliance
    with DISA STIG requirements.

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-22
    Last Modified   : 2025-12-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000560

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with administrative privileges to enable auditing of
    successful Other Logon/Logoff events ("Audit Other Logon/Logoff Events" = Success)
    as required by DISA STIG WN11-AU-000560.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Output "Configuring 'Audit Other Logon/Logoff Events' to Success..."

# Enable Audit Other Logon/Logoff Events (Success)
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

# Verify configuration
Write-Output "Verifying configuration..."
$auditStatus = auditpol /get /subcategory:"Other Logon/Logoff Events"

Write-Output $auditStatus

# Confirm compliance
if ($auditStatus -match "Success\s+Enabled") {
    Write-Output "SUCCESS: 'Audit Other Logon/Logoff Events' is correctly configured."
} else {
    Write-Warning "WARNING: Configuration may not have applied correctly."
}

# STIG: WN11-AU-000560
# Requirement: Audit Other Logon/Logoff Events must be enabled for Success
