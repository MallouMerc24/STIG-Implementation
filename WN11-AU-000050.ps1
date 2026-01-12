<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit
    successful process creation events by enabling the Advanced Audit Policy
    setting for "Audit Process Creation" in compliance with DISA STIG
    requirements.

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-22
    Last Modified   : 2025-12-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000050

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  :
    PowerShell Ver. : 

.USAGE
    Run this script with administrative privileges to enable auditing of
    successful process creation events ("Audit Process Creation" = Success)
    as required by DISA STIG WN11-AU-000050.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Output "Configuring 'Audit Process Creation' to Success..."

# Enable Audit Process Creation (Success)
auditpol /set /subcategory:"Process Creation" /success:enable

# Verify configuration
Write-Output "Verifying configuration..."
$auditStatus = auditpol /get /subcategory:"Process Creation"

Write-Output $auditStatus

# Confirm compliance
if ($auditStatus -match "Success\s+Enabled") {
    Write-Output "SUCCESS: 'Audit Process Creation' is correctly configured."
} else {
    Write-Warning "WARNING: Configuration may not have applied correctly."
}

# STIG: WN11-AU-000050
# Requirement: Audit Process Creation must be enabled for Success
