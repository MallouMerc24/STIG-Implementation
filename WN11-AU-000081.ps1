<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit
    failed File Share access events by enabling the Advanced Audit Policy
    setting for "Audit File Share" failures in compliance with DISA STIG
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
    STIG-ID         : WN11-AU-000081

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with administrative privileges to enable auditing of
    failed File Share access events ("Audit File Share" = Failure) as
    required by DISA STIG WN11-AU-000081.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Output "Configuring 'Audit File Share' to Failure..."

# Enable Audit File Share (Failure)
auditpol /set /subcategory:"File Share" /failure:enable

# Verify configuration
Write-Output "Verifying configuration..."
$auditStatus = auditpol /get /subcategory:"File Share"

Write-Output $auditStatus

# Confirm compliance
if ($auditStatus -match "Failure\s+Enabled") {
    Write-Output "SUCCESS: 'Audit File Share' failures are correctly configured."
} else {
    Write-Warning "WARNING: Configuration may not have applied correctly."
}

# STIG: WN11-AU-000081
# Requirement: Audit File Share must be enabled for Failure
