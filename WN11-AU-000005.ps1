<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit
    failed credential validation events by enabling the Advanced Audit Policy
    setting for "Audit Credential Validation" (Failure) in compliance with
    DISA STIG requirement WN11-AU-000005.

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-23
    Last Modified   : 2025-12-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run this script with administrative privileges to enable auditing of
    failed credential validation events ("Audit Credential Validation" = Failure)
    as required by DISA STIG WN11-AU-000005.
#>

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Output "Configuring 'Audit Credential Validation' to Failure..."

# Enable Audit Credential Validation (Failure)
auditpol /set /subcategory:"Credential Validation" /failure:enable

Write-Output "Verifying configuration..."

# Verify configuration
$auditStatus = auditpol /get /subcategory:"Credential Validation"

Write-Output $auditStatus

# Confirm compliance
if ($auditStatus -match "Failure\s+Enabled") {
    Write-Output "SUCCESS: 'Audit Credential Validation' (Failure) is correctly configured."
} else {
    Write-Warning "WARNING: Configuration may not have applied correctly."
}

# STIG: WN11-AU-000005
# Requirement: Audit Credential Validation must be enabled for Failure
