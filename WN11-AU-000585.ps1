<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit command-line process creation events for failures by enabling Process Creation auditing and command-line logging.

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-21
    Last Modified   : 2025-12-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000585

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with administrative privileges to enable auditing of
    command-line process creation failures in compliance with DISA STIG
    requirements.
#>

# Enable Process Creation auditing (Failures)
auditpol /set /subcategory:"Process Creation" /failure:enable

# Enable command-line logging for process creation events
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$ValueName = "ProcessCreationIncludeCmdLine_Enabled"
$ValueData = 1

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set registry value
New-ItemProperty `
    -Path $RegPath `
    -Name $ValueName `
    -PropertyType DWord `
    -Value $ValueData `
    -Force | Out-Null

# STIG: WN11-AU-000585
# Requirement: Command-line process creation auditing must be enabled for failures
