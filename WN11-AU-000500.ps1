<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Marlee Teteh
    LinkedIn        : linkedin.com/in/marlee-teteh
    GitHub          : github.com/MallouMerc24
    Date Created    : 2025-12-21
    Last Modified   : 2025-12-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Execute with administrative privileges to remediate DISA STIG
    WN11-AU-000585 on Windows 11 systems
#>

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Eventlog\Application"
$ValueName = "MaxSize"
$ValueData = 0x8000  # 32768 KB

# Ensure the registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the MaxSize DWORD
New-ItemProperty `
    -Path $RegPath `
    -Name $ValueName `
    -PropertyType DWord `
    -Value $ValueData `
    -Force | Out-Null

# Verify the setting
Get-ItemProperty -Path $RegPath -Name $ValueName

# STIG: WN11-AU-000500
# Requirement: Application Event Log MaxSize >= 32768 KB (0x8000)
