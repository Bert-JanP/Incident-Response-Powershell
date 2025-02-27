<#
.Description: Lists the Windows Run executions of the current user.
.Documentation: -
.Required Permissions: User
#>


$MRUEntries = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
$MRUEntries.PSObject.Properties | Where-Object { $_.Name -ne "MRUList" } | Select-Object Name, Value | Format-Table -AutoSize