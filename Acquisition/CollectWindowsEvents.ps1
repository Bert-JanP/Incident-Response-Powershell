<#
.Description: Collects the application, system and security events from a device.
.Documentation: -
.Required Permissions: Administrator
#>

$ExecutionDate = $(get-date -f yyyy-MM-dd)
$OutputName = "WindowsEvents-$ExecutionDate.csv"
# Initialize an empty array to store event log entries
$logEntries = @()

$eventLogs = 'Application', 'System', 'Security'

# Iterate through each event log
foreach ($logName in $eventLogs) {
    # Get event log entries for the specified log name
    $entries = Get-EventLog -LogName $logName

    # Append entries to the logEntries array
    $logEntries += $entries
}

# Export the event log entries to a CSV file
$logEntries | Export-Csv -Path $OutputName -NoTypeInformation
if (Test-Path -Path $OutputName) {
    $folderPath = (Get-Item $OutputName).DirectoryName
    Write-Host "Output File Location: $folderPath\$OutputName"
} else {
    Write-Host "File does not exist."
}
