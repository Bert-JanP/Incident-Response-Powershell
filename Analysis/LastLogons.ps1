# !!!!!!
# You need to run this script as administrator in order to get results.
# Define the number of last logons to retrieve
$numberOfLogons = 10

$logonEvents = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4624 or EventID=4648]]" | Select-Object -First $numberOfLogons

foreach ($logonEvent in $logonEvents) {
    $time = $logonEvent.TimeCreated
    $message = $logonEvent.Message
    $logonType = if ($logonEvent.Id -eq 4648) { "Explicit" } else { "Interactive" }

    Write-Host "Time: $time"
    Write-Host "Logon Type: $logonType"
    Write-Host "Message:"
    Write-Host $message
	Write-Host "------------------------"
	
}

# Note: This script retrieves logon events from the 'Security' log and filters by Event ID 4624 (successful logon) and 4648 (explicit logon).
