<#
.Description: Returns the last logins based on Event ID 4624 (successful logon) and 4648 (explicit logon).
.Documentation:
	- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
	- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648
.Required Permissions: Administrator
#>

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
