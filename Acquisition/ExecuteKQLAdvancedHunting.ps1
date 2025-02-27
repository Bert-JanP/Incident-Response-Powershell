<#
.Description: Runs a KQL Advanced Hunting query using PowerShell.
.Documentation: https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0&tabs=powershell
.Required Permissions: ThreatHunting.Read.All
#>

# Set the query you want to execute
$KQL = 'DeviceEvents | where ActionType startswith "asr" | project Timestamp, DeviceName, ActionType | take 50'

Import-Module Microsoft.Graph.Security

Connect-MgGraph -Scopes ThreatHunting.Read.All -NoWelcome

$params = @{
	Query = $KQL
    Timespan = "P180D"
}

$Results = Start-MgSecurityHuntingQuery -BodyParameter $params

$Results.Results

$Results.Results | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.AdditionalProperties["Timestamp"]
        DeviceName = $_.AdditionalProperties["DeviceName"]
        ActionType = $_.AdditionalProperties["ActionType"]
        # Add other properties as needed
    }
} | Format-Table -AutoSize