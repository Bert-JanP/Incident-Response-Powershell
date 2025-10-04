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

$rows = @($Results.Results)
$allKeys = $rows | ForEach-Object { $_.AdditionalProperties.Keys } | Select-Object -Unique

$table = @()
foreach ($row in $rows) {
    $obj = New-Object PSObject
    foreach ($key in $allKeys) {
        $value = $row.AdditionalProperties[$key]
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            $obj | Add-Member -NotePropertyName $key -NotePropertyValue ($value -join ", ")
        } else {
            $obj | Add-Member -NotePropertyName $key -NotePropertyValue $value
        }
    }
    $table += $obj
}
$table | Format-Table -Property $allKeys -AutoSize
#Export to csv
# $table | Export-CSV .\QueryExport.csv -NoTypeInformation