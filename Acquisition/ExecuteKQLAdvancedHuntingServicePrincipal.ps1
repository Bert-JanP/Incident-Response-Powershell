<#
.Description: Runs a KQL Advanced Hunting query using PowerShell and Service Principals.
.Documentation: https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0&tabs=powershell
.Required Permissions: ThreatHunting.Read.All
#>

# Set Service Principal Variables
$AppID = "<AppID>"
$TenantID = "<TentantID>"
$Secret = "<Secret>" #Certificate Authentication is recommended.
$SecureClientSecret = ConvertTo-SecureString -String $Secret -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AppID, $SecureClientSecret


# Set the query you want to execute
$KQL = 'DeviceEvents | where ActionType startswith "asr" | project Timestamp, DeviceName, ActionType | take 50'

Import-Module Microsoft.Graph.Security

Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome

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