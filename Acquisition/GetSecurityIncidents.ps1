Import-Module Microsoft.Graph.Security

Connect-MgGraph -Scopes SecurityIncident.Read.All

# Retrieve new and active incidents
$incidents = Get-MgSecurityIncident -All -Filter "status ne 'resolved'"

# Write the output to a CSV file 
$incidents | Export-Csv -Path "SecurityIncidents.csv" -NoTypeInformation 
Write-Host "Filtered security incidents have been exported to SecurityIncidents.csv" -ForegroundColor Green