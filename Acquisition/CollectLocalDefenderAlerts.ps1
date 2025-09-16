<#
.Description: Collects the alerts from the local security center
.Documentation: -
.Required Permissions: User
#>


$Alerts = Get-MpThreatDetection | measure
if($Alerts.Count -ne 0){
    Write-Host $Alerts.Count alerts triggered. -ForegroundColor Red
    Write-Host Details: -ForegroundColor Red
    Get-MpThreatDetection
}
else {
    Write-Host No alerts triggered. -ForegroundColor Green
}