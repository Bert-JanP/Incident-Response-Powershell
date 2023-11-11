Write-Host "List ExclusionPaths:"
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Write-Host "List ExclusionExtensions:"
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
Write-Host "List ExclusionIpAddresses:"
Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress
Write-Host "List ExclusionProcesses:"
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess