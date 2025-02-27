<#
.Description: Returns all Plug and Play devices
.Documentation: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-plug-and-play
.Required Permissions: User
#>


$deviceClasses = @(
    'Net',
    'USB',
    'Volume',
    'Printer',
    'HIDClass'
)

$currentDate = Get-Date -Format "yyyy-MM-dd"

foreach ($class in $deviceClasses) {
    $outputFileName = "$class Devices - $currentDate.txt"
    $outputPath = Join-Path -Path . -ChildPath $outputFileName

    Write-Host "Collecting devices in $class class. Saving results to $outputFileName..."
    
    $deviceInfo = Get-PnpDevice -Class $class | ForEach-Object {
        "Device ID: $($_.InstanceId)"
        "Device Description: $($_.Description)"
        "Device Status: $($_.Status)"
        "-------------------"
    }

    $deviceInfo | Out-File -FilePath $outputPath
    Write-Host "Results saved to $outputPath"
}
