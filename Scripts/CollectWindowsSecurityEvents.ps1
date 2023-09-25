$ExecutionDate = $(get-date -f yyyy-MM-dd)
$OutputName = "SecurityEvents-$ExecutionDate.csv"
Get-EventLog -LogName Security | Export-Csv -Path $OutputName -NoTypeInformation
if (Test-Path -Path $OutputName) {
    $folderPath = (Get-Item $OutputName).DirectoryName
    Write-Host "Output File Location: $folderPath\$OutputName"
} else {
    Write-Host "File does not exist."
}