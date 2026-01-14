<#
.Description: Creates a .zip file containing all browser extensions folders for Chrome, Firefox, and Edge.
.Documentation: -
.Required Permissions: User
.Example:
    .\ExportBrowserExtensions.ps1
.Example Live Response:
    run ExportBrowserExtensions.ps1
#>

function Compress-ToZip {
    param (
        [string]$SourcePath,
        [string]$DestinationZip
    )
    if (Test-Path $SourcePath) {
        Compress-Archive -Path $SourcePath -DestinationPath $DestinationZip -Force
    } else {
        Write-Host "The folder $SourcePath does not exist." -ForegroundColor Red
    }
}

$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
$firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

$tempFolder = "$env:TEMP\BrowserExtensions"
if (Test-Path $tempFolder) {
    Remove-Item -Recurse -Force $tempFolder
}
New-Item -ItemType Directory -Path $tempFolder

if (Test-Path $chromePath) {
    Copy-Item -Path $chromePath -Destination (Join-Path $tempFolder "Chrome") -Recurse
}

if (Test-Path $firefoxProfilesPath) {
    Get-ChildItem $firefoxProfilesPath -Directory | ForEach-Object {
        $extensionsPath = Join-Path $_.FullName "extensions"
        if (Test-Path $extensionsPath) {
            $destinationPath = Join-Path $tempFolder "Firefox_$($_.Name)"
            Copy-Item -Path $extensionsPath -Destination $destinationPath -Recurse
        }
    }
}

if (Test-Path $edgePath) {
    Copy-Item -Path $edgePath -Destination (Join-Path $tempFolder "Edge") -Recurse
}

$zipFilePath = "$PWD\BrowserExtensionExport.zip"
Compress-ToZip -SourcePath $tempFolder -DestinationZip $zipFilePath

Remove-Item -Recurse -Force $tempFolder

Write-Host "Browser extensions have been exported to $zipFilePath." -ForegroundColor Green