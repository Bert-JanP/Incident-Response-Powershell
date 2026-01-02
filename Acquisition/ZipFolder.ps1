<#
.Description: Compresses a folder to a .zip file to easily obtain the contents of the folder.
.Documentation: -
.Required Permissions: User

.Example:
    .\ZipFolder.ps1 -FolderPath "C:\Path\To\Your\Folder"
.Example Live Response:
    run ZipFolder.ps1 -parameters "-FolderPath C:\Users\Public"
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$FolderPath
)

if (-Not (Test-Path -Path $FolderPath -PathType Container)) {
    Write-Host "Error: Folder '$FolderPath' does not exist." -ForegroundColor Red
    exit 1
}

$Timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$ZipFile = "$FolderPath`_$Timestamp.zip"

try {
    Compress-Archive -Path $FolderPath -DestinationPath $ZipFile
    Write-Host "Folder '$FolderPath' has been successfully zipped to '$ZipFile'." -ForegroundColor Green
} catch {
    Write-Host "An error occurred while zipping the folder: $_" -ForegroundColor Red
    exit 1
}