<#
.Description: Lists all installed browser extensions from Chrome, Firefox, and Edge.
.Documentation: This script fetches installed browser extensions for the supported browsers and displays them in the terminal.
.Required Permissions: User
.Example:
    .\ListBrowserExtensions.ps1
#>

function Get-ChromeExtensions {
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromePath) {
        Write-Host "Chrome Extensions:" -ForegroundColor Blue
        Get-ChildItem $chromePath -Directory | ForEach-Object {
            Write-Host $_.Name
        }
    } else {
        Write-Host "Chrome is not installed or no extensions found." -ForegroundColor Blue
    }
}

function Get-FirefoxExtensions {
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Get-ChildItem $firefoxPath -Directory | ForEach-Object {
            $extensionsPath = Join-Path $_.FullName "extensions"
            if (Test-Path $extensionsPath) {
                Write-Host "Firefox Extensions for Profile $($_.Name):" -ForegroundColor Blue
                Get-ChildItem $extensionsPath -File | ForEach-Object {
                    Write-Host $_.Name
                }
            }
        }
    } else {
        Write-Host "Firefox is not installed or no extensions found." -ForegroundColor Blue
    }
}

function Get-EdgeExtensions {
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgePath) {
        Write-Host "Edge Extensions:" -ForegroundColor Blue
        Get-ChildItem $edgePath -Directory | ForEach-Object {
            # Exclude Temp folder
            if ($_.Name -eq "Temp"){
            }
            else {
                Write-Host $_.Name
            } 
            
        }
    } else {
        Write-Host "Edge is not installed or no extensions found." -ForegroundColor Blue
    }
}

Write-Host "Collecting Browser Extensions`n" -ForegroundColor Blue
Get-ChromeExtensions
Write-Host ""
Get-FirefoxExtensions
Write-Host ""
Get-EdgeExtensions