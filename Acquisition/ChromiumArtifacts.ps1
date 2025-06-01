<#
.Description: Collects Chromium Logs for Browser Forensics.
.Recommended to use https://github.com/sqlitebrowser/sqlitebrowser to view exported SQLite Database files
.Documentation: -
.Required Permissions: Administrator

.Example:
    .\ChromiumArtifacts.ps1 -Username "JohnDoe"
    .\ChromiumArtifacts.ps1 -Username "JohnDoe" -CollectAllArtifacts
    .\ChromiumArtifacts.ps1 -AllUsers
    .\ChromiumArtifacts.ps1 -AllUsers -CollectAllArtifacts
.Credits: Continued Development based on initial commit of https://github.com/flimbot & https://github.com/Bert-JanP/Incident-Response-Powershell/commit/cea7ad075b33c0003eeb3b181d2709a8e5fa7002
#>

param (
    [String]$Username,
    [Switch]$AllUsers,
    [Switch]$CollectAllArtifacts
)

$OutputDir = Join-Path -Path (Get-Location) -ChildPath "ChromiumBrowserArtifacts"
$HistoryFolder = Join-Path -Path $OutputDir -ChildPath "Browsers\Chromium"
New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

Write-Host "Collecting Chromium artifacts..."

$filesToCopy = @('Preferences', 'History')

if ($AllUsers) {
    $userDirs = Get-ChildItem "C:\Users" -Directory | Where-Object { Test-Path "$($_.FullName)\AppData\Local" }
} elseif ($Username) {
    $userDir = "C:\Users\$Username"
    if (-Not (Test-Path "$userDir\AppData\Local")) {
        Write-Warning "User profile for '$Username' not found or AppData\Local doesn't exist."
        return
    }
    $userDirs = @([IO.DirectoryInfo]::new($userDir))
} else {
    Write-Warning "Please specify either -Username or -AllUsers"
    return
}

foreach ($userDir in $userDirs) {
    $chromiumPaths = Get-ChildItem "$($userDir.FullName)\AppData\Local\*\*\User Data\*\" -Directory -ErrorAction SilentlyContinue

    foreach ($path in $chromiumPaths) {
        $historyFile = Join-Path -Path $path.FullName -ChildPath "History"
        if ((Test-Path $historyFile) -and (([char[]](Get-Content $historyFile -Encoding byte -TotalCount 15)) -join '' -like "SQLite format*")) {
            $relativePath = $path.FullName -replace "^C:\\Users\\", ""
            $destpath = Join-Path $HistoryFolder $relativePath
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null

            if ($CollectAllArtifacts) {
                Write-Host "Collecting ALL Chromium files from $($path.FullName)"
                Get-ChildItem -Path $path.FullName -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    $relFilePath = $_.FullName -replace [regex]::Escape($path.FullName), ""
                    $targetPath = Join-Path $destpath $relFilePath
                    New-Item -ItemType Directory -Path (Split-Path $targetPath) -Force | Out-Null
                    Copy-Item -Path $_.FullName -Destination $targetPath -Force
                }
            } else {
                foreach ($file in $filesToCopy) {
                    $sourceFile = Join-Path -Path $path.FullName -ChildPath $file
                    if (Test-Path $sourceFile) {
                        Copy-Item -Path $sourceFile -Destination (Join-Path $destpath $file) -Force
                    }
                }
            }
        }
    }
}

Write-Host "Chromium artifacts collection completed. Output folder: $OutputDir"
