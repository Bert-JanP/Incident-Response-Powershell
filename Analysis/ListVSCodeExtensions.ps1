<#
.Description: Lists all installed Visual Studio Code extensions and their versions.
.Documentation:
    - https://code.visualstudio.com/docs/configure/extensions/extension-marketplace
.Required Permissions: User, Administrator when using -AllUsers
.Example:
    .\ListVSCodeExtensions.ps1 -Username "JohnDoe"
    .\ListVSCodeExtensions.ps1 -AllUsers
#>

param (
    [String]$Username,
    [Switch]$AllUsers
)

function Get-ExtensionInfoFromFolder {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExtensionsPath,
        [Parameter(Mandatory = $true)]
        [string]$Product,
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $results = @()

    if (-not (Test-Path $ExtensionsPath)) {
        return $results
    }

    Get-ChildItem -Path $ExtensionsPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extensionFolder = $_

        # Skip hidden/system folders that are not extension packages.
        if ($extensionFolder.Name -like ".*") {
            return
        }

        $packageJsonPath = Join-Path $extensionFolder.FullName "package.json"
        $extensionId = $null
        $version = $null

        if (Test-Path $packageJsonPath) {
            try {
                $packageJson = Get-Content -Path $packageJsonPath -Raw | ConvertFrom-Json
                if ($packageJson.publisher -and $packageJson.name) {
                    $extensionId = "$($packageJson.publisher).$($packageJson.name)"
                }
                $version = $packageJson.version
            } catch {
                # Ignore malformed package.json and fall back to folder-name parsing.
            }
        }

        if (-not $extensionId -or -not $version) {
            if ($extensionFolder.Name -match "^(?<ExtensionId>.+)-(?<Version>\d+\.\d+\.\d+.*)$") {
                if (-not $extensionId) {
                    $extensionId = $Matches.ExtensionId
                }
                if (-not $version) {
                    $version = $Matches.Version
                }
            }
        }

        if ($extensionId) {
            $results += [PSCustomObject]@{
                User        = $UserName
                Product     = $Product
                ExtensionId = $extensionId
                Version     = $version
                Source      = "Folder"
                Path        = $extensionFolder.FullName
            }
        }
    }

    return $results
}

function Get-ExtensionInfoFromJson {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExtensionsJsonPath,
        [Parameter(Mandatory = $true)]
        [string]$Product,
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $results = @()

    if (-not (Test-Path $ExtensionsJsonPath)) {
        return $results
    }

    try {
        $jsonContent = Get-Content -Path $ExtensionsJsonPath -Raw | ConvertFrom-Json
    } catch {
        return $results
    }

    $entries = @()

    if ($jsonContent -is [System.Array]) {
        $entries = $jsonContent
    } elseif ($jsonContent.PSObject.Properties.Name -contains "extensions") {
        $entries = $jsonContent.extensions
    }

    foreach ($entry in $entries) {
        $extensionId = $null
        $version = $null
        $extensionPath = $null

        if ($entry.identifier) {
            if ($entry.identifier.id) {
                $extensionId = $entry.identifier.id
            } elseif ($entry.identifier -is [string]) {
                $extensionId = $entry.identifier
            }
        } elseif ($entry.id) {
            $extensionId = $entry.id
        }

        if ($entry.version) {
            $version = $entry.version
        }

        if ($entry.location) {
            if ($entry.location.fsPath) {
                $extensionPath = $entry.location.fsPath
            } elseif ($entry.location.path) {
                $extensionPath = $entry.location.path
            }
        }

        if ($extensionId) {
            $results += [PSCustomObject]@{
                User        = $UserName
                Product     = $Product
                ExtensionId = $extensionId
                Version     = $version
                Source      = "extensions.json"
                Path        = $extensionPath
            }
        }
    }

    return $results
}

Write-Host "Collecting Visual Studio Code Extensions`n" -ForegroundColor Blue

$allExtensions = @()

if ($AllUsers) {
    $userDirs = Get-ChildItem "C:\Users" -Directory | Where-Object { Test-Path "$($_.FullName)\AppData\Roaming" }
} elseif ($Username) {
    $userDir = "C:\Users\$Username"
    if (-Not (Test-Path "$userDir\AppData\Roaming")) {
        Write-Warning "User profile for '$Username' not found or AppData\Roaming doesn't exist."
        return
    }
    $userDirs = @([IO.DirectoryInfo]::new($userDir))
} else {
    Write-Warning "Please specify either -Username or -AllUsers"
    return
}

foreach ($userDir in $userDirs) {
    $currentUserName = $userDir.Name

    $vscodeExtensionsPath = Join-Path $userDir.FullName ".vscode\extensions"
    $vscodeJsonPath = Join-Path $userDir.FullName "AppData\Roaming\Code\User\extensions\extensions.json"

    $insidersExtensionsPath = Join-Path $userDir.FullName ".vscode-insiders\extensions"
    $insidersJsonPath = Join-Path $userDir.FullName "AppData\Roaming\Code - Insiders\User\extensions\extensions.json"

    $allExtensions += Get-ExtensionInfoFromFolder -ExtensionsPath $vscodeExtensionsPath -Product "VS Code" -UserName $currentUserName
    $allExtensions += Get-ExtensionInfoFromJson -ExtensionsJsonPath $vscodeJsonPath -Product "VS Code" -UserName $currentUserName

    $allExtensions += Get-ExtensionInfoFromFolder -ExtensionsPath $insidersExtensionsPath -Product "VS Code Insiders" -UserName $currentUserName
    $allExtensions += Get-ExtensionInfoFromJson -ExtensionsJsonPath $insidersJsonPath -Product "VS Code Insiders" -UserName $currentUserName
}

$uniqueExtensions = $allExtensions |
    Sort-Object -Property User, Product, ExtensionId, Version, Path -Unique |
    Sort-Object -Property User, Product, ExtensionId

if (-not $uniqueExtensions -or $uniqueExtensions.Count -eq 0) {
    Write-Host "No Visual Studio Code extensions found." -ForegroundColor Blue
} else {
    $uniqueExtensions | Format-Table User, Product, ExtensionId, Version, Source, Path -AutoSize
}
