<#
.Description: Lists the Name, CreationTime and LastAccessTime of the Prefetch files
.Documentation: -
.Required Permissions: User
#>

$PrefetchFolder = Get-Item 'C:\Windows\Prefetch'

#Collect Prefetch Files
$files = Get-ChildItem -Path $PrefetchFolder -File

$results = $files | ForEach-Object {
    [PSCustomObject]@{
        Filename       = $_.Name
        CreationTime   = $_.CreationTime
        LastAccessTime = $_.LastAccessTime
    }
}

# Output the results in a table format
$results | Format-Table -AutoSize