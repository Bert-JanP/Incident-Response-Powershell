# Uploads the current directory contents to a storage blob container

# If 'PublicAccessNotPermittedPublic access is not permitted on this storage account error' is thrown have a look at:
# https://techcommunity.microsoft.com/blog/azurepaasblog/public-access-is-not-permitted-on-this-storage-account/3521288

# Variables
$StorageAccountName = '<StorageAcountName>'
$ContainerName = '<ContainerName>'
$sasToken = 'sp=racwd&st=2024-12-23T16:41:05Z&se=2024-12-24T00:41:05Z&spr=https&sv=2022-11-02&sr=c&sig=DVNEMY%2Xuo%2BXRV3s3hQYKxR%2B4jhbXXXZIyBXyg7kiik8%3R'

$currentFolder = Get-Location 
Write-Host "Current folder: $currentFolder" -ForegroundColor Green
Write-Host "Uploading Files to $StorageAccountLink..." -ForegroundColor Green

$headers = @{ "x-ms-blob-type" = "BlockBlob"; "x-ms-date" = "$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")"}

# Upload Files from current dir to Azure blob storage
Get-ChildItem -File | ForEach-Object {
    $FileName = $_
    $uri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/" + $FileName + "?$sasToken"
    Invoke-RestMethod -Method "PUT" -Headers $headers -Uri $uri -InFile ".\$FileName"
    Write-Host "Uploaded $_.FullName to StorageAccount..." -ForegroundColor Green
}