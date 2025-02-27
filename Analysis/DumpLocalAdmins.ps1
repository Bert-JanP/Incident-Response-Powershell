$admins = Get-LocalGroupMember -Group Administrators
Write-Host "Local Administrators on this device:"
foreach ($admin in $admins) {
    Write-Host $admin.Name
}