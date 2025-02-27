<#
.Description: Changes the users password with a new random password, this new password has to be changed on the first SignIn of the user.
.Documentation: https://learn.microsoft.com/en-us/graph/api/authenticationmethod-resetpassword?view=graph-rest-1.0&tabs=http
.Required Permissions: UserAuthenticationMethod.ReadWrite.All
#>

Connect-MgGraph -Scopes UserAuthenticationMethod.ReadWrite.All

Import-Module Microsoft.Graph.Users.Actions

# List of UPNs that need a password change

$users = ('user1@kqlquery.com', 'user2@kqlquery.com')

Write-Output "Start Force Password Change..."

# Force Password Change
foreach ($user in $users) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $randomString = -join ((1..30) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $method = Get-MgUserAuthenticationPasswordMethod -UserId $user
    Reset-MgUserAuthenticationMethodPassword -UserId $user -AuthenticationMethodId $method.id -NewPassword $randomString
    Write-Host "Set force Change Password Next SignIn for $user. Temporary password is set to $randomString" -ForegroundColor Green
}