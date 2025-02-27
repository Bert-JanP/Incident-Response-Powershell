<#
.Description: Resets the active sessions of all users in the defined list.
.Documentation: https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0&tabs=http
.Required Permissions: User.RevokeSessions.All	
#>

Connect-MgGraph -Scopes User.RevokeSessions.All	

Import-Module Microsoft.Graph.Users.Actions

# List of UPNs that need to be revoked.

$users = ('user1@kqlquery.com', 'user2@kqlquery.com')

Write-Output "Start revoking sessions..."

# Revoke user sessions
foreach ($user in $users) {
    $result = Revoke-MgUserSignInSession -UserId $user
    if ($result) {
        Write-Host "Successfully revoked sessions for $user" -ForegroundColor Green
    } else {
        Write-Host "Failed to revoke sessions for $user" -ForegroundColor Red
    }
}