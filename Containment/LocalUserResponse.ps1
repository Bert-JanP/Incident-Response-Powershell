<#
.Description: Response to local user accounts - list all accounts with admin status, rotate passwords, kill processes, or delete accounts.
.Documentation: -
.Required Permissions: Administrator

.Example:
    .\LocalUserResponse.ps1 -List
.Example:
    .\LocalUserResponse.ps1 -Rotate "S-1-5-21-1234567890-1234567890-1234567890-1001"
.Example:
    .\LocalUserResponse.ps1 -Delete "S-1-5-21-1234567890-1234567890-1234567890-1001"
.Example:
    .\LocalUserResponse.ps1 -Kill "S-1-5-21-1234567890-1234567890-1234567890-1001"
.Example Live Response:
    run LocalUserResponse.ps1 -parameters "-List"
    run LocalUserResponse.ps1 -parameters "-Rotate S-1-5-21-1234567890-1234567890-1234567890-1001"
    run LocalUserResponse.ps1 -parameters "-Kill S-1-5-21-1234567890-1234567890-1234567890-1001"
    run LocalUserResponse.ps1 -parameters "-Delete S-1-5-21-1234567890-1234567890-1234567890-1001"
#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$List,
    
    [Parameter(Mandatory = $false)]
    [string]$Rotate,
    
    [Parameter(Mandatory = $false)]
    [string]$Delete,
    
    [Parameter(Mandatory = $false)]
    [string]$Kill
)

# Function to generate a random 20-character password
function New-RandomPassword {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    $password = -join (1..20 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $password
}

# Function to get local users
function Get-LocalUsers {
    $users = Get-LocalUser
    $admins = (Get-LocalGroupMember -Group Administrators).Name
    return @($users, $admins)
}

# Function to check if a user is an administrator
function Test-IsAdmin {
    param([string]$Username, [array]$AdminNames)
    foreach ($admin in $AdminNames) {
        if ($admin -like "*$Username") {
            return $true
        }
    }
    return $false
}

# List all local accounts
if ($List) {
    Write-Host "Listing all local accounts on this device..." -ForegroundColor Cyan
    Write-Host ""
    
    $result = Get-LocalUsers
    $users = $result[0]
    $admins = $result[1]
    
    Write-Host "ADMINISTRATORS:" -ForegroundColor Yellow
    Write-Host ("=" * 80)
    foreach ($user in $users) {
        if (Test-IsAdmin $user.Name $admins) {
            Write-Host "SID: $($user.SID)" -ForegroundColor Green
            Write-Host "Name: $($user.Name)" -ForegroundColor Green
            Write-Host ""
        }
    }
    
    Write-Host "NON-ADMINISTRATORS:" -ForegroundColor Yellow
    Write-Host ("=" * 80)
    foreach ($user in $users) {
        if (-Not (Test-IsAdmin $user.Name $admins)) {
            Write-Host "SID: $($user.SID)" -ForegroundColor White
            Write-Host "Name: $($user.Name)" -ForegroundColor White
            Write-Host ""
        }
    }
}

# Rotate password for a user
elseif ($Rotate) {
    Write-Host "Rotating password for user with SID: $Rotate" -ForegroundColor Cyan
    
    try {
        $user = Get-LocalUser | Where-Object { $_.SID -eq $Rotate }
        
        if ($null -eq $user) {
            Write-Host "Error: User with SID '$Rotate' not found." -ForegroundColor Red
            exit 1
        }
        
        $newPassword = New-RandomPassword
        $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
        
        Set-LocalUser -SID $Rotate -Password $securePassword
        
        Write-Host "Successfully rotated password for user: $($user.Name)" -ForegroundColor Green
        Write-Host "New Password: $newPassword" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Error rotating password: $_" -ForegroundColor Red
        exit 1
    }
}

# Delete a local account
elseif ($Delete) {
    Write-Host "Deleting user with SID: $Delete" -ForegroundColor Cyan
    
    try {
        $user = Get-LocalUser | Where-Object { $_.SID -eq $Delete }
        
        if ($null -eq $user) {
            Write-Host "Error: User with SID '$Delete' not found." -ForegroundColor Red
            exit 1
        }
        
        # Prevent deletion of critical system accounts
        $criticalAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
        if ($user.Name -in $criticalAccounts) {
            Write-Host "Error: Cannot delete critical system account '$($user.Name)'." -ForegroundColor Red
            exit 1
        }
        
        Remove-LocalUser -SID $Delete
        
        Write-Host "Successfully deleted user: $($user.Name)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error deleting user: $_" -ForegroundColor Red
        exit 1
    }
}

# Kill all processes running under a user
elseif ($Kill) {
    Write-Host "Killing all processes running under user SID: $Kill" -ForegroundColor Cyan
    
    try {
        $user = Get-LocalUser | Where-Object { $_.SID -eq $Kill }
        
        if ($null -eq $user) {
            Write-Host "Error: User with SID '$Kill' not found." -ForegroundColor Red
            exit 1
        }
        
        $username = $user.Name

        $processes = @()
        $allProcesses = Get-CimInstance -ClassName Win32_Process
        foreach ($process in $allProcesses) {
            try {
                $ownerSidResult = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
                if ($ownerSidResult.Sid -eq $Kill) {
                    $processes += $process
                }
            }
            catch {
                # Some system processes may not return owner details; ignore and continue.
            }
        }
        
        if ($processes.Count -eq 0) {
            Write-Host "No processes found running under user: $username" -ForegroundColor Yellow
            exit 0
        }
        
        $killCount = 0
        foreach ($process in $processes) {
            try {
                Stop-Process -Id $process.ProcessId -Force
                Write-Host "Killed process: $($process.Name) (PID: $($process.ProcessId))" -ForegroundColor Green
                $killCount++
            }
            catch {
                Write-Host "Failed to kill process $($process.Name) (PID: $($process.ProcessId)): $_" -ForegroundColor Red
            }
        }
        
        Write-Host "Successfully killed $killCount process(es) running under user: $username" -ForegroundColor Green
    }
    catch {
        Write-Host "Error killing processes: $_" -ForegroundColor Red
        exit 1
    }
}

else {
    Write-Host "No operation specified. Use one of the following parameters:" -ForegroundColor Yellow
    Write-Host "  -List              : List all local accounts" -ForegroundColor White
    Write-Host "  -Rotate <SID>      : Rotate password for a user" -ForegroundColor White
    Write-Host "  -Delete <SID>      : Delete a local account" -ForegroundColor White
    Write-Host "  -Kill <SID>        : Kill all processes running under a user" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\LocalUserResponse.ps1 -List" -ForegroundColor White
    Write-Host "  .\LocalUserResponse.ps1 -Rotate `"S-1-5-21-1234567890-1234567890-1234567890-1001`"" -ForegroundColor White
    Write-Host "  .\LocalUserResponse.ps1 -Delete `"S-1-5-21-1234567890-1234567890-1234567890-1001`"" -ForegroundColor White
    Write-Host "  .\LocalUserResponse.ps1 -Kill `"S-1-5-21-1234567890-1234567890-1234567890-1001`"" -ForegroundColor White
}
