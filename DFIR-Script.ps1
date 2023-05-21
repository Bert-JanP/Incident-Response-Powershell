$ASCIIBanner = @"
  _____                                           _              _   _     _____    ______   _____   _____  
 |  __ \                                         | |            | | | |   |  __ \  |  ____| |_   _| |  __ \ 
 | |__) |   ___   __      __   ___   _ __   ___  | |__     ___  | | | |   | |  | | | |__      | |   | |__) |
 |  ___/   / _ \  \ \ /\ / /  / _ \ | '__| / __| | '_ \   / _ \ | | | |   | |  | | |  __|     | |   |  _  / 
 | |      | (_) |  \ V  V /  |  __/ | |    \__ \ | | | | |  __/ | | | |   | |__| | | |       _| |_  | | \ \ 
 |_|       \___/    \_/\_/    \___| |_|    |___/ |_| |_|  \___| |_| |_|   |_____/  |_|      |_____| |_|  \_\
"@
Write-Host $ASCIIBanner
Write-Host "`n"
Write-Host "By twitter: @BertJanCyber, Github: Bert-JanP"
Write-Host "===========================================`n"

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "DFIR Session starting as Administrator..."
}
else {
    Write-Host "No Administrator session detected. For the best performance run as Administrator. Not all items can be collected..."
    Write-Host "DFIR Session starting..."
}

Write-Host "Creating output directory..."
$CurrentPath = Get-Location
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$FolderCreation = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
mkdir -Force $FolderCreation | Out-Null
Write-Host "Output directory created: $FolderCreation..."

function Get-IPInfo {
    Write-Host "Collecting local ip info..."
    $Ipinfoutput = "$FolderCreation\ipinfo.txt"
    Get-NetIPAddress | Out-File -Force -FilePath $Ipinfoutput
}
function Get-ShadowCopies {
    Write-Host "Collecting Shadow Copies..."
    $ShadowCopy = "$FolderCreation\ShadowCopies.txt"
    Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ShadowCopy
}

function Get-OpenConnections {
    Write-Host "Collecting Open Connections..."
    $ConnectionFolder = "$FolderCreation\Connections"
    mkdir -Force $ConnectionFolder | Out-Null
    $Ipinfoutput = "$ConnectionFolder\OpenConnections.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $Ipinfoutput
}

function Get-AutoRunInfo {
    Write-Host "Collecting AutoRun info..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    mkdir -Force $AutoRunFolder | Out-Null
    $RegKeyOutput = "$AutoRunFolder\AutoRunInfo.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $RegKeyOutput
}

function Get-InstalledDrivers {
    Write-Host "Collecting Installed Drivers..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    $RegKeyOutput = "$AutoRunFolder\InstalledDrivers.txt"
    driverquery | Out-File -Force -FilePath $RegKeyOutput
}

function Get-ActiveUsers {
    Write-Host "Collecting Active users..."
    $UserFolder = "$FolderCreation\UserInformation"
    mkdir -Force $UserFolder | Out-Null
    $ActiveUserOutput = "$UserFolder\ActiveUsers.txt"
    query user /server:$server | Out-File -Force -FilePath $ActiveUserOutput
}

function Get-LocalUsers {
    Write-Host "Collecting Local users..."
    $UserFolder = "$FolderCreation\UserInformation"
    $ActiveUserOutput = "$UserFolder\LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
}

function Get-ActiveProcesses {
    Write-Host "Collecting Active Processes..."
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($process.ExecutablePath -ne $null)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
}

function Get-SecurityEventCount {
    Write-Host "Collecting stats Security Events last 48 hours..."
    $SecurityEvents = "$FolderCreation\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\EventCount.txt"
    $SecurirtyEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-2)
    $SecurirtyEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
}

function Get-SecurityEvents {
    Write-Host "Collecting Security Events last 48 hours..."
    $SecurityEvents = "$FolderCreation\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\SecurityEvents.txt"
    get-eventlog security -After (Get-Date).AddDays(-2) | Format-List * | Out-File -Force -FilePath $ProcessOutput
}
function Get-OfficeConnections {
    Write-Host "Collecting connections made from office applciations..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $OfficeConnection = "$ConnectionFolder\ConnectionsMadeByOffice.txt"
    Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache* -erroraction 'silentlycontinue' | Out-File -Force -FilePath $OfficeConnection 
}

function Get-NetworkShares {
    Write-Host "Collecting Active Network Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\NetworkShares.txt"
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Format-Table | Out-File -Force -FilePath $ProcessOutput
}

function Get-SMBShares {
    Write-Host "Collecting SMB Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\SMBShares.txt"
    Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
}

function Get-RDPSessions {
    Write-Host "Collecting RDS Sessions..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RDPSessions.txt"
    qwinsta /server:localhost | Out-File -Force -FilePath $ProcessOutput
}

function Get-RemotelyOpenedFiles {
    Write-Host "Collecting Remotly Opened Files..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\RemotelyOpenedFiles.txt"
    openfiles | Out-File -Force -FilePath $ProcessOutput
}

function Get-DNSCache {
    Write-Host "Collecting DNS Cache..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
}

function Get-PowershellHistory {
    Write-Host "Collecting Powershell History..."
    $PowershellHistoryOutput = "$FolderCreation\PowershellHistory.txt"
    history | Out-File -Force -FilePath $PowershellHistoryOutput
}

function Get-RecentlyInstalledSoftwareEventLogs {
    Write-Host "Collecting Recently Installed Software EventLogs..."
    $ApplicationFolder = "$FolderCreation\Applications"
    mkdir -Force $ApplicationFolder | Out-Null
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *| Out-File -Force -FilePath $ProcessOutput
}

function Get-RunningServices {
    Write-Host "Collecting Running Services..."
    $ApplicationFolder = "$FolderCreation\Applications"
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-Service | Where-Object {$_.Status -eq "Running"} | format-list | Out-File -Force -FilePath $ProcessOutput
}

function Get-ScheduledTasks {
    Write-Host "Collecting Scheduled Tasks..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    mkdir -Force $ScheduledTaskFolder| Out-Null
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksList.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List | Out-File -Force -FilePath $ProcessOutput
}

function Get-ScheduledTasksRunInfo {
    Write-Host "Collecting Scheduled Tasks Run Info..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksListRunInfo.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
}

function Get-USBConnections {
    Write-Host "Collecting USB Connections..."
    $ProcessFolder = "$FolderCreation\USBInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $USBConnectionsOutput = "$ProcessFolder\USBConnections.csv"

    (Get-WmiObject -Class Win32_USBControllerDevice | Select-Object -Property Antecedent, Dependent -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $USBConnectionsOutput
}


function Zip-Results {
    Write-Host "Write results to $FolderCreation.zip..."
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
}

#Run all functions that do not require admin priviliges
function Run-WithoutAdminPrivilege {
    Get-IPInfo
    Get-OpenConnections
    Get-AutoRunInfo
    Get-ActiveUsers
    Get-LocalUsers
    Get-ActiveProcesses
    Get-OfficeConnections
    Get-NetworkShares
    Get-SMBShares
    Get-RDPSessions
    Get-PowershellHistory
    Get-DNSCache
    Get-InstalledDrivers    
    Get-RecentlyInstalledSoftwareEventLogs
    Get-RunningServices
    Get-ScheduledTasks
    Get-ScheduledTasksRunInfo
    Get-USBConnections
}

#Run all functions that do require admin priviliges
Function Run-WithAdminPrivilges {
    Get-SecurityEventCount
    Get-SecurityEvents
    Get-RemotelyOpenedFiles
    Get-ShadowCopies
}

if ($IsAdmin) {
    Run-WithoutAdminPrivilege
    Run-WithAdminPrivilges
}
else {
    Run-WithoutAdminPrivilege
}

Zip-Results

