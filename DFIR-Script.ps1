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
$CurrentPath = $pwd
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$FolderCreation = "$CurrentPath\..\DFIR-$env:computername-$ExecutionTime"
mkdir -Force $FolderCreation | Out-Null
Write-Host "Output directory created: $FolderCreation..."

$currentUsername = (Get-WmiObject Win32_Process -f 'Name="explorer.exe"').GetOwner().User
$currentUserSid = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match 'S-1-5-21-\d+-\d+\-\d+\-\d+$' -and $_.ProfileImagePath -match "\\$currentUsername$"} | ForEach-Object{$_.PSChildName}
Write-Host "Current user: $currentUsername $currentUserSid"

#CSV Output for import in SIEM
$CSVOutputFolder = "$FolderCreation\SIEMImport"
mkdir -Force $CSVOutputFolder | Out-Null
Write-Host "SIEM Export Output directory created: $CSVOutputFolder..."

function Get-IPInfo {
    Write-Host "Collecting local ip info..."
    $Ipinfoutput = "$FolderCreation\ipinfo.txt"
    Get-NetIPAddress | Out-File -Force -FilePath $Ipinfoutput
	$SIEMOutput = "$CSVOutputFolder\IPConfiguration.csv"
	Get-NetIPAddress | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}
function Get-ShadowCopies {
    Write-Host "Collecting Shadow Copies..."
    $ShadowCopy = "$FolderCreation\ShadowCopies.txt"
    Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ShadowCopy
	$SIEMOutput = "$CSVOutputFolder\ShadowCopy.csv"
	Get-CimInstance Win32_ShadowCopy | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-OpenConnections {
    Write-Host "Collecting Open Connections..."
    $ConnectionFolder = "$FolderCreation\Connections"
    mkdir -Force $ConnectionFolder | Out-Null
    $Ipinfoutput = "$ConnectionFolder\OpenConnections.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $Ipinfoutput
	$SIEMOutput = "$CSVOutputFolder\OpenTCPConnections.csv"
	Get-NetTCPConnection -State Established | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-AutoRunInfo {
    Write-Host "Collecting AutoRun info..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    mkdir -Force $AutoRunFolder | Out-Null
    $RegKeyOutput = "$AutoRunFolder\AutoRunInfo.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $RegKeyOutput
	$SIEMOutput = "$CSVOutputFolder\AutoRun.csv"
	Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-InstalledDrivers {
    Write-Host "Collecting Installed Drivers..."
    $AutoRunFolder = "$FolderCreation\Persistence"
    $RegKeyOutput = "$AutoRunFolder\InstalledDrivers.txt"
    driverquery | Out-File -Force -FilePath $RegKeyOutput
	$SIEMOutput = "$CSVOutputFolder\Drivers.csv"
	driverquery | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-ActiveUsers {
    Write-Host "Collecting Active users..."
    $UserFolder = "$FolderCreation\UserInformation"
    mkdir -Force $UserFolder | Out-Null
    $ActiveUserOutput = "$UserFolder\ActiveUsers.txt"
    query user /server:$server | Out-File -Force -FilePath $ActiveUserOutput
	$SIEMOutput = "$CSVOutputFolder\ActiveUsers.csv"
	query user /server:$server | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-LocalUsers {
    Write-Host "Collecting Local users..."
    $UserFolder = "$FolderCreation\UserInformation"
    $ActiveUserOutput = "$UserFolder\LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
	$SIEMOutput = "$CSVOutputFolder\LocalUsers.csv"
	Get-LocalUser | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-ActiveProcesses {
    Write-Host "Collecting Active Processes..."
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
	$SIEMOutput = "$CSVOutputFolder\Processes.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($null -ne $process.ExecutablePath)
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

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
	($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $SIEMOutput
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
	
}

function Get-SecurityEventCount {
    Write-Host "Collecting stats Security Events last 48 hours..."
    $SecurityEvents = "$FolderCreation\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\EventCount.txt"
    $SecurityEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-2)
    $SecurityEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
}

function Get-SecurityEvents {
    Write-Host "Collecting Security Events last 48 hours..."
    $SecurityEvents = "$FolderCreation\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\SecurityEvents.txt"
    get-eventlog security -After (Get-Date).AddDays(-2) | Format-List * | Out-File -Force -FilePath $ProcessOutput
	$SIEMOutput = "$CSVOutputFolder\SecurityEvents.csv"
	get-eventlog security -After (Get-Date).AddDays(-2) | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-EVTXFiles {
    Write-Host "Collecting Important EVTX Files..."
    $EventViewer = "$FolderCreation\Event Viewer"
    mkdir -Force $EventViewer | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" | Where-Object{$_.BaseName -in $channels} | ForEach-Object{
        Copy-Item  -Path $_.FullName -Destination "$($EventViewer)\$($_.Name)"
    }
}

function Get-OfficeConnections {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid
    )

    Write-Host "Collecting connections made from office applications..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $OfficeConnection = "$ConnectionFolder\ConnectionsMadeByOffice.txt"

    if($UserSid) {
        Get-ItemProperty -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache*" -erroraction 'silentlycontinue' | Out-File -Force -FilePath $OfficeConnection
    }
    else {
        Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache* -erroraction 'silentlycontinue' | Out-File -Force -FilePath $OfficeConnection 
    }
}

function Get-NetworkShares {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid
    )

    Write-Host "Collecting Active Network Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\NetworkShares.txt"

    if($UserSid) {
        Get-ItemProperty -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -erroraction 'silentlycontinue' | Format-Table | Out-File -Force -FilePath $ProcessOutput
    }
    else {
        Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Format-Table | Out-File -Force -FilePath $ProcessOutput
    }
}

function Get-SMBShares {
    Write-Host "Collecting SMB Shares..."
    $ConnectionFolder = "$FolderCreation\Connections"
    $ProcessOutput = "$ConnectionFolder\SMBShares.txt"
    Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
	$SIEMOutput = "$CSVOutputFolder\SMBShares.csv"
	Get-SmbShare | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
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
	$SIEMOutput = "$CSVOutputFolder\DNSCache.csv"
	Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-PowershellHistory {
    Write-Host "Collecting Powershell History..."
    $PowershellHistoryOutput = "$FolderCreation\PowershellHistory.txt"
    history | Out-File -Force -FilePath $PowershellHistoryOutput
	$SIEMOutput = "$CSVOutputFolder\PowerShellHistory.csv"
	history | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-RecentlyInstalledSoftwareEventLogs {
    Write-Host "Collecting Recently Installed Software EventLogs..."
    $ApplicationFolder = "$FolderCreation\Applications"
    mkdir -Force $ApplicationFolder | Out-Null
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *| Out-File -Force -FilePath $ProcessOutput
	$SIEMOutput = "$CSVOutputFolder\InstalledSoftware.csv"
	Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-RunningServices {
    Write-Host "Collecting Running Services..."
    $ApplicationFolder = "$FolderCreation\Applications"
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-Service | Where-Object {$_.Status -eq "Running"} | format-list | Out-File -Force -FilePath $ProcessOutput
	$SIEMOutput = "$CSVOutputFolder\RunningServices.csv"
	Get-Service | Where-Object {$_.Status -eq "Running"} | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-ScheduledTasks {
    Write-Host "Collecting Scheduled Tasks..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    mkdir -Force $ScheduledTaskFolder| Out-Null
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksList.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List | Out-File -Force -FilePath $ProcessOutput
	$SIEMOutput = "$CSVOutputFolder\RunningServices.csv"
	Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-ScheduledTasksRunInfo {
    Write-Host "Collecting Scheduled Tasks Run Info..."
    $ScheduledTaskFolder = "$FolderCreation\ScheduledTask"
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksListRunInfo.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
}

function Get-ConnectedDevices {
    Write-Host "Collecting Information about Connected Devices..."
    $DeviceFolder = "$FolderCreation\ConnectedDevices"
    New-Item -Path $DeviceFolder -ItemType Directory -Force | Out-Null
    $ConnectedDevicesOutput = "$DeviceFolder\ConnectedDevices.csv"
    Get-PnpDevice | Export-Csv -NoTypeInformation -Path $ConnectedDevicesOutput
	$SIEMOutput = "$CSVOutputFolder\RunningServices.csv"
	Get-PnpDevice | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $SIEMOutput -Encoding UTF8
}

function Get-ChromiumFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    Write-Host "Collecting raw Chromium history and profile files..."
    $HistoryFolder = "$FolderCreation\Browsers\Chromium"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @(
        'Preferences',
        'History'
    )

    Get-ChildItem "C:\Users\$Username\AppData\Local\*\*\User Data\*\" | Where-Object { `
        (Test-Path "$_\History") -and `
        [char[]](Get-Content "$($_.FullName)\History" -Encoding byte -TotalCount 'SQLite format'.Length) -join ''
    } | Where-Object { 
        $srcpath = $_.FullName
        $destpath = $_.FullName -replace "^C:\\Users\\$Username\\AppData\\Local",$HistoryFolder -replace "User Data\\",""
        New-Item -Path $destpath -ItemType Directory -Force | Out-Null

        $filesToCopy | ForEach-Object{
            $filesToCopy | Where-Object{ Test-Path "$srcpath\$_" } | ForEach-Object{ Copy-Item -Path "$srcpath\$_" -Destination "$destpath\$_" }
        }
    }
}

function Get-FirefoxFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    if(Test-Path "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles\") {
        Write-Host "Collecting raw Firefox history and profile files..."
        $HistoryFolder = "$FolderCreation\Browsers\Firefox"
        New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

        $filesToCopy = @(
            'places.sqlite',
            'permissions.sqlite',
            'content-prefs.sqlite',
            'extensions'
        )

        Get-ChildItem "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles\" | Where-Object { `
            (Test-Path "$($_.FullName)\places.sqlite") -and `
            [char[]](Get-Content "$($_.FullName)\places.sqlite" -Encoding byte -TotalCount 'SQLite format'.Length) -join ''
        } | ForEach-Object {
            $srcpath = $_.FullName
            $destpath = $_.FullName -replace "^C:\\Users\\$Username\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",$HistoryFolder
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null
            $filesToCopy | Where-Object{ Test-Path "$srcpath\$_" } | ForEach-Object{ Copy-Item -Path "$srcpath\$_" -Destination "$destpath\$_" }
        }
    }
}

function Add-DataSource-Fields-To-CSV {
	# Get all .csv files in the folder
	$csvFiles = Get-ChildItem -Path $CSVOutputFolder -Filter *.csv

	# Loop through each .csv file and add the DataSource column
	foreach ($file in $csvFiles) {
		# Read the CSV file
		$csvData = Import-Csv -Path $file.FullName
		$dataSourceValue = $file.BaseName
		$csvData | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "DataSource" -Value $dataSourceValue -PassThru } |
			Export-Csv -Path $file.FullName -NoTypeInformation
	}

}

function Zip-Results {
    Write-Host "Write results to $FolderCreation.zip..."
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
}

#Run all functions that do not require admin priviliges
function Run-WithoutAdminPrivilege {
    param(
        [Parameter(Mandatory=$false)][String]$UserSid,
        [Parameter(Mandatory=$false)][String]$Username
    )

    Get-IPInfo
    Get-OpenConnections
    Get-AutoRunInfo
    Get-ActiveUsers
    Get-LocalUsers
    Get-ActiveProcesses
    Get-OfficeConnections -UserSid $UserSid
    Get-NetworkShares -UserSid $UserSid
    Get-SMBShares
    Get-RDPSessions
    Get-PowershellHistory
    Get-DNSCache
    Get-InstalledDrivers    
    Get-RecentlyInstalledSoftwareEventLogs
    Get-RunningServices
    Get-ScheduledTasks
    Get-ScheduledTasksRunInfo
    Get-ConnectedDevices
    if($Username) {
        Get-ChromiumFiles -Username $Username
        Get-FirefoxFiles -Username $Username
    }
}

#Run all functions that do require admin priviliges
function Run-WithAdminPrivilges {
    Get-SecurityEventCount
    Get-SecurityEvents
    Get-RemotelyOpenedFiles
    Get-ShadowCopies
    Get-EVTXFiles
}

function SIEM-Data-Wrangling {
	Add-DataSource-Fields-To-CSV
}

Run-WithoutAdminPrivilege -UserSid $currentUserSid -Username $currentUsername
if ($IsAdmin) {
    Run-WithAdminPrivilges
}
SIEM-Data-Wrangling
Zip-Results