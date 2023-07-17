# Connections

### All Open Connections
```
Get-NetTCPConnection -State Established
```

### Connections Made By Office Applications
```
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache*
```
If this command returns an error check if your version is correct. If that is the case then no connection was made from office.

### Network Shares
```
Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\
```

### SMB Shares
```
Get-SmbShare
```

### RDP Sessions
```
qwinsta /server:localhost
```

# Persistence

### Collect All Startup Files
```
Get-CimInstance -ClassName Win32_StartupCommand |
  Select-Object -Property Command, Description, User, Location |
  Out-GridView
```

# Windows Security Events

### Collect The Last 10 Windows Security Event Logs Filter on EventID
```
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 10 | Format-List *
```

### Count By Event Last 2 Days
```
$SecurirtyEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-2)
$SecurirtyEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending
```

### Collect Detailed Information All Windows Security Events Last 2 Days
```
$SecurirtyEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-2)
$SecurirtyEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending
```

# User & Group Information

### Active Users / Kerberos Sessions
```
query user /server:$server
```

### Members of Local Administrator Group
```
net localgroup administrators
```
### Local Users
```
Get-LocalUser | Format-Table 
```

# Processes

### Detailed Proces Information by Procesname
```
Get-Process explorer | Format-List *
```

### Processcommandline
```
Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine, Path | Format-List
```

### Powershell History
```
history
```

### Stop Specific Process by Name
```
Stop-Process -Name "Teams"
```

### Stop Specific Process by ID
```
Stop-Process -ID 666
```

### Scheduled Task List
```
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List
```

### Scheduled Task List Run Status
```
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo
```


# Applications

### Installed Software (RegistryKey Based)
```
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}
```
### Recently Installed Software (Windows Event Logs)
```
Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *
```

### Running Services
```
Get-Service | Where-Object {$_.Status -eq "Running"} | format-list
```

# File Analysis

### Collect File Stream Information
```
Get-Item .\DFIR-Script.ps1 -Stream *
```
### Collect File Content
```
Get-Content .\DFIR-Script.ps1
```

### Collect Raw File Content
```
Get-Content .\DFIR-Script.ps1 -Encoding Byte | Format-hex
```

### Recent Open Docs
```
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
# based on the list select an ID to further investigate
(Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\).71 | Format-Hex
```

### Decode Base64
```
$encodedstring = "aHR0cHM6Ly90aGlzaXNhbWFsaWNpb3VzZG9tYWluLmNvbS9kb3dubG9hZC9tYWx3YXJlLmV4ZQ=="
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encodedstring))
```

# Collect IOC Information

### SHA1 Hash
```
Get-FileHash -Algorithm SHA1 -Path C:\Users\User\AppData\Roaming\Microsoft\MaliciousFile.exe
```
### MD5 Hash
```
Get-FileHash -Algorithm MD5 -Path C:\Users\User\AppData\Roaming\Microsoft\MaliciousFile.exe
```
### SHA1 Hash
```
Get-FileHash -Algorithm SHA256 -Path C:\Users\User\AppData\Roaming\Microsoft\MaliciousFile.exe
```