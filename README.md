# Powershell Digital Forensics & Incident Response (DFIR)[![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Powershell%20DFIR!&url=https://github.com/Bert-JanP/Incident-Response-Powershell)

This repository contains multiple PowerShell scripts that can help you respond to cyber attacks on Windows Devices.

The following Incident Response scripts are included:
- [DFIR Script](./DFIR-Script.ps1): Collects all items as listed in section [DFIR Script](#dfir-script---extracted-artefacts).
- [CollectWindowsEvents](./Scripts/CollectWindowsEvents.ps1): Collects all Windows events and outputs it as CSV.
- [CollectWindowsSecurityEvents](./Scripts/CollectWindowsSecurityEvents.ps1): Collects all Windows security events and outputs it as CSV.
- [CollectPnPDevices](./Scripts/CollectPnPDevices.ps1): Collects all Plug and Play devices, such as USB, Network and Storage.
- [DumpLocalAdmins](./Scripts/DumpLocalAdmins.ps1): Returns all local admins of a device.
- [LastLogons](./Scripts/LastLogons.ps1) - List the last N successful logins of a device.
- [ListInstalledSecurityProducts](./Scripts/ListInstalledSecurityProducts.ps1) - List the installed security products and their status.
- [ListDefenderExclusions](./Scripts/ListDefenderExclusions.ps1) - List the FolderPath, FileExtension, Process and IP exclusions that are defined.

## Related Blogs:
- [Incident Response Part 3: Leveraging Live Response](https://kqlquery.com/posts/leveraging-live-response/)
- [Incident Response PowerShell V2](https://kqlquery.com/posts/incident-response-powershell-v2/)

## DFIR Script - Extracted Artefacts
The [DFIR script](./DFIR-Script.ps1) collects information from multiple sources and structures the output in the current directory in a folder named 'DFIR-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end, so that folder can be remotely collected. This script can also be used within Defender For Endpoint in a Live Response session (see below). The DFIR script collects the following information when running as normal user:
- Local IP Info
- Open Connections
- Autorun Information (Startup Folder & Registry Run keys)
- Active Users
- Local Users
- Connections Made From Office Applications
- Active SMB Shares
- RDP Sessions
- Active Processes
- Active USB Connections
- PowerShell History
- DNS Cache
- Installed Drivers
- Installed Software
- Running Services
- Scheduled Tasks
- Browser history and profile files

For the best experience run the script as admin, then the following items will also be collected:
- Windows Security Events
- Remotely Opened Files
- Shadow Copies
- MPLogs
- Defender Exclusions
- PowerShell History All Users

## SIEM Import Functionality
The forensic artefacts are exported as CSV files, which allows responders to ingest them into their tooling. Some example tools in which you can ingest the data are Sentinel, Splunk, Elastic or Azure Data Explorer. This will allow you to perform filtering, aggregation and visualisation with your preferred query language. 

The folder *CSV Results (SIEM Import Data)* includes all the CSV files containing the artefacts, the folder listing is shown below.

```PowerShell
Name
----
ActiveUsers.csv
AutoRun.csv
ConnectedDevices.csv
DefenderExclusions.csv
DNSCache.csv
Drivers.csv
InstalledSoftware.csv
IPConfiguration.csv
LocalUsers.csv
NetworkShares.csv
OfficeConnections.csv
OpenTCPConnections.csv
PowerShellHistory.csv
Processes.csv
RDPSessions.csv
RemotelyOpenedFiles.csv
RunningServices.csv
ScheduledTasks.csv
ScheduledTasksRunInfo.csv
SecurityEvents.csv
ShadowCopy.csv
SMBShares.csv
```

## DFIR Commands
The [DFIR Commands page](./DFIR-Commands.md) contains individual PowerShell commands that can be used during your incident response process. The following categories are defined:
- Connections
- Persistence
- Windows Security Events
- Processes
- User & Group Information
- Applications
- File Analysis
- Collect IOC Information

## Windows Usage

The script can be executed by running the following command.
```PowerShell
.\DFIR-Script.ps1
```

The script is unsigned, that could result in having to use the -ExecutionPolicy Bypass to run the script.
```PowerShell
Powershell.exe -ExecutionPolicy Bypass .\DFIR-Script.ps1
```

## DFIR Script | Defender For Endpoint Live Response Integration
It is possible to use the DFIR Script in combination with the Defender For Endpoint Live Response. Make sure that Live Response is setup (See DOCS). Since my script is unsigned, a setting change must be made to be able to run the script.

There is a blog article available that explains more about how to leverage Custom Script in Live Response: [Incident Response Part 3: Leveraging Live Response](https://kqlquery.com/posts/leveraging-live-response/)

To run unsigned scripts live Response:
- Security.microsoft.com
- Settings
- Endpoints
- Advanced Features
- Make sure that Live Response is enabled
- If you want to run this on a server enable live response for servers
- Enable Live Response unsigned script execution

Execute script:
- Go to the device page
- Initiate Live Response session
- Upload File to library to upload script
- After uploading the script to the library execute: ```run DFIR-script.ps1``` to start the script. If you want to run the script using parameters, you should run ```run DFIR-Script.ps1 -parameters "-sw 10"```.
- Execute ```getfile DFIR-DeviceName-yyyy-mm-dd``` to download the retrieved artifacts to your local machine for analysis.

### Docs
- [Microsoft Documentation Live Response](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response?view=o365-worldwide)
- [DFE User permissions](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/user-roles?view=o365-worldwide)
- [Defender For Endpoint Settings Live Response](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-features?view=o365-worldwide#live-response)


