# Powershell Digital Forensics & Incident Response
This repository provides PowerShell-based Incident Response scripts.

# DFIR Script
The [DFIR-Script.ps1](./DFIR-Script.ps1) script collects forensic artifacts on Windows devices. Key features include:
- Collecting over 25 potential indicators of compromise.
- CSV-based export files for SIEM integration.
- Defender for Endpoint Live Response integration.

# Granular Response Scripts
These scripts perform specific tasks, such as collecting Windows Security Events, resetting active user sessions, or uploading a folder to Azure Storage Blob. Some scripts use APIs to retrieve or export data, with required permissions described in each script. The scripts are structured for the Incident Response cycle:

| Phase | Description |
|--------|-------------|
| [Acquisition](./Acquisition/) | Scripts and tools for acquiring data and evidence during an incident. |
| [Analysis](./Analysis/) | Sripts for analyzing acquired data to identify indicators of compromise and understand the scope of the incident. |
| [Containment](./Containment/) | Scripts and methods for containing the incident to prevent further damage and spread. |

# Related Blogs:
- [Incident Response Part 3: Leveraging Live Response](https://kqlquery.com/posts/leveraging-live-response/)
- [Incident Response PowerShell V2](https://kqlquery.com/posts/incident-response-powershell-v2/)


# DFIR Script Usage

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
The forensic artifacts are exported as CSV files, allowing responders to ingest them into tools like Sentinel, Splunk, Elastic, or Azure Data Explorer for filtering, aggregation, and visualization.

The folder *CSV Results (SIEM Import Data)* includes all the CSV files containing the artifacts:

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

## Execute the script

The script can be executed by running the following command.
```PowerShell
.\DFIR-Script.ps1
```

The script is unsigned, that could result in having to use the -ExecutionPolicy Bypass to run the script.
```PowerShell
Powershell.exe -ExecutionPolicy Bypass .\DFIR-Script.ps1
```

## Defender For Endpoint Live Response Integration
It is possible to use the scripts in combination with the Defender For Endpoint Live Response. Make sure that Live Response is setup (See DOCS). Since my script is unsigned, a setting change must be made to be able to run the script.

There is a blog article available that explains more about how to leverage Custom Script in Live Response: [Incident Response Part 3: Leveraging Live Response](https://kqlquery.com/posts/leveraging-live-response/)

To run unsigned scripts live Response:
- Go to Security.microsoft.com
- Navigate to Settings > Endpoints > Advanced Features
- Ensure Live Response is enabled
- Enable Live Response for servers if needed
- Enable Live Response unsigned script execution

Execute script:
- Go to the device page
- Initiate Live Response session
- Upload File to library to upload script
- After uploading the script to the library execute: ```run DFIR-script.ps1``` to start the script. If you want to run the script using parameters, you should run ```run DFIR-Script.ps1 -parameters "-sw 10"```
- Execute ```getfile DFIR-DeviceName-yyyy-mm-dd``` to download the retrieved artifacts to your local machine for analysis.

### Docs
- [Microsoft Documentation Live Response](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response?view=o365-worldwide)
- [DFE User permissions](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/user-roles?view=o365-worldwide)
- [Defender For Endpoint Settings Live Response](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-features?view=o365-worldwide#live-response)