# Powershell Digital Forensics & Incident Response (DFIR)[![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Powershell%20DFIR!&url=https://github.com/Bert-JanP/Incident-Response-Powershell)

This repository contains multiple PowerShell scripts that can help you respond to cyber attacks on Windows Devices.

The following Incident Response scripts are included:
- [DFIR Script](./DFIR-Script.ps1): Collects all items as listed in section [DFIR Script](#dfir-script).
- [CollectWindowsEvents](./Scripts/CollectWindowsEvents.ps1): Collects all Windows events and outputs it as CSV.
- [CollectWindowsSecurityEvents](./Scripts/CollectWindowsSecurityEvents.ps1): Collects all Windows security events and outputs it as CSV.
- [CollectPnPDevices](./Scripts/CollectPnPDevices.ps1): Collects all Plug and Play devices, such as USB, Network and Storage.
- [DumpLocalAdmins](./Scripts/DumpLocalAdmins.ps1): Returns all local admins of a device.
- [LastLogons](./Scripts/LastLogons.ps1) - List the last N successful logins of a device.
- [ListInstalledSecurityProducts](./Scripts/ListInstalledSecurityProducts.ps1) - List the installed security products and their status.

## DFIR Script
The [DFIR script](./DFIR-Script.ps1) collects information from multiple sources and structures the output in the current directory in a folder named 'DFIR-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end, so that folder can be remotely collected. This script can also be used within Defender For Endpoint in a Live Response session (see below). The DFIR script collects the following information when running as normal user:
- Local IP Info
- Open Connections
- Aautorun Information (Startup Folder & Registry Run keys)
- Active Users
- Local Users
- Connections Made From Office Applications
- Active SMB Shares
- RDP Sessions
- Active Processes
- Active USB Connections
- Powershell History
- DNS Cache
- Installed Drivers
- Installed Software
- Running Services
- Scheduled Tasks

For the best experience run the script as admin, then the following items will also be collected:
- Windows Security Events
- Remotely Opened Files
- Shadow Copies

## DFIR Commands
The [DFIR Commands page](./DFIR-Commands.md) contains invidividual powershell commands that can be used during your incident response process. The follwing catagories are defined:
- Connections
- Persistence
- Windows Security Events
- Processes
- User & Group Information
- Applications
- File Analysis
- Collect IOC Information

## Windows Usage

The script can be excuted by running the following command.
```PowerShell
.\DFIR-Script.ps1
```

The script is unsigned, that could result in having to use the -ExecutionPolicy Bypass to run the script.
```PowerShell
Powershell.exe -ExecutionPolicy Bypass .\DFIR-Script.ps1
```

## DFIR Script | Defender For Endpoit Live Response Integration
It is possible to use the DFIR Script in combination with the Defender For Endpoint Live Repsonse. Make sure that Live Response is setup  (See DOCS). Since my script is usigned a setting change must be made to able to run the script.

To run unsigned scripts live Response:
- Security.microsoft.com
- Settings
- Endpoints
- Advanced Features
- Make sure that Live Response is enabled
- If you want to run this on a server enable live resonse for servers
- Enable Live Response unsigened script execution

Execute script:
- Go to the device page
- Initiate Live Response session
- Upload File to library to upload script
- After uploading the script to the library, use the ***run*** command to run the script

To collect the output of the DFIR script perform the following actions:
```PowerShell
getfile "C:\windows\DFIR-TestDevice-2022-07-06.zip" &	
```

### Docs
- [Microsoft Documentation Live Response](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response?view=o365-worldwide)
- [DFE User permissions](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/user-roles?view=o365-worldwide)
- [Defender For Endpoint Settings Live Response](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-features?view=o365-worldwide#live-response)


