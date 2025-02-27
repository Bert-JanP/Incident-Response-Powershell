function ListSecurityProducts {
	Write-Host "AntiSpywareProduct:"
	Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiSpywareProduct | Select-Object -Property displayName, instanceGuid, pathToSignedProductExe, pathToSignedReportingExe, productState, @{Name='CustomProductState';Expression={ 
    switch ($_.productState) {
        397568 { "Windows Defender Enabled and Up to date" }
		397584 { "Windows Defender Enabled and Out of date" }
		393472 { "Windows Defender disabled" }
        default { "Unknown" }
    }
}}, timestamp
	Write-Host "AntiVirusProduct:"
	Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -Property displayName, instanceGuid, pathToSignedProductExe, pathToSignedReportingExe, productState, @{Name='CustomProductState';Expression={ 
    switch ($_.productState) {
        397568 { "Windows Defender Enabled and Up to date" }
		397584 { "Windows Defender Enabled and Out of date" }
		393472 { "Windows Defender disabled" }
        default { "Unknown" }
    }
	}}, timestamp
	Write-Host "FirewallProduct:"
	Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | Select-Object -Property displayName, instanceGuid, pathToSignedProductExe, pathToSignedReportingExe, productState, @{Name='CustomProductState';Expression={ 
    switch ($_.productState) {
        266256 { "Firewall enabled" }
		262160 { "Firewall disabled" }
        default { "Unknown" }
    }
	}}, timestamp
}

ListSecurityProducts
