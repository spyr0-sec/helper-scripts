# Get-ExchangeConfiguration - Runs several helpful Exchange cmdlets to pull down configurations for assessment
# Must be run in an Exchange Management Shell as admin 
# spyr0 - v0.1
# Usage: ./ExchangeConfiguration

New-Item -Path .\ExchangeConfiguration -ItemType Directory

# Get-ExCommand | Select-String -Pattern 'Get-*'
Get-ExchangeServer | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\ServerDetails.txt
Get-TransportConfig | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\TransportConfig.txt
Get-ExchangeServer | ForEach-Object{Get-ImapSettings -Server $_.Name | Select-Object *} | Tee-Object -FilePath .\ExchangeConfiguration\ImapSettings.txt
Get-ExchangeServer | ForEach-Object{Get-PopSettings -Server $_.Name | Select-Object *} | Tee-Object -FilePath .\ExchangeConfiguration\PopSettings.txt
Get-MobileDeviceMailboxPolicy | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\MobileDeviceMailboxPolicies.txt
Get-OwaVirtualDirectory | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\OWAVirtualDirectories.txt
Get-SenderFilterConfig | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\SenderFilterConfig.txt
Get-UMDialPlan | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\UMDialPlan.txt
Get-UMMailboxPolicy | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\UMMailboxPolicy.txt
Get-AdminAuditLogConfig | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\AdminAuditLogPolicy.txt
Get-RemoteDomain | Select-Object * | Tee-Object -FilePath .\ExchangeConfiguration\RemoteDomains.txt