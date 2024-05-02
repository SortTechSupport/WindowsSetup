# Check if the shell is running as Administrator. If not, call itself with "Run as Admin"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
# Create a log file for debugging
Start-Transcript -Append $PSScriptRoot\Logs\WindowsSetupLog.txt

# Module for asset management
Import-Module SnipeitPS

# Load XML content from file
$xmlFilePath = "$PSScriptRoot\WindowsSetup.xml"

# Create an XmlDocument and load XML content from the file
$xml = New-Object System.Xml.XmlDocument
$xml.Load($xmlFilePath)

## Housekeeping ##

# Set F8 to boot to Safe Mode
Write-Host -ForegroundColor Green "Setting boot menu to legacy"
bcdedit /set "{current}" bootmenupolicy legacy

# Set Percentage for System Protection
Write-Host -ForegroundColor Green "Setting size for system restore"
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%

# Configure over provisioning for SSD
Write-Host -ForegroundColor Green "Configure Over Provisioning via TRIM"
fsutil behavior set DisableDeleteNotify 0

# Enable system restore on C:\
Write-Host -ForegroundColor Green "Enabling system restore..."
Enable-ComputerRestore -Drive "$env:SystemDrive"

# Force Restore point to not skip
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F

# Disable sleep timers and create a restore point just in case
Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

# Set Power Options
Write-Host -ForegroundColor Green "Set Power options and Time Zone"
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -monitor-timeout-dc 0
powercfg.exe -change -disk-timeout-ac 0
powercfg.exe -change -disk-timeout-dc 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0

# Set British Time Zone
Set-TimeZone -Id "GMT Standard Time"

# Enable .NET Framework
Write-Host -ForegroundColor Green "Enable .NET Framework"
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

# Disable LLMNR
Write-Host -ForegroundColor Green "Disabling LLMNR"
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD -Force

# Disable NBT-NS 
Write-Host -ForegroundColor Green "Disabling NBT-NS"
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object {Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

# Enable SMB signing as 'always'
Write-Host -ForegroundColor Green "Enabling SMB signing as always"
$Parameters = @{
    RequireSecuritySignature = $True
    EnableSecuritySignature = $True
    EncryptData = $True
    Confirm = $false
}
Set-SmbServerConfiguration @Parameters

## Software Installation ##

# Install Chocolatey and other basic programs
Write-Host -ForegroundColor Green "Install Chocolatey to automate basic program installation"
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y
    choco install googlechrome -y --ignore-checksums
    choco install adobereader -y
    choco install 7zip -y
    choco install citrix-workspace -y

# Create Citrix shortcut on Public Desktop
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Citrix.lnk")
$Shortcut.TargetPath = "https://sortgroup.cloud.com/"
$shortcut.IconLocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$Shortcut.Save()

## Software Removal ##
# Get apps
$unnecessaryApps = $xml.SelectNodes('//apps/unnecessary/app') | ForEach-Object { $_.id }
$sponsoredApps = $xml.SelectNodes('//apps/sponsored/app') | ForEach-Object { $_.id }
$allApps = $unnecessaryApps + $sponsoredApps

# Iterate through the apps
foreach ($Bloat in $allApps) {
    Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue | Remove-AppxProvisionedPackage -Online
    Write-Host -ForegroundColor Green "Trying to remove $Bloat."
}
    Write-Host  -ForegroundColor Green "Finished Removing Bloatware Apps"

## Call next scripts ##
Write-Host -ForegroundColor Green "Removing existing office install"
& .\ExecuteSaraCmd.ps1

Write-Host -ForegroundColor Green "Installing SortGroup Microsoft Office Suite"
& .\Install-Office365Suite.ps1

Write-Host -ForegroundColor Green "Installing VSA"
Start-Process msiexec.exe -Wait -ArgumentList '/I "\\vfp02\software$\_Local installers\VSASetup.msi" /quiet'

Write-Host -ForegroundColor Green "Installing Practice Evolve"
& \\pesvr01\PracticeEvolveInstall\PEInstall.ps1

Write-Host -ForegroundColor Green "Installing Teams"
.\TeamsBootStrapper.exe -p

## Add asset to Snipe ## 
$url = $xml.SelectSingleNode('//Snipe/SnipeURL').InnerText
$apiKey = $xml.SelectSingleNode('//Snipe/SnipeAPIKey').InnerText
Connect-SnipeitPS -url $url -apiKey $apiKey

$computerName = $env:COMPUTERNAME
$serialNumber = (Get-WmiObject win32_bios).SerialNumber

$assetExists = Get-SnipeITAsset -search $serialNumber
if(([string]::IsNullOrEmpty($assetExists)))
{
    $modelno = (Get-WmiObject -class Win32_ComputerSystem).Model
    $modelSelection = Get-SnipeitModel | Where-Object {$_.model_number -like "*$modelno*"}
    New-SnipeitAsset -Name $computerName -tag $computerName -serial $serialNumber -Model_id $modelSelection.id -rtd_location_id "1" -Status "2"
}
else {
    Write-Output "$computerName - $serialNumber already exists"
    exit
}

## Close debugging log Transcript ##
Stop-Transcript
Write-Host -ForegroundColor Green "Windows Setup complete."
Start-Sleep -s 5
