#Check if the shell is running as Administrator. If not, call itself with "Run as Admin"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
#Create a log file for debugging
Start-Transcript -Append $PSScriptRoot\Logs\WindowsSetupLog.txt

#Set F8 to boot to Safe Mode
Write-Host -ForegroundColor Green "Setting boot menu to legacy"
bcdedit /set "{current}" bootmenupolicy legacy

#Set Percentage for System Protection
Write-Host -ForegroundColor Green "Setting size for system restore"
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%

#Configure over provisioning for SSD
Write-Host -ForegroundColor Green "Configure Over Provisioning via TRIM"
fsutil behavior set DisableDeleteNotify 0

# Enable system restore on C:\
Write-Host -ForegroundColor Green "Enabling system restore..."
Enable-ComputerRestore -Drive "$env:SystemDrive"

#Force Restore point to not skip
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F

#Disable sleep timers and create a restore point just in case
Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

#Set Power Options
Write-Host -ForegroundColor Green "Set Power options and Time Zone"
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -monitor-timeout-dc 0
powercfg.exe -change -disk-timeout-ac 0
powercfg.exe -change -disk-timeout-dc 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0

#Set British Time Zone
Set-TimeZone -Id "GMT Standard Time"

#Enable .NET Framework
Write-Host -ForegroundColor Green "Enable .NET Framework"
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

#Disable LLMNR
Write-Host -ForegroundColor Green "Disabling LLMNR"
REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient”
REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ” EnableMulticast” /t REG_DWORD /d “0” /f

#Disable NBT-NS
Write-Host -ForegroundColor Green "Disabling NBT-NS"
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object {Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

Write-Host -ForegroundColor Green "Enabling SMB signing as always"
#Enable SMB signing as 'always'
$Parameters = @{
    RequireSecuritySignature = $True
    EnableSecuritySignature = $True
    EncryptData = $True
    Confirm = $false
}
Set-SmbServerConfiguration @Parameters

#Software Installation

Write-Host -ForegroundColor Green "Install Chocolatey to automate basic program installation"
#install Chocolatey and other programs
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y

#Install Chrome
    choco install googlechrome -y --ignore-checksums

#Install Adobe Reader
    choco install adobereader -y

#Install 7-zip
    choco install 7zip -y

#install Slack
    choco install slack -y

#install Citrix
    choco install citrix-workspace -y

#Create Citrix shortcut on Public Desktop
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Citrix.lnk")
$Shortcut.TargetPath = "https://sortgroup.cloud.com/"
$Shortcut.Save()

$Bloatware = @(
    #Unnecessary Windows AppX Apps
    "Microsoft.3DBuilder"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.AppConnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.MinecraftUWP"
    "Microsoft.GamingServices"
    "Microsoft.WindowsReadingList"
    #"Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.XboxApp"
    "Microsoft.ConnectivityStore"
    "Microsoft.CommsPhone"
    "Microsoft.ScreenSketch"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.YourPhone"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "*Adobe Express*"
    "*Spotify*"
    "*Disney+*"
    "*Xbox*"
    "*Clipchamp*"
    "*Prime Video*"
    "*TikTok*"
    "*Instagram*"
    "*Facebook*"
    "*McAfee*"

    #Sponsored Windows 10 AppX Apps
    #Add sponsored/featured apps to remove in the "*AppName*" format
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
    "*Viber*"
    "*ACGMediaPlayer*"
    "*Netflix*"
    "*OneCalendar*"
    "*LinkedInforWindows*"
    "*HiddenCityMysteryofShadows*"
    "*Hulu*"
    "*HiddenCity*"
    "*AdobePhotoshopExpress*"
    "*HotspotShieldFreeVPN*"
    "*McAfee*"
)

    Write-Host  -ForegroundColor Green "Removing Bloatware"

    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue | Remove-AppxProvisionedPackage -Online
        Write-Host  -ForegroundColor Green "Trying to remove $Bloat."
        $ResultText.text = "`r`n" +"`r`n" + "Trying to remove $Bloat."
    }

    Write-Host  -ForegroundColor Green "Finished Removing Bloatware Apps"
    $ResultText.text = "`r`n" +"`r`n" + "Finished Removing Bloatware Apps"

#Call next scripts
Write-Host -ForegroundColor Green "Removing existing office install"
& \\vfp02\SortGroup\Scripts\OfficeSetup\OfficeInstall\ExecuteSaraCmd.ps1

Write-Host -ForegroundColor Green "Installing SortGroup Microsoft Office Suite"
& \\vfp02\SortGroup\Scripts\OfficeSetup\OfficeInstall\Install-Office365Suite.ps1

Write-Host -ForegroundColor Green "Installing VSA"
Start-Process msiexec.exe -Wait -ArgumentList '/I "\\vfp02\software$\_Local installers\VSASetup.msi" /quiet'

Write-Host -ForegroundColor Green "Installing Practice Evolve"
& \\pesvr01\PracticeEvolveInstall\PEInstall.ps1

Write-Host -ForegroundColor Green "Installing Teams"
.\TeamsBootStrapper.exe -p

#Close debugging log Transcript
Stop-Transcript

Write-Host -ForegroundColor Green "Windows Setup complete."
#Sleep to read completion
Start-Sleep -s 5