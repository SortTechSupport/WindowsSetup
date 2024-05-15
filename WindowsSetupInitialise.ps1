# Check if the shell is running as Administrator. If not, call itself with "Run as Admin"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Specify the root and log paths for Windows Setup
$rootPath = "C:\Windows-Setup\"
New-Item -ItemType Directory -Path $rootPath -Force
New-Item -ItemType Directory -Path $rootPath\Logs -Force
Set-Location -Path $rootPath

#Install Snipe Module for asset management
Install-Module SnipeitPS
Update-Module SnipeitPS

# Pull setup script from Github and run it 
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SortTechSupport/WindowsSetup/main/WindowsSetup.ps1 -OutFile ".\WindowsSetup.ps1"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SortTechSupport/WindowsSetup/main/OfficeSetup/ExecuteSaraCmd.ps1 -OutFile ".\ExecuteSaraCmd.ps1"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SortTechSupport/WindowsSetup/main/OfficeSetup/Install-Office365Suite.ps1 -OutFile ".\Install-Office365Suite.ps1"
Invoke-WebRequest -Url https://files.wildix.com/integrations/win/collaboration/Collaboration-x64.msi -OutFile ".\Collaboration-x64.msi"
Copy-Item "\\vfp02\software$\_Local installers\WindowsSetup\WindowsSetup.xml" -Destination $rootPath
Copy-Item "\\vfp02\software$\_Local installers\WindowsSetup\UserBasedLicencingConfiguration.xml" -Destination $rootPath
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" -OutFile ".\TeamsBootStrapper.exe"

# Run the Windows-Setup Script
& .\WindowsSetup.ps1
