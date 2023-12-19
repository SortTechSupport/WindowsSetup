# Specify the root and log paths for Windows Setup
$rootPath = "C:\Windows-Setup\"
New-Item -ItemType Directory -Path $rootPath -Force
New-Item -ItemType Directory -Path $rootPath\Logs -Force
Set-Location -Path $rootPath

# Pull setup script from Github and run it 
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Kisageru/WindowsSetup/main/Windows-Setup.ps1 -OutFile ".\Windows-Setup.ps1"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Kisageru/WindowsSetup/main/ExecuteSaraCmd.ps1 -OutFile ".\ExecuteSaraCmd.ps1"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Kisageru/WindowsSetup/main/Install-Office365Suite.ps1 -OutFile ".\Install-Office365Suite.ps1"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Kisageru/WindowsSetup/main/UserBasedLicencingConfiguration.xml -Outfile ".\UserBasedLicencingConfiguration.xml"
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" -OutFile ".\TeamsBootStrapper.exe"

# Run the Windows-Setup Script
& .\Windows-Setup.ps1