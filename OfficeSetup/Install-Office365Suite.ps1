## Downloads and installs the Office 365 suite for Windows using the Office Deployment Tool
## To use - invoke this script and supply the path for the .xml file
## eg. .\Install-Office365Suite.ps1 -ConfigurationXMLFile "\\Path\To\UserBasedLicencingConfiguration.xml"

# Check if the shell is running as Administrator. If not, call itself with "Run as Admin"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
  Exit
}

function Get-ODTURL {

  [String]$MSWebPage = Invoke-RestMethod 'https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_17531-20046.exe' #'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117'

  $MSWebPage | ForEach-Object {
    if ($_ -match 'url=(https://.*officedeploymenttool.*\.exe)') {
      $matches[1]
    }
  }
}

$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

# Define config XML and create install folder
$ConfigurationXMLFile = "$PSScriptRoot\UserBasedLicencingConfiguration.xml"
$OfficeInstallDownloadPath = "$PSScriptRoot\OfficeInstall"

If(-Not(Test-Path $OfficeInstallDownloadPath )){
  New-Item -Path $OfficeInstallDownloadPath  -ItemType Directory -ErrorAction Stop | Out-Null
}

# Get the ODT Download link
$ODTInstallLink = Get-ODTURL

# Download the Office Deployment Tool
Write-Verbose "Downloading the Office Deployment Tool..."
Try{
  $ODTInstallLink
  Invoke-WebRequest -Uri $ODTInstallLink -OutFile "$OfficeInstallDownloadPath\ODTSetup.exe"
}Catch{
  Write-Warning "There was an error downloading the Office Deployment Tool."
  Write-Warning "Please verify the below link is valid:"
  Write-Warning $ODTInstallLink
  Exit
}

# Run the Office Deployment Tool setup
Try{
  Write-Verbose "Running the Office Deployment Tool..."
  Start-Process "$OfficeInstallDownloadPath\ODTSetup.exe" -ArgumentList "/quiet /extract:$OfficeInstallDownloadPath" -Wait
}Catch{
  Write-Warning "Error running the Office Deployment Tool. The error is below:"
  Write-Warning $_
}

# Run the O365 install
Try{
  Write-Verbose "Downloading and installing Office 365"
  Start-Process "$OfficeInstallDownloadPath\Setup.exe" -ArgumentList "/configure $ConfigurationXMLFile" -Wait -PassThru
}Catch{
  Write-Warning "Error running the Office install. The error is below:"
  Write-Warning $_
}
