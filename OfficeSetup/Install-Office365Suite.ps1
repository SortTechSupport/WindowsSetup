
#Downloads and installs the Office 365 suite for Windows using the Office Deployment Tool
#To use - invoke this script and supply the path for the .xml file
# eg. .\Install-Office365Suite.ps1 -ConfigurationXMLFile "\\vfp02\sortgroup\Scripts\OfficeSetup\OfficeInstall\UserBasedLicencingConfiguration.xml"

Function Test-URL{
  Param(
    $CurrentURL
  )

  Try{
    $HTTPRequest = [System.Net.WebRequest]::Create($CurrentURL)
    $HTTPResponse = $HTTPRequest.GetResponse()
    $HTTPStatus = [Int]$HTTPResponse.StatusCode

    If($HTTPStatus -ne 200) {
      Return $False
    }

      $HTTPResponse.Close()

  }Catch{
      Return $False
  }    
  Return $True
}
Function Get-ODTURL {
  $ODTDLLink = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16130-20218.exe"

  If((Test-URL -CurrentURL $ODTDLLink) -eq $False){
    $MSWebPage = (Invoke-WebRequest "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117" -UseBasicParsing).Content
  
    $MSWebPage | ForEach-Object {
      If ($_ -match "url=(https://.*officedeploymenttool.*\.exe)"){
        $ODTDLLink = $matches[1]}
      }
  }
  Return $ODTDLLink
}

$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If(!($CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
    Write-Warning "Script is not running as Administrator"
    Write-Warning "Please rerun this script as Administrator."
    Exit
}

$OfficeInstallDownloadPath = "C:\temp\OfficeInstall"

If(-Not(Test-Path $OfficeInstallDownloadPath )){
  New-Item -Path $OfficeInstallDownloadPath  -ItemType Directory -ErrorAction Stop | Out-Null
}

#Get the ODT Download link
$ODTInstallLink = Get-ODTURL

#Download the Office Deployment Tool
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

#Run the Office Deployment Tool setup
Try{
  Write-Verbose "Running the Office Deployment Tool..."
  Start-Process "$OfficeInstallDownloadPath\ODTSetup.exe" -ArgumentList "/quiet /extract:$OfficeInstallDownloadPath" -Wait
}Catch{
  Write-Warning "Error running the Office Deployment Tool. The error is below:"
  Write-Warning $_
}

#Run the O365 install
$ConfigurationXMLFile = "\\vfp02\sortgroup\Scripts\OfficeSetup\OfficeInstall\UserBasedLicencingConfiguration.xml"
Try{
  Write-Verbose "Downloading and installing Office 365"
  #$OfficeInstall = Start-Process "$OfficeInstallDownloadPath\Setup.exe" -ArgumentList "/configure $ConfiguratonXMLFile" -Wait -PassThru
  Start-Process "$OfficeInstallDownloadPath\Setup.exe" -ArgumentList "/configure $ConfigurationXMLFile" -Wait -PassThru
}Catch{
  Write-Warning "Error running the Office install. The error is below:"
  Write-Warning $_
}


#Check if Office 365 suite was installed correctly.

$RegLocations = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                 )

$OfficeInstalled = $False
Foreach ($Key in (Get-ChildItem $RegLocations) ) {
  If($Key.GetValue("DisplayName") -like "*Office 365*") {
    $OfficeVersionInstalled = $Key.GetValue("DisplayName")
    $OfficeInstalled = $True
  }
}

If($OfficeInstalled){
  Write-Verbose "$($OfficeVersionInstalled) installed successfully!"
}Else{
  Write-Warning "Office 365 was not detected after the install ran"
}