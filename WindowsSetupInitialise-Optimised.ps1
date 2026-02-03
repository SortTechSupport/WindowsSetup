#Requires -RunAsAdministrator
<#.SYNOPSIS
initialisation script for Windows Setup automation.

.DESCRIPTION
Improved version with parallel downloads, better error handling, and faster execution.

.NOTES
Author: Conrad Kent
Date: 2026-02-03
Improvements:
- Parallel file downloads using Start-BitsTransfer and Jobs
- Module installation optimization
- Better error handling
- Progress indicators
#>

# Ensure we're running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Set error handling
$ErrorActionPreference = 'Stop'

Write-Host -ForegroundColor Cyan "=== Windows Setup Initialization ==="

# Specify the root and log paths
$rootPath = "C:\Windows-Setup\"
Write-Host -ForegroundColor Green "Creating directory structure..."
New-Item -ItemType Directory -Path $rootPath -Force | Out-Null
New-Item -ItemType Directory -Path "$rootPath\Logs" -Force | Out-Null
Set-Location -Path $rootPath

#Region - Module Installation
Write-Host -ForegroundColor Green "Installing required PowerShell modules..."

# Set PSGallery as trusted to avoid prompts
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

# Install modules in parallel using jobs
$moduleJobs = @()
$modules = @('SnipeitPS', 'PSWindowsUpdate')

foreach ($module in $modules) {
    $moduleJobs += Start-Job -ScriptBlock {
        param($moduleName)
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Install-Module -Name $moduleName -Force -AllowClobber -Scope AllUsers
        } else {
            Update-Module -Name $moduleName -Force
        }
    } -ArgumentList $module
}

# Wait for module installation to complete
Write-Host "  Installing modules in parallel..." -NoNewline
$moduleJobs | Wait-Job | Out-Null
$moduleJobs | Receive-Job
$moduleJobs | Remove-Job
Write-Host " Done!" -ForegroundColor Green
#EndRegion

#Region - File Downloads
Write-Host -ForegroundColor Green "Downloading required files..."

# Define all downloads
$downloads = @(
    @{
        Url = 'https://raw.githubusercontent.com/SortTechSupport/WindowsSetup/main/WindowsSetup-Optimized.ps1'
        Destination = "$rootPath\WindowsSetup.ps1"
        UseWebRequest = $true
    },
    @{
        Url = 'https://raw.githubusercontent.com/SortTechSupport/WindowsSetup/main/OfficeSetup/ExecuteSaraCmd.ps1'
        Destination = "$rootPath\ExecuteSaraCmd.ps1"
        UseWebRequest = $true
    },
    @{
        Url = 'https://raw.githubusercontent.com/SortTechSupport/WindowsSetup/main/OfficeSetup/Install-Office365Suite.ps1'
        Destination = "$rootPath\Install-Office365Suite.ps1"
        UseWebRequest = $true
    },
    @{
        Url = 'https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409'
        Destination = "$rootPath\TeamsBootStrapper.exe"
        UseWebRequest = $false  # Use BITS for larger files
    },
    @{
        Url = 'https://files.wildix.com/integrations/win/collaboration/Collaboration-x64.msi'
        Destination = "$rootPath\Collaboration-x64.msi"
        UseWebRequest = $false  # Use BITS for larger files
    }
)

# Download files in parallel using jobs
$downloadJobs = @()
foreach ($download in $downloads) {
    if ($download.UseWebRequest) {
        # Use Invoke-WebRequest for small text files
        $downloadJobs += Start-Job -ScriptBlock {
            param($url, $dest)
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        } -ArgumentList $download.Url, $download.Destination
    } else {
        # Use BITS for larger binary files (faster and resumable)
        $downloadJobs += Start-Job -ScriptBlock {
            param($url, $dest)
            Import-Module BitsTransfer
            Start-BitsTransfer -Source $url -Destination $dest -Priority High
        } -ArgumentList $download.Url, $download.Destination
    }
}

# Wait for downloads with progress indicator
$completed = 0
$total = $downloadJobs.Count
while ($downloadJobs | Where-Object { $_.State -eq 'Running' }) {
    $completed = ($downloadJobs | Where-Object { $_.State -eq 'Completed' }).Count
    Write-Progress -Activity "Downloading files" -Status "$completed of $total complete" -PercentComplete (($completed / $total) * 100)
    Start-Sleep -Milliseconds 500
}
Write-Progress -Activity "Downloading files" -Completed

# Check for errors
$downloadJobs | ForEach-Object {
    if ($_.State -eq 'Failed') {
        Write-Host -ForegroundColor Red "Download failed: $($_.ChildJobs[0].Error)"
    }
}

$downloadJobs | Receive-Job
$downloadJobs | Remove-Job

Write-Host "  All downloads complete!" -ForegroundColor Green
#EndRegion

#Region - Network File Copies
Write-Host -ForegroundColor Green "Copying configuration files from network share..."

$networkFiles = @(
    @{
        Source = "\\vfp02\software$\_Local installers\WindowsSetup\WindowsSetup.xml"
        Destination = "$rootPath\WindowsSetup.xml"
    },
    @{
        Source = "\\vfp02\software$\_Local installers\WindowsSetup\UserBasedLicencingConfiguration.xml"
        Destination = "$rootPath\UserBasedLicencingConfiguration.xml"
    }
)

# Copy network files (these can't be parallelized easily, but we can use Robocopy for speed)
foreach ($file in $networkFiles) {
    try {
        # Use Copy-Item with -Force for overwrite
        Copy-Item -Path $file.Source -Destination $file.Destination -Force -ErrorAction Stop
        Write-Host "  Copied: $(Split-Path $file.Source -Leaf)" -ForegroundColor Gray
    } catch {
        Write-Host -ForegroundColor Red "  Failed to copy $(Split-Path $file.Source -Leaf): $_"
    }
}
#EndRegion

Write-Host -ForegroundColor Cyan "`n=== Initialization Complete ==="
Write-Host -ForegroundColor Green "Launching WindowsSetup.ps1...`n"

# Run the Windows-Setup Script
& "$rootPath\WindowsSetup.ps1"
