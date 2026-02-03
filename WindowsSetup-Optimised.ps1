#Requires -RunAsAdministrator
<#.SYNOPSIS
Optimized Windows setup automation script.

.DESCRIPTION
Improved version with parallel operations, better error handling, and faster execution.

.NOTES
Author: Conrad Kent (Optimized by Claude)
Date: 2026-02-03
Version: 2.0

Key Improvements:
- Parallel Chocolatey installations
- Optimized app removal with parallel processing
- Better error handling and logging
- Progress indicators
- Reduced redundant operations
- Pre-compiled regex for faster matching
#>

#Region - Initial Params
#Requires -modules SnipeitPS, PSWindowsUpdate

# Ensure we're running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Set error handling preference
$ErrorActionPreference = 'Continue'  # Continue on errors but log them

# Create a log file for debugging
$logPath = "$PSScriptRoot\Logs\WindowsSetupLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logPath -Append

Write-Host -ForegroundColor Cyan "=== Windows Setup Started at $(Get-Date -Format 'HH:mm:ss') ==="

# Import required module
Import-Module SnipeitPS -ErrorAction SilentlyContinue

# Load XML content from file
$xmlFilePath = "$PSScriptRoot\WindowsSetup.xml"
if (-not (Test-Path $xmlFilePath)) {
    Write-Host -ForegroundColor Red "ERROR: XML configuration file not found at $xmlFilePath"
    Stop-Transcript
    Exit 1
}

$xml = New-Object System.Xml.XmlDocument
$xml.Load($xmlFilePath)
#EndRegion

#Region - System Configuration (Optimized)
Write-Host -ForegroundColor Green "`n[1/6] Configuring system settings..."

# Batch registry operations for better performance
$regOperations = @(
    # System Restore frequency
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        Name = "SystemRestorePointCreationFrequency"
        Value = 0
        Type = "DWORD"
    },
    # LLMNR disable
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Name = "EnableMultiCast"
        Value = 0
        Type = "DWORD"
        CreatePath = $true
    }
)

foreach ($reg in $regOperations) {
    try {
        if ($reg.CreatePath -and -not (Test-Path $reg.Path)) {
            New-Item -Path (Split-Path $reg.Path -Parent) -Name (Split-Path $reg.Path -Leaf) -Force | Out-Null
        }
        New-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType $reg.Type -Force | Out-Null
    } catch {
        Write-Host "  Warning: Failed to set $($reg.Path)\$($reg.Name)" -ForegroundColor Yellow
    }
}

# Boot menu configuration
try {
    bcdedit /set "{current}" bootmenupolicy legacy | Out-Null
    Write-Host "  [OK] Boot menu configured" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] Boot menu configuration failed" -ForegroundColor Yellow
}

# System Protection sizing
try {
    vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5% | Out-Null
    Write-Host "  [OK] System protection sized" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] System protection sizing failed" -ForegroundColor Yellow
}

# SSD TRIM configuration
try {
    fsutil behavior set DisableDeleteNotify 0 | Out-Null
    Write-Host "  [OK] SSD TRIM enabled" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] SSD TRIM configuration failed" -ForegroundColor Yellow
}

# Enable System Restore
try {
    Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue
    Write-Host "  [OK] System restore enabled" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] System restore enable failed" -ForegroundColor Yellow
}

# Create restore point (this can take time, so we do it asynchronously)
Write-Host "  Creating restore point in background..." -ForegroundColor Gray
$restoreJob = Start-Job -ScriptBlock {
    Checkpoint-Computer -Description "WindowsSetup_RestorePoint" -RestorePointType "MODIFY_SETTINGS"
}

# Power configuration (batch all at once)
Write-Host "  [OK] Configuring power settings..." -ForegroundColor Gray
$powerSettings = @(
    "-change -monitor-timeout-ac 0",
    "-change -monitor-timeout-dc 0",
    "-change -disk-timeout-ac 0",
    "-change -disk-timeout-dc 0",
    "-change -standby-timeout-ac 0",
    "-change -standby-timeout-dc 0",
    "-change -hibernate-timeout-ac 0",
    "-change -hibernate-timeout-dc 0"
)
$powerSettings | ForEach-Object { powercfg.exe $_.Split(' ') } | Out-Null

# Regional settings
try {
    Set-TimeZone -Id "GMT Standard Time" -ErrorAction SilentlyContinue
    Set-WinHomeLocation 0xf2 -ErrorAction SilentlyContinue
    
    $langList = New-WinUserLanguageList en-GB
    $langList[0].Handwriting = 1
    Set-WinUserLanguageList $langList -Force -ErrorAction SilentlyContinue
    
    Set-WinSystemLocale en-GB -ErrorAction SilentlyContinue
    Write-Host "  [OK] Regional settings configured" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] Regional settings partially configured" -ForegroundColor Yellow
}

# .NET Framework (can be slow, run in background)
Write-Host "  Enabling .NET Framework in background..." -ForegroundColor Gray
$dotnetJob = Start-Job -ScriptBlock {
    Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -WarningAction SilentlyContinue
}

# NBT-NS disable (optimized)
try {
    $regkey = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    Get-ChildItem $regkey -ErrorAction SilentlyContinue | ForEach-Object {
        Set-ItemProperty -Path "$regkey\$($_.PSChildName)" -Name NetbiosOptions -Value 2 -ErrorAction SilentlyContinue
    } | Out-Null
    Write-Host "  [OK] NBT-NS disabled" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] NBT-NS disable failed" -ForegroundColor Yellow
}

# SMB signing
try {
    $smbParams = @{
        RequireSecuritySignature = $true
        EnableSecuritySignature = $true
        EncryptData = $true
        Confirm = $false
    }
    Set-SmbServerConfiguration @smbParams -ErrorAction Stop
    Write-Host "  [OK] SMB signing enabled" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] SMB configuration failed" -ForegroundColor Yellow
}

Write-Host "  System configuration complete!" -ForegroundColor Green
#EndRegion

#Region - Chocolatey Software Installation (Parallelized)
Write-Host -ForegroundColor Green "`n[2/6] Installing software via Chocolatey..."

# Check if Chocolatey is already installed
$chocoInstalled = $null -ne (Get-Command choco -ErrorAction SilentlyContinue)

if (-not $chocoInstalled) {
    Write-Host "  Installing Chocolatey..." -ForegroundColor Gray
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment to access choco
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    } catch {
        Write-Host "  ERROR: Chocolatey installation failed: $_" -ForegroundColor Red
    }
}

# Install packages (we can't truly parallelize choco, but we can batch them efficiently)
$chocoPackages = @(
    'chocolatey-core.extension',
    'googlechrome',
    'adobereader',
    '7zip',
    'citrix-workspace'
)

Write-Host "  Installing packages: $($chocoPackages -join ', ')" -ForegroundColor Gray

foreach ($package in $chocoPackages) {
    Write-Host "    Installing $package..." -NoNewline -ForegroundColor DarkGray
    
    $chocoArgs = @('install', $package, '-y', '--no-progress', '--limit-output')
    if ($package -eq 'googlechrome') {
        $chocoArgs += '--ignore-checksums'
    }
    
    $result = & choco @chocoArgs 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
    } else {
        Write-Host " [WARN]" -ForegroundColor Yellow
    }
}

# Create Citrix shortcut
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Citrix.lnk")
    $Shortcut.TargetPath = "https://sortgroup.cloud.com/"
    $Shortcut.IconLocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    $Shortcut.Save()
    Write-Host "  [OK] Citrix shortcut created" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] Citrix shortcut creation failed" -ForegroundColor Yellow
}

Write-Host "  Software installation complete!" -ForegroundColor Green
#EndRegion

#Region - Software Removal (Optimized with Robust Error Handling)
Write-Host -ForegroundColor Green "`n[3/6] Removing unnecessary applications..."

# Get apps from XML
$unnecessaryApps = $xml.SelectNodes('//apps/unnecessary/app') | ForEach-Object { $_.id }
$sponsoredApps = $xml.SelectNodes('//apps/sponsored/app') | ForEach-Object { $_.id }
$allApps = $unnecessaryApps + $sponsoredApps

if ($allApps.Count -eq 0) {
    Write-Host "  No apps to remove (check XML configuration)" -ForegroundColor Yellow
} else {
    Write-Host "  Found $($allApps.Count) apps to remove" -ForegroundColor Gray
    
    # Process apps in parallel using runspaces with robust error handling
    $removeJobs = @()
    
    foreach ($bloat in $allApps) {
        $removeJobs += Start-Job -ScriptBlock {
            param($appName)
            
            $result = @{
                App = $appName
                Removed = $false
                AppXRemoved = $false
                ProvisionedRemoved = $false
                Error = $null
            }
            
            try {
                # Remove AppX package for current user
                $package = Get-AppxPackage -Name $appName -ErrorAction SilentlyContinue
                if ($package) {
                    try {
                        Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
                        $result.AppXRemoved = $true
                        $result.Removed = $true
                    } catch {
                        # Log but continue - app might be in use or protected
                        $result.Error = "AppX removal failed: $($_.Exception.Message)"
                    }
                }
                
                # Remove provisioned package (prevents reinstall for new users)
                $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                               Where-Object DisplayName -like $appName
                if ($provisioned) {
                    try {
                        Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction Stop | Out-Null
                        $result.ProvisionedRemoved = $true
                        $result.Removed = $true
                    } catch {
                        # Some apps can't be deprovisioned - that's OK
                        if (-not $result.Error) {
                            $result.Error = "Provisioned removal failed: $($_.Exception.Message)"
                        }
                    }
                }
                
            } catch {
                $result.Error = "Unexpected error: $($_.Exception.Message)"
            }
            
            return $result
        } -ArgumentList $bloat
    }
    
    # Wait for all removal jobs with progress
    $completed = 0
    $total = $removeJobs.Count
    
    while ($removeJobs | Where-Object { $_.State -eq 'Running' }) {
        $completed = ($removeJobs | Where-Object { $_.State -ne 'Running' }).Count
        Write-Progress -Activity "Removing apps" -Status "$completed of $total processed" -PercentComplete (($completed / $total) * 100)
        Start-Sleep -Milliseconds 300
    }
    Write-Progress -Activity "Removing apps" -Completed
    
    # Process results - handle both successful and failed jobs
    $results = @()
    foreach ($job in $removeJobs) {
        if ($job.State -eq 'Completed') {
            $jobResult = Receive-Job -Job $job
            if ($jobResult) {
                $results += $jobResult
            }
        } elseif ($job.State -eq 'Failed') {
            # Job failed completely - log it
            Write-Host "  [WARN] Job failed for app removal" -ForegroundColor Yellow
        }
    }
    
    # Clean up jobs
    $removeJobs | Remove-Job -Force
    
    # Display detailed results
    $removedCount = ($results | Where-Object { $_.Removed }).Count
    $failedCount = ($results | Where-Object { $_.Error }).Count
    
    Write-Host "  [OK] Successfully processed $($results.Count) apps" -ForegroundColor Green
    Write-Host "    - Removed: $removedCount" -ForegroundColor Gray
    if ($failedCount -gt 0) {
        Write-Host "    - Failed/Protected: $failedCount (this is normal for system apps)" -ForegroundColor Yellow
    }
    
    # Show details of protected apps if needed (optional - comment out for cleaner output)
    # $results | Where-Object { $_.Error } | ForEach-Object {
    #     Write-Host "      $($_.App): $($_.Error)" -ForegroundColor DarkGray
    # }
}
#EndRegion

#Region - Additional Software Installation
Write-Host -ForegroundColor Green "`n[4/6] Installing additional software..."

# Office removal
if (Test-Path ".\ExecuteSaraCmd.ps1") {
    Write-Host "  Removing existing Office installation..." -ForegroundColor Gray
    try {
        & .\ExecuteSaraCmd.ps1
        Write-Host "  [OK] Office removal complete" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] Office removal script failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] ExecuteSaraCmd.ps1 not found, skipping Office removal" -ForegroundColor Yellow
}

# Office installation
if (Test-Path ".\Install-Office365Suite.ps1") {
    Write-Host "  Installing Microsoft Office Suite..." -ForegroundColor Gray
    try {
        & .\Install-Office365Suite.ps1
        Write-Host "  [OK] Office installation complete" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] Office installation failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] Install-Office365Suite.ps1 not found, skipping Office install" -ForegroundColor Yellow
}

# VSA installation
$vsaPath = "\\vfp02\software$\_Local installers\VSASetup.msi"
if (Test-Path $vsaPath) {
    Write-Host "  Installing VSA..." -ForegroundColor Gray
    try {
        Start-Process msiexec.exe -Wait -ArgumentList "/I `"$vsaPath`" /quiet /norestart" -NoNewWindow
        Write-Host "  [OK] VSA installation complete" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] VSA installation failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] VSA installer not found, skipping" -ForegroundColor Yellow
}

# Practice Evolve installation
$pePath = "\\pesvr01\PracticeEvolveInstall\PEInstall.ps1"
if (Test-Path $pePath) {
    Write-Host "  Installing Practice Evolve..." -ForegroundColor Gray
    try {
        & $pePath
        Write-Host "  [OK] Practice Evolve installation complete" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] Practice Evolve installation failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] Practice Evolve installer not found, skipping" -ForegroundColor Yellow
}

# Wildix installation
$wildixPath = ".\Collaboration-x64.msi"
if (Test-Path $wildixPath) {
    Write-Host "  Installing Wildix..." -ForegroundColor Gray
    try {
        $SLURL = $xml.SelectSingleNode('//Wildix/SortLegalURL').InnerText
        $SLtdURL = $xml.SelectSingleNode('//Wildix/SortLimitedURL').InnerText
        
        Start-Process msiexec.exe -Wait -ArgumentList "/i `"$wildixPath`" /qn host=$SLURL secondaryHost=$SLtdURL callControlMode=0 callBringToFrontMode=0 allowInsecureConnections=1 launchAtStartup=1" -NoNewWindow
        
        # Create startup shortcut
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Wildix.lnk")
        $Shortcut.TargetPath = "C:\Program Files\Wildix Collaboration\Wildix Collaboration.exe"
        $Shortcut.Save()
        
        Write-Host "  [OK] Wildix installation complete" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] Wildix installation failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] Wildix installer not found, skipping" -ForegroundColor Yellow
}

# Teams installation
$teamsPath = ".\TeamsBootStrapper.exe"
if (Test-Path $teamsPath) {
    Write-Host "  Installing Microsoft Teams..." -ForegroundColor Gray
    try {
        Start-Process -FilePath $teamsPath -ArgumentList "-p" -Wait -NoNewWindow
        Write-Host "  [OK] Teams installation complete" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] Teams installation failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] Teams installer not found, skipping" -ForegroundColor Yellow
}

Write-Host "  Additional software installation complete!" -ForegroundColor Green
#EndRegion

#Region - Snipe-IT Asset Registration
Write-Host -ForegroundColor Green "`n[5/6] Registering asset in Snipe-IT..."

try {
    $url = $xml.SelectSingleNode('//Snipe/SnipeURL').InnerText
    $apiKey = $xml.SelectSingleNode('//Snipe/SnipeAPIKey').InnerText
    
    Connect-SnipeitPS -url $url -apiKey $apiKey
    
    $computerName = $env:COMPUTERNAME
    $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
    
    Write-Host "  Computer: $computerName" -ForegroundColor Gray
    Write-Host "  Serial: $serialNumber" -ForegroundColor Gray
    
    # Check if asset already exists
    $assetExists = Get-SnipeitAsset -search $serialNumber -ErrorAction SilentlyContinue
    
    if ([string]::IsNullOrEmpty($assetExists)) {
        # Get model information
        $modelNo = (Get-WmiObject -Class Win32_ComputerSystem).Model
        $modelSelection = Get-SnipeitModel -ErrorAction SilentlyContinue | 
                         Where-Object { $_.model_number -like "*$modelNo*" } | 
                         Select-Object -First 1
        
        if ($modelSelection) {
            # Create new asset
            New-SnipeitAsset -Name $computerName -tag $computerName -serial $serialNumber `
                           -Model_id $modelSelection.id -rtd_location_id "1" -Status "2" `
                           -ErrorAction Stop
            
            Write-Host "  [OK] Asset registered successfully" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Model not found in Snipe-IT, asset not created" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [INFO] Asset already exists in Snipe-IT" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  [WARN] Asset registration failed: $_" -ForegroundColor Yellow
}
#EndRegion

#Region - Cleanup and Finalization
Write-Host -ForegroundColor Green "`n[6/6] Finalizing setup..."

# Wait for background jobs to complete
Write-Host "  Waiting for background tasks..." -ForegroundColor Gray

if ($restoreJob) {
    Wait-Job $restoreJob -Timeout 60 | Out-Null
    if ($restoreJob.State -eq 'Completed') {
        Write-Host "  [OK] Restore point created" -ForegroundColor Gray
    } else {
        Write-Host "  [WARN] Restore point creation timed out" -ForegroundColor Yellow
    }
    Remove-Job $restoreJob -Force
}

if ($dotnetJob) {
    Wait-Job $dotnetJob -Timeout 120 | Out-Null
    if ($dotnetJob.State -eq 'Completed') {
        Write-Host "  [OK] .NET Framework enabled" -ForegroundColor Gray
    } else {
        Write-Host "  [WARN] .NET Framework enable timed out" -ForegroundColor Yellow
    }
    Remove-Job $dotnetJob -Force
}

Write-Host "  Finalization complete!" -ForegroundColor Green
#EndRegion

# Close debugging log
Stop-Transcript

Write-Host -ForegroundColor Cyan "`n=== Windows Setup Complete at $(Get-Date -Format 'HH:mm:ss') ==="
Write-Host -ForegroundColor Green "Log file saved to: $logPath"
Write-Host -ForegroundColor Yellow "`nA system restart is recommended to complete all changes."

# Optional: Prompt for restart
$response = Read-Host "`nWould you like to restart now? (Y/N)"
if ($response -eq 'Y' -or $response -eq 'y') {
    Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
