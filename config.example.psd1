@{
    # Working directory created on the target machine during setup
    # e.g. 'C:\Windows-Setup'
    RootPath = ''

    # Files downloaded by the Initialise script onto the target machine.
    # UseWebRequest = $true  → Invoke-WebRequest (small text files)
    # UseWebRequest = $false → BITS transfer (large binaries, resumable)
    Downloads = @(
        @{
            Url           = ''   # URL to WindowsSetup.ps1
            Destination   = ''   # e.g. C:\Windows-Setup\WindowsSetup.ps1
            UseWebRequest = $true
        },
        @{
            Url           = ''   # URL to ExecuteSaraCmd.ps1
            Destination   = ''   # e.g. C:\Windows-Setup\ExecuteSaraCmd.ps1
            UseWebRequest = $true
        },
        @{
            Url           = ''   # URL to Install-Office365Suite.ps1
            Destination   = ''   # e.g. C:\Windows-Setup\Install-Office365Suite.ps1
            UseWebRequest = $true
        },
        @{
            Url           = ''   # URL to Teams bootstrapper .exe
            Destination   = ''   # e.g. C:\Windows-Setup\TeamsBootStrapper.exe
            UseWebRequest = $false
        },
        @{
            Url           = ''   # URL to Wildix Collaboration MSI
            Destination   = ''   # e.g. C:\Windows-Setup\Collaboration-x64.msi
            UseWebRequest = $false
        }
    )

    # Configuration files to copy from a network share onto the target machine
    NetworkFiles = @(
        @{
            Source      = ''   # UNC path e.g. \\server\share\WindowsSetup.xml
            Destination = ''   # Local path e.g. C:\Windows-Setup\WindowsSetup.xml
        },
        @{
            Source      = ''   # UNC path e.g. \\server\share\UserBasedLicencingConfiguration.xml
            Destination = ''   # Local path
        }
    )

    # Registry paths used during system hardening.
    # These are standard Windows paths — safe to leave as-is unless your environment differs.
    RegPaths = @{
        SystemRestore   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        LlmnrDnsClient  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        NbtNsInterfaces = 'HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces'
    }

    # Citrix desktop shortcut created on the target machine
    Citrix = @{
        ShortcutPath = ''   # e.g. C:\Users\Public\Desktop\Citrix.lnk
        TargetUrl    = ''   # e.g. https://yourorg.cloud.com/
        IconPath     = ''   # e.g. C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    }

    # Paths to software installers
    Installers = @{
        VsaMsiPath         = ''   # UNC or local path to VSA .msi
        PracticeEvolvePath = ''   # UNC path to PracticeEvolve install script (.ps1)
        WildixMsiPath      = ''   # Local path to Wildix MSI (downloaded by Initialise)
    }

    # Wildix client paths — used after the MSI has installed
    Wildix = @{
        StartupShortcutPath = ''   # e.g. C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Wildix.lnk
        ExePath             = ''   # e.g. C:\Program Files\Wildix Collaboration\Wildix Collaboration.exe
    }
}
