# Windows Setup Automation

Automated Windows device imaging scripts used by Sort Group IT while the Intune rollout is pending. Replaces the previous manual setup process.

---

## What it does

A technician runs a single initialisation script on a freshly imaged machine. It downloads everything needed, then hands off to the main setup script which configures the OS, removes bloatware, installs software, and registers the device in Snipe-IT — all with minimal interaction.

---

## Scripts

### `WindowsSetupInitialise-Optimised.ps1`
**Run this one first, manually.**

1. Creates the working directory (`C:\Windows-Setup\`) on the target machine
2. Installs required PowerShell modules (`SnipeitPS`, `PSWindowsUpdate`) in parallel
3. Downloads required files from the internet in parallel (scripts, Teams bootstrapper, Wildix MSI)
4. Copies XML configuration files from the network share onto the target machine
5. Launches `WindowsSetup.ps1` automatically

### `WindowsSetup-Optimised.ps1`
**Launched automatically by the Initialise script. Can also be run standalone.**

Runs in six stages:

| Stage | What it does |
|-------|-------------|
| 1/6 | System configuration — registry hardening, boot menu, power settings, regional/locale (en-GB), .NET Framework, SMB signing |
| 2/6 | Chocolatey installation and software deployment (Chrome, Adobe Reader, 7-Zip, Citrix Workspace) |
| 3/6 | Bloatware removal — app list sourced from `WindowsSetup.xml` |
| 4/6 | Additional software — Office removal (SaRA), Office 365, VSA, Practice Evolve, Wildix, Teams |
| 5/6 | Snipe-IT asset registration |
| 6/6 | Cleanup, wait for background jobs, optional restart |

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| PowerShell | Version 5.1 or later (built into Windows 10/11) |
| Permissions | Must be run as Administrator — scripts will self-elevate if not |
| Network access | Must be able to reach `\\vfp02\software$` and `\\pesvr01\PracticeEvolveInstall` |
| Internet access | Required during Initialise for downloads (GitHub, Microsoft, Wildix) |
| PSGallery | Script sets it as Trusted automatically |
| `WindowsSetup.xml` | Must exist on the network share — contains bloatware list, Wildix URLs, Snipe-IT credentials |

The Chocolatey install requires internet access and downloads from `community.chocolatey.org`. No pre-installation of Chocolatey is needed — the script installs it.

---

## Configuration

All environment-specific values (paths, URLs, network shares) live in `Config.psd1`.

**This file is excluded from git and must never be committed.** Use `config.example.psd1` as a template.

### First-time setup

1. Copy `config.example.psd1` to `Config.psd1` in the repo root
2. Fill in every empty value — comments in the example file explain each one
3. Verify the network share paths are reachable from a target machine before running

### Config file structure

```
Config.psd1
├── RootPath              — working directory created on the target machine
├── Downloads[]           — files downloaded during Initialise (URLs + destinations)
├── NetworkFiles[]        — files copied from the network share (source + destination)
├── RegPaths{}            — registry key paths used during hardening
├── Citrix{}              — Citrix desktop shortcut details
├── Installers{}          — paths to VSA MSI, Practice Evolve script, Wildix MSI
└── Wildix{}              — Wildix shortcut and executable paths (post-install)
```

> **Note:** Snipe-IT credentials (URL and API key) and Wildix server URLs are stored in `WindowsSetup.xml` on the network share, not in `Config.psd1`.

---

## How to run

### Full imaging run (recommended)

1. On the target machine, open PowerShell as Administrator
2. Navigate to the repo or copy `WindowsSetupInitialise-Optimised.ps1` and `Config.psd1` locally
3. Run:
   ```powershell
   .\WindowsSetupInitialise-Optimised.ps1
   ```
4. The script will create the working directory, download files, and launch the main setup automatically

### Running the main script standalone

If the working directory is already set up (files downloaded, XML in place):

```powershell
.\WindowsSetup-Optimised.ps1
```

Ensure `Config.psd1` and `WindowsSetup.xml` are both present in the same directory.

### Logs

Each run of `WindowsSetup-Optimised.ps1` creates a timestamped transcript in `C:\Windows-Setup\Logs\`. Check here first if anything goes wrong.

---

## If something breaks

**Check the log first** — `C:\Windows-Setup\Logs\WindowsSetupLog_<timestamp>.txt`

| Symptom | Likely cause | What to try |
|---------|-------------|-------------|
| Script won't start | Not running as Administrator | Right-click → Run as Administrator |
| `Config.psd1 not found` | File missing or wrong directory | Ensure `Config.psd1` is in the same folder as the script |
| XML errors at stage 1 | `WindowsSetup.xml` missing or network share unreachable | Check `\\vfp02\software$` is accessible |
| Chocolatey fails | No internet, or proxy blocking `community.chocolatey.org` | Check internet/proxy access |
| Snipe-IT registration fails | Credentials in XML expired, or API down | Check XML credentials manually, or skip and register in Snipe-IT manually |
| Module install fails | PSGallery unreachable | Run Initialise with internet access; modules can also be installed manually |
| Wildix not installed | Known issue — MSI invocation method needs updating (Phase 2 work) | Install Wildix manually from `C:\Windows-Setup\Collaboration-x64.msi` |

**Contact:** Sort Group IT — original script author: Conrad Kent. Current maintainer: Tom Brown.

---

## Repository structure

```
WindowsSetup/
├── WindowsSetupInitialise-Optimised.ps1   — run first; downloads files and launches setup
├── WindowsSetup-Optimised.ps1             — main imaging script
├── config.example.psd1                    — template for Config.psd1 (safe to commit)
├── Config.psd1                            — EXCLUDED from git; contains real paths
├── .gitignore
├── OfficeSetup/
│   ├── ExecuteSaraCmd.ps1                 — Microsoft SaRA tool for Office removal
│   └── Install-Office365Suite.ps1         — Office 365 installation script
└── Logs/                                  — created on target machines; excluded from git
```
