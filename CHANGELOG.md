# Changelog

---

## [2026-03-24] — Phase 1: Config file refactor
**Scripts:** `WindowsSetupInitialise-Optimised.ps1`, `WindowsSetup-Optimised.ps1`
**Author:** Tom Brown

- Extracted all hardcoded paths and URLs into `Config.psd1`
- Both scripts now import config via `Import-PowerShellDataFile` at startup with an early-exit check if the file is missing
- Added `Config.psd1` to `.gitignore` to prevent credentials and internal paths from being committed
- Created `config.example.psd1` as a safe-to-commit template for new staff
- Rewrote `Config.psd1` as a valid PowerShell data file (previous version was a mix of code fragments and could not be imported)

---

## [2026-02-03] — Version 2.0: Optimised rewrite
**Scripts:** `WindowsSetupInitialise-Optimised.ps1`, `WindowsSetup-Optimised.ps1`
**Author:** Conrad Kent

### WindowsSetupInitialise-Optimised.ps1

- **Parallel module installation** — `SnipeitPS` and `PSWindowsUpdate` now installed via background jobs simultaneously rather than sequentially
- **Parallel file downloads** — files downloaded concurrently using `Start-BitsTransfer` (large binaries) and `Invoke-WebRequest` (scripts), with a live progress indicator
- **BITS for large files** — Teams bootstrapper and Wildix MSI use BITS (`Start-BitsTransfer`) rather than WebRequest; faster and resumable if interrupted
- **Progress indicators** — download progress displayed during parallel operations
- **Better error handling** — failed downloads reported individually rather than crashing the whole script

### WindowsSetup-Optimised.ps1

- **Parallel app removal** — bloatware removal uses background jobs per app rather than sequential processing; includes progress bar and per-app result reporting
- **Robust removal error handling** — both AppX and provisioned package removal wrapped in separate try/catch blocks; a failure on one app does not stop removal of others; protected/system apps reported as informational rather than errors
- **Registry operations batched** — system hardening registry writes collected into an array and processed in a single loop for better structure and performance
- **Restore point created asynchronously** — `Checkpoint-Computer` runs as a background job (`$restoreJob`) to avoid blocking the rest of setup; waited on at the end
- **.NET Framework enabled asynchronously** — `Enable-WindowsOptionalFeature` for NetFx3 runs as a background job (`$dotnetJob`) for the same reason
- **Power settings batched** — all eight `powercfg` timeout settings applied in a single `ForEach-Object` loop
- **Better error handling and logging** — `Start-Transcript` captures full session output to a timestamped log file; all operations wrapped in try/catch with `[OK]`/`[WARN]` output
- **Progress indicators** — each of the six stages labelled; app removal shows percentage progress
- **Reduced redundant operations** — removed duplicate calls present in the original script

---

## [UNKNOWN] — Version 1.0: Original script
**Author:** Conrad Kent

Initial implementation covering:
- System configuration (registry, power, locale, SMB, restore point)
- Chocolatey installation and package deployment
- Bloatware removal from XML list
- Office removal and reinstall
- VSA, Practice Evolve, Wildix, Teams installation
- Snipe-IT asset registration
- Optional restart prompt
