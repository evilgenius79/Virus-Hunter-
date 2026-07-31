# Synaptics.exe Trojan Removal Tool

[![validate](https://github.com/evilgenius79/Virus-Hunter-/actions/workflows/validate.yml/badge.svg)](https://github.com/evilgenius79/Virus-Hunter-/actions/workflows/validate.yml)

A defensive PowerShell remediation script for the **"Synaptics.exe" trojan**
(also known as **Xred**) — a malware family that disguises itself as the
legitimate Synaptics touchpad driver, **infects your other programs** (keeping
the clean original beside them as `._cache_<name>.exe`), spreads via USB drives
and infected Office documents, hides your real files, and adds itself to Windows
startup. It also cleans the **generic USB shortcut-worm pattern** (hidden
folders replaced by decoy `.lnk` files, hidden script droppers) used by families
like Jenxcus/Houdini and Gamarue.

> **How it decides what's malicious (trust model):** a file matching the
> malware's names is treated as **genuine only if it carries a valid
> Authenticode signature whose subject CN is "Synaptics."** This is stronger
> than trusting a file just because it lives in `C:\Program Files\Synaptics\` —
> it catches malware that drops *into* Program Files, and avoids deleting a
> legitimately signed file found elsewhere. As an extra guard, the tool will
> **never delete** anything inside `C:\Program Files\Synaptics\`.
> Where a heuristic isn't certain (visible scripts on a USB root, unfamiliar
> WMI consumers or IFEO debuggers), the tool **flags for manual review instead
> of deleting**.

## What it does

1. **Requires Administrator rights** and refuses to run without them.
2. **Creates a System Restore checkpoint** first (on live runs), so you can roll
   back if needed.
3. **Finds and kills** `Synaptics` / `wszui` / `wszqms` / `wszust` processes that
   are *not* validly signed by Synaptics — sweeping repeatedly, because these
   worms often run as watchdog pairs that restart each other. Files it can't
   delete because they're still locked are **scheduled for deletion at the next
   reboot**.
4. **Repairs infected programs** — where Xred wrapped one of your `.exe` files
   and kept the clean original as `._cache_<name>.exe`, the infected file is
   replaced with the clean copy, so you get your program back instead of losing
   it.
5. **Removes persistence** beyond the basics:
   - Malicious **scheduled tasks** and **services**.
   - Registry **`Run` / `RunOnce`** entries under `HKCU` and `HKLM`, plus the
     old **`Load` / `Run`** values under the HKCU Windows key.
   - Hijacked **Winlogon** `Shell` / `Userinit` values (repaired to defaults).
   - Malicious **Startup-folder** shortcuts.
   - Malicious **WMI event subscriptions** and **IFEO "Debugger"** hijacks
     (unfamiliar but non-family ones are flagged for review, not removed).
6. **Cleans the Office/Excel infection vector** — removes malicious files from
   the **XLSTART** folders and resets the macro-security keys (`AccessVBOM`,
   `VBAWarnings`) the worm lowers. Without this, Excel can reinfect the machine.
7. **Cleans removable (USB) drives** — unsigned `Synaptics*.exe` droppers,
   `autorun.inf`, decoy `.lnk` shortcuts (including ones masquerading as your
   hidden folders or launching script hosts), hidden script droppers, and
   "folder-icon" worm copies named after real folders. USB *hard drives* show
   up to Windows as fixed disks, not removable — add them with
   `-AlsoScanDrives D,E`.
8. **Deletes** the known malicious folders/files and the executables of the
   processes it terminated.
9. **Repairs the hosts file** — removes entries that blackhole antivirus or
   Windows-update domains (a backup of the original is saved first).
10. **(Optional) Confirms via VirusTotal** — with `-VirusTotalApiKey`, looks up
    the SHA256 of each detected file and logs its detection ratio. Read-only; it
    never changes what the tool deletes, and it paces requests to respect the
    free-tier rate limit.
11. **Repairs Explorer** so hidden files and extensions show again, then
    **un-hides** files the malware marked Hidden/System (it only clears the
    attributes — it never deletes your data).
12. **Writes a detailed log** to your Desktop.

## How to run it safely (step by step for a layperson)

1. **Save the file.** Download `Remove-SynapticsTrojan.ps1` to your Desktop.

2. **Open PowerShell as Administrator.**
   - Click the Start button, type **PowerShell**.
   - **Right-click** "Windows PowerShell" and choose **"Run as administrator"**.
   - Click **Yes** if Windows asks for permission.

3. **Go to your Desktop** inside the blue PowerShell window by typing this and
   pressing Enter:
   ```powershell
   cd "$env:USERPROFILE\Desktop"
   ```

4. **Do a safe test run first (changes nothing).** This shows you exactly what
   the tool *would* remove, without deleting anything:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Remove-SynapticsTrojan.ps1 -DryRun
   ```
   Read the output. Lines marked `WOULD ...` are what it plans to do.

5. **Run it for real** once you're comfortable:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Remove-SynapticsTrojan.ps1
   ```

6. **Check the log.** A file like
   `SynapticsTrojan-Cleanup_YYYYMMDD_HHMMSS.log` is saved on your Desktop with a
   full record of what was found, terminated, and deleted.

7. **Finish up.** Restart your computer, then run a **full scan with a reputable
   antivirus** (Windows Defender is fine). This script is a focused remediation
   aid, not a complete replacement for antivirus software.

### Tips
- If you see a red message about Administrator rights, you skipped step 2 —
  re-open PowerShell with **Run as administrator**.
- The `-ExecutionPolicy Bypass` part only affects that single run; it does not
  weaken your system's settings permanently.
- Keep the log file in case you need to show what was removed.

## Parameters

| Parameter | Description |
|---|---|
| `-DryRun` | Report-only. Makes **no** changes. Use this first. |
| `-LogPath <path>` | Where to write the log (defaults to the Desktop). |
| `-ScanRemovableDrives` | Also scan USB drive roots for droppers (on by default). |
| `-AlsoScanDrives D,E` | Extra drive letters to treat like removable drives (USB hard drives report as fixed disks). The system drive is refused. |
| `-NoRestorePoint` | Skip creating the System Restore checkpoint on live runs. |
| `-VirusTotalApiKey <key>` | Optional. Look up detected files' SHA256 on VirusTotal and log the detection ratio (read-only). |

## Exit codes

The script's exit code tells you the outcome at a glance (useful for scheduled
runs and technicians):

| Code | Meaning |
|---|---|
| `0` | Nothing malicious found. |
| `1` | Not run as Administrator — nothing was scanned. |
| `2` | Infections were found (and removed, unless `-DryRun`). Check the log. |
| `3` | One or more errors occurred — read the log before assuming the machine is clean. |

## Known limitations

- **Infected Office documents are not repaired.** Xred can inject macros into
  workbooks themselves. Detecting that reliably requires parsing VBA streams,
  which is beyond a remediation script — after cleanup, re-scan your `.xls` /
  `.xlsm` files with your antivirus and be suspicious of workbooks that grew in
  size around the infection date.
- **`AppData` is not un-hidden.** The un-hide step deliberately skips `AppData`
  (many things there are legitimately hidden). If the worm hid something there
  specifically, un-hide it manually.
- This is a **focused remediation aid, not an antivirus**. Follow up with a
  full AV scan after rebooting.

## Development & testing

Every push runs a GitHub Actions workflow on a Windows runner that parses the
script under both Windows PowerShell 5.1 and PowerShell 7, lints it with
PSScriptAnalyzer, and runs the Pester unit tests in `tests/`. Dot-sourcing the
script (`. .\Remove-SynapticsTrojan.ps1`) loads its functions without
performing any cleanup, which is what the tests rely on.

## Disclaimer

This tool is provided for legitimate cleanup of systems you own or are
authorized to administer. Always test with `-DryRun` first and keep backups of
important data.
