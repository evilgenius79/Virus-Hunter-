# Synaptics.exe Trojan Removal Tool

A defensive PowerShell remediation script for the **"Synaptics.exe" trojan** — a
malware family that disguises itself as the legitimate Synaptics touchpad driver,
spreads via USB drives and infected Office documents, hides your real files, and
adds itself to Windows startup.

> **Important:** The *genuine* Synaptics driver lives in
> `C:\Program Files\Synaptics\`. This tool treats that location as trusted and
> **never** touches it. It only acts on copies running or stored in the usual
> malware locations (`C:\ProgramData\Synaptics`, `C:\Users\Public\`, AppData,
> and the root of USB drives).

## What it does

1. **Requires Administrator rights** and refuses to run without them.
2. **Finds and kills** `Synaptics` / `wszui.exe` processes that run from outside
   `C:\Program Files\Synaptics\`.
3. **Deletes** the known malicious folders/files and hidden `Synaptics*.exe`
   droppers on the root of removable (USB) drives.
4. **Cleans the registry** — removes malicious startup entries from the `Run`
   keys under `HKCU` and `HKLM`.
5. **Repairs Explorer** so hidden files and file extensions show again, then
   **un-hides** files the malware marked Hidden/System.
6. **Writes a detailed log** to your Desktop.

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

## Disclaimer

This tool is provided for legitimate cleanup of systems you own or are
authorized to administer. Always test with `-DryRun` first and keep backups of
important data.
