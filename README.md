# Synaptics.exe Trojan Removal Tool

A defensive PowerShell remediation script for the **"Synaptics.exe" trojan** — a
malware family that disguises itself as the legitimate Synaptics touchpad driver,
spreads via USB drives and infected Office documents, hides your real files, and
adds itself to Windows startup.

> **How it decides what's malicious (trust model):** a file matching the
> malware's names is treated as **genuine only if it carries a valid
> Authenticode signature from "Synaptics."** This is stronger than trusting a
> file just because it lives in `C:\Program Files\Synaptics\` — it catches
> malware that drops *into* Program Files, and avoids deleting a legitimately
> signed file found elsewhere. As an extra guard, the tool will **never delete**
> anything inside `C:\Program Files\Synaptics\`.

## What it does

1. **Requires Administrator rights** and refuses to run without them.
2. **Creates a System Restore checkpoint** first (on live runs), so you can roll
   back if needed.
3. **Finds and kills** `Synaptics` / `wszui` / `wszqms` / `wszust` processes that
   are *not* validly signed by Synaptics.
4. **Removes persistence** beyond the basics:
   - Malicious **scheduled tasks** and **services**.
   - Registry **`Run` and `RunOnce`** entries under `HKCU` and `HKLM`.
   - Hijacked **Winlogon** `Shell` / `Userinit` values (repaired to defaults).
   - Malicious **Startup-folder** shortcuts.
5. **Cleans the Office/Excel infection vector** — removes malicious files from
   the **XLSTART** folders and resets the macro-security keys (`AccessVBOM`,
   `VBAWarnings`) the worm lowers. Without this, Excel can reinfect the machine.
6. **Cleans removable (USB) drives** — hidden `Synaptics*.exe` droppers,
   `autorun.inf`, and malicious `.lnk` decoy shortcuts.
7. **Deletes** the known malicious folders/files and the executables of the
   processes it terminated.
8. **Repairs Explorer** so hidden files and extensions show again, then
   **un-hides** files the malware marked Hidden/System (it only clears the
   attributes — it never deletes your data).
9. **Writes a detailed log** to your Desktop.

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
| `-NoRestorePoint` | Skip creating the System Restore checkpoint on live runs. |

## Disclaimer

This tool is provided for legitimate cleanup of systems you own or are
authorized to administer. Always test with `-DryRun` first and keep backups of
important data.
