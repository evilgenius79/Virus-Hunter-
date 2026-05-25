#Requires -Version 5.1
<#
.SYNOPSIS
    Dedicated removal tool for the "Synaptics.exe" trojan family.

.DESCRIPTION
    This script detects and removes the well-known "Synaptics.exe" malware (an
    XLS/USB-spreading dropper that masquerades as the legitimate Synaptics
    touchpad driver). It is written to be conservative: the genuine driver that
    lives under C:\Program Files\Synaptics\ is treated as trusted and is never
    touched. Anything named like the malware that runs from a NON-trusted
    location is treated as suspicious.

    Actions performed:
      1. Verifies it is running with Administrator privileges.
      2. Finds running processes named Synaptics / wszui and inspects their
         on-disk path. Processes running from outside Program Files are killed.
      3. Removes the known malicious folders/files (e.g. C:\ProgramData\Synaptics)
         and hidden Synaptics*.exe droppers found on the root of removable drives.
      4. Scans the HKCU and HKLM ...\CurrentVersion\Run keys and removes startup
         entries that point at the malicious paths.
      5. Repairs the Explorer registry values the malware flips to hide files,
         then clears the Hidden/System attributes the malware sets on files.
      6. Writes a detailed, timestamped text log of everything it did.

    SAFETY: Run with -DryRun first. In DryRun mode the script only reports what
    it WOULD do and changes nothing. Re-run without -DryRun to apply changes.

.PARAMETER DryRun
    Report-only mode. No process is killed, no file/registry change is made.
    STRONGLY RECOMMENDED for the first run.

.PARAMETER LogPath
    Where to write the log file. Defaults to the user's Desktop.

.PARAMETER ScanRemovableDrives
    Also scan the root of removable (USB) drives for hidden Synaptics droppers.
    Enabled by default.

.EXAMPLE
    PS> .\Remove-SynapticsTrojan.ps1 -DryRun
    Shows everything the tool would remove, without changing anything.

.EXAMPLE
    PS> .\Remove-SynapticsTrojan.ps1
    Performs the actual cleanup and writes a log to the Desktop.

.NOTES
    Author : Senior Cybersecurity Engineer
    Tested : Windows 10 / 11, Windows Server 2016+ (PowerShell 5.1+)
    This is a remediation aid, not a replacement for a full AV scan. After
    running it, perform a full scan with a reputable antivirus product.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$LogPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) ("SynapticsTrojan-Cleanup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))),
    [switch]$ScanRemovableDrives = $true
)

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

# The ONLY directory where a legitimate Synaptics executable is allowed to live.
# Anything matching our target names running/stored elsewhere is suspect.
$TrustedRoot = Join-Path $env:ProgramFiles 'Synaptics'

# Process base names (no extension) we care about.
$TargetProcessNames = @('Synaptics', 'wszui')

# Known malicious folders/files. These are the classic drop locations for this
# malware family. The legitimate driver is never in these places.
$KnownMaliciousPaths = @(
    (Join-Path $env:ProgramData 'Synaptics'),                      # C:\ProgramData\Synaptics
    (Join-Path $env:ProgramData 'Synaptics\Synaptics.exe'),
    (Join-Path $env:ProgramData 'Synaptics\wszqms.exe'),
    (Join-Path $env:PUBLIC      'Synaptics.exe'),                   # C:\Users\Public\Synaptics.exe
    (Join-Path $env:APPDATA     'Synaptics'),                       # roaming AppData
    (Join-Path $env:LOCALAPPDATA 'Synaptics')                      # local AppData
)

# Registry Run keys to inspect.
$RunKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
)

# ----------------------------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------------------------

$script:LogLines = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO', 'FOUND', 'ACTION', 'WARN', 'ERROR', 'OK')]
        [string]$Level = 'INFO'
    )
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[{0}] [{1,-6}] {2}" -f $stamp, $Level, $Message
    $script:LogLines.Add($line)

    switch ($Level) {
        'FOUND'  { Write-Host $line -ForegroundColor Yellow }
        'ACTION' { Write-Host $line -ForegroundColor Cyan }
        'WARN'   { Write-Host $line -ForegroundColor Magenta }
        'ERROR'  { Write-Host $line -ForegroundColor Red }
        'OK'     { Write-Host $line -ForegroundColor Green }
        default  { Write-Host $line }
    }
}

function Save-Log {
    try {
        $header = @(
            '============================================================',
            ' Synaptics.exe Trojan Removal Tool - Cleanup Log',
            (' Generated : {0}' -f (Get-Date)),
            (' Computer  : {0}' -f $env:COMPUTERNAME),
            (' User      : {0}' -f $env:USERNAME),
            (' Mode      : {0}' -f $(if ($DryRun) { 'DRY RUN (no changes made)' } else { 'LIVE (changes applied)' })),
            '============================================================',
            ''
        )
        ($header + $script:LogLines) | Set-Content -Path $LogPath -Encoding UTF8
        Write-Host ""
        Write-Host "Log written to: $LogPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Could not write log file to '$LogPath': $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsTrustedPath {
    # Returns $true only if the supplied path lives under the legitimate
    # C:\Program Files\Synaptics\ tree. Used to whitelist the real driver.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $full    = [System.IO.Path]::GetFullPath($Path)
        $trusted = [System.IO.Path]::GetFullPath($TrustedRoot)
        return $full.StartsWith($trusted, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Remove-ItemSecurely {
    # Clears read-only/hidden/system attributes, then deletes. Honors DryRun.
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "Path not present (nothing to delete): $Path" -Level INFO
        return
    }

    if (Test-IsTrustedPath $Path) {
        Write-Log "REFUSING to delete trusted path: $Path" -Level WARN
        return
    }

    if ($DryRun) {
        Write-Log "WOULD delete: $Path" -Level ACTION
        return
    }

    try {
        # Strip protective attributes from the item and everything beneath it.
        Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
        try { (Get-Item -LiteralPath $Path -Force).Attributes = 'Normal' } catch {}

        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted: $Path" -Level OK
    }
    catch {
        Write-Log "FAILED to delete '$Path': $($_.Exception.Message)" -Level ERROR
    }
}

# ----------------------------------------------------------------------------
# Step 1 - Administrator check
# ----------------------------------------------------------------------------

function Assert-Administrator {
    Write-Log "Checking for Administrator privileges..." -Level INFO
    if (-not (Test-IsAdmin)) {
        Write-Log "This script must be run as Administrator. Aborting." -Level ERROR
        Write-Host ""
        Write-Host "  >> Right-click PowerShell and choose 'Run as administrator', then re-run this script. <<" -ForegroundColor Red
        Save-Log
        exit 1
    }
    Write-Log "Administrator privileges confirmed." -Level OK
}

# ----------------------------------------------------------------------------
# Step 2 - Process detection & termination
# ----------------------------------------------------------------------------

function Stop-MaliciousProcesses {
    Write-Log "Scanning running processes for $($TargetProcessNames -join ', ')..." -Level INFO
    $suspectPaths = New-Object System.Collections.Generic.List[string]

    foreach ($name in $TargetProcessNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) {
            Write-Log "No running process named '$name'." -Level INFO
            continue
        }

        foreach ($p in $procs) {
            $exePath = $null
            try { $exePath = $p.Path } catch { $exePath = $null }

            if ([string]::IsNullOrWhiteSpace($exePath)) {
                # Path inaccessible (often the case for protected/malicious procs).
                Write-Log "Process '$name' (PID $($p.Id)) path could not be read - treating as suspicious." -Level FOUND
            }
            elseif (Test-IsTrustedPath $exePath) {
                Write-Log "Process '$name' (PID $($p.Id)) runs from trusted path '$exePath' - leaving it alone." -Level OK
                continue
            }
            else {
                Write-Log "Process '$name' (PID $($p.Id)) runs from UNTRUSTED path '$exePath'." -Level FOUND
            }

            if ($exePath) { $suspectPaths.Add($exePath) | Out-Null }

            if ($DryRun) {
                Write-Log "WOULD terminate process '$name' (PID $($p.Id))." -Level ACTION
            }
            else {
                try {
                    Stop-Process -Id $p.Id -Force -ErrorAction Stop
                    Write-Log "Terminated process '$name' (PID $($p.Id))." -Level OK
                }
                catch {
                    Write-Log "FAILED to terminate '$name' (PID $($p.Id)): $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }

    return $suspectPaths
}

# ----------------------------------------------------------------------------
# Step 3 - File / folder cleanup
# ----------------------------------------------------------------------------

function Remove-MaliciousFiles {
    param([System.Collections.Generic.List[string]]$ExtraPaths)

    Write-Log "Cleaning up known malicious file/folder locations..." -Level INFO

    foreach ($path in $KnownMaliciousPaths) {
        if (Test-Path -LiteralPath $path) {
            Write-Log "Detected malicious item: $path" -Level FOUND
            Remove-ItemSecurely -Path $path
        }
    }

    # The actual executable paths of processes we just killed.
    if ($ExtraPaths) {
        foreach ($path in ($ExtraPaths | Sort-Object -Unique)) {
            if (Test-Path -LiteralPath $path) {
                Write-Log "Removing executable of terminated process: $path" -Level FOUND
                Remove-ItemSecurely -Path $path
            }
        }
    }
}

function Remove-RemovableDriveDroppers {
    if (-not $ScanRemovableDrives) { return }

    Write-Log "Scanning removable drive roots for hidden Synaptics droppers..." -Level INFO
    # DriveType 2 = Removable (USB sticks, external flash, etc.)
    $removable = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 2' -ErrorAction SilentlyContinue

    if (-not $removable) {
        Write-Log "No removable drives detected." -Level INFO
        return
    }

    foreach ($drive in $removable) {
        $root = $drive.DeviceID + '\'
        Write-Log "Inspecting removable drive root: $root" -Level INFO

        $droppers = Get-ChildItem -LiteralPath $root -Filter 'Synaptics*.exe' -Force -ErrorAction SilentlyContinue |
                    Where-Object { -not $_.PSIsContainer }

        if (-not $droppers) {
            Write-Log "No Synaptics droppers on $root." -Level INFO
            continue
        }

        foreach ($file in $droppers) {
            # A genuine Synaptics.exe will not sit in the root of a USB stick,
            # especially hidden. Flag it.
            $isHidden = ($file.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
            Write-Log ("Found dropper '{0}' on removable drive (Hidden={1})." -f $file.FullName, $isHidden) -Level FOUND
            Remove-ItemSecurely -Path $file.FullName
        }
    }
}

# ----------------------------------------------------------------------------
# Step 4 - Registry Run-key cleanup
# ----------------------------------------------------------------------------

function Remove-MaliciousRunKeys {
    Write-Log "Scanning registry Run keys for malicious startup entries..." -Level INFO

    foreach ($key in $RunKeys) {
        if (-not (Test-Path -LiteralPath $key)) {
            Write-Log "Run key not present: $key" -Level INFO
            continue
        }

        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop }
        catch {
            Write-Log "Could not read '$key': $($_.Exception.Message)" -Level WARN
            continue
        }

        foreach ($valueName in ($props.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
            $valueData = [string]$props.$valueName

            # Decide if this entry is malicious: it references our target names
            # AND does not point at the trusted Program Files location.
            $mentionsTarget = $false
            foreach ($n in $TargetProcessNames) {
                if ($valueData -match [regex]::Escape($n)) { $mentionsTarget = $true; break }
            }
            if (-not $mentionsTarget) { continue }

            # Extract the executable path from the command line for the trust test.
            $exeCandidate = $valueData.Trim('"')
            if ($exeCandidate -match '^\s*"?([^"]+\.exe)') { $exeCandidate = $Matches[1] }

            if (Test-IsTrustedPath $exeCandidate) {
                Write-Log "Run entry '$valueName' in $key points to trusted driver - leaving it." -Level OK
                continue
            }

            Write-Log "Malicious Run entry found in ${key}: '$valueName' = '$valueData'" -Level FOUND

            if ($DryRun) {
                Write-Log "WOULD remove Run value '$valueName' from $key." -Level ACTION
            }
            else {
                try {
                    Remove-ItemProperty -LiteralPath $key -Name $valueName -ErrorAction Stop
                    Write-Log "Removed Run value '$valueName' from $key." -Level OK
                }
                catch {
                    Write-Log "FAILED to remove Run value '$valueName' from ${key}: $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 5 - Repair Explorer "hide files" settings & un-hide files
# ----------------------------------------------------------------------------

function Repair-HiddenFileSettings {
    Write-Log "Repairing Explorer settings the malware uses to hide files..." -Level INFO

    $advanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'

    # Values the malware flips:
    #   Hidden      : should be 1 (show hidden files)
    #   ShowSuperHidden : should be 1 (show protected OS files)
    #   HideFileExt : should be 0 (show file extensions)
    $desired = @{
        'Hidden'          = 1
        'ShowSuperHidden' = 1
        'HideFileExt'     = 0
    }

    if (-not (Test-Path -LiteralPath $advanced)) {
        Write-Log "Explorer Advanced key not found: $advanced" -Level WARN
        return
    }

    foreach ($name in $desired.Keys) {
        $want = $desired[$name]
        $current = $null
        try { $current = (Get-ItemProperty -LiteralPath $advanced -Name $name -ErrorAction Stop).$name } catch {}

        if ($current -eq $want) {
            Write-Log "Explorer setting '$name' already correct ($want)." -Level OK
            continue
        }

        Write-Log "Explorer setting '$name' is '$current', should be '$want'." -Level FOUND
        if ($DryRun) {
            Write-Log "WOULD set '$name' = $want in $advanced." -Level ACTION
        }
        else {
            try {
                Set-ItemProperty -LiteralPath $advanced -Name $name -Value $want -Type DWord -ErrorAction Stop
                Write-Log "Set Explorer '$name' = $want." -Level OK
            }
            catch {
                Write-Log "FAILED to set '$name': $($_.Exception.Message)" -Level ERROR
            }
        }
    }
}

function Restore-HiddenItems {
    # The malware sets Hidden+System on legitimate user files/folders so the
    # victim's own data appears to "disappear". This clears those attributes
    # in common user locations. It only removes Hidden/System; it never deletes.
    Write-Log "Restoring visibility of files hidden by the malware (clearing Hidden/System attributes)..." -Level INFO

    $scanRoots = New-Object System.Collections.Generic.List[string]
    $scanRoots.Add($env:USERPROFILE)

    if ($ScanRemovableDrives) {
        $removable = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 2' -ErrorAction SilentlyContinue
        foreach ($d in $removable) { $scanRoots.Add($d.DeviceID + '\') }
    }

    foreach ($root in $scanRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Write-Log "Un-hiding items under: $root" -Level INFO

        $hiddenItems = Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                (($_.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0 -or
                 ($_.Attributes -band [System.IO.FileAttributes]::System) -ne 0)
            }

        foreach ($item in $hiddenItems) {
            # Skip genuine OS hidden files we shouldn't touch.
            if ($item.Name -in @('desktop.ini', 'thumbs.db', 'ntuser.dat')) { continue }
            if ($item.FullName -match '\\(AppData|\.git)\\') { continue }

            if ($DryRun) {
                Write-Log "WOULD clear Hidden/System on: $($item.FullName)" -Level ACTION
            }
            else {
                try {
                    $item.Attributes = $item.Attributes -band `
                        (-bnot ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System))
                    Write-Log "Cleared Hidden/System on: $($item.FullName)" -Level OK
                }
                catch {
                    Write-Log "FAILED to clear attributes on '$($item.FullName)': $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

function Invoke-Cleanup {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "   Synaptics.exe Trojan Removal Tool" -ForegroundColor White
    Write-Host ("   Mode: {0}" -f $(if ($DryRun) { 'DRY RUN (no changes will be made)' } else { 'LIVE' })) -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host ""

    Write-Log "Cleanup started. Trusted (legitimate) location: $TrustedRoot" -Level INFO

    Assert-Administrator

    $suspectPaths = Stop-MaliciousProcesses
    Remove-MaliciousFiles  -ExtraPaths $suspectPaths
    Remove-RemovableDriveDroppers
    Remove-MaliciousRunKeys
    Repair-HiddenFileSettings
    Restore-HiddenItems

    Write-Log "Cleanup finished." -Level INFO
    if ($DryRun) {
        Write-Log "This was a DRY RUN. No changes were made. Re-run WITHOUT -DryRun to apply." -Level WARN
    }
    else {
        Write-Log "Recommend a full antivirus scan and a reboot to complete remediation." -Level INFO
    }

    Save-Log
}

Invoke-Cleanup
