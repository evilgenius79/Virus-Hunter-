#Requires -Version 5.1
<#
.SYNOPSIS
    Dedicated removal tool for the "Synaptics.exe" trojan family.

.DESCRIPTION
    Detects and removes the well-known "Synaptics.exe" malware - an Excel/Office
    and USB-spreading worm that masquerades as the legitimate Synaptics touchpad
    driver, hides the victim's real files, persists via the registry, scheduled
    tasks and the Excel XLSTART folder, and drops itself onto removable drives.

    TRUST MODEL (this is what makes the tool safe AND strong):
      A file matching the malware's names is considered GENUINE only if it carries
      a *valid Authenticode signature from "Synaptics"*. This is stronger than
      trusting a file just because it sits in Program Files - it catches malware
      that drops itself into Program Files, and it avoids destroying a legitimately
      signed file found elsewhere. The directory C:\Program Files\Synaptics\ is
      additionally protected: the tool will never delete anything inside it.

    Actions performed:
      1. Requires Administrator privileges.
      2. (Live runs) Creates a System Restore checkpoint first.
      3. Terminates Synaptics / wszui processes that are NOT validly signed by
         Synaptics, recording their on-disk paths.
      4. Removes malicious scheduled tasks and services.
      5. Deletes known malicious folders/files and the executables of the killed
         processes.
      6. Cleans removable drives: hidden Synaptics*.exe droppers, autorun.inf,
         and malicious .lnk decoy shortcuts.
      7. Cleans persistence in the registry: Run, RunOnce, and the Winlogon
         Shell/Userinit values.
      8. Removes malicious .lnk files from the Startup folders.
      9. Cleans the Excel XLSTART folders and repairs the Office macro-security
         keys (AccessVBOM / VBAWarnings) the worm lowers.
     10. Repairs the Explorer "hide files" settings and un-hides files the worm
         marked Hidden/System.
     11. Writes a detailed, timestamped text log.

    SAFETY: Run with -DryRun first. In DryRun mode nothing is changed.

.PARAMETER DryRun
    Report-only mode. No process killed, no file/registry/task change made.
    STRONGLY RECOMMENDED for the first run.

.PARAMETER LogPath
    Where to write the log file. Defaults to the user's Desktop.

.PARAMETER ScanRemovableDrives
    Also scan the root of removable (USB) drives. Enabled by default.

.PARAMETER NoRestorePoint
    Skip creation of the System Restore checkpoint on live runs.

.EXAMPLE
    PS> .\Remove-SynapticsTrojan.ps1 -DryRun
    Shows everything the tool would do, without changing anything.

.EXAMPLE
    PS> .\Remove-SynapticsTrojan.ps1
    Performs the actual cleanup and writes a log to the Desktop.

.NOTES
    A remediation aid, not a replacement for a full AV scan. After running it,
    reboot and perform a full scan with a reputable antivirus product.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$LogPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) ("SynapticsTrojan-Cleanup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))),
    [switch]$ScanRemovableDrives = $true,
    [switch]$NoRestorePoint
)

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

# The ONLY directory tree the tool refuses to delete from (the real driver).
$TrustedRoot = Join-Path $env:ProgramFiles 'Synaptics'

# Signer subject that identifies the genuine vendor.
$TrustedSignerPattern = 'Synaptics'

# Process / file base names this malware family uses.
$TargetProcessNames = @('Synaptics', 'wszui', 'wszqms', 'wszust')

# Known malicious drop locations. The legitimate driver is never here.
$KnownMaliciousPaths = @(
    (Join-Path $env:ProgramData 'Synaptics'),
    (Join-Path $env:PUBLIC      'Synaptics.exe'),
    (Join-Path $env:APPDATA     'Synaptics'),
    (Join-Path $env:LOCALAPPDATA 'Synaptics')
)

# Registry autostart keys to inspect.
$RunKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$WinlogonKey = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'

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
# Trust / utility helpers
# ----------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsUnderTrustedRoot {
    # True only if the path lives under C:\Program Files\Synaptics\.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $full    = [System.IO.Path]::GetFullPath($Path)
        $trusted = [System.IO.Path]::GetFullPath($TrustedRoot)
        return $full.StartsWith($trusted, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Test-IsGenuineSynaptics {
    # The core trust test: a file is genuine ONLY if it carries a valid
    # Authenticode signature whose signer is Synaptics. Anything else (unsigned,
    # invalid, revoked, or signed by someone else) is treated as malicious.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and
            $sig.SignerCertificate.Subject -match $TrustedSignerPattern) {
            return $true
        }
    }
    catch { }
    return $false
}

function Get-ExeFromCommand {
    # Pulls the first .exe path out of a command line / registry value.
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    if ($Command -match '"([^"]+\.exe)"')      { return $Matches[1] }
    if ($Command -match '([A-Za-z]:\\[^\s,"]+\.exe)') { return $Matches[1] }
    if ($Command -match '(\S+\.exe)')          { return $Matches[1] }
    return $null
}

function Test-CommandIsMalicious {
    # A command/target is malicious if it references one of the malware names or
    # a known malicious path AND the referenced executable is NOT genuinely
    # signed by Synaptics.
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }

    $mentions = $false
    foreach ($n in $TargetProcessNames) {
        if ($Command -match [regex]::Escape($n)) { $mentions = $true; break }
    }
    if (-not $mentions) {
        foreach ($p in $KnownMaliciousPaths) {
            if ($Command -match [regex]::Escape($p)) { $mentions = $true; break }
        }
    }
    if (-not $mentions) { return $false }

    $exe = Get-ExeFromCommand $Command
    if ($exe -and (Test-IsGenuineSynaptics $exe)) { return $false }
    return $true
}

function Remove-ItemSecurely {
    # Clears protective attributes, then deletes. Honors DryRun. Never touches
    # the genuine driver tree.
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "Path not present (nothing to delete): $Path" -Level INFO
        return
    }
    if (Test-IsUnderTrustedRoot $Path) {
        Write-Log "REFUSING to delete trusted driver path: $Path" -Level WARN
        return
    }
    if ($DryRun) {
        Write-Log "WOULD delete: $Path" -Level ACTION
        return
    }
    try {
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
        Write-Host "  >> Right-click PowerShell and choose 'Run as administrator', then re-run. <<" -ForegroundColor Red
        Save-Log
        exit 1
    }
    Write-Log "Administrator privileges confirmed." -Level OK
}

# ----------------------------------------------------------------------------
# Step 2 - System Restore checkpoint (live runs only)
# ----------------------------------------------------------------------------

function New-RestoreCheckpoint {
    if ($DryRun -or $NoRestorePoint) { return }
    Write-Log "Creating a System Restore checkpoint before making changes..." -Level INFO
    try {
        Checkpoint-Computer -Description 'Before Synaptics trojan cleanup' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Log "System Restore checkpoint created." -Level OK
    }
    catch {
        Write-Log "Could not create a restore point (System Restore may be disabled, or this is a Server OS, or one was created in the last 24h): $($_.Exception.Message)" -Level WARN
    }
}

# ----------------------------------------------------------------------------
# Step 3 - Process detection & termination
# ----------------------------------------------------------------------------

function Stop-MaliciousProcesses {
    Write-Log "Scanning running processes for $($TargetProcessNames -join ', ')..." -Level INFO
    $suspectPaths = New-Object System.Collections.Generic.List[string]

    foreach ($name in $TargetProcessNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { Write-Log "No running process named '$name'." -Level INFO; continue }

        foreach ($p in $procs) {
            $exePath = $null
            try { $exePath = $p.Path } catch { $exePath = $null }

            if ($exePath -and (Test-IsGenuineSynaptics $exePath)) {
                Write-Log "Process '$name' (PID $($p.Id)) at '$exePath' is validly signed by Synaptics - leaving it alone." -Level OK
                continue
            }

            if ([string]::IsNullOrWhiteSpace($exePath)) {
                Write-Log "Process '$name' (PID $($p.Id)) path unreadable - treating as malicious." -Level FOUND
            }
            else {
                $reason = if (Test-IsUnderTrustedRoot $exePath) { 'in Program Files but NOT validly signed' } else { 'untrusted path / signature' }
                Write-Log "Process '$name' (PID $($p.Id)) at '$exePath' is malicious ($reason)." -Level FOUND
                $suspectPaths.Add($exePath) | Out-Null
            }

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
# Step 4 - Scheduled tasks & services
# ----------------------------------------------------------------------------

function Remove-MaliciousScheduledTasks {
    Write-Log "Scanning scheduled tasks for malicious persistence..." -Level INFO
    $tasks = $null
    try { $tasks = Get-ScheduledTask -ErrorAction Stop }
    catch { Write-Log "Get-ScheduledTask unavailable on this system - skipping task scan." -Level WARN; return }

    foreach ($t in $tasks) {
        foreach ($a in @($t.Actions)) {
            $cmd = ('{0} {1}' -f $a.Execute, $a.Arguments).Trim()
            if (-not (Test-CommandIsMalicious $cmd)) { continue }

            $full = "$($t.TaskPath)$($t.TaskName)"
            Write-Log "Malicious scheduled task found: '$full' -> '$cmd'" -Level FOUND
            if ($DryRun) {
                Write-Log "WOULD unregister scheduled task '$full'." -Level ACTION
            }
            else {
                try {
                    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                    Write-Log "Removed scheduled task '$full'." -Level OK
                }
                catch {
                    Write-Log "FAILED to remove task '$full': $($_.Exception.Message)" -Level ERROR
                }
            }
            break
        }
    }
}

function Remove-MaliciousServices {
    Write-Log "Scanning services for malicious persistence..." -Level INFO
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    foreach ($s in $services) {
        if (-not (Test-CommandIsMalicious $s.PathName)) { continue }

        Write-Log "Malicious service found: '$($s.Name)' -> '$($s.PathName)'" -Level FOUND
        if ($DryRun) {
            Write-Log "WOULD stop and delete service '$($s.Name)'." -Level ACTION
        }
        else {
            try { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue } catch {}
            $r = & sc.exe delete $s.Name 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Log "Deleted service '$($s.Name)'." -Level OK }
            else { Write-Log "FAILED to delete service '$($s.Name)': $r" -Level ERROR }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 5 - File / folder cleanup
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
    if ($ExtraPaths) {
        foreach ($path in ($ExtraPaths | Sort-Object -Unique)) {
            if (Test-Path -LiteralPath $path) {
                Write-Log "Removing executable of terminated process: $path" -Level FOUND
                Remove-ItemSecurely -Path $path
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 6 - Removable drive cleanup (droppers, autorun.inf, decoy .lnk)
# ----------------------------------------------------------------------------

function Clear-RemovableDrives {
    if (-not $ScanRemovableDrives) { return }
    Write-Log "Scanning removable drive roots..." -Level INFO

    $removable = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 2' -ErrorAction SilentlyContinue
    if (-not $removable) { Write-Log "No removable drives detected." -Level INFO; return }

    foreach ($drive in $removable) {
        $root = $drive.DeviceID + '\'
        Write-Log "Inspecting removable drive root: $root" -Level INFO

        # 1) Synaptics*.exe droppers in the root.
        Get-ChildItem -LiteralPath $root -Filter 'Synaptics*.exe' -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                $hidden = ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                Write-Log ("Dropper on removable drive (Hidden={0}): {1}" -f $hidden, $_.FullName) -Level FOUND
                Remove-ItemSecurely -Path $_.FullName
            }

        # 2) autorun.inf auto-execution file.
        $autorun = Join-Path $root 'autorun.inf'
        if (Test-Path -LiteralPath $autorun) {
            Write-Log "autorun.inf present on removable drive: $autorun" -Level FOUND
            Remove-ItemSecurely -Path $autorun
        }

        # 3) Decoy .lnk shortcuts in the root that launch the malware.
        Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $target = $null
                try { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath } catch {}
                $args2 = $null
                try { $args2 = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).Arguments } catch {}
                $cmd = ("{0} {1}" -f $target, $args2).Trim()
                if (Test-CommandIsMalicious $cmd) {
                    Write-Log "Malicious decoy shortcut on removable drive: $($_.FullName) -> '$cmd'" -Level FOUND
                    Remove-ItemSecurely -Path $_.FullName
                }
            }
    }
}

# ----------------------------------------------------------------------------
# Step 7 - Registry autostart cleanup (Run / RunOnce / Winlogon)
# ----------------------------------------------------------------------------

function Remove-MaliciousRunKeys {
    Write-Log "Scanning registry Run / RunOnce keys..." -Level INFO

    foreach ($key in $RunKeys) {
        if (-not (Test-Path -LiteralPath $key)) { Write-Log "Key not present: $key" -Level INFO; continue }

        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop }
        catch { Write-Log "Could not read '$key': $($_.Exception.Message)" -Level WARN; continue }

        foreach ($valueName in ($props.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
            $valueData = [string]$props.$valueName
            if (-not (Test-CommandIsMalicious $valueData)) { continue }

            Write-Log "Malicious autostart entry in ${key}: '$valueName' = '$valueData'" -Level FOUND
            if ($DryRun) {
                Write-Log "WOULD remove value '$valueName' from $key." -Level ACTION
            }
            else {
                try {
                    Remove-ItemProperty -LiteralPath $key -Name $valueName -ErrorAction Stop
                    Write-Log "Removed value '$valueName' from $key." -Level OK
                }
                catch { Write-Log "FAILED to remove '$valueName' from ${key}: $($_.Exception.Message)" -Level ERROR }
            }
        }
    }

    Repair-WinlogonValues
}

function Repair-WinlogonValues {
    if (-not (Test-Path -LiteralPath $WinlogonKey)) { return }
    $props = $null
    try { $props = Get-ItemProperty -LiteralPath $WinlogonKey -ErrorAction Stop } catch { return }

    # Shell should be exactly "explorer.exe".
    $shell = [string]$props.Shell
    if ($shell -and (Test-CommandIsMalicious $shell)) {
        Write-Log "Winlogon 'Shell' is hijacked: '$shell'" -Level FOUND
        if ($DryRun) { Write-Log "WOULD reset Winlogon 'Shell' to 'explorer.exe'." -Level ACTION }
        else {
            try { Set-ItemProperty -LiteralPath $WinlogonKey -Name 'Shell' -Value 'explorer.exe' -ErrorAction Stop
                  Write-Log "Reset Winlogon 'Shell' to 'explorer.exe'." -Level OK }
            catch { Write-Log "FAILED to reset Winlogon 'Shell': $($_.Exception.Message)" -Level ERROR }
        }
    }

    # Userinit should be "...\userinit.exe,".
    $userinit = [string]$props.Userinit
    if ($userinit -and (Test-CommandIsMalicious $userinit)) {
        $clean = "$env:SystemRoot\system32\userinit.exe,"
        Write-Log "Winlogon 'Userinit' is hijacked: '$userinit'" -Level FOUND
        if ($DryRun) { Write-Log "WOULD reset Winlogon 'Userinit' to '$clean'." -Level ACTION }
        else {
            try { Set-ItemProperty -LiteralPath $WinlogonKey -Name 'Userinit' -Value $clean -ErrorAction Stop
                  Write-Log "Reset Winlogon 'Userinit' to '$clean'." -Level OK }
            catch { Write-Log "FAILED to reset Winlogon 'Userinit': $($_.Exception.Message)" -Level ERROR }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 8 - Startup folder shortcuts
# ----------------------------------------------------------------------------

function Remove-MaliciousStartupShortcuts {
    Write-Log "Scanning Startup folders for malicious shortcuts..." -Level INFO
    $startupDirs = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($dir in $startupDirs) {
        Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $cmd = $_.FullName
            if ($_.Extension -eq '.lnk') {
                try {
                    $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName)
                    $cmd = ("{0} {1}" -f $sc.TargetPath, $sc.Arguments).Trim()
                } catch {}
            }
            if (Test-CommandIsMalicious $cmd) {
                Write-Log "Malicious Startup item: $($_.FullName) -> '$cmd'" -Level FOUND
                Remove-ItemSecurely -Path $_.FullName
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 9 - Office / Excel XLSTART and macro-security repair
# ----------------------------------------------------------------------------

function Clear-OfficePersistence {
    Write-Log "Cleaning Excel XLSTART folders and repairing Office macro security..." -Level INFO

    # XLSTART locations: per-user and any under the Office install dirs.
    $xlstartDirs = New-Object System.Collections.Generic.List[string]
    $xlstartDirs.Add((Join-Path $env:APPDATA 'Microsoft\Excel\XLSTART'))
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $base) { continue }
        Get-ChildItem -LiteralPath $base -Directory -Filter 'XLSTART' -Recurse -ErrorAction SilentlyContinue -Depth 4 |
            ForEach-Object { $xlstartDirs.Add($_.FullName) }
    }

    foreach ($dir in ($xlstartDirs | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        Write-Log "Inspecting XLSTART: $dir" -Level INFO
        Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $isExe  = $_.Extension -in @('.exe', '.scr', '.com', '.bat', '.cmd', '.vbs', '.js')
            $named  = $false
            foreach ($n in $TargetProcessNames) { if ($_.Name -match [regex]::Escape($n)) { $named = $true; break } }
            if ($isExe -or $named) {
                Write-Log "Malicious file in XLSTART: $($_.FullName)" -Level FOUND
                Remove-ItemSecurely -Path $_.FullName
            }
            else {
                Write-Log "Non-executable XLSTART item left in place (review manually if unexpected): $($_.FullName)" -Level WARN
            }
        }
    }

    # Repair the macro-security keys the worm lowers to auto-run macros.
    $officeVersions = @('11.0','12.0','14.0','15.0','16.0')
    $apps = @('Excel','Word','PowerPoint')
    foreach ($ver in $officeVersions) {
        foreach ($app in $apps) {
            $secKey = "HKCU:\Software\Microsoft\Office\$ver\$app\Security"
            if (-not (Test-Path -LiteralPath $secKey)) { continue }
            $sp = $null
            try { $sp = Get-ItemProperty -LiteralPath $secKey -ErrorAction Stop } catch { continue }

            # AccessVBOM=1 lets code reach the VBA project model; should be 0.
            if ($sp.PSObject.Properties.Name -contains 'AccessVBOM' -and [int]$sp.AccessVBOM -eq 1) {
                Write-Log "$app $ver 'AccessVBOM' is enabled (1)." -Level FOUND
                if ($DryRun) { Write-Log "WOULD set AccessVBOM=0 in $secKey." -Level ACTION }
                else {
                    try { Set-ItemProperty -LiteralPath $secKey -Name 'AccessVBOM' -Value 0 -Type DWord -ErrorAction Stop
                          Write-Log "Set $app $ver AccessVBOM=0." -Level OK }
                    catch { Write-Log "FAILED to set AccessVBOM: $($_.Exception.Message)" -Level ERROR }
                }
            }
            # VBAWarnings=1 means "enable all macros"; restore to 2 (disable w/ notify).
            if ($sp.PSObject.Properties.Name -contains 'VBAWarnings' -and [int]$sp.VBAWarnings -eq 1) {
                Write-Log "$app $ver 'VBAWarnings' set to enable-all-macros (1)." -Level FOUND
                if ($DryRun) { Write-Log "WOULD set VBAWarnings=2 in $secKey." -Level ACTION }
                else {
                    try { Set-ItemProperty -LiteralPath $secKey -Name 'VBAWarnings' -Value 2 -Type DWord -ErrorAction Stop
                          Write-Log "Set $app $ver VBAWarnings=2." -Level OK }
                    catch { Write-Log "FAILED to set VBAWarnings: $($_.Exception.Message)" -Level ERROR }
                }
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 10 - Repair Explorer "hide files" settings & un-hide files
# ----------------------------------------------------------------------------

function Repair-HiddenFileSettings {
    Write-Log "Repairing Explorer settings used to hide files..." -Level INFO
    $advanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    $desired = @{ 'Hidden' = 1; 'ShowSuperHidden' = 1; 'HideFileExt' = 0 }

    if (-not (Test-Path -LiteralPath $advanced)) { Write-Log "Explorer Advanced key not found." -Level WARN; return }

    foreach ($name in $desired.Keys) {
        $want = $desired[$name]
        $current = $null
        try { $current = (Get-ItemProperty -LiteralPath $advanced -Name $name -ErrorAction Stop).$name } catch {}
        if ($current -eq $want) { Write-Log "Explorer '$name' already correct ($want)." -Level OK; continue }

        Write-Log "Explorer '$name' is '$current', should be '$want'." -Level FOUND
        if ($DryRun) { Write-Log "WOULD set '$name' = $want." -Level ACTION }
        else {
            try { Set-ItemProperty -LiteralPath $advanced -Name $name -Value $want -Type DWord -ErrorAction Stop
                  Write-Log "Set Explorer '$name' = $want." -Level OK }
            catch { Write-Log "FAILED to set '$name': $($_.Exception.Message)" -Level ERROR }
        }
    }
}

function Restore-HiddenItems {
    # Clears Hidden/System on user files/USB roots the worm hid. Never deletes.
    Write-Log "Restoring visibility of files hidden by the malware..." -Level INFO
    $scanRoots = New-Object System.Collections.Generic.List[string]
    $scanRoots.Add($env:USERPROFILE)
    if ($ScanRemovableDrives) {
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 2' -ErrorAction SilentlyContinue |
            ForEach-Object { $scanRoots.Add($_.DeviceID + '\') }
    }

    foreach ($root in $scanRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Write-Log "Un-hiding items under: $root" -Level INFO
        Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                (($_.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0 -or
                 ($_.Attributes -band [System.IO.FileAttributes]::System) -ne 0)
            } | ForEach-Object {
                if ($_.Name -in @('desktop.ini', 'thumbs.db', 'ntuser.dat')) { return }
                if ($_.FullName -match '\\(AppData|\.git)\\') { return }
                if ($DryRun) { Write-Log "WOULD clear Hidden/System on: $($_.FullName)" -Level ACTION }
                else {
                    try {
                        $_.Attributes = $_.Attributes -band `
                            (-bnot ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System))
                        Write-Log "Cleared Hidden/System on: $($_.FullName)" -Level OK
                    }
                    catch { Write-Log "FAILED to clear attributes on '$($_.FullName)': $($_.Exception.Message)" -Level ERROR }
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

    Write-Log "Cleanup started. Genuine driver = valid Synaptics signature; protected tree = $TrustedRoot" -Level INFO

    Assert-Administrator
    New-RestoreCheckpoint

    $suspectPaths = Stop-MaliciousProcesses
    Remove-MaliciousScheduledTasks
    Remove-MaliciousServices
    Remove-MaliciousFiles -ExtraPaths $suspectPaths
    Clear-RemovableDrives
    Remove-MaliciousRunKeys
    Remove-MaliciousStartupShortcuts
    Clear-OfficePersistence
    Repair-HiddenFileSettings
    Restore-HiddenItems

    Write-Log "Cleanup finished." -Level INFO
    if ($DryRun) {
        Write-Log "This was a DRY RUN. No changes were made. Re-run WITHOUT -DryRun to apply." -Level WARN
    }
    else {
        Write-Log "Reboot, then run a full antivirus scan to complete remediation." -Level INFO
    }
    Save-Log
}

Invoke-Cleanup
