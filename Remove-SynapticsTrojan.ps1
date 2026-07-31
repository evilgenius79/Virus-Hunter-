#Requires -Version 5.1
<#
.SYNOPSIS
    Dedicated removal tool for the "Synaptics.exe" (Xred) trojan family and
    related USB shortcut-worms.

.DESCRIPTION
    Detects and removes the well-known "Synaptics.exe" malware (also known as
    Xred) - an Excel/Office and USB-spreading worm that masquerades as the
    legitimate Synaptics touchpad driver, INFECTS other .exe files (keeping the
    clean original beside them as "._cache_<name>.exe"), hides the victim's real
    files, persists via the registry, scheduled tasks, WMI subscriptions and the
    Excel XLSTART folder, and drops itself onto removable drives. It also cleans
    the generic USB shortcut-worm pattern (hidden folders replaced by decoy .lnk
    files, hidden script droppers) used by families like Jenxcus and Gamarue.

    TRUST MODEL (this is what makes the tool safe AND strong):
      A file matching the malware's names is considered GENUINE only if it carries
      a *valid Authenticode signature whose subject CN is "Synaptics"*. This is
      stronger than trusting a file just because it sits in Program Files - it
      catches malware that drops itself into Program Files, and it avoids
      destroying a legitimately signed file found elsewhere. The directory
      C:\Program Files\Synaptics\ is additionally protected: the tool will never
      delete anything inside it.

    Actions performed:
      1. Requires Administrator privileges.
      2. (Live runs) Creates a System Restore checkpoint first.
      3. Terminates Synaptics / wszui processes that are NOT validly signed by
         Synaptics, recording their on-disk paths - sweeping repeatedly until
         watchdog pairs that respawn each other stay dead.
      4. Removes malicious scheduled tasks and services.
      5. Deletes known malicious folders/files and the executables of the killed
         processes. Files locked by running malware are scheduled for deletion
         at the next reboot.
      6. Repairs Xred-infected executables: where a clean original was kept as
         "._cache_<name>.exe", the infected host is replaced by the clean copy.
      7. Cleans removable drives (plus any drives given via -AlsoScanDrives):
         unsigned Synaptics*.exe droppers, autorun.inf, decoy .lnk shortcuts,
         hidden script droppers, and "folder-icon" worm copies named after
         hidden real folders.
      8. Cleans persistence in the registry: Run, RunOnce, the HKCU Windows
         Load/Run values, and the Winlogon Shell/Userinit values.
      9. Removes malicious .lnk files from the Startup folders.
     10. Removes malicious WMI event-subscription persistence and IFEO
         "Debugger" hijacks (others are flagged for manual review).
     11. Cleans the Excel XLSTART folders and repairs the Office macro-security
         keys (AccessVBOM / VBAWarnings) the worm lowers.
     12. Removes hosts-file entries that blackhole antivirus / Windows-update
         domains (backing the file up first).
     13. (Optional) Looks up the SHA256 of detected files on VirusTotal for
         confirmation - read-only, requires -VirusTotalApiKey.
     14. Repairs the Explorer "hide files" settings and un-hides files the worm
         marked Hidden/System.
     15. Writes a detailed, timestamped text log ending with a summary, and
         returns a meaningful exit code (see NOTES).

    SAFETY: Run with -DryRun first. In DryRun mode nothing is changed.

.PARAMETER DryRun
    Report-only mode. No process killed, no file/registry/task change made.
    STRONGLY RECOMMENDED for the first run.

.PARAMETER LogPath
    Where to write the log file. Defaults to the user's Desktop.

.PARAMETER ScanRemovableDrives
    Also scan the root of removable (USB) drives. Enabled by default.

.PARAMETER AlsoScanDrives
    Extra drive letters (e.g. 'D','E') to treat like removable drives during
    the drive cleanup, infected-exe repair, and un-hide steps. Useful for USB
    hard drives, which Windows reports as fixed disks rather than removable.
    The system drive is refused here - it is already covered by the other steps.

.PARAMETER NoRestorePoint
    Skip creation of the System Restore checkpoint on live runs.

.PARAMETER VirusTotalApiKey
    Optional VirusTotal API key. When supplied, the SHA256 of each detected file
    is looked up on VirusTotal and the detection ratio is logged. This is purely
    informational (read-only) and never changes what the tool deletes.

.EXAMPLE
    PS> .\Remove-SynapticsTrojan.ps1 -DryRun
    Shows everything the tool would do, without changing anything.

.EXAMPLE
    PS> .\Remove-SynapticsTrojan.ps1
    Performs the actual cleanup and writes a log to the Desktop.

.NOTES
    A remediation aid, not a replacement for a full AV scan. After running it,
    reboot and perform a full scan with a reputable antivirus product.

    Exit codes: 0 = nothing found, 1 = not run as Administrator,
    2 = infections were found (see the log), 3 = one or more errors occurred.

    Dot-sourcing the script (". .\Remove-SynapticsTrojan.ps1") loads its
    functions without performing any cleanup - the Pester tests rely on this.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$LogPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) ("SynapticsTrojan-Cleanup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))),
    [switch]$ScanRemovableDrives = $true,
    [string[]]$AlsoScanDrives,
    [switch]$NoRestorePoint,
    [string]$VirusTotalApiKey
)

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

# The ONLY directory tree the tool refuses to delete from (the real driver).
$TrustedRoot = Join-Path $env:ProgramFiles 'Synaptics'

# Signer subject that identifies the genuine vendor. Anchored on CN= so a
# look-alike organisation name elsewhere in the subject cannot satisfy it.
$TrustedSignerPattern = 'CN=Synaptics'

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

# Image File Execution Options roots ("Debugger" value hijack persistence).
$IFEOKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
)

# Script extensions USB worms drop (hidden) in removable drive roots.
$WormScriptExtensions = @('.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.bat', '.cmd', '.scr', '.pif')

# The hosts file, and domain fragments malware commonly blackholes to stop
# antivirus / OS updates. A line that maps one of these to a loopback / null
# address is treated as a malicious block.
$HostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$SinkholeAddresses = @('0.0.0.0', '127.0.0.1', '::1', '::')
$SecurityDomains = @(
    'microsoft.com', 'windowsupdate.com', 'update.microsoft', 'msftncsi.com',
    'defender',
    'avast.com', 'avg.com', 'avira', 'bitdefender', 'eset', 'nod32',
    'kaspersky', 'mcafee', 'norton', 'symantec', 'sophos', 'malwarebytes',
    'trendmicro', 'f-secure', 'drweb', 'comodo', 'clamav', 'virustotal.com'
)

# ----------------------------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------------------------

$script:LogLines = New-Object System.Collections.Generic.List[string]
$script:Stats = @{ FOUND = 0; WARN = 0; ERROR = 0 }

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO', 'FOUND', 'ACTION', 'WARN', 'ERROR', 'OK')]
        [string]$Level = 'INFO'
    )
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[{0}] [{1,-6}] {2}" -f $stamp, $Level, $Message
    $script:LogLines.Add($line)
    if ($script:Stats.ContainsKey($Level)) { $script:Stats[$Level]++ }
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

$script:WShell = $null
function Get-ShortcutCommand {
    # Resolves a .lnk to "target arguments" using one shared COM object.
    param([string]$LnkPath)
    try {
        if (-not $script:WShell) { $script:WShell = New-Object -ComObject WScript.Shell }
        $sc = $script:WShell.CreateShortcut($LnkPath)
        return ("{0} {1}" -f $sc.TargetPath, $sc.Arguments).Trim()
    }
    catch { return $null }
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

function Get-CacheOriginalName {
    # "._cache_app.exe" -> "app.exe"; $null when the name doesn't match.
    param([string]$Name)
    if ($Name -notlike '._cache_*') { return $null }
    return $Name.Substring(8)
}

function Test-HostsLineIsMalicious {
    # True when a hosts-file line maps a security/update domain to a sinkhole
    # address. Comments, blanks and ordinary entries are never flagged.
    param([string]$Line)
    $trimmed = ([string]$Line).Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { return $false }
    $tokens = $trimmed -split '\s+'
    if ($tokens.Count -lt 2) { return $false }
    if ($SinkholeAddresses -notcontains $tokens[0]) { return $false }
    $hostNames = $tokens[1..($tokens.Count - 1)] -join ' '
    foreach ($d in $SecurityDomains) {
        if ($hostNames -match [regex]::Escape($d)) { return $true }
    }
    return $false
}

$script:MoveFileExType = $null
function Register-DeleteOnReboot {
    # Files locked by still-running malware can't be deleted now; MoveFileEx
    # with MOVEFILE_DELAY_UNTIL_REBOOT (4) queues them for removal at boot.
    param([string]$Path)
    try {
        if (-not $script:MoveFileExType) {
            $script:MoveFileExType = Add-Type -Name 'Native' -Namespace 'SynapticsCleanup' -PassThru -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
        }
        if ($script:MoveFileExType::MoveFileEx($Path, $null, 4)) {
            Write-Log "Scheduled for deletion at next reboot: $Path" -Level OK
            return $true
        }
    }
    catch {}
    Write-Log "Could not schedule reboot-time deletion for: $Path" -Level WARN
    return $false
}

$script:ScanDriveRootsCache = $null
function Get-ScanDriveRoots {
    # Removable drives (if enabled) plus any -AlsoScanDrives letters. Cached so
    # repeated callers don't re-query WMI or re-log warnings.
    if ($null -ne $script:ScanDriveRootsCache) { return ,$script:ScanDriveRootsCache }

    $roots = New-Object System.Collections.Generic.List[string]
    if ($ScanRemovableDrives) {
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 2' -ErrorAction SilentlyContinue |
            ForEach-Object { $roots.Add($_.DeviceID + '\') }
    }
    foreach ($d in $AlsoScanDrives) {
        $letter = ($d.TrimEnd(':', '\')).ToUpper()
        if ($letter -notmatch '^[A-Z]$') {
            Write-Log "Ignoring invalid -AlsoScanDrives entry '$d' (use a drive letter like 'D')." -Level WARN
            continue
        }
        $root = "${letter}:\"
        if ($root -eq ($env:SystemDrive + '\')) {
            Write-Log "Refusing to treat the system drive $root as a worm-target drive; it is covered by the other steps." -Level WARN
            continue
        }
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Log "-AlsoScanDrives drive $root is not present - skipping." -Level WARN
            continue
        }
        if ($roots -notcontains $root) { $roots.Add($root) }
    }
    $script:ScanDriveRootsCache = $roots.ToArray()
    return ,$script:ScanDriveRootsCache
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
        Write-Log "FAILED to delete '$Path' (likely locked by a running process): $($_.Exception.Message)" -Level ERROR
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($item) {
            if ($item.PSIsContainer) {
                Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                    ForEach-Object { Register-DeleteOnReboot $_.FullName | Out-Null }
            }
            Register-DeleteOnReboot $Path | Out-Null
        }
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

    # Windows silently skips checkpoints made within 24h of the previous one;
    # lift that throttle for this one call, then put the setting back.
    $srKey    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $freqName = 'SystemRestorePointCreationFrequency'
    $hadValue = $false; $prev = $null
    try {
        $prev = (Get-ItemProperty -LiteralPath $srKey -Name $freqName -ErrorAction Stop).$freqName
        $hadValue = $true
    } catch {}
    try { Set-ItemProperty -LiteralPath $srKey -Name $freqName -Value 0 -Type DWord -ErrorAction SilentlyContinue } catch {}

    try {
        Checkpoint-Computer -Description 'Before Synaptics trojan cleanup' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Log "System Restore checkpoint created." -Level OK
    }
    catch {
        Write-Log "Could not create a restore point (System Restore may be disabled, or this is a Server OS): $($_.Exception.Message)" -Level WARN
    }
    finally {
        try {
            if ($hadValue) { Set-ItemProperty -LiteralPath $srKey -Name $freqName -Value $prev -Type DWord -ErrorAction SilentlyContinue }
            else           { Remove-ItemProperty -LiteralPath $srKey -Name $freqName -ErrorAction SilentlyContinue }
        } catch {}
    }
}

# ----------------------------------------------------------------------------
# Step 3 - Process detection & termination
# ----------------------------------------------------------------------------

function Stop-MaliciousProcesses {
    # These worms often run as watchdog pairs that respawn each other, so a
    # single kill pass isn't enough: sweep repeatedly until a pass finds no
    # family process running.
    Write-Log "Scanning running processes for $($TargetProcessNames -join ', ')..." -Level INFO
    $suspectPaths = New-Object System.Collections.Generic.List[string]
    $maxRounds = 5

    for ($round = 1; $round -le $maxRounds; $round++) {
        $actedOn = 0
        foreach ($name in $TargetProcessNames) {
            foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
                $exePath = $null
                try { $exePath = $p.Path } catch { $exePath = $null }

                if ($exePath -and (Test-IsGenuineSynaptics $exePath)) {
                    if ($round -eq 1) {
                        Write-Log "Process '$name' (PID $($p.Id)) at '$exePath' is validly signed by Synaptics - leaving it alone." -Level OK
                    }
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($exePath)) {
                    Write-Log "Process '$name' (PID $($p.Id)) path unreadable - treating as malicious." -Level FOUND
                }
                else {
                    $reason = if (Test-IsUnderTrustedRoot $exePath) { 'in Program Files but NOT validly signed' } else { 'untrusted path / signature' }
                    Write-Log "Process '$name' (PID $($p.Id)) at '$exePath' is malicious ($reason)." -Level FOUND
                    if (-not $suspectPaths.Contains($exePath)) { $suspectPaths.Add($exePath) }
                }

                $actedOn++
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

        if ($actedOn -eq 0) {
            if ($round -eq 1) { Write-Log "No malicious family processes are running." -Level INFO }
            else { Write-Log "No family process reappeared (sweep $round) - the watchdog respawn loop is broken." -Level OK }
            break
        }
        if ($DryRun) { break }   # one reporting pass is enough
        if ($round -eq $maxRounds) {
            Write-Log "Family processes still reappearing after $maxRounds sweeps - deletion continues; reboot afterwards and re-run." -Level WARN
            break
        }
        Start-Sleep -Milliseconds 750
    }

    # The comma keeps the array intact through PowerShell's pipeline unrolling
    # (an empty or single-element result would otherwise arrive as $null/string).
    return ,$suspectPaths.ToArray()
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
    param([string[]]$ExtraPaths)
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
    $driveRoots = Get-ScanDriveRoots
    if (-not $driveRoots) { Write-Log "No removable (or additionally requested) drives to scan." -Level INFO; return }
    Write-Log "Scanning drive roots for worm droppers..." -Level INFO

    foreach ($root in $driveRoots) {
        Write-Log "Inspecting drive root: $root" -Level INFO

        # 1) Synaptics*.exe droppers in the root. A validly signed file (e.g. a
        #    driver installer the user stored there) is left alone.
        Get-ChildItem -LiteralPath $root -Filter 'Synaptics*.exe' -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                if (Test-IsGenuineSynaptics $_.FullName) {
                    Write-Log "Validly signed Synaptics file on removable drive left alone: $($_.FullName)" -Level OK
                    return
                }
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

        # 3) Decoy .lnk shortcuts in the root. USB worms replace real folders
        #    with a hidden copy plus a same-named .lnk that launches the malware
        #    (Jenxcus/Houdini/Gamarue pattern), so three tests apply: launches
        #    this family, launches a script host with arguments, or masquerades
        #    as a hidden sibling of the same name.
        Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $cmd = Get-ShortcutCommand $_.FullName
                if (-not $cmd) { return }

                $isFamily = Test-CommandIsMalicious $cmd
                $viaScriptHost = ($cmd -match '(^|\\)(wscript|cscript|cmd|mshta|powershell|rundll32)(\.exe)?\s+\S')

                $decoyOfHidden = $false
                $sibling = Join-Path $root $_.BaseName
                if (Test-Path -LiteralPath $sibling) {
                    $sib = Get-Item -LiteralPath $sibling -Force -ErrorAction SilentlyContinue
                    if ($sib -and (($sib.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0)) { $decoyOfHidden = $true }
                }

                if ($isFamily -or $viaScriptHost -or $decoyOfHidden) {
                    $why = if ($isFamily) { 'launches this malware family' }
                           elseif ($viaScriptHost) { 'launches a script host with arguments' }
                           else { 'masquerades as the hidden item of the same name' }
                    Write-Log "Malicious decoy shortcut on removable drive ($why): $($_.FullName) -> '$cmd'" -Level FOUND
                    Remove-ItemSecurely -Path $_.FullName
                }
            }

        # 4) Hidden script droppers in the root. Visible scripts are only
        #    flagged - they may be the user's own.
        Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.Extension -in $WormScriptExtensions } |
            ForEach-Object {
                $isHidden = ($_.Attributes -band ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)) -ne 0
                if ($isHidden) {
                    Write-Log "Hidden script dropper on removable drive: $($_.FullName)" -Level FOUND
                    Remove-ItemSecurely -Path $_.FullName
                }
                else {
                    Write-Log "Script file on removable drive root left in place (delete manually if not yours): $($_.FullName)" -Level WARN
                }
            }

        # 5) "Folder-icon" worm copies: an .exe named after a sibling folder.
        #    Removed when either side is hidden (the worm hides the real one);
        #    flagged otherwise.
        Get-ChildItem -LiteralPath $root -Filter '*.exe' -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                $sibDir = Join-Path $root $_.BaseName
                if (-not (Test-Path -LiteralPath $sibDir -PathType Container)) { return }
                $dir = Get-Item -LiteralPath $sibDir -Force -ErrorAction SilentlyContinue
                $dirHidden = $dir -and (($dir.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0)
                $exeHidden = ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                if ($dirHidden -or $exeHidden) {
                    Write-Log "Folder-masquerade worm copy on removable drive: $($_.FullName) (real folder: $sibDir)" -Level FOUND
                    Remove-ItemSecurely -Path $_.FullName
                }
                else {
                    Write-Log "Executable named after sibling folder (review manually): $($_.FullName)" -Level WARN
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

    # 'Load' / 'Run' under the HKCU Windows key: an old but still-abused
    # autostart most cleaners forget.
    $windowsKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
    if (Test-Path -LiteralPath $windowsKey) {
        foreach ($vn in @('Load', 'Run')) {
            $vd = $null
            try { $vd = [string](Get-ItemProperty -LiteralPath $windowsKey -Name $vn -ErrorAction Stop).$vn } catch { continue }
            if (-not (Test-CommandIsMalicious $vd)) { continue }

            Write-Log "Malicious '$vn' value in ${windowsKey}: '$vd'" -Level FOUND
            if ($DryRun) {
                Write-Log "WOULD remove '$vn' from $windowsKey." -Level ACTION
            }
            else {
                try {
                    Remove-ItemProperty -LiteralPath $windowsKey -Name $vn -ErrorAction Stop
                    Write-Log "Removed '$vn' from $windowsKey." -Level OK
                }
                catch { Write-Log "FAILED to remove '$vn' from ${windowsKey}: $($_.Exception.Message)" -Level ERROR }
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
                $resolved = Get-ShortcutCommand $_.FullName
                if ($resolved) { $cmd = $resolved }
            }
            if (Test-CommandIsMalicious $cmd) {
                Write-Log "Malicious Startup item: $($_.FullName) -> '$cmd'" -Level FOUND
                Remove-ItemSecurely -Path $_.FullName
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 8b - WMI event-subscription persistence
# ----------------------------------------------------------------------------

function Remove-WmiPersistence {
    Write-Log "Scanning WMI event subscriptions (root\subscription) for persistence..." -Level INFO
    $ns = 'root/subscription'

    $consumers = @()
    foreach ($class in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
        try { $consumers += @(Get-CimInstance -Namespace $ns -ClassName $class -ErrorAction Stop) } catch {}
    }
    if (-not $consumers) { Write-Log "No command-line / script WMI event consumers present." -Level OK; return }

    $bindings = @(Get-CimInstance -Namespace $ns -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)

    foreach ($c in $consumers) {
        $cmd = if ($c.CimClass.CimClassName -eq 'CommandLineEventConsumer') {
            ('{0} {1}' -f $c.ExecutablePath, $c.CommandLineTemplate).Trim()
        } else {
            ('{0} {1}' -f $c.ScriptFileName, $c.ScriptText).Trim()
        }

        if (-not (Test-CommandIsMalicious $cmd)) {
            # Legit software (e.g. SCCM) uses these; only flag, never guess.
            Write-Log "WMI event consumer left in place (review if unexpected): '$($c.Name)'" -Level INFO
            continue
        }

        Write-Log "Malicious WMI event consumer: '$($c.Name)' -> '$cmd'" -Level FOUND
        if ($DryRun) {
            Write-Log "WOULD remove WMI consumer '$($c.Name)' with its bindings and filters." -Level ACTION
            continue
        }
        foreach ($b in $bindings) {
            $bConsumerName = $null
            try { $bConsumerName = $b.Consumer.Name } catch {}
            if ($bConsumerName -ne $c.Name) { continue }
            try {
                Remove-CimInstance -InputObject $b -ErrorAction Stop
                if ($b.Filter) { Remove-CimInstance -InputObject $b.Filter -ErrorAction SilentlyContinue }
                Write-Log "Removed WMI binding/filter for consumer '$($c.Name)'." -Level OK
            }
            catch { Write-Log "FAILED to remove WMI binding for '$($c.Name)': $($_.Exception.Message)" -Level ERROR }
        }
        try {
            Remove-CimInstance -InputObject $c -ErrorAction Stop
            Write-Log "Removed WMI consumer '$($c.Name)'." -Level OK
        }
        catch { Write-Log "FAILED to remove WMI consumer '$($c.Name)': $($_.Exception.Message)" -Level ERROR }
    }
}

# ----------------------------------------------------------------------------
# Step 8c - Image File Execution Options "Debugger" hijacks
# ----------------------------------------------------------------------------

function Remove-IFEOHijacks {
    Write-Log "Scanning Image File Execution Options for Debugger hijacks..." -Level INFO
    foreach ($base in $IFEOKeys) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = $null
            try { $dbg = [string](Get-ItemProperty -LiteralPath $_.PSPath -Name 'Debugger' -ErrorAction Stop).Debugger } catch { return }
            if ([string]::IsNullOrWhiteSpace($dbg)) { return }

            if (Test-CommandIsMalicious $dbg) {
                Write-Log "IFEO Debugger hijack on '$($_.PSChildName)': '$dbg'" -Level FOUND
                if ($DryRun) {
                    Write-Log "WOULD remove Debugger value from IFEO\$($_.PSChildName)." -Level ACTION
                }
                else {
                    try {
                        Remove-ItemProperty -LiteralPath $_.PSPath -Name 'Debugger' -ErrorAction Stop
                        Write-Log "Removed IFEO Debugger for '$($_.PSChildName)'." -Level OK
                    }
                    catch { Write-Log "FAILED to remove IFEO Debugger for '$($_.PSChildName)': $($_.Exception.Message)" -Level ERROR }
                }
            }
            else {
                # Legit uses exist (procdump, gflags) - flag, don't remove.
                Write-Log "IFEO Debugger present on '$($_.PSChildName)' ('$dbg') - not this family; review manually." -Level WARN
            }
        }
    }
}

# ----------------------------------------------------------------------------
# Step 8d - Repair Xred-infected executables ("._cache_" clean-copy pairs)
# ----------------------------------------------------------------------------

function Repair-InfectedExecutables {
    # The Synaptics/Xred family is also a file INFECTOR: it replaces a host
    # .exe with itself and keeps the clean original beside it, renamed to
    # "._cache_<name>.exe". Restoring that copy recovers the user's program
    # instead of just deleting it.
    Write-Log "Scanning for infected executables ('._cache_*.exe' clean-copy companions)..." -Level INFO

    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add($env:USERPROFILE)
    foreach ($r in (Get-ScanDriveRoots)) { $roots.Add($r) }

    $pairs = 0
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Filter '._cache_*.exe' -File -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $originalName = Get-CacheOriginalName $_.Name
                if (-not $originalName) { return }
                $pairs++
                $cachePath = $_.FullName
                $hostPath  = Join-Path $_.DirectoryName $originalName

                $hostExists = Test-Path -LiteralPath $hostPath
                if ($hostExists) {
                    $hostSig = $null
                    try { $hostSig = (Get-AuthenticodeSignature -LiteralPath $hostPath -ErrorAction Stop).Status } catch {}
                    if ($hostSig -eq 'Valid') {
                        Write-Log "Host '$hostPath' is validly signed (not infected); pair left for manual review." -Level WARN
                        return
                    }
                    Write-Log "Infected executable pair: '$hostPath' (infected) + '$cachePath' (clean original)." -Level FOUND
                }
                else {
                    Write-Log "Orphaned clean copy (host missing): '$cachePath' -> will restore as '$originalName'." -Level FOUND
                }

                if ($DryRun) {
                    Write-Log "WOULD restore '$hostPath' from the clean copy '$cachePath'." -Level ACTION
                    return
                }
                try {
                    if ($hostExists) {
                        (Get-Item -LiteralPath $hostPath -Force).Attributes = 'Normal'
                        Remove-Item -LiteralPath $hostPath -Force -ErrorAction Stop
                    }
                    (Get-Item -LiteralPath $cachePath -Force).Attributes = 'Normal'
                    Move-Item -LiteralPath $cachePath -Destination $hostPath -ErrorAction Stop
                    Write-Log "Restored clean original: $hostPath" -Level OK
                }
                catch {
                    Write-Log "FAILED to restore '$hostPath': $($_.Exception.Message)" -Level ERROR
                }
            }
    }
    if ($pairs -eq 0) { Write-Log "No '._cache_*.exe' infected pairs found." -Level OK }
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
    # Clears Hidden/System on user files and scanned drives the worm hid.
    # Never deletes anything.
    Write-Log "Restoring visibility of files hidden by the malware..." -Level INFO
    $scanRoots = New-Object System.Collections.Generic.List[string]
    $scanRoots.Add($env:USERPROFILE)
    foreach ($r in (Get-ScanDriveRoots)) { $scanRoots.Add($r) }

    foreach ($root in $scanRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Write-Log "Un-hiding items under: $root" -Level INFO
        $scanned = 0
        Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $scanned++
                if ($scanned % 500 -eq 0) {
                    Write-Progress -Activity "Scanning for hidden items" -Status "$scanned items checked under $root"
                }
                if ((($_.Attributes -band [System.IO.FileAttributes]::Hidden) -eq 0) -and
                    (($_.Attributes -band [System.IO.FileAttributes]::System) -eq 0)) { return }
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
        Write-Progress -Activity "Scanning for hidden items" -Completed
    }
}

# ----------------------------------------------------------------------------
# Step 11 - Hosts file repair
# ----------------------------------------------------------------------------

function Repair-HostsFile {
    Write-Log "Checking the hosts file for malicious security/update blocks..." -Level INFO
    if (-not (Test-Path -LiteralPath $HostsFile)) { Write-Log "Hosts file not found." -Level WARN; return }

    $lines = $null
    try { $lines = Get-Content -LiteralPath $HostsFile -ErrorAction Stop }
    catch { Write-Log "Could not read hosts file: $($_.Exception.Message)" -Level WARN; return }

    $bad  = New-Object System.Collections.Generic.List[string]
    $keep = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        if (Test-HostsLineIsMalicious $line) {
            $bad.Add($line)
            Write-Log "Malicious hosts entry (blocks security/update): $($line.Trim())" -Level FOUND
        }
        else {
            $keep.Add($line)
        }
    }

    if ($bad.Count -eq 0) { Write-Log "No malicious hosts entries found." -Level OK; return }

    if ($DryRun) {
        Write-Log "WOULD back up the hosts file and remove $($bad.Count) malicious entr$(if($bad.Count -eq 1){'y'}else{'ies'})." -Level ACTION
        return
    }
    try {
        $backup = "$HostsFile.bak_{0:yyyyMMdd_HHmmss}" -f (Get-Date)
        Copy-Item -LiteralPath $HostsFile -Destination $backup -Force -ErrorAction Stop
        Set-Content -LiteralPath $HostsFile -Value $keep -Encoding ASCII -ErrorAction Stop
        Write-Log "Removed $($bad.Count) malicious hosts entr$(if($bad.Count -eq 1){'y'}else{'ies'}). Backup: $backup" -Level OK
    }
    catch {
        Write-Log "FAILED to repair hosts file: $($_.Exception.Message)" -Level ERROR
    }
}

# ----------------------------------------------------------------------------
# Step 12 - Optional VirusTotal hash lookup (read-only, informational)
# ----------------------------------------------------------------------------

function Invoke-VirusTotalLookup {
    param([string[]]$Paths)
    if ([string]::IsNullOrWhiteSpace($VirusTotalApiKey)) { return }

    Write-Log "Querying VirusTotal for detected files (informational only)..." -Level INFO
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $first = $true

    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { continue }
        $hash = $null
        try { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { continue }
        if (-not $seen.Add($hash)) { continue }

        # Free-tier keys allow 4 requests/minute - pace to stay under it.
        if (-not $first) { Start-Sleep -Seconds 16 }
        $first = $false

        for ($attempt = 1; $attempt -le 2; $attempt++) {
            try {
                $resp = Invoke-RestMethod -Method Get `
                    -Uri "https://www.virustotal.com/api/v3/files/$hash" `
                    -Headers @{ 'x-apikey' = $VirusTotalApiKey } `
                    -ErrorAction Stop
                $stats = $resp.data.attributes.last_analysis_stats
                $mal = [int]$stats.malicious
                $total = ([int]$stats.malicious + [int]$stats.suspicious + [int]$stats.undetected + [int]$stats.harmless)
                Write-Log "VirusTotal: $mal/$total engines flag '$path' (SHA256 $hash)." -Level FOUND
                break
            }
            catch {
                $status = $null
                try { $status = [int]$_.Exception.Response.StatusCode } catch {}
                if ($status -eq 404) {
                    Write-Log "VirusTotal: hash for '$path' is unknown to VT (SHA256 $hash)." -Level INFO
                    break
                }
                elseif ($status -eq 429 -and $attempt -eq 1) {
                    Write-Log "VirusTotal rate limit hit - waiting 60s and retrying once..." -Level WARN
                    Start-Sleep -Seconds 60
                }
                else {
                    Write-Log "VirusTotal lookup failed for '$path': $($_.Exception.Message)" -Level WARN
                    break
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

    Write-Log "Cleanup started. Genuine driver = valid Synaptics signature; protected tree = $TrustedRoot" -Level INFO

    Assert-Administrator
    New-RestoreCheckpoint

    $suspectPaths = Stop-MaliciousProcesses
    Remove-MaliciousScheduledTasks
    Remove-MaliciousServices

    # VirusTotal lookup runs BEFORE deletion so the files still exist on disk.
    $vtTargets = New-Object System.Collections.Generic.List[string]
    foreach ($p in $suspectPaths) { $vtTargets.Add($p) }
    foreach ($p in $KnownMaliciousPaths) { if (Test-Path -LiteralPath $p) { $vtTargets.Add($p) } }
    Invoke-VirusTotalLookup -Paths $vtTargets

    Remove-MaliciousFiles -ExtraPaths $suspectPaths
    Repair-InfectedExecutables
    Clear-RemovableDrives
    Remove-MaliciousRunKeys
    Remove-MaliciousStartupShortcuts
    Remove-WmiPersistence
    Remove-IFEOHijacks
    Clear-OfficePersistence
    Repair-HostsFile
    Repair-HiddenFileSettings
    Restore-HiddenItems

    Write-Log "Cleanup finished." -Level INFO
    Write-Log ("Summary: {0} finding(s), {1} item(s) flagged for manual review, {2} error(s)." -f `
        $script:Stats.FOUND, $script:Stats.WARN, $script:Stats.ERROR) -Level INFO
    if ($DryRun) {
        Write-Log "This was a DRY RUN. No changes were made. Re-run WITHOUT -DryRun to apply." -Level WARN
    }
    else {
        Write-Log "Reboot, then run a full antivirus scan to complete remediation." -Level INFO
    }
    Save-Log
}

# Run only when executed directly. Dot-sourcing (". .\Remove-SynapticsTrojan.ps1")
# loads the functions without performing any cleanup - the Pester tests rely on
# this. Exit codes: 0 clean, 1 not admin, 2 findings, 3 errors.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Cleanup
    if     ($script:Stats.ERROR -gt 0) { exit 3 }
    elseif ($script:Stats.FOUND -gt 0) { exit 2 }
    else                               { exit 0 }
}
