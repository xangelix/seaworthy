# scripts/windows-msi-update.ps1 - the Windows lab's update lane
# (.github/workflows/lab-windows.yml, job `update`): a Windows service updated through
# its update helper. The releases come from the build job's bundle
# (scripts/windows-lab-build.ps1): the lab's `agent` product
# (crates/seaworthy-launcher/e2e/scm/seaworthy.toml: the `scm` launcher, its cores and
# the `scm_helper` update helper, a throwaway ML-DSA-87 release key compiled in), built
# by the build plan, packaged by `seaworthy package` with WiX as 1.0.0-rc.1 and 1.0.0,
# Authenticode-signed with the build job's throwaway certificate, with signed release
# manifests.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-msi-update.ps1 -Bundle <bundle>
#
# Steps, each a JUnit case (target\junit\windows-msi-update\windows-msi-update.xml):
#   sequence  the MSIs' InstallExecuteSequence and CustomAction tables (Windows
#             Installer's own reading): the old product is removed right after
#             InstallInitialize (nothing that writes to the script may sit between them:
#             error 1603); the recovery actions run after InstallServices on a first
#             install or an upgrade only; the rollback actions that put a removed
#             version's recovery actions and helper DACL back sit in the removal's
#             sequence before DeleteServices, condition `Installed AND REMOVE="ALL"`, type
#             3426 (rollback, in the script, no impersonation, exit ignored, an exe in a
#             directory)
#   install   release 1.0.0-rc.1 (sequence 1) installed by hand (msiexec /i): the service
#             runs; the helper's service, <service>-update, is installed, LocalSystem,
#             demand-start and stopped, its DACL the .wxs's (start and query for the
#             service's account, nothing more); HKLM\SOFTWARE\<Vendor>\<Directory> holds
#             Release = 1.0.0~rc.1-1 and UpdatePolicy = auto; %ProgramData%\<Vendor>,
#             ...\<Directory>, its updates directory (the helper's staging), its
#             update-logs (the helper's log) and its state (which the service's account may
#             also write) are owned by SYSTEM or Administrators, grant no one else a write
#             and aren't reparse points; Programs and Features names the product by its non-ASCII
#             display name, whole (the MSI's UTF-8 code page); every installed binary
#             carries the release's version resource (FileVersion 1.0.0.1, ProductVersion
#             1.0.0-rc.1) and an Authenticode signature Windows accepts (the lane's
#             certificate trusted for the run), as does the MSI; the service's recovery
#             actions are the .wxs's (sc qfailure, sc qfailureflag)
#   serve     the lane's version gate and release server on loopback 127.0.0.1:8470
#             (seaworthy-service's windows_scm_e2e stub): `/required` answers 1.0.0, and
#             release 1.0.0 (sequence 2) and its signed manifest are served where the
#             helper looks: repo/releases/<package>/stable/<token>/<target>/<package>.msi
#   update    the update asked for as the service asks (StartService on the helper's
#             service): the helper verifies the release, stages it and hands it to
#             msiexec, detached, and exits ("handed <package> ... to its installer" in its
#             log); Windows Installer then upgrades: Release reads 1.0.0-2, the service
#             runs again under a new process, one Programs and Features entry, msiexec's
#             log (msiexec-last.log in the staging directory) reports success, the
#             helper's service is still installed and stopped, its DACL the .wxs's; the
#             binaries carry 1.0.0.2 and 1.0.0 and verify; the recovery actions survived
#             the upgrade
#   again     the helper asked again: nothing to install (up to date, a backoff or a run
#             too soon), it exits 0, the release and the service's process unchanged
#   repair    a standard user's repair (msiexec /fa ... UPDATES=off, run under this job's
#             token restricted to a standard user's: Administrators deny-only, no
#             privileges, medium integrity): it succeeds or is refused (the exit code is
#             recorded); either way UpdatePolicy is still auto, the release and the
#             recovery actions unchanged and the service running
#   rollback  release 1.0.1 (sequence 3), whose install fails after InstallServices (the
#             build's broken .wxs): the upgrade had removed 1.0.0 in the same transaction,
#             and Windows Installer rolls it all back: msiexec exits 1603, Release still
#             reads 1.0.0-2, one Programs and Features entry at 1.0.0, the service runs,
#             its recovery actions are the .wxs's, the helper's service is installed and
#             stopped and its DACL is the .wxs's again (the rollback actions)
#   remove    msiexec /x: both services, the program directory, the registry values and
#             the Programs and Features entry gone
#   squat     (on its own) a standard user creates %ProgramData%\<Vendor>,
#             ...\<Directory> and its state first, owning them (any user may create a
#             directory in ProgramData); 1.0.0-rc.1 installs over them and its launcher's
#             guard takes them back (SYSTEM owns them), and the helper updates to 1.0.0 from
#             its staging there (its audit accepts them); then removed
#   squat-content  (on its own, last) the same user also creates a directory of their own
#             inside the state directory: the guard refuses the install (1603, msiexec's
#             log names ProgramDataFolders), nothing is installed, and the planted
#             directory is left as it was
# The helper logs to %ProgramData%\<Vendor>\<Directory>\update-logs\scm_helper.log (the SCM
# gives a service no stderr); a failure prints it, msiexec's log, the server's output and
# both services' states. Every log is kept under target\windows-msi-update\evidence.
#
# A throwaway machine (a GitHub-hosted runner): it installs services, changes HKLM,
# creates a local user and trusts the lane's throwaway certificate, as an administrator,
# and undoes the last two. Windows PowerShell 5.1 or PowerShell 7: this file is ASCII, so
# the display name is built from its characters' code points (a BOM-less script reads as
# ANSI in Windows PowerShell).
[CmdletBinding()]
param(
    [string]$Bundle = $(if ($env:SEAWORTHY_LAB_BUNDLE) { $env:SEAWORTHY_LAB_BUNDLE } else { 'target\windows-lab\bundle' }),
    [string]$Product = 'agent',
    # seaworthy.toml's display-name: "Acme E2E Agent (Pr<U+00FC>fung, <U+8A66><U+9A13>)".
    [string]$DisplayName = ('Acme E2E Agent (Pr' + [char]0x00FC + 'fung, ' + [char]0x8A66 + [char]0x9A13 + ')'),
    [string]$Vendor = 'AcmeE2E',
    [string]$Directory = 'Agent',
    [string]$Package = 'acmee2e-agent',
    [string]$Service = 'AcmeAgent',
    # The helper's log stem (seaworthy.toml's `helper`).
    [string]$HelperExe = 'scm_helper',
    # What the lane's gate answers (no build metadata: the releases carry none).
    [string]$Token = '1.0.0',
    # The helper's compiled-in gate and release server (scm_helper/build.rs's default URLs).
    [int]$Port = 8470,
    [int]$UpdateSeconds = 300,
    [string]$JUnitDir = $(if ($env:SEAWORTHY_JUNIT_DIR) { $env:SEAWORTHY_JUNIT_DIR } else { 'target\junit\windows-msi-update' }),
    [string]$EvidenceDir = $(if ($env:SEAWORTHY_EVIDENCE_DIR) { $env:SEAWORTHY_EVIDENCE_DIR } else { 'target\windows-msi-update\evidence' })
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Results = New-Object System.Collections.Generic.List[object]
New-Item -ItemType Directory -Force -Path $JUnitDir, $EvidenceDir | Out-Null
$JUnit = (Resolve-Path -LiteralPath $JUnitDir).Path
$Evidence = (Resolve-Path -LiteralPath $EvidenceDir).Path
$Bundle = (Resolve-Path -LiteralPath $Bundle).Path

function Write-Log([string]$Text) { Write-Host ("{0:HH:mm:ss.fff} {1}" -f (Get-Date), $Text) }
function Assert-True([bool]$Condition, [string]$Why) { if (-not $Condition) { throw "ASSERTION FAILED: $Why" } }

# Runs a step. A failed step stops the steps after it (they're reported as skipped),
# unless it is -Independent: then the run goes on without it.
function Invoke-Step([string]$Name, [scriptblock]$Body, [switch]$Independent) {
    Write-Host ''
    Write-Host "=== STEP $Name ==="
    $started = Get-Date
    $failure = $null
    if ($Results | Where-Object { $_.Failure -and -not $_.Independent }) {
        $failure = 'not run: an earlier step failed (fail-fast)'
        Write-Log $failure
        $Results.Add([pscustomobject]@{ Name = $Name; Seconds = 0; Failure = $failure; Skipped = $true; Independent = $true })
        return
    }
    try { & $Body } catch { $failure = "$($_.Exception.Message)`n$($_.ScriptStackTrace)"; Write-Log "FAIL $Name -- $failure" }
    $Results.Add([pscustomobject]@{ Name = $Name; Seconds = ((Get-Date) - $started).TotalSeconds; Failure = $failure; Skipped = $false; Independent = [bool]$Independent })
}

function Write-JUnit {
    $failures = @($Results | Where-Object { $_.Failure -and -not $_.Skipped }).Count
    $skipped = @($Results | Where-Object { $_.Skipped }).Count
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $xml = New-Object System.Text.StringBuilder
    [void]$xml.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$xml.AppendLine("<testsuite name=`"windows-msi-update`" tests=`"$($Results.Count)`" failures=`"$failures`" skipped=`"$skipped`">")
    foreach ($r in $Results) {
        $name = [Security.SecurityElement]::Escape($r.Name)
        [void]$xml.Append("  <testcase classname=`"windows-msi-update`" name=`"$name`" time=`"$([Math]::Round($r.Seconds, 3).ToString($inv))`"")
        if ($r.Skipped) { [void]$xml.AppendLine('><skipped/></testcase>') }
        elseif ($r.Failure) { [void]$xml.AppendLine("><failure message=`"$([Security.SecurityElement]::Escape(($r.Failure -split "`n")[0]))`">$([Security.SecurityElement]::Escape($r.Failure))</failure></testcase>") }
        else { [void]$xml.AppendLine('/>') }
    }
    [void]$xml.AppendLine('</testsuite>')
    [IO.File]::WriteAllText((Join-Path $JUnit 'windows-msi-update.xml'), $xml.ToString())
}

# msiexec's own process, its log kept as evidence (not Start-Process -Wait, which waits
# on every descendant through a job object).
function Invoke-Msiexec([string[]]$Arguments, [string]$Log) {
    $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', "`"$Log`"")) -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(900000)) { $p.Kill(); throw "msiexec $($Arguments -join ' ') took longer than 15 minutes" }
    return $p.ExitCode
}

# Polls $Condition once a second for up to $Seconds.
function Wait-Until([int]$Seconds, [string]$What, [scriptblock]$Condition) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (& $Condition)) {
        if ((Get-Date) -gt $deadline) { throw "ASSERTION FAILED: $What (after $Seconds s)" }
        Start-Sleep -Seconds 1
    }
}

# A service as Windows' WMI reports it (State, StartMode, StartName, ProcessId,
# ExitCode, ServiceSpecificExitCode), or $null.
function Get-Svc([string]$Name) {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
}

# The Programs and Features entries of this product (by display name); every caller
# takes @(Get-Entries) (Windows PowerShell 5.1 unrolls one entry).
function Get-Entries {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    @(foreach ($root in $roots) {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if ($p -and ($p.PSObject.Properties.Name -contains 'DisplayName') -and $p.DisplayName -eq $DisplayName) {
                    [pscustomobject]@{ Code = $_.PSChildName; Version = $p.DisplayVersion }
                }
            }
        })
}

# Every Programs and Features entry whose name starts like this product's, with its
# characters' code points: what a code page lost, when the name isn't found whole.
function Show-NearEntries {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and ($p.PSObject.Properties.Name -contains 'DisplayName') -and ([string]$p.DisplayName).StartsWith('Acme E2E')) {
                $points = @([string]$p.DisplayName -split '' | Where-Object { $_ } | ForEach-Object { '{0:X4}' -f [int][char]$_ }) -join ' '
                Write-Log "  entry $($_.PSChildName): $points"
            }
        }
    }
    $wanted = @($DisplayName -split '' | Where-Object { $_ } | ForEach-Object { '{0:X4}' -f [int][char]$_ }) -join ' '
    Write-Log "  wanted: $wanted"
}

$Key = "HKLM:\SOFTWARE\$Vendor\$Directory"
# A value of the product's key, or $null (during an upgrade the key may be briefly gone).
function Get-RegValue([string]$Name) {
    $item = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $Name)) { return [string]$item.$Name }
    return $null
}

# SYSTEM, Administrators, TrustedInstaller: the only principals that may own or write
# the helper's directories (seaworthy-updater's rule).
$TrustedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# Rights that change a directory or what's in it: add file, add subdirectory, write
# extended attributes, delete child, write attributes, delete, write DAC, write owner,
# generic all, generic write.
$WriteRights = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
function Get-Owner([string]$Path) {
    (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
}
# The service's virtual account, which its state directory admits as a writer.
function Get-ServiceSid {
    (New-Object Security.Principal.NTAccount("NT SERVICE\$Service")).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Assert-PrivateDirectory([string]$Path, [string[]]$Also = @()) {
    $item = Get-Item -LiteralPath $Path -Force
    # FILE_ATTRIBUTE_REPARSE_POINT: a junction or a link.
    Assert-True ((([int]$item.Attributes) -band 0x400) -eq 0) "$Path is not a reparse point"
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Assert-True ($TrustedSids -contains $owner) "$Path is owned by SYSTEM, Administrators or TrustedInstaller (it is owned by $owner)"
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        # InheritOnly: applies to children only, not to the directory.
        if ((([int]$rule.PropagationFlags) -band 2) -ne 0) { continue }
        $sid = $rule.IdentityReference.Value
        if ($TrustedSids -contains $sid -or $Also -contains $sid) { continue }
        $rights = [int]$rule.FileSystemRights
        Assert-True (($rights -band $WriteRights) -eq 0) "$Path grants $sid no write access (it grants $($rule.FileSystemRights))"
    }
}

$HelperService = "$Service-update"
$Target = 'x86_64-pc-windows-msvc'
$InstallDir = Join-Path $env:ProgramFiles "$Vendor\$Directory"
$VendorData = Join-Path $env:ProgramData $Vendor
$Support = Join-Path $VendorData $Directory
$State = Join-Path $Support 'state'
$Staging = Join-Path $Support 'updates'
$HelperLogs = Join-Path $Support 'update-logs'
$HelperLog = Join-Path $HelperLogs "$HelperExe.log"
$MsiexecLog = Join-Path $Staging 'msiexec-last.log'
$ServerExe = Join-Path $Bundle 'bin\windows_scm_e2e.exe'
$Www = Join-Path ([IO.Path]::GetTempPath()) 'seaworthy-msi-update-www'
$Server = $null

# The bundle's MSI of one release.
function Get-Msi([string]$Dir) {
    $packages = Join-Path $Bundle "$Dir\packages"
    $msi = @(Get-ChildItem -LiteralPath $packages -Filter '*.msi' -File -ErrorAction SilentlyContinue)
    Assert-True ($msi.Count -eq 1) "one MSI under $packages (found $($msi.Count))"
    return $msi[0].FullName
}

# A release the helper may install: its MSI and its signed manifest beside it.
function Get-Release([string]$Dir) {
    $msi = Get-Msi $Dir
    Assert-True (Test-Path -LiteralPath "$msi.manifest" -PathType Leaf) "$(Split-Path -Leaf $msi) has its signed manifest"
    return $msi
}

# The .wxs a release's MSI was built from (beside it in the bundle).
function Get-Wxs([string]$Dir) {
    $packages = Join-Path $Bundle "$Dir\packages"
    $wxs = @(Get-ChildItem -LiteralPath $packages -Filter '*.wxs' -File -ErrorAction SilentlyContinue)
    Assert-True ($wxs.Count -eq 1) "one .wxs under $packages (found $($wxs.Count))"
    return [IO.File]::ReadAllText($wxs[0].FullName)
}

# The tail of a log, if it exists (msiexec writes UTF-16; Get-Content reads its BOM).
function Show-Tail([string]$Path, [int]$Lines = 60) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Write-Host "--- $Path (last $Lines lines)"
        Get-Content -LiteralPath $Path -Tail $Lines | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "--- $($Path): none"
    }
}

function Show-Diagnostics {
    Write-Host ''
    Write-Host '=== DIAGNOSTICS ==='
    foreach ($name in @($Service, $HelperService)) {
        $s = Get-Svc $name
        if ($s) { Write-Host "$name : $($s.State), start $($s.StartMode), as $($s.StartName), pid $($s.ProcessId), exit $($s.ExitCode) (service-specific $($s.ServiceSpecificExitCode))" }
        else { Write-Host "$name : not installed" }
    }
    Write-Host "Release = '$(Get-RegValue 'Release')', UpdatePolicy = '$(Get-RegValue 'UpdatePolicy')'"
    Show-NearEntries
    Show-Tail $HelperLog
    Show-Tail $MsiexecLog 80
    Show-Tail (Join-Path $Evidence 'server.err') 40
}

# ---------------------------------------------------------------------------
# The MSI's own tables, read through Windows Installer's automation object.

$Installer = New-Object -ComObject WindowsInstaller.Installer
function Invoke-Com($Object, [string]$Member, [Reflection.BindingFlags]$Kind, [object[]]$Arguments) {
    $Object.GetType().InvokeMember($Member, $Kind, $null, $Object, $Arguments)
}

# Rows of `SELECT <columns> FROM <table>` as objects named by the columns.
function Get-MsiRows([string]$Msi, [string]$Table, [string[]]$Columns) {
    $method = [Reflection.BindingFlags]::InvokeMethod
    $property = [Reflection.BindingFlags]::GetProperty
    # 0: msiOpenDatabaseModeReadOnly.
    $database = Invoke-Com $Installer 'OpenDatabase' $method @($Msi, 0)
    $view = $null
    try {
        $query = 'SELECT ' + (($Columns | ForEach-Object { '`' + $_ + '`' }) -join ', ') + ' FROM `' + $Table + '`'
        $view = Invoke-Com $database 'OpenView' $method @($query)
        Invoke-Com $view 'Execute' $method @() | Out-Null
        $rows = New-Object System.Collections.Generic.List[object]
        while ($true) {
            $record = Invoke-Com $view 'Fetch' $method @()
            if ($null -eq $record) { break }
            $row = [ordered]@{}
            for ($i = 0; $i -lt $Columns.Count; $i++) { $row[$Columns[$i]] = [string](Invoke-Com $record 'StringData' $property @($i + 1)) }
            $rows.Add([pscustomobject]$row)
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($record)
        }
        return $rows.ToArray()
    } finally {
        if ($view) { Invoke-Com $view 'Close' $method @() | Out-Null; [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view) }
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database)
    }
}

# The ordering and rollback rules of a service MSI's sequence (the step's header).
function Assert-MsiSequence([string]$Msi) {
    $name = Split-Path -Leaf $Msi
    $sequence = @{}
    foreach ($row in @(Get-MsiRows $Msi 'InstallExecuteSequence' @('Action', 'Condition', 'Sequence'))) { $sequence[$row.Action] = $row }
    $actions = @{}
    foreach ($row in @(Get-MsiRows $Msi 'CustomAction' @('Action', 'Type', 'Source', 'Target'))) { $actions[$row.Action] = $row }
    $at = {
        param([string]$Action)
        Assert-True ($sequence.ContainsKey($Action)) "${name}: InstallExecuteSequence schedules $Action"
        [int]$sequence[$Action].Sequence
    }
    Assert-True ((& $at 'RemoveExistingProducts') -eq (& $at 'InstallInitialize') + 1) "${name}: RemoveExistingProducts runs right after InstallInitialize ($(& $at 'RemoveExistingProducts') vs $(& $at 'InstallInitialize')): nothing that writes to the script sits between them"
    foreach ($action in @('ServiceRecovery', 'ServiceRecoveryOnErrorExit')) {
        Assert-True ($actions.ContainsKey($action) -and $actions[$action].Type -eq '3106') "${name}: $action is a deferred, non-impersonated exe custom action (type 3106)"
        Assert-True ($sequence[$action].Condition -eq 'NOT Installed AND NOT REMOVE="ALL"') "${name}: $action runs on a first install or an upgrade only (condition '$($sequence[$action].Condition)')"
        Assert-True ((& $at 'InstallServices') -lt (& $at $action) -and (& $at $action) -lt (& $at 'StartServices')) "${name}: $action runs after InstallServices and before StartServices"
    }
    foreach ($action in @('ServiceRecoveryRollback', 'ServiceRecoveryOnErrorExitRollback', 'HelperServiceDaclRollback')) {
        Assert-True ($actions.ContainsKey($action)) "${name}: the CustomAction table holds $action"
        Assert-True ($actions[$action].Type -eq '3426') "${name}: $action is type 3426 (rollback, in the script, no impersonation, exit ignored, an exe in a directory; it is $($actions[$action].Type))"
        Assert-True ($sequence[$action].Condition -eq 'Installed AND REMOVE="ALL"') "${name}: $action runs on a removal only (condition '$($sequence[$action].Condition)')"
        Assert-True ((& $at 'StopServices') -lt (& $at $action) -and (& $at $action) -lt (& $at 'DeleteServices')) "${name}: $action sits before DeleteServices, in the removal's sequence"
    }
    # The %ProgramData% guard: the installed launcher (18) in the script (1024) as SYSTEM
    # (2048), after the files and before the services, on a first install or an upgrade.
    Assert-True ($actions.ContainsKey('ProgramDataFolders') -and $actions['ProgramDataFolders'].Type -eq '3090') "${name}: ProgramDataFolders runs the installed launcher, deferred, as SYSTEM (type 3090)"
    Assert-True ($actions['ProgramDataFolders'].Target.StartsWith('--seaworthy-install-programdata ')) "${name}: ProgramDataFolders passes the guard's argument (target '$($actions['ProgramDataFolders'].Target)')"
    Assert-True ($sequence['ProgramDataFolders'].Condition -eq 'NOT Installed AND NOT REMOVE="ALL"') "${name}: ProgramDataFolders runs on a first install or an upgrade only"
    Assert-True ((& $at 'RemoveExistingProducts') -lt (& $at 'InstallFiles') -and (& $at 'InstallFiles') -lt (& $at 'ProgramDataFolders') -and (& $at 'ProgramDataFolders') -lt (& $at 'InstallServices')) "${name}: ProgramDataFolders runs after InstallFiles and before InstallServices"
    Write-Log "${name}: RemoveExistingProducts at $(& $at 'RemoveExistingProducts') right after InstallInitialize; the recovery, rollback and %ProgramData% actions in place"
}

# ---------------------------------------------------------------------------
# A standard user: LogonUser and in-process impersonation create the squatter's
# directories as that user (a child process under another user's credentials can't
# start in a CI job: no access to the job's window station, 0xC0000142); the repair runs
# msiexec under this job's own token restricted to a standard user's (Administrators
# deny-only, privileges removed, medium integrity), which keeps the window station.
# C# 5: Windows PowerShell 5.1's Add-Type compiles with the .NET Framework's compiler.
$LaneSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class SeaworthyMsiLane
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel { public SidAndAttributes Label; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint Low; public int High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Cb; public string Reserved; public string Desktop; public string Title;
        public int X; public int Y; public int XSize; public int YSize; public int XCountChars; public int YCountChars;
        public int FillAttribute; public int Flags; public short ShowWindow; public short Reserved2Count;
        public IntPtr Reserved2; public IntPtr StdInput; public IntPtr StdOutput; public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr Process; public IntPtr Thread; public int ProcessId; public int ThreadId; }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUserW(string user, string domain, string password, int logonType, int provider, out IntPtr token);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string system, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state, uint length, IntPtr previous, IntPtr returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableSidCount, SidAndAttributes[] sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictedSidCount, IntPtr sidsToRestrict, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(IntPtr token, int infoClass, ref TokenMandatoryLabel info, uint length);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(IntPtr token, string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private const int LogonInteractive = 2;          // LOGON32_LOGON_INTERACTIVE
    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint DisableMaxPrivilege = 0x1;   // keeps SeChangeNotifyPrivilege only
    private const int TokenIntegrityLevel = 25;
    private const uint SeGroupIntegrity = 0x20;
    private const uint SePrivilegeEnabled = 0x2;
    private const uint CreateNoWindow = 0x08000000;
    private const uint WaitTimeout = 0x102;

    // Logs the local user on: the token the impersonated calls run with.
    public static SafeAccessTokenHandle LogOn(string user, string password)
    {
        IntPtr token;
        if (!LogonUserW(user, ".", password, LogonInteractive, 0, out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return new SafeAccessTokenHandle(token);
    }

    // The token's user SID.
    public static string UserSid(SafeAccessTokenHandle token)
    {
        using (WindowsIdentity identity = new WindowsIdentity(token.DangerousGetHandle()))
        {
            return identity.User.Value;
        }
    }

    // As the token: creates each directory (and its parents), owned by it.
    public static void CreateDirectories(SafeAccessTokenHandle token, string[] paths)
    {
        WindowsIdentity.RunImpersonated(token, () =>
        {
            foreach (string path in paths)
            {
                Directory.CreateDirectory(path);
            }
        });
    }

    private static byte[] SidBytes(SecurityIdentifier sid)
    {
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        return bytes;
    }

    // Runs `commandLine` under this process's token restricted to a standard user's:
    // Administrators deny-only, every privilege but change-notify removed, medium
    // integrity. Its exit code; a run past `milliseconds` is terminated and throws.
    public static int RunRestricted(string commandLine, uint milliseconds)
    {
        IntPtr process;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery | TokenDuplicate | TokenAssignPrimary | TokenAdjustDefault | TokenAdjustPrivileges, out process))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken");
        }
        IntPtr restricted = IntPtr.Zero;
        GCHandle admins = GCHandle.Alloc(SidBytes(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)), GCHandleType.Pinned);
        GCHandle medium = GCHandle.Alloc(SidBytes(new SecurityIdentifier("S-1-16-8192")), GCHandleType.Pinned);
        try
        {
            // CreateProcessAsUser wants the quota privilege enabled (a token restricted
            // from this process's own needs no assign-primary).
            Luid quota;
            if (LookupPrivilegeValueW(null, "SeIncreaseQuotaPrivilege", out quota))
            {
                TokenPrivileges enable = new TokenPrivileges { Count = 1, Luid = quota, Attributes = SePrivilegeEnabled };
                AdjustTokenPrivileges(process, false, ref enable, 0, IntPtr.Zero, IntPtr.Zero);
            }
            SidAndAttributes[] disable = { new SidAndAttributes { Sid = admins.AddrOfPinnedObject(), Attributes = 0 } };
            if (!CreateRestrictedToken(process, DisableMaxPrivilege, 1, disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken");
            }
            TokenMandatoryLabel label = new TokenMandatoryLabel();
            label.Label.Sid = medium.AddrOfPinnedObject();
            label.Label.Attributes = SeGroupIntegrity;
            uint length = (uint)(Marshal.SizeOf(typeof(TokenMandatoryLabel)) + new SecurityIdentifier("S-1-16-8192").BinaryLength);
            if (!SetTokenInformation(restricted, TokenIntegrityLevel, ref label, length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetTokenInformation (integrity)");
            }
            StartupInfo startup = new StartupInfo();
            startup.Cb = Marshal.SizeOf(typeof(StartupInfo));
            ProcessInformation information;
            if (!CreateProcessAsUserW(restricted, null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, false, CreateNoWindow, IntPtr.Zero, null, ref startup, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser");
            }
            try
            {
                if (WaitForSingleObject(information.Process, milliseconds) == WaitTimeout)
                {
                    TerminateProcess(information.Process, 1);
                    throw new TimeoutException(commandLine + " ran longer than " + milliseconds + " ms");
                }
                uint code;
                if (!GetExitCodeProcess(information.Process, out code))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess");
                }
                return unchecked((int)code);
            }
            finally
            {
                CloseHandle(information.Thread);
                CloseHandle(information.Process);
            }
        }
        finally
        {
            admins.Free();
            medium.Free();
            if (restricted != IntPtr.Zero) { CloseHandle(restricted); }
            CloseHandle(process);
        }
    }
}
'@
if (-not ('SeaworthyMsiLane' -as [type])) { Add-Type -TypeDefinition $LaneSource -Language CSharp }

$SquatUser = 'acmesquat'
# Never on a command line or in the log: New-LocalUser takes a SecureString.
$SquatPassword = 'Aq9!' + [Guid]::NewGuid().ToString('N').Substring(0, 20)
$SquatSid = $null

function New-LaneUser([string]$Name, [string]$Password) {
    if (Get-Command -Name 'New-LocalUser' -ErrorAction SilentlyContinue) {
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
        # A local account's description holds at most 48 characters.
        $null = New-LocalUser -Name $Name -Password $secure -AccountNeverExpires -PasswordNeverExpires -Description 'msi lane: ProgramData squatter (removed)'
    } else {
        $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
        $account = $computer.Create('User', $Name)
        $account.SetPassword($Password)
        $account.SetInfo()
    }
}

function Remove-LaneUser([string]$Name) {
    if (Get-Command -Name 'Remove-LocalUser' -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $Name -ErrorAction SilentlyContinue
    } else {
        try { ([ADSI]"WinNT://$env:COMPUTERNAME,computer").Delete('User', $Name) } catch { }
    }
}

# ---------------------------------------------------------------------------
# The lane's code-signing certificate (the build job's, the one seaworthy.toml pins),
# trusted for this run: Authenticode verified by Windows itself
# (Get-AuthenticodeSignature), not only by the CLI's pins.
$LaneCert = $null
function Import-LaneCertificate {
    $pem = Join-Path $Bundle 'codesign.pem'
    Assert-True (Test-Path -LiteralPath $pem -PathType Leaf) "the lane's certificate $pem (the build job's)"
    $base64 = ((Get-Content -LiteralPath $pem) | Where-Object { $_ -notmatch '-----' }) -join ''
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String($base64))
    foreach ($name in @('Root', 'TrustedPublisher')) {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store ($name, 'LocalMachine')
        $store.Open('ReadWrite')
        $store.Add($cert)
        $store.Close()
    }
    $script:LaneCert = $cert
    Write-Log "trusted the lane's certificate $($cert.Subject) ($($cert.Thumbprint)) for this run"
}

function Remove-LaneCertificate {
    if (-not $script:LaneCert) { return }
    foreach ($name in @('Root', 'TrustedPublisher')) {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store ($name, 'LocalMachine')
        $store.Open('ReadWrite')
        $store.Remove($script:LaneCert)
        $store.Close()
    }
}

function Assert-Signed([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    Assert-True ($signature.Status -eq 'Valid') "$Path carries an Authenticode signature Windows accepts (status $($signature.Status): $($signature.StatusMessage))"
    Assert-True ($signature.SignerCertificate.Thumbprint -eq $script:LaneCert.Thumbprint) "$Path is signed by the lane's certificate (signed by $($signature.SignerCertificate.Subject))"
}

# Every installed binary: the release's version resource (the CLI's stamp: FileVersion
# major.minor.patch.sequence, ProductVersion the release as written, the product's name)
# and a valid signature.
function Assert-InstalledBinaries([string]$FileVersion, [string]$ProductVersion, [bool]$PreRelease) {
    $binaries = @(Get-ChildItem -LiteralPath $InstallDir -Recurse -File -Include '*.exe', '*.dll')
    Assert-True ($binaries.Count -ge 3) "the launcher, the helper and the cores are installed under $InstallDir (found $($binaries.Count))"
    foreach ($binary in $binaries) {
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($binary.FullName)
        $fixed = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
        Assert-True ($info.FileVersion -eq $FileVersion -and $fixed -eq $FileVersion) "$($binary.Name): FileVersion $FileVersion (string '$($info.FileVersion)', fixed $fixed)"
        Assert-True ($info.ProductVersion -eq $ProductVersion) "$($binary.Name): ProductVersion $ProductVersion (it is '$($info.ProductVersion)')"
        Assert-True ($info.IsPreRelease -eq $PreRelease) "$($binary.Name): pre-release flag $PreRelease"
        Assert-True ($info.ProductName -eq $DisplayName) "$($binary.Name): ProductName is the display name, whole (it is '$($info.ProductName)')"
        Assert-Signed $binary.FullName
    }
    Write-Log "$($binaries.Count) installed binaries carry $FileVersion / $ProductVersion and verify"
}

# The service's recovery actions as the .wxs's ServiceRecovery custom actions set them
# (sc.exe failure ... reset= N actions= a/d[/a/d...], sc.exe failureflag ... F), against
# what the SCM reports.
function Get-ExpectedRecovery([string]$Wxs) {
    $failure = [regex]::Match($Wxs, "failure $([regex]::Escape($Service)) reset= (\d+) actions= ([^""&]+)")
    $flag = [regex]::Match($Wxs, "failureflag $([regex]::Escape($Service)) (\d)")
    Assert-True ($failure.Success -and $flag.Success) "the .wxs sets $Service's recovery actions (ServiceRecovery, ServiceRecoveryOnErrorExit)"
    [pscustomobject]@{ Reset = $failure.Groups[1].Value; Actions = $failure.Groups[2].Value.Trim(); Flag = $flag.Groups[1].Value }
}

function Get-Recovery {
    $q = (& sc.exe qfailure $Service 2048 | Out-String)
    $reset = [regex]::Match($q, 'RESET_PERIOD \(in seconds\)\s*:\s*(\d+)')
    $actions = @([regex]::Matches($q, '(RESTART|RUN PROCESS|REBOOT) -- Delay = (\d+) milliseconds') | ForEach-Object {
            '{0}/{1}' -f ($_.Groups[1].Value.ToLowerInvariant() -replace ' ', ''), $_.Groups[2].Value
        }) -join '/'
    $f = (& sc.exe qfailureflag $Service | Out-String)
    $flag = if ($f -match 'FAILURE_ACTIONS_ON_NONCRASH_FAILURES\s*:\s*TRUE') { '1' } elseif ($f -match 'FAILURE_ACTIONS_ON_NONCRASH_FAILURES\s*:\s*FALSE') { '0' } else { '?' }
    [pscustomobject]@{ Reset = $(if ($reset.Success) { $reset.Groups[1].Value } else { '?' }); Actions = $actions; Flag = $flag; Raw = "$q`n$f" }
}

function Assert-Recovery([string]$When) {
    $want = $script:ExpectedRecovery
    $got = Get-Recovery
    Assert-True ($got.Reset -eq $want.Reset -and $got.Actions -eq $want.Actions -and $got.Flag -eq $want.Flag) `
        "$When, $Service's recovery is reset $($want.Reset) s, actions $($want.Actions), on non-crash failures $($want.Flag) (sc reports reset $($got.Reset), actions '$($got.Actions)', flag $($got.Flag)):`n$($got.Raw)"
    Write-Log "$When, $Service's recovery: reset $($got.Reset) s, actions $($got.Actions), on non-crash failures $($got.Flag)"
}

# The helper service's DACL, as the .wxs's MsiLockPermissionsEx gives it: the service's
# account may start and query it, nothing more.
function Get-HelperDacl([string]$Wxs) {
    $sddl = [regex]::Match($Wxs, '<ServiceInstall Id="HelperService"[^>]*>\s*<PermissionEx Sddl="([^"]+)"')
    Assert-True $sddl.Success 'the .wxs gives the helper service a DACL'
    [Net.WebUtility]::HtmlDecode($sddl.Groups[1].Value)
}

# A rolled-back upgrade recreates the helper service from Windows Installer's record:
# the .wxs's rollback action puts its DACL back.
function Assert-HelperDacl([string]$When) {
    $wanted = $script:HelperDacl
    # sc's output: a blank line, then the descriptor. An empty pipeline casts to $null,
    # not '': say what sc printed when it holds none.
    $raw = (& sc.exe sdshow $HelperService 2>&1 | Out-String)
    $scExit = $LASTEXITCODE
    $shown = @($raw -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(O:|G:|D:)' }) | Select-Object -First 1
    Assert-True ([bool]$shown) "$When, sc sdshow $HelperService printed no security descriptor (exit $scExit): $($raw.Trim())"
    # The DACL: from D: up to the SACL's S: (an ACE's rights, such as SW, never hold a
    # colon).
    $at = $shown.IndexOf('D:')
    $dacl = if ($at -ge 0) { ($shown.Substring($at) -csplit 'S:', 2)[0] } else { '' }
    Assert-True ($dacl -eq $wanted) "$When, $HelperService's DACL is the .wxs's $wanted (sc sdshow: $shown)"
    Write-Log "$When, $HelperService's DACL is the .wxs's"
}

# The helper's and msiexec's logs, kept as evidence (the squat step removes the
# directories that hold the first run's).
function Save-Logs([string]$Prefix) {
    foreach ($log in @($HelperLog, $MsiexecLog)) {
        if (Test-Path -LiteralPath $log -PathType Leaf) {
            Copy-Item -LiteralPath $log -Destination (Join-Path $Evidence ($Prefix + (Split-Path -Leaf $log))) -Force
        }
    }
}

# Waits for Windows Installer's client the helper started on the staged release.
function Wait-StagedInstall {
    Wait-Until 300 'the upgrade finishes (no msiexec /i of the staged release left)' {
        -not @(Get-CimInstance -ClassName Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($Staging, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    }
}

$rc1 = $null
$v1 = $null
$firstPid = $null
$ExpectedRecovery = $null
$HelperDacl = $null

Invoke-Step 'sequence' {
    foreach ($dir in @("$Product-rc1", "$Product-v1", "$Product-bad")) { Assert-MsiSequence (Get-Msi $dir) }
}

Invoke-Step 'install' {
    $script:rc1 = Get-Release "$Product-rc1"
    $script:v1 = Get-Release "$Product-v1"
    Assert-True (Test-Path -LiteralPath $ServerExe -PathType Leaf) "the lane's server $ServerExe"
    Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "$InstallDir doesn't exist before the install (a clean runner)"
    Assert-True (-not (Get-Svc $Service)) "$Service isn't installed before the install"
    Import-LaneCertificate
    $wxs = Get-Wxs "$Product-rc1"
    $script:ExpectedRecovery = Get-ExpectedRecovery $wxs
    $code = Invoke-Msiexec @('/i', "`"$script:rc1`"") (Join-Path $Evidence 'install.log')
    Assert-True ($code -eq 0) "msiexec /i of 1.0.0-rc.1 exited $code"
    Wait-Until 60 "$Service runs" { $s = Get-Svc $Service; $s -and $s.State -eq 'Running' }
    $helper = Get-Svc $HelperService
    Assert-True ([bool]$helper) "the helper's service $HelperService is installed"
    Assert-True ($helper.StartMode -eq 'Manual') "$HelperService is demand-start (it is $($helper.StartMode))"
    Assert-True ($helper.StartName -eq 'LocalSystem') "$HelperService runs as LocalSystem (it runs as $($helper.StartName))"
    Assert-True ($helper.State -eq 'Stopped') "$HelperService waits, stopped (it is $($helper.State))"
    $script:HelperDacl = Get-HelperDacl $wxs
    Assert-HelperDacl 'after the first install'
    Assert-True ((Get-RegValue 'Release') -eq '1.0.0~rc.1-1') "$Key\Release is 1.0.0~rc.1-1 (it is '$(Get-RegValue 'Release')')"
    Assert-True ((Get-Item -LiteralPath $Key).GetValueKind('Release') -eq [Microsoft.Win32.RegistryValueKind]::String) "$Key\Release is a REG_SZ"
    Assert-True ((Get-RegValue 'UpdatePolicy') -eq 'auto') "$Key\UpdatePolicy is auto (it is '$(Get-RegValue 'UpdatePolicy')')"
    foreach ($dir in @($VendorData, $Support, $Staging, $HelperLogs)) { Assert-PrivateDirectory $dir }
    Assert-PrivateDirectory $State @(Get-ServiceSid)
    $entries = @(Get-Entries)
    if ($entries.Count -ne 1) { Show-NearEntries }
    Assert-True ($entries.Count -eq 1) "one Programs and Features entry named $DisplayName, whole (found $($entries.Count))"
    Assert-InstalledBinaries '1.0.0.1' '1.0.0-rc.1' $true
    Assert-Signed $script:rc1
    Assert-Recovery 'after the first install'
    $script:firstPid = (Get-Svc $Service).ProcessId
    Write-Log "installed 1.0.0-rc.1: $Service runs (pid $script:firstPid), $HelperService waits"
}

Invoke-Step 'serve' {
    $release = Join-Path $Www "repo\releases\$Package\stable\$Token\$Target"
    if (Test-Path -LiteralPath $Www) { Remove-Item -LiteralPath $Www -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $release | Out-Null
    Copy-Item -LiteralPath $script:v1 -Destination (Join-Path $release "$Package.msi")
    Copy-Item -LiteralPath "$($script:v1).manifest" -Destination (Join-Path $release "$Package.msi.manifest")
    [IO.File]::WriteAllText((Join-Path $Www 'required.txt'), "$Token`n")
    $ready = Join-Path $Evidence 'server.ready'
    Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
    $script:Server = Start-Process -FilePath $ServerExe -NoNewWindow -PassThru `
        -ArgumentList @('serve', '--root', "`"$Www`"", '--log', "`"$(Join-Path $Evidence 'server-requests.log')`"", '--ready-file', "`"$ready`"", '--port', "$Port", '--lifetime-secs', '3600') `
        -RedirectStandardOutput (Join-Path $Evidence 'server.out') -RedirectStandardError (Join-Path $Evidence 'server.err')
    Wait-Until 30 "the lane's server is ready" { Test-Path -LiteralPath $ready }
    Write-Log "the gate answers $Token on $((Get-Content -LiteralPath $ready -Raw).Trim()); 1.0.0 is served from $release"
}

Invoke-Step 'update' {
    & sc.exe start $HelperService | Out-Host
    Assert-True ($LASTEXITCODE -eq 0) "sc.exe start $HelperService exited $LASTEXITCODE"
    Wait-Until $UpdateSeconds 'the helper had 1.0.0 installed: Release reads 1.0.0-2' { (Get-RegValue 'Release') -eq '1.0.0-2' }
    # Windows Installer's client, started by the helper on the staged file, finishes
    # after the release's registry value is written.
    Wait-StagedInstall
    Wait-Until 120 "$Service runs again, under a new process" {
        $s = Get-Svc $Service; $s -and $s.State -eq 'Running' -and $s.ProcessId -ne $script:firstPid
    }
    Assert-True (Test-Path -LiteralPath $HelperLog -PathType Leaf) "the helper logged to $HelperLog"
    $logOwner = Get-Owner $HelperLog
    Assert-True ($TrustedSids -contains $logOwner) "the helper's log is SYSTEM's or Administrators' (it is owned by $logOwner)"
    Assert-True ([bool](Select-String -LiteralPath $HelperLog -Pattern "handed $([regex]::Escape($Package)) .* to its installer" -Quiet)) "the helper's log says it handed $Package to its installer"
    Assert-True (Test-Path -LiteralPath $MsiexecLog -PathType Leaf) "msiexec logged to $MsiexecLog"
    Assert-True ([bool](Select-String -LiteralPath $MsiexecLog -Pattern 'success or error status: 0' -Quiet)) "msiexec's log reports success"
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) "one Programs and Features entry named $DisplayName (found $($entries.Count))"
    $helper = Get-Svc $HelperService
    Assert-True ([bool]$helper) "$HelperService is still installed after the upgrade"
    Assert-True ($helper.State -eq 'Stopped' -and $helper.StartMode -eq 'Manual') "$HelperService waits, demand-start (it is $($helper.State), $($helper.StartMode))"
    Assert-HelperDacl 'after the upgrade'
    foreach ($dir in @($VendorData, $Support, $Staging, $HelperLogs)) { Assert-PrivateDirectory $dir }
    Assert-PrivateDirectory $State @(Get-ServiceSid)
    Assert-InstalledBinaries '1.0.0.2' '1.0.0' $false
    Assert-Signed $script:v1
    Assert-Recovery 'after the upgrade'
    Write-Log "the helper installed 1.0.0 (sequence 2); $Service runs as pid $((Get-Svc $Service).ProcessId)"
}

Invoke-Step 'again' {
    $before = (Get-Svc $Service).ProcessId
    & sc.exe start $HelperService | Out-Host
    Assert-True ($LASTEXITCODE -eq 0) "sc.exe start $HelperService exited $LASTEXITCODE"
    # 1077: the freshly installed service hasn't run yet.
    Wait-Until 120 "$HelperService ran and stopped" { $s = Get-Svc $HelperService; $s -and $s.State -eq 'Stopped' -and $s.ExitCode -ne 1077 }
    $helper = Get-Svc $HelperService
    Assert-True ($helper.ExitCode -eq 0) "$HelperService exited 0 with 1.0.0 installed (Win32 exit $($helper.ExitCode), service-specific $($helper.ServiceSpecificExitCode))"
    Assert-True ((Get-RegValue 'Release') -eq '1.0.0-2') "Release still reads 1.0.0-2 (it is '$(Get-RegValue 'Release')')"
    Assert-True ((Get-Svc $Service).ProcessId -eq $before) "$Service wasn't reinstalled or restarted"
}

Invoke-Step 'repair' -Independent {
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) 'one entry to repair'
    $log = Join-Path $Evidence 'repair-standard-user.log'
    $command = "`"$env:SystemRoot\System32\msiexec.exe`" /fa $($entries[0].Code) UPDATES=off /qn /norestart /l*v `"$log`""
    Write-Log "as a standard user (a restricted token): $command"
    $code = [SeaworthyMsiLane]::RunRestricted($command, 900000)
    # Either a repair (it ran elevated in the Windows Installer service, as a standard
    # user's repair of a per-machine product does) or a refusal; never the command
    # line's UPDATES=.
    Set-Content -LiteralPath (Join-Path $Evidence 'repair-standard-user.exit') -Value $code
    Write-Log "the standard user's repair exited $code ($(if ($code -eq 0) { 'repaired' } else { 'refused or failed' }))"
    Wait-Until 120 "$Service runs after the repair" { $s = Get-Svc $Service; $s -and $s.State -eq 'Running' }
    Assert-True ((Get-RegValue 'UpdatePolicy') -eq 'auto') "a standard user's repair ignores UPDATES=off: UpdatePolicy is still auto (it is '$(Get-RegValue 'UpdatePolicy')')"
    Assert-True ((Get-RegValue 'Release') -eq '1.0.0-2') "the repair leaves Release at 1.0.0-2 (it is '$(Get-RegValue 'Release')')"
    Assert-Recovery 'after a standard user''s repair'
}

Invoke-Step 'rollback' {
    $msi = Get-Msi "$Product-bad"
    $log = Join-Path $Evidence 'rollback.log'
    $code = Invoke-Msiexec @('/i', "`"$msi`"") $log
    Assert-True ($code -eq 1603) "the upgrade to 1.0.1 fails (1603) (it exited $code)"
    Assert-True ([bool](Select-String -LiteralPath $log -Pattern 'LaneRollsBack' -Quiet)) "the failing custom action ran (the upgrade got past InstallServices)"
    Wait-Until 120 "$Service runs again after the rollback" { $s = Get-Svc $Service; $s -and $s.State -eq 'Running' }
    Assert-True ((Get-RegValue 'Release') -eq '1.0.0-2') "the rollback restores Release 1.0.0-2 (it is '$(Get-RegValue 'Release')')"
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1 -and $entries[0].Version -eq '1.0.0') "one Programs and Features entry, at 1.0.0 (found $($entries.Count): $(($entries | ForEach-Object { $_.Version }) -join ', '))"
    $helper = Get-Svc $HelperService
    Assert-True ([bool]$helper -and $helper.State -eq 'Stopped' -and $helper.StartMode -eq 'Manual') "$HelperService is installed, demand-start and stopped after the rollback"
    foreach ($dir in @($VendorData, $Support, $Staging, $HelperLogs)) { Assert-PrivateDirectory $dir }
    Assert-PrivateDirectory $State @(Get-ServiceSid)
    Assert-Recovery 'after a rolled-back upgrade'
    Assert-HelperDacl 'after a rolled-back upgrade'
}

Invoke-Step 'remove' {
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) 'one entry to remove'
    $code = Invoke-Msiexec @('/x', $entries[0].Code) (Join-Path $Evidence 'remove.log')
    Assert-True ($code -eq 0) "msiexec /x exited $code"
    foreach ($name in @($Service, $HelperService)) { Assert-True (-not (Get-Svc $name)) "$name is gone" }
    Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "$InstallDir is gone"
    foreach ($name in @('Release', 'UpdatePolicy')) { Assert-True ($null -eq (Get-RegValue $name)) "$Key\$name is gone" }
    Assert-True (@(Get-Entries).Count -eq 0) 'no Programs and Features entry is left'
}

# Last and on its own (a squatter the install can't evict would keep the helper from its
# staging directory: every later step would fail for it): a standard user creates the
# product's ProgramData directories first, then 1.0.0-rc.1 installs over them, takes
# them back (SYSTEM owns them), and the helper updates from them.
Invoke-Step 'squat' -Independent {
    # The removal keeps directories that hold files: start from none.
    Save-Logs ''
    if (Test-Path -LiteralPath $VendorData) { Remove-Item -LiteralPath $VendorData -Recurse -Force }
    New-LaneUser $SquatUser $SquatPassword
    $logon = [SeaworthyMsiLane]::LogOn($SquatUser, $SquatPassword)
    try {
        $script:SquatSid = [SeaworthyMsiLane]::UserSid($logon)
        [SeaworthyMsiLane]::CreateDirectories($logon, [string[]]@($VendorData, $Support, $State))
    } finally {
        $logon.Dispose()
    }
    foreach ($dir in @($VendorData, $Support, $State)) {
        $owner = Get-Owner $dir
        Assert-True ($owner -eq $script:SquatSid) "$dir was created by the standard user $SquatUser ($script:SquatSid), its owner (it is owned by $owner)"
    }
    Write-Log "the standard user $SquatUser ($script:SquatSid) owns $VendorData, $Support and $State before the install"
    $code = Invoke-Msiexec @('/i', "`"$script:rc1`"") (Join-Path $Evidence 'squat-install.log')
    Assert-True ($code -eq 0) "msiexec /i of 1.0.0-rc.1 over the squatter's directories exited $code"
    Wait-Until 60 "$Service runs" { $s = Get-Svc $Service; $s -and $s.State -eq 'Running' }
    foreach ($dir in @($VendorData, $Support, $State)) {
        $owner = Get-Owner $dir
        Assert-True ($owner -eq 'S-1-5-18') "the install took $dir back from $($SquatUser): SYSTEM owns it (it is owned by $owner)"
    }
    foreach ($dir in @($VendorData, $Support, $Staging, $HelperLogs)) { Assert-PrivateDirectory $dir }
    Assert-PrivateDirectory $State @(Get-ServiceSid)
    Assert-HelperDacl 'after the install over the squatter''s directories'
    # The helper's staging audit accepts them: it updates to 1.0.0.
    & sc.exe start $HelperService | Out-Host
    Assert-True ($LASTEXITCODE -eq 0) "sc.exe start $HelperService exited $LASTEXITCODE"
    Wait-Until $UpdateSeconds 'the helper updated from the taken-back directories: Release reads 1.0.0-2' { (Get-RegValue 'Release') -eq '1.0.0-2' }
    Wait-StagedInstall
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) 'one entry to remove'
    $code = Invoke-Msiexec @('/x', $entries[0].Code) (Join-Path $Evidence 'squat-remove.log')
    Assert-True ($code -eq 0) "msiexec /x exited $code"
}

# After the squat: a standard user creates the product's ProgramData directories and,
# inside the state directory, one of their own. The guard takes the directories back but
# can't trust what the user planted below them, so the install is refused (1603) and
# rolled back, and the planted directory is left as it was: nothing is rewritten.
Invoke-Step 'squat-content' -Independent {
    if (Test-Path -LiteralPath $VendorData) { Remove-Item -LiteralPath $VendorData -Recurse -Force }
    $exists = if (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue) { [bool](Get-LocalUser -Name $SquatUser -ErrorAction SilentlyContinue) } else { [bool]$script:SquatSid }
    if (-not $exists) { New-LaneUser $SquatUser $SquatPassword }
    $planted = Join-Path $State 'planted'
    $logon = [SeaworthyMsiLane]::LogOn($SquatUser, $SquatPassword)
    try {
        $script:SquatSid = [SeaworthyMsiLane]::UserSid($logon)
        [SeaworthyMsiLane]::CreateDirectories($logon, [string[]]@($VendorData, $Support, $State, $planted))
    } finally {
        $logon.Dispose()
    }
    Assert-True ((Get-Owner $planted) -eq $script:SquatSid) "$planted was created by $SquatUser"
    $log = Join-Path $Evidence 'squat-content-install.log'
    $code = Invoke-Msiexec @('/i', "`"$script:rc1`"") $log
    Assert-True ($code -eq 1603) "the install over planted content is refused (1603) (it exited $code)"
    Assert-True ([bool](Select-String -LiteralPath $log -Pattern 'ProgramDataFolders' -Quiet)) "the guard's custom action ran and failed (msiexec's log names ProgramDataFolders)"
    Assert-True (-not (Get-Svc $Service)) "$Service isn't installed after the refused install"
    Assert-True (@(Get-Entries).Count -eq 0) 'no Programs and Features entry after the refused install'
    Assert-True ((Get-Owner $planted) -eq $script:SquatSid) "the planted directory is left as it was: still $SquatUser's"
    Write-Log "the install over $SquatUser's planted $planted was refused and rolled back"
    Remove-Item -LiteralPath $VendorData -Recurse -Force
}

if ($Server -and -not $Server.HasExited) { Stop-Process -Id $Server.Id -Force -ErrorAction SilentlyContinue }
Save-Logs $(if ($Results | Where-Object { $_.Name -eq 'squat' -and -not $_.Skipped }) { 'squat-' } else { '' })
Remove-LaneCertificate
Remove-LaneUser $SquatUser
Write-JUnit
$failed = @($Results | Where-Object { $_.Failure -and -not $_.Skipped })
if ($failed.Count -gt 0) { Show-Diagnostics }
Write-Host ''
Write-Host "windows-msi-update: $($Results.Count) steps, $($failed.Count) failed -- JUnit: $(Join-Path $JUnit 'windows-msi-update.xml')"
if ($failed.Count -gt 0) { exit 1 }
