# scripts/windows-upgrade.ps1 - the Windows lab's upgrade-from-previous lane
# (.github/workflows/lab-windows.yml, job `upgrade`): the lab fixture's PREVIOUS build
# (the latest successful Windows lab run on main, fetched and checked by
# scripts/windows-upgrade-previous.ps1) installed, then updated to this run's build
# (scripts/windows-lab-build.ps1's upgrade candidate, bundle\upgrade) by its own update
# helper, against the lab, exactly as a fleet updates. Both are non-release builds of the
# `agent` product (crates/seaworthy-launcher/e2e/scm/seaworthy.toml: the `scm` launcher,
# its cores and the `scm_helper` update helper), whose manifests the fixture's public CI
# test key signs and whose helper trusts that key alone and dials only the lab's names
# under .invalid.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-upgrade.ps1 `
#       -Previous <previous build> -Candidate <bundle>\upgrade -LabExe <bundle>\bin\seaworthy-lab.exe
#
# Steps, each a JUnit case (<JUnitDir>\windows-upgrade.xml), fail-fast:
#   builds      both builds' lab-build.json: Windows builds of the agent, signed by the CI
#               test key (packages.json says ci_test), trusting the same key, the previous
#               one an older release; the candidate's MSI has its manifest beside it
#   lab         a throwaway CA (`seaworthy-lab ca`: name-constrained to the lab's names,
#               its key never written) in LocalMachine\Root for this run only, its leaf for
#               packages.lab.invalid and updates.lab.invalid, both mapped to 127.0.0.1 in
#               the hosts file; the lab server (`seaworthy-lab serve`) on 127.0.0.1:443
#               over TLS answers the candidate's version token at the required-version
#               endpoint (read from a token file on every request) and serves the release
#               tree; the lab's client, the helper's own TLS construction on the machine's
#               trust store, reads the token before anything is installed
#   install     the previous build's MSI (msiexec /i): the service runs, the helper's
#               service waits (LocalSystem, demand start, stopped), Release names the
#               previous release, UpdatePolicy is auto, its files are the previous build's
#               (lab\build.txt, the binaries' version resources); a state file is written
#               into the service's state directory
#   policy      the administrator's policy says off (Group Policy's key,
#               HKLM\SOFTWARE\Policies\<Vendor>\<Directory>\UpdatePolicy, owned by
#               Administrators and writable only by SYSTEM and Administrators); the update
#               asked for as the service asks (StartService on the helper's service): the
#               helper says the policy is off, exits 0, fetches nothing, installs nothing;
#               then the key is removed
#   foreign     the candidate's manifest re-signed by a throwaway key
#               (`seaworthy-lab foreign-manifest`): the helper fetches it, refuses it ("no
#               trusted release key verified it") and installs nothing
#   update      after the helper's backoff (a run within 30 s of the last is throttled, a
#               failed release waits a minute: at least 70 s), the real manifest: the
#               helper verifies the candidate, stages it and hands it to msiexec, and
#               Windows Installer upgrades the product
#   transition  Release names the candidate's release, one Programs and Features entry (the
#               derived UpgradeCode held across the two builds), the service runs again in
#               a new process (another PID, started after the update was asked, the
#               installed launcher, its core's start-up line in starts.log), the installed
#               files are the candidate's (lab\build.txt names its token, every binary
#               carries its version), the helper's service is installed and stopped with
#               the DACL it had before (and the candidate's .wxs gives), and the service's
#               state survived (the state file, the previous process's start-up line)
#   remove      msiexec /x: both services, the program directory, the registry values and
#               the Programs and Features entry gone
#
# Every machine change is undone in a `finally` block, whatever happens: the server
# stopped, the CA removed from LocalMachine\Root, the hosts file restored byte for byte,
# the policy key removed, the product uninstalled and its %ProgramData% directory
# removed. `-Phase Cleanup` undoes the same from what is left on the machine (the
# workflow runs it in an always-run step, for a run killed before its `finally`). The
# helper logs to %ProgramData%\<Vendor>\<Directory>\update-logs\scm_helper.log (a previous
# build from before the helper had a log directory of its own, to ...\logs\scm_helper.log:
# both are read); a failure prints them, msiexec's log and the lab server's, and every log is
# kept under <EvidenceDir>.
#
# A throwaway machine (a GitHub-hosted runner), as an administrator. Windows PowerShell
# 5.1 or PowerShell 7: this file is ASCII, so the display name is built from its
# characters' code points.
[CmdletBinding()]
param(
    [ValidateSet('All', 'Cleanup', 'SelfTest')][string]$Phase = 'All',
    # The previous build (scripts/windows-upgrade-previous.ps1's <Out>) and this run's
    # (the bundle's upgrade directory), each holding lab-build.json, packages.json and
    # packages\.
    [string]$Previous,
    [string]$Candidate,
    # The lab harness (the bundle's bin\seaworthy-lab.exe).
    [string]$LabExe,
    [string]$Product = 'agent',
    # seaworthy.toml's display-name: "Acme E2E Agent (Pr<U+00FC>fung, <U+8A66><U+9A13>)".
    [string]$DisplayName = ('Acme E2E Agent (Pr' + [char]0x00FC + 'fung, ' + [char]0x8A66 + [char]0x9A13 + ')'),
    [string]$Vendor = 'AcmeE2E',
    [string]$Directory = 'Agent',
    [string]$Package = 'acmee2e-agent',
    [string]$Service = 'AcmeAgent',
    # The helper's log stem (seaworthy.toml's `helper`).
    [string]$HelperExe = 'scm_helper',
    [string]$Channel = 'stable',
    # The helper's throttle (30 s) and a failed release's first backoff (a minute), with
    # slack: what the Linux and macOS lanes wait.
    [int]$BackoffSeconds = 70,
    [int]$UpdateSeconds = 600,
    # The lab's files: its CA and leaf, the release tree, the token and ready files, the
    # hosts file's original bytes and the CA's thumbprint (what -Phase Cleanup reads).
    [string]$WorkDir = $(if ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'lab-upgrade\lab' } else { 'target\windows-upgrade\lab' }),
    [string]$JUnitDir = $(if ($env:SEAWORTHY_JUNIT_DIR) { $env:SEAWORTHY_JUNIT_DIR } else { 'target\junit\windows-upgrade' }),
    [string]$EvidenceDir = $(if ($env:SEAWORTHY_EVIDENCE_DIR) { $env:SEAWORTHY_EVIDENCE_DIR } else { 'target\windows-upgrade\evidence' })
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Target = 'x86_64-pc-windows-msvc'
$PackagesHost = 'packages.lab.invalid'
$UpdatesHost = 'updates.lab.invalid'
$HostsMark = '# seaworthy lab'
$CaSubject = '^CN=seaworthy lab CA [0-9a-f]{8}$'
# What the helper logs (seaworthy-updater's helper): a manifest no compiled-in key
# verifies, and an administrator's `off` read from Group Policy's key (a key it distrusts
# reads as `off` too, "from an untrusted or invalid source": not this).
$Refused = 'no trusted release key verified it'
$PolicyOff = 'update policy is `off` from Group Policy'
# SYSTEM and Administrators may write, Users read, owned by Administrators: what Group
# Policy's keys hold, so the helper trusts the value (seaworthy-updater's policy rules).
$TrustedKeyDacl = 'D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)'
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544')
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Write-Log([string]$Text) { Write-Host ("{0:HH:mm:ss.fff} {1}" -f (Get-Date), $Text) }
function Assert-True([bool]$Condition, [string]$Why) { if (-not $Condition) { throw "ASSERTION FAILED: $Why" } }

# ---------------------------------------------------------------------------
# Pure helpers (-Phase SelfTest covers them)

# A JSON object's field, or $null when it has none (strict mode refuses a missing one).
function Get-Field($Object, [string]$Field) {
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $property = $Object.PSObject.Properties[$Field]
    if ($null -eq $property) { return $null }
    return $property.Value
}

# The installed-release record's spelling of a release (the MSI's Release value, deb's
# spelling): the version with "~" for its first "-" (no build metadata), then
# "-<sequence>".
function Get-ReleaseSpelling([string]$Version, [long]$Sequence) {
    $plain = ($Version -split '\+', 2)[0]
    $at = $plain.IndexOf('-')
    if ($at -ge 0) { $plain = $plain.Substring(0, $at) + '~' + $plain.Substring($at + 1) }
    return "$plain-$Sequence"
}

# The binaries' fixed FileVersion (the CLI's stamp): major.minor.patch.sequence, the
# sequence clamped to the field's 16 bits.
function Get-FileVersion([string]$Version, [long]$Sequence) {
    $core = ($Version -split '[-+]', 2)[0]
    return '{0}.{1}' -f $core, [Math]::Min($Sequence, 65535)
}

# The release tree's directory of one release, as the helper's URL template names it.
function Get-ReleaseDir([string]$Root, [string]$Token) {
    return [System.IO.Path]::Combine($Root, 'repo', 'releases', $Package, $Channel, $Token, $Target)
}

# A service DACL from `sc.exe sdshow` output: the descriptor's D: part, up to its S:
# (an ACE's rights never hold a colon). $null when the output holds no descriptor.
function Get-DaclFromSdShow([string]$Raw) {
    $shown = @($Raw -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(O:|G:|D:)' }) | Select-Object -First 1
    if (-not $shown) { return $null }
    $at = $shown.IndexOf('D:')
    if ($at -lt 0) { return '' }
    return ($shown.Substring($at) -csplit 'S:', 2)[0]
}

# The helper service's DACL as a .wxs's MsiLockPermissionsEx gives it.
function Get-WxsHelperDacl([string]$Wxs) {
    $sddl = [regex]::Match($Wxs, '<ServiceInstall Id="HelperService"[^>]*>\s*<PermissionEx Sddl="([^"]+)"')
    if (-not $sddl.Success) { return $null }
    return [System.Net.WebUtility]::HtmlDecode($sddl.Groups[1].Value)
}

# The hosts file's bytes with the lab's line appended (CRLF; a newline first when the
# file doesn't end with one).
function Add-HostsLine([byte[]]$Original) {
    $line = "127.0.0.1 $PackagesHost $UpdatesHost $HostsMark`r`n"
    if ($Original.Length -gt 0 -and $Original[$Original.Length - 1] -ne 10) { $line = "`r`n" + $line }
    $added = [System.Text.Encoding]::ASCII.GetBytes($line)
    $all = New-Object byte[] ($Original.Length + $added.Length)
    [Array]::Copy($Original, $all, $Original.Length)
    [Array]::Copy($added, 0, $all, $Original.Length, $added.Length)
    return , $all
}

# The hosts file's text without the lab's lines (the cleanup's fallback when no original
# was saved).
function Remove-HostsLines([string]$Text) {
    $kept = @($Text -split "`r?`n" | Where-Object { $_.IndexOf($HostsMark, [StringComparison]::Ordinal) -lt 0 })
    return ($kept -join "`r`n")
}

# One lab build: its lab-build.json and packages.json, checked, with its MSI (and .wxs).
function Read-LabBuild([string]$Dir, [string]$What) {
    $file = Join-Path $Dir 'lab-build.json'
    Assert-True (Test-Path -LiteralPath $file -PathType Leaf) "$What has a lab-build.json ($file)"
    $build = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json
    Assert-True ((Get-Field $build 'format') -eq 1) "${What}: lab-build.json format 1"
    Assert-True ((Get-Field $build 'platform') -ceq 'windows') "$What is a Windows build (platform '$(Get-Field $build 'platform')')"
    Assert-True ((Get-Field $build 'product') -ceq $Product) "$What is the $Product product (it is '$(Get-Field $build 'product')')"
    Assert-True ((Get-Field $build 'package') -ceq $Package) "$What is $Package (it is '$(Get-Field $build 'package')')"
    Assert-True ("$(Get-Field $build 'trust')" -cmatch '^[0-9a-f]{64}$') "$What names the SHA-256 of the key it trusts"
    $sequence = Get-Field $build 'sequence'
    Assert-True ("$sequence" -match '^[1-9][0-9]{0,17}$') "$What has a release sequence ('$sequence')"
    # The token names a directory of the release tree: a version token's characters only.
    $token = "$(Get-Field $build 'token')"
    Assert-True ($token -cmatch '^[A-Za-z0-9._+-]{1,128}$' -and $token -notmatch '\.\.') "$What has a version token ('$token')"
    Assert-True ("$(Get-Field $build 'version')" -cmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$') "$What has a release version ('$(Get-Field $build 'version')')"
    $listingFile = Join-Path $Dir 'packages.json'
    Assert-True (Test-Path -LiteralPath $listingFile -PathType Leaf) "$What has a packages.json"
    $listing = [System.IO.File]::ReadAllText($listingFile) | ConvertFrom-Json
    Assert-True ((Get-Field $listing 'ci_test') -eq $true) "$What is signed by the CI test key (packages.json: ci_test)"
    Assert-True ((Get-Field $listing 'token') -ceq (Get-Field $build 'token')) "${What}: packages.json and lab-build.json name one token"
    $artifacts = @(Get-Field $listing 'artifacts')
    $msi = @($artifacts | Where-Object { $null -ne $_ -and (Get-Field $_ 'kind') -ceq 'msi' })
    Assert-True ($msi.Count -eq 1) "$What lists one MSI (found $($msi.Count))"
    $listed = @($artifacts | Where-Object { $null -ne $_ } | ForEach-Object { "$(Get-Field $_ 'file')" })
    foreach ($name in $listed) { Assert-True ($name -cmatch '^packages/[A-Za-z0-9._+-]+$' -and $name -notmatch '\.\.') "${What}: packages.json lists '$name', a file in packages/" }
    $msiPath = Join-Path $Dir (Get-Field $msi[0] 'file')
    Assert-True (Test-Path -LiteralPath $msiPath -PathType Leaf) "${What}'s MSI $msiPath"
    # The .wxs the MSI was built from: listed, or beside it (the helper DACL it gives).
    $wxs = @($artifacts | Where-Object { $null -ne $_ -and (Get-Field $_ 'kind') -ceq 'wxs' } | ForEach-Object { Join-Path $Dir (Get-Field $_ 'file') })
    if ($wxs.Count -eq 0) { $wxs = @(Get-ChildItem -LiteralPath (Split-Path -Parent $msiPath) -Filter '*.wxs' -File | ForEach-Object { $_.FullName }) }
    $wxsPath = $null
    if ($wxs.Count -eq 1 -and (Test-Path -LiteralPath $wxs[0] -PathType Leaf)) { $wxsPath = $wxs[0] }
    return [pscustomobject]@{
        Version = [string](Get-Field $build 'version'); Sequence = [long]$sequence; Token = $token
        Trust = [string](Get-Field $build 'trust'); Msi = $msiPath; Wxs = $wxsPath
        Release = (Get-ReleaseSpelling (Get-Field $build 'version') ([long]$sequence))
        FileVersion = (Get-FileVersion (Get-Field $build 'version') ([long]$sequence))
    }
}

# ---------------------------------------------------------------------------
# The machine

# Polls $Condition once a second for up to $Seconds.
function Wait-Until([int]$Seconds, [string]$What, [scriptblock]$Condition) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (& $Condition)) {
        if ((Get-Date) -gt $deadline) { throw "ASSERTION FAILED: $What (after $Seconds s)" }
        Start-Sleep -Seconds 1
    }
}

# msiexec's own process, its log kept (not Start-Process -Wait, which waits on every
# descendant through a job object).
function Invoke-Msiexec([string[]]$Arguments, [string]$Log) {
    $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', "`"$Log`"")) -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(900000)) { $p.Kill(); throw "msiexec $($Arguments -join ' ') took longer than 15 minutes" }
    return $p.ExitCode
}

# A service as WMI reports it (State, StartMode, StartName, ProcessId, ExitCode), or $null.
function Get-Svc([string]$Name) {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
}

# This product's Programs and Features entries (by display name); callers take @(...).
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

# A value of the product's key, or $null (during an upgrade the key may be briefly gone).
function Get-RegValue([string]$Name) {
    $item = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $Name)) { return [string]$item.$Name }
    return $null
}

# How many lines of the helper's log hold $Text.
function Get-SaidCount([string]$Text) {
    $count = 0
    foreach ($log in @(Get-HelperLogFiles)) { $count += @(Select-String -LiteralPath $log -SimpleMatch -Pattern $Text).Count }
    return $count
}

# The helper's log files that exist: its own update-logs\ directory, or logs\ for a
# previous build from before it had one.
function Get-HelperLogFiles {
    return @($HelperLogs | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}

# How many of the lab server's request lines hold $Text.
function Get-ServedCount([string]$Text) {
    $log = Join-Path $script:Evidence 'lab-server.log'
    if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { return 0 }
    return @(Get-Content -LiteralPath $log | Where-Object { $_.IndexOf($Text, [StringComparison]::Ordinal) -ge 0 }).Count
}

# The helper service's DACL as the SCM reports it.
function Get-HelperDacl {
    $raw = (& sc.exe sdshow $HelperService 2>&1 | Out-String)
    $dacl = Get-DaclFromSdShow $raw
    Assert-True ([bool]$dacl) "sc sdshow $HelperService printed a DACL (exit $LASTEXITCODE): $($raw.Trim())"
    return $dacl
}

# Asks for an update as the service does (StartService on the helper's service) and
# waits until the helper's log says $Text once more, then until the run has ended. The
# helper's Win32 exit code.
function Invoke-Helper([int]$Seconds, [string]$Text) {
    $before = Get-SaidCount $Text
    & sc.exe start $HelperService | Out-Host
    Assert-True ($LASTEXITCODE -eq 0) "sc.exe start $HelperService exited $LASTEXITCODE"
    Wait-Until $Seconds "the helper's log says '$Text'" { (Get-SaidCount $Text) -gt $before }
    # 1077: the service hasn't run since it was installed.
    Wait-Until 120 "$HelperService ran and stopped" { $s = Get-Svc $HelperService; $s -and $s.State -eq 'Stopped' -and $s.ExitCode -ne 1077 }
    return (Get-Svc $HelperService).ExitCode
}

# Nothing was installed or restarted.
function Assert-Untouched([string]$Case) {
    Assert-True ((Get-RegValue 'Release') -eq $script:Old.Release) "${Case}: Release still names $($script:Old.Release) (it is '$(Get-RegValue 'Release')')"
    $s = Get-Svc $Service
    Assert-True ($s -and $s.State -eq 'Running' -and $s.ProcessId -eq $script:FirstPid) "${Case}: $Service runs on, unrestarted (pid $script:FirstPid, now $(if ($s) { "$($s.State) pid $($s.ProcessId)" } else { 'gone' }))"
}

# Every installed binary's fixed FileVersion.
function Assert-InstalledVersion([string]$FileVersion, [string]$When) {
    # By extension, not -Include: Windows PowerShell 5.1 ignores -Include beside -LiteralPath.
    $binaries = @(Get-ChildItem -LiteralPath $InstallDir -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })
    Assert-True ($binaries.Count -ge 3) "$When, the launcher, the helper and the cores are installed under $InstallDir (found $($binaries.Count))"
    foreach ($binary in $binaries) {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binary.FullName)
        $fixed = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
        Assert-True ($fixed -eq $FileVersion) "$When, $($binary.Name) carries FileVersion $FileVersion (it carries $fixed)"
    }
}

function Read-Marker {
    $marker = Join-Path $InstallDir 'lab\build.txt'
    Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) "the product installs lab\build.txt ($marker)"
    return ([System.IO.File]::ReadAllText($marker)).Trim()
}

# The service's core's start-up line for this process (scm_core's starts.log: tab-separated
# key=value fields, among them the process's own image as exe=), or $null.
function Get-StartLine([int]$ProcessId) {
    if (-not (Test-Path -LiteralPath $StartsLog -PathType Leaf)) { return $null }
    $found = @(Select-String -LiteralPath $StartsLog -Pattern "^start`tpid=$ProcessId`t")
    if ($found.Count -eq 0) { return $null }
    return [string]$found[0].Line
}

function Get-LineField([string]$Line, [string]$Field) {
    foreach ($part in @($Line -split "`t")) {
        if ($part.StartsWith("$Field=", [StringComparison]::Ordinal)) { return $part.Substring($Field.Length + 1) }
    }
    return $null
}

# The lab's root, read from its PEM file.
function Read-Certificate([string]$Pem) {
    $base64 = ((Get-Content -LiteralPath $Pem) | Where-Object { $_ -notmatch '-----' }) -join ''
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String($base64))
}

function Open-RootStore {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store ('Root', 'LocalMachine')
    $store.Open('ReadWrite')
    return $store
}

function Clear-DnsCache {
    if (Get-Command -Name 'Clear-DnsClientCache' -ErrorAction SilentlyContinue) { Clear-DnsClientCache }
    else { & ipconfig.exe /flushdns | Out-Null }
}

# ---------------------------------------------------------------------------
# Cleanup: every change this lane makes, undone from what is on the machine (each part
# on its own: one failing never keeps the others from running).

function Invoke-Cleanup {
    $labDir = [System.IO.Path]::GetFullPath($WorkDir)
    $problems = New-Object System.Collections.Generic.List[string]
    $part = {
        param([string]$What, [scriptblock]$Body)
        try { & $Body } catch { $problems.Add("${What}: $($_.Exception.Message)"); Write-Log "cleanup: $What failed: $($_.Exception.Message)" }
    }
    & $part 'the lab server' {
        $pidFile = Join-Path $labDir 'server.pid'
        if (Test-Path -LiteralPath $pidFile) {
            $serverId = [int]([System.IO.File]::ReadAllText($pidFile).Trim())
            $process = Get-Process -Id $serverId -ErrorAction SilentlyContinue
            if ($process -and $process.ProcessName -eq 'seaworthy-lab') { Stop-Process -Id $serverId -Force; Write-Log "cleanup: stopped the lab server ($serverId)" }
            Remove-Item -LiteralPath $pidFile -Force
        }
    }
    & $part 'the lab CA' {
        $store = Open-RootStore
        try {
            $thumbprints = @()
            $thumbFile = Join-Path $labDir 'ca.thumbprint'
            if (Test-Path -LiteralPath $thumbFile) { $thumbprints += [System.IO.File]::ReadAllText($thumbFile).Trim() }
            foreach ($cert in @($store.Certificates)) {
                if ($thumbprints -contains $cert.Thumbprint -or $cert.Subject -match $CaSubject) {
                    $store.Remove($cert)
                    Write-Log "cleanup: removed $($cert.Subject) ($($cert.Thumbprint)) from LocalMachine\Root"
                }
            }
            if (Test-Path -LiteralPath $thumbFile) { Remove-Item -LiteralPath $thumbFile -Force }
        } finally {
            $store.Close()
        }
    }
    & $part 'the hosts file' {
        $saved = Join-Path $labDir 'hosts.orig'
        if (Test-Path -LiteralPath $saved) {
            [System.IO.File]::WriteAllBytes($Hosts, [System.IO.File]::ReadAllBytes($saved))
            Remove-Item -LiteralPath $saved -Force
            Write-Log 'cleanup: restored the hosts file'
        } elseif ([System.IO.File]::ReadAllText($Hosts).IndexOf($HostsMark, [StringComparison]::Ordinal) -ge 0) {
            [System.IO.File]::WriteAllText($Hosts, (Remove-HostsLines ([System.IO.File]::ReadAllText($Hosts))), [System.Text.Encoding]::ASCII)
            Write-Log 'cleanup: removed the lab''s lines from the hosts file'
        }
        Clear-DnsCache
    }
    & $part 'the policy key' {
        if (Test-Path -LiteralPath $PolicyVendorKey) { Remove-Item -LiteralPath $PolicyVendorKey -Recurse -Force; Write-Log "cleanup: removed $PolicyVendorKey" }
    }
    & $part 'the product' {
        foreach ($entry in @(Get-Entries)) {
            $code = Invoke-Msiexec @('/x', $entry.Code) (Join-Path $script:Evidence 'cleanup-remove.log')
            Write-Log "cleanup: msiexec /x $($entry.Code) exited $code"
            if ($code -ne 0 -and $code -ne 1605) { throw "msiexec /x $($entry.Code) exited $code" }
        }
        foreach ($name in @($Service, $HelperService)) {
            if (Get-Svc $name) { throw "$name is still installed" }
        }
        if (Test-Path -LiteralPath $VendorData) { Remove-Item -LiteralPath $VendorData -Recurse -Force; Write-Log "cleanup: removed $VendorData" }
    }
    return $problems.ToArray()
}

# ---------------------------------------------------------------------------
# Evidence and the report

function Show-Tail([string]$Path, [int]$Lines = 60) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Write-Host "--- $Path (last $Lines lines)"
        Get-Content -LiteralPath $Path -Tail $Lines | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "--- $($Path): none"
    }
}

function Save-Evidence {
    # The previous build's logs\ copy first, so the newer update-logs\ one is kept.
    foreach ($file in @($HelperLogs[1], $HelperLogs[0], $MsiexecLog, $StartsLog, (Join-Path $State 'exits.log'))) {
        if (Test-Path -LiteralPath $file -PathType Leaf) { Copy-Item -LiteralPath $file -Destination $script:Evidence -Force -ErrorAction SilentlyContinue }
    }
    $logs = Join-Path $State 'logs'
    if (Test-Path -LiteralPath $logs) { Copy-Item -LiteralPath $logs -Destination (Join-Path $script:Evidence 'service-logs') -Recurse -Force -ErrorAction SilentlyContinue }
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
    Show-Tail (Join-Path $script:Evidence "$HelperExe.log")
    Show-Tail (Join-Path $script:Evidence 'msiexec-last.log') 80
    Show-Tail (Join-Path $script:Evidence 'lab-server.log') 40
    Show-Tail (Join-Path $script:Evidence 'starts.log') 20
}

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    Write-Host ''
    Write-Host "=== STEP $Name ==="
    $started = Get-Date
    $failure = $null
    if ($Results | Where-Object { $_.Failure }) {
        $failure = 'not run: an earlier step failed (fail-fast)'
        Write-Log $failure
        $Results.Add([pscustomobject]@{ Name = $Name; Seconds = 0; Failure = $failure; Skipped = $true })
        return
    }
    try { & $Body } catch { $failure = "$($_.Exception.Message)`n$($_.ScriptStackTrace)"; Write-Log "FAIL $Name -- $failure" }
    $Results.Add([pscustomobject]@{ Name = $Name; Seconds = ((Get-Date) - $started).TotalSeconds; Failure = $failure; Skipped = $false })
}

function Write-JUnit {
    $failures = @($Results | Where-Object { $_.Failure -and -not $_.Skipped }).Count
    $skipped = @($Results | Where-Object { $_.Skipped }).Count
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $xml = New-Object System.Text.StringBuilder
    [void]$xml.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$xml.AppendLine("<testsuite name=`"windows-upgrade`" tests=`"$($Results.Count)`" failures=`"$failures`" skipped=`"$skipped`">")
    foreach ($r in $Results) {
        $name = [System.Security.SecurityElement]::Escape($r.Name)
        [void]$xml.Append("  <testcase classname=`"windows-upgrade`" name=`"$name`" time=`"$([Math]::Round($r.Seconds, 3).ToString($inv))`"")
        if ($r.Skipped) { [void]$xml.AppendLine('><skipped/></testcase>') }
        elseif ($r.Failure) { [void]$xml.AppendLine("><failure message=`"$([System.Security.SecurityElement]::Escape(($r.Failure -split "`n")[0]))`">$([System.Security.SecurityElement]::Escape($r.Failure))</failure></testcase>") }
        else { [void]$xml.AppendLine('/>') }
    }
    [void]$xml.AppendLine('</testsuite>')
    [System.IO.File]::WriteAllText((Join-Path $script:JUnit 'windows-upgrade.xml'), $xml.ToString(), $Utf8NoBom)
}

# ---------------------------------------------------------------------------
# Self-test

function Invoke-SelfTest {
    $check = { param([bool]$Ok, [string]$What) if (-not $Ok) { throw "selftest: $What" } }
    & $check ((Get-ReleaseSpelling '0.1.0' 7) -ceq '0.1.0-7') 'the release spelling of 0.1.0 (7)'
    & $check ((Get-ReleaseSpelling '1.4.0-rc.2' 812) -ceq '1.4.0~rc.2-812') 'the release spelling of a pre-release'
    & $check ((Get-ReleaseSpelling '1.4.0-rc-2' 3) -ceq '1.4.0~rc-2-3') 'only the first "-" becomes "~"'
    & $check ((Get-ReleaseSpelling '0.1.0+g0123456789ab' 9) -ceq '0.1.0-9') 'build metadata is no part of the release'
    & $check ((Get-FileVersion '0.1.0' 42) -ceq '0.1.0.42') 'the FileVersion'
    & $check ((Get-FileVersion '1.4.0-rc.2' 70000) -ceq '1.4.0.65535') 'the FileVersion clamps the sequence'
    & $check ((Get-ReleaseDir 'w' '0.1.0+g1') -ceq [System.IO.Path]::Combine('w', 'repo', 'releases', 'acmee2e-agent', 'stable', '0.1.0+g1', $Target)) 'the release tree'
    Write-Log 'selftest: release spellings, file versions and the release tree'

    $sd = "`r`n[SC] QueryServiceObjectSecurity SUCCESS`r`n`r`nD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPLORC;;;S-1-5-80-1)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`r`n"
    & $check ((Get-DaclFromSdShow $sd) -ceq 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPLORC;;;S-1-5-80-1)') 'the DACL from sc sdshow, without the SACL'
    & $check ($null -eq (Get-DaclFromSdShow "[SC] OpenService FAILED 1060:`r`n")) 'no descriptor, no DACL'
    $wxs = "<ServiceInstall Id=`"HelperService`" Name=`"AcmeAgent-update`">`n          <PermissionEx Sddl=`"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CC;;;BA)`" />"
    & $check ((Get-WxsHelperDacl $wxs) -ceq 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CC;;;BA)') 'the helper DACL from a .wxs'
    & $check ($null -eq (Get-WxsHelperDacl '<Wix/>')) 'a .wxs without a helper'
    $line = "start`tpid=12`tversion=1.0.0`tuser=nt service\acmeagent`tsid=S-1-5-80-1`texe=C:\Program Files\AcmeE2E\Agent\scm.exe`tfips=false`tunix_ms=5"
    & $check ((Get-LineField $line 'exe') -ceq 'C:\Program Files\AcmeE2E\Agent\scm.exe' -and (Get-LineField $line 'pid') -ceq '12') 'a starts.log field'
    & $check ($null -eq (Get-LineField $line 'core')) 'a field starts.log lacks'
    Write-Log 'selftest: service DACLs from sc sdshow and from the .wxs; starts.log fields'

    $original = [System.Text.Encoding]::ASCII.GetBytes("127.0.0.1 localhost`r`n# a comment")
    $added = Add-HostsLine $original
    $text = [System.Text.Encoding]::ASCII.GetString($added)
    & $check ($text.StartsWith("127.0.0.1 localhost`r`n# a comment`r`n")) 'the hosts line starts on a line of its own'
    & $check ($text.EndsWith("127.0.0.1 $PackagesHost $UpdatesHost $HostsMark`r`n")) 'the hosts line maps both names'
    & $check ((Remove-HostsLines $text).TrimEnd() -ceq "127.0.0.1 localhost`r`n# a comment") 'the hosts line removed again'
    & $check ([System.Text.Encoding]::ASCII.GetString((Add-HostsLine ([byte[]]@()))) -ceq "127.0.0.1 $PackagesHost $UpdatesHost $HostsMark`r`n") 'an empty hosts file'
    Write-Log 'selftest: the hosts file'

    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('sw-upgrade-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $dir 'packages') | Out-Null
    try {
        [System.IO.File]::WriteAllText((Join-Path $dir 'packages/acmee2e-agent-0.1.0-7.msi'), 'msi', $Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $dir 'packages/acmee2e-agent-0.1.0-7-windows-x86_64.wxs'), $wxs, $Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $dir 'packages.json'), '{"token": "0.1.0+g0123456789ab", "ci_test": true, "artifacts": [{"kind": "wxs", "file": "packages/acmee2e-agent-0.1.0-7-windows-x86_64.wxs"}, {"kind": "msi", "file": "packages/acmee2e-agent-0.1.0-7.msi"}]}', $Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $dir 'lab-build.json'), ('{"format": 1, "platform": "windows", "product": "agent", "package": "acmee2e-agent", "version": "0.1.0", "sequence": 7, "token": "0.1.0+g0123456789ab", "trust": "' + ('a' * 64) + '", "files": {}}'), $Utf8NoBom)
        $build = Read-LabBuild $dir 'the self-test build'
        & $check ($build.Release -ceq '0.1.0-7' -and $build.FileVersion -ceq '0.1.0.7' -and $build.Sequence -eq 7) 'a lab build read back'
        & $check ($build.Msi.EndsWith('acmee2e-agent-0.1.0-7.msi') -and $build.Wxs.EndsWith('.wxs')) 'its MSI and .wxs'
        [System.IO.File]::WriteAllText((Join-Path $dir 'packages.json'), '{"token": "0.1.0+g0123456789ab", "artifacts": [{"kind": "msi", "file": "packages/acmee2e-agent-0.1.0-7.msi"}]}', $Utf8NoBom)
        $wasRefused = $false
        try { Read-LabBuild $dir 'an unsigned build' | Out-Null } catch { $wasRefused = $true }
        & $check $wasRefused 'a build the CI test key did not sign is refused'
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log 'selftest: lab builds'
    Write-Log 'selftest: PASSED'
}

if ($Phase -eq 'SelfTest') {
    Invoke-SelfTest
    exit 0
}

# ===========================================================================
# The lane
# ===========================================================================

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { throw 'the lane runs on Windows (-Phase SelfTest runs anywhere)' }

# The machine's paths (the product's, as its MSI lays them out).
$Results = New-Object System.Collections.Generic.List[object]
$Hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$Key = "HKLM:\SOFTWARE\$Vendor\$Directory"
$PolicyVendorKey = "HKLM:\SOFTWARE\Policies\$Vendor"
$PolicyKey = "$PolicyVendorKey\$Directory"
$HelperService = "$Service-update"
$InstallDir = Join-Path $env:ProgramFiles "$Vendor\$Directory"
$VendorData = Join-Path $env:ProgramData $Vendor
$Support = Join-Path $VendorData $Directory
$State = Join-Path $Support 'state'
$Staging = Join-Path $Support 'updates'
$HelperLogs = @((Join-Path $Support "update-logs\$HelperExe.log"), (Join-Path $Support "logs\$HelperExe.log"))
$MsiexecLog = Join-Path $Staging 'msiexec-last.log'
$StartsLog = Join-Path $State 'starts.log'
$StateFile = Join-Path $State 'lab-state'
New-Item -ItemType Directory -Force -Path $JUnitDir, $EvidenceDir, $WorkDir | Out-Null
$JUnit = (Resolve-Path -LiteralPath $JUnitDir).Path
$Evidence = (Resolve-Path -LiteralPath $EvidenceDir).Path
$Lab = (Resolve-Path -LiteralPath $WorkDir).Path

if ($Phase -eq 'Cleanup') {
    $problems = @(Invoke-Cleanup)
    if ($problems.Count -gt 0) { Write-Host "windows-upgrade: cleanup: $($problems -join '; ')"; exit 1 }
    Write-Host 'windows-upgrade: cleanup: the machine holds none of the lane''s changes'
    exit 0
}

foreach ($required in @(@('-Previous', $Previous), @('-Candidate', $Candidate), @('-LabExe', $LabExe))) {
    if (-not $required[1]) { throw "windows-upgrade: $($required[0]) is required" }
}
$Previous = (Resolve-Path -LiteralPath $Previous).Path
$Candidate = (Resolve-Path -LiteralPath $Candidate).Path
$LabExe = (Resolve-Path -LiteralPath $LabExe).Path
$Tls = Join-Path $Lab 'tls'
$Www = Join-Path $Lab 'www'
$TokenFile = Join-Path $Lab 'token'
$Ready = Join-Path $Lab 'ready'
$ForeignManifest = Join-Path $Lab 'foreign.manifest'
$Old = $null
$New = $null
$FirstPid = $null
$DaclBefore = $null
$StateText = $null
$AskedAt = $null
$Server = $null

try {
    Invoke-Step 'builds' {
        $script:Old = Read-LabBuild $Previous 'the previous build'
        $script:New = Read-LabBuild $Candidate 'the candidate'
        Assert-True ($script:Old.Trust -ceq $script:New.Trust) 'both builds trust one CI test key (scripts/windows-upgrade-previous.ps1 skips a build that trusts another)'
        Assert-True ($script:Old.Sequence -lt $script:New.Sequence) "the previous build ($($script:Old.Release)) is older than the candidate ($($script:New.Release))"
        Assert-True (Test-Path -LiteralPath "$($script:New.Msi).manifest" -PathType Leaf) "the candidate's MSI has its manifest ($($script:New.Msi).manifest)"
        Assert-True (Test-Path -LiteralPath $LabExe -PathType Leaf) "the lab harness $LabExe"
        Write-Log "the previous build $($script:Old.Release) ($($script:Old.Token)), the candidate $($script:New.Release) ($($script:New.Token))"
    }

    Invoke-Step 'lab' {
        # Evidence for a failed bind (the server then exits, naming the error).
        foreach ($listener in @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)) {
            $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            Write-Log "port 443 already has a listener: $($listener.LocalAddress) (process $($listener.OwningProcess) $(if ($owner) { $owner.ProcessName }))"
        }
        foreach ($dir in @($Tls, $Www)) { if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force } }
        & $LabExe ca --out $Tls --name $PackagesHost --name $UpdatesHost | Out-Host
        Assert-True ($LASTEXITCODE -eq 0) "seaworthy-lab ca exited $LASTEXITCODE"
        $ca = Read-Certificate (Join-Path $Tls 'ca.pem')
        Assert-True ($ca.Subject -match $CaSubject) "the lab CA names the run ($($ca.Subject))"
        $constraints = @($ca.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.30' })
        Assert-True ($constraints.Count -eq 1 -and $constraints[0].Critical) 'the lab CA carries critical name constraints'
        # The thumbprint first, so a cleanup finds the root even if this run dies next.
        [System.IO.File]::WriteAllText((Join-Path $Lab 'ca.thumbprint'), $ca.Thumbprint, $Utf8NoBom)
        $store = Open-RootStore
        try { $store.Add($ca) } finally { $store.Close() }
        Write-Log "LocalMachine\Root trusts $($ca.Subject) ($($ca.Thumbprint)) for this run, constrained to $PackagesHost and $UpdatesHost"

        $saved = Join-Path $Lab 'hosts.orig'
        if (-not (Test-Path -LiteralPath $saved)) { [System.IO.File]::WriteAllBytes($saved, [System.IO.File]::ReadAllBytes($Hosts)) }
        [System.IO.File]::WriteAllBytes($Hosts, (Add-HostsLine ([System.IO.File]::ReadAllBytes($saved))))
        Clear-DnsCache
        Wait-Until 30 "$PackagesHost and $UpdatesHost resolve to 127.0.0.1" {
            $ok = $true
            foreach ($name in @($PackagesHost, $UpdatesHost)) {
                try { $ok = $ok -and (@([System.Net.Dns]::GetHostAddresses($name) | ForEach-Object { $_.ToString() }) -contains '127.0.0.1') } catch { $ok = $false }
            }
            $ok
        }

        $release = Get-ReleaseDir $Www $script:New.Token
        New-Item -ItemType Directory -Force -Path $release | Out-Null
        Copy-Item -LiteralPath $script:New.Msi -Destination (Join-Path $release "$Package.msi")
        & $LabExe foreign-manifest --manifest "$($script:New.Msi).manifest" --out $ForeignManifest | Out-Host
        Assert-True ($LASTEXITCODE -eq 0) "seaworthy-lab foreign-manifest exited $LASTEXITCODE"
        # The token file names the previous build's release first; the lane switches it to
        # the candidate's below, with the server running.
        [System.IO.File]::WriteAllText($TokenFile, $script:Old.Token, $Utf8NoBom)
        Remove-Item -LiteralPath $Ready -Force -ErrorAction SilentlyContinue
        $script:Server = Start-Process -FilePath $LabExe -NoNewWindow -PassThru `
            -ArgumentList @('serve', '--root', "`"$Www`"", '--token-file', "`"$TokenFile`"", '--ready', "`"$Ready`"",
                '--listen', '127.0.0.1:443', '--tls-cert', "`"$(Join-Path $Tls 'leaf.pem')`"", '--tls-key', "`"$(Join-Path $Tls 'leaf.key')`"") `
            -RedirectStandardOutput (Join-Path $script:Evidence 'lab-server.out') -RedirectStandardError (Join-Path $script:Evidence 'lab-server.log')
        [System.IO.File]::WriteAllText((Join-Path $Lab 'server.pid'), "$($script:Server.Id)", $Utf8NoBom)
        Wait-Until 30 'the lab server is ready' {
            if ($script:Server.HasExited) { throw "the lab server exited $($script:Server.ExitCode): $([System.IO.File]::ReadAllText((Join-Path $script:Evidence 'lab-server.log')).Trim())" }
            Test-Path -LiteralPath $Ready
        }
        # Through the helper's own TLS construction and the machine's trust store; the
        # server reads the token file on every request, so the switch needs no restart.
        foreach ($token in @($script:Old.Token, $script:New.Token)) {
            [System.IO.File]::WriteAllText($TokenFile, $token, $Utf8NoBom)
            $answer = (& $LabExe required-version --url "https://$UpdatesHost/_lab/required-version" | Out-String).Trim()
            Assert-True ($LASTEXITCODE -eq 0) "the lab's client reads the required version through LocalMachine\Root (exit $LASTEXITCODE)"
            Assert-True ($answer -ceq $token) "the lab answers $token (it answered '$answer')"
        }
        Assert-True (-not $script:Server.HasExited) 'the lab server runs on'
        Write-Log "the lab answered $($script:Old.Token), then $($script:New.Token) (the token file switched, no restart) at https://$UpdatesHost; it serves the release tree at https://$PackagesHost"
    }

    Invoke-Step 'install' {
        Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "$InstallDir doesn't exist before the install (a clean runner)"
        Assert-True (-not (Get-Svc $Service)) "$Service isn't installed before the install"
        $code = Invoke-Msiexec @('/i', "`"$($script:Old.Msi)`"") (Join-Path $script:Evidence 'install-previous.log')
        Assert-True ($code -eq 0) "msiexec /i of the previous build exited $code"
        Wait-Until 60 "$Service runs" { $s = Get-Svc $Service; $s -and $s.State -eq 'Running' }
        $helper = Get-Svc $HelperService
        Assert-True ([bool]$helper) "the helper's service $HelperService is installed"
        Assert-True ($helper.StartMode -eq 'Manual' -and $helper.StartName -eq 'LocalSystem' -and $helper.State -eq 'Stopped') "$HelperService waits: demand-start, LocalSystem, stopped (it is $($helper.StartMode), $($helper.StartName), $($helper.State))"
        Assert-True ((Get-RegValue 'Release') -eq $script:Old.Release) "$Key\Release is $($script:Old.Release) (it is '$(Get-RegValue 'Release')')"
        Assert-True ((Get-RegValue 'UpdatePolicy') -eq 'auto') "$Key\UpdatePolicy is auto (it is '$(Get-RegValue 'UpdatePolicy')')"
        Assert-True ((Read-Marker) -ceq $script:Old.Token) "the installed files are the previous build's: lab\build.txt names $($script:Old.Token) (it names '$(Read-Marker)')"
        Assert-InstalledVersion $script:Old.FileVersion 'after the install'
        $script:DaclBefore = Get-HelperDacl
        if ($script:Old.Wxs) {
            $wanted = Get-WxsHelperDacl ([System.IO.File]::ReadAllText($script:Old.Wxs))
            Assert-True ($script:DaclBefore -ceq $wanted) "$HelperService's DACL is the previous .wxs's $wanted (sc sdshow: $script:DaclBefore)"
        }
        $script:FirstPid = (Get-Svc $Service).ProcessId
        Wait-Until 60 "the service's core logged its start (pid $script:FirstPid in starts.log)" { $null -ne (Get-StartLine $script:FirstPid) }
        $script:StateText = "kept $([Guid]::NewGuid().ToString('N'))"
        [System.IO.File]::WriteAllText($StateFile, $script:StateText, $Utf8NoBom)
        Write-Log "installed $($script:Old.Release): $Service runs (pid $script:FirstPid), $HelperService waits (DACL $script:DaclBefore)"
    }

    Invoke-Step 'policy' {
        foreach ($path in @($PolicyVendorKey, $PolicyKey)) {
            if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
            $acl = New-Object System.Security.AccessControl.RegistrySecurity
            $acl.SetSecurityDescriptorSddlForm("O:BA$TrustedKeyDacl")
            try {
                Set-Acl -LiteralPath $path -AclObject $acl
            } catch {
                # An elevated administrator's new key is Administrators' already.
                Write-Log "setting $path's owner failed ($($_.Exception.Message)); setting its DACL alone"
                $acl = New-Object System.Security.AccessControl.RegistrySecurity
                $acl.SetSecurityDescriptorSddlForm($TrustedKeyDacl, [System.Security.AccessControl.AccessControlSections]::Access)
                Set-Acl -LiteralPath $path -AclObject $acl
            }
            # Through the key: Windows PowerShell 5.1's Get-Acl -LiteralPath
            # reports a registry key that exists as missing.
            $owner = (Get-Item -LiteralPath $path).GetAccessControl().GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            Assert-True ($TrustedOwners -contains $owner) "$path is owned by SYSTEM or Administrators, as the helper requires (it is owned by $owner)"
        }
        New-ItemProperty -LiteralPath $PolicyKey -Name 'UpdatePolicy' -PropertyType String -Value 'off' -Force | Out-Null
        Copy-Item -LiteralPath "$($script:New.Msi).manifest" -Destination (Join-Path (Get-ReleaseDir $Www $script:New.Token) "$Package.msi.manifest") -Force
        $served = Get-ServedCount '/repo/releases/'
        $exit = Invoke-Helper 180 $PolicyOff
        Assert-True ($exit -eq 0) "the helper exits 0 when the policy is off (Win32 exit $exit)"
        Assert-True ((Get-ServedCount '/repo/releases/') -eq $served) 'the helper fetched nothing from the release tree'
        Assert-Untouched 'the policy is off'
        Remove-Item -LiteralPath $PolicyVendorKey -Recurse -Force
        Write-Log "the administrator's ``off`` policy: the helper installed nothing"
    }

    Invoke-Step 'foreign' {
        Copy-Item -LiteralPath $ForeignManifest -Destination (Join-Path (Get-ReleaseDir $Www $script:New.Token) "$Package.msi.manifest") -Force
        $fetched = Get-ServedCount '.msi.manifest'
        $exit = Invoke-Helper 300 $Refused
        Assert-True ((Get-ServedCount '.msi.manifest') -gt $fetched) 'the helper fetched the manifest it refused'
        Assert-Untouched 'another key'
        Write-Log "the helper refused the manifest another key signed (Win32 exit $exit); Release still names $($script:Old.Release)"
    }

    Invoke-Step 'update' {
        # A run within 30 s of the last is throttled; a failed release backs off a minute.
        Start-Sleep -Seconds $BackoffSeconds
        Copy-Item -LiteralPath "$($script:New.Msi).manifest" -Destination (Join-Path (Get-ReleaseDir $Www $script:New.Token) "$Package.msi.manifest") -Force
        $script:AskedAt = Get-Date
        & sc.exe start $HelperService | Out-Host
        Assert-True ($LASTEXITCODE -eq 0) "sc.exe start $HelperService exited $LASTEXITCODE"
        Wait-Until $UpdateSeconds "the helper had the candidate installed: Release names $($script:New.Release)" { (Get-RegValue 'Release') -eq $script:New.Release }
        # Windows Installer's client, started by the helper on the staged file, finishes
        # after the release's registry value is written.
        Wait-Until 300 'the upgrade finishes (no msiexec /i of the staged release left)' {
            -not @(Get-CimInstance -ClassName Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($Staging, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
        }
        Wait-Until 120 "$Service runs again, under a new process" {
            $s = Get-Svc $Service; $s -and $s.State -eq 'Running' -and $s.ProcessId -ne $script:FirstPid
        }
        Assert-True ((Get-HelperLogFiles).Count -gt 0 -and [bool](Select-String -LiteralPath (Get-HelperLogFiles) -Pattern "handed $([regex]::Escape($Package)) .* to its installer" -Quiet)) "the helper's log says it handed $Package to its installer"
        Assert-True ([bool](Select-String -LiteralPath $MsiexecLog -Pattern 'success or error status: 0' -Quiet)) "msiexec's log reports success"
    }

    Invoke-Step 'transition' {
        Assert-True ((Get-RegValue 'Release') -eq $script:New.Release) "$Key\Release names $($script:New.Release) (it is '$(Get-RegValue 'Release')')"
        Assert-True ((Get-Item -LiteralPath $Key).GetValueKind('Release') -eq [Microsoft.Win32.RegistryValueKind]::String) "$Key\Release is a REG_SZ"
        $entries = @(Get-Entries)
        Assert-True ($entries.Count -eq 1) "one Programs and Features entry named ${DisplayName}: the upgrade replaced the previous build (found $($entries.Count))"
        $s = Get-Svc $Service
        Assert-True ($s.State -eq 'Running' -and $s.ProcessId -ne $script:FirstPid) "$Service runs in a new process (pid $script:FirstPid, then $($s.ProcessId))"
        $newPid = [int]$s.ProcessId
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$newPid"
        Assert-True ($process -and $process.Name -eq 'scm.exe') "process $newPid is the launcher (it is '$(if ($process) { $process.Name })')"
        Assert-True ($process.CreationDate -gt $script:AskedAt) "process $newPid started after the update was asked ($($process.CreationDate) vs $script:AskedAt)"
        # The core, loaded in that process, names its image itself.
        Wait-Until 60 "the new process's core logged its start (pid $newPid in starts.log)" { $null -ne (Get-StartLine $newPid) }
        $launcher = Join-Path $InstallDir 'scm.exe'
        $image = Get-LineField (Get-StartLine $newPid) 'exe'
        Assert-True ([string]::Equals($image, $launcher, [StringComparison]::OrdinalIgnoreCase)) "process $newPid runs the installed launcher $launcher (its core says exe=$image)"
        Assert-True ((Read-Marker) -ceq $script:New.Token) "the installed files are the candidate's: lab\build.txt names $($script:New.Token) (it names '$(Read-Marker)')"
        Assert-InstalledVersion $script:New.FileVersion 'after the update'
        $helper = Get-Svc $HelperService
        Assert-True ($helper -and $helper.State -eq 'Stopped' -and $helper.StartMode -eq 'Manual' -and $helper.StartName -eq 'LocalSystem') "$HelperService is still installed: demand-start, LocalSystem, stopped"
        $dacl = Get-HelperDacl
        Assert-True ($dacl -ceq $script:DaclBefore) "$HelperService's DACL is unchanged by the upgrade (before $script:DaclBefore, after $dacl)"
        if ($script:New.Wxs) {
            $wanted = Get-WxsHelperDacl ([System.IO.File]::ReadAllText($script:New.Wxs))
            Assert-True ($dacl -ceq $wanted) "$HelperService's DACL is the candidate .wxs's $wanted (sc sdshow: $dacl)"
        }
        Assert-True ((Test-Path -LiteralPath $StateFile -PathType Leaf) -and ([System.IO.File]::ReadAllText($StateFile) -ceq $script:StateText)) "the service's state survived the upgrade ($StateFile)"
        Assert-True ($null -ne (Get-StartLine $script:FirstPid)) 'the previous process''s start-up line survived in starts.log'
        Write-Log "the helper installed $($script:New.Release); $Service runs again (pid $newPid), its files are the candidate's, its state kept"
    }

    Invoke-Step 'remove' {
        Save-Evidence
        $entries = @(Get-Entries)
        Assert-True ($entries.Count -eq 1) 'one entry to remove'
        $code = Invoke-Msiexec @('/x', $entries[0].Code) (Join-Path $script:Evidence 'remove.log')
        Assert-True ($code -eq 0) "msiexec /x exited $code"
        foreach ($name in @($Service, $HelperService)) { Assert-True (-not (Get-Svc $name)) "$name is gone" }
        Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "$InstallDir is gone"
        foreach ($name in @('Release', 'UpdatePolicy')) { Assert-True ($null -eq (Get-RegValue $name)) "$Key\$name is gone" }
        Assert-True (@(Get-Entries).Count -eq 0) 'no Programs and Features entry is left'
    }
} finally {
    Save-Evidence
    $failed = @($Results | Where-Object { $_.Failure -and -not $_.Skipped })
    if ($failed.Count -gt 0 -or $Results.Count -lt 8) { Show-Diagnostics }
    $problems = @(Invoke-Cleanup)
    if ($problems.Count -gt 0) {
        $Results.Add([pscustomobject]@{ Name = 'cleanup'; Seconds = 0; Failure = ($problems -join "`n"); Skipped = $false })
    }
    Write-JUnit
}
$failed = @($Results | Where-Object { $_.Failure -and -not $_.Skipped })
Write-Host ''
Write-Host "windows-upgrade: $($Results.Count) steps, $($failed.Count) failed -- JUnit: $(Join-Path $JUnit 'windows-upgrade.xml')"
if ($failed.Count -gt 0) { exit 1 }
