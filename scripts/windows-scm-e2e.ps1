<#
.SYNOPSIS
    Windows SCM end-to-end suite for seaworthy-service (and seaworthy-updater's update request).

.DESCRIPTION
    Runs DIRECTLY on a Windows machine with a real Service Control Manager, elevated: a
    GitHub-hosted `windows-2025` runner (jobs there run as an administrator on a fresh VM),
    or any disposable Windows Server / Windows 11 machine. The suite installs and removes
    an MSI, creates and deletes a service, writes under %ProgramFiles% and %ProgramData%, and
    reads the System event log: never run it on a machine you care about.

    The service under test is a product: an SCM fixture service (a launcher `scm.exe` and
    one core per CPU level, `scm_core_*.dll`: crates/seaworthy-launcher/e2e's `scm` and
    `scm_core`, scm/seaworthy.toml's [product.scm]) that the seaworthy CLI's MSI (-Msi) lays out
    under %ProgramFiles%\AcmeE2E\Scm and registers as `acme-e2e` under its virtual account,
    with its failure actions, its DACLs and its %ProgramData%\AcmeE2E\Scm\state directory
    (seaworthy-service installs nothing itself). `windows_scm_e2e.exe`
    (crates/seaworthy-service/examples/windows_scm_e2e.rs) is the version-gate stub and
    drives start/stop/status through the crate's WindowsBackend (never raw sc.exe).

    The fixture service's contract, which these cases assert on:
      - image path `"<ProgramDir>\scm.exe" run --name <ServiceName>`, AUTO_START, one
        Restart failure action of -RestartDelayMs, failure actions on non-crash failures;
      - it runs seaworthy-service's run loop (`run_windows_service`) and reads
        `<state>\service.conf` (`stub_addr=<host:port>`, `poll_ms=<n>`, or `gate=off`);
      - one line per process start in `<state>\starts.log` and per exit in
        `<state>\exits.log`, each `kind<TAB>k=v<TAB>...` (start: pid, version, fips, user,
        sid; exit: pid, code, reason = the ServiceExit or RunError text), a heartbeat in
        `<state>\status.txt` naming the pid whose tasks ran, a per-process log in
        `<state>\logs\service-<pid>.log`;
      - a file dropped into `<state>\control\` triggers `fatal` (the body's
        Outcome::Fatal: RunError::Fatal), `panic` (a panic in the body: RunError::TaskPanicked)
        or `abort` (a real crash);
      - it polls the stub's `/required` every poll_ms; a demand for another version asks the
        update helper `<ServiceName>-update` through seaworthy-updater's request and keeps
        running, logging -RequestFailedPattern when no helper is installed (none is here).

    Every check is a named JUnit test case. Fail-fast: the first failure aborts the
    remaining (dependent) cases, which are reported as skipped "not run"; cleanup and
    the JUnit report ALWAYS run. Cases a CI machine cannot run (an OS shutdown) are
    reported as skipped with the label "EXPECTED VM-ONLY" -- never as passed.

    A version mismatch never stops the service: it asks the product's update helper
    (`<name>-update`) to install the server's release and keeps running. No helper is
    installed here, so the gate.* cases assert the service stays up and logs the failed
    request; the helper's own install path belongs to the install-and-update lane.

    With -ExpectFips the suite also checks a FIPS product's MSI (the AWS-LC-FIPS module's
    DLL beside its cores; the service must report fips=true), and the entropy cases run
    fresh processes of seaworthy-crypto's entropy_probe example (one first random draw
    each: AWS-LC's CPU-jitter entropy aborts a process whose startup health test fails).

    Requirements:
      - an elevated shell (Administrators); the first case fails fast without it;
      - Windows PowerShell 5.1 or PowerShell 7 (the script is kept 5.1-compatible: no
        ternary, no `??`, no `&&`/`||` pipeline chains, no `?.`; ASCII only);
      - static-CRT binaries, or the Visual C++ Redistributable installed (hosted runners
        have it);
      - about 6-8 minutes for the SCM cases plus the native nextest suite's own time: give
        the job 45 minutes. Every wait inside the script has its own bound.

.PARAMETER Phase
    All            the full suite (default).
    Service        the suite without the entropy cases (a hosted runner's required lane:
                   GitHub's Windows runners are Hyper-V guests, where the first-draw rate
                   is the hypervisor's, not the code's; docs/testing-windows.md).
    Entropy        the entropy cases alone (no administrator, no MSI): the rate as data.
    SelfTest       pure-logic self-tests of this script (parsers, quoting, JUnit) --
                   runs on any PowerShell (Linux pwsh included); with -FixtureExe it
                   also round-trips the version-gate stub.

.EXAMPLE
    # A CI job: every input from its environment (SEAWORTHY_WINDOWS_BIN_DIR, SEAWORTHY_JUNIT_DIR, ...)
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-scm-e2e.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-scm-e2e.ps1 `
        -BinDir C:\e2e\bin -Msi C:\e2e\acme-e2e.msi -JUnitDir C:\e2e\junit

.EXAMPLE
    # The Windows lab's bundle (scripts/windows-lab-build.ps1): its bin\ and the SCM MSI.
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-scm-e2e.ps1 -Phase Service `
        -BinDir <bundle>\bin -Msi (Get-Item <bundle>\scm\packages\*.msi).FullName `
        -RustScmTestExe <bundle>\bin\windows_scm-test.exe
#>
[CmdletBinding()]
param(
    # Inputs default to a CI job's environment interface:
    #   SEAWORTHY_WINDOWS_BIN_DIR  the example .exes  -> -FixtureExe / -EntropyProbeExe / -EntropyDiagExe
    #   SEAWORTHY_JUNIT_DIR        where the JUnit reports MUST land
    #   SEAWORTHY_NEXTEST_EXE / SEAWORTHY_NEXTEST_ARCHIVE / SEAWORTHY_NEXTEST_PROFILE / SEAWORTHY_WORKSPACE
    #                              the Rust suites (cargo-nextest.exe over an archive)
    [string]$BinDir = $env:SEAWORTHY_WINDOWS_BIN_DIR,
    [string]$FixtureExe,
    # The service's MSI: the SCM fixture product of its seaworthy.toml, built by the
    # seaworthy CLI (a FIPS build for -ExpectFips 1).
    [string]$Msi = $env:SEAWORTHY_SCM_MSI,
    # Its Programs and Features name (seaworthy.toml's display-name).
    [string]$ProductName = 'Acme SCM fixture',
    [string]$JUnitDir = $env:SEAWORTHY_JUNIT_DIR,
    # The fixture product's service name and restart delay.
    [string]$ServiceName = 'acme-e2e',
    [int]$RestartDelayMs = 8000,
    # What the fixture logs when `<name>-update` can't be started (no helper is installed
    # here): the gate.* cases' evidence. Empty = the default built from -ServiceName.
    [string]$RequestFailedPattern,
    # The Rust half: crates/seaworthy-service/tests/windows_scm.rs (-RustScmTestExe runs
    # that test executable directly; otherwise nextest runs it from the archive) and the
    # whole archive's suite natively on Windows.
    [string]$RustScmTestExe = $env:SEAWORTHY_RUST_SCM_TEST_EXE,
    [string]$NextestExe = $env:SEAWORTHY_NEXTEST_EXE,
    [string]$NextestArchive = $env:SEAWORTHY_NEXTEST_ARCHIVE,
    [string]$NextestProfile = $env:SEAWORTHY_NEXTEST_PROFILE,
    [string]$WorkspaceRemap = $env:SEAWORTHY_WORKSPACE,
    # nextest's parallelism for the native suite. Its default is one test process per
    # LOGICAL CPU; on a memory-capped machine the suite's most process-heavy phase can
    # abort native test processes silently (NTSTATUS exits). A small fixed width bounds
    # the peak.
    [int]$NextestThreads = $(if ($env:SEAWORTHY_NEXTEST_THREADS) { [int]$env:SEAWORTHY_NEXTEST_THREADS } else { 4 }),
    # A FIPS lane: the directory holding the AWS-LC-FIPS DLL pair the FIPS test archive
    # imports at load time (on the native nextest suite's PATH; the MSI lays the service's
    # own copy beside its cores).
    [string]$FipsDllDir = $env:SEAWORTHY_FIPS_DLL_DIR,
    # '1' / '0': assert the fixture's (and the probe's) FIPS posture; empty = not asserted.
    [string]$ExpectFips = $env:SEAWORTHY_EXPECT_FIPS,
    # entropy.first_draw_never_aborts: how many fresh processes, how many at once.
    [string]$EntropyProbeExe,
    [int]$EntropyProbeCount = $(if ($env:SEAWORTHY_ENTROPY_PROBE_COUNT) { [int]$env:SEAWORTHY_ENTROPY_PROBE_COUNT } else { 1000 }),
    [int]$EntropyProbeParallel = $(if ($env:SEAWORTHY_ENTROPY_PROBE_PARALLEL) { [int]$env:SEAWORTHY_ENTROPY_PROBE_PARALLEL } else { 4 }),
    # entropy.jitter_diagnostics (an optional jitter-entropy diagnostic, entropy_diag.exe):
    # warm trials per process, concurrent processes, and cold one-trial processes per
    # backend.
    [string]$EntropyDiagExe,
    [int]$EntropyDiagTrials = $(if ($env:SEAWORTHY_ENTROPY_DIAG_TRIALS) { [int]$env:SEAWORTHY_ENTROPY_DIAG_TRIALS } else { 500 }),
    [int]$EntropyDiagParallel = $(if ($env:SEAWORTHY_ENTROPY_DIAG_PARALLEL) { [int]$env:SEAWORTHY_ENTROPY_DIAG_PARALLEL } else { 4 }),
    [int]$EntropyDiagCold = $(if ($env:SEAWORTHY_ENTROPY_DIAG_COLD) { [int]$env:SEAWORTHY_ENTROPY_DIAG_COLD } else { 400 }),
    [ValidateSet('All', 'Service', 'Entropy', 'SelfTest')][string]$Phase = 'All',
    [switch]$KeepInstalled
)

if (-not $FixtureExe -and $BinDir) { $FixtureExe = Join-Path $BinDir 'windows_scm_e2e.exe' }
if (-not $EntropyProbeExe -and $BinDir) { $EntropyProbeExe = Join-Path $BinDir 'entropy_probe.exe' }
if (-not $EntropyDiagExe -and $BinDir) { $EntropyDiagExe = Join-Path $BinDir 'entropy_diag.exe' }
if (-not $JUnitDir) { $JUnitDir = Join-Path (Get-Location) 'windows-scm-e2e-junit' }
$DiagnosticsDir = Join-Path $JUnitDir 'diagnostics'

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Paths and constants

$script:IsWin = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if ($script:IsWin) {
    $script:ProgramFilesDir = $env:ProgramFiles
    $script:ProgramDataDir = $env:ProgramData
    $script:System32 = Join-Path $env:SystemRoot 'System32'
} else {
    $script:ProgramFilesDir = '/tmp/seaworthy-e2e-pf'
    $script:ProgramDataDir = '/tmp/seaworthy-e2e-pd'
    $script:System32 = '/usr/bin'
}
$script:ScExe = Join-Path $script:System32 'sc.exe'
$script:IcaclsExe = Join-Path $script:System32 'icacls.exe'
# What the MSI lays out (seaworthy.toml: vendor AcmeE2E, windows-directory Scm, the
# launcher `scm`): the program directory, and the state directory the service's
# account may modify, below the two locked %ProgramData% directories.
$script:InstallRoot = Join-Path $script:ProgramFilesDir 'AcmeE2E'
$script:ProgramDir = Join-Path $script:InstallRoot 'Scm'
$script:ProgramPath = Join-Path $script:ProgramDir 'scm.exe'
$script:DataRoot = Join-Path $script:ProgramDataDir 'AcmeE2E'
$script:MsiDataDir = Join-Path $script:DataRoot 'Scm'
$script:StateDir = Join-Path $script:MsiDataDir 'state'
# The suite's own files, outside the product's directories.
$script:SuiteRoot = Join-Path $script:ProgramDataDir 'AcmeE2E-suite'
$script:WorkDir = Join-Path $script:SuiteRoot 'work'
$script:StubRoot = Join-Path $script:WorkDir 'stub'
$script:StubLog = Join-Path $script:WorkDir 'stub.log'
$script:MsiLog = Join-Path $script:WorkDir 'msiexec.log'
# What the fixture logs when seaworthy-updater's request can't start `<name>-update`
# (no helper is installed here): the gate.* cases' evidence (-RequestFailedPattern).
if (-not $RequestFailedPattern) {
    $RequestFailedPattern = 'the server requires ' + [regex]::Escape($ServiceName) +
        ' 9\.9\.9, but asking the update helper failed: requesting an update failed: opening service ' +
        [regex]::Escape("$ServiceName-update") + ' to start it'
}
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false

$script:Cases = New-Object System.Collections.ArrayList
$script:Aborted = $false
$script:CaseLog = $null
$script:StubProcess = $null
$script:Ctx = @{}   # values shared between cases (the stub address)
$script:ExpectFipsBool = $null
if ($ExpectFips -eq '1') { $script:ExpectFipsBool = $true } elseif ($ExpectFips -eq '0') { $script:ExpectFipsBool = $false }

# ---------------------------------------------------------------------------
# Logging, assertions, the case runner

function Write-Log {
    param([string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Message
    Write-Host $line
    if ($null -ne $script:CaseLog) { [void]$script:CaseLog.AppendLine($line) }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Skip-Case {
    param([string]$Reason)
    throw "SKIP:$Reason"
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        # A case a CI machine cannot run: reported skipped, labeled.
        [string]$VmOnly,
        # Runs even after an earlier failure, and its own failure does not abort the
        # rest (the Rust suites: they depend on nothing the SCM cases set up).
        [switch]$Independent
    )
    $case = [ordered]@{ Name = $Name; Status = 'passed'; Message = ''; Time = 0.0; Output = '' }
    $script:CaseLog = New-Object System.Text.StringBuilder
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ''
    Write-Host "=== CASE $Name ==="
    if ($VmOnly) {
        $case.Status = 'skipped'
        $case.Message = "EXPECTED VM-ONLY: $VmOnly"
        Write-Log $case.Message
    } elseif ($script:Aborted -and -not $Independent) {
        $case.Status = 'skipped'
        $case.Message = 'not run: an earlier case failed (fail-fast)'
        Write-Log $case.Message
    } else {
        try {
            & $Body
            Write-Log "PASS $Name"
        } catch {
            $text = "$($_.Exception.Message)"
            if ($text.StartsWith('SKIP:')) {
                $case.Status = 'skipped'
                $case.Message = $text.Substring(5)
                Write-Log "SKIP $Name -- $($case.Message)"
            } else {
                $case.Status = 'failed'
                $case.Message = $text
                Write-Log "FAIL $Name -- $text"
                Write-Log "at: $($_.ScriptStackTrace)"
                if (-not $Independent) {
                    try { Write-Diagnostics } catch { Write-Log "diagnostics failed: $_" }
                    $script:Aborted = $true
                }
            }
        }
    }
    $watch.Stop()
    $case.Time = $watch.Elapsed.TotalSeconds
    $case.Output = $script:CaseLog.ToString()
    $script:CaseLog = $null
    [void]$script:Cases.Add([pscustomobject]$case)
}

function Wait-Until {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][int]$TimeoutSec,
        [Parameter(Mandatory = $true)][string]$What,
        [int]$IntervalMs = 250
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $value = & $Condition
        if ($value) { return $value }
        Start-Sleep -Milliseconds $IntervalMs
    }
    throw "TIMEOUT after ${TimeoutSec}s waiting for: $What"
}

# ---------------------------------------------------------------------------
# Native processes: raw stdout/stderr (PS 5.1 wraps redirected native stderr into
# ErrorRecords -- never parse through that), exit codes, a hard timeout.

function ConvertTo-ArgString {
    param([string[]]$Arguments)
    $parts = foreach ($arg in $Arguments) {
        if ($arg.Length -gt 0 -and $arg -notmatch '[\s"]') {
            $arg
        } else {
            # CommandLineToArgvW rules: backslashes double only before a quote.
            $escaped = [regex]::Replace($arg, '(\\*)"', { param($m) $m.Groups[1].Value + $m.Groups[1].Value + '\"' })
            $escaped = [regex]::Replace($escaped, '(\\+)$', { param($m) $m.Groups[1].Value + $m.Groups[1].Value })
            '"' + $escaped + '"'
        }
    }
    return ($parts -join ' ')
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{},
        [int]$TimeoutSec = 180
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ConvertTo-ArgString $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSec * 1000)) {
        try { $process.Kill() } catch { }
        throw "TIMEOUT: $Exe $($psi.Arguments) did not exit within ${TimeoutSec}s"
    }
    $process.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        StdOut   = $stdout.Result
        StdErr   = $stderr.Result
    }
}

function Invoke-Fixture {
    param([string[]]$Arguments, [int]$TimeoutSec = 180)
    $result = Invoke-Native -Exe $FixtureExe -Arguments $Arguments -TimeoutSec $TimeoutSec
    Write-Log ("fixture {0} -> exit {1}" -f ($Arguments -join ' '), $result.ExitCode)
    foreach ($line in (($result.StdOut + $result.StdErr) -split "`r?`n")) {
        if ($line.Trim()) { Write-Log "  | $line" }
    }
    return $result
}

function Write-TextNoBom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

# Read a file the service may be appending to at this instant: share read, write,
# AND delete (File.ReadAllLines shares read only and throws on a concurrent writer).
function Read-SharedText {
    param([string]$Path)
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try {
        $reader = New-Object System.IO.StreamReader($stream, $script:Utf8NoBom)
        return $reader.ReadToEnd()
    } finally {
        $stream.Dispose()
    }
}

function Read-Lines {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @((Read-SharedText $Path) -split "`r?`n" | Where-Object { $_.Trim() })
}

# ---------------------------------------------------------------------------
# Parsers (pure; covered by -Phase SelfTest)

# `sc.exe queryex <name>` -> State / Win32Exit / SpecificExit / Pid.
function ConvertFrom-ScQueryEx {
    param([string]$Text)
    $o = [ordered]@{ State = ''; Win32Exit = -1; SpecificExit = -1; Pid = 0 }
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*STATE\s*:\s*\d+\s+(\w+)') { $o.State = $Matches[1] }
        elseif ($line -match '^\s*WIN32_EXIT_CODE\s*:\s*(\d+)') { $o.Win32Exit = [int64]$Matches[1] }
        elseif ($line -match '^\s*SERVICE_EXIT_CODE\s*:\s*(\d+)') { $o.SpecificExit = [int64]$Matches[1] }
        elseif ($line -match '^\s*PID\s*:\s*(\d+)') { $o.Pid = [int]$Matches[1] }
    }
    return [pscustomobject]$o
}

# `icacls <path>` -> entries @{ Principal; Tokens[] } (the path prefix of the first
# line stripped; the summary line ignored).
function ConvertFrom-Icacls {
    param([string]$Text, [string]$Path)
    $entries = New-Object System.Collections.ArrayList
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = $raw
        if ($line.StartsWith($Path)) { $line = $line.Substring($Path.Length) }
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('Successfully processed')) { continue }
        if ($line -match '^(?<p>.+?):(?<r>(\([^)]*\))+)$') {
            $tokens = @([regex]::Matches($Matches['r'], '\(([^)]*)\)') | ForEach-Object { $_.Groups[1].Value })
            [void]$entries.Add([pscustomobject]@{ Principal = $Matches['p']; Tokens = $tokens })
        }
    }
    # Emitted element by element: callers collect with @(...).
    return $entries.ToArray()
}

# Rights tokens that let a principal change or replace what is in a directory.
$script:WriteTokens = @('F', 'M', 'W', 'D', 'DE', 'DC', 'WDAC', 'WO', 'WD', 'AD', 'WA', 'WEA', 'GA', 'GW', 'MA')

function Test-GrantsWrite {
    param($Entry)
    if ($Entry.Tokens -contains 'DENY') { return $false }
    foreach ($token in $Entry.Tokens) {
        foreach ($right in ($token -split ',')) {
            if ($script:WriteTokens -contains $right.Trim()) { return $true }
        }
    }
    return $false
}

function Test-TrustedPrincipal {
    param([string]$Principal, [string]$ServiceAccount)
    $p = $Principal.ToLowerInvariant()
    return ($p -eq 'nt authority\system' -or $p -eq 'builtin\administrators' -or
        $p -eq 'nt service\trustedinstaller' -or $p -eq 'creator owner' -or
        ($ServiceAccount -and $p -eq $ServiceAccount.ToLowerInvariant()))
}

# The one-line-per-event logs the fixture writes: `kind<TAB>k=v<TAB>k=v...`.
function ConvertFrom-FixtureLog {
    param([string[]]$Lines)
    foreach ($line in $Lines) {
        $fields = $line -split "`t"
        $o = [ordered]@{ Kind = $fields[0] }
        foreach ($field in ($fields | Select-Object -Skip 1)) {
            $i = $field.IndexOf('=')
            if ($i -gt 0) { $o[$field.Substring(0, $i)] = $field.Substring($i + 1) }
        }
        [pscustomobject]$o
    }
}

# The version-gate stub's request log: `unix_ms<TAB>method<TAB>path<TAB>status<TAB>bytes`.
# The log is cumulative for the whole run (every gate poll and connect of every
# process), so a case counting requests passes -Since: the unix ms it captured
# before its trigger.
function Get-StubRequests {
    param([string]$PathLike = '*', [int64]$Since = 0)
    foreach ($line in (Read-Lines $script:StubLog)) {
        $f = $line -split "`t"
        if ($f.Count -ge 5 -and $f[2] -like $PathLike -and [int64]$f[0] -ge $Since) {
            [pscustomobject]@{ Ms = [int64]$f[0]; Method = $f[1]; Path = $f[2]; Status = [int]$f[3]; Bytes = [int64]$f[4] }
        }
    }
}

function ConvertTo-XmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $clean = [regex]::Replace($Text, '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
    return [System.Security.SecurityElement]::Escape($clean)
}

function Write-JUnit {
    param([string]$Path, [string]$Suite, $Cases)
    $failures = @($Cases | Where-Object { $_.Status -eq 'failed' }).Count
    $skipped = @($Cases | Where-Object { $_.Status -eq 'skipped' }).Count
    $total = 0.0
    foreach ($c in $Cases) { $total += $c.Time }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture   # '.' decimals whatever the locale
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine([string]::Format($inv, '<testsuites name="{0}" tests="{1}" failures="{2}" skipped="{3}" time="{4:F3}">',
            (ConvertTo-XmlText $Suite), @($Cases).Count, $failures, $skipped, $total))
    [void]$sb.AppendLine([string]::Format($inv, '  <testsuite name="{0}" tests="{1}" failures="{2}" errors="0" skipped="{3}" time="{4:F3}" timestamp="{5}" hostname="{6}">',
            (ConvertTo-XmlText $Suite), @($Cases).Count, $failures, $skipped, $total,
            (Get-Date).ToUniversalTime().ToString('s'), (ConvertTo-XmlText ([System.Environment]::MachineName))))
    foreach ($c in $Cases) {
        [void]$sb.Append([string]::Format($inv, '    <testcase classname="{0}" name="{1}" time="{2:F3}">',
                (ConvertTo-XmlText $Suite), (ConvertTo-XmlText $c.Name), $c.Time))
        if ($c.Status -eq 'failed') {
            [void]$sb.Append(('<failure message="{0}">{1}</failure>' -f (ConvertTo-XmlText $c.Message), (ConvertTo-XmlText $c.Message)))
        } elseif ($c.Status -eq 'skipped') {
            [void]$sb.Append(('<skipped message="{0}"/>' -f (ConvertTo-XmlText $c.Message)))
        }
        [void]$sb.Append(('<system-out>{0}</system-out>' -f (ConvertTo-XmlText $c.Output)))
        [void]$sb.AppendLine('</testcase>')
    }
    [void]$sb.AppendLine('  </testsuite>')
    [void]$sb.AppendLine('</testsuites>')
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Write-TextNoBom -Path $Path -Text $sb.ToString()
}

# ---------------------------------------------------------------------------
# Service observation

function Get-ScState {
    param([string]$Name = $ServiceName)
    $r = Invoke-Native -Exe $script:ScExe -Arguments @('queryex', $Name) -TimeoutSec 30
    if ($r.ExitCode -eq 1060) { return $null }   # ERROR_SERVICE_DOES_NOT_EXIST
    if ($r.ExitCode -ne 0) { throw "sc.exe queryex $Name failed ($($r.ExitCode)): $($r.StdOut)$($r.StdErr)" }
    return ConvertFrom-ScQueryEx $r.StdOut
}

function Format-ScState {
    param($State)
    if ($null -eq $State) { return 'NOT INSTALLED' }
    return ('{0} win32={1} specific={2} pid={3}' -f $State.State, $State.Win32Exit, $State.SpecificExit, $State.Pid)
}

function Get-Starts { return @(ConvertFrom-FixtureLog (Read-Lines (Join-Path $script:StateDir 'starts.log'))) }
function Get-Exits { return @(ConvertFrom-FixtureLog (Read-Lines (Join-Path $script:StateDir 'exits.log'))) }

# The exit record(s) of the process the SCM knew as $ScmPid, from $Since (Unix ms) on.
# Windows reuses process ids within a run, so an id alone also finds any earlier
# process that had it.
function Get-ExitsOf {
    param([int]$ScmPid, [Parameter(Mandatory = $true)][int64]$Since)
    return @(Get-Exits | Where-Object { $_.pid -eq "$ScmPid" -and [int64]$_.unix_ms -ge $Since })
}

# The failed update requests a service log holds from $Since on. The log is named by
# process id, so it also holds any earlier process that had the id.
function Get-RequestFailures {
    param([string]$Log, [Parameter(Mandatory = $true)][int64]$Since)
    return @(Read-Lines $Log | Where-Object {
            $_ -match $script:RequestFailedPattern -and [int64]($_ -split ' ', 2)[0] -ge $Since })
}

# Whether the process the SCM knew as $ScmPid has written status.txt from $Since on.
function Test-HeartbeatOf {
    param([int]$ScmPid, [Parameter(Mandatory = $true)][int64]$Since)
    foreach ($line in (Read-Lines (Join-Path $script:StateDir 'status.txt'))) {
        if ($line -match "^pid=$ScmPid\t.*\theartbeat_unix_ms=(\d+)" -and [int64]$Matches[1] -ge $Since) { return $true }
    }
    return $false
}

# The AWS-LC-FIPS module's DLLs a FIPS build imports at load time
# (aws-lc-fips-sys 0.14: aws_lc_fips_<ver>_crypto.dll; older releases added
# ..._rust_wrapper.dll).
function Get-FipsDlls {
    if (-not $FipsDllDir) { return @() }
    return @(Get-ChildItem -LiteralPath $FipsDllDir -Filter 'aws_lc_fips_*.dll' -File | Sort-Object Name)
}

# Run $Count processes of $Exe $Arguments, $Parallel at a time; their exit codes and
# stdout (the jitter diagnostic's one JSON line each).
function Invoke-ParallelNative {
    param([string]$Exe, [string[]]$Arguments, [int]$Count, [int]$Parallel, [int]$TimeoutSec = 1800)
    $results = New-Object System.Collections.ArrayList
    $running = New-Object System.Collections.ArrayList
    $started = 0
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($results.Count -lt $Count) {
        if ((Get-Date) -gt $deadline) { throw "TIMEOUT: $($results.Count) of $Count $Exe runs finished" }
        while ($running.Count -lt $Parallel -and $started -lt $Count) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Exe
            $psi.Arguments = ConvertTo-ArgString $Arguments
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($psi)
            # Drain both pipes asynchronously: a full stderr pipe would block the child.
            [void]$running.Add([pscustomobject]@{ P = $process; Out = $process.StandardOutput.ReadToEndAsync(); Err = $process.StandardError.ReadToEndAsync() })
            $started++
        }
        foreach ($r in @($running)) {
            if ($r.P.HasExited) {
                $r.P.WaitForExit()
                [void]$results.Add([pscustomobject]@{ ExitCode = $r.P.ExitCode; StdOut = $r.Out.Result; StdErr = $r.Err.Result })
                $r.P.Dispose()
                $running.Remove($r)
            }
        }
        Start-Sleep -Milliseconds 5
    }
    return $results.ToArray()
}

# Fold the diagnostic's JSON lines into one summary; every line is also kept in
# diagnostics\entropy-diag.jsonl (an artifact) tagged with $Label.
function Measure-EntropyDiag {
    param([string]$Label, [object[]]$Results)
    $file = Join-Path $DiagnosticsDir 'entropy-diag.jsonl'
    New-Item -ItemType Directory -Force -Path $DiagnosticsDir | Out-Null
    $sum = [ordered]@{ processes = 0; crashed = 0; trials = 0; ok = 0; abort_init = 0; abort_alloc = 0; abort_read = 0 }
    $init = @{}
    $read = @{}
    $p99 = 0.0
    $backend = ''
    foreach ($r in $Results) {
        $sum.processes++
        $line = "$($r.StdOut)".Trim()
        if ($r.ExitCode -ne 0 -or -not $line.StartsWith('{')) {
            $sum.crashed++
            Write-Log ("  {0}: a diagnostic process exited {1} ({2}) {3}" -f $Label, $r.ExitCode, (Format-ExitCode $r.ExitCode), "$($r.StdErr)".Trim())
            continue
        }
        Add-Content -LiteralPath $file -Value ($line -replace '^\{', ('{"run":"' + $Label + '",')) -Encoding UTF8
        $j = $line | ConvertFrom-Json
        $backend = $j.backend
        $sum.trials += [int]$j.trials
        foreach ($k in @('ok', 'abort_init', 'abort_alloc', 'abort_read')) { $sum[$k] += [int]$j.outcomes.$k }
        foreach ($prop in $j.init_failures.PSObject.Properties) { $init[$prop.Name] = [int]$init[$prop.Name] + [int]$prop.Value }
        foreach ($try in $j.read_failures.PSObject.Properties) {
            foreach ($prop in $try.Value.PSObject.Properties) {
                $key = "$($try.Name):$($prop.Name)"
                $read[$key] = [int]$read[$key] + [int]$prop.Value
            }
        }
        if ([double]$j.trial_ms.p99 -gt $p99) { $p99 = [double]$j.trial_ms.p99 }
    }
    $aborts = $sum.abort_init + $sum.abort_alloc + $sum.abort_read
    Write-Log ("  {0} [{1}]: {2} processes ({3} crashed), {4} trials: {5} ok, {6} would-be aborts (init {7}, alloc {8}, read {9}); worst p99 {10:F1} ms" -f `
        $Label, $backend, $sum.processes, $sum.crashed, $sum.trials, $sum.ok, $aborts, $sum.abort_init, $sum.abort_alloc, $sum.abort_read, $p99)
    foreach ($k in ($init.Keys | Sort-Object)) { Write-Log "    init failure $k x$($init[$k])" }
    foreach ($k in ($read.Keys | Sort-Object)) { Write-Log "    read failure $k x$($read[$k])" }
    return [pscustomobject]@{ Label = $Label; Crashed = $sum.crashed; Processes = $sum.processes }
}

# The entropy.jitter_diagnostics body (a function so the self-test drives the same
# backend loop): per backend, warm ($Parallel concurrent x $Trials) and cold ($Cold
# one-trial processes) runs, summarized. Returns the per-run summaries.
function Invoke-JitterDiagnostics {
    param([int]$Trials = $EntropyDiagTrials, [int]$Parallel = $EntropyDiagParallel, [int]$Cold = $EntropyDiagCold)
    Write-ResourceSnapshot 'before the jitter diagnostics'
    # Objects, never nested @() arrays: PowerShell unrolls @(@(...)) into its
    # elements (the first run iterated over the STRING 'vendored' -- labels "v-",
    # argument 'e').
    $backends = New-Object System.Collections.ArrayList
    [void]$backends.Add([pscustomobject]@{ Name = 'vendored'; Args = [string[]]@() })
    $fipsDll = @(Get-FipsDlls | Where-Object { $_.Name -like '*_crypto.dll' })
    if ($fipsDll.Count -eq 1) {
        # The module DLL's jitterentropy exports are an observation, not a
        # contract: probe them first (zero trials) and drop the backend, loudly,
        # if the DLL does not export them.
        $fipsArgs = @('--backend', "fips-dll=$($fipsDll[0].FullName)")
        $probe = Invoke-Native -Exe $EntropyDiagExe -Arguments (@('--trials', '0') + $fipsArgs) -TimeoutSec 60
        if ($probe.ExitCode -eq 0) {
            Write-Log "  fips-dll backend: $($probe.StdErr.Trim())"
            [void]$backends.Add([pscustomobject]@{ Name = 'fips-dll'; Args = [string[]]$fipsArgs })
        } else {
            Write-Log "  fips-dll backend unavailable (exit $($probe.ExitCode)): $($probe.StdErr.Trim())"
        }
    }
    $runs = @()
    foreach ($b in $backends) {
        # (PowerShell names are case-insensitive: a local `$cold` IS the [int]$Cold
        # parameter, so the result variables are named apart.)
        $warmResults = Invoke-ParallelNative -Exe $EntropyDiagExe -Count $Parallel -Parallel $Parallel `
            -Arguments ([string[]]@('--trials', "$Trials", '--label', "$($b.Name)-warm") + $b.Args)
        $runs += Measure-EntropyDiag -Label "$($b.Name)-warm (x$Parallel concurrent)" -Results $warmResults
        $coldResults = Invoke-ParallelNative -Exe $EntropyDiagExe -Count $Cold -Parallel $Parallel `
            -Arguments ([string[]]@('--trials', '1', '--label', "$($b.Name)-cold") + $b.Args)
        $runs += Measure-EntropyDiag -Label "$($b.Name)-cold" -Results $coldResults
    }
    return $runs
}

function Format-ExitCode {
    param([int]$Code)
    return ('0x{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes($Code), 0))
}

# Start $Count fresh entropy_probe processes, $Parallel at a time, and tally how
# they ended. A first-draw abort is an NTSTATUS exit (0xC0000409 fast-fail) with no
# output. WER keeps at most 3 of the probe's dumps, so its crashes can't evict the
# suite's other dumps.
function Invoke-EntropyProbe {
    param([int]$Count = $EntropyProbeCount)
    if ($env:SEAWORTHY_CRASHDUMP_DIR) {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\entropy_probe.exe'
        try {
            New-Item -Path $key -Force | Out-Null
            Set-ItemProperty -Path $key -Name DumpFolder -Value $env:SEAWORTHY_CRASHDUMP_DIR -Type ExpandString
            Set-ItemProperty -Path $key -Name DumpType -Value 1 -Type DWord
            Set-ItemProperty -Path $key -Name DumpCount -Value 3 -Type DWord
        } catch { Write-Log "per-probe LocalDumps not configured: $($_.Exception.Message)" }
    }
    $codes = @{}
    $outputs = @{}
    $running = New-Object System.Collections.ArrayList
    $started = 0
    $finished = 0
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $deadline = (Get-Date).AddSeconds([math]::Max(300, $Count))
    while ($finished -lt $Count) {
        if ((Get-Date) -gt $deadline) { throw "TIMEOUT: $finished of $Count probes finished" }
        while ($running.Count -lt $EntropyProbeParallel -and $started -lt $Count) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $EntropyProbeExe
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            [void]$running.Add([System.Diagnostics.Process]::Start($psi))
            $started++
        }
        foreach ($process in @($running)) {
            if ($process.HasExited) {
                $process.WaitForExit()
                $code = $process.ExitCode
                $out = $process.StandardOutput.ReadToEnd().Trim()
                if ($codes.ContainsKey($code)) { $codes[$code]++ } else { $codes[$code] = 1 }
                if ($code -eq 0) { if ($outputs.ContainsKey($out)) { $outputs[$out]++ } else { $outputs[$out] = 1 } }
                $process.Dispose()
                $running.Remove($process)
                $finished++
            }
        }
        Start-Sleep -Milliseconds 5
    }
    $watch.Stop()
    return [pscustomobject]@{ Codes = $codes; Outputs = $outputs; Seconds = $watch.Elapsed.TotalSeconds }
}

function Send-Control {
    param([string]$Command)
    $dir = Join-Path $script:StateDir 'control'
    Write-TextNoBom -Path (Join-Path $dir $Command) -Text ''
    Write-Log "control command '$Command' dropped"
}

function Set-Required {
    param([string]$Version)
    $path = Join-Path $script:StubRoot 'required.txt'
    if ($Version) {
        Write-TextNoBom -Path $path -Text "$Version`n"
        Write-Log "version gate now requires $Version"
    } else {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        Write-Log 'version gate demand removed'
    }
}

function Get-ScmEvents {
    param([datetime]$Since)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $Since } -ErrorAction Stop |
                Where-Object { $_.Message -like "*$ProductName*" } |
                Sort-Object TimeCreated |
                ForEach-Object { '{0:HH:mm:ss} id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') })
    } catch {
        return @("(System event log unavailable: $($_.Exception.Message))")
    }
}

# Trigger a failure and watch the SCM. Tracks the process that FAILS (the one running
# before the trigger, or -- when the trigger starts a stopped service -- the first new
# process seen), records the first STOPPED observation after it with its exit codes,
# and returns once a DIFFERENT, newer process has logged its start and reached
# $UntilState: the SCM's recovery action.
function Watch-Restart {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Trigger,
        [string]$UntilState = 'RUNNING',
        [int]$TimeoutSec = 120
    )
    $before = Get-ScState
    $since = Get-Date
    $sinceMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Write-Log "before: $(Format-ScState $before)"
    $startsBefore = @(Get-Starts).Count
    $failing = 0
    if ($before.State -ne 'STOPPED') { $failing = $before.Pid }
    & $Trigger
    $stopped = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $s = Get-ScState
        if ($null -eq $s) { throw 'the service disappeared from the SCM' }
        if ($null -eq $stopped) {
            if ($failing -eq 0 -and $s.State -ne 'STOPPED' -and $s.Pid -ne 0) {
                $failing = $s.Pid
                Write-Log "started: $(Format-ScState $s)"
            } elseif ($s.State -eq 'STOPPED' -and ($failing -ne 0 -or $s.Win32Exit -ne $before.Win32Exit -or $s.SpecificExit -ne $before.SpecificExit)) {
                # The trigger started a stopped service whose process failed between two
                # polls: its start record names it.
                if ($failing -eq 0) {
                    $fresh = @(Get-Starts | Select-Object -Skip $startsBefore)
                    if ($fresh.Count -ge 1) { $failing = [int]$fresh[0].pid }
                }
                $stopped = $s
                $startsAtStop = @(Get-Starts).Count
                Write-Log "observed: $(Format-ScState $s) (failed pid $failing)"
            }
        } elseif ($s.State -eq $UntilState -and $s.Pid -ne 0) {
            # A start record from after the stop: the new process can have any earlier
            # process's id, even the failed one's.
            $newStart = @(Get-Starts | Select-Object -Skip $startsAtStop | Where-Object { $_.pid -eq "$($s.Pid)" })
            if ($newStart.Count -eq 1) {
                $elapsed = ((Get-Date) - $since).TotalSeconds
                Write-Log ("restarted by the SCM after {0:F1}s: {1}" -f $elapsed, (Format-ScState $s))
                foreach ($e in (Get-ScmEvents -Since $since.AddSeconds(-2))) { Write-Log "  event: $e" }
                return [pscustomobject]@{ Stopped = $stopped; After = $s; NewStart = $newStart[0]; OldPid = $failing; SinceMs = $sinceMs; Elapsed = $elapsed }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    foreach ($e in (Get-ScmEvents -Since $since.AddSeconds(-2))) { Write-Log "  event: $e" }
    throw "TIMEOUT after ${TimeoutSec}s: no SCM restart into $UntilState (failed pid $failing; stopped observed: $(Format-ScState $stopped); now: $(Format-ScState (Get-ScState)))"
}

function Get-IcaclsEntries {
    param([string]$Path)
    $r = Invoke-Native -Exe $script:IcaclsExe -Arguments @($Path) -TimeoutSec 30
    Assert-True ($r.ExitCode -eq 0) "icacls $Path failed: $($r.StdOut)$($r.StdErr)"
    foreach ($line in ($r.StdOut -split "`r?`n")) { if ($line.Trim()) { Write-Log "  icacls| $line" } }
    return ConvertFrom-Icacls -Text $r.StdOut -Path $Path
}

function Invoke-Icacls {
    param([string[]]$Arguments)
    $r = Invoke-Native -Exe $script:IcaclsExe -Arguments $Arguments -TimeoutSec 60
    Assert-True ($r.ExitCode -eq 0) "icacls $($Arguments -join ' ') failed: $($r.StdOut)$($r.StdErr)"
}

function Get-VirtualAccountSid {
    param([string]$Name)
    $account = New-Object System.Security.Principal.NTAccount('NT SERVICE', $Name)
    return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Get-ProcessOwnerSid {
    param([int]$ProcessId)
    $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId"
    if ($null -eq $process) { return $null }
    return (Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid).Sid
}

# ---------------------------------------------------------------------------
# The version-gate stub

function Start-Stub {
    $ready = Join-Path $script:WorkDir 'stub.ready'
    Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
    $arguments = ConvertTo-ArgString @('serve', '--root', $script:StubRoot, '--log', $script:StubLog,
        '--ready-file', $ready, '--lifetime-secs', '7200')
    $script:StubProcess = Start-Process -FilePath $FixtureExe -ArgumentList $arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $script:WorkDir 'stub.out') -RedirectStandardError (Join-Path $script:WorkDir 'stub.err')
    $addr = Wait-Until -TimeoutSec 30 -What 'the version-gate stub to listen' -Condition {
        if (Test-Path -LiteralPath $ready) { (Read-SharedText $ready).Trim() }
    }
    Write-Log "version-gate stub pid $($script:StubProcess.Id) listening on $addr"
    return $addr
}

function Get-Http {
    param([string]$Url)
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Timeout = 10000
    try {
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $body = $reader.ReadToEnd()
        $response.Close()
        return [pscustomobject]@{ Status = 200; Body = $body }
    } catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if ($null -eq $response) { throw }
        $status = [int]$response.StatusCode
        $response.Close()
        return [pscustomobject]@{ Status = $status; Body = '' }
    }
}

# ---------------------------------------------------------------------------
# The Rust suites (nextest over the cross-built archive)

function Write-NativeOutput {
    param($Result, [string]$Prefix)
    foreach ($line in (($Result.StdOut + $Result.StdErr) -split "`r?`n")) { if ($line.Trim()) { Write-Log "  ${Prefix}| $line" } }
}

# One `cargo-nextest.exe nextest run` over the archive, extracted to a fixed directory so
# the profile's JUnit report (<target>\nextest\<profile>\junit.xml) can be collected
# into $JUnitDir as $JUnitName.
function Invoke-Nextest {
    param([string]$Filter, [string]$RunIgnored, [string]$JUnitName, [int]$TimeoutSec)
    if (-not ($NextestExe -and $NextestArchive)) {
        Skip-Case 'no nextest (-NextestExe/-NextestArchive or SEAWORTHY_NEXTEST_EXE/SEAWORTHY_NEXTEST_ARCHIVE) was given'
    }
    Assert-True (Test-Path -LiteralPath $NextestExe -PathType Leaf) "nextest $NextestExe does not exist"
    Assert-True (Test-Path -LiteralPath $NextestArchive -PathType Leaf) "archive $NextestArchive does not exist"
    $extract = Join-Path $script:DataRoot ('nextest-' + [System.IO.Path]::GetFileNameWithoutExtension($JUnitName))
    if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $extract | Out-Null
    # The standalone cargo-nextest binary takes `nextest` as argv[1].
    $arguments = @('nextest', 'run', '--archive-file', $NextestArchive, '--extract-to', $extract, '--extract-overwrite',
        '-E', $Filter, '--run-ignored', $RunIgnored, '--no-fail-fast')
    if ($NextestProfile) { $arguments += @('--profile', $NextestProfile) }
    if ($WorkspaceRemap) { $arguments += @('--workspace-remap', $WorkspaceRemap) }
    if ($RunIgnored -eq 'only') {
        $arguments += @('--test-threads', '1')
    } elseif ($NextestThreads -gt 0) {
        $arguments += @('--test-threads', "$NextestThreads")
    }
    Write-ResourceSnapshot "before nextest ($JUnitName)"
    # The profile's report path is shared by both nextest runs: clear it first
    # so a run that dies before writing its report can never pass off the
    # previous run's file as its own.
    $remappedReport = $null
    if ($WorkspaceRemap -and $NextestProfile) {
        $remappedReport = Join-Path $WorkspaceRemap "target\nextest\$NextestProfile\junit.xml"
        if (Test-Path -LiteralPath $remappedReport) { Remove-Item -LiteralPath $remappedReport -Force }
    }
    $environment = @{ SEAWORTHY_WINDOWS_SCM_E2E = '1' }
    # FIPS builds import the AWS-LC-FIPS DLL at load time; the archive's linked path
    # did not reach the test processes' PATH (the crypto crate's tests died 0xC0000135
    # while the windows_scm binary -- which links no crypto, so the import was
    # dropped -- ran). The bundle's DLL directory goes on PATH explicitly.
    if ($FipsDllDir) { $environment['PATH'] = "$FipsDllDir;$env:PATH" }
    $r = Invoke-Native -Exe $NextestExe -Arguments $arguments -Environment $environment -TimeoutSec $TimeoutSec
    Write-NativeOutput $r 'nextest'
    # With --workspace-remap nextest writes the profile's report under the
    # REMAPPED workspace's target dir (`<remap>\target\nextest\<profile>\junit.xml`,
    # verified with a local archive run), never under --extract-to: looking
    # only in $extract lost every Windows run's JUnit (and with it the abort
    # record of a crashed test). Both nextest runs share one profile, so the
    # report is copied out right after each run, before the next overwrites it.
    $report = @()
    if ($remappedReport -and (Test-Path -LiteralPath $remappedReport -PathType Leaf)) {
        $report = @(Get-Item -LiteralPath $remappedReport)
    }
    if ($report.Count -eq 0) {
        $report = @(Get-ChildItem -LiteralPath $extract -Recurse -Filter 'junit.xml' -ErrorAction SilentlyContinue)
    }
    # Any crash dumps WER wrote (the job configures LocalDumps): the file
    # name carries the crashed image and pid, so the log names them.
    if ($env:SEAWORTHY_CRASHDUMP_DIR -and (Test-Path -LiteralPath $env:SEAWORTHY_CRASHDUMP_DIR)) {
        foreach ($dump in @(Get-ChildItem -LiteralPath $env:SEAWORTHY_CRASHDUMP_DIR -Filter '*.dmp' -ErrorAction SilentlyContinue)) {
            Write-Log "crash dump present: $($dump.Name) ($($dump.Length) bytes, $($dump.LastWriteTime.ToString('HH:mm:ss.fff')))"
        }
    }
    if ($report.Count -ge 1) {
        Copy-Item -LiteralPath $report[0].FullName -Destination (Join-Path $JUnitDir $JUnitName) -Force
        Write-Log "nextest JUnit report collected as $JUnitName"
    } else {
        Write-Log 'no nextest JUnit report found (profile without [junit]?)'
    }
    return $r
}

# ---------------------------------------------------------------------------
# Diagnostics + cleanup

function Write-Diagnostics {
    if ($Phase -eq 'SelfTest' -or $Phase -eq 'Entropy') { return }
    Write-Log "diagnostics: service state $(Format-ScState (Get-ScState))"
    foreach ($file in @('starts.log', 'exits.log', 'status.txt')) {
        foreach ($line in (Read-Lines (Join-Path $script:StateDir $file))) { Write-Log "  $file| $line" }
    }
    $logs = Join-Path $script:StateDir 'logs'
    if (Test-Path -LiteralPath $logs) {
        $latest = Get-ChildItem -LiteralPath $logs -Filter '*.log' | Sort-Object LastWriteTime | Select-Object -Last 2
        foreach ($log in $latest) {
            foreach ($line in (Get-Content -LiteralPath $log.FullName -Tail 40)) { Write-Log "  $($log.Name)| $line" }
        }
    }
    # The gate polls once per poll_ms: the count, and the last few.
    $stub = @(Get-StubRequests)
    if ($stub.Count -gt 0) { Write-Log "  stub: $($stub.Count) requests in total" }
    foreach ($request in @($stub | Select-Object -Last 10)) { Write-Log "  stub| $($request.Method) $($request.Path) $($request.Status) $($request.Bytes)" }
    if (Test-Path -LiteralPath $script:ProgramDir) {
        foreach ($item in (Get-ChildItem -LiteralPath $script:ProgramDir -Force)) { Write-Log "  programdir| $($item.Name) $($item.Length)" }
    }
    if (Test-Path -LiteralPath $script:MsiLog) {
        foreach ($line in (Get-Content -LiteralPath $script:MsiLog -Tail 40)) { Write-Log "  msiexec| $line" }
    }
}

function Save-Artifacts {
    $diag = $DiagnosticsDir
    New-Item -ItemType Directory -Force -Path $diag | Out-Null
    if (Test-Path -LiteralPath $script:StateDir) {
        Copy-Item -LiteralPath $script:StateDir -Destination (Join-Path $diag 'state') -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($file in @('stub.log', 'stub.out', 'stub.err', 'msiexec.log')) {
        $path = Join-Path $script:WorkDir $file
        if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $diag -Force }
    }
    if ($script:IsWin) {
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 200 -ErrorAction Stop |
                ForEach-Object { '{0:o} id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') } |
                Set-Content -LiteralPath (Join-Path $diag 'scm-events.txt') -Encoding UTF8
        } catch { }
    }
}

# Logical CPUs, physical memory, and the commit charge: a memory-capped
# machine shows its cap here (the resource-exhaustion question silent
# native aborts raise). Never fails the suite.
function Write-ResourceSnapshot {
    param([string]$When)
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $mib = { param($kib) [math]::Round($kib / 1024) }
        Write-Log ("resources ({0}): logical CPUs={1}, physical={2} MiB (free {3} MiB), commit limit={4} MiB (free {5} MiB)" -f `
            $When, [Environment]::ProcessorCount, [math]::Round($cs.TotalPhysicalMemory / 1MB),
            (& $mib $os.FreePhysicalMemory), (& $mib $os.TotalVirtualMemorySize), (& $mib $os.FreeVirtualMemory))
    } catch {
        Write-Log "resources ($When): unavailable ($($_.Exception.Message))"
    }
}

# This product's Programs and Features entries (by display name): @{ Code; Version }.
# Callers collect with @(...) (PowerShell 5.1 unrolls one entry to a scalar).
function Get-ProductEntries {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($props -and ($props.PSObject.Properties.Name -contains 'DisplayName') -and $props.DisplayName -eq $ProductName) {
                [pscustomobject]@{ Code = $key.PSChildName; Version = $props.DisplayVersion }
            }
        }
    }
}

# msiexec, silent, logging verbosely to $script:MsiLog, waited for ALONE and bounded:
# never Start-Process -Wait, which waits on a job object for every descendant
# (Restart Manager may start an app from msiexec's process, and the wait would
# never end). The exit code (0 success, 3010 success with a reboot pending).
function Invoke-Msiexec {
    param([string[]]$Arguments, [int]$TimeoutSec = 900)
    $msiexec = Join-Path $script:System32 'msiexec.exe'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:MsiLog) | Out-Null
    $all = @($Arguments) + @('/qn', '/norestart', '/l*v', $script:MsiLog)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $msiexec
    $psi.Arguments = ConvertTo-ArgString $all
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    if (-not $process.WaitForExit($TimeoutSec * 1000)) {
        try { $process.Kill() } catch { }
        throw "TIMEOUT: msiexec $($psi.Arguments) did not exit within ${TimeoutSec}s"
    }
    Write-Log ("msiexec {0} -> exit {1} (log {2})" -f ($Arguments -join ' '), $process.ExitCode, $script:MsiLog)
    return $process.ExitCode
}

# Removes this product if an earlier run (a persistent shell host) left it installed.
function Remove-ProductQuietly {
    foreach ($entry in @(Get-ProductEntries)) {
        $code = Invoke-Msiexec @('/x', $entry.Code)
        Write-Log "cleanup: msiexec /x $($entry.Code) ($ProductName $($entry.Version)) -> exit $code"
    }
}

# Leftovers of an EARLIER run on a persistent host (hosted runners start clean): the
# product, the state the MSI keeps on removal, and the suite's work directory. Only
# this suite's own `AcmeE2E` names are touched.
function Remove-StaleE2EState {
    Remove-ProductQuietly
    foreach ($dir in @($script:InstallRoot, $script:DataRoot, $script:SuiteRoot)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        & icacls.exe $dir /reset /T /C /Q | Out-Null
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        Assert-True (-not (Test-Path -LiteralPath $dir)) "stale e2e directory $dir from an earlier run could not be removed"
        Write-Log "removed stale e2e directory from an earlier run: $dir"
    }
}

# ---------------------------------------------------------------------------
# Preconditions shared by the phases

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    Write-Log "running as $($identity.Name)"
    Assert-True ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) `
        'the suite must run elevated (an administrator; GitHub-hosted Windows runners are): it installs an MSI and reads service ACLs'
}

function Assert-Inputs {
    Assert-True ([bool]$FixtureExe) '-FixtureExe is required'
    Assert-True (Test-Path -LiteralPath $FixtureExe -PathType Leaf) "-FixtureExe $FixtureExe does not exist"
    Assert-True ([bool]$Msi) '-Msi (SEAWORTHY_SCM_MSI) is required: the service under test'
    Assert-True (Test-Path -LiteralPath $Msi -PathType Leaf) "-Msi $Msi does not exist"
    Write-Log "MSI: $Msi ($((Get-Item -LiteralPath $Msi).Length) bytes)"
    if ($FipsDllDir) {
        $dlls = @(Get-FipsDlls)
        foreach ($dll in $dlls) { Write-Log "FIPS DLL: $($dll.Name) ($($dll.Length) bytes)" }
        Assert-True (@($dlls | Where-Object { $_.Name -like '*_crypto.dll' }).Count -eq 1) "the AWS-LC-FIPS crypto DLL is in -FipsDllDir $FipsDllDir"
    }
}

# The MSI's state directory, back to a clean slate for the suite (its DACL is the
# MSI's: the files written here inherit the service account's Modify), and the
# service's configuration.
function Reset-StateDir {
    param([string]$Conf)
    Assert-True (Test-Path -LiteralPath $script:StateDir -PathType Container) "the MSI created $($script:StateDir)"
    foreach ($item in @(Get-ChildItem -LiteralPath $script:StateDir -Force)) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $script:StateDir 'control') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $script:StateDir 'logs') | Out-Null
    Write-TextNoBom -Path (Join-Path $script:StateDir 'service.conf') -Text $Conf
}

# Installs the MSI and waits for the service it starts (ServiceControl Start="install":
# with no service.conf yet the gate is off), then stops it and hands the suite a clean
# state directory with $Conf.
function Install-Product {
    param([string]$Conf)
    $installing = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $code = Invoke-Msiexec @('/i', $Msi)
    Assert-True ($code -eq 0) "msiexec /i exited $code (0 expected; 3010 = a reboot pending; log $($script:MsiLog))"
    Wait-Until -TimeoutSec 90 -What 'the service the MSI started to be RUNNING' -Condition {
        $s = Get-ScState; $null -ne $s -and $s.State -eq 'RUNNING' } | Out-Null
    $pid0 = (Get-ScState).Pid
    $stop = Invoke-Fixture @('stop', '--name', $ServiceName)
    Assert-True ($stop.ExitCode -eq 0) 'backend stop() of the MSI-started service'
    Wait-Until -TimeoutSec 30 -What 'the MSI-started process''s exit record' -Condition {
        @(Get-ExitsOf $pid0 -Since $installing).Count -ge 1 } | Out-Null
    Reset-StateDir -Conf $Conf
}

# ===========================================================================
# Phase: All
# ===========================================================================

function Invoke-MainSuite {
    Invoke-Case 'environment.preconditions' {
        Assert-Administrator
        Assert-Inputs
        $os = Get-CimInstance Win32_OperatingSystem
        Write-Log "OS: $($os.Caption) build $($os.BuildNumber) ($($os.Version))"
        Write-Log "PowerShell $($PSVersionTable.PSVersion)"
        $scm = Get-Service -Name 'EventLog' -ErrorAction SilentlyContinue
        Assert-True ($null -ne $scm) 'the Service Control Manager must be reachable (a full Windows or Server Core host, not Nano Server)'
        Write-ResourceSnapshot 'start'
        Remove-StaleE2EState
        New-Item -ItemType Directory -Force -Path $script:WorkDir | Out-Null
        New-Item -ItemType Directory -Force -Path $script:StubRoot | Out-Null
    }

    Invoke-Case 'fixture.selfcheck' {
        $v = Invoke-Fixture @('version')
        Assert-True ($v.ExitCode -eq 0 -and $v.StdOut.Trim() -eq '1.0.0') "the fixture reports 1.0.0 (got '$($v.StdOut.Trim())')"
        $t = Invoke-Fixture @('target-triple')
        Assert-True ($t.ExitCode -eq 0 -and $t.StdOut.Trim() -eq 'x86_64-pc-windows-msvc') "target triple (got '$($t.StdOut.Trim())')"
        $bad = Invoke-Fixture @('no-such-command')
        Assert-True ($bad.ExitCode -eq 2) 'an unknown command is a usage error (exit 2) and starts nothing'
        if ($null -ne $script:ExpectFipsBool) {
            $f = Invoke-Fixture @('fips')
            Assert-True ($f.ExitCode -eq 0 -and $f.StdOut.Trim() -eq "fips=$("$($script:ExpectFipsBool)".ToLowerInvariant())") "the fixture's FIPS posture is $($script:ExpectFipsBool) (got '$($f.StdOut.Trim())')"
        }
    }

    Invoke-Case 'stub.version_gate' {
        $script:Ctx.StubAddr = Start-Stub
        $required = Get-Http "http://$($script:Ctx.StubAddr)/required"
        Assert-True ($required.Status -eq 404) 'no version demand yet (404)'
    }

    Invoke-Case 'msi.install_registers_the_virtual_account_service' {
        # The MSI (the crate installs nothing itself) lays out the launcher and its
        # cores, registers the service under its virtual account with its failure
        # actions, and starts it (ServiceControl Start="install").
        Assert-True (-not (Test-Path -LiteralPath $script:ProgramDir)) "$($script:ProgramDir) must not pre-exist (the MSI lays it out)"
        Assert-True ($null -eq (Get-ScState)) "no $ServiceName service before the install"
        Install-Product -Conf "stub_addr=$($script:Ctx.StubAddr)`npoll_ms=1000`n"
        Assert-True (Test-Path -LiteralPath $script:ProgramPath -PathType Leaf) "the launcher is installed at $($script:ProgramPath)"
        $cores = @(Get-ChildItem -LiteralPath $script:ProgramDir -Filter 'scm_core_*.dll' -File)
        foreach ($core in $cores) { Write-Log "core: $($core.Name) ($($core.Length) bytes)" }
        Assert-True ($cores.Count -eq 3) "one core per CPU target (x86-64-v4, v3, v2) beside the launcher (found $($cores.Count))"
        $entries = @(Get-ProductEntries)
        Assert-True ($entries.Count -eq 1) "one Programs and Features entry named $ProductName (found $($entries.Count))"
        $state = Get-ScState
        Assert-True ($null -ne $state -and $state.State -eq 'STOPPED') "registered, stopped for the suite (got $(Format-ScState $state))"
        $qc = Invoke-Native -Exe $script:ScExe -Arguments @('qc', $ServiceName)
        foreach ($line in ($qc.StdOut -split "`r?`n")) { if ($line.Trim()) { Write-Log "  qc| $line" } }
        Assert-True ($qc.StdOut -match "(?m)SERVICE_START_NAME\s*:\s*NT SERVICE\\$([regex]::Escape($ServiceName))\s*$") 'the account is the virtual NT SERVICE\<name>'
        Assert-True ($qc.StdOut -match 'AUTO_START') 'auto-start'
        Assert-True ($qc.StdOut -match ('(?m)BINARY_PATH_NAME\s*:\s*"?' + [regex]::Escape($script:ProgramPath) + '"?\s+run --name ' + [regex]::Escape($ServiceName))) 'the image path is the installed launcher, its arguments `run --name <name>`'
        $failure = Invoke-Native -Exe $script:ScExe -Arguments @('qfailure', $ServiceName)
        foreach ($line in ($failure.StdOut -split "`r?`n")) { if ($line.Trim()) { Write-Log "  qfailure| $line" } }
        Assert-True ($failure.StdOut -match "RESTART -- Delay = $RestartDelayMs") 'the Restart failure action carries the configured delay'
        $flag = Invoke-Native -Exe $script:ScExe -Arguments @('qfailureflag', $ServiceName)
        Assert-True ($flag.StdOut -match 'TRUE') 'failure actions apply to non-crash failures (the fatal exit: Stopped + service-specific 1)'
    }

    Invoke-Case 'msi.dacl_protected_non_admin_unwritable' {
        $account = "NT SERVICE\$ServiceName"
        # The program directory (MsiLockPermissionsEx): protected; SYSTEM and
        # Administrators full, the account read + execute -- a service never
        # rewrites its own program (updates are the package manager's).
        Assert-True ((Get-Acl -LiteralPath $script:ProgramDir).AreAccessRulesProtected) "$($script:ProgramDir) DACL is PROTECTED (no inheritance from above)"
        $entries = @(Get-IcaclsEntries $script:ProgramDir)
        foreach ($entry in $entries) {
            Assert-True (-not ($entry.Tokens -contains 'I')) "$($script:ProgramDir) has no inherited ACE ($($entry.Principal))"
        }
        $principals = @($entries | ForEach-Object { $_.Principal.ToLowerInvariant() } | Sort-Object -Unique)
        $allowed = @('nt authority\system', 'builtin\administrators', $account.ToLowerInvariant())
        foreach ($p in $principals) { Assert-True ($allowed -contains $p) "$($script:ProgramDir) grants only SYSTEM, Administrators, and the service account (found $p)" }
        $accountEntry = @($entries | Where-Object { $_.Principal -ieq $account })
        Assert-True ($accountEntry.Count -eq 1 -and -not (Test-GrantsWrite $accountEntry[0])) "the virtual account holds read + execute, no write, on its program directory (got $(@($accountEntry | ForEach-Object { $_.Tokens -join ',' }) -join ' | '))"
        foreach ($file in @(Get-ChildItem -LiteralPath $script:ProgramDir -File)) {
            foreach ($entry in @(Get-IcaclsEntries $file.FullName)) {
                if (-not (Test-TrustedPrincipal $entry.Principal '')) {
                    Assert-True (-not (Test-GrantsWrite $entry)) "$($file.Name) grants no write to $($entry.Principal)"
                }
            }
        }
        # The vendor directory above it keeps %ProgramFiles%' DACL: nobody untrusted writes.
        foreach ($entry in @(Get-IcaclsEntries $script:InstallRoot)) {
            if (-not (Test-TrustedPrincipal $entry.Principal '')) {
                Assert-True (-not (Test-GrantsWrite $entry)) "$($script:InstallRoot) grants no write to $($entry.Principal)"
            }
        }
        # %ProgramData%: any user may create a directory there, so the MSI locks both
        # directories above the state (OWNER RIGHTS read-control only: a squatting owner
        # keeps no implicit WRITE_DAC), and the state grants the account Modify alone.
        foreach ($dir in @($script:DataRoot, $script:MsiDataDir, $script:StateDir)) {
            Assert-True ((Get-Acl -LiteralPath $dir).AreAccessRulesProtected) "$dir DACL is PROTECTED"
            $dirEntries = @(Get-IcaclsEntries $dir)
            $allowedHere = @('nt authority\system', 'builtin\administrators', 'owner rights')
            if ($dir -eq $script:StateDir) { $allowedHere += $account.ToLowerInvariant() }
            foreach ($entry in $dirEntries) {
                $p = $entry.Principal.ToLowerInvariant()
                Assert-True ($allowedHere -contains $p) "$dir grants only $($allowedHere -join ', ') (found $p)"
                if ($p -eq 'owner rights') { Assert-True (-not (Test-GrantsWrite $entry)) "${dir}: OWNER RIGHTS holds read-control only ($($entry.Tokens -join ','))" }
            }
        }
        $stateAccount = @(Get-IcaclsEntries $script:StateDir | Where-Object { $_.Principal -ieq $account })
        Assert-True ($stateAccount.Count -ge 1 -and (Test-GrantsWrite $stateAccount[0])) 'the account may modify its state directory'
    }

    if ($null -ne $script:ExpectFipsBool) {
        Invoke-Case 'msi.installed_fips_posture' {
            # A FIPS product's MSI lays the AWS-LC-FIPS module's DLL beside its cores
            # (the product's Windows sidecars); a non-FIPS one ships none.
            $dlls = @(Get-ChildItem -LiteralPath $script:ProgramDir -Filter 'aws_lc_fips_*.dll' -File)
            foreach ($dll in $dlls) {
                Write-Log "installed FIPS DLL: $($dll.Name) ($($dll.Length) bytes)"
                foreach ($entry in @(Get-IcaclsEntries $dll.FullName)) {
                    if (-not (Test-TrustedPrincipal $entry.Principal '')) {
                        Assert-True (-not (Test-GrantsWrite $entry)) "$($dll.Name) grants no write to $($entry.Principal)"
                    }
                }
            }
            if ($script:ExpectFipsBool) {
                Assert-True (@($dlls | Where-Object { $_.Name -like '*_crypto.dll' }).Count -eq 1) 'the module DLL is installed beside the cores'
            } else {
                Assert-True ($dlls.Count -eq 0) 'a non-FIPS MSI ships no module DLL'
            }
            $want = "fips=$("$($script:ExpectFipsBool)".ToLowerInvariant())"
            $f = Invoke-Native -Exe $script:ProgramPath -Arguments @('fips')
            Assert-True ($f.ExitCode -eq 0 -and $f.StdOut.Trim() -eq $want) "the installed launcher's core reports $want (got exit $($f.ExitCode) '$($f.StdOut.Trim())' $($f.StdErr.Trim()))"
        }
    }

    Invoke-Case 'start.running' {
        $r = Invoke-Fixture @('start', '--name', $ServiceName, '--timeout-secs', '90') -TimeoutSec 150
        Assert-True ($r.ExitCode -eq 0) 'the backend start() reports Running'
        $state = Get-ScState
        Assert-True ($state.State -eq 'RUNNING' -and $state.Pid -ne 0) "the SCM reports RUNNING (got $(Format-ScState $state))"
        $starts = @(Get-Starts)
        Assert-True ($starts.Count -eq 1 -and $starts[0].version -eq '1.0.0' -and [int]$starts[0].pid -eq $state.Pid) 'one start, version 1.0.0, the SCM-reported PID'
        if ($null -ne $script:ExpectFipsBool) {
            Assert-True ($starts[0].fips -eq "$($script:ExpectFipsBool)") "the running service's FIPS posture is $($script:ExpectFipsBool) (got $($starts[0].fips))"
        }
        Wait-Until -TimeoutSec 30 -What 'the first heartbeat (the service body is running)' -Condition {
            Test-Path -LiteralPath (Join-Path $script:StateDir 'status.txt') } | Out-Null
    }

    Invoke-Case 'account.runs_as_virtual_account_sid' {
        $expected = Get-VirtualAccountSid $ServiceName
        Write-Log "NT SERVICE\$ServiceName = $expected"
        Assert-True ($expected -like 'S-1-5-80-*') 'virtual account SIDs live under S-1-5-80'
        $state = Get-ScState
        $owner = Get-ProcessOwnerSid $state.Pid
        Write-Log "process $($state.Pid) owner SID = $owner"
        Assert-True ($owner -eq $expected) 'the service process token is the virtual account (outside view)'
        $self = @(Get-Starts)[-1]
        Write-Log "self-report: user=$($self.user) sid=$($self.sid)"
        Assert-True ($self.sid -eq $expected) 'the service reports the same SID from inside (whoami /user)'
    }

    Invoke-Case 'failure.fatal_exit_is_restarted' {
        # The fixture's fatal outcome: RunError::Fatal -> Stopped + service-specific 1.
        $w = Watch-Restart -Trigger { Send-Control 'fatal' } -TimeoutSec ($RestartDelayMs / 1000 + 90)
        Assert-True ($w.Stopped.Win32Exit -eq 1066 -and $w.Stopped.SpecificExit -eq 1) "Stopped with ERROR_SERVICE_SPECIFIC_ERROR / 1 (got $(Format-ScState $w.Stopped))"
        Assert-True ($w.Elapsed -ge ($RestartDelayMs / 1000 - 1)) 'the restart honored the failure-action delay'
        $exit = @(Get-ExitsOf $w.OldPid -Since $w.SinceMs)
        Assert-True ($exit.Count -eq 1 -and $exit[0].code -eq '1' -and $exit[0].reason -match '^fatal service error: Injected\("fatal"\)') "the old process saw its fatal outcome (exit code 1; got $(@($exit | ForEach-Object { "code=$($_.code) reason=$($_.reason)" }) -join ' | '))"
    }

    Invoke-Case 'failure.panic_is_restarted' {
        $w = Watch-Restart -Trigger { Send-Control 'panic' } -TimeoutSec ($RestartDelayMs / 1000 + 90)
        Assert-True ($w.Stopped.Win32Exit -eq 1066 -and $w.Stopped.SpecificExit -eq 1) "Stopped with ERROR_SERVICE_SPECIFIC_ERROR / 1 (got $(Format-ScState $w.Stopped))"
        $exit = @(Get-ExitsOf $w.OldPid -Since $w.SinceMs)
        Assert-True ($exit.Count -eq 1 -and $exit[0].reason -match 'panicked') 'the old process saw the task panic'
    }

    Invoke-Case 'failure.crash_is_restarted' {
        # A real crash (abort): no Stopped report at all -- the SCM's crash recovery.
        $w = Watch-Restart -Trigger { Send-Control 'abort' } -TimeoutSec ($RestartDelayMs / 1000 + 90)
        Assert-True ($w.Stopped.Win32Exit -ne 0 -and $w.Stopped.Win32Exit -ne 1066) "a crash reads as an unexpected termination, not a service-specific stop (got $(Format-ScState $w.Stopped))"
    }

    Invoke-Case 'gate.running_mismatch_requests_update_and_keeps_running' {
        # A version rejection inside a running task never stops the service. The
        # fixture hands it to seaworthy-updater's request, which (policy `auto`: the
        # machine has no policy key) starts `<name>-update`. No helper is installed
        # here, so the request fails and says so; the service keeps running on the
        # build it has and its tasks keep ticking.
        $before = Get-ScState
        Assert-True ($before.State -eq 'RUNNING') "running before the demand (got $(Format-ScState $before))"
        $startsBefore = @(Get-Starts).Count
        $log = Join-Path (Join-Path $script:StateDir 'logs') "service-$($before.Pid).log"
        $demanded = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Set-Required '9.9.9'
        Wait-Until -TimeoutSec 60 -What 'the service to log the failed update request' -Condition {
            @(Get-RequestFailures $log -Since $demanded).Count -ge 1 } | Out-Null
        # Ten poll periods (poll_ms=1000) after the request: the same process, still
        # RUNNING, the gate task still asking, and one request per the requester's
        # interval (60 s).
        $since = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Start-Sleep -Seconds 10
        $s = Get-ScState
        Assert-True ($s.State -eq 'RUNNING' -and $s.Pid -eq $before.Pid) "the same process is still RUNNING (got $(Format-ScState $s))"
        Assert-True (@(Get-Starts).Count -eq $startsBefore) 'no new start'
        Assert-True (@(Get-ExitsOf $before.Pid -Since $demanded).Count -eq 0) 'the process never exited'
        $polls = @(Get-StubRequests '/required' -Since $since)
        Assert-True ($polls.Count -ge 5) "the gate task kept ticking after the request ($($polls.Count) gate polls in 10 s)"
        $requests = @(Get-RequestFailures $log -Since $demanded)
        foreach ($line in $requests) { Write-Log "  service| $line" }
        Assert-True ($requests.Count -eq 1) "one update request per interval (got $($requests.Count))"
        Set-Required ''
    }

    Invoke-Case 'gate.connect_mismatch_waits_running_and_stops_cleanly' {
        # The same rejection at connect (init): the fixture asks for the update, waits
        # (mismatch_retry: 5 s here) and connects again. The service reports RUNNING
        # before init, so a service waiting on the server stays stoppable: an
        # MSI upgrade stops it, and STOP must be a clean exit, never a 1061 refusal.
        $stop = Invoke-Fixture @('stop', '--name', $ServiceName)
        Assert-True ($stop.ExitCode -eq 0) 'backend stop()'
        $s = Get-ScState
        Assert-True ($s.State -eq 'STOPPED' -and $s.Win32Exit -eq 0) "a clean stop reports exit 0 (got $(Format-ScState $s))"
        Set-Required '9.9.9'
        $startsBefore = @(Get-Starts).Count
        $started = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $r = Invoke-Fixture @('start', '--name', $ServiceName, '--timeout-secs', '60') -TimeoutSec 120
        Assert-True ($r.ExitCode -eq 0) 'backend start() reaches RUNNING although the connect is refused'
        $s = Get-ScState
        Assert-True ($s.State -eq 'RUNNING' -and $s.Pid -ne 0) "RUNNING while init retries (got $(Format-ScState $s))"
        $newPid = $s.Pid
        $since = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $log = Join-Path (Join-Path $script:StateDir 'logs') "service-$newPid.log"
        Wait-Until -TimeoutSec 60 -What 'the starting process to log the failed update request' -Condition {
            @(Get-RequestFailures $log -Since $started).Count -ge 1 } | Out-Null
        Start-Sleep -Seconds 12
        $s = Get-ScState
        Assert-True ($s.State -eq 'RUNNING' -and $s.Pid -eq $newPid) "the same process waits, RUNNING (got $(Format-ScState $s))"
        Assert-True (@(Get-Starts).Count -eq $startsBefore + 1) 'one start'
        $connects = @(Get-StubRequests '/required' -Since $since)
        Assert-True ($connects.Count -ge 2) "the connect is retried every mismatch_retry ($($connects.Count) gate requests in 12 s)"
        $requests = @(Get-RequestFailures $log -Since $started)
        Assert-True ($requests.Count -eq 1) "one update request per interval (got $($requests.Count))"
        Assert-True (-not (Test-HeartbeatOf $newPid -Since $started)) 'no task has run: the body waits for the connect'
        # The stop an MSI upgrade sends lands mid-init: a clean exit.
        $stop = Invoke-Fixture @('stop', '--name', $ServiceName)
        Assert-True ($stop.ExitCode -eq 0) 'backend stop() during the connect wait'
        $s = Get-ScState
        Assert-True ($s.State -eq 'STOPPED' -and $s.Win32Exit -eq 0) "stopped cleanly mid-init, exit 0 (got $(Format-ScState $s))"
        # The process writes its exit record after the dispatcher returns, so the
        # record can trail the SCM's STOPPED.
        Wait-Until -TimeoutSec 30 -What 'the waiting process''s exit record' -Condition {
            @(Get-ExitsOf $newPid -Since $started).Count -ge 1 } | Out-Null
        $exit = @(Get-ExitsOf $newPid -Since $started)
        Assert-True ($exit.Count -eq 1 -and $exit[0].code -eq '0' -and $exit[0].reason -eq 'Stopped') 'the waiting process exited 0 (ServiceExit::Stopped)'
        # Back to normal for the cases after this one.
        Set-Required ''
        $restarted = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $r = Invoke-Fixture @('start', '--name', $ServiceName, '--timeout-secs', '60') -TimeoutSec 120
        Assert-True ($r.ExitCode -eq 0) 'backend start() with no demand'
        $s = Get-ScState
        Wait-Until -TimeoutSec 30 -What 'the restarted service to run its tasks' -Condition {
            Test-HeartbeatOf $s.Pid -Since $restarted } | Out-Null
    }

    Invoke-Case 'stop.clean_stop_is_not_restarted' {
        $startsBefore = @(Get-Starts).Count
        $exitsBefore = @(Get-Exits).Count
        $r = Invoke-Fixture @('stop', '--name', $ServiceName)
        Assert-True ($r.ExitCode -eq 0) 'backend stop()'
        $s = Get-ScState
        Assert-True ($s.State -eq 'STOPPED' -and $s.Win32Exit -eq 0) "clean Stopped(0) (got $(Format-ScState $s))"
        # The exit record can trail the SCM's STOPPED (written after the dispatcher returns).
        Wait-Until -TimeoutSec 30 -What 'the stopped process''s exit record' -Condition {
            @(Get-Exits).Count -gt $exitsBefore } | Out-Null
        $last = @(Get-Exits)[-1]
        Assert-True ($last.code -eq '0' -and $last.reason -eq 'Stopped') 'the process exited 0 (ServiceExit::Stopped)'
        Start-Sleep -Milliseconds ($RestartDelayMs + 5000)
        $s = Get-ScState
        Assert-True ($s.State -eq 'STOPPED' -and @(Get-Starts).Count -eq $startsBefore) "no recovery action after a clean stop (got $(Format-ScState $s))"
    }

    Invoke-Case 'shutdown.os_shutdown_control' -VmOnly ('SERVICE_CONTROL_SHUTDOWN (and the AUTO_START at the next boot) needs an OS ' +
        'shutdown and restart, which a CI job cannot survive; the physical/VM check before a release covers a real shutdown and boot') { }

    Invoke-Case 'msi.uninstall' {
        if ($KeepInstalled) { Skip-Case '-KeepInstalled was given' }
        $entries = @(Get-ProductEntries)
        Assert-True ($entries.Count -eq 1) "the product is installed once (found $($entries.Count))"
        $code = Invoke-Msiexec @('/x', $entries[0].Code)
        Assert-True ($code -eq 0) "msiexec /x exited $code (log $($script:MsiLog))"
        Wait-Until -TimeoutSec 60 -What 'the SCM to reap the service' -Condition { $null -eq (Get-ScState) } | Out-Null
        $running = @(Get-CimInstance Win32_Process -Filter "Name='scm.exe'")
        Assert-True ($running.Count -eq 0) 'no service process remains'
        Assert-True (-not (Test-Path -LiteralPath $script:ProgramDir)) "the MSI removed $($script:ProgramDir)"
        Assert-True (@(Get-ProductEntries).Count -eq 0) 'no Programs and Features entry remains'
        # The state directory stays when it holds files (the MSI's documented removal);
        # the diagnostics copy it, the next run's preconditions remove it.
        Write-Log "state directory after removal: exists=$(Test-Path -LiteralPath $script:StateDir)"
    }

    Invoke-Case 'rust.windows_scm_integration_tests' -Independent {
        # crates/seaworthy-service/tests/windows_scm.rs: typed ServiceError answers against
        # the real SCM (double-gated: #[ignore] + SEAWORTHY_WINDOWS_SCM_E2E=1).
        if ($RustScmTestExe) {
            Assert-True (Test-Path -LiteralPath $RustScmTestExe -PathType Leaf) "-RustScmTestExe $RustScmTestExe does not exist"
            $r = Invoke-Native -Exe $RustScmTestExe -Arguments @('--ignored', '--test-threads', '1') -Environment @{ SEAWORTHY_WINDOWS_SCM_E2E = '1' } -TimeoutSec 900
            Write-NativeOutput $r 'rust'
            Assert-True ($r.ExitCode -eq 0) "the Rust SCM integration tests passed (exit $($r.ExitCode))"
        } else {
            $r = Invoke-Nextest -Filter 'binary(windows_scm)' -RunIgnored 'only' -JUnitName 'nextest-windows-scm.xml' -TimeoutSec 900
            Assert-True ($r.ExitCode -eq 0) "the Rust SCM integration tests passed (exit $($r.ExitCode))"
            $summary = [regex]::Match(($r.StdOut + $r.StdErr), '(\d+) tests? run: (\d+) passed')
            Assert-True ($summary.Success -and [int]$summary.Groups[1].Value -ge 1 -and $summary.Groups[1].Value -eq $summary.Groups[2].Value) 'the SCM integration tests actually ran, and all passed'
        }
    }

    Invoke-Case 'rust.nextest_suite_native_windows' -Independent {
        # Every non-ignored test in the archive (the crates it carries), natively on
        # Windows -- the lane Wine approximates. Tests that write real HKLM keys (the
        # update policy against the live registry) opt in through
        # SEAWORTHY_WINDOWS_LIVE_REGISTRY and run only here: an administrator on a
        # disposable machine.
        $env:SEAWORTHY_WINDOWS_LIVE_REGISTRY = '1'
        try {
            $r = Invoke-Nextest -Filter 'all()' -RunIgnored 'default' -JUnitName 'nextest-windows.xml' -TimeoutSec 2400
        } finally {
            Remove-Item Env:\SEAWORTHY_WINDOWS_LIVE_REGISTRY -ErrorAction SilentlyContinue
        }
        Assert-True ($r.ExitCode -eq 0) "the archive's suite passed natively on Windows (exit $($r.ExitCode))"
    }
}

# ===========================================================================
# The entropy cases (Phase All and Entropy)
# ===========================================================================

function Invoke-EntropySuite {
    Invoke-Case 'entropy.first_draw_never_aborts' -Independent {
        # AWS-LC seeds on the first RAND_bytes of a process; with CPU-jitter entropy
        # linked in, a failed startup health test ABORTS the process.
        # Fresh processes under load ($EntropyProbeParallel at once) are the only way to
        # see the rate. Windows builds keep jitter (FIPS builds cannot opt out; the
        # non-FIPS opt-out is commented out in .cargo/config.toml): 0 aborts expected on
        # bare metal; inside small virtual machines the rate can be non-zero, and this
        # case then turns red. A Hyper-V guest (a GitHub-hosted runner) runs it as
        # -Phase Entropy, informational: the rate there is the hypervisor's
        # (docs/testing-windows.md).
        if (-not ($EntropyProbeExe -and (Test-Path -LiteralPath $EntropyProbeExe -PathType Leaf))) {
            Skip-Case "no entropy probe ($EntropyProbeExe)"
        }
        Write-ResourceSnapshot 'before the entropy probe'
        $r = Invoke-EntropyProbe
        $aborted = 0
        foreach ($code in $r.Codes.Keys) {
            Write-Log ("  exit {0} ({1}): {2} process(es)" -f $code, (Format-ExitCode $code), $r.Codes[$code])
            if ($code -ne 0) { $aborted += $r.Codes[$code] }
        }
        foreach ($out in $r.Outputs.Keys) { Write-Log "  output '$out': $($r.Outputs[$out])" }
        Write-Log ("{0} probes, {1} at a time, in {2:F1}s: {3} aborted" -f $EntropyProbeCount, $EntropyProbeParallel, $r.Seconds, $aborted)
        if ($null -ne $script:ExpectFipsBool) {
            $want = "entropy_probe ok fips=$("$($script:ExpectFipsBool)".ToLowerInvariant())"
            foreach ($out in $r.Outputs.Keys) { Assert-True ($out -eq $want) "every probe reports '$want' (got '$out')" }
        }
        Assert-True ($aborted -eq 0) ("{0} of {1} fresh processes died on their first random draw ({2})" -f $aborted, $EntropyProbeCount,
            (($r.Codes.Keys | Where-Object { $_ -ne 0 } | ForEach-Object { Format-ExitCode $_ }) -join ', '))
    }

    Invoke-Case 'entropy.jitter_diagnostics' -Independent {
        # DATA, not a gate (entropy_diag.exe, optional): the jitter self-test and root-seed
        # reads, replayed without the module's abort. Warm = many trials per process
        # under $EntropyDiagParallel concurrent processes; cold = fresh one-trial
        # processes (a real first draw). The FIPS DLL backend runs the certified
        # module's own jitter code. Fails only if the diagnostic itself cannot run.
        if (-not ($EntropyDiagExe -and (Test-Path -LiteralPath $EntropyDiagExe -PathType Leaf))) {
            Skip-Case "no entropy diagnostic ($EntropyDiagExe)"
        }
        $runs = @(Invoke-JitterDiagnostics)
        foreach ($run in $runs) {
            Assert-True ($run.Crashed -lt $run.Processes) "$($run.Label): every diagnostic process failed (see above)"
        }
    }
}

# ===========================================================================
# Phase: SelfTest (pure logic; any PowerShell, Linux pwsh included)
# ===========================================================================

function Invoke-SelfTest {
    Invoke-Case 'selftest.sc_queryex_parser' {
        $text = "SERVICE_NAME: acme-e2e`r`n        TYPE               : 10  WIN32_OWN_PROCESS`r`n        STATE              : 1  STOPPED`r`n" +
        "        WIN32_EXIT_CODE    : 1066  (0x42a)`r`n        SERVICE_EXIT_CODE  : 7  (0x7)`r`n        CHECKPOINT         : 0x0`r`n" +
        "        WAIT_HINT          : 0x0`r`n        PID                : 0`r`n        FLAGS              :`r`n"
        $s = ConvertFrom-ScQueryEx $text
        Assert-True ($s.State -eq 'STOPPED' -and $s.Win32Exit -eq 1066 -and $s.SpecificExit -eq 7 -and $s.Pid -eq 0) "parsed $(Format-ScState $s)"
        $s = ConvertFrom-ScQueryEx "        STATE              : 4  RUNNING `r`n        PID                : 4242`r`n"
        Assert-True ($s.State -eq 'RUNNING' -and $s.Pid -eq 4242) 'running + pid'
        $s = ConvertFrom-ScQueryEx "        STATE              : 2  START_PENDING `r`n"
        Assert-True ($s.State -eq 'START_PENDING') 'START_PENDING keeps the underscore'
    }
    Invoke-Case 'selftest.icacls_parser' {
        $path = 'C:\Program Files\AcmeE2E\acme-e2e'
        $text = "$path NT AUTHORITY\SYSTEM:(OI)(CI)(F)`r`n" +
        '                                    BUILTIN\Administrators:(OI)(CI)(F)' + "`r`n" +
        '                                    NT SERVICE\acme-e2e:(OI)(CI)(M)' + "`r`n" +
        '                                    BUILTIN\Users:(I)(OI)(CI)(RX)' + "`r`n" +
        '                                    Everyone:(DENY)(WDAC)' + "`r`n" +
        '                                    NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)' + "`r`n" +
        '                                    BUILTIN\Users:(Rc,S,AD,X)' + "`r`n`r`n" +
        "Successfully processed 1 files; Failed processing 0 files`r`n"
        $entries = @(ConvertFrom-Icacls -Text $text -Path $path)
        Assert-True ($entries.Count -eq 7) "7 entries (got $($entries.Count))"
        Assert-True ($entries[0].Principal -eq 'NT AUTHORITY\SYSTEM' -and ($entries[0].Tokens -join ',') -eq 'OI,CI,F') 'first line, path prefix stripped'
        Assert-True ((Test-GrantsWrite $entries[2]) -and -not (Test-GrantsWrite $entries[3])) 'M writes, RX does not'
        Assert-True (-not (Test-GrantsWrite $entries[4])) 'a DENY entry grants nothing'
        Assert-True ((Test-GrantsWrite $entries[5]) -and ($entries[5].Tokens -contains 'I')) 'inherited Modify is a write grant and is marked inherited'
        Assert-True (Test-GrantsWrite $entries[6]) 'a specific-rights list with AD (add subdirectory) is a write grant'
        Assert-True ((Test-TrustedPrincipal 'NT SERVICE\acme-e2e' 'NT SERVICE\acme-e2e') -and -not (Test-TrustedPrincipal 'BUILTIN\Users' 'NT SERVICE\x')) 'trusted set'
        $entries = @(ConvertFrom-Icacls -Text "C:\ BUILTIN\Administrators:(OI)(CI)(F)`r`n    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)`r`n" -Path 'C:\')
        $grant = @($entries | Where-Object { $_.Principal -match 'Authenticated Users' -and $_.Tokens -contains 'IO' -and $_.Tokens -contains 'M' })
        Assert-True ($grant.Count -eq 1) 'the C:\ inherit-only grant is detected'
    }
    Invoke-Case 'selftest.argument_quoting' {
        $cases = @(
            @(@('a', 'b c', ''), 'a "b c" ""'),
            @(@('C:\Program Files\x\'), '"C:\Program Files\x\\"'),
            @(@('say "hi"'), '"say \"hi\""'),
            @(@('*S-1-5-32-545:(OI)(CI)(M)'), '*S-1-5-32-545:(OI)(CI)(M)')
        )
        foreach ($c in $cases) {
            $got = ConvertTo-ArgString $c[0]
            Assert-True ($got -eq $c[1]) "quote $($c[0] -join '|') -> [$got] expected [$($c[1])]"
        }
    }
    Invoke-Case 'selftest.fixture_log_parser' {
        $rows = @(ConvertFrom-FixtureLog @("start`tpid=12`tversion=2.0.0`tuser=nt service\acme-e2e`tsid=S-1-5-80-1`texe=C:\a b\c.exe`tunix_ms=5"))
        Assert-True ($rows.Count -eq 1 -and $rows[0].pid -eq '12' -and $rows[0].version -eq '2.0.0' -and $rows[0].exe -eq 'C:\a b\c.exe') 'fields'
        $rows = @(ConvertFrom-FixtureLog @("exit`tpid=12`tcode=1`treason=fatal service error: a=b"))
        Assert-True ($rows[0].reason -eq 'fatal service error: a=b') 'the first = splits'
    }
    Invoke-Case 'selftest.a_reused_process_id_finds_only_the_later_process' {
        $script:StateDir = $script:DataRoot
        $write = { param($Name, $Text) [System.IO.File]::WriteAllText((Join-Path $script:StateDir $Name), $Text, $script:Utf8NoBom) }
        & $write 'exits.log' ("exit`tpid=968`tcode=abort`treason=injected abort`tunix_ms=1000`n" +
            "exit`tpid=5268`tcode=0`treason=Stopped`tunix_ms=1500`n" +
            "exit`tpid=968`tcode=0`treason=Stopped`tunix_ms=2000`n")
        Assert-True (@(Get-ExitsOf 968 -Since 0).Count -eq 2) 'both processes that had the id'
        $exit = @(Get-ExitsOf 968 -Since 1800)
        Assert-True ($exit.Count -eq 1 -and $exit[0].code -eq '0') 'only the later one from its start on'
        Assert-True (@(Get-ExitsOf 96 -Since 0).Count -eq 0) 'the whole id, not a prefix'
        & $write 'status.txt' "pid=968`tversion=1.0.0`theartbeat_unix_ms=1000`n"
        Assert-True (Test-HeartbeatOf 968 -Since 500) 'a heartbeat from the process'
        Assert-True (-not (Test-HeartbeatOf 968 -Since 1800)) 'an earlier process''s heartbeat is not this one''s'
        Assert-True (-not (Test-HeartbeatOf 96 -Since 0)) 'the whole id in the status, not a prefix'
        $failure = "the server requires $ServiceName 9.9.9, but asking the update helper failed: requesting an update failed: opening service $ServiceName-update to start it: no such service"
        & $write 'service-968.log' ("1000 ERROR seaworthy_updater::request: $failure`n2000 INFO scm_core: starting`n" +
            "3000 ERROR seaworthy_updater::request: $failure`n")
        $log = Join-Path $script:StateDir 'service-968.log'
        Assert-True (@(Get-RequestFailures $log -Since 0).Count -eq 2) 'both requests in the shared log'
        Assert-True (@(Get-RequestFailures $log -Since 1800).Count -eq 1) 'only the later process''s request'
        Assert-True (@(Get-RequestFailures (Join-Path $script:StateDir 'no-such.log') -Since 0).Count -eq 0) 'no log yet'
    }
    Invoke-Case 'selftest.a_restart_can_take_an_earlier_process_id' {
        # The restarted process has the id of the one that failed, and an older start
        # record has it too: the SCM's states, scripted.
        $script:StateDir = $script:DataRoot
        $starts = Join-Path $script:StateDir 'starts.log'
        $record = "start`tpid=968`tversion=1.0.0`tunix_ms=1`n"
        [System.IO.File]::WriteAllText($starts, $record + $record, $script:Utf8NoBom)
        $script:ScPolls = 0
        function Get-ScmEvents { }
        function Get-ScState {
            $script:ScPolls++
            if ($script:ScPolls -eq 2) { return [pscustomobject]@{ State = 'STOPPED'; Win32Exit = 1067; SpecificExit = 0; Pid = 0 } }
            if ($script:ScPolls -eq 3) { [System.IO.File]::AppendAllText($starts, $record, $script:Utf8NoBom) }
            return [pscustomobject]@{ State = 'RUNNING'; Win32Exit = 0; SpecificExit = 0; Pid = 968 }
        }
        $w = Watch-Restart -Trigger { } -TimeoutSec 5
        Assert-True ($w.OldPid -eq 968 -and $w.After.Pid -eq 968 -and $w.Stopped.Win32Exit -eq 1067) 'the restart is seen'
    }
    Invoke-Case 'selftest.junit_writer' {
        $cases = @(
            [pscustomobject]@{ Name = 'a<b'; Status = 'passed'; Message = ''; Time = 0.5; Output = "line1`nctl:$([char]7)" },
            [pscustomobject]@{ Name = 'c'; Status = 'failed'; Message = 'boom & "x"'; Time = 1; Output = '' },
            [pscustomobject]@{ Name = 'd'; Status = 'skipped'; Message = 'EXPECTED VM-ONLY: y'; Time = 0; Output = '' }
        )
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "seaworthy-junit-selftest-$PID.xml"
        Write-JUnit -Path $path -Suite 'selftest' -Cases $cases
        [xml]$xml = Get-Content -LiteralPath $path -Raw
        $suite = $xml.testsuites.testsuite
        Assert-True ($suite.tests -eq '3' -and $suite.failures -eq '1' -and $suite.skipped -eq '1') 'counts'
        Assert-True ($suite.testcase[0].name -eq 'a<b') 'escaped names round-trip'
        Assert-True ($suite.testcase[1].failure.message -eq 'boom & "x"') 'failure message'
        Assert-True ($suite.testcase[2].skipped.message -like 'EXPECTED VM-ONLY*') 'skipped label'
        Remove-Item -LiteralPath $path -Force
    }
    Invoke-Case 'selftest.entropy_probe_tally' {
        if (-not ($EntropyProbeExe -and (Test-Path -LiteralPath $EntropyProbeExe -PathType Leaf))) { Skip-Case 'no -EntropyProbeExe given' }
        $r = Invoke-EntropyProbe -Count 24
        Assert-True ($r.Codes.Count -eq 1 -and $r.Codes[0] -eq 24) "24 probes, all exit 0 (got $(($r.Codes.Keys | ForEach-Object { "$_=$($r.Codes[$_])" }) -join ' '))"
        Assert-True ($r.Outputs.Count -eq 1 -and @($r.Outputs.Keys)[0] -match '^entropy_probe ok fips=(true|false)$') 'each probe printed its one status line'
        Assert-True ((Format-ExitCode -1073740791) -eq '0xC0000409') 'NTSTATUS exit codes format as unsigned hex'
    }

    Invoke-Case 'selftest.entropy_diag_summary' {
        if (-not ($EntropyDiagExe -and (Test-Path -LiteralPath $EntropyDiagExe -PathType Leaf))) { Skip-Case 'no -EntropyDiagExe given' }
        $results = Invoke-ParallelNative -Exe $EntropyDiagExe -Arguments @('--trials', '3', '--label', 'selftest') -Count 3 -Parallel 2
        Assert-True ($results.Count -eq 3) "three diagnostic runs (got $($results.Count))"
        $bad = Invoke-ParallelNative -Exe $EntropyDiagExe -Arguments @('--bogus') -Count 1 -Parallel 1
        $summary = Measure-EntropyDiag -Label 'selftest' -Results ($results + $bad)
        Assert-True ($summary.Processes -eq 4 -and $summary.Crashed -eq 1) "the summary counts 4 processes, 1 failed (got $($summary.Processes)/$($summary.Crashed))"
        $lines = @(Read-Lines (Join-Path $DiagnosticsDir 'entropy-diag.jsonl') | Where-Object { $_ -match '"run":"selftest"' })
        Assert-True ($lines.Count -ge 3) 'each run''s JSON line lands in diagnostics\entropy-diag.jsonl, tagged with its run label'
        Assert-True ((@($lines)[0] | ConvertFrom-Json).trials -eq 3) 'the tagged lines stay valid JSON'
    }

    Invoke-Case 'selftest.jitter_diagnostics_backends' {
        if (-not ($EntropyDiagExe -and (Test-Path -LiteralPath $EntropyDiagExe -PathType Leaf))) { Skip-Case 'no -EntropyDiagExe given' }
        $runs = @(Invoke-JitterDiagnostics -Trials 2 -Parallel 2 -Cold 3)
        $labels = @($runs | ForEach-Object { $_.Label })
        Assert-True ($runs.Count -eq 2) "one warm + one cold run for the vendored backend (got: $($labels -join ' | '))"
        Assert-True ($labels[0] -like 'vendored-warm*' -and $labels[1] -eq 'vendored-cold') "labels name the backend (got: $($labels -join ' | '))"
        foreach ($run in $runs) { Assert-True ($run.Crashed -eq 0) "$($run.Label): no diagnostic process failed" }
    }

    Invoke-Case 'selftest.stub_round_trip' {
        if (-not $FixtureExe) { Skip-Case 'no -FixtureExe given' }
        New-Item -ItemType Directory -Force -Path (Join-Path $script:StubRoot 'static') | Out-Null
        Write-TextNoBom -Path (Join-Path $script:StubRoot 'static/hello.txt') -Text 'hello'
        try {
            $addr = Start-Stub
            Assert-True ((Get-Http "http://$addr/required").Status -eq 404) '/required absent -> 404'
            Set-Required '2.0.0'
            $r = Get-Http "http://$addr/required"
            Assert-True ($r.Status -eq 200 -and $r.Body -eq '2.0.0') "/required -> 2.0.0 (got $($r.Status) '$($r.Body)')"
            Assert-True ((Get-Http "http://$addr/static/hello.txt").Body -eq 'hello') 'static file'
            Assert-True ((Get-Http "http://$addr/static/../../etc/passwd").Status -eq 404) 'traversal refused'
            $logged = @(Get-StubRequests '/required')
            Assert-True ($logged.Count -eq 2 -and $logged[0].Status -eq 404 -and $logged[1].Status -eq 200) 'the request log records both'
        } finally {
            if ($script:StubProcess) { Stop-Process -Id $script:StubProcess.Id -Force -ErrorAction SilentlyContinue; $script:StubProcess = $null }
        }
    }
}

# ===========================================================================
# Main
# ===========================================================================

New-Item -ItemType Directory -Force -Path $JUnitDir | Out-Null
$suite = "windows-scm-e2e"
try {
    switch ($Phase) {
        'All' { Invoke-MainSuite; Invoke-EntropySuite }
        'Service' { Invoke-MainSuite }
        'Entropy' {
            $suite = 'windows-scm-entropy'
            Invoke-EntropySuite
        }
        'SelfTest' {
            $suite = 'windows-scm-e2e-selftest'
            $script:DataRoot = Join-Path ([System.IO.Path]::GetTempPath()) "seaworthy-e2e-selftest-$PID"
            $script:WorkDir = $script:DataRoot
            $script:StubRoot = Join-Path $script:DataRoot 'stub'
            $script:StubLog = Join-Path $script:DataRoot 'stub.log'
            New-Item -ItemType Directory -Force -Path $script:DataRoot | Out-Null
            Invoke-SelfTest
            Remove-Item -LiteralPath $script:DataRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
} finally {
    if ($script:StubProcess) {
        Stop-Process -Id $script:StubProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($Phase -eq 'All' -or $Phase -eq 'Service') {
        try { Save-Artifacts } catch { Write-Host "saving diagnostics failed: $_" }
        if (-not $KeepInstalled -and $script:IsWin) {
            try { Remove-ProductQuietly } catch { Write-Host "cleanup of $ProductName failed: $_" }
        }
    }
    $junit = Join-Path $JUnitDir "$suite.xml"
    Write-JUnit -Path $junit -Suite $suite -Cases $script:Cases
    $failed = @($script:Cases | Where-Object { $_.Status -eq 'failed' }).Count
    $skipped = @($script:Cases | Where-Object { $_.Status -eq 'skipped' }).Count
    Write-Host ''
    Write-Host ("{0}: {1} cases, {2} failed, {3} skipped -- JUnit: {4}" -f $suite, $script:Cases.Count, $failed, $skipped, $junit)
}
if (@($script:Cases | Where-Object { $_.Status -eq 'failed' }).Count -gt 0) { exit 1 }
exit 0
