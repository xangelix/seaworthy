<#
.SYNOPSIS
    The Windows upgrade-from-previous lane's previous build: scripts/upgrade-previous.sh
    ported to PowerShell. The artifact <Name> (a build scripts/windows-lab-build.ps1 wrote
    as <Out>\upgrade-candidate) of the latest successful run of the Windows lab workflow on
    `main` before this run, fetched through the GitHub API with the job's own token
    (`actions: read`), checked and unpacked into <Out>.

.DESCRIPTION
    The rules are scripts/upgrade-previous.sh's, unchanged:

      the run       a successful run of -Workflow (default lab-windows.yml) on -Branch
                    (default main), from a push, the schedule or a manual dispatch (never
                    a pull request's: its code isn't main's), whose head is this
                    repository's, with a lower run number than this run (an older release
                    than this run's candidate), the highest such;
      the artifact  that run's one artifact of that name, not expired, its zip no larger
                    than 1 GiB and matching the SHA-256 digest GitHub recorded at upload;
                    then every file lab-build.json lists matches its SHA-256, and the
                    build's CI test key is the one this checkout's fixture trusts
                    (-TrustKey; else this candidate isn't one its helper would install).

    Exit 0 with <Out> filled (<Out>\previous-run.json names the run); 3 when there is
    nothing to update from (no such run yet: the lane's first run on main, or one whose
    artifact is gone or predates this lane; or a build that trusts another key), and the
    lane skips with a notice while this run becomes the next one's previous build; 1 on
    any other error, which fails the lane: a broken download or a digest mismatch never
    skips; 2 for a usage error.

    Environment: GITHUB_TOKEN (the job's token: never printed, never on a command line;
    Windows' own curl.exe reads it from a header file in a directory only this account
    can open, and sends it to the API host only, never across a redirect to the artifact
    storage), GITHUB_REPOSITORY, GITHUB_RUN_NUMBER, GITHUB_API_URL (default
    https://api.github.com). Every request: https only (redirects too), TLS 1.2 or newer,
    bounded in time and size. The zip is unpacked entry by entry into a new, empty <Out>:
    an entry that would land outside it, or names a stream, is refused.

    Windows PowerShell 5.1 or PowerShell 7.

.PARAMETER Phase
    Fetch      the fetch (default; Windows only: System32\curl.exe).
    SelfTest   the selection rules, the artifact checks, the zip and lab-build.json checks
               and the exit codes, on canned data, with no network: any PowerShell (Linux
               pwsh included).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-upgrade-previous.ps1 `
        -Name lab-upgrade-windows -Out $env:RUNNER_TEMP\lab-upgrade\previous
#>
[CmdletBinding()]
param(
    [string]$Name,
    [string]$Out,
    [string]$Workflow = $(if ($env:SEAWORTHY_UPGRADE_WORKFLOW) { $env:SEAWORTHY_UPGRADE_WORKFLOW } else { 'lab-windows.yml' }),
    [string]$Branch = $(if ($env:SEAWORTHY_UPGRADE_BRANCH) { $env:SEAWORTHY_UPGRADE_BRANCH } else { 'main' }),
    # The fixture's CI test public key, relative to the repository (the trust check).
    [string]$TrustKey = 'crates/seaworthy-launcher/e2e/scm/keys/ci-test.pub',
    [ValidateSet('Fetch', 'SelfTest')][string]$Phase = 'Fetch'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
# An API answer, the zip, what the zip unpacks to, and its entries.
$MaxApiBytes = 16MB
$MaxZipBytes = 1GB
$MaxUnpackedBytes = 4GB
$MaxEntries = 10000
$NonePrefix = 'upgrade-previous: no previous build: '

function Say([string]$What) { Write-Host "upgrade-previous: $What" }
function Fail([string]$Why) { throw "upgrade-previous: FAIL: $Why" }
# Nothing to update from: exit 3, the lane skips.
function Skip([string]$Why) { throw ($NonePrefix + $Why) }

# The exit code a failure's message maps to: 3 for nothing to update from, else 1.
function Get-ExitCode([string]$Message) {
    if ($Message.StartsWith($NonePrefix, [StringComparison]::Ordinal)) { return 3 }
    return 1
}

# A JSON object's field, or $null when it has none (strict mode refuses a missing one).
function Get-Field($Object, [string]$Field) {
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $property = $Object.PSObject.Properties[$Field]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-Digits($Value) { return ($null -ne $Value) -and ("$Value" -match '^[0-9]{1,19}$') }

# ---------------------------------------------------------------------------
# The rules (pure; -Phase SelfTest covers them)

# The previous run among the workflow's runs (the API's JSON, parsed): see the header.
# Exact, case-sensitive comparisons, as jq's.
function Select-PreviousRun {
    param($Runs, [long]$Current, [string]$Repository, [string]$Branch)
    $best = $null
    foreach ($run in @(Get-Field $Runs 'workflow_runs')) {
        if ($null -eq $run) { continue }
        $number = Get-Field $run 'run_number'
        if (-not (Test-Digits $number) -or [long]$number -ge $Current) { continue }
        if ((Get-Field $run 'conclusion') -cne 'success') { continue }
        if ((Get-Field $run 'head_branch') -cne $Branch) { continue }
        if (@('push', 'schedule', 'workflow_dispatch') -cnotcontains (Get-Field $run 'event')) { continue }
        if ((Get-Field (Get-Field $run 'head_repository') 'full_name') -cne $Repository) { continue }
        if ($null -eq $best -or [long]$number -gt [long](Get-Field $best 'run_number')) { $best = $run }
    }
    if ($null -eq $best) { return $null }
    $id = Get-Field $best 'id'
    $sha = Get-Field $best 'head_sha'
    if (-not (Test-Digits $id)) { Fail "run $(Get-Field $best 'run_number') has the id '$id'" }
    if ("$sha" -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { Fail "run $(Get-Field $best 'run_number') has the head '$sha'" }
    return [pscustomobject]@{ Id = [long]$id; Number = [long](Get-Field $best 'run_number'); HeadSha = [string]$sha }
}

# The run's artifact named $Name (the API's JSON, parsed), checked: none, or an expired
# one, is nothing to update from; a bad id, an oversized one or one without a recorded
# SHA-256 digest fails.
function Select-Artifact {
    param($Artifacts, [string]$Name, [long]$RunNumber)
    $found = $null
    foreach ($artifact in @(Get-Field $Artifacts 'artifacts')) {
        if ($null -ne $artifact -and (Get-Field $artifact 'name') -ceq $Name) { $found = $artifact; break }
    }
    if ($null -eq $found) { Skip "run $RunNumber has no $Name artifact (it predates this lane)" }
    if ((Get-Field $found 'expired') -ne $false) { Skip "run $RunNumber's $Name artifact has expired" }
    $id = Get-Field $found 'id'
    $size = Get-Field $found 'size_in_bytes'
    $digest = Get-Field $found 'digest'
    if (-not (Test-Digits $id)) { Fail "artifact id '$id'" }
    if (-not (Test-Digits $size) -or [long]$size -gt $MaxZipBytes) { Fail "the artifact is '$size' bytes (at most 1 GiB)" }
    if ("$digest" -cnotmatch '^sha256:[0-9a-f]{64}$') { Fail "run $RunNumber's $Name artifact has no recorded SHA-256 digest ('$digest')" }
    return [pscustomobject]@{ Id = [long]$id; Size = [long]$size; Digest = [string]$digest }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# The downloaded zip against the digest GitHub recorded at upload.
function Assert-Digest([string]$Zip, [string]$Digest, [string]$What) {
    $actual = Get-Sha256 $Zip
    if ("sha256:$actual" -cne $Digest) { Fail "$What is sha256:$actual, but GitHub recorded $Digest" }
}

# $Name under $Root, or a failure when it would land anywhere else.
function Resolve-Inside([string]$Root, [string]$Name, [string]$What) {
    if ($Name -match '[:\x00-\x1f*?"<>|]' -or [System.IO.Path]::IsPathRooted($Name)) { Fail "$What '$Name' isn't a relative path" }
    $path = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Root, $Name))
    if (-not $path.StartsWith($Root + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal)) {
        Fail "$What '$Name' lands outside $Root"
    }
    return $path
}

# Unpacks $Zip into $Dest (new and empty), entry by entry: every entry inside $Dest, no
# stream names, no entry written twice, bounded in count and size.
function Expand-CheckedZip([string]$Zip, [string]$Dest) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $root = [System.IO.Path]::GetFullPath($Dest).TrimEnd('\', '/')
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $entries = @($archive.Entries)
        if ($entries.Count -gt $MaxEntries) { Fail "the artifact holds $($entries.Count) entries (at most $MaxEntries)" }
        [long]$total = 0
        foreach ($entry in $entries) { $total += $entry.Length }
        if ($total -gt $MaxUnpackedBytes) { Fail "the artifact unpacks to $total bytes (at most 4 GiB)" }
        foreach ($entry in $entries) {
            $path = Resolve-Inside $root $entry.FullName 'the artifact''s entry'
            if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
                continue
            }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
            # Never overwrites: a second entry of one name fails.
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $path, $false)
        }
    } finally {
        $archive.Dispose()
    }
}

# <Root>\lab-build.json, checked: format 1, every listed file inside <Root> and matching
# its SHA-256. Its parsed content.
function Assert-LabBuild([string]$Root) {
    $root = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $file = Join-Path $root 'lab-build.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Fail 'the artifact holds no lab-build.json' }
    $build = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json
    $files = Get-Field $build 'files'
    if ((Get-Field $build 'format') -ne 1 -or $null -eq $files -or @($files.PSObject.Properties).Count -eq 0) {
        Fail "the previous build doesn't match its lab-build.json: format 1 with files expected"
    }
    foreach ($property in @($files.PSObject.Properties)) {
        $path = Resolve-Inside $root $property.Name 'lab-build.json lists'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "the previous build doesn't match its lab-build.json: $($property.Name): listed but missing" }
        $actual = Get-Sha256 $path
        if ($actual -cne "$($property.Value)") { Fail "the previous build doesn't match its lab-build.json: $($property.Name): sha256 $actual, listed $($property.Value)" }
    }
    return $build
}

# The build trusts the key this checkout's fixture trusts, or it is nothing to update
# from (a key rotation: its helper would refuse this run's candidate).
function Assert-Trust($Build, [string]$Key, [long]$RunNumber) {
    if ("$(Get-Field $Build 'trust')" -cne (Get-Sha256 $Key)) {
        Skip "run $RunNumber's build trusts another CI test key than this checkout's fixture (a key rotation): its helper would refuse this candidate"
    }
}

# ---------------------------------------------------------------------------
# The fetch

# A directory only this account can open (one full-control entry, nothing inherited):
# the token's header file goes there.
function New-PrivateDirectory {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('sw-previous-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $dir -AclObject $acl
    return $dir
}

# One request through Windows' curl.exe, the token from the header file; $true when it
# succeeded within $MaxBytes. -Follow takes GitHub's redirect to the artifact storage
# (curl never carries a custom Authorization header to another host).
function Invoke-Api {
    param([string]$Url, [string]$File, [long]$MaxBytes, [int]$MaxSeconds, [switch]$Follow)
    $arguments = @('--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '--fail', '--silent', '--show-error',
        '--retry', '3', '--retry-delay', '2', '--connect-timeout', '30', '--max-time', "$MaxSeconds",
        '--max-filesize', "$MaxBytes", '--output', $File, '--header', "@$script:AuthFile",
        '--header', 'Accept: application/vnd.github+json', '--header', 'X-GitHub-Api-Version: 2022-11-28')
    if ($Follow) { $arguments += '--location' }
    if (Test-Path -LiteralPath $File) { Remove-Item -LiteralPath $File -Force }
    & $script:Curl @($arguments + @($Url))
    if ($LASTEXITCODE -ne 0) { return $false }
    # curl stops a transfer at --max-filesize only from 8.4 on.
    return ((Test-Path -LiteralPath $File -PathType Leaf) -and (Get-Item -LiteralPath $File).Length -le $MaxBytes)
}

function Invoke-Fetch {
    if (-not $Name -or -not $Out) { Write-Host 'usage: windows-upgrade-previous.ps1 -Name <artifact name> -Out <dir>'; exit 2 }
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { Fail 'the fetch runs on Windows (-Phase SelfTest runs anywhere)' }
    $token = $env:GITHUB_TOKEN
    $repository = $env:GITHUB_REPOSITORY
    $runNumber = $env:GITHUB_RUN_NUMBER
    $api = $env:GITHUB_API_URL
    if (-not $api) { $api = 'https://api.github.com' }
    if (-not $token) { Fail 'GITHUB_TOKEN is not set (the job token, permissions: actions: read)' }
    if ($token -match '[\x00-\x20\x7f]') { Fail 'GITHUB_TOKEN holds a space or a control character' }
    if (-not $repository -or -not $runNumber) { Fail 'not in GitHub Actions (GITHUB_REPOSITORY, GITHUB_RUN_NUMBER)' }
    if ($Name -cnotmatch '^[A-Za-z0-9._-]+$') { Fail "artifact name '$Name'" }
    if ($Workflow -cnotmatch '^[A-Za-z0-9._-]+$') { Fail "workflow '$Workflow'" }
    if ($Branch -cnotmatch '^[A-Za-z0-9._/-]+$') { Fail "branch '$Branch'" }
    if ($repository -cnotmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') { Fail "repository '$repository'" }
    if ($runNumber -cnotmatch '^[0-9]{1,18}$') { Fail "run number '$runNumber'" }
    if ($api -cnotmatch '^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._/-]*)?$') { Fail "API URL '$api'" }
    $api = $api.TrimEnd('/')
    $key = Join-Path $Repo $TrustKey
    if (-not (Test-Path -LiteralPath $key -PathType Leaf)) { Fail "no trusted key file $key" }
    $script:Curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path -LiteralPath $script:Curl -PathType Leaf)) { Fail "no $script:Curl" }
    $dest = $Out
    if (-not [System.IO.Path]::IsPathRooted($dest)) { $dest = Join-Path (Get-Location).Path $dest }
    $dest = [System.IO.Path]::GetFullPath($dest)

    $private = New-PrivateDirectory
    try {
        $script:AuthFile = Join-Path $private 'auth'
        [System.IO.File]::WriteAllText($script:AuthFile, "Authorization: Bearer $token`n", $Utf8NoBom)
        $runsFile = Join-Path $private 'runs.json'
        if (-not (Invoke-Api -Url "$api/repos/$repository/actions/workflows/$Workflow/runs?branch=$Branch&status=success&exclude_pull_requests=true&per_page=100" -File $runsFile -MaxBytes $MaxApiBytes -MaxSeconds 120)) {
            Fail "listing $Workflow's runs failed"
        }
        $run = Select-PreviousRun -Runs ([System.IO.File]::ReadAllText($runsFile) | ConvertFrom-Json) -Current ([long]$runNumber) -Repository $repository -Branch $Branch
        if ($null -eq $run) { Skip "no successful $Workflow run on $Branch before run $runNumber" }
        Say "the previous build is run $($run.Number)'s ($($run.HeadSha))"

        $artifactsFile = Join-Path $private 'artifacts.json'
        if (-not (Invoke-Api -Url "$api/repos/$repository/actions/runs/$($run.Id)/artifacts?name=$Name&per_page=100" -File $artifactsFile -MaxBytes $MaxApiBytes -MaxSeconds 120)) {
            Fail "listing run $($run.Number)'s artifacts failed"
        }
        $artifact = Select-Artifact -Artifacts ([System.IO.File]::ReadAllText($artifactsFile) | ConvertFrom-Json) -Name $Name -RunNumber $run.Number

        # The zip, by its id; GitHub answers with a redirect to its storage.
        $zip = Join-Path $private 'artifact.zip'
        if (-not (Invoke-Api -Url "$api/repos/$repository/actions/artifacts/$($artifact.Id)/zip" -File $zip -MaxBytes $MaxZipBytes -MaxSeconds 600 -Follow)) {
            Fail "downloading run $($run.Number)'s $Name artifact failed (or it is larger than 1 GiB)"
        }
        Assert-Digest $zip $artifact.Digest "run $($run.Number)'s $Name artifact"
        Say "the artifact matches its recorded digest ($($artifact.Digest))"

        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Expand-CheckedZip $zip $dest
        $build = Assert-LabBuild $dest
        Assert-Trust $build $key $run.Number
        $record = [ordered]@{ run_id = $run.Id; run_number = $run.Number; head_sha = $run.HeadSha; artifact_digest = $artifact.Digest }
        [System.IO.File]::WriteAllText((Join-Path $dest 'previous-run.json'), (($record | ConvertTo-Json) + "`n"), $Utf8NoBom)
        Say "unpacked $(Get-Field $build 'package') $(Get-Field $build 'token') (sequence $(Get-Field $build 'sequence')) into $dest"
    } finally {
        Remove-Item -LiteralPath $private -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Self-test

function Assert-Throws([scriptblock]$Body, [string]$Like, [string]$What) {
    $message = $null
    try { & $Body } catch { $message = $_.Exception.Message }
    if ($null -eq $message) { throw "selftest: $What did not fail" }
    if ($message -notlike $Like) { throw "selftest: $What failed with '$message', not '$Like'" }
}

function Invoke-SelfTest {
    $repository = 'acme/seaworthy'
    $run = {
        param([long]$Number, [string]$Conclusion = 'success', [string]$Branch = 'main', [string]$Event = 'push', [string]$Repository = 'acme/seaworthy')
        $head = $null
        if ($Repository) { $head = [pscustomobject]@{ full_name = $Repository } }
        [pscustomobject]@{ id = 1000 + $Number; run_number = $Number; conclusion = $Conclusion; head_branch = $Branch; event = $Event
            head_sha = ('{0:x40}' -f $Number); head_repository = $head }
    }
    $runs = [pscustomobject]@{ workflow_runs = @(
            (& $run 5), (& $run 12 -Event 'schedule'), (& $run 11 -Event 'workflow_dispatch'), (& $run 13 -Conclusion 'failure'),
            (& $run 14 -Branch 'next'), (& $run 15 -Event 'pull_request'), (& $run 16 -Repository 'fork/seaworthy'),
            (& $run 17 -Repository ''), (& $run 18 -Event 'workflow_run'), (& $run 19 -Repository 'Acme/Seaworthy'),
            (& $run 20), (& $run 25)) }
    $chosen = Select-PreviousRun -Runs $runs -Current 20 -Repository $repository -Branch 'main'
    if ($null -eq $chosen -or $chosen.Number -ne 12 -or $chosen.Id -ne 1012) { throw 'selftest: the previous run is the highest successful main run before this one (12)' }
    if ($null -ne (Select-PreviousRun -Runs $runs -Current 5 -Repository $repository -Branch 'main')) { throw 'selftest: no run before the first' }
    if ($null -ne (Select-PreviousRun -Runs ([pscustomobject]@{ workflow_runs = @() }) -Current 9 -Repository $repository -Branch 'main')) { throw 'selftest: no runs, no previous run' }
    if ($null -ne (Select-PreviousRun -Runs ([pscustomobject]@{ total_count = 0 }) -Current 9 -Repository $repository -Branch 'main')) { throw 'selftest: an answer without runs' }
    Say 'selftest: the run: the highest successful push, schedule or dispatch run of this repository on main before this one'

    $digest = 'sha256:' + ('ab' * 32)
    $artifact = { param($Fields) [pscustomobject]@{ artifacts = @([pscustomobject]$Fields) } }
    $good = @{ name = 'lab-upgrade-windows'; id = 77; expired = $false; size_in_bytes = 1234; digest = $digest }
    $picked = Select-Artifact -Artifacts (& $artifact $good) -Name 'lab-upgrade-windows' -RunNumber 12
    if ($picked.Id -ne 77 -or $picked.Digest -cne $digest) { throw 'selftest: the artifact' }
    Assert-Throws { Select-Artifact -Artifacts ([pscustomobject]@{ artifacts = @() }) -Name 'lab-upgrade-windows' -RunNumber 12 } ($NonePrefix + '*predates*') 'a run without the artifact'
    Assert-Throws { Select-Artifact -Artifacts (& $artifact ($good + @{})) -Name 'lab-upgrade-linux' -RunNumber 12 } ($NonePrefix + '*') 'another name'
    $expired = $good.Clone(); $expired.expired = $true
    Assert-Throws { Select-Artifact -Artifacts (& $artifact $expired) -Name 'lab-upgrade-windows' -RunNumber 12 } ($NonePrefix + '*expired*') 'an expired artifact'
    $undigested = $good.Clone(); $undigested.Remove('digest')
    Assert-Throws { Select-Artifact -Artifacts (& $artifact $undigested) -Name 'lab-upgrade-windows' -RunNumber 12 } '*FAIL*no recorded SHA-256*' 'an artifact without a digest'
    $md5 = $good.Clone(); $md5.digest = 'md5:' + ('ab' * 16)
    Assert-Throws { Select-Artifact -Artifacts (& $artifact $md5) -Name 'lab-upgrade-windows' -RunNumber 12 } '*FAIL*no recorded SHA-256*' 'a digest that is not SHA-256'
    $huge = $good.Clone(); $huge.size_in_bytes = $MaxZipBytes + 1
    Assert-Throws { Select-Artifact -Artifacts (& $artifact $huge) -Name 'lab-upgrade-windows' -RunNumber 12 } '*FAIL*at most 1 GiB*' 'an artifact over 1 GiB'
    $badId = $good.Clone(); $badId.id = '7;x'
    Assert-Throws { Select-Artifact -Artifacts (& $artifact $badId) -Name 'lab-upgrade-windows' -RunNumber 12 } '*FAIL*artifact id*' 'a bad artifact id'
    Say 'selftest: the artifact: missing or expired skips; no SHA-256 digest, over 1 GiB or a bad id fails'

    if ((Get-ExitCode ($NonePrefix + 'x')) -ne 3 -or (Get-ExitCode 'upgrade-previous: FAIL: x') -ne 1) { throw 'selftest: exit codes' }

    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('sw-previous-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    try {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $sha = { param([string]$Text) -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($Utf8NoBom.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) }
        $key = Join-Path $dir 'ci-test.pub'
        [System.IO.File]::WriteAllText($key, "00ff`n", $Utf8NoBom)
        # A zip of name -> text entries.
        $newZip = {
            param([string]$Path, [System.Collections.IDictionary]$Entries)
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
            $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($entryName in $Entries.Keys) {
                    $writer = New-Object System.IO.StreamWriter($zip.CreateEntry($entryName).Open(), $Utf8NoBom)
                    try { $writer.Write($Entries[$entryName]) } finally { $writer.Dispose() }
                }
            } finally {
                $zip.Dispose()
                $stream.Dispose()
            }
        }
        $labBuild = {
            param([string]$Msi, [string]$Trust)
            '{"format": 1, "package": "acmee2e-agent", "token": "0.1.0+g0123456789ab", "sequence": 7, "trust": "' + $Trust +
            '", "files": {"packages.json": "' + (& $sha '{}') + '", "packages/acmee2e-agent-0.1.0-7.msi": "' + (& $sha $Msi) + '"}}'
        }
        $entries = [ordered]@{ 'packages.json' = '{}'; 'packages/acmee2e-agent-0.1.0-7.msi' = 'msi'; 'lab-build.json' = (& $labBuild 'msi' (& $sha "00ff`n")) }
        $zipFile = Join-Path $dir 'good.zip'
        & $newZip $zipFile $entries
        Assert-Digest $zipFile ('sha256:' + (Get-Sha256 $zipFile)) 'the zip'
        Assert-Throws { Assert-Digest $zipFile $digest 'the zip' } '*FAIL*but GitHub recorded*' 'a zip whose digest differs'
        $unpacked = Join-Path $dir 'out'
        New-Item -ItemType Directory -Path $unpacked | Out-Null
        Expand-CheckedZip $zipFile $unpacked
        $build = Assert-LabBuild $unpacked
        Assert-Trust $build $key 12
        if ((Get-Field $build 'token') -cne '0.1.0+g0123456789ab') { throw 'selftest: lab-build.json read back' }
        [System.IO.File]::WriteAllText($key, "11ee`n", $Utf8NoBom)
        Assert-Throws { Assert-Trust $build $key 12 } ($NonePrefix + '*another CI test key*') 'a build trusting another key'
        [System.IO.File]::WriteAllText((Join-Path $unpacked 'packages/acmee2e-agent-0.1.0-7.msi'), 'tampered', $Utf8NoBom)
        Assert-Throws { Assert-LabBuild $unpacked } '*FAIL*sha256*listed*' 'a file that differs from its listing'
        Remove-Item -LiteralPath (Join-Path $unpacked 'packages/acmee2e-agent-0.1.0-7.msi') -Force
        Assert-Throws { Assert-LabBuild $unpacked } '*FAIL*listed but missing*' 'a listed file that is missing'
        Say 'selftest: lab-build.json: every listed file present and matching; another trusted key skips'

        $cases = @(
            @{ What = 'an entry above the directory'; Entries = [ordered]@{ '../evil.txt' = 'x' }; Like = '*FAIL*outside*' },
            @{ What = 'an entry deep above the directory'; Entries = [ordered]@{ 'a/../../evil.txt' = 'x' }; Like = '*FAIL*outside*' },
            @{ What = 'an absolute entry'; Entries = [ordered]@{ '/evil.txt' = 'x' }; Like = '*FAIL*' },
            @{ What = 'a stream name'; Entries = [ordered]@{ 'lab-build.json:hidden' = 'x' }; Like = '*FAIL*relative path*' },
            @{ What = 'a twice-written entry'; Entries = [ordered]@{ 'a.txt' = 'x'; './a.txt' = 'y' }; Like = '*' }
        )
        $index = 0
        foreach ($case in $cases) {
            $index++
            $bad = Join-Path $dir "bad-$index.zip"
            & $newZip $bad $case.Entries
            $target = Join-Path $dir "bad-$index"
            New-Item -ItemType Directory -Path $target | Out-Null
            Assert-Throws { Expand-CheckedZip $bad $target } $case.Like $case.What
            if (Test-Path -LiteralPath (Join-Path $dir 'evil.txt')) { throw "selftest: $($case.What) wrote outside the directory" }
        }
        $empty = Join-Path $dir 'empty'
        New-Item -ItemType Directory -Path $empty | Out-Null
        Assert-Throws { Assert-LabBuild $empty } '*FAIL*no lab-build.json*' 'an artifact without lab-build.json'
        [System.IO.File]::WriteAllText((Join-Path $empty 'lab-build.json'), '{"format": 2, "files": {"a": "b"}}', $Utf8NoBom)
        Assert-Throws { Assert-LabBuild $empty } '*FAIL*format 1*' 'another format'
        [System.IO.File]::WriteAllText((Join-Path $empty 'lab-build.json'), '{"format": 1, "files": {"../x": "b"}}', $Utf8NoBom)
        Assert-Throws { Assert-LabBuild $empty } '*FAIL*outside*' 'a listing naming a file outside'
        Say 'selftest: the zip: nothing outside the directory, no streams, nothing written twice'
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Say 'selftest: PASSED'
}

try {
    if ($Phase -eq 'SelfTest') { Invoke-SelfTest } else { Invoke-Fetch }
} catch {
    $message = $_.Exception.Message
    [Console]::Error.WriteLine($message)
    exit (Get-ExitCode $message)
}
exit 0
