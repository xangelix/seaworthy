<#
.SYNOPSIS
    The Windows build of seaworthy's GitLab CI template
    (ci/gitlab/seaworthy-windows.yml): the x86_64-pc-windows-msvc build plan the
    prepare job wrote, carried out.

.DESCRIPTION
    Reads <work>\plan-x86_64-pc-windows-msvc.tsv (seaworthy build-plan) and runs each
    step, as scripts/ci/seaworthy.sh build does on Linux:

      build     <target dir> <rustflags> <cargo args>   cargo build --release --locked
                                                        --target x86_64-pc-windows-msvc
                                                        --target-dir <root>\<target dir>,
                                                        the flags as target.<triple>.rustflags
                                                        (TOML literal strings, one argument)
      copy      <built file> <artifact path>            into <work>\artifacts
      sidecars  <directory> <pattern> <artifact dir>    every file the pattern matches under
                                                        the core build's build\ directory
                                                        (the AWS-LC-FIPS DLL pair), beside
                                                        the core: at least one, and one set
                                                        of bytes per name

    -TargetDir (SEAWORTHY_BUILD_TARGET_DIR) carries out one target directory's steps alone
    (base, or a CPU: its build, its copies, the sidecars its build leaves), so one CI job per
    CPU builds in parallel; the artifact directories the jobs leave merge.

    SEAWORTHY_RUSTFLAGS (every build) and SEAWORTHY_CORE_RUSTFLAGS (the cores' builds
    alone: each step whose target directory isn't base) add the caller's flags after the
    plan's, as scripts/ci/seaworthy.sh build does: whitespace-separated, with {workspace}
    (the workspace manifest's directory, absolute), {triple} and {cpu} (the step's target
    directory) expanded; a flag choosing the CPU or its features, a quote, or another
    {placeholder} is refused.

    SEAWORTHY_REMAP_PATHS (1, the default) remaps the source paths rustc writes into the
    binaries, as scripts/ci/seaworthy.sh build does: the workspace to /workspace, the
    target root to /target, each cargo home to /cargo and each git dependency's checkout
    to /cargo/git/checkouts/<hash>, after the plan's flags and before the caller's; 0
    leaves them.

    Runs in the MSVC build image (the template's windows-image: VS Build Tools, CMake,
    Go, NASM, rustup), where the AWS-LC-FIPS module builds natively. Before building, it
    enters the x64 MSVC developer environment (vswhere, then vcvarsall.bat x64) unless
    the job is already in one: the module's bindgen step needs %INCLUDE% (vcruntime.h),
    and libclang (LIBCLANG_PATH, else Visual Studio's C++ Clang tools). SEAWORTHY_VSWHERE
    names vswhere.exe for an image that keeps it elsewhere.

    PowerShell 5.1 compatible (no ternary, no ??, no && / || chains).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File seaworthy\scripts\seaworthy-build.ps1
#>
[CmdletBinding()]
param(
    [string]$Work = $(if ($env:SEAWORTHY_WORK) { $env:SEAWORTHY_WORK } else { 'seaworthy' }),
    [string]$Manifest = $(if ($env:SEAWORTHY_MANIFEST) { $env:SEAWORTHY_MANIFEST } else { 'Cargo.toml' }),
    [string]$TargetRoot = $env:SEAWORTHY_TARGET_DIR,
    [string]$CargoArgs = $env:SEAWORTHY_CARGO_ARGS,
    [string]$TargetDir = $env:SEAWORTHY_BUILD_TARGET_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Triple = 'x86_64-pc-windows-msvc'

function Fail([string]$Why) {
    throw "seaworthy: FAIL: $Why"
}

function Say([string]$What) {
    Write-Host "seaworthy: $What"
}

# A release never builds binaries that trust the product's CI test keys:
# seaworthy-formats' switch (1 turns it on) must be off on a release
# (SEAWORTHY_RELEASE=1, the templates' release rule).
if ($env:SEAWORTHY_RELEASE -eq '1' -and $env:SEAWORTHY_ALLOW_CI_TEST_KEYS -and $env:SEAWORTHY_ALLOW_CI_TEST_KEYS -ne '0') {
    Fail "SEAWORTHY_ALLOW_CI_TEST_KEYS is '$($env:SEAWORTHY_ALLOW_CI_TEST_KEYS)' on a release: a release never trusts the CI test keys (unset it, or set it to 0)"
}

# The x64 MSVC developer environment, imported into this process so cargo
# and every build script inherit it, unless the job already runs in one
# (VCToolsInstallDir and INCLUDE set). Without it a FIPS core's
# aws-lc-fips-sys fails in bindgen: clang finds the Windows SDK's headers but
# not MSVC's own (vcruntime.h). vcvarsall.bat's environment comes back
# through a temp .cmd file's `set`, which sidesteps Windows PowerShell's
# native-argument quoting. Off Windows (the template's tests under pwsh)
# with no SEAWORTHY_VSWHERE, nothing to enter.
function Enter-MsvcEnvironment {
    if ($env:VCToolsInstallDir -and $env:INCLUDE) {
        Say "MSVC: already in a developer environment ($($env:VCToolsInstallDir))"
    } else {
        $VsWhere = $env:SEAWORTHY_VSWHERE
        if (-not $VsWhere -and ${env:ProgramFiles(x86)}) {
            $VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        }
        if (-not $VsWhere -or -not (Test-Path -LiteralPath $VsWhere)) {
            if ($env:OS -ne 'Windows_NT' -and -not $env:SEAWORTHY_VSWHERE) {
                Say 'MSVC: not on Windows, no developer environment to enter'
                return
            }
            Fail "vswhere.exe not found ($VsWhere): the windows-image needs Visual Studio Build Tools with the MSVC x64 tools (or set SEAWORTHY_VSWHERE)"
        }
        $Vs = @(& $VsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Where-Object { $_ }) | Select-Object -First 1
        if (-not $Vs) { Fail 'no Visual Studio installation with the MSVC x64 tools (vswhere found none)' }
        $Bat = Join-Path $Vs 'VC\Auxiliary\Build\vcvarsall.bat'
        if (-not (Test-Path -LiteralPath $Bat)) { Fail "vcvarsall.bat not found ($Bat)" }
        $Cmd = Join-Path ([System.IO.Path]::GetTempPath()) "seaworthy-vcvars-$PID.cmd"
        Set-Content -LiteralPath $Cmd -Encoding ASCII -Value @("@call `"$Bat`" x64 >nul", '@set')
        try {
            $Lines = @(& cmd.exe /d /c $Cmd)
        } finally {
            Remove-Item -LiteralPath $Cmd -Force -ErrorAction SilentlyContinue
        }
        $Count = 0
        foreach ($Entry in $Lines) {
            $At = "$Entry".IndexOf('=')
            if ($At -gt 0) {
                [Environment]::SetEnvironmentVariable("$Entry".Substring(0, $At), "$Entry".Substring($At + 1), 'Process')
                $Count++
            }
        }
        if (-not ($env:INCLUDE -and $env:LIB -and $env:VCToolsInstallDir)) {
            Fail "vcvarsall.bat x64 did not set INCLUDE, LIB and VCToolsInstallDir ($Bat)"
        }
        Say "MSVC: $Vs ($Count variables; VCToolsInstallDir=$($env:VCToolsInstallDir))"
        if (-not ($env:LIBCLANG_PATH -and (Test-Path -LiteralPath (Join-Path $env:LIBCLANG_PATH 'libclang.dll')))) {
            $Clang = Join-Path $Vs 'VC\Tools\Llvm\x64\bin'
            if (Test-Path -LiteralPath (Join-Path $Clang 'libclang.dll')) {
                $env:LIBCLANG_PATH = $Clang
            }
        }
    }
    if ($env:LIBCLANG_PATH) {
        Say "libclang: $($env:LIBCLANG_PATH)"
    } else {
        Say "libclang: not found (a FIPS core's bindgen needs it: set LIBCLANG_PATH, or install Visual Studio's C++ Clang tools)"
    }
}

if (-not $TargetRoot) { $TargetRoot = Join-Path $Work 'target' }
$Artifacts = Join-Path $Work 'artifacts'
$Plan = Join-Path $Work "plan-$Triple.tsv"
if (-not (Test-Path -LiteralPath $Plan)) {
    Say "${Triple}: no product needs it"
    exit 0
}
# The release's version and build metadata, as the prepare job recorded
# them (release.env): a product's version token compiles from them, as on
# Linux (seaworthy.sh build).
$ReleaseEnv = Join-Path $Work 'release.env'
if (Test-Path -LiteralPath $ReleaseEnv) {
    foreach ($Entry in (Get-Content -LiteralPath $ReleaseEnv)) {
        if ($Entry -match '^(SEAWORTHY_RELEASE_VERSION|SEAWORTHY_RELEASE_BUILD)=([0-9A-Za-z.-]*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        } elseif ($Entry) {
            Fail "${ReleaseEnv}: unexpected line '$Entry'"
        }
    }
    Say "building release $($env:SEAWORTHY_RELEASE_VERSION)+$($env:SEAWORTHY_RELEASE_BUILD)"
}
if ($env:RUSTFLAGS -or $env:CARGO_ENCODED_RUSTFLAGS -or $env:CARGO_BUILD_RUSTFLAGS) {
    Fail "RUSTFLAGS (or CARGO_BUILD_RUSTFLAGS) is set: it would replace or drop the per-CPU flags (put product flags in .cargo/config.toml's target.<triple>.rustflags, or in SEAWORTHY_RUSTFLAGS / SEAWORTHY_CORE_RUSTFLAGS)"
}

# {workspace} in the caller's flags: the workspace root, absolute (cargo runs
# a dependency's rustc in that dependency's own directory). Resolved against
# PowerShell's location, which .NET's current directory needn't follow.
$Workspace = ''
if ("$($env:SEAWORTHY_RUSTFLAGS) $($env:SEAWORTHY_CORE_RUSTFLAGS)".Contains('{workspace}')) {
    $ManifestPath = $Manifest
    if (-not [System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath = Join-Path (Get-Location).Path $ManifestPath }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        Fail "{workspace} names the workspace manifest's directory, but $Manifest doesn't exist (SEAWORTHY_MANIFEST)"
    }
    $Workspace = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($ManifestPath))
}

# The caller's extra rustflags for one build step: the words of $Flags,
# {workspace}, {triple} and {cpu} (the step's target directory: its CPU, or
# base for the launcher and helper) expanded. Refused: a flag choosing the
# CPU or its features (the plan's alone: each core's record must name what
# it was built for), a quote (the flags travel as TOML literal strings) and
# any other {placeholder}.
function Get-ExtraFlags([string]$Flags, [string]$Cpu) {
    $Out = @()
    foreach ($Word in @("$Flags" -split '\s+' | Where-Object { $_ })) {
        if ($Word.Contains('target-cpu') -or $Word.Contains('target-feature')) {
            Fail "extra rustflags may not choose the CPU or its features ('$Word'): the build plan sets them per core"
        }
        $Word = $Word.Replace('{workspace}', $Workspace).Replace('{triple}', $Triple).Replace('{cpu}', $Cpu)
        if ($Word.Contains("'")) { Fail "extra rustflags may not hold a quote: $Word" }
        if ($Word -match '\{[A-Za-z_]+\}') {
            Fail "extra rustflags: unknown placeholder $($Matches[0]) in '$Word' ({workspace}, {triple} and {cpu} expand)"
        }
        $Out += $Word
    }
    return ,$Out
}
$Extra = @()
if ($CargoArgs) { $Extra = @($CargoArgs -split '\s+' | Where-Object { $_ }) }

# One --remap-path-prefix flag, refusing a path the flags can't carry (they
# travel as TOML literal strings, so no quote).
function Get-Remap([string]$From, [string]$To) {
    if ($From.Contains("'")) { Fail "can't remap the source path '$From' (a quote): set SEAWORTHY_REMAP_PATHS=0, or build elsewhere" }
    return "--remap-path-prefix=$From=$To"
}

# The build's --remap-path-prefix flags (seaworthy.sh build's remap_paths):
# the source paths rustc writes into the binaries name no build machine,
# home directory or private repository. The crates' own directories
# (<crate>-<version>) stay. rustc applies the last matching prefix, so the
# most specific come last; the cargo homes and checkouts are the ones cargo
# metadata names, every feature and platform's, sorted ordinally as the
# Linux build sorts them (LC_ALL=C).
function Get-RemapFlags {
    $Out = @()
    $ManifestPath = $Manifest
    if (-not [System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath = Join-Path (Get-Location).Path $ManifestPath }
    $Out += Get-Remap ([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($ManifestPath))) '/workspace'
    $RootPath = $TargetRoot
    if (-not [System.IO.Path]::IsPathRooted($RootPath)) { $RootPath = Join-Path (Get-Location).Path $RootPath }
    $Out += Get-Remap ([System.IO.Path]::GetFullPath($RootPath)) '/target'
    $Json = & cargo metadata --quiet --format-version 1 --locked --all-features --manifest-path $Manifest
    if ($LASTEXITCODE -ne 0) {
        Fail "cargo metadata failed ($LASTEXITCODE): the source paths to remap come from it (SEAWORTHY_REMAP_PATHS=0 turns remapping off)"
    }
    $Homes = @{}
    $Checkouts = @{}
    # The manifest paths as JSON strings (a backslash is escaped), read
    # without ConvertFrom-Json, as the Linux build reads them with grep.
    foreach ($Found in [regex]::Matches(($Json -join "`n"), '"manifest_path":"([^"]*)"')) {
        $Path = $Found.Groups[1].Value.Replace('\\', '\')
        if ($Path -match '^(.*?)[\\/]git[\\/]checkouts[\\/]([^\\/]+)[\\/]') {
            $Homes[$Matches[1]] = $true
            $Dir = $Matches[2]
            $Checkouts[$Matches[0].Substring(0, $Matches[0].Length - 1)] = '/cargo/git/checkouts/' + $Dir.Substring($Dir.LastIndexOf('-') + 1)
        } elseif ($Path -match '^(.*?)[\\/]registry[\\/]src[\\/]') {
            $Homes[$Matches[1]] = $true
        }
    }
    $Sorted = [string[]]@($Homes.Keys)
    [Array]::Sort($Sorted, [System.StringComparer]::Ordinal)
    foreach ($From in $Sorted) { $Out += Get-Remap $From '/cargo' }
    $Sorted = [string[]]@($Checkouts.Keys)
    [Array]::Sort($Sorted, [System.StringComparer]::Ordinal)
    foreach ($From in $Sorted) { $Out += Get-Remap $From $Checkouts[$From] }
    return ,$Out
}
$Remaps = @()
if ($env:SEAWORTHY_REMAP_PATHS -eq '0') {
} elseif ((-not $env:SEAWORTHY_REMAP_PATHS) -or $env:SEAWORTHY_REMAP_PATHS -eq '1') {
    $Remaps = Get-RemapFlags
    Say "remapping source paths: $(($Remaps | ForEach-Object { $_.Substring('--remap-path-prefix='.Length) }) -join ' ')"
} else {
    Fail "SEAWORTHY_REMAP_PATHS is 1 (the default) or 0, not '$($env:SEAWORTHY_REMAP_PATHS)'"
}
Enter-MsvcEnvironment

$Steps = @(Get-Content -LiteralPath $Plan)
if ($TargetDir) {
    if ($TargetDir -notmatch '^[A-Za-z0-9._-]+$') { Fail "'$TargetDir' isn't a target directory" }
    $Steps = @($Steps | Where-Object {
        $F = "$_" -split "`t"
        ($F[0] -eq 'build' -and $F.Count -gt 1 -and $F[1] -eq $TargetDir) -or
        (($F[0] -eq 'copy' -or $F[0] -eq 'sidecars') -and $F.Count -gt 1 -and $F[1].StartsWith("$TargetDir/"))
    })
    if (-not @($Steps | Where-Object { "$_".StartsWith("build`t") })) {
        Fail "the $Triple plan has no target directory '$TargetDir'"
    }
    Say "${Triple}: the $TargetDir build alone"
}

$Line = 0
foreach ($Text in $Steps) {
    $Line++
    if (-not $Text) { continue }
    $Fields = $Text -split "`t"
    switch ($Fields[0]) {
        'build' {
            if ($Fields.Count -ne 4) { Fail "plan line ${Line}: a build step has $($Fields.Count) fields" }
            $Dir = $Fields[1]
            $CargoSelect = @($Fields[3] -split ' ' | Where-Object { $_ })
            $Config = @('--config', 'profile.release.strip=false')
            $Flags = @()
            if ($Fields[2] -ne '-') { $Flags += @($Fields[2] -split ' ' | Where-Object { $_ }) }
            $Flags += $Remaps
            # The caller's flags after the plan's and the remaps: every
            # build's, then (a core's step: its target directory is its CPU,
            # never base) the cores'.
            $Flags += Get-ExtraFlags $env:SEAWORTHY_RUSTFLAGS $Dir
            if ($Dir -ne 'base') { $Flags += Get-ExtraFlags $env:SEAWORTHY_CORE_RUSTFLAGS $Dir }
            if ($Flags.Count -gt 0) {
                # TOML literal strings: one argument, unchanged by Windows
                # PowerShell 5.1's argument passing (which mangles double
                # quotes). A {workspace} path with a space stays inside its
                # quotes, one argument.
                $Quoted = @($Flags | ForEach-Object { "'" + $_ + "'" })
                $Config += @('--config', ("target.$Triple.rustflags=[" + ($Quoted -join ',') + ']'))
            }
            $ManifestArgs = @('--manifest-path', $Manifest)
            if ($CargoSelect -contains '--manifest-path') { $ManifestArgs = @() }
            Say "cargo build $($CargoSelect -join ' ') ($Dir)"
            & cargo build --quiet --release --locked --target $Triple --target-dir (Join-Path $TargetRoot $Dir) @Config @ManifestArgs @CargoSelect @Extra
            if ($LASTEXITCODE -ne 0) { Fail "cargo build $($CargoSelect -join ' ') failed ($LASTEXITCODE)" }
        }
        'copy' {
            if ($Fields.Count -ne 3) { Fail "plan line ${Line}: a copy step has $($Fields.Count) fields" }
            $From = Join-Path $TargetRoot $Fields[1]
            $To = Join-Path $Artifacts $Fields[2]
            if (-not (Test-Path -LiteralPath $From -PathType Leaf)) { Fail "the build left no $From" }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $To) | Out-Null
            Copy-Item -LiteralPath $From -Destination $To -Force
        }
        'sidecars' {
            if ($Fields.Count -ne 4) { Fail "plan line ${Line}: a sidecars step has $($Fields.Count) fields" }
            $From = Join-Path $TargetRoot $Fields[1]
            $Pattern = $Fields[2]
            $To = Join-Path $Artifacts $Fields[3]
            if (-not (Test-Path -LiteralPath $From -PathType Container)) { Fail "the core build left no $From" }
            $Found = @(Get-ChildItem -LiteralPath $From -Recurse -File -Filter $Pattern -ErrorAction SilentlyContinue)
            if ($Found.Count -eq 0) { Fail "no sidecar matching $Pattern under $From (is the core built with the module that ships it?)" }
            New-Item -ItemType Directory -Force -Path $To | Out-Null
            foreach ($Group in @($Found | Group-Object Name)) {
                $Hashes = @($Group.Group | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } | Sort-Object -Unique)
                if ($Hashes.Count -ne 1) { Fail "$($Group.Name): $($Group.Count) builds with different bytes under $From" }
                Copy-Item -LiteralPath $Group.Group[0].FullName -Destination (Join-Path $To $Group.Name) -Force
                Say "sidecar $($Group.Name) -> $To"
            }
        }
        default { Fail "plan line ${Line}: unknown step '$($Fields[0])'" }
    }
}
$Built = @(Get-ChildItem -LiteralPath (Join-Path $Artifacts $Triple) -Recurse -File)
Say "built: $($Built.Count) file(s) under $(Join-Path $Artifacts $Triple)"
