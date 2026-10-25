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
    [string]$CargoArgs = $env:SEAWORTHY_CARGO_ARGS
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
    Fail "RUSTFLAGS (or CARGO_BUILD_RUSTFLAGS) is set: it would replace or drop the per-CPU flags (put product flags in .cargo/config.toml's target.<triple>.rustflags)"
}
$Extra = @()
if ($CargoArgs) { $Extra = @($CargoArgs -split '\s+' | Where-Object { $_ }) }
Enter-MsvcEnvironment

$Line = 0
foreach ($Text in (Get-Content -LiteralPath $Plan)) {
    $Line++
    if (-not $Text) { continue }
    $Fields = $Text -split "`t"
    switch ($Fields[0]) {
        'build' {
            if ($Fields.Count -ne 4) { Fail "plan line ${Line}: a build step has $($Fields.Count) fields" }
            $Dir = $Fields[1]
            $CargoSelect = @($Fields[3] -split ' ' | Where-Object { $_ })
            $Config = @('--config', 'profile.release.strip=false')
            if ($Fields[2] -ne '-') {
                # TOML literal strings, no spaces: one argument, unchanged by
                # Windows PowerShell 5.1's argument passing (which mangles
                # double quotes).
                $Quoted = @($Fields[2] -split ' ' | Where-Object { $_ } | ForEach-Object { "'" + $_ + "'" })
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
