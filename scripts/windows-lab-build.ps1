<#
.SYNOPSIS
    The Windows lab's build (.github/workflows/lab-windows.yml): the seaworthy CLI and the
    lanes' tools built natively, the fixture products built by the CLI's build plan and
    packaged by `seaworthy package` with WiX, Authenticode-signed with a certificate made
    for the run, and the bundle the lanes install.

.DESCRIPTION
    Runs on a Windows machine with Visual Studio's MSVC tools and rustup (a GitHub-hosted
    `windows-2025` runner), elevated: installing WiX is an MSI install. A throwaway
    machine: it installs WiX machine-wide. Steps, fail-fast:

      tools     WiX 5.0.2 from its pinned MSI (the version the CLI and the GitLab template
                build with; MS-RL) and osslsigncode 2.14 from its pinned Windows build, each
                checked against its SHA-256 before anything runs; with -Fips also NASM
                2.16.03 from its pinned zip (the AWS-LC FIPS module's assembly needs it),
                with CMake, Go, Ninja and Visual Studio's clang (bindgen) from the image
                (Ninja 1.13.2 from its pinned zip when neither has it).
      cli       `seaworthy` and the lanes' binaries, release builds of this workspace:
                seaworthy-service's windows_scm_e2e example (the version-gate stub and
                start/stop/status) and its windows_scm test, seaworthy-crypto's
                entropy_probe example, seaworthy-updater's windows_policy_live test and
                the lab harness `seaworthy-lab`. With -Fips, the first three on the FIPS
                module (and fips_selfcheck, run here with --expect-fips), the module's DLL
                beside them, and neither of the last two.
      keys      an ML-DSA-87 release key (`seaworthy keygen`) and a self-signed RSA-3072
                code-signing certificate, basicConstraints critical CA:FALSE (Windows'
                Authenticode policy refuses a CA as the signer), both made here for this
                run. Only the certificate leaves the job (the lanes trust it). Beside
                them, the fixture's committed public CI test key (scm/keys/ci-test.*).
      build     crates/seaworthy-launcher/e2e/scm/seaworthy.toml (seaworthy-fips.toml with
                -Fips), copied beside the keys, and without -Fips the desktop fixture's
                seaworthy.toml: `seaworthy build-plan`, carried out by
                scripts/ci/seaworthy-build.ps1 (the GitLab template's Windows build step).
      package   `seaworthy package` with SEAWORTHY_WIX: the SCM product 1.0.0; the update
                lane's agent 1.0.0-rc.1 (sequence 1) and 1.0.0 (2), signed with release
                manifests; agent 1.0.1 (3), whose .wxs gets a custom action failing after
                InstallServices (the rolled-back upgrade) and is built by WiX directly; the
                desktop viewer 1.0.0 (1) and 1.0.1 (2) and the command-line viewer-lite 1.0.0
                (1), unsigned (both MSIs for either scope; the viewer with its licence page,
                the lite one putting its directory on PATH). Every MSI passes Windows
                Installer's validation (`wix msi validate`: an ICE error fails the build).
      upgrade   the upgrade-from-previous lane's candidate (scripts/windows-upgrade.ps1):
                the plan built again with seaworthy-formats' CI test-key switch
                (SEAWORTHY_ALLOW_CI_TEST_KEYS=1, for this build alone: a dev build, never
                a release), the helper trusting the run's release key and, through
                `ci_test_keys!`, the CI test key (so it carries the CI test-key marker),
                and dialing the lab's names under .invalid alone, the agent packaged as the
                workspace's version, sequence -UpgradeSequence, build g<commit>, its
                token written into lab\build.txt: a dev build (`--authenticode-only`, the
                run's certificate) whose manifest the CI test key signs
                (`--ci-test-signing`). Into <Out>\upgrade-candidate: lab-build.json (the
                build's identity, the SHA-256 of the test key it trusts and of every
                file), packages.json and packages\, which the workflow keeps on main as
                the next run's previous build. Not with -Fips.
      bundle    <Out>\bundle, what the lanes install (docs/testing-windows.md, the candidate
                as upgrade\), listed with SHA-256 in its manifest.txt.

    Needs PowerShell 7 (the certificate's PEM export is .NET's); the syntax stays Windows
    PowerShell 5.1's.

.PARAMETER Phase
    All        the build (default).
    SelfTest   the pure parts on any PowerShell 7 (Linux pwsh included): the certificate's
               extensions, the broken .wxs, TOML quoting. -Wxs names a service .wxs to break
               (default: the CLI's golden agent.wxs).

.EXAMPLE
    pwsh -NoProfile -File scripts\windows-lab-build.ps1 -Out $env:RUNNER_TEMP\windows-lab
#>
[CmdletBinding()]
param(
    [string]$Out = $(if ($env:SEAWORTHY_LAB_OUT) { $env:SEAWORTHY_LAB_OUT } else { 'target\windows-lab' }),
    # The cargo target root of every build: short, because the AWS-LC FIPS module's CMake
    # build nests its objects deep under it and Windows caps an object path at 250
    # characters.
    [string]$TargetRoot = $(if ($env:SEAWORTHY_LAB_TARGET_DIR) { $env:SEAWORTHY_LAB_TARGET_DIR } else { Join-Path "$env:SystemDrive\" 'swl' }),
    [switch]$Fips,
    [ValidateSet('All', 'SelfTest')][string]$Phase = 'All',
    [string]$Wxs,
    # The upgrade candidate's release sequence (CI: the workflow's run number, so a later
    # run's build is a newer release than an earlier one's).
    [string]$UpgradeSequence = $(if ($env:SEAWORTHY_UPGRADE_SEQUENCE) { $env:SEAWORTHY_UPGRADE_SEQUENCE } else { '1' }),
    [string]$WixMsiUrl = 'https://github.com/wixtoolset/wix/releases/download/v5.0.2/wix-cli-x64.msi',
    [string]$WixMsiSha256 = '097383B2773BDD3D76A6A2CD3F4DE6357BAE59172E1B6FA5AD87CE062074E8D0',
    [string]$WixVersion = '5.0.2',
    [string]$OsslsigncodeUrl = 'https://github.com/mtrojnar/osslsigncode/releases/download/2.14/osslsigncode-2.14-windows-x64-mingw.zip',
    [string]$OsslsigncodeSha256 = '9A1722AAF62A27852C4EB9C35749A0248065052D0AE0A93D4ED6BB49DEF027F2',
    [string]$OsslsigncodeVersion = '2.14',
    [string]$NasmUrl = 'https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/nasm-2.16.03-win64.zip',
    [string]$NasmSha256 = '3EE4782247BCB874378D02F7EAB4E294A84D3D15F3F6EE2DE2F47A46AA7226E6',
    [string]$NasmVersion = '2.16.03',
    # Only when neither the image nor Visual Studio's developer environment has Ninja (the
    # FIPS module's CMake build uses its generator on Windows).
    [string]$NinjaUrl = 'https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-win.zip',
    [string]$NinjaSha256 = '07FC8261B42B20E71D1720B39068C2E14FFCEE6396B76FB7A795FB460B78DC65',
    [string]$NinjaVersion = '1.13.2'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Triple = 'x86_64-pc-windows-msvc'
$Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
# Forward slashes: the build plan names crate paths with `/` only; cargo takes them.
$FixtureManifest = 'crates/seaworthy-launcher/e2e/Cargo.toml'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
# The lab's names (scripts/windows-upgrade.ps1 maps them to the loopback): the upgrade
# candidate's helper dials nothing else.
$LabPackagesHost = 'packages.lab.invalid'
$LabUpdatesHost = 'updates.lab.invalid'

function Say([string]$What) { Write-Host ('{0:HH:mm:ss} windows-lab: {1}' -f (Get-Date), $What) }
function Fail([string]$Why) { throw "windows-lab: FAIL: $Why" }
function Step([string]$Name) { Write-Host ''; Write-Host "=== $Name ===" }

function Resolve-RepoPath([string]$Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) { $Path = Join-Path $Repo $Path }
    return [System.IO.Path]::GetFullPath($Path)
}

function Write-Text([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
}

# Whether the file at $Path holds the ASCII text $Text (Latin-1 maps each byte to one
# character, so an ordinal search over the decoded bytes is a byte search).
function Test-FileContains([string]$Path, [string]$Text) {
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    return $latin1.GetString([System.IO.File]::ReadAllBytes($Path)).IndexOf($Text, [System.StringComparison]::Ordinal) -ge 0
}

# A native program, its exit code checked. Its output goes to the job log and to
# <Out>\logs\<Log>.log when -Log is given.
function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments, [string]$What, [string]$Log)
    Say ("> {0} {1}" -f $Exe, ($Arguments -join ' '))
    if ($Log) {
        $file = Join-Path $script:Logs "$Log.log"
        # Not 2>&1 under 'Stop': Windows PowerShell turns native stderr into errors.
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $file -Append | Out-Host } finally { $ErrorActionPreference = $previous }
    } else {
        & $Exe @Arguments
    }
    if ($LASTEXITCODE -ne 0) { Fail "$What failed (exit $LASTEXITCODE)" }
}

# cargo with --message-format=json-render-diagnostics: the parsed JSON messages
# (diagnostics render to stderr, as usual).
function Invoke-CargoJson {
    param([string[]]$Arguments, [string]$What)
    Say ("> cargo {0}" -f ($Arguments -join ' '))
    $lines = @(& cargo @Arguments --message-format=json-render-diagnostics)
    if ($LASTEXITCODE -ne 0) { Fail "$What failed (cargo exit $LASTEXITCODE)" }
    $messages = New-Object System.Collections.ArrayList
    foreach ($line in $lines) {
        if ("$line".StartsWith('{')) { [void]$messages.Add(("$line" | ConvertFrom-Json)) }
    }
    return $messages.ToArray()
}

# The executable cargo built for target $Name (an example or a test).
function Get-CargoExecutable {
    param([object[]]$Messages, [string]$Name)
    $found = @($Messages | Where-Object {
            $_.reason -eq 'compiler-artifact' -and $_.target.name -eq $Name -and
            ($_.PSObject.Properties.Name -contains 'executable') -and $_.executable })
    if ($found.Count -ne 1) { Fail "cargo reported $($found.Count) executables for $Name (expected one)" }
    return [string]$found[0].executable
}

# A TOML literal string (single quotes, no escapes): a Windows path as it is.
function ConvertTo-TomlLiteral([string]$Text) {
    if ($Text -match "['\r\n]") { Fail "cannot write '$Text' as a TOML literal string" }
    return "'" + $Text + "'"
}

# ---------------------------------------------------------------------------
# Pinned tools

function Get-PinnedFile {
    param([string]$Url, [string]$Sha256, [string]$Name)
    $dir = Join-Path $Out 'downloads'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir $Name
    Say "downloading $Url"
    # Windows' own curl.exe (Windows 10 1803 and Server 2019 on), as
    # scripts/ci/seaworthy-msi.ps1 does: Invoke-WebRequest bounds neither the
    # size nor the whole transfer. https only, redirects included; the pin
    # below decides.
    if (-not $Url.StartsWith('https://', [StringComparison]::Ordinal)) { Fail "$Name must come from an https URL, not $Url" }
    $curlExe = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path -LiteralPath $curlExe -PathType Leaf)) { Fail "no $curlExe to download $Name with" }
    if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    & $curlExe --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 `
        --connect-timeout 30 --max-time 600 --max-filesize 268435456 --output $file $Url
    if ($LASTEXITCODE -ne 0) { Fail "downloading $Url failed (curl.exe exit $LASTEXITCODE)" }
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if ($hash -ne $Sha256.ToUpperInvariant()) {
        Remove-Item -LiteralPath $file -Force
        Fail "$Name has SHA-256 $hash, not the pinned $Sha256"
    }
    Say "${Name}: SHA-256 verified"
    return $file
}

# The pinned wix.exe: an installed one of that version, or the pinned MSI installed
# (msiexec waited for alone: Start-Process -Wait waits on every descendant).
function Install-Wix {
    $candidates = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        $candidates += @(Get-ChildItem -LiteralPath $root -Directory -Filter 'WiX Toolset*' -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path (Join-Path $_.FullName 'bin') 'wix.exe' } |
                Where-Object { Test-Path -LiteralPath $_ })
    }
    foreach ($candidate in $candidates) {
        $version = (& $candidate --version | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $version.StartsWith("$WixVersion+")) { return $candidate }
    }
    $msi = Get-PinnedFile -Url $WixMsiUrl -Sha256 $WixMsiSha256 -Name 'wix-cli-x64.msi'
    $log = Join-Path $script:Logs 'wix-install.log'
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -PassThru `
        -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$log`"")
    $null = $process.Handle
    if (-not $process.WaitForExit(600000)) { $process.Kill(); Fail 'installing WiX took longer than 10 minutes' }
    if ($process.ExitCode -notin @(0, 3010)) { Fail "installing WiX failed (msiexec exit $($process.ExitCode); log $log)" }
    $installed = @(Get-ChildItem -LiteralPath $env:ProgramFiles -Directory -Filter 'WiX Toolset*' |
            ForEach-Object { Join-Path (Join-Path $_.FullName 'bin') 'wix.exe' } | Where-Object { Test-Path -LiteralPath $_ })
    if ($installed.Count -ne 1) { Fail "expected one wix.exe under $env:ProgramFiles\WiX Toolset*\bin, found $($installed.Count)" }
    $version = (& $installed[0] --version | Out-String).Trim()
    if (-not $version.StartsWith("$WixVersion+")) { Fail "the installed WiX is $version, not $WixVersion" }
    return $installed[0]
}

# A pinned zip, unpacked under <Out>\tools\<Name>.
function Expand-PinnedZip {
    param([string]$Url, [string]$Sha256, [string]$Name)
    $zip = Get-PinnedFile -Url $Url -Sha256 $Sha256 -Name "$Name.zip"
    $dir = Join-Path (Join-Path $Out 'tools') $Name
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    Expand-Archive -LiteralPath $zip -DestinationPath $dir
    return $dir
}

function Install-Osslsigncode {
    $dir = Expand-PinnedZip -Url $OsslsigncodeUrl -Sha256 $OsslsigncodeSha256 -Name 'osslsigncode'
    $exe = Join-Path $dir 'bin\osslsigncode.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail "the osslsigncode zip holds no bin\osslsigncode.exe" }
    $version = (& $exe --version | Select-Object -First 1 | Out-String).Trim()
    if (-not $version.StartsWith("osslsigncode $OsslsigncodeVersion,")) { Fail "osslsigncode reports '$version', not $OsslsigncodeVersion" }
    $env:PATH = "$(Split-Path -Parent $exe);$env:PATH"
    Say "osslsigncode: $version"
    return $exe
}

function Install-Nasm {
    $dir = Expand-PinnedZip -Url $NasmUrl -Sha256 $NasmSha256 -Name 'nasm'
    $exe = Join-Path $dir "nasm-$NasmVersion\nasm.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail "the NASM zip holds no nasm-$NasmVersion\nasm.exe" }
    $version = (& $exe -v | Out-String).Trim()
    if ($version -notmatch "version $([regex]::Escape($NasmVersion))\b") { Fail "nasm reports '$version', not $NasmVersion" }
    $env:PATH = "$(Split-Path -Parent $exe);$env:PATH"
    Say "nasm: $version"
}

function Install-NinjaIfMissing {
    $found = Get-Command 'ninja' -ErrorAction SilentlyContinue
    if ($found) { Say "ninja: $($found.Source)"; return }
    $dir = Expand-PinnedZip -Url $NinjaUrl -Sha256 $NinjaSha256 -Name 'ninja'
    $exe = Join-Path $dir 'ninja.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail 'the Ninja zip holds no ninja.exe' }
    $version = (& $exe --version | Out-String).Trim()
    if ($version -ne $NinjaVersion) { Fail "ninja reports '$version', not $NinjaVersion" }
    $env:PATH = "$dir;$env:PATH"
    Say "ninja: $version (pinned)"
}

# The x64 MSVC developer environment imported into this process (INCLUDE, LIB, PATH,
# ...), so cargo and every build script inherit it: the FIPS module's build runs `cl`
# and its bindgen step needs %INCLUDE% and libclang. Mirrors
# scripts/ci/seaworthy-build.ps1, which enters it for the plan's builds.
function Enter-MsvcEnvironment {
    if ($env:VCToolsInstallDir -and $env:INCLUDE) { return }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { Fail "vswhere.exe not found ($vswhere): no Visual Studio with the MSVC tools" }
    $vs = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Where-Object { $_ }) | Select-Object -First 1
    if (-not $vs) { Fail 'no Visual Studio installation with the MSVC x64 tools' }
    $bat = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
    $cmd = Join-Path ([System.IO.Path]::GetTempPath()) "seaworthy-lab-vcvars-$PID.cmd"
    Set-Content -LiteralPath $cmd -Encoding ASCII -Value @("@call `"$bat`" x64 >nul", '@set')
    try { $lines = @(& cmd.exe /d /c $cmd) } finally { Remove-Item -LiteralPath $cmd -Force -ErrorAction SilentlyContinue }
    foreach ($line in $lines) {
        $at = "$line".IndexOf('=')
        if ($at -gt 0) { [Environment]::SetEnvironmentVariable("$line".Substring(0, $at), "$line".Substring($at + 1), 'Process') }
    }
    if (-not ($env:INCLUDE -and $env:LIB -and $env:VCToolsInstallDir)) { Fail "vcvarsall.bat x64 did not set INCLUDE, LIB and VCToolsInstallDir ($bat)" }
    Say "MSVC: $vs (VCToolsInstallDir=$env:VCToolsInstallDir)"
    if (-not ($env:LIBCLANG_PATH -and (Test-Path -LiteralPath (Join-Path $env:LIBCLANG_PATH 'libclang.dll')))) {
        foreach ($candidate in @((Join-Path $vs 'VC\Tools\Llvm\x64\bin'), (Join-Path $env:ProgramFiles 'LLVM\bin'))) {
            if (Test-Path -LiteralPath (Join-Path $candidate 'libclang.dll')) { $env:LIBCLANG_PATH = $candidate; break }
        }
    }
    if (-not $env:LIBCLANG_PATH) { Fail 'libclang.dll not found (LIBCLANG_PATH, Visual Studio''s C++ Clang tools, or LLVM): the FIPS module''s bindgen needs it' }
    Say "libclang: $env:LIBCLANG_PATH"
}

# The FIPS module's other build tools: CMake and Go from the image (Go from the
# runner's tool cache when it isn't on PATH).
function Assert-FipsTools {
    if (-not (Get-Command 'go' -ErrorAction SilentlyContinue)) {
        $roots = @(Get-ChildItem -Path Env: | Where-Object { $_.Name -match '^GOROOT_\d+_\d+_X64$' } |
                Sort-Object { [version]($_.Name -replace '^GOROOT_(\d+)_(\d+)_X64$', '$1.$2') } -Descending)
        if ($roots.Count -eq 0) { Fail 'go is not on PATH and no GOROOT_<major>_<minor>_X64 tool cache entry exists: the FIPS module''s build needs Go' }
        $env:PATH = "$(Join-Path $roots[0].Value 'bin');$env:PATH"
    }
    foreach ($tool in @('cmake', 'go', 'nasm', 'ninja')) {
        $found = Get-Command $tool -ErrorAction SilentlyContinue
        if (-not $found) { Fail "$tool is not on PATH: the FIPS module's build needs it" }
        Say "$tool -> $($found.Source)"
    }
    Say "go: $((& go version | Out-String).Trim())"
    Say "cmake: $((& cmake --version | Select-Object -First 1 | Out-String).Trim())"
}

# ---------------------------------------------------------------------------
# Keys

# A self-signed code-signing certificate for this run: RSA-3072, SHA-256, one RDN,
# basicConstraints critical CA:FALSE (Windows refuses a CA as an Authenticode signer:
# TRUST_E_BASIC_CONSTRAINTS), keyUsage digitalSignature, extendedKeyUsage codeSigning,
# valid for $Days days. The certificate and its PKCS#8 key as PEM.
function New-LabCertificate {
    param([string]$Pem, [string]$Key, [string]$CommonName, [int]$Days = 7)
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    try {
        $name = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$CommonName")
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $name, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
        $usages = [System.Security.Cryptography.OidCollection]::new()
        [void]$usages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $false))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false))
        $now = [DateTimeOffset]::UtcNow
        $certificate = $request.CreateSelfSigned($now.AddMinutes(-10), $now.AddDays($Days))
        try {
            Write-Text $Pem ($certificate.ExportCertificatePem() + "`n")
            Write-Text $Key ($rsa.ExportPkcs8PrivateKeyPem() + "`n")
            return $certificate.Thumbprint
        } finally {
            $certificate.Dispose()
        }
    } finally {
        $rsa.Dispose()
    }
}

# The certificate's extensions, read back: what Windows' Authenticode policy and
# osslsigncode need of a signer.
function Assert-LabCertificate {
    param([string]$Pem, [string]$CommonName)
    $base64 = ((Get-Content -LiteralPath $Pem) | Where-Object { $_ -notmatch '-----' }) -join ''
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($base64))
    try {
        if ($certificate.Subject -ne "CN=$CommonName") { Fail "the certificate's subject is '$($certificate.Subject)'" }
        $basic = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        if ($basic.Count -ne 1 -or -not $basic[0].Critical -or $basic[0].CertificateAuthority) {
            Fail 'the certificate must carry basicConstraints, critical, CA:FALSE'
        }
        $usage = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        if ($usage.Count -ne 1 -or -not ($usage[0].KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)) {
            Fail 'the certificate must carry keyUsage digitalSignature'
        }
        $extended = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
        if ($extended.Count -ne 1 -or -not (@($extended[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains '1.3.6.1.5.5.7.3.3')) {
            Fail 'the certificate must carry extendedKeyUsage codeSigning'
        }
        if ($certificate.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1' -or $certificate.PublicKey.GetRSAPublicKey().KeySize -ne 3072) {
            Fail 'the certificate must hold an RSA-3072 key'
        }
        Say "certificate: $($certificate.Subject), CA:FALSE (critical), codeSigning, until $($certificate.NotAfter.ToUniversalTime().ToString('u'))"
    } finally {
        $certificate.Dispose()
    }
}

# ---------------------------------------------------------------------------
# The broken release (the update lane's rolled-back upgrade)

# Gives a service .wxs a deferred custom action that fails (cmd.exe exits 1,
# Return="check") right after the service's recovery actions are set: past
# InstallServices, where an upgrade (MajorUpgrade, afterInstallInitialize) has already
# removed the installed release, so Windows Installer rolls the whole transaction back.
function Set-BrokenWxs {
    param([string]$Path)
    $action = '<CustomAction Id="LaneRollsBack" Directory="System64Folder" ExeCommand="&quot;[System64Folder]cmd.exe&quot; /c exit 1" Execute="deferred" Impersonate="no" Return="check" />'
    $custom = '<Custom Action="LaneRollsBack" After="ServiceRecoveryOnErrorExit" Condition="NOT Installed AND NOT REMOVE=&quot;ALL&quot;" />'
    $lines = [System.IO.File]::ReadAllText($Path) -split "`n"
    $patched = New-Object System.Collections.Generic.List[string]
    $placed = 0
    foreach ($line in $lines) {
        $patched.Add($line)
        $indent = ([regex]::Match($line, '^\s*')).Value
        if ($line.TrimStart().StartsWith('<CustomAction Id="ServiceRecoveryOnErrorExit"')) { $patched.Add($indent + $action); $placed++ }
        elseif ($line.TrimStart().StartsWith('<Custom Action="ServiceRecoveryOnErrorExit"')) { $patched.Add($indent + $custom); $placed++ }
    }
    if ($placed -ne 2) { Fail "${Path}: the failing custom action wasn't placed ($placed of 2 anchors: no recovery actions to follow?)" }
    Write-Text $Path ($patched -join "`n")
}

# ---------------------------------------------------------------------------
# The upgrade candidate's record

# <Dir>\lab-build.json, the format scripts/upgrade-candidate.sh writes and
# scripts/windows-upgrade-previous.ps1 checks: the build's identity, the SHA-256 of the
# CI test public key its helper trusts, and the SHA-256 of every other file under <Dir>
# by its path relative to it (forward slashes).
function Write-LabBuild {
    param([string]$Dir, [string]$Product, [string]$Package, [string]$Version, [long]$Sequence,
        [string]$Build, [string]$Token, [string]$Commit, [string]$TrustKey)
    $root = [System.IO.Path]::GetFullPath($Dir).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $names = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.FullName -ne (Join-Path $root 'lab-build.json') } |
            ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') })
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $files = [ordered]@{}
    foreach ($name in $names) { $files[$name] = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant() }
    $record = [ordered]@{
        build = $Build; commit = $Commit; files = $files; format = 1; package = $Package; platform = 'windows'
        product = $Product; sequence = $Sequence; token = $Token
        trust = (Get-FileHash -LiteralPath $TrustKey -Algorithm SHA256).Hash.ToLowerInvariant(); version = $Version
    }
    Write-Text (Join-Path $root 'lab-build.json') (($record | ConvertTo-Json -Depth 4) + "`n")
}

# ---------------------------------------------------------------------------
# Self-test

function Invoke-SelfTest {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) "seaworthy-lab-selftest-$PID"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    try {
        $pem = Join-Path $dir 'codesign.pem'
        $key = Join-Path $dir 'codesign.key'
        $thumbprint = New-LabCertificate -Pem $pem -Key $key -CommonName 'AcmeE2E Test Code Signing'
        Assert-LabCertificate -Pem $pem -CommonName 'AcmeE2E Test Code Signing'
        if (-not ((Get-Content -LiteralPath $key -Raw).StartsWith('-----BEGIN PRIVATE KEY-----'))) { Fail 'the key is not PKCS#8 PEM' }
        Say "selftest: certificate $thumbprint and its key written as PEM"

        $sample = $Wxs
        if (-not $sample) { $sample = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $Repo 'crates') 'seaworthy') 'tests') 'golden') 'wix\agent.wxs' }
        $copy = Join-Path $dir 'agent.wxs'
        Copy-Item -LiteralPath $sample -Destination $copy
        Set-BrokenWxs $copy
        $text = [System.IO.File]::ReadAllText($copy)
        if (([regex]::Matches($text, 'LaneRollsBack')).Count -ne 2) { Fail 'the broken .wxs names LaneRollsBack twice' }
        [xml]$xml = $text
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
        $custom = $xml.SelectSingleNode('//w:InstallExecuteSequence/w:Custom[@Action="LaneRollsBack"]', $ns)
        if (-not $custom -or $custom.After -ne 'ServiceRecoveryOnErrorExit') { Fail 'LaneRollsBack runs after ServiceRecoveryOnErrorExit' }
        $broken = Join-Path $dir 'none.wxs'
        Write-Text $broken "<Wix>`n</Wix>`n"
        $refused = $false
        try { Set-BrokenWxs $broken } catch { $refused = $true }
        if (-not $refused) { Fail 'a .wxs without recovery actions must be refused' }
        Say 'selftest: the broken .wxs is well-formed and fails right after the recovery actions'

        $candidate = Join-Path $dir 'candidate'
        New-Item -ItemType Directory -Force -Path (Join-Path $candidate 'packages') | Out-Null
        Write-Text (Join-Path $candidate 'packages\acmee2e-agent-0.1.0-7.msi') 'msi'
        Write-Text (Join-Path $candidate 'packages.json') '{"ci_test": true}'
        Write-Text (Join-Path $dir 'ci-test.pub') "00ff`n"
        Write-LabBuild -Dir $candidate -Product 'agent' -Package 'acmee2e-agent' -Version '0.1.0' -Sequence 7 -Build 'g0123456789ab' `
            -Token '0.1.0+g0123456789ab' -Commit '0123456789ab' -TrustKey (Join-Path $dir 'ci-test.pub')
        $record = Get-Content -LiteralPath (Join-Path $candidate 'lab-build.json') -Raw | ConvertFrom-Json
        $sha = { param([string]$Text) -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($Utf8NoBom.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) }
        if ($record.format -ne 1 -or $record.platform -ne 'windows' -or $record.sequence -ne 7 -or $record.token -ne '0.1.0+g0123456789ab') { Fail 'lab-build.json: the identity' }
        if ($record.trust -ne (& $sha "00ff`n")) { Fail 'lab-build.json: the trusted key''s SHA-256' }
        $listed = @($record.files.PSObject.Properties | ForEach-Object { $_.Name })
        if (($listed -join ',') -ne 'packages.json,packages/acmee2e-agent-0.1.0-7.msi') { Fail "lab-build.json lists $($listed -join ', ')" }
        if ($record.files.'packages/acmee2e-agent-0.1.0-7.msi' -ne (& $sha 'msi')) { Fail 'lab-build.json: a file''s SHA-256' }
        Say 'selftest: the upgrade candidate''s lab-build.json lists every file and the trusted key'

        if ((ConvertTo-TomlLiteral 'C:\a b\c.exe') -ne "'C:\a b\c.exe'") { Fail 'TOML literal quoting' }
        $refused = $false
        try { ConvertTo-TomlLiteral "C:\it's" | Out-Null } catch { $refused = $true }
        if (-not $refused) { Fail 'a quote in a TOML literal must be refused' }
        Say 'selftest: PASSED'
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Phase -eq 'SelfTest') {
    Invoke-SelfTest
    exit 0
}

# ===========================================================================
# The build
# ===========================================================================

if ($PSVersionTable.PSVersion.Major -lt 7) { Fail 'run it with PowerShell 7 (pwsh): the certificate''s PEM export needs .NET' }
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { Fail 'the build runs on Windows (-Phase SelfTest runs anywhere)' }
Set-Location -LiteralPath $Repo
$Out = Resolve-RepoPath $Out
$TargetRoot = [System.IO.Path]::GetFullPath($TargetRoot)
if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Recurse -Force }
$script:Logs = Join-Path $Out 'logs'
$Keys = Join-Path $Out 'keys'
$Bin = Join-Path $Out 'bin'
$Bundle = Join-Path $Out 'bundle'
New-Item -ItemType Directory -Force -Path $script:Logs, $Keys, $Bin, $Bundle | Out-Null
$Variant = 'non-FIPS'
if ($Fips) { $Variant = 'FIPS' }
Say "building the $Variant lab into $Out (cargo targets under $TargetRoot)"

Step 'tools'
$script:Wix = Install-Wix
Say "WiX: $($script:Wix) ($((& $script:Wix --version | Out-String).Trim()))"
$Osslsigncode = Install-Osslsigncode
if ($Fips) {
    Install-Nasm
    Enter-MsvcEnvironment
    Install-NinjaIfMissing
    Assert-FipsTools
}
Say "rustc: $((& rustc --version | Out-String).Trim())"

Step 'cli'
$WorkspaceTarget = Join-Path $TargetRoot 'ws'
Invoke-Checked 'cargo' @('build', '--release', '--locked', '--target-dir', $WorkspaceTarget, '-p', 'seaworthy', '--bin', 'seaworthy') 'building the seaworthy CLI'
$Seaworthy = Join-Path $WorkspaceTarget 'release\seaworthy.exe'
if (-not (Test-Path -LiteralPath $Seaworthy -PathType Leaf)) { Fail "no $Seaworthy" }
Say "seaworthy: $Seaworthy"

# The lanes' binaries. With -Fips they link the FIPS module, whose DLL goes beside them.
$serviceFeatures = 'runtime'
$cryptoFeatures = @()
if ($Fips) {
    $serviceFeatures = 'runtime,seaworthy-crypto/fips'
    $cryptoFeatures = @('--features', 'fips')
}
$common = @('--release', '--locked', '--target-dir', $WorkspaceTarget)
$messages = @()
$messages += Invoke-CargoJson (@('build') + $common + @('-p', 'seaworthy-service', '--features', $serviceFeatures, '--example', 'windows_scm_e2e')) 'building windows_scm_e2e'
$messages += Invoke-CargoJson (@('build') + $common + @('-p', 'seaworthy-crypto') + $cryptoFeatures + @('--example', 'entropy_probe')) 'building entropy_probe'
$messages += Invoke-CargoJson (@('test', '--no-run') + $common + @('-p', 'seaworthy-service', '--features', $serviceFeatures, '--test', 'windows_scm')) 'building the windows_scm test'
Copy-Item -LiteralPath (Get-CargoExecutable $messages 'windows_scm_e2e') -Destination (Join-Path $Bin 'windows_scm_e2e.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $messages 'entropy_probe') -Destination (Join-Path $Bin 'entropy_probe.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $messages 'windows_scm') -Destination (Join-Path $Bin 'windows_scm-test.exe')
if ($Fips) {
    $messages += Invoke-CargoJson (@('build') + $common + @('-p', 'seaworthy-crypto', '--features', 'fips', '--example', 'fips_selfcheck')) 'building fips_selfcheck'
    Copy-Item -LiteralPath (Get-CargoExecutable $messages 'fips_selfcheck') -Destination (Join-Path $Bin 'fips_selfcheck.exe')
    # The module's DLL, from the build script that built it (one set of bytes per name).
    $dirs = @($messages | Where-Object { $_.reason -eq 'build-script-executed' -and "$($_.package_id)" -match 'aws-lc-fips-sys' } |
            ForEach-Object { @($_.out_dir) + @($_.linked_paths | ForEach-Object { "$_" -replace '^[a-z]+=', '' }) } |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique)
    $dlls = @(foreach ($dir in $dirs) { Get-ChildItem -LiteralPath $dir -Recurse -File -Filter 'aws_lc_fips_*.dll' -ErrorAction SilentlyContinue })
    $byName = @($dlls | Group-Object Name)
    if (@($byName | Where-Object { $_.Name -like '*_crypto.dll' }).Count -ne 1) { Fail "expected one AWS-LC FIPS crypto DLL, found: $(@($dlls | ForEach-Object { $_.FullName }) -join ', ')" }
    foreach ($group in $byName) {
        $hashes = @($group.Group | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } | Sort-Object -Unique)
        if ($hashes.Count -ne 1) { Fail "$($group.Name): $($group.Count) builds with different bytes" }
        Copy-Item -LiteralPath $group.Group[0].FullName -Destination (Join-Path $Bin $group.Name)
        Say "FIPS module DLL: $($group.Name)"
    }
    Invoke-Checked (Join-Path $Bin 'fips_selfcheck.exe') @('--expect-fips') 'fips_selfcheck --expect-fips' -Log 'fips-selfcheck'
} else {
    $messages += Invoke-CargoJson (@('test', '--no-run') + $common + @('-p', 'seaworthy-updater', '--test', 'windows_policy_live')) 'building the windows_policy_live test'
    Copy-Item -LiteralPath (Get-CargoExecutable $messages 'windows_policy_live') -Destination (Join-Path $Bin 'windows_policy_live-test.exe')
    # The upgrade lane's lab: the TLS lab server, its throwaway CA, the foreign-key
    # manifest and the required-version client.
    $messages += Invoke-CargoJson (@('build') + $common + @('-p', 'seaworthy-lab', '--bin', 'seaworthy-lab')) 'building seaworthy-lab'
    Copy-Item -LiteralPath (Get-CargoExecutable $messages 'seaworthy-lab') -Destination (Join-Path $Bin 'seaworthy-lab.exe')
}

Step 'keys'
$CommonName = 'AcmeE2E Test Code Signing'
$CodesignPem = Join-Path $Keys 'codesign.pem'
$thumbprint = New-LabCertificate -Pem $CodesignPem -Key (Join-Path $Keys 'codesign.key') -CommonName $CommonName
Assert-LabCertificate -Pem $CodesignPem -CommonName $CommonName
Say "code-signing certificate $thumbprint"
$Signing = Join-Path $Out 'signing.toml'
$signingText = ''
$CiTestSigning = Join-Path $Out 'signing.ci-test.toml'
if (-not $Fips) {
    Invoke-Checked $Seaworthy @('keygen', '--algorithm', 'ml-dsa-87', '--secret', (Join-Path $Keys 'release.key'), '--public', (Join-Path $Keys 'release.pub')) 'seaworthy keygen'
    $signingText += "[[manifest]]`nalgorithm = `"ml-dsa-87`"`nkey = `"keys/release.key`"`n`n"
    # The fixture's public CI test key (seaworthy.toml's [defaults.ci-test-keys]): the
    # upgrade candidate's manifest signer, which its helper trusts as a CI test key.
    foreach ($name in @('ci-test.pub', 'ci-test.key')) {
        Copy-Item -LiteralPath (Join-Path $Repo "crates\seaworthy-launcher\e2e\scm\keys\$name") -Destination (Join-Path $Keys $name)
    }
    Write-Text $CiTestSigning "[[manifest]]`nalgorithm = `"ml-dsa-87`"`nkey = `"keys/ci-test.key`"`n"
}
$signingText += "[authenticode]`ncertificate = `"keys/codesign.pem`"`nkey = `"keys/codesign.key`"`ntool = $(ConvertTo-TomlLiteral $Osslsigncode)`n"
Write-Text $Signing $signingText

Step 'build'
# The lab's products, beside the keys their seaworthy.toml names.
$configName = 'seaworthy.toml'
if ($Fips) { $configName = 'seaworthy-fips.toml' }
$ScmConfig = Join-Path $Out 'seaworthy.toml'
Copy-Item -LiteralPath (Join-Path $Repo "crates\seaworthy-launcher\e2e\scm\$configName") -Destination $ScmConfig
if (-not $Fips) {
    # The agent's files (lab\build.txt: `unreleased`, until the upgrade step writes its
    # candidate's token).
    Copy-Item -LiteralPath (Join-Path $Repo 'crates\seaworthy-launcher\e2e\scm\lab') -Destination (Join-Path $Out 'lab') -Recurse
}
Invoke-Checked $Seaworthy @('check', '--config', $ScmConfig) 'seaworthy check (the lab''s products)'
$DesktopConfig = Join-Path $Repo 'crates\seaworthy-launcher\e2e\desktop\seaworthy.toml'

# One configuration's build plan, carried out by the template's Windows build step in
# its work directory (<work>\artifacts), every target directory under $TargetRoot.
function Build-Products {
    param([string]$Config, [string]$Work)
    New-Item -ItemType Directory -Force -Path $Work | Out-Null
    $plan = @(& $Seaworthy build-plan --config $Config --triple $Triple --manifest $FixtureManifest)
    if ($LASTEXITCODE -ne 0) { Fail "seaworthy build-plan failed for $Config (exit $LASTEXITCODE)" }
    foreach ($line in $plan) { Say "plan| $line" }
    $planFile = Join-Path $Work "plan-$Triple.tsv"
    Write-Text $planFile (($plan -join "`n") + "`n")
    Copy-Item -LiteralPath $planFile -Destination (Join-Path $script:Logs ("plan-{0}.tsv" -f (Split-Path -Leaf $Work)))
    $env:SEAWORTHY_WORK = $Work
    $env:SEAWORTHY_MANIFEST = $FixtureManifest
    $env:SEAWORTHY_TARGET_DIR = $TargetRoot
    if ($Fips) { $env:SEAWORTHY_CARGO_ARGS = '--features fips' } else { Remove-Item Env:\SEAWORTHY_CARGO_ARGS -ErrorAction SilentlyContinue }
    # In this PowerShell (the script keeps Windows PowerShell 5.1's syntax for the GitLab
    # template; a 5.1 child of PowerShell 7 would inherit 7's module path).
    & (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $Repo 'scripts\ci\seaworthy-build.ps1') | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail "scripts\ci\seaworthy-build.ps1 failed for $Config (exit $LASTEXITCODE)" }
    return (Join-Path $Work 'artifacts')
}

# The update helper compiles the lab's seaworthy.toml and release key in.
$env:SEAWORTHY_E2E_HELPER_CONFIG = $ScmConfig
if (-not $Fips) { $env:SEAWORTHY_E2E_HELPER_RELEASE_KEY = Join-Path $Keys 'release.pub' }
$ScmArtifacts = Build-Products -Config $ScmConfig -Work (Join-Path $Out 'scm')
$DesktopArtifacts = $null
if (-not $Fips) { $DesktopArtifacts = Build-Products -Config $DesktopConfig -Work (Join-Path $Out 'desktop') }

Step 'package'
# One release of one product into <Out>\releases\<Name>; its packages directory. With
# -NoWix, the .wxs only. -Signed: a release (manifests by the run's release key);
# -CiTest: a dev build (the run's Authenticode signature, manifests by the public CI test
# key, which `repo` refuses to publish).
function Invoke-Package {
    param([string]$Config, [string]$Artifacts, [string]$Name, [string]$Product, [string]$Version, [long]$Sequence, [string]$Build, [switch]$Signed, [switch]$CiTest, [switch]$NoWix)
    $dest = Join-Path (Join-Path $Out 'releases') $Name
    # Without -Build the release's version token is its version alone (what the update
    # lane's gate answers).
    $arguments = @('package', '--config', $Config, '--artifacts', $Artifacts, '--out', $dest, '--product', $Product,
        '--release', $Version, '--sequence', "$Sequence", '--platforms', 'windows')
    if ($Build) { $arguments += @('--build', $Build) }
    if ($Signed) { $arguments += @('--signing', $Signing) }
    if ($CiTest) { $arguments += @('--signing', $Signing, '--authenticode-only', '--ci-test-signing', $CiTestSigning) }
    if ($NoWix) { Remove-Item Env:\SEAWORTHY_WIX -ErrorAction SilentlyContinue } else { $env:SEAWORTHY_WIX = $script:Wix }
    try {
        Invoke-Checked $Seaworthy $arguments "seaworthy package ($Product $Version-$Sequence)" -Log "package-$Name"
    } finally {
        Remove-Item Env:\SEAWORTHY_WIX -ErrorAction SilentlyContinue
    }
    $packages = Join-Path (Join-Path $dest $Product) 'packages'
    foreach ($item in @(Get-ChildItem -LiteralPath $packages -File)) { Say "  $Name| $($item.Name) ($($item.Length) bytes)" }
    return $packages
}

# Windows Installer's validation (the ICEs): an error fails the build, warnings print.
# On a copy: the MSI is already signed, with a manifest naming its digest, and
# validation merges the ICE database into what it validates.
function Test-Msi([string]$Msi) {
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($Msi)
    $copy = Join-Path $script:Logs "$stem.validate.msi"
    Copy-Item -LiteralPath $Msi -Destination $copy -Force
    try {
        Invoke-Checked $script:Wix @('msi', 'validate', $copy) "Windows Installer's validation of $(Split-Path -Leaf $Msi)" -Log "validate-$stem"
    } finally {
        Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }
}

function Get-Single([string]$Dir, [string]$Filter) {
    $found = @(Get-ChildItem -LiteralPath $Dir -File -Filter $Filter)
    if ($found.Count -ne 1) { Fail "expected one $Filter in $Dir, found $($found.Count)" }
    return $found[0].FullName
}

# Copies a release's packages directory into the bundle as <Name>\packages.
function Add-ToBundle([string]$Packages, [string]$Name) {
    $dest = Join-Path (Join-Path $Bundle $Name) 'packages'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    # Not the layout's marker file.
    foreach ($item in @(Get-ChildItem -LiteralPath $Packages -File | Where-Object { -not $_.Name.StartsWith('.') })) {
        Copy-Item -LiteralPath $item.FullName -Destination $dest
    }
}

$scm = Invoke-Package -Config $ScmConfig -Artifacts $ScmArtifacts -Name 'scm' -Product 'scm' -Version '1.0.0' -Sequence 1 -Signed
Test-Msi (Get-Single $scm '*.msi')
Add-ToBundle $scm 'scm'
if (-not $Fips) {
    foreach ($release in @(@('agent-rc1', '1.0.0-rc.1', 1), @('agent-v1', '1.0.0', 2))) {
        $packages = Invoke-Package -Config $ScmConfig -Artifacts $ScmArtifacts -Name $release[0] -Product 'agent' -Version $release[1] -Sequence $release[2] -Signed
        $msi = Get-Single $packages '*.msi'
        Test-Msi $msi
        if (-not (Test-Path -LiteralPath "$msi.manifest" -PathType Leaf)) { Fail "$msi has no signed manifest beside it" }
        Add-ToBundle $packages $release[0]
    }
    # 1.0.1, whose install fails late: the signed tree and its .wxs, broken, built by WiX
    # directly (unsigned: the lane installs it by hand).
    $bad = Invoke-Package -Config $ScmConfig -Artifacts $ScmArtifacts -Name 'agent-bad' -Product 'agent' -Version '1.0.1' -Sequence 3 -Signed -NoWix
    $badWxs = Get-Single $bad '*.wxs'
    Set-BrokenWxs $badWxs
    $tree = Join-Path (Join-Path (Join-Path (Join-Path $Out 'releases') 'agent-bad') 'agent') "$Triple\tree"
    $msi = [System.IO.Path]::ChangeExtension($badWxs, '.msi')
    $pdb = Join-Path $script:Logs 'agent-bad.wixpdb'
    Push-Location -LiteralPath $tree
    try {
        Invoke-Checked $script:Wix @('build', '-arch', 'x64', '-nologo', '-bindpath', "tree=$tree", '-pdb', $pdb, '-o', $msi, $badWxs) 'wix build (agent 1.0.1, broken)' -Log 'wix-agent-bad'
    } finally {
        Pop-Location
    }
    Test-Msi $msi
    Add-ToBundle $bad 'agent-bad'
    Say "agent 1.0.1's .wxs fails its install after InstallServices (the rolled-back upgrade)"

    foreach ($release in @(@('viewer-1', '1.0.0', 1), @('viewer-2', '1.0.1', 2))) {
        $packages = Invoke-Package -Config $DesktopConfig -Artifacts $DesktopArtifacts -Name $release[0] -Product 'viewer' -Version $release[1] -Sequence $release[2]
        Test-Msi (Get-Single $packages '*.msi')
        Add-ToBundle $packages $release[0]
    }
    $lite = Invoke-Package -Config $DesktopConfig -Artifacts $DesktopArtifacts -Name 'viewer-lite-1' -Product 'viewer-lite' -Version '1.0.0' -Sequence 1
    Test-Msi (Get-Single $lite '*.msi')
    Add-ToBundle $lite 'viewer-lite-1'
    # Programs and Features' icon, as the layout staged it (the install lane compares
    # Windows Installer's cached copy with it).
    $icon = Join-Path (Join-Path (Join-Path $Out 'releases') 'viewer-1') "viewer\$Triple\tree\Acme\Viewer.ico"
    if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) { Fail "the layout staged no $icon" }
    Copy-Item -LiteralPath $icon -Destination (Join-Path (Join-Path $Bundle 'viewer-1') 'icon.ico')
}

if (-not $Fips) {
    Step 'upgrade'
    if ($UpgradeSequence -notmatch '^[1-9][0-9]{0,9}$') { Fail "-UpgradeSequence '$UpgradeSequence' isn't a release sequence" }
    # The workspace's version, through a crate that inherits it.
    $labVersion = (& $Seaworthy manifest-version --manifest (Join-Path $Repo 'crates\seaworthy-lab\Cargo.toml') | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $labVersion) { Fail "seaworthy manifest-version failed (exit $LASTEXITCODE)" }
    $labCommit = (& git -C $Repo rev-parse --short=12 HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $labCommit -notmatch '^[0-9a-f]{12,40}$') { Fail "git rev-parse --short=12 HEAD answered '$labCommit'" }
    $labBuild = "g$labCommit"
    $labToken = "$labVersion+$labBuild"
    $labSequence = [long]$UpgradeSequence
    # The installed files name the build (lab\build.txt, the agent's files).
    Write-Text (Join-Path $Out 'lab\build.txt') "$labToken`n"
    # The helper trusts the run's release key and, as a CI test build does, the CI test
    # key: through ci_test_keys! under the CI test-key switch, set for this build alone
    # (a dev build; seaworthy-build.ps1 refuses the switch on a release). It dials the
    # lab's names only (scm_helper/build.rs refuses any other URL); everything else is
    # the same build.
    $env:SEAWORTHY_E2E_HELPER_RELEASE_KEY = Join-Path $Keys 'release.pub'
    $env:SEAWORTHY_E2E_HELPER_CI_TEST_KEY = Join-Path $Keys 'ci-test.pub'
    $env:SEAWORTHY_ALLOW_CI_TEST_KEYS = '1'
    $env:SEAWORTHY_E2E_HELPER_PACKAGE_URL = "https://$LabPackagesHost/repo/releases/{product}/{channel}/{version}/{target}/{product}.{format}"
    $env:SEAWORTHY_E2E_HELPER_VERSION_URL = "https://$LabUpdatesHost/_lab/required-version"
    try {
        $upgradeArtifacts = Build-Products -Config $ScmConfig -Work (Join-Path $Out 'upgrade-build')
    } finally {
        foreach ($name in @('SEAWORTHY_E2E_HELPER_RELEASE_KEY', 'SEAWORTHY_E2E_HELPER_CI_TEST_KEY', 'SEAWORTHY_ALLOW_CI_TEST_KEYS',
                'SEAWORTHY_E2E_HELPER_PACKAGE_URL', 'SEAWORTHY_E2E_HELPER_VERSION_URL')) {
            Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue
        }
    }
    # The candidate's helper carries the CI test-key marker (it trusts a CI test key),
    # which `seaworthy verify` accepts in a --ci-test-signing build alone.
    $helper = Get-ChildItem -LiteralPath $upgradeArtifacts -Recurse -File -Filter 'scm_helper.exe' | Select-Object -First 1
    if (-not $helper) { Fail "the upgrade build made no scm_helper.exe under $upgradeArtifacts" }
    if (-not (Test-FileContains $helper.FullName ('seaworthy-ci-test-keys' + ':trusted:1'))) {
        Fail "$($helper.FullName) doesn't carry the CI test-key marker: built without the switch?"
    }
    Say "the candidate's helper trusts the CI test key (it carries the CI test-key marker)"
    $packages = Invoke-Package -Config $ScmConfig -Artifacts $upgradeArtifacts -Name 'agent-upgrade' -Product 'agent' `
        -Version $labVersion -Sequence $labSequence -Build $labBuild -CiTest
    $msi = Get-Single $packages '*.msi'
    Test-Msi $msi
    if (-not (Test-Path -LiteralPath "$msi.manifest" -PathType Leaf)) { Fail "$msi has no manifest beside it" }
    $listingFile = Join-Path (Split-Path -Parent $packages) 'packages.json'
    $listing = Get-Content -LiteralPath $listingFile -Raw | ConvertFrom-Json
    if (-not ($listing.PSObject.Properties.Name -contains 'ci_test') -or $listing.ci_test -ne $true) { Fail "$listingFile isn't a CI test build's listing" }
    if ($listing.token -ne $labToken -or $listing.sequence -ne $labSequence) { Fail "$listingFile names $($listing.token) (sequence $($listing.sequence)), not $labToken ($labSequence)" }
    $UpgradeCandidate = Join-Path $Out 'upgrade-candidate'
    New-Item -ItemType Directory -Force -Path (Join-Path $UpgradeCandidate 'packages') | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $packages -File | Where-Object { -not $_.Name.StartsWith('.') })) {
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $UpgradeCandidate 'packages')
    }
    Copy-Item -LiteralPath $listingFile -Destination (Join-Path $UpgradeCandidate 'packages.json')
    Write-LabBuild -Dir $UpgradeCandidate -Product 'agent' -Package $listing.package -Version $labVersion -Sequence $labSequence `
        -Build $labBuild -Token $labToken -Commit $labCommit -TrustKey (Join-Path $Keys 'ci-test.pub')
    Copy-Item -LiteralPath $UpgradeCandidate -Destination (Join-Path $Bundle 'upgrade') -Recurse
    Say "upgrade candidate: $($listing.package) $labToken (sequence $labSequence), signed by the CI test key, in $UpgradeCandidate"
}

Step 'bundle'
Copy-Item -LiteralPath $CodesignPem -Destination (Join-Path $Bundle 'codesign.pem')
New-Item -ItemType Directory -Force -Path (Join-Path $Bundle 'bin') | Out-Null
foreach ($item in @(Get-ChildItem -LiteralPath $Bin -File)) { Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $Bundle 'bin') }
$commit = (& git -C $Repo rev-parse HEAD | Out-String).Trim()
$manifest = New-Object System.Collections.Generic.List[string]
$manifest.Add("seaworthy Windows lab bundle ($Variant)")
$manifest.Add("commit: $commit")
$manifest.Add("rustc: $((& rustc --version | Out-String).Trim())")
$manifest.Add("wix: $((& $script:Wix --version | Out-String).Trim())")
$manifest.Add("osslsigncode: $((& $Osslsigncode --version | Select-Object -First 1 | Out-String).Trim())")
$manifest.Add('files (SHA-256):')
foreach ($file in @(Get-ChildItem -LiteralPath $Bundle -Recurse -File | Sort-Object FullName)) {
    $relative = $file.FullName.Substring($Bundle.Length + 1)
    $manifest.Add(('  {0}  {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative))
}
Write-Text (Join-Path $Bundle 'manifest.txt') (($manifest -join "`n") + "`n")
Get-Content -LiteralPath (Join-Path $Bundle 'manifest.txt') | ForEach-Object { Write-Host $_ }
Say "PASSED: the $Variant bundle is $Bundle"
