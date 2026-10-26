# scripts/ci/seaworthy-msi.ps1 - the GitLab CI template's MSI job: WiX on
# the Windows runner builds each product's .wxs, which `seaworthy package`
# wrote on Linux beside the signed Windows tree, into an MSI, and validates
# it (Windows Installer's ICEs).
# The MSI leaves unsigned: the template's adopt job (`seaworthy adopt-msi`,
# on Linux) checks its payload against the signed tree, signs it, and lists
# it with its manifest and SBOM.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File seaworthy\scripts\seaworthy-msi.ps1
#
# Reads <work>\dist\<product>\packages\*.wxs and <work>\dist\<product>\
# x86_64-pc-windows-msvc\tree (the package job's artifacts); writes
# <work>\msi\<product>\<stem>-windows-x86_64.msi. A product without an msi
# output has no .wxs and is skipped.
#
# WiX: v5.0.2 (MS-RL, the last release without the Open Source Maintenance
# Fee), installed from its pinned MSI (https, bounded, SHA-256 checked)
# unless the image already carries that version. Every ICE error fails the
# job (none is suppressed; warnings are printed).
#
# Windows PowerShell 5.1 (the runner's shell): no PS 7 syntax.
[CmdletBinding()]
param(
    [string]$Work = $(if ($env:SEAWORTHY_WORK) { $env:SEAWORTHY_WORK } else { 'seaworthy' }),
    [string]$WixMsiUrl = 'https://github.com/wixtoolset/wix/releases/download/v5.0.2/wix-cli-x64.msi',
    [string]$WixMsiSha256 = '097383B2773BDD3D76A6A2CD3F4DE6357BAE59172E1B6FA5AD87CE062074E8D0',
    [string]$WixVersion = '5.0.2'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$Why) { throw "seaworthy-msi: FAIL: $Why" }
function Say([string]$What) { Write-Host "seaworthy-msi: $What" }

# A release never builds binaries that trust the product's CI test keys:
# seaworthy-formats' switch (1 turns it on) must be off on a release
# (SEAWORTHY_RELEASE=1, the templates' release rule).
if ($env:SEAWORTHY_RELEASE -eq '1' -and $env:SEAWORTHY_ALLOW_CI_TEST_KEYS -and $env:SEAWORTHY_ALLOW_CI_TEST_KEYS -ne '0') {
    Fail "SEAWORTHY_ALLOW_CI_TEST_KEYS is '$($env:SEAWORTHY_ALLOW_CI_TEST_KEYS)' on a release: a release never trusts the CI test keys (unset it, or set it to 0)"
}

# The pinned wix.exe: the image's, or installed from the pinned MSI.
function Get-Wix {
    $found = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        $found += @(Get-ChildItem -LiteralPath $root -Directory -Filter 'WiX Toolset*' -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path (Join-Path $_.FullName 'bin') 'wix.exe' } |
            Where-Object { Test-Path -LiteralPath $_ })
    }
    foreach ($candidate in $found) {
        $version = (& $candidate --version 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $version.StartsWith("$WixVersion+")) { return $candidate }
    }
    $msi = Join-Path ([IO.Path]::GetTempPath()) 'wix-cli-x64.msi'
    # https only (redirects too), bounded in time and size, through Windows'
    # own curl.exe (Windows 10 1803 and Server 2019 on): Invoke-WebRequest
    # bounds neither the size nor the whole transfer. The pin decides.
    if (-not $WixMsiUrl.StartsWith('https://', [StringComparison]::Ordinal)) { Fail "-WixMsiUrl must be an https URL, not $WixMsiUrl" }
    $curlExe = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path -LiteralPath $curlExe -PathType Leaf)) { Fail "no $curlExe to download WiX with (Windows 10 1803 and Server 2019 on ship it)" }
    if (Test-Path -LiteralPath $msi) { Remove-Item -LiteralPath $msi -Force }
    & $curlExe --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 `
        --connect-timeout 30 --max-time 600 --max-filesize 134217728 --output $msi $WixMsiUrl
    if ($LASTEXITCODE -ne 0) { Fail "downloading $WixMsiUrl failed (curl.exe exit $LASTEXITCODE)" }
    $hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
    if ($hash -ne $WixMsiSha256.ToUpperInvariant()) { Fail "wix-cli-x64.msi has SHA-256 $hash, not the pinned $WixMsiSha256" }
    # msiexec's own process, not Start-Process -Wait (which waits on every
    # descendant through a job object).
    $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(600000)) { $p.Kill(); Fail 'installing WiX took longer than 10 minutes' }
    if ($p.ExitCode -notin @(0, 3010)) { Fail "installing WiX failed (msiexec exit $($p.ExitCode))" }
    $installed = @(Get-ChildItem -LiteralPath $env:ProgramFiles -Directory -Filter 'WiX Toolset*' |
        ForEach-Object { Join-Path (Join-Path $_.FullName 'bin') 'wix.exe' } | Where-Object { Test-Path -LiteralPath $_ })
    if ($installed.Count -ne 1) { Fail "expected one wix.exe under $env:ProgramFiles\WiX Toolset*\bin, found $($installed.Count)" }
    $version = (& $installed[0] --version | Out-String).Trim()
    if (-not $version.StartsWith("$WixVersion+")) { Fail "the installed WiX is $version, not $WixVersion" }
    return $installed[0]
}

$dist = Join-Path $Work 'dist'
if (-not (Test-Path -LiteralPath $dist -PathType Container)) { Fail "no $dist (from the package job)" }
$out = Join-Path $Work 'msi'
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
$wix = $null
$built = 0
foreach ($product in @(Get-ChildItem -LiteralPath $dist -Directory | Sort-Object Name)) {
    if (-not (Test-Path -LiteralPath (Join-Path $product.FullName 'packages.json'))) { continue }
    $packages = Join-Path $product.FullName 'packages'
    $sources = @(Get-ChildItem -LiteralPath $packages -Filter '*.wxs' -File -ErrorAction SilentlyContinue)
    if ($sources.Count -eq 0) { continue }
    if ($sources.Count -ne 1) { Fail "$packages holds $($sources.Count) .wxs files, not one" }
    $tree = Join-Path (Join-Path $product.FullName 'x86_64-pc-windows-msvc') 'tree'
    if (-not (Test-Path -LiteralPath $tree -PathType Container)) { Fail "no $tree beside $($sources[0].Name)" }
    if (-not $wix) { $wix = Get-Wix; Say "WiX: $wix" }
    $dir = Join-Path $out $product.Name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $msi = Join-Path $dir ($sources[0].BaseName + '.msi')
    & $wix build -arch x64 -bindpath "tree=$tree" -o $msi $sources[0].FullName
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $msi)) { Fail "wix build failed for $($product.Name) (exit $LASTEXITCODE)" }
    # The .wixpdb beside it gives validation source lines; it doesn't ship.
    & $wix msi validate $msi
    if ($LASTEXITCODE -ne 0) { Fail "Windows Installer's validation (ICE) refused $($product.Name)'s MSI (exit $LASTEXITCODE)" }
    Remove-Item -LiteralPath ([IO.Path]::ChangeExtension($msi, '.wixpdb')) -Force -ErrorAction SilentlyContinue
    Say "$($product.Name): $msi"
    $built++
}
Say "$built MSI(s) built and validated"
