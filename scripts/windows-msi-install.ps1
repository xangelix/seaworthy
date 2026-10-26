# scripts/windows-msi-install.ps1 - the Windows lab's MSI install lane
# (.github/workflows/lab-windows.yml, job `install`): the desktop fixture's MSI
# (crates/seaworthy-launcher/e2e/desktop/seaworthy.toml's viewer), built by
# `seaworthy package` with WiX on the build job (scripts/windows-lab-build.ps1),
# installed by Windows Installer, launched, upgraded and removed.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-msi-install.ps1 -Bundle <bundle>
#
# Steps, each a JUnit case (target\junit\windows-msi\windows-msi.xml):
#   install    msiexec /i of release 1.0.0 (bundle\viewer-1): the launcher, its cores and
#              the data files where the layout put them; the Start-menu and desktop
#              shortcuts to the launcher, started in the install directory; one Programs
#              and Features entry (its install location recorded), Windows Installer's
#              cached copy of the product's icon (ProductIcon) beside it
#   launch     the installed launcher picks a core and runs it (core=...); the launcher
#              carries its own icon and manifest (e2e/demo's build.rs), so Windows'
#              loader checks the tree the version stamp rebuilt
#   upgrade    release 1.0.1 (bundle\viewer-2, the same product packaged again) installed
#              over the first: one entry, the newer version, the files and shortcuts in place
#   remove     msiexec /x: the files, the install directory, the shortcuts, the entry and
#              the shortcuts' registry values gone
# The MSIs are unsigned (the fixture names no Authenticode identity), as Windows
# Installer allows. A throwaway machine: it installs and removes a product. Windows
# PowerShell 5.1 or PowerShell 7.
[CmdletBinding()]
param(
    [string]$Bundle = $(if ($env:SEAWORTHY_LAB_BUNDLE) { $env:SEAWORTHY_LAB_BUNDLE } else { 'target\windows-lab\bundle' }),
    [string]$Product = 'viewer',
    [string]$DisplayName = 'Acme Viewer',
    [string]$Vendor = 'Acme',
    [string]$Directory = 'Viewer',
    [string]$Executable = 'demo',
    [string]$JUnitDir = $(if ($env:SEAWORTHY_JUNIT_DIR) { $env:SEAWORTHY_JUNIT_DIR } else { 'target\junit\windows-msi' }),
    [string]$EvidenceDir = $(if ($env:SEAWORTHY_EVIDENCE_DIR) { $env:SEAWORTHY_EVIDENCE_DIR } else { 'target\windows-msi' })
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Results = New-Object System.Collections.Generic.List[object]
New-Item -ItemType Directory -Force -Path $JUnitDir, $EvidenceDir | Out-Null
$JUnit = (Resolve-Path -LiteralPath $JUnitDir).Path
$Evidence = (Resolve-Path -LiteralPath $EvidenceDir).Path

function Write-Log([string]$Text) { Write-Host ("{0:HH:mm:ss.fff} {1}" -f (Get-Date), $Text) }
function Assert-True([bool]$Condition, [string]$Why) { if (-not $Condition) { throw "ASSERTION FAILED: $Why" } }

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
    [void]$xml.AppendLine("<testsuite name=`"windows-msi`" tests=`"$($Results.Count)`" failures=`"$failures`" skipped=`"$skipped`">")
    foreach ($r in $Results) {
        $name = [Security.SecurityElement]::Escape($r.Name)
        [void]$xml.Append("  <testcase classname=`"windows-msi`" name=`"$name`" time=`"$([Math]::Round($r.Seconds, 3).ToString($inv))`"")
        if ($r.Skipped) { [void]$xml.AppendLine('><skipped/></testcase>') }
        elseif ($r.Failure) { [void]$xml.AppendLine("><failure message=`"$([Security.SecurityElement]::Escape(($r.Failure -split "`n")[0]))`">$([Security.SecurityElement]::Escape($r.Failure))</failure></testcase>") }
        else { [void]$xml.AppendLine('/>') }
    }
    [void]$xml.AppendLine('</testsuite>')
    [IO.File]::WriteAllText((Join-Path $JUnit 'windows-msi.xml'), $xml.ToString())
}

# msiexec's own process, its log kept as evidence (not Start-Process -Wait, which waits
# on every descendant through a job object).
function Invoke-Msiexec([string[]]$Arguments, [string]$Log) {
    $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', "`"$Log`"")) -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(900000)) { $p.Kill(); throw "msiexec $($Arguments -join ' ') took longer than 15 minutes" }
    return $p.ExitCode
}

# The Programs and Features entries of this product (by display name). PowerShell
# unrolls a function's array on return (one entry arrives as a scalar, none as $null),
# and Windows PowerShell 5.1's strict mode has no .Count for either: every caller takes
# @(Get-Entries).
function Get-Entries {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    @(foreach ($root in $roots) {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if ($p -and ($p.PSObject.Properties.Name -contains 'DisplayName') -and $p.DisplayName -eq $DisplayName) {
                    $location = if ($p.PSObject.Properties.Name -contains 'InstallLocation') { [string]$p.InstallLocation } else { '' }
                    [pscustomobject]@{ Code = $_.PSChildName; Version = $p.DisplayVersion; Location = $location }
                }
            }
        })
}

# What Windows Installer itself records of a product (MsiGetProductInfo), through its
# automation object.
$installer = New-Object -ComObject WindowsInstaller.Installer
function Get-ProductInfo([string]$Code, [string]$Property) {
    $installer.GetType().InvokeMember('ProductInfo', [Reflection.BindingFlags]::GetProperty, $null, $installer, @($Code, $Property))
}

# One release's MSI and the ProductVersion its .wxs names.
function Get-Release([string]$Name) {
    $packages = Join-Path (Join-Path $Bundle $Name) 'packages'
    $msi = @(Get-ChildItem -LiteralPath $packages -Filter '*.msi' -File -ErrorAction SilentlyContinue)
    Assert-True ($msi.Count -eq 1) "one MSI under $packages (found $($msi.Count))"
    $wxs = @(Get-ChildItem -LiteralPath $packages -Filter '*.wxs' -File)
    Assert-True ($wxs.Count -eq 1) "the .wxs beside $($msi[0].Name)"
    $version = ([regex]::Match([IO.File]::ReadAllText($wxs[0].FullName), '<Package [^>]* Version="([0-9.]+)"')).Groups[1].Value
    Assert-True ([bool]$version) "$($wxs[0].Name) names a ProductVersion"
    return [pscustomobject]@{ Msi = $msi[0].FullName; Version = $version }
}

$installDir = Join-Path $env:ProgramFiles "$Vendor\$Directory"
$launcher = Join-Path $installDir "$Executable.exe"
$startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$DisplayName.lnk"
$desktop = Join-Path $env:PUBLIC "Desktop\$DisplayName.lnk"
$shortcutKey = "HKCU:\SOFTWARE\$Vendor\$Directory"
$shell = New-Object -ComObject WScript.Shell
# Programs and Features' icon as the layout staged it (tree\<Vendor>\<Directory>.ico).
$treeIcon = Join-Path (Join-Path $Bundle "$Product-1") 'icon.ico'

function Assert-Installed([string]$Version) {
    foreach ($relative in @("$Executable.exe", 'demo_core_x86-64-v4.dll', 'demo_core_x86-64-v3.dll', 'demo_core_x86-64-v2.dll', 'share\readme.txt', 'share\fonts\demo.txt')) {
        Assert-True (Test-Path -LiteralPath (Join-Path $installDir $relative) -PathType Leaf) "$relative is installed under $installDir"
    }
    foreach ($link in @($startMenu, $desktop)) {
        Assert-True (Test-Path -LiteralPath $link -PathType Leaf) "the shortcut $link exists"
        $shortcut = $shell.CreateShortcut($link)
        Assert-True ($shortcut.TargetPath -eq $launcher) "$link targets $launcher (it targets $($shortcut.TargetPath))"
        Assert-True ($shortcut.WorkingDirectory.TrimEnd('\') -eq $installDir) "$link starts in $installDir (it starts in $($shortcut.WorkingDirectory))"
    }
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) "one Programs and Features entry named $DisplayName (found $($entries.Count))"
    Assert-True ($entries[0].Version -eq $Version) "the entry is version $Version (it is $($entries[0].Version))"
    Assert-True ($entries[0].Location.TrimEnd('\') -eq $installDir) "the entry's install location is $installDir (it is '$($entries[0].Location)')"
    # Programs and Features' icon: an MSI's Uninstall key carries no DisplayIcon;
    # Windows Installer caches ARPPRODUCTICON's Icon table entry and registers it as the
    # product's ProductIcon.
    $icon = [string](Get-ProductInfo $entries[0].Code 'ProductIcon') -replace ',-?\d+$', ''
    Assert-True ($icon -and (Test-Path -LiteralPath $icon -PathType Leaf)) "the product's icon (ProductIcon, from ARPPRODUCTICON) is registered and cached (it is '$icon')"
    Assert-True ((Get-FileHash -LiteralPath $icon).Hash -eq (Get-FileHash -LiteralPath $treeIcon).Hash) "the cached icon $icon is the package's ($treeIcon)"
    return $entries[0]
}

$first = $null
$second = $null

Invoke-Step 'install' {
    $script:first = Get-Release "$Product-1"
    $script:second = Get-Release "$Product-2"
    Assert-True (Test-Path -LiteralPath $treeIcon -PathType Leaf) "the bundle carries the layout's icon ($treeIcon)"
    Assert-True (-not (Test-Path -LiteralPath $installDir)) "$installDir doesn't exist before the install"
    $code = Invoke-Msiexec @('/i', "`"$($script:first.Msi)`"") (Join-Path $Evidence 'install.log')
    Assert-True ($code -eq 0) "msiexec /i exited $code"
    $null = Assert-Installed $script:first.Version
    Assert-True ((Get-ItemProperty -LiteralPath $shortcutKey).StartMenuShortcut -eq 1) 'the Start-menu shortcut keys on its HKCU value'
}

Invoke-Step 'launch' {
    # Windows PowerShell 5.1 turns a native program's stderr line into a terminating
    # error under 'Stop': a failing launcher's own message is kept instead, and its exit
    # code decides.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $output = & $launcher 2>&1 | Out-String } finally { $ErrorActionPreference = $previous }
    Assert-True ($LASTEXITCODE -eq 0) "the launcher exited $LASTEXITCODE`n$output"
    Assert-True ($output -match 'core=x86-64-v[234]') "the launcher ran a core:`n$output"
    Write-Log "launcher: $($output.Trim())"
}

Invoke-Step 'upgrade' {
    Assert-True ([version]$script:second.Version -gt [version]$script:first.Version) "the second release ($($script:second.Version)) is newer than the first ($($script:first.Version))"
    $code = Invoke-Msiexec @('/i', "`"$($script:second.Msi)`"") (Join-Path $Evidence 'upgrade.log')
    Assert-True ($code -eq 0) "msiexec /i of the upgrade exited $code"
    $null = Assert-Installed $script:second.Version
}

Invoke-Step 'remove' {
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) 'one entry to remove'
    $code = Invoke-Msiexec @('/x', $entries[0].Code) (Join-Path $Evidence 'remove.log')
    Assert-True ($code -eq 0) "msiexec /x exited $code"
    Assert-True (-not (Test-Path -LiteralPath $installDir)) "$installDir is gone"
    foreach ($link in @($startMenu, $desktop)) { Assert-True (-not (Test-Path -LiteralPath $link)) "$link is gone" }
    Assert-True (@(Get-Entries).Count -eq 0) 'no Programs and Features entry is left'
    $left = Get-ItemProperty -LiteralPath $shortcutKey -ErrorAction SilentlyContinue
    Assert-True (-not $left -or -not ($left.PSObject.Properties.Name -contains 'StartMenuShortcut')) 'the shortcuts registry values are gone'
}

Write-JUnit
$failed = @($Results | Where-Object { $_.Failure -and -not $_.Skipped })
Write-Host ''
Write-Host "windows-msi: $($Results.Count) steps, $($failed.Count) failed -- JUnit: $(Join-Path $JUnit 'windows-msi.xml')"
if ($failed.Count -gt 0) { exit 1 }
