# scripts/windows-msi-install.ps1 - the Windows lab's MSI install lane
# (.github/workflows/lab-windows.yml, job `install`): the desktop fixture's MSI
# (crates/seaworthy-launcher/e2e/desktop/seaworthy.toml's viewer), built by
# `seaworthy package` with WiX on the build job (scripts/windows-lab-build.ps1),
# installed by Windows Installer for everyone and for the current user, launched,
# upgraded and removed; and the command-line viewer-lite's PATH entry, both ways.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-msi-install.ps1 -Bundle <bundle>
#
# Both MSIs install for either scope (`[product.<id>.msi] install-scope = "either"`): a
# plain msiexec /i installs for the current user, ALLUSERS=1 MSIINSTALLPERUSER="" for
# everyone. Steps, each a JUnit case (target\junit\windows-msi\windows-msi.xml):
#   install    msiexec /i of release 1.0.0 (bundle\viewer-1) for everyone: the launcher,
#              its cores and the data files where the layout put them under Program Files;
#              the all-users Start-menu and desktop shortcuts to the launcher, started in the
#              install directory; one Programs and Features entry (its install location
#              recorded), Windows Installer's cached copy of the product's icon
#              (ProductIcon) beside it; Windows Error Reporting's exclusion of demo.exe
#              under HKLM, of the kind and value WerAddExcludedApplication writes; the
#              document type under HKLM\SOFTWARE\Classes: .acmeview's ProgID, content
#              type and OpenWithProgids, the ProgID's icon and its open and inspect
#              verbs starting the launcher with the file after --, and `assoc` naming it
#   launch     the installed launcher picks a core and runs it (core=...); the launcher
#              carries its own icon and manifest (e2e/demo's build.rs), so Windows'
#              loader checks the tree the version stamp rebuilt
#   upgrade    release 1.0.1 (bundle\viewer-2, the same product packaged again) installed
#              over the first, for everyone again (Windows Installer upgrades within the
#              installed scope): one entry, the newer version, the files and shortcuts in place
#   remove     msiexec /x: the files, the install directory, the shortcuts, the entry, the
#              shortcuts' registry values and the WER exclusion gone
#   user       msiexec /i of release 1.0.0 with nothing set: installed for the current user
#              alone (%LocalAppData%\Programs, the user's Start menu and desktop, the entry,
#              the WER exclusion and the document type under HKCU, nothing under Program
#              Files or HKLM), the launcher runs, and msiexec /x removes all of it
#   path       viewer-lite 1.0.0 (bundle\viewer-lite-1) for the current user: its directory
#              appended to the user's PATH (HKCU\Environment), the launcher found through it;
#              then for everyone: appended to the system PATH; each entry gone on removal
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

# The Programs and Features entries of a product (by display name), for everyone and for
# the current user. PowerShell unrolls a function's array on return (one entry arrives as
# a scalar, none as $null), and Windows PowerShell 5.1's strict mode has no .Count for
# either: every caller takes @(Get-Entries).
function Get-Entries([string]$Name = $DisplayName, [string[]]$Roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')) {
    @(foreach ($root in $Roots) {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if ($p -and ($p.PSObject.Properties.Name -contains 'DisplayName') -and $p.DisplayName -eq $Name) {
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

# Where an install for everyone (machine) and one for the current user (user) put things.
$Scopes = @{
    machine = [pscustomobject]@{
        InstallDir = Join-Path $env:ProgramFiles "$Vendor\$Directory"
        StartMenu  = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$DisplayName.lnk"
        Desktop    = Join-Path $env:PUBLIC "Desktop\$DisplayName.lnk"
        Uninstall  = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
        Hive       = 'HKLM:'
        Classes    = 'HKLM:\SOFTWARE\Classes'
        Arguments  = @('ALLUSERS=1', 'MSIINSTALLPERUSER=""')
    }
    user    = [pscustomobject]@{
        InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$Vendor\$Directory"
        StartMenu  = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$DisplayName.lnk"
        Desktop    = Join-Path ([Environment]::GetFolderPath('Desktop')) "$DisplayName.lnk"
        Uninstall  = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
        Hive       = 'HKCU:'
        Classes    = 'HKCU:\Software\Classes'
        Arguments  = @()
    }
}
$shortcutKey = "HKCU:\SOFTWARE\$Vendor\$Directory"
$werKey = 'Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
$shell = New-Object -ComObject WScript.Shell

# Windows' own writer of a WER exclusion, to compare what the MSI wrote with.
Add-Type -Namespace SeaworthyLab -Name Wer -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wer.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int WerAddExcludedApplication(string exeName, bool allUsers);
[System.Runtime.InteropServices.DllImport("wer.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int WerRemoveExcludedApplication(string exeName, bool allUsers);
'@

# A registry value's kind and data, or $null when it isn't there.
function Get-Value([string]$Key, [string]$Name) {
    $item = Get-Item -LiteralPath $Key -ErrorAction SilentlyContinue
    if (-not $item -or -not ($item.GetValueNames() -contains $Name)) { return $null }
    return [pscustomobject]@{ Kind = $item.GetValueKind($Name); Data = $item.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') }
}

# demo.exe's WER exclusion in `Hive`, checked against what WerAddExcludedApplication writes
# for another name in the user's hive.
function Assert-WerExcluded([string]$Hive) {
    $ours = Get-Value "$Hive\$werKey" "$Executable.exe"
    Assert-True ($null -ne $ours) "$Hive\$werKey has $Executable.exe (Windows Error Reporting's exclusion)"
    $probe = 'seaworthy-lab-probe.exe'
    $hr = [SeaworthyLab.Wer]::WerAddExcludedApplication($probe, $false)
    Assert-True ($hr -eq 0) "WerAddExcludedApplication($probe) returned $hr"
    try {
        $theirs = Get-Value "HKCU:\$werKey" $probe
        Assert-True ($null -ne $theirs) "WerAddExcludedApplication wrote HKCU:\$werKey\$probe"
        Assert-True ($ours.Kind -eq $theirs.Kind -and "$($ours.Data)" -eq "$($theirs.Data)") "the MSI's exclusion is $($ours.Kind) $($ours.Data), WerAddExcludedApplication's $($theirs.Kind) $($theirs.Data)"
    } finally {
        $null = [SeaworthyLab.Wer]::WerRemoveExcludedApplication($probe, $false)
    }
}
# Programs and Features' icon as the layout staged it (tree\<Vendor>\<Directory>.ico).
$treeIcon = Join-Path (Join-Path $Bundle "$Product-1") 'icon.ico'

function Assert-Installed([string]$Version, [string]$Scope = 'machine') {
    $at = $Scopes[$Scope]
    $installDir = $at.InstallDir
    $launcher = Join-Path $installDir "$Executable.exe"
    foreach ($relative in @("$Executable.exe", 'demo_core_x86-64-v4.dll', 'demo_core_x86-64-v3.dll', 'demo_core_x86-64-v2.dll', 'share\readme.txt', 'share\fonts\demo.txt')) {
        Assert-True (Test-Path -LiteralPath (Join-Path $installDir $relative) -PathType Leaf) "$relative is installed under $installDir"
    }
    foreach ($link in @($at.StartMenu, $at.Desktop)) {
        Assert-True (Test-Path -LiteralPath $link -PathType Leaf) "the shortcut $link exists"
        $shortcut = $shell.CreateShortcut($link)
        Assert-True ($shortcut.TargetPath -eq $launcher) "$link targets $launcher (it targets $($shortcut.TargetPath))"
        Assert-True ($shortcut.WorkingDirectory.TrimEnd('\') -eq $installDir) "$link starts in $installDir (it starts in $($shortcut.WorkingDirectory))"
    }
    $entries = @(Get-Entries -Roots $at.Uninstall)
    Assert-True ($entries.Count -eq 1) "one Programs and Features entry named $DisplayName for $Scope (found $($entries.Count))"
    Assert-True (@(Get-Entries).Count -eq 1) "no other entry named $DisplayName in either scope"
    Assert-True ($entries[0].Version -eq $Version) "the entry is version $Version (it is $($entries[0].Version))"
    Assert-True ($entries[0].Location.TrimEnd('\') -eq $installDir) "the entry's install location is $installDir (it is '$($entries[0].Location)')"
    # Programs and Features' icon: an MSI's Uninstall key carries no DisplayIcon;
    # Windows Installer caches ARPPRODUCTICON's Icon table entry and registers it as the
    # product's ProductIcon.
    $icon = [string](Get-ProductInfo $entries[0].Code 'ProductIcon') -replace ',-?\d+$', ''
    Assert-True ($icon -and (Test-Path -LiteralPath $icon -PathType Leaf)) "the product's icon (ProductIcon, from ARPPRODUCTICON) is registered and cached (it is '$icon')"
    Assert-True ((Get-FileHash -LiteralPath $icon).Hash -eq (Get-FileHash -LiteralPath $treeIcon).Hash) "the cached icon $icon is the package's ($treeIcon)"
    Assert-WerExcluded $at.Hive
    Assert-FileType $Scope
    $other = @{ machine = 'user'; user = 'machine' }[$Scope]
    Assert-True (-not (Test-Path -LiteralPath $Scopes[$other].InstallDir)) "nothing is installed where an install for $other would go ($($Scopes[$other].InstallDir))"
    if ($Scope -eq 'user') {
        Assert-True ($null -eq (Get-Value "HKLM:\$werKey" "$Executable.exe")) 'a per-user install writes no machine-wide WER exclusion'
    }
    return $entries[0]
}

# The viewer's document type (`[[product.viewer.file-types]]`), registered in `Scope`'s
# Classes: the extension's ProgID, content type and OpenWithProgids entry, the ProgID's
# icon (the installed .ico) and verbs (the launcher, the file in quotes after --).
$DocExtension = '.acmeview'
$DocProgId = 'Acme.ViewerDocument'
function Assert-FileType([string]$Scope) {
    $at = $Scopes[$Scope]
    $launcher = Join-Path $at.InstallDir "$Executable.exe"
    $classes = $at.Classes
    $expected = @(
        @("$classes\$DocExtension", '', $DocProgId),
        @("$classes\$DocExtension", 'Content Type', 'application/x-acme-viewer-doc'),
        @("$classes\$DocProgId", '', 'Acme Viewer document'),
        @("$classes\$DocProgId\DefaultIcon", '', "`"$(Join-Path $at.InstallDir "$DocProgId.ico")`",0"),
        @("$classes\$DocProgId\shell", '', 'open'),
        @("$classes\$DocProgId\shell\open\command", '', "`"$launcher`" -- `"%1`""),
        @("$classes\$DocProgId\shell\inspect\command", '', "`"$launcher`" --inspect -- `"%1`"")
    )
    foreach ($row in $expected) {
        $value = Get-Value $row[0] $row[1]
        Assert-True ($null -ne $value -and "$($value.Data)" -eq $row[2]) "$($row[0]) [$($row[1])] is '$(if ($value) { $value.Data })', not '$($row[2])'"
    }
    Assert-True ($null -ne (Get-Value "$classes\$DocExtension\OpenWithProgids" $DocProgId)) "$DocExtension\OpenWithProgids lists $DocProgId"
    Assert-True (Test-Path -LiteralPath (Join-Path $at.InstallDir "$DocProgId.ico") -PathType Leaf) "the document icon is installed"
    $assoc = (& cmd.exe /d /c "assoc $DocExtension" | Out-String).Trim()
    Assert-True ($assoc -eq "$DocExtension=$DocProgId") "assoc $DocExtension says '$assoc'"
    $other = @{ machine = 'user'; user = 'machine' }[$Scope]
    Assert-True (-not (Test-Path -LiteralPath "$($Scopes[$other].Classes)\$DocProgId")) "nothing registers $DocProgId in $($Scopes[$other].Classes)"
}

# The product's removal: everything the install put in `Scope` gone.
function Assert-Removed([string]$Scope) {
    $at = $Scopes[$Scope]
    Assert-True (-not (Test-Path -LiteralPath $at.InstallDir)) "$($at.InstallDir) is gone"
    foreach ($link in @($at.StartMenu, $at.Desktop)) { Assert-True (-not (Test-Path -LiteralPath $link)) "$link is gone" }
    Assert-True (@(Get-Entries).Count -eq 0) 'no Programs and Features entry is left'
    $left = Get-ItemProperty -LiteralPath $shortcutKey -ErrorAction SilentlyContinue
    Assert-True (-not $left -or -not ($left.PSObject.Properties.Name -contains 'StartMenuShortcut')) 'the shortcuts registry values are gone'
    Assert-True ($null -eq (Get-Value "$($at.Hive)\$werKey" "$Executable.exe")) "the WER exclusion in $($at.Hive) is gone"
    foreach ($key in @("$($at.Classes)\$DocProgId", "$($at.Classes)\$DocExtension")) {
        Assert-True (-not (Test-Path -LiteralPath $key)) "$key is gone"
    }
}

# The launcher at `Path` picks a core and runs it.
function Invoke-Launcher([string]$Path) {
    # Windows PowerShell 5.1 turns a native program's stderr line into a terminating
    # error under 'Stop': a failing launcher's own message is kept instead, and its exit
    # code decides.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $output = & $Path 2>&1 | Out-String } finally { $ErrorActionPreference = $previous }
    Assert-True ($LASTEXITCODE -eq 0) "$Path exited $LASTEXITCODE`n$output"
    Assert-True ($output -match 'core=x86-64-v[234]') "$Path ran a core:`n$output"
    Write-Log "launcher: $($output.Trim())"
}

# The PATH entries of `Hive`'s environment (the system's for HKLM, the user's for HKCU).
function Get-PathEntries([string]$Hive) {
    $key = if ($Hive -eq 'HKLM:') { 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' } else { 'HKCU:\Environment' }
    $value = Get-Value $key 'Path'
    if ($null -eq $value) { return @() }
    return @("$($value.Data)" -split ';' | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') })
}

$first = $null
$second = $null

Invoke-Step 'install' {
    $script:first = Get-Release "$Product-1"
    $script:second = Get-Release "$Product-2"
    Assert-True (Test-Path -LiteralPath $treeIcon -PathType Leaf) "the bundle carries the layout's icon ($treeIcon)"
    foreach ($scope in @('machine', 'user')) {
        Assert-True (-not (Test-Path -LiteralPath $Scopes[$scope].InstallDir)) "$($Scopes[$scope].InstallDir) doesn't exist before the install"
    }
    $code = Invoke-Msiexec (@('/i', "`"$($script:first.Msi)`"") + $Scopes.machine.Arguments) (Join-Path $Evidence 'install.log')
    Assert-True ($code -eq 0) "msiexec /i (for everyone) exited $code"
    $null = Assert-Installed $script:first.Version 'machine'
    Assert-True ((Get-ItemProperty -LiteralPath $shortcutKey).StartMenuShortcut -eq 1) 'the Start-menu shortcut keys on its HKCU value'
}

Invoke-Step 'launch' {
    Invoke-Launcher (Join-Path $Scopes.machine.InstallDir "$Executable.exe")
}

Invoke-Step 'upgrade' {
    Assert-True ([version]$script:second.Version -gt [version]$script:first.Version) "the second release ($($script:second.Version)) is newer than the first ($($script:first.Version))"
    $code = Invoke-Msiexec (@('/i', "`"$($script:second.Msi)`"") + $Scopes.machine.Arguments) (Join-Path $Evidence 'upgrade.log')
    Assert-True ($code -eq 0) "msiexec /i of the upgrade exited $code"
    $null = Assert-Installed $script:second.Version 'machine'
}

Invoke-Step 'remove' {
    $entries = @(Get-Entries)
    Assert-True ($entries.Count -eq 1) 'one entry to remove'
    $code = Invoke-Msiexec @('/x', $entries[0].Code) (Join-Path $Evidence 'remove.log')
    Assert-True ($code -eq 0) "msiexec /x exited $code"
    Assert-Removed 'machine'
}

Invoke-Step 'user' {
    $code = Invoke-Msiexec (@('/i', "`"$($script:first.Msi)`"") + $Scopes.user.Arguments) (Join-Path $Evidence 'install-user.log')
    Assert-True ($code -eq 0) "msiexec /i (for the current user) exited $code"
    $entry = Assert-Installed $script:first.Version 'user'
    Invoke-Launcher (Join-Path $Scopes.user.InstallDir "$Executable.exe")
    $code = Invoke-Msiexec @('/x', $entry.Code) (Join-Path $Evidence 'remove-user.log')
    Assert-True ($code -eq 0) "msiexec /x (for the current user) exited $code"
    Assert-Removed 'user'
}

Invoke-Step 'path' {
    $lite = Get-Release 'viewer-lite-1'
    foreach ($scope in @('user', 'machine')) {
        $dir = Join-Path $(if ($scope -eq 'user') { Join-Path $env:LOCALAPPDATA 'Programs' } else { $env:ProgramFiles }) "$Vendor\ViewerLite"
        $hive = $Scopes[$scope].Hive
        Assert-True (-not ((Get-PathEntries $hive) -contains $dir)) "$dir isn't on $hive's PATH before the install"
        $code = Invoke-Msiexec (@('/i', "`"$($lite.Msi)`"") + $Scopes[$scope].Arguments) (Join-Path $Evidence "install-lite-$scope.log")
        Assert-True ($code -eq 0) "msiexec /i of viewer-lite ($scope) exited $code"
        $entries = @(Get-PathEntries $hive)
        Assert-True ($entries -contains $dir) "$dir is on $hive's PATH: $($entries -join ';')"
        Assert-True ($entries[-1] -eq $dir) "$dir is appended, last on $hive's PATH: $($entries -join ';')"
        $other = @{ HKLM = 'HKCU:'; HKCU = 'HKLM:' }[$hive.TrimEnd(':')]
        Assert-True (-not ((Get-PathEntries $other) -contains $dir)) "$dir isn't on $other's PATH"
        # A new process finds the launcher by name through that PATH.
        $env:Path = (@(Get-PathEntries 'HKLM:') + @(Get-PathEntries 'HKCU:')) -join ';'
        $found = (Get-Command "$Executable.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
        Assert-True ($found -and $found.Source -eq (Join-Path $dir "$Executable.exe")) "$Executable.exe is found on PATH in $dir (found '$(if ($found) { $found.Source })')"
        $entry = @(Get-Entries -Name 'Acme Viewer Lite')
        Assert-True ($entry.Count -eq 1) "one viewer-lite entry ($scope)"
        $code = Invoke-Msiexec @('/x', $entry[0].Code) (Join-Path $Evidence "remove-lite-$scope.log")
        Assert-True ($code -eq 0) "msiexec /x of viewer-lite ($scope) exited $code"
        Assert-True (-not ((Get-PathEntries $hive) -contains $dir)) "$dir is off $hive's PATH after the removal"
    }
}

Write-JUnit
$failed = @($Results | Where-Object { $_.Failure -and -not $_.Skipped })
Write-Host ''
Write-Host "windows-msi: $($Results.Count) steps, $($failed.Count) failed -- JUnit: $(Join-Path $JUnit 'windows-msi.xml')"
if ($failed.Count -gt 0) { exit 1 }
