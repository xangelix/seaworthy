<#
.SYNOPSIS
    Parses PowerShell scripts with PowerShell's own parser, applies the AST rules
    below and, when PSScriptAnalyzer is installed, checks them against Windows
    PowerShell 5.1's syntax (the default `powershell` shell on Windows). Driven by
    scripts/check-powershell.sh.

.DESCRIPTION
    Rules:
      - parse errors, as PowerShell itself reports them;
      - a variable assigned (or used as a foreach variable) under a different
        spelling of a script parameter or script-level variable: names ignore case,
        so `$helper = ...` inside a function silently replaces the script's `$Helper`;
      - with PSScriptAnalyzer: PSUseCompatibleSyntax for Windows PowerShell 5.1.

    Exit code: 0 clean, 1 findings.
#>
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Files)
$ErrorActionPreference = 'Stop'
$bad = 0
foreach ($file in $Files) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $file).Path, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) {
        Write-Host ('{0}:{1}: {2}' -f $file, $e.Extent.StartLineNumber, $e.Message)
        $bad++
    }
    # Variable names are case-insensitive: a step's `$helper = ...` replaces
    # the script's `$Helper` for the rest of that step. Assigning a script
    # parameter or script-level variable under another spelling is that
    # mistake.
    $params = @()
    if ($ast.ParamBlock) { $params += @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
    $params += @($ast.FindAll({
                param($n)
                if ($n -isnot [System.Management.Automation.Language.AssignmentStatementAst] -or
                    $n.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $false }
                $scope = $n.Parent
                while ($scope -isnot [System.Management.Automation.Language.ScriptBlockAst]) { $scope = $scope.Parent }
                $scope -eq $ast
            }, $true) | ForEach-Object { $_.Left.VariablePath.UserPath })
    $params = @($params | Sort-Object -Unique -CaseSensitive)
    $targets = @($ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.AssignmentStatementAst] -or
                $n -is [System.Management.Automation.Language.ForEachStatementAst]
            }, $true) | ForEach-Object {
            if ($_ -is [System.Management.Automation.Language.ForEachStatementAst]) { $_.Variable } else { $_.Left }
        } | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] })
    foreach ($v in $targets) {
        $name = $v.VariablePath.UserPath
        foreach ($p in $params) {
            if ($name -ieq $p -and $name -cne $p) {
                Write-Host ('{0}:{1}: ${2} replaces the script''s ${3} (variable names ignore case): rename it' -f $file, $v.Extent.StartLineNumber, $name, $p)
                $bad++
            }
        }
    }
}
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    $settings = @{
        IncludeRules = @('PSUseCompatibleSyntax')
        Rules        = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') } }
    }
    foreach ($file in $Files) {
        foreach ($d in @(Invoke-ScriptAnalyzer -Path $file -Settings $settings)) {
            Write-Host ('{0}:{1}: {2} ({3})' -f $file, $d.Line, $d.Message, $d.RuleName)
            $bad++
        }
    }
    $mode = 'parsed + Windows PowerShell 5.1 syntax'
} else {
    $mode = 'parsed only (Install-Module PSScriptAnalyzer adds the Windows PowerShell 5.1 syntax check)'
}
if ($bad -gt 0) {
    Write-Host "check-powershell: $bad finding(s)"
    exit 1
}
Write-Host "check-powershell: $($Files.Count) scripts clean ($mode)"
