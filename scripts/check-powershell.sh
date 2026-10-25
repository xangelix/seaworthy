#!/usr/bin/env bash
# scripts/check-powershell.sh — every tracked PowerShell script, parsed by
# PowerShell's own parser, checked by a small AST rule set, and (with
# PSScriptAnalyzer installed) checked against Windows PowerShell 5.1's
# syntax, the default `powershell` shell of Windows images and CI runners.
#
# These scripts otherwise run only on a Windows machine, where a syntax
# error costs a CI round trip. Needs `pwsh` (PowerShell 7) on PATH.
#
#   scripts/check-powershell.sh      # exit 0 clean, 1 findings, 2 no pwsh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
command -v pwsh >/dev/null 2>&1 || { echo "check-powershell: pwsh not found" >&2; exit 2; }
mapfile -t files < <(git ls-files --cached --others --exclude-standard -- '*.ps1')
[ "${#files[@]}" -gt 0 ] || { echo "check-powershell: no PowerShell scripts"; exit 0; }
exec pwsh -NoProfile -NonInteractive -File scripts/lib/check-powershell.ps1 "${files[@]}"
