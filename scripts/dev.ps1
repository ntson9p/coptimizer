<#
.SYNOPSIS
Runs COptimizer from source in demo mode: a simulated PC that needs no
Administrator rights and reads nothing real. Opens the page in your browser.
Extra arguments are passed on, e.g. scripts\dev.ps1 -no-browser
#>
$repo = Split-Path -Parent $PSScriptRoot
go -C $repo run ./cmd/coptimizer -demo @args
exit $LASTEXITCODE
