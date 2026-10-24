<#
.SYNOPSIS
Runs COptimizer's tests so that they cannot change the real system.

.DESCRIPTION
Refuses to run as Administrator, except for -Smoke -Elevated (read-only smoke
tests) and GitHub-hosted CI runners, which are thrown away after each run.
Test sandboxes are created in <repo>\.tmp, never in the system temp folder.
See docs/testing.md.

.PARAMETER Smoke
Run only the read-only smoke tests against the real system.

.PARAMETER Elevated
With -Smoke: also run the smoke tests that need Administrator rights.
#>
param(
    [switch]$Smoke,
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$onCI = ($env:GITHUB_ACTIONS -eq 'true') -and ($env:RUNNER_ENVIRONMENT -eq 'github-hosted')

if ($Elevated -and -not $Smoke) { throw '-Elevated only works together with -Smoke.' }
if ($Elevated -and -not $isAdmin) { throw '-Smoke -Elevated needs an Administrator terminal.' }
if ($isAdmin -and -not $onCI -and -not $Elevated) {
    throw 'Refusing to run tests as Administrator. Open a normal terminal and run scripts\test.ps1 again.'
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'Go was not found on PATH. Install the version named in go.mod.'
}

$tmp = Join-Path $repo '.tmp'
New-Item -ItemType Directory -Force $tmp | Out-Null
$env:TMP = $tmp
$env:TEMP = $tmp
$env:GOTMPDIR = $tmp

$code = 0
Push-Location $repo
try {
    $unformatted = @(gofmt -l .)
    if ($unformatted.Count -gt 0) {
        Write-Host 'These files need gofmt:'
        $unformatted | ForEach-Object { Write-Host "  $_" }
        $code = 1
    }
    if ($code -eq 0) {
        go vet ./...
        $code = $LASTEXITCODE
    }
    if ($code -eq 0) {
        if ($Smoke) {
            if ($Elevated) { $env:COPTIMIZER_SMOKE_ELEVATED = '1' }
            go test -count=1 -tags smoke -run Smoke ./...
        } else {
            go test -count=1 ./...
        }
        $code = $LASTEXITCODE
    }
} finally {
    Pop-Location
}
exit $code
