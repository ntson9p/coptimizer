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

.PARAMETER UI
After the Go tests, build the exe and run the browser tests in e2e\ against
coptimizer -demo. Needs Node.js and an installed Chrome.

.PARAMETER Race
Run the tests with Go's race detector, skipping the slowest ones (-short).
It needs a C compiler for cgo, as GitHub's Windows runners have.

.PARAMETER Cover
Measure which statements the tests run, counting the tests of every package,
and fail if a package falls below its minimum (docs/testing.md, section 8).
#>
param(
    [switch]$Smoke,
    [switch]$Elevated,
    [switch]$UI,
    [switch]$Race,
    [switch]$Cover
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$onCI = ($env:GITHUB_ACTIONS -eq 'true') -and ($env:RUNNER_ENVIRONMENT -eq 'github-hosted')

if ($Elevated -and -not $Smoke) { throw '-Elevated only works together with -Smoke.' }
if ($Elevated -and -not $isAdmin) { throw '-Smoke -Elevated needs an Administrator terminal.' }
if ($Smoke -and ($Race -or $Cover)) { throw '-Race and -Cover are for the normal tests, not -Smoke.' }
if ($isAdmin -and -not $onCI -and -not $Elevated) {
    throw 'Refusing to run tests as Administrator. Open a normal terminal and run scripts\test.ps1 again.'
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'Go was not found on PATH. Install the version named in go.mod.'
}

# The share of statements the tests must run, per package, counting the tests
# of every package. The deleter and the deny list aim at every line; what they
# can't reach in a test is the fuses' code for the real app and system calls
# that can't be made to fail safely.
$minimumCoverage = [ordered]@{
    'internal/clean'   = 99
    'internal/actions' = 98
    'internal/safety'  = 95
    'internal/rules'   = 95
    'internal/scan'    = 92
    'internal/winfs'   = 85
    'internal/server'  = 85
    'internal/store'   = 85
}

# Test-Coverage reads a coverage profile and checks the minimums. Blocks that
# several test binaries report count as run if any of them ran them.
function Test-Coverage([string]$file) {
    $blocks = @{}
    foreach ($line in (Get-Content -LiteralPath $file)) {
        if ($line -match '^(.+):(\d+\.\d+,\d+\.\d+) (\d+) (\d+)$') {
            $key = "$($Matches[1]):$($Matches[2])"
            if (-not $blocks.ContainsKey($key)) {
                $blocks[$key] = [pscustomobject]@{ File = $Matches[1]; Statements = [int]$Matches[3]; Run = $false }
            }
            if ([long]$Matches[4] -gt 0) { $blocks[$key].Run = $true }
        }
    }
    $total = @{}
    $run = @{}
    foreach ($b in $blocks.Values) {
        $pkg = $b.File.Substring(0, $b.File.LastIndexOf('/')) -replace '^github\.com/ntson9p/coptimizer/', ''
        $total[$pkg] += $b.Statements
        if ($b.Run) { $run[$pkg] += $b.Statements }
    }
    $failed = 0
    Write-Host 'Coverage, counting the tests of every package:'
    foreach ($pkg in ($total.Keys | Sort-Object)) {
        $pct = [math]::Floor(1000 * [double]$run[$pkg] / $total[$pkg]) / 10
        $note = ''
        if ($minimumCoverage.Contains($pkg)) {
            $note = "(minimum $($minimumCoverage[$pkg])%)"
            if ($pct -lt $minimumCoverage[$pkg]) {
                $note += ' TOO LOW'
                $failed++
            }
        }
        Write-Host ('  {0,-22} {1,5:N1}% {2}' -f $pkg, $pct, $note)
    }
    if ($failed -gt 0) { return 1 }
    return 0
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
            $code = $LASTEXITCODE
        } else {
            $goArgs = @('test', '-count=1')
            if ($Race) {
                $env:CGO_ENABLED = '1'
                $goArgs += '-race', '-short'
            }
            $coverFile = Join-Path $tmp 'cover.out'
            if ($Cover) { $goArgs += '-coverpkg=./internal/...', "-coverprofile=$coverFile" }
            & go @goArgs ./...
            $code = $LASTEXITCODE
            if ($code -eq 0 -and $Cover) { $code = Test-Coverage $coverFile }
        }
    }
    if ($code -eq 0 -and $UI) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'build.ps1')
        $code = $LASTEXITCODE
    }
    if ($code -eq 0 -and $UI) {
        Push-Location (Join-Path $repo 'e2e')
        try {
            if (-not (Test-Path 'node_modules')) {
                # Keep npm's download cache inside the repo too.
                npm ci --no-audit --no-fund --cache (Join-Path $tmp 'npm-cache')
            }
            if ($LASTEXITCODE -eq 0) { node --test }
            $code = $LASTEXITCODE
        } finally {
            Pop-Location
        }
    }
} finally {
    Pop-Location
}
exit $code
