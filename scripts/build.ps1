<#
.SYNOPSIS
Builds dist\coptimizer.exe, stamped with the version from git.
#>
$repo = Split-Path -Parent $PSScriptRoot
$version = git -C $repo describe --tags --always --dirty 2>$null
if ($LASTEXITCODE -ne 0 -or -not $version) { $version = 'dev' }
$out = Join-Path $repo 'dist\coptimizer.exe'

Push-Location $repo
try {
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o $out ./cmd/coptimizer
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($code -eq 0) { Write-Host "Built $out ($version)" }
exit $code
