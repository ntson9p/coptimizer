<#
.SYNOPSIS
Destructive tests: real cleanups by the real exe, on a disposable machine only.

.DESCRIPTION
Does nothing unless COPTIMIZER_DESTRUCTIVE=1. Then it refuses to run unless
the machine is disposable, which is a GitHub-hosted runner
(GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted) or a virtual
machine with the marker file C:\COPTIMIZER_DISPOSABLE_VM, and unless it has
Administrator rights.

It puts junk in the user's npm cache, temp folder and Recycle Bin, and a
junction inside the npm cache that leads to a canary folder. Then it drives
dist\coptimizer.exe -serve through its HTTP API, as the page does: scan C:,
preview each cleanup, run it. It checks that the junk is gone, that the canary
and recent temp files survive, that free space grew, and that the history
records every cleanup. See docs/testing.md, section 5.
#>
$ErrorActionPreference = 'Stop'

if ($env:COPTIMIZER_DESTRUCTIVE -ne '1') {
    Write-Host 'Destructive tests skipped: COPTIMIZER_DESTRUCTIVE is not 1.'
    exit 0
}
$onRunner = ($env:GITHUB_ACTIONS -eq 'true') -and ($env:RUNNER_ENVIRONMENT -eq 'github-hosted')
if (-not ($onRunner -or (Test-Path 'C:\COPTIMIZER_DISPOSABLE_VM'))) {
    throw 'Refusing to run destructive tests: this is not a disposable machine.'
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The destructive tests need Administrator rights, as COptimizer itself does.'
}

$repo = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repo 'dist\coptimizer.exe'
$data = Join-Path $repo '.tmp\destructive-data'
$mb = 1MB

function Fail([string]$msg) { throw "FAILED: $msg" }

function New-Junk([string]$dir, [int]$files, [int]$sizeMB, [TimeSpan]$age) {
    New-Item -ItemType Directory -Force $dir | Out-Null
    $bytes = New-Object byte[] ($sizeMB * $mb)
    (New-Object Random 7).NextBytes($bytes)
    for ($i = 0; $i -lt $files; $i++) {
        $p = Join-Path $dir ("junk{0:D3}.bin" -f $i)
        [IO.File]::WriteAllBytes($p, $bytes)
        if ($age -gt [TimeSpan]::Zero) {
            $when = (Get-Date).Subtract($age)
            $item = Get-Item -LiteralPath $p
            $item.CreationTime = $when
            $item.LastWriteTime = $when
        }
    }
}

# The junk, and what must survive.
$local = $env:LOCALAPPDATA
$npmJunk = Join-Path $local 'npm-cache\_cacache\coptimizer-junk'
$tempJunk = Join-Path $local 'Temp\coptimizer-junk'
$tempFresh = Join-Path $local 'Temp\coptimizer-fresh.tmp'
$canaryDir = Join-Path $env:USERPROFILE 'coptimizer-canary'
$canary = Join-Path $canaryDir 'keep.txt'
$link = Join-Path $local 'npm-cache\_cacache\link-to-canary'

Write-Host 'Creating junk…'
New-Junk $npmJunk 30 10 ([TimeSpan]::Zero)                 # 300 MB: npm's finding starts at 200 MB
New-Junk $tempJunk 40 10 ([TimeSpan]::FromDays(3))         # 400 MB, old enough to clean
[IO.File]::WriteAllText($tempFresh, 'recent: must stay')
New-Item -ItemType Directory -Force $canaryDir | Out-Null
[IO.File]::WriteAllText($canary, 'must survive the cleanup')
New-Item -ItemType Junction -Path $link -Target $canaryDir | Out-Null

Add-Type -AssemblyName Microsoft.VisualBasic
$binDir = Join-Path $env:USERPROFILE 'coptimizer-bin-junk'
New-Junk $binDir 15 10 ([TimeSpan]::Zero)                  # 150 MB: the Recycle Bin's finding starts at 100 MB
foreach ($f in Get-ChildItem -LiteralPath $binDir -File) {
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($f.FullName, 'OnlyErrorDialogs', 'SendToRecycleBin')
}

# The server, started as the launcher would, with a known one-time code.
$port = 18765
$code = 'c0de' + (Get-Random -Maximum 99999999)
$base = "http://127.0.0.1:$port"
$log = Join-Path $repo '.tmp\destructive-server.log'
New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null
$server = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $log `
    -ArgumentList "-serve -port $port -launch-code $code -instance destructive -no-browser -data-dir `"$data`""
try {
    for ($i = 0; ; $i++) {
        try { Invoke-RestMethod "$base/healthz" | Out-Null; break } catch {
            if ($i -gt 150) { Fail 'the server did not start' }
            Start-Sleep -Milliseconds 200
        }
    }
    $token = (Invoke-RestMethod -Method Post "$base/api/session" -ContentType 'application/json' -Body (@{ code = $code } | ConvertTo-Json)).token
    $h = @{ Authorization = "Bearer $token" }
    $status = Invoke-RestMethod "$base/api/status" -Headers $h
    if (-not $status.elevated -or -not $status.cleanups -or $status.simulate) { Fail "unexpected status: $($status | ConvertTo-Json -Compress)" }

    Write-Host 'Scanning C:…'
    $started = Get-Date
    $scan = Invoke-RestMethod -Method Post "$base/api/scans" -Headers $h -ContentType 'application/json' -Body '{"drives":["C:\\"]}'
    do {
        Start-Sleep -Seconds 5
        $scan = Invoke-RestMethod "$base/api/scans/$($scan.id)" -Headers $h
        if (((Get-Date) - $started).TotalMinutes -gt 25) { Fail 'the scan took too long' }
    } while ($scan.state -eq 'running')
    if ($scan.state -ne 'done') { Fail "scan: $($scan.state) $($scan.error)" }
    Write-Host ("Scanned {0:N0} files in {1:N0} s" -f $scan.summary.files, ((Get-Date) - $started).TotalSeconds)

    $report = Invoke-RestMethod "$base/api/scans/$($scan.id)/findings" -Headers $h
    foreach ($id in 'dev.npm-cache', 'personal.temp', 'personal.recycle-bin') {
        if (-not ($report.findings | Where-Object id -eq $id)) { Fail "no $id finding" }
    }

    foreach ($case in @(
            @{ Rule = 'dev.npm-cache'; Min = 290 * $mb },
            @{ Rule = 'personal.temp'; Min = 390 * $mb },
            @{ Rule = 'personal.recycle-bin'; Min = 140 * $mb })) {
        $plan = Invoke-RestMethod -Method Post "$base/api/plans" -Headers $h -ContentType 'application/json' -Body (@{ ruleId = $case.Rule } | ConvertTo-Json)
        if ($plan.blocked) { Fail "$($case.Rule): blocked: $($plan.blocked) $($plan.running -join ',')" }
        if ($plan.bytes -lt $case.Min) { Fail ("{0}: the preview expects {1:N0} bytes; the junk alone is {2:N0}" -f $case.Rule, $plan.bytes, $case.Min) }
        $job = Invoke-RestMethod -Method Post "$base/api/jobs" -Headers $h -ContentType 'application/json' -Body (@{ planId = $plan.id } | ConvertTo-Json)
        do {
            Start-Sleep -Seconds 1
            $job = Invoke-RestMethod "$base/api/jobs/$($job.id)" -Headers $h
        } while ($job.state -eq 'queued' -or $job.state -eq 'running')
        # Other programs may hold some temp files open: partial is fine there.
        if ($job.state -ne 'succeeded' -and -not ($job.state -eq 'partial' -and $case.Rule -eq 'personal.temp')) {
            Fail "$($case.Rule): $($job.state) $($job.error)"
        }
        Write-Host ("{0}: {1}, expected {2:N0} MB, freed {3:N0} MB, deleted {4:N0} files" -f `
                $case.Rule, $job.state, ($plan.bytes / $mb), ($job.freed / $mb), $job.outcome.files)
        if ($job.freed -lt $case.Min * 0.8) { Fail ("{0}: free space grew by only {1:N0} bytes" -f $case.Rule, $job.freed) }
    }

    # What must be gone, and what must not.
    if (Test-Path -LiteralPath $npmJunk) { if (@(Get-ChildItem -LiteralPath $npmJunk -Force).Count -gt 0) { Fail 'npm junk is still there' } }
    if (@(Get-ChildItem -LiteralPath $tempJunk -Force -ErrorAction SilentlyContinue).Count -gt 0) { Fail 'old temp junk is still there' }
    if (-not (Test-Path -LiteralPath $tempFresh)) { Fail 'a recent temp file was deleted' }
    if (-not (Test-Path -LiteralPath $canary)) { Fail 'the canary behind the junction was deleted' }
    if (-not (Get-Item -LiteralPath $link -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { Fail 'the junction is gone' }
    $history = @(Get-Content -LiteralPath (Join-Path $data 'history.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    if ($history.Count -ne 3) { Fail "history.jsonl has $($history.Count) entries; want 3" }
    Write-Host 'Destructive tests passed.'
} finally {
    try { Invoke-RestMethod -Method Post "$base/api/shutdown" -Headers $h | Out-Null } catch {}
    Start-Sleep -Seconds 1
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Select-Object -First 8 | ForEach-Object { Write-Host "server: $_" }
}
