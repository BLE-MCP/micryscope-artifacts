param(
    [string]$Market    = "awesome",
    [string]$Language  = "JavaScript",
    # GitHub-friendly: allow user to override CodeQL path via env var CODEQL_EXE.
    # Fallback assumes "codeql" is available in PATH.
    [string]$CodeqlExe = $(if ($env:CODEQL_EXE) { $env:CODEQL_EXE } else { "codeql" })
)


# Script dir -> benchmarks dir -> repo root
$SCRIPT_DIR     = Split-Path -Parent $MyInvocation.MyCommand.Path
$BENCHMARKS_DIR = Split-Path -Parent $SCRIPT_DIR
$REPO_ROOT      = Split-Path -Parent $BENCHMARKS_DIR

# 1. Source root (each subfolder is an MCP server project)
$SRC_ROOT = Join-Path $BENCHMARKS_DIR ("datasets\{0}\{1}" -f $Market, $Language)

# 2. CodeQL DB and SARIF output directories
$DB_ROOT  = Join-Path $BENCHMARKS_DIR ("perf\dbs\{0}\{1}" -f $Market, $Language)
$OUT_ROOT = Join-Path $BENCHMARKS_DIR ("perf\results\{0}\{1}" -f $Market, $Language)

# 3. Custom query search-path (parent directory of qlpacks)
#    Here we assume the qlpacks live under <repo_root>\codeql\
$SEARCH_PATH = Join-Path $REPO_ROOT "codeql"

# Ensure directories exist
New-Item -ItemType Directory -Force -Path $DB_ROOT  | Out-Null
New-Item -ItemType Directory -Force -Path $OUT_ROOT | Out-Null

# Sanity checks for a smoother GitHub experience
if (-not (Test-Path $SRC_ROOT)) {
    Write-Host "ERROR: Source root not found: $SRC_ROOT" -ForegroundColor Red
    Write-Host "Please place benchmark datasets under: benchmarks/datasets/<Market>/<Language>/" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $SEARCH_PATH)) {
    Write-Host "ERROR: CodeQL search-path not found: $SEARCH_PATH" -ForegroundColor Red
    Write-Host "Expected qlpacks under: <repo_root>/codeql/" -ForegroundColor Red
    exit 1
}

# Perf CSV
$csvPath = Join-Path $OUT_ROOT ("codeql_perf-{0}-{1}.csv" -f $Market, $Language)
"Market,Language,Project,DbCreateSeconds,AnalyzeSeconds,TotalSeconds,CreateOk,AnalyzeOk" | `
    Out-File -FilePath $csvPath -Encoding utf8

# List projects (skip node_modules / dist / .git)
$skipNames = @("node_modules", "dist", ".git")
$projects = Get-ChildItem -Path $SRC_ROOT -Directory |
            Where-Object { $skipNames -notcontains $_.Name } |
            Sort-Object Name
$projCount = $projects.Count

Write-Host "Found $projCount projects under $SRC_ROOT" -ForegroundColor Cyan
Write-Host "Using CodeQL executable: $CodeqlExe" -ForegroundColor Cyan
Write-Host "Using search-path: $SEARCH_PATH" -ForegroundColor Cyan

# Optional: milestone cumulative timing
$milestones = @(500,1000,1500,2000,2500,3000,4000,5000,6000,7000,8000,9000,9403) |
    Where-Object { $_ -le $projCount }

$createCum  = 0.0
$analyzeCum = 0.0

$idx = 0

foreach ($p in $projects) {
    $idx++
    $projName = $p.Name
    $projRoot = $p.FullName

    Write-Host "`n[$idx/$projCount] Project: $projName" -ForegroundColor Yellow

    $dbPath    = Join-Path $DB_ROOT  ("{0}-db" -f $projName)
    $sarifPath = Join-Path $OUT_ROOT ("{0}-crypto.sarif" -f $projName)

    # If DB exists, remove it to ensure cold-start timing
    if (Test-Path $dbPath) {
        Remove-Item -Recurse -Force $dbPath
    }

    # -------- 1) database create timing --------
    $swCreate = [System.Diagnostics.Stopwatch]::StartNew()
    & $CodeqlExe database create $dbPath `
        --language=javascript `
        --source-root=$projRoot `
        --threads=4
    $swCreate.Stop()

    $createSec = [Math]::Round($swCreate.Elapsed.TotalSeconds, 3)
    $createOk  = ($LASTEXITCODE -eq 0)

    $createCum += $createSec

    Write-Host ("   [create]   {0,8:F3} s   ok={1}" -f $createSec, $createOk)

    # If create fails, skip analyze
    if (-not $createOk) {
        $analyzeSec = 0.0
        $analyzeOk  = $false
    }
    else {
        # -------- 2) database analyze timing --------
        $swAnalyze = [System.Diagnostics.Stopwatch]::StartNew()
        & $CodeqlExe database analyze $dbPath `
            "mcp-crypto-misuse-javascript/src/crypto-misuse-javascript.ql" `
            --search-path=$SEARCH_PATH `
            --format=sarif-latest `
            --output=$sarifPath `
            --threads=4
        $swAnalyze.Stop()

        $analyzeSec = [Math]::Round($swAnalyze.Elapsed.TotalSeconds, 3)
        $analyzeOk  = ($LASTEXITCODE -eq 0)

        $analyzeCum += $analyzeSec

        Write-Host ("   [analyze]  {0,8:F3} s   ok={1}" -f $analyzeSec, $analyzeOk)
    }

    $totalSec = $createSec + $analyzeSec
    Write-Host ("   [total]    {0,8:F3} s" -f $totalSec)

    # Append CSV line
    $line = "{0},{1},{2},{3},{4},{5},{6},{7}" -f `
        $Market, $Language, $projName,
        $createSec, $analyzeSec, $totalSec, $createOk, $analyzeOk
    Add-Content -Path $csvPath -Value $line

    # Milestone print (optional)
    if ($milestones -contains $idx) {
        Write-Host ""
        Write-Host "===== CodeQL cumulative timing after $idx projects =====" -ForegroundColor Green
        Write-Host ("  DB create cumulative : {0,8:F2} s" -f $createCum)
        Write-Host ("  Analyze cumulative   : {0,8:F2} s" -f $analyzeCum)
        Write-Host "========================================================"
    }
}

Write-Host "`nDone. Perf CSV saved to $csvPath" -ForegroundColor Cyan
