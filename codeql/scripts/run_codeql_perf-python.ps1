param(
    [string]$Market    = "awesome",
    [string]$Language  = "Python",
    [string]$CodeqlExe = "D:\codeql\codeql.exe"
)


$SRC_ROOT = "E:\mcp_source_code\servers\$Market\$Language"


$DB_ROOT    = "E:\mcp_detection-v2\dbs\$Market\$Language"
$RESULT_DIR = "E:\mcp_detection-v2\results\$Market\$Language"


$QUERY = "D:\mcp_detection\codeql\mcp-crypto-misuse-python\src\crypto-misuse.ql"


New-Item -ItemType Directory -Force -Path $DB_ROOT    | Out-Null
New-Item -ItemType Directory -Force -Path $RESULT_DIR | Out-Null


$csvPath = Join-Path $RESULT_DIR "codeql_perf-$Market-$Language-optimized.csv"
"Market,Language,Project,DbCreateSeconds,AnalyzeSeconds,TotalSeconds,CreateOk,AnalyzeOk" |
    Set-Content -Path $csvPath -Encoding utf8

Write-Host "Market   = $Market"
Write-Host "Language = $Language"
Write-Host "SRC_ROOT = $SRC_ROOT"
Write-Host "DB_ROOT  = $DB_ROOT"
Write-Host "RESULTS  = $RESULT_DIR"
Write-Host "QUERY    = $QUERY"
Write-Host "CodeQL   = $CodeqlExe"
Write-Host ""


$projects =
    Get-ChildItem -Directory $SRC_ROOT |
    Where-Object { $_.Name -notin @('plugins', 'node_modules', 'dist') } |
    Sort-Object Name

$projCount = $projects.Count
Write-Host "Found $projCount projects under $SRC_ROOT" -ForegroundColor Cyan


$milestones = @(500,1000,1500,2000,2500,3000,4000,5000,6000,7000,8000,9000,9403) |
    Where-Object { $_ -le $projCount }

$createCum  = 0.0
$analyzeCum = 0.0
$idx = 0

foreach ($p in $projects) {
    $idx++
    $projRoot = $p.FullName
    $projName = $p.Name

    Write-Host "`n[$idx/$projCount] Project: $projName" -ForegroundColor Yellow


    $hasPy = Get-ChildItem -Path $projRoot -Recurse -Include *.py `
               -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hasPy) {
        Write-Host "   No *.py source found, skip." -ForegroundColor DarkYellow
        continue
    }


    $dbPath    = Join-Path $DB_ROOT    ("{0}-db" -f $projName)
    $sarifPath = Join-Path $RESULT_DIR ("{0}-crypto.sarif" -f $projName)


    if (Test-Path $dbPath) {
        Write-Host "   DB exists, skip create + analyze: $dbPath" -ForegroundColor Yellow
        continue
    }


    $createSec = 0.0
    $createOk  = $true

    if (-not (Test-Path $dbPath)) {
        Write-Host "   Creating CodeQL DB for $projName ..." -ForegroundColor Cyan

        $swCreate = [System.Diagnostics.Stopwatch]::StartNew()

        & $CodeqlExe database create $dbPath `
            --language=python `
            --source-root $projRoot `
            --threads=0

        $swCreate.Stop()

        $createSec = [Math]::Round($swCreate.Elapsed.TotalSeconds, 3)
        $createOk  = ($LASTEXITCODE -eq 0)
        $createCum += $createSec

        Write-Host ("   [create]   {0,8:F3} s   ok={1} (exit={2})" -f $createSec, $createOk, $LASTEXITCODE)

        if (-not $createOk) {

            $analyzeSec = 0.0
            $analyzeOk  = $false
            $totalSec   = $createSec

            $line = "{0},{1},{2},{3},{4},{5},{6},{7}" -f `
                $Market, $Language, $projName, $createSec, $analyzeSec, $totalSec, $createOk, $analyzeOk
            Add-Content -Path $csvPath -Value $line
            continue
        }
    } else {
        Write-Host "   Using existing CodeQL DB: $dbPath" -ForegroundColor Yellow
    }


    $swAnalyze = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "   Running analyze ..." -ForegroundColor Cyan

    & $CodeqlExe database analyze --rerun $dbPath `
        $QUERY `
        --format=sarifv2.1.0 `
        --output $sarifPath `
        --threads=0 `
        --log-to-stderr `
        --verbosity=progress

    $swAnalyze.Stop()

    $analyzeSec = [Math]::Round($swAnalyze.Elapsed.TotalSeconds, 3)
    $analyzeOk  = ($LASTEXITCODE -eq 0)
    $analyzeCum += $analyzeSec

    Write-Host ("   [analyze]  {0,8:F3} s   ok={1} (exit={2})" -f $analyzeSec, $analyzeOk, $LASTEXITCODE)

    $totalSec = $createSec + $analyzeSec
    Write-Host ("   [total]    {0,8:F3} s" -f $totalSec)


    $line = "{0},{1},{2},{3},{4},{5},{6},{7}" -f `
        $Market, $Language, $projName, $createSec, $analyzeSec, $totalSec, $createOk, $analyzeOk
    Add-Content -Path $csvPath -Value $line


    if ($milestones -contains $idx) {
        Write-Host ""
        Write-Host "===== CodeQL cumulative timing after $idx projects =====" -ForegroundColor Green
        Write-Host ("  DB create cumulative : {0,8:F2} s" -f $createCum)
        Write-Host ("  Analyze cumulative   : {0,8:F2} s" -f $analyzeCum)
        Write-Host "========================================================"
    }
}

Write-Host "`nDone. Perf CSV saved to $csvPath" -ForegroundColor Cyan

