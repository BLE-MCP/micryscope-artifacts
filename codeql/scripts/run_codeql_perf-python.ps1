param(
    [string]$Market    = "awesome",
    [string]$Language  = "Python",
    [string]$CodeqlExe = "D:\codeql\codeql.exe"   # 按实际 codeql.exe 路径修改
)

# 1. 源码根目录（每个子文件夹是一个 MCP server 项目）
$SRC_ROOT = "E:\mcp_source_code\servers\$Market\$Language"

# 2. CodeQL 数据库和结果输出目录（统一放在 perf 目录下，便于统计）
$DB_ROOT    = "E:\mcp_detection-v2\dbs\$Market\$Language"
$RESULT_DIR = "E:\mcp_detection-v2\results\$Market\$Language"

# 3. 你的自定义查询（单个 QL 文件）
$QUERY = "D:\mcp_detection\codeql\mcp-crypto-misuse-python\src\crypto-misuse.ql"

# 确保目录存在
New-Item -ItemType Directory -Force -Path $DB_ROOT    | Out-Null
New-Item -ItemType Directory -Force -Path $RESULT_DIR | Out-Null

# 4. 性能统计 CSV（文件名你也可以改回原来的）
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

# 5. 列出所有 MCP server 项目（子目录），过滤掉明显无关的目录
$projects =
    Get-ChildItem -Directory $SRC_ROOT |
    Where-Object { $_.Name -notin @('plugins', 'node_modules', 'dist') } |
    Sort-Object Name

$projCount = $projects.Count
Write-Host "Found $projCount projects under $SRC_ROOT" -ForegroundColor Cyan

# 可选：里程碑
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

    # 跳过没有 Python 源码的目录
    $hasPy = Get-ChildItem -Path $projRoot -Recurse -Include *.py `
               -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hasPy) {
        Write-Host "   No *.py source found, skip." -ForegroundColor DarkYellow
        continue
    }

    # 统一的 DB 目录和结果文件
    $dbPath    = Join-Path $DB_ROOT    ("{0}-db" -f $projName)
    $sarifPath = Join-Path $RESULT_DIR ("{0}-crypto.sarif" -f $projName)

    # ===== 新增：如果 DB 已存在，则整个项目跳过（不 create、不 analyze） =====
    if (Test-Path $dbPath) {
        Write-Host "   DB exists, skip create + analyze: $dbPath" -ForegroundColor Yellow
        continue
    }

    # ===== 1) database create（只在 DB 不存在时创建） =====
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
            # 建库失败，不再跑分析，直接记录一行并跳过
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

    # ===== 2) database analyze =====
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

    # 写入 CSV
    $line = "{0},{1},{2},{3},{4},{5},{6},{7}" -f `
        $Market, $Language, $projName, $createSec, $analyzeSec, $totalSec, $createOk, $analyzeOk
    Add-Content -Path $csvPath -Value $line

    # 里程碑输出（可选）
    if ($milestones -contains $idx) {
        Write-Host ""
        Write-Host "===== CodeQL cumulative timing after $idx projects =====" -ForegroundColor Green
        Write-Host ("  DB create cumulative : {0,8:F2} s" -f $createCum)
        Write-Host ("  Analyze cumulative   : {0,8:F2} s" -f $analyzeCum)
        Write-Host "========================================================"
    }
}

Write-Host "`nDone. Perf CSV saved to $csvPath" -ForegroundColor Cyan
