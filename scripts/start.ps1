# 관제 서버(9000)와 욕설·위협 감지 서버(8002)를 띄운다.
#
#   .\scripts\start.ps1              규칙 사전만 (기본값)
#   .\scripts\start.ps1 -WithModel   학습 모델 + 규칙 사전 병행
#
# 기본값이 사전만인 이유는 README "분류기" 절을 볼 것. 요약하면 AIHub 데이터의 위협 정의가
# 우리 현장과 달라서, 그 데이터로 학습한 모델은 간접 위협("가만 안 둬")을 정상으로 본다.
param([switch]$WithModel)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
New-Item -ItemType Directory -Force -Path "$root\logs" | Out-Null

# 이미 떠 있으면 내린다 (포트를 물고 있으면 새 프로세스가 조용히 죽는다)
Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -like "*threat_server.app*" -or $_.CommandLine -like "*threat_server.control_server*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$env:CONTROL_SERVER_URL = "http://127.0.0.1:9000/api/alerts"
$env:THREAT_THRESHOLD = "0.8"     # test셋 임계값 표를 보고 정했다 (README 참고)
if ($WithModel) { $env:THREAT_MODEL_DIR = "$root\models\threat-kcelectra" }
else { Remove-Item Env:\THREAT_MODEL_DIR -ErrorAction SilentlyContinue }

$control = Start-Process -FilePath "uv" -WorkingDirectory $root -WindowStyle Hidden -PassThru `
    -ArgumentList "run uvicorn threat_server.control_server:app --host 127.0.0.1 --port 9000" `
    -RedirectStandardOutput "$root\logs\control_$stamp.out.log" `
    -RedirectStandardError  "$root\logs\control_$stamp.err.log"

$threat = Start-Process -FilePath "uv" -WorkingDirectory $root -WindowStyle Hidden -PassThru `
    -ArgumentList "run uvicorn threat_server.app:create_app --factory --host 127.0.0.1 --port 8002" `
    -RedirectStandardOutput "$root\logs\threat_$stamp.out.log" `
    -RedirectStandardError  "$root\logs\threat_$stamp.err.log"

# 모델을 GPU에 올리는 데 시간이 걸리므로 넉넉히 기다린다
$deadline = (Get-Date).AddSeconds(180)
do {
    Start-Sleep -Seconds 3
    try { $a = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:9000/api/alerts).StatusCode -eq 200 } catch { $a = $false }
    try { $b = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8002/health).StatusCode -eq 200 } catch { $b = $false }
} while (-not ($a -and $b) -and (Get-Date) -lt $deadline)

Write-Host "control(9000)=$a pid=$($control.Id)   threat(8002)=$b pid=$($threat.Id)"
Write-Host "분류기: $(if ($WithModel) { '모델 + 규칙 사전 병행' } else { '규칙 사전만' })   임계값: $env:THREAT_THRESHOLD"
Write-Host "로그: logs\threat_$stamp.err.log"
