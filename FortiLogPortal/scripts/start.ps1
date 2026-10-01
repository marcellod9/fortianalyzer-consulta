# FortiLogPortal - inicia o portal em http://127.0.0.1:8000
param([switch]$NoBrowser, [switch]$Reload)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "Ambiente não instalado. Execute scripts\install.bat primeiro." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "config\.env")) {
    Write-Host "config\.env não encontrado. Copie config\.env.example para config\.env e preencha." -ForegroundColor Red
    exit 1
}
$runArgs = @("backend\run.py")
if ($NoBrowser) { $runArgs += "--no-browser" }
if ($Reload) { $runArgs += "--reload" }
& $venvPy @runArgs
