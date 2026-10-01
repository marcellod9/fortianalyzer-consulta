# FortiLogPortal - atualização: reinstala dependências e migra o banco.
# Antes, substitua os arquivos do projeto pela versão nova (ou "git pull"),
# preservando config\.env, database\, logs\ e exports\.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
if (Test-Path ".git") {
    Write-Host "Repositório git detectado: atualizando código ..."
    git pull
}
$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) { & (Join-Path $PSScriptRoot "install.ps1"); exit $LASTEXITCODE }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (Test-Path "database\fortilogportal.db") {
    Copy-Item "database\fortilogportal.db" "database\fortilogportal-$stamp.bak"
    Write-Host "Backup do banco: database\fortilogportal-$stamp.bak"
}
& $venvPy -m pip install -r requirements.txt
& $venvPy -c "import sys; sys.path.insert(0,'backend'); from app.database import init_db; init_db(); print('Banco atualizado.')"
Write-Host "Atualização concluída. Compare config\.env com config\.env.example para novas opções." -ForegroundColor Green
