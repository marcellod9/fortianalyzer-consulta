# FortiLogPortal - instalação local (Windows / PowerShell)
# Uso: clique duas vezes em scripts\install.bat  ou  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
Write-Host "== FortiLogPortal: instalação em $Root" -ForegroundColor Cyan

# 1. Python 3.10+
$py = $null
foreach ($cand in @("py -3", "python")) {
    try {
        $v = & cmd /c "$cand --version" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v -match "Python 3\.(\d+)") {
            if ([int]$Matches[1] -ge 10) { $py = $cand; break }
        }
    } catch { }
}
if (-not $py) {
    Write-Host "Python 3.10 ou superior não encontrado. Instale em https://www.python.org/downloads/ (marque 'Add python.exe to PATH')." -ForegroundColor Red
    exit 1
}
Write-Host "Python encontrado: $py ($v)"

# 2. Ambiente virtual
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Criando ambiente virtual .venv ..."
    & cmd /c "$py -m venv .venv"
    if ($LASTEXITCODE -ne 0) { throw "Falha ao criar o ambiente virtual" }
}
$venvPy = Join-Path $Root ".venv\Scripts\python.exe"

# 3. Dependências
Write-Host "Instalando dependências (requirements.txt) ..."
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar dependências. Se houver proxy, defina HTTPS_PROXY antes de rodar." }

# 4. Arquivo de configuração
if (-not (Test-Path "config\.env")) {
    Copy-Item "config\.env.example" "config\.env"
    Write-Host "Criado config\.env a partir do modelo. Edite-o com os tokens antes de iniciar." -ForegroundColor Yellow
}

# 5. Pastas e banco de dados
foreach ($d in "database","logs","exports","cache") { New-Item -ItemType Directory -Force -Path $d | Out-Null }
& $venvPy -c "import sys; sys.path.insert(0,'backend'); from app.database import init_db; init_db(); print('Banco SQLite pronto.')"

Write-Host ""
Write-Host "Instalação concluída." -ForegroundColor Green
Write-Host "Próximos passos: 1) edite config\.env   2) execute scripts\start.bat"
