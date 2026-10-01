# FortiLogPortal - atualização automática a partir do GitHub
#
# Baixa a versão mais recente do repositório, substitui o código (backend, frontend,
# scripts, docs, tests) e preserva os seus dados locais:
#   config\.env, database\, logs\, exports\, cache\, .venv\
#
# Uso: scripts\update.bat            (ou: powershell -ExecutionPolicy Bypass -File scripts\update.ps1)
#      scripts\update.bat -Force     (reinstala mesmo se já estiver na versão mais recente)
#      scripts\update.bat -Branch main
#
# Repositório e branch podem ser definidos no config\.env:
#   UPDATE_REPO=marcellod9/fortianalyzer-consulta
#   UPDATE_BRANCH=claude/fortilogportal-poc-vf3roq
param([string]$Branch = "", [string]$Repo = "", [switch]$Force)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"   # deixa o Invoke-WebRequest muito mais rápido no PS 5.1

function Get-EnvValue([string]$name) {
    if (-not (Test-Path "config\.env")) { return "" }
    $line = Get-Content "config\.env" | Where-Object { $_ -match "^\s*$name\s*=" } | Select-Object -First 1
    if ($line) { return ($line -split "=", 2)[1].Trim().Trim('"') }
    return ""
}

# Copia arquivos novos/alterados de $from para $to e remove os que deixaram de existir.
# Arquivos iguais não são tocados (o update.bat em execução não pode ser reescrito no meio).
function Sync-Folder([string]$from, [string]$to) {
    New-Item -ItemType Directory -Force -Path $to | Out-Null
    $from = (Get-Item -LiteralPath $from).FullName.TrimEnd("\")   # mesmo formato que o Get-ChildItem devolve
    $to = (Get-Item -LiteralPath $to).FullName.TrimEnd("\")
    $wanted = @{}
    foreach ($f in Get-ChildItem -LiteralPath $from -Recurse -File) {
        $rel = $f.FullName.Substring($from.Length + 1)
        $wanted[$rel.ToLowerInvariant()] = $true
        $dest = Join-Path $to $rel
        if ((Test-Path -LiteralPath $dest) -and
            (Get-FileHash -LiteralPath $dest).Hash -eq (Get-FileHash -LiteralPath $f.FullName).Hash) { continue }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
    }
    foreach ($f in Get-ChildItem -LiteralPath $to -Recurse -File) {
        $rel = $f.FullName.Substring($to.Length + 1)
        if (-not $wanted.ContainsKey($rel.ToLowerInvariant()) -and $rel -notmatch "(^|\\)__pycache__\\") {
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not $Repo)   { $Repo = Get-EnvValue "UPDATE_REPO" }
if (-not $Repo)   { $Repo = "marcellod9/fortianalyzer-consulta" }
if (-not $Branch) { $Branch = Get-EnvValue "UPDATE_BRANCH" }
if (-not $Branch) { $Branch = "claude/fortilogportal-poc-vf3roq" }

Write-Host "== FortiLogPortal: atualização a partir de github.com/$Repo ($Branch)" -ForegroundColor Cyan

# 1. O portal precisa estar parado
try {
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:8000/api/health" | Out-Null
    Write-Host "O portal está em execução. Feche a janela do portal (Ctrl+C) e rode o update de novo." -ForegroundColor Yellow
    exit 1
} catch { }

# 2. Versão disponível x instalada
$versionFile = Join-Path $Root ".versao-instalada"
$installed = if (Test-Path $versionFile) { (Get-Content $versionFile -Raw).Trim() } else { "" }
$latest = ""
try {
    $commit = Invoke-RestMethod -UseBasicParsing -Headers @{ "User-Agent" = "FortiLogPortal-update" } `
        "https://api.github.com/repos/$Repo/commits/$([uri]::EscapeDataString($Branch))"
    $latest = $commit.sha
    Write-Host ("Versão disponível: {0} - {1}" -f $latest.Substring(0, 7), ($commit.commit.message -split "`n")[0])
} catch {
    Write-Host "Não foi possível consultar a versão no GitHub ($($_.Exception.Message)). Baixando mesmo assim." -ForegroundColor Yellow
}
if ($latest -and $latest -eq $installed -and -not $Force) {
    Write-Host "Você já está na versão mais recente. Use -Force para reinstalar." -ForegroundColor Green
    exit 0
}

# 3. Download e extração
$tmp = Join-Path $env:TEMP ("flp-update-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp "repo.zip"
    $ref = if ($latest) { $latest } else { $Branch }
    Write-Host "Baixando código ..."
    Invoke-WebRequest -UseBasicParsing "https://github.com/$Repo/archive/$ref.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $src = Get-ChildItem -Path $tmp -Directory | Where-Object { Test-Path (Join-Path $_.FullName "FortiLogPortal\backend") } | Select-Object -First 1
    if (-not $src) { throw "Pasta FortiLogPortal não encontrada no pacote baixado." }
    $src = Join-Path $src.FullName "FortiLogPortal"

    # 4. Backup do código e do banco
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backup = Join-Path $Root "backups\$stamp"
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    foreach ($d in "backend", "frontend", "scripts", "docs", "tests") {
        if (Test-Path $d) { Copy-Item $d (Join-Path $backup $d) -Recurse -Force }
    }
    if (Test-Path "database\fortilogportal.db") { Copy-Item "database\fortilogportal.db" (Join-Path $backup "fortilogportal.db") }
    Write-Host "Backup salvo em backups\$stamp"

    # 5. Substitui o código arquivo a arquivo. As pastas em si nunca são apagadas: a pasta
    #    scripts\ está em uso pelo próprio update.bat (o Windows não deixa removê-la).
    foreach ($d in "backend", "frontend", "scripts", "docs", "tests") {
        if (Test-Path (Join-Path $src $d)) { Sync-Folder (Join-Path $src $d) (Join-Path $Root $d) }
    }
    foreach ($f in "requirements.txt", "requirements-dev.txt", "README.md", ".gitignore", "config\.env.example") {
        if (Test-Path (Join-Path $src $f)) { Copy-Item (Join-Path $src $f) $f -Force }
    }
    foreach ($d in "database", "logs", "exports", "cache") { New-Item -ItemType Directory -Force -Path $d | Out-Null }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# 6. Dependências e banco
$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    & (Join-Path $Root "scripts\install.ps1")
} else {
    Write-Host "Atualizando dependências ..."
    & $venvPy -m pip install -q -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar dependências." }
    & $venvPy -c "import sys; sys.path.insert(0,'backend'); from app.database import init_db; init_db(); print('Banco atualizado.')"
}
if ($latest) { Set-Content -Path $versionFile -Value $latest }

# 7. Variáveis novas no modelo de configuração
if (Test-Path "config\.env") {
    $mine = Get-Content "config\.env" | Where-Object { $_ -match "^\s*[A-Z0-9_]+\s*=" } | ForEach-Object { ($_ -split "=", 2)[0].Trim() }
    $new = Get-Content "config\.env.example" | Where-Object { $_ -match "^\s*[A-Z0-9_]+\s*=" } |
        Where-Object { $mine -notcontains (($_ -split "=", 2)[0].Trim()) }
    if ($new) {
        Write-Host "Opções novas em config\.env.example (copie para o seu config\.env se quiser alterar o padrão):" -ForegroundColor Yellow
        $new | ForEach-Object { Write-Host "  $_" }
    }
}

Write-Host ""
Write-Host "Atualização concluída. Inicie o portal com scripts\start.bat" -ForegroundColor Green
