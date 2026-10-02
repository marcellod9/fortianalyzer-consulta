# FortiLogPortal - executa os testes automatizados (não acessam as APIs reais)
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
& $venvPy -m pip install -q -r requirements-dev.txt
& $venvPy -m pytest -q tests
