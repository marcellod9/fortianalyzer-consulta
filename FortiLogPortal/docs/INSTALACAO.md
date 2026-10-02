# Instalação (Windows)

## Pré-requisitos

| Item | Observação |
|---|---|
| Windows 10/11 | PowerShell 5.1 (já incluso) |
| Python 3.10 ou superior | https://www.python.org/downloads/ — marque **Add python.exe to PATH** |
| Acesso HTTPS a `fortianalyzer.marista.edu.br` | a partir da sua máquina (VPN/rede interna) |
| Acesso HTTPS a `api.xdr.trendmicro.com` | ou à URL da região do tenant |
| Token do FortiAnalyzer e chave de API do Vision One | veja [CONFIGURACAO_APIS.md](CONFIGURACAO_APIS.md) |

Não é necessário Docker, IIS nem privilégio de administrador.

## Passo a passo

1. Copie a pasta `FortiLogPortal` para:

   ```
   C:\Users\marcello.sousa\OneDrive - MARISTA BRASIL\Documents\Projetos Claude\FortiLogPortal
   ```

   > Dica: o OneDrive sincroniza `.venv`, `database` e `logs`. Se incomodar, marque a pasta como
   > "Sempre manter neste dispositivo" ou exclua essas subpastas da sincronização.

2. Dê dois cliques em `scripts\install.bat`. O script:
   - localiza o Python 3.10+;
   - cria o ambiente virtual `.venv`;
   - instala as dependências de `requirements.txt`;
   - cria `config\.env` a partir de `config\.env.example` (se ainda não existir);
   - cria o banco `database\fortilogportal.db`.

   Se o Windows bloquear scripts, rode no PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
   ```

3. Abra `config\.env` no Bloco de Notas e preencha `FAZ_API_TOKEN` e `V1_API_TOKEN`.

4. Dê dois cliques em `scripts\start.bat`.

## Proxy corporativo

Se a instalação de pacotes falhar por proxy, antes do `install.ps1`:

```powershell
$env:HTTPS_PROXY = "http://proxy:porta"
```

Para o portal acessar as APIs via proxy, descomente `HTTPS_PROXY`/`NO_PROXY` no `config\.env`
(a biblioteca `requests` respeita essas variáveis). Se o proxy fizer inspeção TLS, aponte
`V1_VERIFY_TLS` para o arquivo `.pem` da CA corporativa.

## Testes automatizados

`scripts\test.bat` instala as dependências de desenvolvimento e roda `pytest`. Os testes usam
dados simulados e um banco temporário; não acessam o FortiAnalyzer nem o Vision One.
