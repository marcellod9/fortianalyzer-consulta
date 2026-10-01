# Atualização

Os dados locais ficam em pastas que a atualização não apaga:

| Pasta/arquivo | Conteúdo | Preservar |
|---|---|---|
| `config\.env` | credenciais e opções | sim |
| `database\fortilogportal.db` | histórico, cache, configurações | sim |
| `logs\`, `exports\` | logs e arquivos exportados | sim |

## Com git

```powershell
cd "C:\Users\marcello.sousa\OneDrive - MARISTA BRASIL\Documents\Projetos Claude\FortiLogPortal"
scripts\update.bat
```

O `update.ps1` faz `git pull` (se a pasta for um repositório), faz backup do banco
(`database\fortilogportal-AAAAMMDD-HHMMSS.bak`), atualiza as dependências e aplica mudanças de
esquema do banco.

## Sem git (cópia manual)

1. Pare o portal.
2. Substitua as pastas `backend`, `frontend`, `scripts`, `docs`, `tests` e os arquivos
   `requirements*.txt`, `README.md` e `config\.env.example` pela versão nova.
3. Execute `scripts\update.bat`.
4. Compare `config\.env.example` com o seu `config\.env` e copie as variáveis novas.

## Voltar uma versão

Restaure a pasta de código anterior e, se necessário, renomeie o `.bak` mais recente para
`database\fortilogportal.db`.
