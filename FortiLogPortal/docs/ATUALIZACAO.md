# Atualização

Com o portal fechado, dê dois cliques em `scripts\update.bat` (ou rode no terminal):

```powershell
cd "C:\Users\marcello.sousa\OneDrive - MARISTA BRASIL\Documents\Projetos Claude\FortiLogPortal"
scripts\update.bat
```

O script:

1. Confere se o portal está parado (se estiver rodando, pede para fechar).
2. Consulta no GitHub o último commit do branch e compara com `.versao-instalada`.
   Se já estiver na versão mais recente, não faz nada.
3. Baixa o ZIP desse commit e faz backup do código atual e do banco em `backups\AAAAMMDD-HHMMSS\`.
4. Substitui `backend`, `frontend`, `scripts`, `docs`, `tests`, `requirements*.txt`, `README.md`,
   `.gitignore` e `config\.env.example`.
5. Atualiza as dependências Python e aplica mudanças de esquema do banco.
6. Lista as opções novas do `config\.env.example` que ainda não estão no seu `config\.env`.
7. Inicia o portal (o mesmo que `scripts\start.bat`). Para só atualizar, use `-NoStart`.

Nunca são alterados:

| Pasta/arquivo | Conteúdo |
|---|---|
| `config\.env` | credenciais e opções |
| `database\` | histórico, cache, configurações |
| `logs\`, `exports\`, `cache\` | logs, arquivos exportados, cache |
| `.venv\` | ambiente Python |

## Opções

```powershell
scripts\update.bat -Force          # reinstala mesmo já estando na versão mais recente
scripts\update.bat -Branch main    # usa outro branch nesta execução
scripts\update.bat -NoStart        # só atualiza, sem iniciar o portal
```

Para fixar repositório e branch, acrescente ao `config\.env`:

```
UPDATE_REPO=marcellod9/fortianalyzer-consulta
UPDATE_BRANCH=main
```

O padrão é o branch de desenvolvimento do POC (`claude/fortilogportal-poc-vf3roq`). Depois que o
PR for aceito no `main`, defina `UPDATE_BRANCH=main`.

O download usa o GitHub público, sem token. Se o repositório virar privado, o update automático
deixa de funcionar e a cópia manual abaixo continua valendo. Atrás de proxy, o PowerShell usa o
proxy configurado no Windows.

## Cópia manual (alternativa)

1. Pare o portal.
2. Baixe o ZIP do branch no GitHub e substitua as pastas `backend`, `frontend`, `scripts`, `docs`,
   `tests` e os arquivos `requirements*.txt`, `README.md` e `config\.env.example`.
3. Execute `scripts\update.bat -Force`.

## Voltar uma versão

Copie as pastas de `backups\AAAAMMDD-HHMMSS\` de volta para a raiz do portal e, se necessário,
o `fortilogportal.db` dessa pasta para `database\`.
