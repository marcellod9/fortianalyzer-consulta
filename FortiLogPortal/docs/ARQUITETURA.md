# Arquitetura

```
Navegador (127.0.0.1:8000)
   │  HTML Jinja2 + Bootstrap 5 + JS (fetch /api/...)
   ▼
FastAPI (backend/app)
   ├── routers/pages.py     páginas
   ├── routers/api.py       API REST, histórico e auditoria (routers/common.py)
   └── services/
        ├── fortianalyzer.py   cliente JSON-RPC (requests)         ──HTTPS──▶ FortiAnalyzer
        ├── faz_filters.py     validação + expressão de filtro
        ├── logsearch.py       busca normalizada, bloqueios em paralelo, cache
        ├── explain.py         normalização e linguagem simples
        ├── visionone.py       cliente REST v3.0 (requests)       ──HTTPS──▶ Vision One
        ├── reputation.py      reputação consolidada de IP/domínio/URL
        ├── correlation.py     FortiAnalyzer x Vision One
        ├── dashboard.py       agregações do dashboard
        ├── export.py          CSV / XLSX (openpyxl) / PDF (reportlab)
        └── telemetry.py       tempo de resposta e falhas das integrações
   ▼
SQLite (database/fortilogportal.db)
```

## Fluxo de uma pesquisa de bloqueio

1. A tela envia `POST /api/faz/blocks` com usuário/IP/site e período.
2. `LogQuery` valida cada campo e monta a expressão (`user~"joao" and action=blocked`).
3. `logsearch.blocked_search` dispara, em paralelo, buscas em `webfilter`, `traffic`,
   `app-ctrl` e `dns` (cada uma: `add` → `get` até 100% → `delete` no LogView).
4. Cada linha é normalizada por `explain.normalize` (colunas do portal + motivo + explicação).
5. O resultado vai para o cache, o histórico registra a consulta e um `result_id` temporário
   permite exportar sem reenviar os dados.

## Banco de dados (SQLite)

| Tabela | Conteúdo |
|---|---|
| `query_history` | data/hora, usuário, tipo, termo, parâmetros, status, nº de resultados e bloqueios, resumo, tempo |
| `app_log` | logs internos: chamadas de integração (com `duration_ms`), falhas, erros |
| `cache` | respostas das APIs com expiração (`PORTAL_CACHE_TTL`) |
| `settings` | configurações não sensíveis (reservado para preferências futuras) |
| `temp_data` | informações temporárias: resultados para exportação (1 h) |
| `ioc_lookup` | resultado de cada consulta de reputação (dashboard Vision One) |
| `meta` | versão do esquema |

Credenciais **não** ficam no banco.

## API REST

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/health` | saúde |
| GET | `/api/status` | configuração (sem segredos) e tempo de resposta das integrações |
| POST | `/api/status/test/{faz\|v1}` | teste de conexão |
| GET | `/api/faz/logtypes` | tipos de log |
| GET | `/api/faz/adoms`, `/api/faz/adoms/{adom}/devices` | inventário |
| POST | `/api/faz/logs` | pesquisa de logs (`LogQuery`) |
| POST | `/api/faz/blocks` | bloqueios em vários tipos de log |
| POST | `/api/v1/reputation` | `{indicator, type: auto\|url\|domain\|ip, sandbox}` |
| GET | `/api/v1/sandbox/{task_id}` | acompanhamento do Sandbox |
| GET | `/api/v1/alerts?days=&severity=&status=` | alertas do Workbench |
| GET | `/api/v1/endpoints` | inventário de endpoints |
| POST | `/api/correlation` | `{indicator, start, end, adom}` |
| GET | `/api/dashboard/faz?hours=&refresh=`, `/api/dashboard/local` | dashboard |
| GET | `/api/history?type=&q=` | histórico |
| GET | `/api/export/{result_id}.{csv\|xlsx\|pdf}`, `/api/export/history.{fmt}` | exportação |
| GET | `/api/app-log`, DELETE `/api/cache` | diagnóstico |

`LogQuery`: `adom, devices[], logtype, start, end, srcip, dstip, srcport, dstport, user, url,
hostname, policy, profile, srcintf, dstintf, action, only_blocked, limit`.

## Preparação para correlação e novos módulos

- Os clientes (`fortianalyzer.py`, `visionone.py`) só falam com as APIs; regras de negócio ficam
  em `services/` separados. Um novo módulo (ex.: incidentes) é um novo serviço + rota + página.
- `visionone.py` já expõe `workbench_alerts`, `endpoints` e Sandbox, base para Alertas,
  Incidentes/Workbench e Inventário.
- `correlation.py` recebe um indicador e cruza eventos do FAZ com a reputação; a mesma estrutura
  serve para correlacionar alertas do Vision One com logs do firewall (por IP/host/usuário).
- `reputation.lookup` aceita tipos novos (hash de arquivo) adicionando um ramo em
  `parse_indicator` e no casamento com Suspicious Objects (`fileSha1`, `fileSha256`).
