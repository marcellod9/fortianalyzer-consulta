# FortiLogPortal

Portal web local para a equipe de **Sustentação do Marista Brasil** consultar, sem acesso direto às
ferramentas de segurança:

- bloqueios de navegação e de firewall, com a **regra** e a **política** responsáveis;
- logs de tráfego, filtro web, aplicações, DNS, IPS e antivírus do **FortiAnalyzer**;
- reputação de **URLs, domínios e IPs** e indicadores de ameaça (IOC) no **Trend Micro Vision One**;
- correlação FortiAnalyzer + Vision One para um indicador;
- histórico de consultas, dashboard e exportação em **CSV, XLSX e PDF**.

Os eventos técnicos são traduzidos para linguagem simples:

```
Usuário:   joao.silva
Acesso:    facebook.com
Resultado: Bloqueado
Motivo:    Categoria "Social Networking" não permitida pela política de navegação corporativa.
Política:  WebFilter_Corporativo
Regra:     1 - Internet_Corporativa
Firewall:  FW-BRASILIA
```

> **Fase 1 (POC):** roda só em `http://127.0.0.1:8000`, sem Docker e sem autenticação. Não é para produção.

## Início rápido (Windows)

1. Instale o **Python 3.10+** (marque *Add python.exe to PATH*).
2. Copie a pasta `FortiLogPortal` para
   `C:\Users\marcello.sousa\OneDrive - MARISTA BRASIL\Documents\Projetos Claude\FortiLogPortal`.
3. Execute `scripts\install.bat` (cria `.venv`, instala dependências, cria `config\.env` e o banco).
4. Edite `config\.env` com `FAZ_API_TOKEN` e `V1_API_TOKEN` (veja [docs/CONFIGURACAO_APIS.md](docs/CONFIGURACAO_APIS.md)).
5. Execute `scripts\start.bat`. O navegador abre em http://127.0.0.1:8000.

Quer ver a interface antes de ter os tokens? Coloque `PORTAL_DEMO=true` no `config\.env`
(dados simulados, com aviso em todas as telas). Volte para `false` para usar as APIs reais.

## Telas

| Tela | O que faz |
|---|---|
| **Dashboard** | Sites, usuários e regras mais bloqueados, firewalls com mais eventos (FAZ, últimas N horas); domínios/IPs/URLs maliciosos consultados; totais e histórico diário |
| **Bloqueios** | "Por que foi bloqueado?": busca por usuário, IP ou site em filtro web, firewall, aplicações e DNS ao mesmo tempo, com explicação |
| **Logs** | Pesquisa completa: IP/porta de origem e destino, usuário, URL, domínio, regra, política, equipamento, interfaces, ação, período |
| **Reputação** | URL, domínio ou IP (ou vários, um por linha) no Vision One: reputação, risk score, categoria, severidade, tipo da ameaça, IOC relacionados, última análise, confiança, fonte e recomendações |
| **Correlação** | Um indicador cruzado nas duas ferramentas, com análise consolidada |
| **Histórico** | Todas as consultas (data, usuário, tipo, termo, resultado), com filtro e exportação |
| **Configuração** | Teste de conexão das APIs, tempo de resposta, logs internos e limpeza de cache |

## Estrutura

```
FortiLogPortal
├── backend\            código Python (FastAPI)
│   ├── run.py          inicialização (uvicorn em 127.0.0.1)
│   └── app\
│       ├── main.py     aplicação, middleware de logs/tempo, tratamento de erros
│       ├── config.py   leitura de config\.env (sem segredos no código)
│       ├── database.py SQLite: histórico, logs internos, cache, configurações, temporários
│       ├── routers\    API REST (/api/...) e páginas
│       ├── services\   FortiAnalyzer, Vision One, reputação, correlação, explicação, exportação, dashboard
│       └── demo\       dados simulados (somente PORTAL_DEMO=true)
├── frontend\           templates Jinja2, Bootstrap 5, JavaScript (bibliotecas locais, sem CDN)
├── config\             .env.example (modelo) e .env (seu, fora do git)
├── database\           fortilogportal.db
├── scripts\            install / start / update / test (.bat e .ps1)
├── logs\               app.log, auditoria.log, integracoes.log
├── exports\            cópia de cada arquivo exportado
├── cache\              reservado para cache em disco
├── docs\               documentação
└── tests\              testes automatizados (pytest, sem acesso às APIs reais)
```

## Documentação

- [Instalação](docs/INSTALACAO.md)
- [Configuração das APIs (FortiAnalyzer e Vision One)](docs/CONFIGURACAO_APIS.md)
- [Execução local e uso](docs/EXECUCAO_LOCAL.md)
- [Atualização](docs/ATUALIZACAO.md)
- [Arquitetura, banco de dados e API REST](docs/ARQUITETURA.md)
- [Melhorias futuras](docs/ROADMAP.md)

## Segurança da POC

- Tokens só em `config\.env` (fora do git); a tela de configuração nunca os exibe.
- O portal escuta apenas em `127.0.0.1`.
- Todo filtro digitado é validado antes de virar expressão do FortiAnalyzer (sem injeção de filtro).
- Auditoria local em `logs\auditoria.log` e na tabela `query_history` (os logs contêm dados pessoais; LGPD).
- Exportações protegidas contra injeção de fórmulas no Excel.
- Falhas de uma integração não derrubam as outras; cada erro aparece na tela e em `logs\integracoes.log`.
