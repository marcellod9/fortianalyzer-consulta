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

> **Fase 1 (POC):** roda só neste computador, sem Docker. O login com a conta Microsoft (Entra ID, com MFA)
> é ligado com `AUTH_MODE=entra` (veja [docs/CONFIGURACAO_ENTRA.md](docs/CONFIGURACAO_ENTRA.md)).

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
| **Diagnóstico** | "Não consigo acessar": usuário, IP, MAC ou máquina e o site; procura bloqueios no filtro web, controle de aplicações, filtro DNS e regras do firewall de uma vez e diz o que fazer; *Ver máquina no Vision One* mostra o agente Trend e os alertas abertos |
| **Logs** | Pesquisa completa: IP/porta de origem e destino, usuário, URL, domínio, regra, política, equipamento, interfaces, ação, período; modo *Tempo real* com atualização automática. Nos detalhes do evento: reputação do destino e *Máquina no Vision One* (agente Trend ativo, isolamento e alertas do Workbench da máquina e do usuário) |
| **Reputação** | URL, domínio ou IP (ou vários, um por linha) no Vision One, com a categoria do FortiGuard vista nos logs: reputação, risk score, categoria, severidade, tipo da ameaça, IOC relacionados, última análise, confiança, fonte e recomendações; o Sandbox reaproveita a análise da mesma URL das últimas 24 h e mostra a cota do dia |
| **Ameaças** | Máquinas comprometidas (alertas de IOC e botnet do Event Monitor do FortiAnalyzer, sem ACK primeiro), Top Threats do FortiView (pontuação, incidentes bloqueados e permitidos), mapa de ameaças por país e ranking de ameaças dos logs (IPS, antivírus, sites maliciosos e phishing, botnet, DNS, tráfego com ameaça): ameaças, máquinas e usuários afetados, o que não foi bloqueado em destaque, gráficos, máquina no Vision One e exportação. Sub-aba **Mapa em tempo real**: arcos animados do firewall ao país de cada ameaça nova, lista ao vivo, pausa e velocidade |
| **Relatórios** | Relatório de acessos geral, por usuário, IP, site ou aplicação, com gráficos de pizza (categorias, firewalls), barras (sites, aplicações, usuários, IPs, máquinas) e linha do tempo de permitidos x bloqueados; tabela completa de quem acessou (usuário, IP, máquina, acessos, primeiro e último acesso, firewall) ou, no relatório de um usuário, do que ele acessou; baixa em PDF (com os gráficos) ou Excel (gráficos e eventos) |
| **Correlação** | Um indicador cruzado nas duas ferramentas, com análise consolidada |
| **Histórico** | Todas as consultas (data, usuário, tipo, termo, resultado), com filtro e exportação |
| **Configuração** | Teste de conexão das APIs, tempo de resposta, logs internos e limpeza de cache (só administradores) |
| **Acessos** | Quem entrou no portal e quem pode emitir relatórios: o administrador inclui o e-mail e liga ou desliga a permissão (só administradores) |

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
│       ├── services\   FortiAnalyzer, Vision One, diagnóstico, reputação, correlação, explicação, exportação, dashboard
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
- [Login Microsoft Entra ID com MFA e permissão de relatórios](docs/CONFIGURACAO_ENTRA.md)
- [Execução local e uso](docs/EXECUCAO_LOCAL.md)
- [Atualização](docs/ATUALIZACAO.md)
- [Arquitetura, banco de dados e API REST](docs/ARQUITETURA.md)
- [Melhorias futuras](docs/ROADMAP.md)

## Segurança da POC

- Tokens só em `config\.env` (fora do git); a tela de configuração nunca os exibe.
- O portal escuta apenas em `127.0.0.1`.
- Com `AUTH_MODE=entra`: login Microsoft (OIDC + PKCE, MSAL), MFA pelo Acesso Condicional, sessão no
  servidor com cookie HttpOnly, permissão de relatórios por usuário e auditoria de login e permissões.
- Todo filtro digitado é validado antes de virar expressão do FortiAnalyzer (sem injeção de filtro).
- Auditoria local em `logs\auditoria.log` e na tabela `query_history` (os logs contêm dados pessoais; LGPD).
- Exportações protegidas contra injeção de fórmulas no Excel.
- Falhas de uma integração não derrubam as outras; cada erro aparece na tela e em `logs\integracoes.log`.
