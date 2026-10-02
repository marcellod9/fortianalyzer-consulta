# Configuração das APIs

Toda credencial fica em `config\.env` (copiado de `config\.env.example`). Esse arquivo está no
`.gitignore` e nunca deve ser enviado por e-mail, chat ou repositório.

Depois de editar o `.env`, reinicie o portal e use **Configuração > Testar FortiAnalyzer / Testar Vision One**.

---

## 1. FortiAnalyzer (`https://fortianalyzer.marista.edu.br`)

O portal usa a **API JSON-RPC oficial** do FortiAnalyzer (`POST /jsonrpc`), a mesma documentada
no Fortinet Developer Network (FNDN):

| Chamada | Uso |
|---|---|
| `get /sys/status` | teste de conexão (hostname e versão) |
| `get /dvmdb/adom` | lista ADOMs |
| `get /dvmdb/adom/{adom}/device` | lista firewalls (nome, número de série, IP) |
| `add /logview/adom/{adom}/logsearch` (apiver 3, com `limit` e `offset`) | cria a busca de uma página e devolve `tid`. Sem `limit`, o FAZ para em 100 eventos; o máximo é 1000. Cada `tid` entrega uma página: a próxima é uma busca nova com `offset` maior |
| `get /logview/adom/{adom}/logsearch/{tid}` | lê a página até `percentage = 100`; o total vem em `total-count` e é um mínimo quando a página vem cheia |
| `delete /logview/adom/{adom}/logsearch/{tid}` | libera a tarefa no FAZ |

A aba **Relatórios** usa a mesma busca (filtro web e controle de aplicações), então não precisa de
permissão extra além de *Log View*.

A aba **Ameaças** usa a mesma busca nos logs de IPS, antivírus, filtro web (sites maliciosos e phishing),
controle de aplicações (botnet) e DNS, e também:

| URL | Uso |
|---|---|
| `add /fortiview/adom/{adom}/top-threats/run` (apiver 3, `device`, `time-range`, `sort-by` threatweight) | Top Threats, a mesma lista de *FortiView > Threats > Top Threats* -> `tid` |
| `get /fortiview/adom/{adom}/top-threats/run/{tid}` | lê até `percentage = 100`: `threat`, `threattype`, `level_s`, `threatweight`, `incidents`, `incident_block`, `incident_pass`, `cve_list` |
| `get /eventmgmt/adom/{adom}/alerts` (apiver 3, `time-range`, `limit`, `offset`) | alertas do Event Monitor. A aba mostra os dos handlers de IOC e botnet (ex.: *Compromised Host Detection IOC By Threat*, *Botnet Communication Detection*), agrupados por máquina |

A tabela *FortiView > Threats > Indicator of Compromise* não tem consulta na API de IOC (`/ioc/...` só tem
licença, nova varredura e ACK). As mesmas detecções chegam como alertas do Event Monitor, desde que os
handlers padrão de IOC estejam habilitados (*Incidents & Events > Handlers*). Essa leitura exige
**Event Management: Read-Only** no perfil, e o Top Threats exige **FortiView: Read-Only**. Sem uma delas, a parte
correspondente mostra o aviso e o resto da aba continua funcionando.

O **Mapa de ameaças** usa os campos `srccountry`/`dstcountry` dos próprios logs de ameaça (o país do lado externo:
a origem num ataque de entrada do IPS, o destino nos demais).
Além dos logs de IPS, antivírus, filtro web, botnet e DNS, entram os **logs de tráfego com reputação**
(`logtype` traffic com o filtro `crscore>0`; campos `crscore`, `crlevel` e `threats`), a mesma base do Threat Map e
do Top Threats do FAZ. Neles, quando a origem tem país e o destino é a rede interna, o país mostrado é o de origem.
A busca de IPS usa o tipo de log `attack`, o nome do IPS na API do FortiAnalyzer; se a versão recusar, o portal
tenta `ips` uma vez e passa a usar esse nome. O desenho do mapa é local
(`frontend/static/vendor/worldmap`, Natural Earth via world-atlas, licença ISC), sem acesso à internet.

O **Mapa em tempo real** repete a mesma busca de logs a cada 15, 30 ou 60 s, uma fonte por vez (IPS, botnet,
antivírus, sites maliciosos, phishing, DNS), e cada resultado já entra no mapa assim que chega. A primeira consulta
olha os últimos 10 minutos; as seguintes começam 1 minuto antes do evento mais novo já visto daquela fonte (no
máximo 5 minutos), o que deixa cada busca no FAZ curta. Só os eventos que ainda não apareceram são animados. A posição de cada firewall vem
dos campos `latitude`/`longitude` do dispositivo em `get /dvmdb/adom/{adom}/device` (no FortiGate,
`config system global` > `gui-device-latitude`/`gui-device-longitude`); sem eles, o firewall aparece no centro do Brasil.
O FortiAnalyzer pode levar alguns minutos para receber e indexar os logs, então o mapa mostra o que já chegou nele.

A sub-aba **Trend inativo** junta duas fontes. Do FortiAnalyzer vêm as máquinas internas que passaram pelo firewall
no período (FortiView `top-sources`; se a versão não tiver essa visão, os 5000 logs de tráfego mais recentes), com
`srcname`, `srcmac`, `user`, `osname` e `srcintf` da identificação de dispositivos do FortiGate. Do Vision One vem o
inventário `GET /v3.0/endpointSecurity/endpoints` (campos `endpointName`, `lastUsedIp`, `ipAddresses`,
`eppAgent.status`, `eppAgent.lastConnectedDateTime`, `edrSensor.connectivity`, os mesmos do SDK oficial pytmv1),
lido até `V1_INVENTORY_MAX` endpoints e guardado 30 minutos. O cruzamento é pelo nome da máquina e, sem nome, pelo IP.
A máquina que não vier nessa lista é procurada uma a uma no Endpoint Inventory (`GET /v3.0/eiqs/endpoints` com
TMV1-Query pelo nome e pelo IP, até 300 máquinas) e a situação do agente vem de `GET /v3.0/endpointSecurity/endpoints/{id}`,
como na busca de máquina; só quem não é achado por nenhum dos dois aparece como **Sem Trend**.
A chave de API precisa visualizar o Endpoint Inventory.

### Criar o acesso (no FortiAnalyzer)

1. **System Settings > Admin > Profiles**: crie um perfil **somente leitura** com *Log View*
   (Read-Only), *Device Manager* (Read-Only) e, para a aba Ameaças, *Event Management* e *FortiView* (Read-Only).
   Os demais itens em *None*.
2. **System Settings > Admin > Administrators > Create New**:
   - *Admin Type*: **REST API Admin**;
   - *Admin Profile*: o perfil acima;
   - *Administrative Domain*: só as ADOMs necessárias;
   - *Trusted Hosts*: o IP da sua máquina (ou a faixa da VPN/rede da equipe);
   - *JSON API Access*: **Read**.
3. Ao salvar, o FAZ exibe o **token** uma única vez. Cole em `FAZ_API_TOKEN`.

O token é enviado como `Authorization: Bearer <token>` (FortiAnalyzer 7.2.2 ou superior; o
ambiente atual é 7.4.7).

### Variáveis

| Variável | Exemplo | Descrição |
|---|---|---|
| `FAZ_URL` | `https://fortianalyzer.marista.edu.br` | sem `/jsonrpc` no final |
| `FAZ_API_TOKEN` | *(token)* | token do REST API Admin |
| `FAZ_VERIFY_TLS` | `true` | `true`, `false` ou caminho do `.pem` da CA interna |
| `FAZ_DEFAULT_ADOM` | `root` | ADOM selecionada por padrão |
| `FAZ_MAX_RESULTS` | `1000` | máximo de linhas por consulta |
| `REPORT_MAX_ROWS` | `5000` | Relatório geral: eventos lidos por tipo de log para os gráficos (os mais recentes do período; o total vem do FAZ) |
| `REPORT_MAX_ROWS_FILTRADO` | `20000` | Relatório por usuário, IP, site ou aplicação: eventos lidos para a tabela detalhada e os gráficos |
| `FAZ_SEARCH_TIMEOUT` | `120` | segundos até desistir de uma busca |

Se o certificado do FAZ for emitido pela CA interna, exporte a CA em Base64 (`.pem`/`.cer`),
salve em `config\ca-marista.pem` e use `FAZ_VERIFY_TLS=config\ca-marista.pem` (caminho
relativo à pasta FortiLogPortal ou absoluto). Use `false` só em teste.

### Mapeamento dos campos de log (FortiOS 7.x)

| Portal | Campo do log | Observação |
|---|---|---|
| Data e hora | `date` + `time` (ou `itime`) | horário do firewall |
| Firewall | `devname` | |
| IP/porta origem e destino | `srcip`, `srcport`, `dstip`, `dstport` | aceita IP ou rede (`10.1.0.0/16`) |
| Usuário | `user` (ou `unauthuser`) | |
| Site / URL | `hostname` (`qname` em DNS), `url` | |
| Aplicação / categoria | `app`, `appcat`, `catdesc` | |
| Regra | `policyid` + `policyname` | regra 0 = bloqueio implícito |
| Política | `profile` | perfil de segurança (web filter, app control, DNS...) |
| Interfaces | `srcintf`, `dstintf` | |
| Ação | `action` | Allow / Deny / Block |
| Motivo | `eventtype`, `catdesc`, `msg`, `attack`, `virus` | traduzido para linguagem simples |

"Somente bloqueios" usa `action=deny` (tráfego), `blocked` (filtro web, antivírus, SSL),
`block` (aplicações, DNS) e `dropped` (IPS).

---

## 2. Trend Micro Vision One (`https://portal.xdr.trendmicro.com`)

O portal usa a **API pública oficial v3.0** (https://automation.trendmicro.com/xdr/api-v3),
com `Authorization: Bearer <chave>`.

### Região (V1_BASE_URL)

A URL da API depende da região do tenant. `portal.xdr.trendmicro.com` corresponde à região **EUA**:

| Região | V1_BASE_URL |
|---|---|
| EUA | `https://api.xdr.trendmicro.com` |
| Europa | `https://api.eu.xdr.trendmicro.com` |
| Japão | `https://api.xdr.trendmicro.co.jp` |
| Singapura | `https://api.sg.xdr.trendmicro.com` |
| Austrália | `https://api.au.xdr.trendmicro.com` |
| Índia | `https://api.in.xdr.trendmicro.com` |
| Oriente Médio e África | `https://api.mea.xdr.trendmicro.com` |

### Criar a chave de API

1. No console: **Administration > User Roles**: crie uma função (ex.: `FortiLogPortal-Leitura`)
   apenas com permissões de visualização de:
   - *Threat Intelligence > Suspicious Object Management* (View);
   - *Search* (View) — para detecções;
   - *Workbench* (View) — para alertas;
   - *Sandbox Analysis* (View e Submit) — só se for usar a análise de URL;
   - *Endpoint Inventory* (View) — para a *Máquina no Vision One* (agente Trend da máquina de origem).
2. **Administration > API Keys > Add API Key**: escolha a função acima e uma validade.
3. Copie a chave para `V1_API_TOKEN`.

Os nomes exatos das permissões podem variar conforme a versão do console. Se uma fonte
responder HTTP 403, a tela de reputação mostra qual fonte falhou; ajuste a função.

### Endpoints usados

| Endpoint | Uso no portal |
|---|---|
| `GET /v3.0/healthcheck/connectivity` | teste de conexão |
| `GET /v3.0/threatintel/suspiciousObjects` | IOC marcados como suspeitos (risco, ação, validade) |
| `GET /v3.0/threatintel/suspiciousObjectExceptions` | objetos marcados como confiáveis |
| `GET /v3.0/search/detections` + header `TMV1-Query` | detecções do indicador no ambiente |
| `GET /v3.0/workbench/alerts` | alertas que citam o indicador e alertas da máquina ou do usuário (entidades do *impact scope*) |
| `GET /v3.0/eiqs/endpoints` + header `TMV1-Query` | procura a máquina pelo IP ou nome (`ip eq '10.0.0.1' or endpointName eq 'PC-01'`) |
| `GET /v3.0/endpointSecurity/endpoints/{id}` | situação do agente: ligado, último contato, sensor XDR, isolamento |
| `GET /v3.0/endpointSecurity/endpoints` | inventário de endpoints (`/api/v1/endpoints`) |
| `POST /v3.0/sandbox/urls/analyze`, `GET /v3.0/sandbox/tasks/{id}`, `GET /v3.0/sandbox/analysisResults/{id}` | análise de URL no Sandbox (opcional) |
| `GET /v3.0/sandbox/submissionUsage` | cota diária do Sandbox (`submissionRemainingCount`), conferida antes de cada envio |

### Como a reputação é calculada

A API pública v3.0 **não tem um endpoint de "reputação global"** para consultar um IP ou domínio
avulso. O portal consolida as fontes oficiais acima:

| Campo exibido | Origem |
|---|---|
| Reputação | Malicioso (score ≥ 80), Suspeito (≥ 50), Baixo risco, Confiável (exceção) ou Sem registro |
| Risk Score | maior valor entre: risco do Suspicious Object (high 90, medium 65, low 35), score do alerta do Workbench, detecções (≥ 55) e Sandbox |
| Categoria | descrição do Suspicious Object |
| Severidade | risco do Suspicious Object ou severidade do alerta |
| Tipo da ameaça | modelos de alerta, nomes de detecção, tipos do Sandbox |
| IOC relacionados | outros indicadores dos alertas e do Sandbox |
| Última análise | data mais recente entre as fontes |
| Nível de confiança | Alta (Suspicious Object/Sandbox), Média (alerta/detecção), Baixa (sem registro) |
| Fonte | fontes que retornaram ocorrência |
| Recomendações | orientação do portal conforme a classificação |

"Sem registro" significa que o indicador não aparece no tenant no período (`V1_LOOKBACK_DAYS`),
não que é seguro. Para URLs, o Sandbox dá uma análise própria (`V1_SANDBOX_ENABLED=true`;
consome a cota diária de envios do tenant).

**Economia do Sandbox.** Pela tabela de créditos da Trend, cada envio ao Sandbox (manual ou pela
API) custa 2 créditos; consultar o andamento e o resultado não custa. Por isso o portal guarda cada
envio no banco local e, se a mesma URL foi enviada nas últimas 24 h, reaproveita aquela análise
(concluída ou ainda em andamento) em vez de enviar de novo. A tela avisa "Resultado reaproveitado" e
oferece *Analisar de novo*, que pede confirmação e faz um envio novo. Antes de cada envio o portal
consulta a cota do dia: com cota zerada, o envio não sai; se a chave não tiver permissão para ver a
cota, o envio segue normalmente. O reaproveitamento vale para quem usa o mesmo portal (o mesmo
banco); com cada analista rodando o seu, ele é por máquina.

### Consultas de detecções

As consultas usam a sintaxe `campo:"valor"` do header `TMV1-Query`, configuráveis no `.env`:

```
V1_DETECTION_QUERY_URL=request:"{v}"
V1_DETECTION_QUERY_DOMAIN=request:"*{v}*"
V1_DETECTION_QUERY_IP=dst:"{v}" or src:"{v}"
```

Valide no primeiro uso real: faça a mesma busca na tela *Search* do Vision One (fonte
*Detections*) e, se o tenant usar outros campos, ajuste as variáveis.

### Variáveis

| Variável | Padrão | Descrição |
|---|---|---|
| `V1_BASE_URL` | `https://api.xdr.trendmicro.com` | URL da região |
| `V1_API_TOKEN` | *(vazio)* | chave de API |
| `V1_VERIFY_TLS` | `true` | `true`, `false` ou caminho da CA (proxy com inspeção TLS) |
| `V1_LOOKBACK_DAYS` | `30` | janela de busca de detecções e alertas |
| `V1_SANDBOX_ENABLED` | `false` | habilita o envio de URL ao Sandbox |
