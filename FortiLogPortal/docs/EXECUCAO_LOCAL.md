# Execução local e uso

## Iniciar e parar

- Iniciar: `scripts\start.bat` (abre o navegador em http://127.0.0.1:8000).
- Parar: feche a janela ou pressione `Ctrl+C`.
- Sem abrir o navegador: `powershell -File scripts\start.ps1 -NoBrowser`.
- Desenvolvimento (recarrega ao salvar o código): `powershell -File scripts\start.ps1 -Reload`.
- Outra porta: `PORTAL_PORT=8080` no `config\.env`.

A documentação interativa da API fica em http://127.0.0.1:8000/docs.

## Identificação de quem consulta

Ainda não há autenticação. Digite seu nome/login no campo do topo da tela; ele fica salvo no
navegador e vai para o histórico e para `logs\auditoria.log`. Sem esse campo, o portal registra
o usuário do Windows que iniciou o servidor.

## Roteiro de validação da POC

1. **Configuração**: clique em *Testar FortiAnalyzer* e *Testar Vision One*. Os dois devem
   responder "Conectado".
2. **Diagnóstico**: informe o login de quem reclamou e o site (ex.: `facebook.com`) e clique em
   *Diagnosticar*. Confira se o resultado (bloqueado, permitido ou sem eventos) e a camada que
   bloqueou batem com o FortiAnalyzer. Teste também por IP, por MAC e por nome da máquina.
   *Ver máquina no Vision One* mostra se o agente Trend está ativo e se há alertas abertos.
3. **Logs**: escolha o firewall, adicione o filtro de usuário de quem reclamou de bloqueio e marque
   "Somente bloqueios". Confira se a regra e o motivo batem com o FortiAnalyzer. Teste também o
   botão direito (filtrar/excluir) e o duplo clique (detalhes). Nos detalhes, *Consultar reputação*
   mostra o resultado do Vision One na própria janela (site e, se houver, o IP de destino), com a
   opção *Analisar no Sandbox* para sites/URLs (ao lado, a cota do dia; clicar de novo na mesma URL
   reaproveita a análise das últimas 24 h, com *Analisar de novo* para forçar um envio). Em logs sem login, a coluna Origem mostra o nome da
   máquina (e os detalhes, MAC e sistema) quando o FortiGate tem a identificação de dispositivos ligada.
   *Máquina no Vision One* procura o IP de origem (e o nome da máquina) no inventário do Vision One:
   confira se o agente, o último contato e os alertas batem com o console (*Endpoint Inventory* e
   *Workbench*).
4. **Logs em tempo real**: clique em *Tempo real* (escolha 5 s, 10 s, 30 s ou 1 min). A lista
   começa com os últimos 5 minutos e os eventos novos entram no topo, destacados. Gere um acesso
   bloqueado de teste e veja se ele aparece. *Pausar* para a atualização e libera a exportação.
5. **Logs, outros tipos**: repita com Filtro web e Filtro DNS para ver bloqueios de navegação.
6. **Reputação**: consulte `8.8.8.8`, `google.com`, `https://google.com` e um indicador que
   esteja na lista de Suspicious Objects do tenant. Para sites acessados nas últimas 24 h, a linha
   *FortiGuard* mostra a categoria do site e ela entra no veredito (ex.: Phishing vira Malicioso).
7. **Relatórios**: gere o *Geral (todos)* do último dia e depois *Por usuário* com o login de
   alguém da equipe. Confira os totais com o FortiAnalyzer (Log View, mesmo período e filtro) e
   baixe o PDF e o Excel. Se aparecer o aviso de amostra, o período tem mais eventos do que
   `REPORT_MAX_ROWS` (padrão 5000 por tipo de log): os gráficos usam os mais recentes.
8. **Correlação**: consulte um domínio bloqueado por categoria e um que esteja no Vision One.
9. **Exportação**: exporte um resultado em CSV, XLSX e PDF (cópias ficam em `exports\`).
10. **Histórico e Dashboard**: confira se as consultas aparecem e se os gráficos carregam.

## Dicas de desempenho

- Buscas longas (7 dias, sem filtro) pesam no FortiAnalyzer. Prefira períodos curtos e filtros.
- O tempo real faz uma pesquisa a cada ciclo (olhando os últimos 3 minutos de novo, porque o
  FortiAnalyzer leva alguns segundos para receber e indexar cada log). Ele não atualiza com a aba
  escondida e pausa sozinho depois de 1 hora ligado. Em firewalls muito movimentados, use filtros.
- Resultados ficam em cache por `PORTAL_CACHE_TTL` segundos (padrão 10 min). Para forçar nova
  consulta, use *Configuração > Limpar cache*.
- O dashboard do FortiAnalyzer usa uma amostra dos bloqueios mais recentes (até
  `FAZ_MAX_RESULTS` por tipo de log) e fica em cache por pelo menos 5 minutos.

## Onde olhar quando algo falha

| Arquivo | Conteúdo |
|---|---|
| `logs\app.log` | erros e requisições do portal |
| `logs\integracoes.log` | cada chamada às APIs, com tempo de resposta e falhas |
| `logs\auditoria.log` | quem consultou o quê |
| Tela *Configuração* | os mesmos dados, mais tempo médio por integração |

Mensagens comuns:

| Mensagem | Causa provável |
|---|---|
| FortiAnalyzer recusou o token (HTTP 401/403) | token errado ou seu IP fora dos *Trusted Hosts* |
| sem permissão para este recurso | perfil do REST API Admin sem *Log View*/*Device Manager* ou ADOM não liberada |
| `/dvmdb/adom`: sem permissão | o admin REST não pode listar ADOMs/firewalls; o portal usa `FAZ_DEFAULT_ADOM` e "todos os firewalls". Confira se `FAZ_DEFAULT_ADOM` é o nome exato da ADOM liberada, ou dê *Device Manager: Read-Only* ao perfil |
| Falha de certificado TLS | CA interna não confiável: ajuste `FAZ_VERIFY_TLS`/`V1_VERIFY_TLS` |
| Vision One HTTP 403 | função da chave sem a permissão daquela fonte |
| Máquina no Vision One: inventário com HTTP 403 | função da chave sem *Endpoint Inventory (View)*; os alertas continuam aparecendo |
| Vision One HTTP 404 | `V1_BASE_URL` de outra região |
| Tempo limite da busca excedido | período grande demais; reduza ou filtre |
