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
2. **Logs**: escolha o firewall, adicione o filtro de usuário de quem reclamou de bloqueio e marque
   "Somente bloqueios". Confira se a regra e o motivo batem com o FortiAnalyzer. Teste também o
   botão direito (filtrar/excluir) e o duplo clique (detalhes).
3. **Logs, outros tipos**: repita com Filtro web e Filtro DNS para ver bloqueios de navegação.
4. **Reputação**: consulte `8.8.8.8`, `google.com`, `https://google.com` e um indicador que
   esteja na lista de Suspicious Objects do tenant.
5. **Correlação**: consulte um domínio bloqueado por categoria e um que esteja no Vision One.
6. **Exportação**: exporte um resultado em CSV, XLSX e PDF (cópias ficam em `exports\`).
7. **Histórico e Dashboard**: confira se as consultas aparecem e se os gráficos carregam.

## Dicas de desempenho

- Buscas longas (7 dias, sem filtro) pesam no FortiAnalyzer. Prefira períodos curtos e filtros.
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
| Vision One HTTP 404 | `V1_BASE_URL` de outra região |
| Tempo limite da busca excedido | período grande demais; reduza ou filtre |
