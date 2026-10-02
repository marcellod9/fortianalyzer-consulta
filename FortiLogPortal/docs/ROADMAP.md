# Melhorias futuras

## Fase 2: uso pela equipe

- **Autenticação corporativa**: feito (Entra ID com MFA, `AUTH_MODE=entra`; permissão de relatórios por usuário).
- **RBAC**: além de Relatórios, perfis Segurança (Sandbox) e Auditoria (histórico de todos);
  restrição por ADOM/unidade; liberar por grupo do Entra.
- **Servidor interno**: publicar em uma VM com HTTPS (certificado interno), serviço do Windows
  ou systemd, e chave do Vision One em cofre (Windows Credential Manager ou Azure Key Vault).
- **Retenção/LGPD**: expurgo automático do histórico e das exportações após N dias.

## Vision One

- Telas de **Alertas** (Active, Critical, Open) e **Incidentes/Workbench** sobre
  `/api/v1/alerts`, já disponível na API do portal.
- **Detections** e **IOC Search/Correlation** por usuário e endpoint.
- **Reputação de arquivo/hash** (SHA-1/SHA-256) e envio de arquivo ao Sandbox.
- **Inventário de endpoints**: tela com todos os agentes (status e política) sobre `/api/v1/endpoints`.
  A situação de uma máquina já aparece nos detalhes do evento e no Diagnóstico.

## FortiAnalyzer

- Paginação além de `FAZ_MAX_RESULTS` (offset no `get logsearch`).
- Relatórios com totais exatos de períodos longos via FortiView (`/fortiview/adom/{adom}/{view}/run`): a aba
  Relatórios usa a busca de logs porque, em testes publicados de outras versões, o FortiView recusa filtro
  por usuário/aplicação e o `top-websites` agrupa por categoria, não por site. Validar no FAZ 7.4.7 antes.
- Rodar os relatórios nativos do FAZ (Reports) e baixar o PDF pelo portal.
- Consultas salvas ("o que o IP X acessou hoje", "bloqueios do usuário Y nesta semana").
- Nome amigável de regras e objetos via FortiManager (se disponível).

## Correlação

- Correlação automática: ao abrir um alerta do Vision One, buscar no FAZ os acessos do mesmo
  host/IP/usuário no período do alerta.
- Indicador de "acesso permitido a recurso malicioso" no dashboard, com alerta para a Segurança.

## Plataforma

- Agendamentos (relatório diário de bloqueios por e-mail).
- Empacotamento (instalador ou Docker) para a fase de produção.
