# Melhorias futuras

## Fase 2: uso pela equipe

- **Autenticação corporativa**: Microsoft Entra ID (OIDC) com MFA; trocar o campo "Seu nome"
  pelo usuário autenticado no histórico e na auditoria.
- **RBAC**: perfis Sustentação (consulta), Segurança (tudo, inclusive Sandbox) e Auditoria
  (histórico); restrição por ADOM/unidade.
- **Servidor interno**: publicar em uma VM com HTTPS (certificado interno), serviço do Windows
  ou systemd, e chave do Vision One em cofre (Windows Credential Manager ou Azure Key Vault).
- **Retenção/LGPD**: expurgo automático do histórico e das exportações após N dias.

## Vision One

- Telas de **Alertas** (Active, Critical, Open) e **Incidentes/Workbench** sobre
  `/api/v1/alerts`, já disponível na API do portal.
- **Detections** e **IOC Search/Correlation** por usuário e endpoint.
- **Reputação de arquivo/hash** (SHA-1/SHA-256) e envio de arquivo ao Sandbox.
- **Inventário de endpoints**: agentes protegidos, status e política, sobre `/api/v1/endpoints`.

## FortiAnalyzer

- Paginação além de `FAZ_MAX_RESULTS` (offset no `get logsearch`).
- Relatórios prontos via FortiView/Reports do FAZ para o dashboard, em vez de amostras.
- Consultas salvas ("o que o IP X acessou hoje", "bloqueios do usuário Y nesta semana").
- Nome amigável de regras e objetos via FortiManager (se disponível).

## Correlação

- Correlação automática: ao abrir um alerta do Vision One, buscar no FAZ os acessos do mesmo
  host/IP/usuário no período do alerta.
- Indicador de "acesso permitido a recurso malicioso" no dashboard, com alerta para a Segurança.

## Plataforma

- Agendamentos (relatório diário de bloqueios por e-mail).
- Empacotamento (instalador ou Docker) para a fase de produção.
