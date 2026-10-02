# Login com a conta Microsoft (Entra ID) e MFA

Com `AUTH_MODE=entra`, o portal só abre depois do login Microsoft. O que o portal faz:

- OpenID Connect com **authorization code + PKCE**, pela biblioteca oficial da Microsoft (MSAL para Python).
  `state`, `nonce`, emissor, público (aud), validade, locatário (tid) e o tempo desde o último login
  (`max_age`) são conferidos em cada login.
- O usuário é identificado pelo **oid** (ID do objeto no Entra, que não muda), nunca só pelo e-mail.
- A sessão fica no servidor. O navegador recebe um cookie aleatório `HttpOnly` e `SameSite=Lax`, e no
  banco fica só o hash dele. A sessão termina depois de 8 horas ou de 60 minutos sem uso; os dois valores
  podem ser ajustados no `config\.env`.
- Ações na API (POST, PUT, DELETE) exigem um cabeçalho próprio do portal, então outro site não consegue
  agir em nome do usuário (CSRF).
- Login, saída, logins recusados e mudanças de permissão ficam no Histórico (tipos *Login* e *Permissão*)
  e em `logs\auditoria.log`.

**O MFA é exigido pelo Acesso Condicional do Entra ID**, que é como a Microsoft recomenda proteger um
aplicativo: o próprio Entra pede o segundo fator e bloqueia quem não cumprir, antes de o portal receber
qualquer coisa. O ID token v2 não informa o método usado (o claim `amr` não vem nele). Por isso, se quiser
que o portal também confira, use o **contexto de autenticação** opcional (passo 7).

## 1. Registrar o aplicativo

Centro de administração do Microsoft Entra (entra.microsoft.com) > **Identidade > Aplicativos > Registros de aplicativo > Novo registro**:

- Nome: `FortiLogPortal`
- Tipos de conta: **Somente contas deste diretório organizacional** (locatário único)
- URI de redirecionamento: plataforma **Web**, `http://localhost:8000/auth/callback`

Depois, em **Autenticação** do aplicativo, acrescente na mesma plataforma **Web** a URI `http://localhost:8000/auth/saiu`
(página mostrada depois de *Sair*) e salve. Se o registro foi criado sem URI, use **Adicionar uma plataforma > Web**.

Quando o portal for para um servidor com HTTPS, acrescente a URI `https://<servidor>/auth/callback` e mude
`ENTRA_REDIRECT_URI` no `config\.env`. O Entra só aceita `http` para `localhost`.

Na **Visão geral**, copie o **ID do aplicativo (cliente)** e o **ID do diretório (locatário)**.

## 2. Credencial do aplicativo

**Certificados e segredos**:

- **Certificado (recomendado pela Microsoft):** carregue a parte pública (.cer). O arquivo `.pem` com a chave
  privada fica no computador do portal, e você preenche `ENTRA_CERT_PATH` e `ENTRA_CERT_THUMBPRINT`.
- **Segredo do cliente:** crie um segredo, copie o **Valor** (aparece uma vez só) para `ENTRA_CLIENT_SECRET`
  e anote a data de expiração.

O segredo vai só no `config\.env`, nunca no código nem em chat.

## 3. Permissões de API

Basta a permissão padrão **Microsoft Graph > User.Read (delegada)**. O portal pede apenas `openid profile`.
Se a organização exigir, clique em **Conceder consentimento do administrador**.

## 4. Funções de aplicativo (opcional, para controlar pelo Entra)

**Funções de aplicativo > Criar função** (tipo de membro: Usuários/Grupos):

| Nome de exibição | Valor | Dá direito a |
|---|---|---|
| Emitir relatórios | `Relatorios.Emitir` | Aba Relatórios |
| Administrador do portal | `Portal.Admin` | Relatórios, Configuração e Acessos |

Também dá para controlar quem emite relatórios pela aba **Acessos** do portal, sem mexer no Entra (passo 8).
As duas formas valem juntas.

## 5. Quem pode entrar

**Aplicativos empresariais > FortiLogPortal**:

- **Propriedades > Atribuição obrigatória? = Sim**. Só quem for atribuído entra; os demais são recusados pela Microsoft.
- **Usuários e grupos > Adicionar**: adicione o grupo da Sustentação (acesso padrão) e, se usar o passo 4,
  quem recebe `Relatorios.Emitir` ou `Portal.Admin`.

## 6. Exigir MFA (Acesso Condicional)

**Proteção > Acesso Condicional > Nova política** (requer Entra ID P1):

- Usuários: os grupos do passo 5 (ou todos os usuários), excluindo as contas de emergência.
- Recursos de destino: **FortiLogPortal**.
- Conceder: **Exigir força de autenticação > Autenticação multifator** (ou *MFA resistente a phishing*).
- Sessão (opcional): **Frequência de entrada** de 8 horas.
- Comece em **Somente relatório**, confira os logs de entrada e depois mude para **Ativado**.

## 7. Contexto de autenticação (opcional)

Use este passo para o portal também recusar um login que não passou pela política de MFA.

1. **Acesso Condicional > Contexto de autenticação > Novo**: ID `c1`, nome "MFA FortiLogPortal", marque
   *Publicar em aplicativos*.
2. Em uma política de Acesso Condicional, escolha **Recursos de destino > Contexto de autenticação > c1** e
   conceda *Exigir autenticação multifator*.
3. No `config\.env`, defina `ENTRA_AUTH_CONTEXT=c1`.

O portal pede o contexto no login e só aceita o token que traz `acrs = c1`. Se o login passar a ser recusado
com a mensagem "não cumpriu o contexto de autenticação", confira a política. Se precisar liberar o acesso
enquanto confere, deixe `ENTRA_AUTH_CONTEXT` vazio e reinicie o portal: o MFA continua exigido pela política
do passo 6.

## 8. config\.env

```
AUTH_MODE=entra
ENTRA_TENANT_ID=<ID do diretório>
ENTRA_CLIENT_ID=<ID do aplicativo>
ENTRA_CLIENT_SECRET=<valor do segredo>      (ou ENTRA_CERT_PATH + ENTRA_CERT_THUMBPRINT)
ENTRA_REDIRECT_URI=http://localhost:8000/auth/callback
PORTAL_ADMINS=marcello.sousa@marista.org.br
```

Reinicie o portal. Ele passa a abrir em `http://localhost:8000` (o endereço da URI de redirecionamento),
e quem chegar por `127.0.0.1` é levado para lá.

## Permissão de relatórios

Quem pode usar a aba **Relatórios**:

- os administradores (`PORTAL_ADMINS` ou a função `Portal.Admin`);
- quem tiver a função `Relatorios.Emitir` no Entra;
- quem o administrador incluir na aba **Acessos**: digite o e-mail e clique em *Liberar relatórios*.
  A pessoa não precisa ter entrado antes; no primeiro login a permissão é ligada à conta dela (oid).
  Se o e-mail for reaproveitado depois por outra conta, a permissão não passa para ela.

Para tirar a permissão, use a chave *Emite relatórios* na lista. Vale na hora, sem a pessoa sair e entrar de
novo. O botão de lixeira remove a pessoa da lista e encerra as sessões abertas dela. Sem permissão, a aba
some do menu e a API de relatórios responde 403.

As abas **Configuração** e **Acessos** são só dos administradores. As demais abas (Dashboard, Diagnóstico,
Logs, Reputação, Correlação e Histórico) ficam abertas a todos que conseguem entrar.

## Problemas comuns

| Mensagem | O que fazer |
|---|---|
| AADSTS500113 (nenhum endereço de resposta registrado) | O aplicativo não tem URI de redirecionamento: em *Autenticação* > *Adicionar uma plataforma* > **Web**, cadastre `http://localhost:8000/auth/callback` |
| AADSTS50011 (redirect URI não corresponde) | A URI no Entra (plataforma Web) precisa ser idêntica a `ENTRA_REDIRECT_URI` |
| AADSTS50105 (usuário não atribuído) | Adicione a pessoa ou o grupo em *Usuários e grupos* (passo 5) |
| AADSTS7000215 (segredo inválido) | O segredo expirou ou foi copiado o *ID do segredo*; copie o **Valor** |
| "O login expirou ou foi aberto em outra janela" | Comece de novo pelo endereço `http://localhost:8000` |
| "Login não configurado" | A tela lista o que falta no `config\.env` |
