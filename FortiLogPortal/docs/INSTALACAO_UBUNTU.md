# Instalação no servidor (Ubuntu 24.04 LTS)

O portal fica em `/opt/radar-marista`, roda como serviço (`radar-marista`, usuário `radar`, sem login no
sistema) e é publicado pelo nginx em HTTPS. O portal em si só escuta em `127.0.0.1:8000`.

| Caminho | Conteúdo | Preservado na atualização |
|---|---|---|
| `/opt/radar-marista/` | código (somente leitura para o serviço) | substituído |
| `/opt/radar-marista/config/.env` | credenciais e configuração (`root:radar`, 640) | sim |
| `/opt/radar-marista/database/` | banco SQLite (histórico, acessos, eventos guardados) | sim |
| `/opt/radar-marista/logs/` | `app.log`, `auditoria.log`, `integracoes.log` | sim |
| `/opt/radar-marista/exports/`, `cache/` | exportações e cache | sim |
| `/etc/systemd/system/radar-marista.service` | serviço | substituído |
| `/etc/nginx/sites-available/radar-marista` | site HTTPS | criado só na 1ª vez |

## Pré-requisitos de rede

Saída do servidor (HTTPS, 443):

- FortiAnalyzer (`FAZ_URL`) e, se usar, o FortiGate da categoria FortiGuard (`FGT_URL`, porta de administração);
- Vision One (`api.xdr.trendmicro.com` ou a URL da região);
- `login.microsoftonline.com` (login Microsoft);
- `github.com`, `api.github.com` e `codeload.github.com` (só para instalar e atualizar; sem eles use `--zip`);
- repositório de pacotes do Ubuntu e `pypi.org` / `files.pythonhosted.org` (dependências Python).

Entrada: 443 (e 80, que só redireciona para 443) a partir da rede dos analistas.

## 1. Instalar

```bash
sudo apt-get update && sudo apt-get install -y curl unzip
cd /tmp
curl -fSL -o radar.zip https://codeload.github.com/marcellod9/fortianalyzer-consulta/zip/refs/heads/claude/fortilogportal-poc-vf3roq
unzip -q -o radar.zip
sudo bash fortianalyzer-consulta-*/FortiLogPortal/deploy/install.sh
```

O script instala Python, nginx e dependências, cria o usuário `radar`, copia o código para `/opt/radar-marista`,
cria o `.venv`, o serviço e o site do nginx (com um certificado de teste) e confere se o portal responde.

## 2. Configurar o `config/.env`

```bash
sudo nano /opt/radar-marista/config/.env
sudo systemctl restart radar-marista
```

Dá para aproveitar o `config\.env` do Windows (copie o conteúdo para esse arquivo). Confira:

- `PORTAL_HOST=127.0.0.1` (o instalador já ajusta) e `PORTAL_DEMO=false`;
- **login Microsoft**: `AUTH_MODE=entra` e `ENTRA_REDIRECT_URI=https://<nome-do-servidor>/auth/callback`. Cadastre
  esse mesmo endereço no aplicativo do Entra ID (*Authentication > Web > Redirect URIs*). Sem isso o login
  Microsoft recusa com AADSTS50011. O endereço `http://localhost:8000/auth/callback` do Windows pode continuar lá;
- **certificados**: `FAZ_VERIFY_TLS` / `FGT_VERIFY_TLS` com caminho do Windows (`C:\...`) não funcionam aqui. Copie o
  `.pem` da CA interna para `/opt/radar-marista/config/ca-interna.pem` e use esse caminho;
- `ENTRA_CERT_PATH` (se usar certificado em vez de segredo) também precisa de caminho Linux dentro de `config/`.

Depois de editar, `sudo systemctl restart radar-marista`.

### Levar o histórico do Windows (opcional)

Com o portal do Windows fechado, copie `database\fortilogportal.db` para o servidor e:

```bash
sudo systemctl stop radar-marista
sudo cp fortilogportal.db /opt/radar-marista/database/
sudo chown radar:radar /opt/radar-marista/database/fortilogportal.db
sudo systemctl start radar-marista
```

## 3. Certificado HTTPS

O nginx começa com o certificado de teste do Ubuntu (o navegador avisa). Troque pelo da instituição:

```bash
sudo mkdir -p /etc/ssl/radar
sudo cp radar.crt /etc/ssl/radar/radar.crt      # certificado + cadeia intermediária
sudo cp radar.key /etc/ssl/radar/radar.key
sudo chmod 600 /etc/ssl/radar/radar.key
sudo nano /etc/nginx/sites-available/radar-marista
#   ssl_certificate     /etc/ssl/radar/radar.crt;
#   ssl_certificate_key /etc/ssl/radar/radar.key;
#   server_name radar.marista.edu.br;   (opcional)
sudo nginx -t && sudo systemctl reload nginx
```

Esse arquivo não é sobrescrito nas atualizações.

## 4. Atualizar

```bash
sudo /opt/radar-marista/deploy/update.sh
```

Baixa a versão mais recente do GitHub (repositório e branch: `UPDATE_REPO` e `UPDATE_BRANCH` no `.env`), substitui
o código, instala dependências novas e reinicia o serviço. `.env`, banco, logs e exportações ficam como estão.
Opções: `--force` (reinstala mesmo na mesma versão), `--zip arquivo.zip` (servidor sem acesso ao GitHub: baixe o
.zip em outra máquina e copie), `--branch nome`.

Configurações novas que aparecerem no `config/.env.example` precisam ser copiadas à mão para o `.env`, como no
Windows.

## Operação do dia a dia

| Para | Comando |
|---|---|
| Ver se está rodando | `systemctl status radar-marista` |
| Reiniciar (depois de mudar o `.env`) | `sudo systemctl restart radar-marista` |
| Logs do serviço | `journalctl -u radar-marista -n 100 --no-pager` |
| Logs do portal | `sudo tail -f /opt/radar-marista/logs/app.log` |
| Auditoria | `sudo less /opt/radar-marista/logs/auditoria.log` |
| Teste rápido | `curl -s http://127.0.0.1:8000/api/health` |

**Backup**: `config/.env` e `database/` (o resto é reinstalável). Ex.:
`sudo tar czf /root/radar-backup-$(date +%F).tgz -C /opt/radar-marista config/.env database`

## Problemas comuns

| Sintoma | Causa provável |
|---|---|
| `502 Bad Gateway` no navegador | o serviço parou: `journalctl -u radar-marista -n 50` (erro no `.env`, porta 8000 ocupada) |
| Login volta para `localhost:8000` | `ENTRA_REDIRECT_URI` ainda é o do Windows |
| AADSTS50011 | o endereço `https://<servidor>/auth/callback` não está cadastrado no Entra ID |
| Erro de certificado ao consultar o FAZ | `FAZ_VERIFY_TLS` aponta para um caminho do Windows ou para um arquivo que o usuário `radar` não lê |
| `update.sh` não baixa | o servidor não alcança o GitHub: use `--zip` |
