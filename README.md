# @resolutec/auth

Login único dos apps Resolutec. O app **não tem tela de login**: o usuário entra pelo
Portal Resolutec e volta para o app já identificado, com as permissões que tem neste app.
Decisão e fases: ADR-025 no cofre do portal.

## Modo token (o do Studio Creator)

No Creator um app **não alcança outro de servidor a servidor** (`UND_ERR_CONNECT_TIMEOUT`).
Por isso o token vem **pelo navegador** e o app valida com a chave pública numa variável:

```
navegador ──► app /api/auth/login ──► portal /api/sso/authorize?response_type=token ──(sessão do portal)──►
app /api/auth/callback#access_token=… (fragmento: só o navegador lê) ──► página de volta envia o token
ao servidor do app (POST) ──► confere assinatura (SSO_PUBLIC_KEY), app, validade e state ──► cookie HTTP-only
```

- Todo redirecionamento é **no navegador** (200 + HTML): o proxy do Creator segue 302 no servidor e perde os cookies.
- O token leva o `state` (`nonce`): token de outra tentativa de login é recusado.
- Token vencido (15 min) = repetir o login; com a sessão do portal valendo (12 h), volta na hora.
- Bloquear o usuário no portal vale **no próximo login** (até 15 min). `consultarPortal()` não funciona neste modo.

Sem `SSO_PUBLIC_KEY`, o pacote usa o **modo código** (o servidor troca o código em `/api/sso/token`
com `SSO_CLIENT_SECRET` e busca a chave em `/api/sso/jwks`) — só onde o app alcança o portal.

## Instalar

Repositório **público**, versão por tag (o `dist/` vai no repositório, já compilado). Instale pelo
**arquivo da versão**, sem Git:

```json
"dependencies": {
  "@resolutec/auth": "https://github.com/marcelo-resolutec/resolutec-auth/archive/refs/tags/v1.2.0.tar.gz"
}
```

> Não use `github:...` nem `git+https://...` no Studio Creator: a instalação de lá roda sem SSH e sem
> credencial do GitHub, e o instalador tenta SSH para repositórios do GitHub (erro 128). O arquivo da
> versão é baixado por HTTPS comum.
>
> O pacote é público de propósito: ele **não tem segredo** (só confere o token com a chave pública do
> portal). Segredos ficam nas variáveis de cada app. Nunca colocar chave, segredo ou endereço interno aqui.

## Variáveis do app

| Variável | Exemplo |
| --- | --- |
| `PORTAL_URL` | `https://portal-resolutec.studio-creator.skyone.cloud` |
| `SSO_CLIENT_ID` | `chamados` (id em `main.sso_clientes`, prefixo das permissões) |
| `SSO_REDIRECT_URI` | `https://<app>.studio-creator.skyone.cloud/api/auth/callback` |
| `SSO_PUBLIC_KEY` | o JSON de `https://portal-resolutec.studio-creator.skyone.cloud/api/sso/jwks` (chave **pública**, não é segredo) |
| `COOKIE_SECURE` | `false` só em `http://localhost` |
| `SSO_CLIENT_SECRET` | só no modo código |

> Se o portal trocar a `SSO_PRIVATE_KEY`, atualizar a `SSO_PUBLIC_KEY` de **todos** os apps.

## Usar no middleware do Vite (mesmo padrão do portal)

```ts
import { criarAuth, configDoAmbiente, pode } from "@resolutec/auth";

const auth = criarAuth(configDoAmbiente());

server.middlewares.use(async (req, res, next) => {
  if (!req.url?.startsWith("/api/")) return next();
  // GET /api/auth/login?destino=/x, GET+POST /api/auth/callback, /api/auth/logout, /api/auth/me
  if (await auth.rotas(req, res)) return;

  const usuario = await auth.exigirUsuario(req, res); // 401 sem sessão
  if (!usuario) return;
  if (!pode(usuario, "chamados.atender")) { res.statusCode = 403; return res.end(); }
  // ...
});
```

No front: chamar `/api/auth/me`; se vier **401**, ir para
`/api/auth/login?destino=<rota atual>` com `window.location.assign` (navegação completa, não do React Router).

## Cadastrar o app no portal (uma vez, com autorização)

1. Banco do portal (o `segredo_hash` só é usado no modo código; no modo token pode ser o hash de um segredo qualquer):
   ```sql
   INSERT INTO main.sso_clientes (id, nome, redirect_uris, segredo_hash, ativo)
   VALUES ('chamados', 'Abertura de chamado', 'https://<app>/api/auth/callback', '<hash>', true);
   INSERT INTO main.app_permissoes (permissao, app_id, label, descricao) VALUES
     ('chamados', 'chamados', 'Abrir chamados', '...'),
     ('chamados.atender', 'chamados', 'Atender', '...');
   ```
2. No app: as variáveis acima, com `SSO_PUBLIC_KEY` copiada do `/api/sso/jwks` do portal.
3. No portal, `SSO_ATIVO=true` e `SSO_PRIVATE_KEY` nas variáveis do Studio Creator.
4. Dar as permissões aos grupos em Gestão > Grupos.

## Regras

- **Nunca** escrever em `main.*` do banco: usuários e acesso são do portal.
- Cada app usa o próprio schema (`chamados.*`, `monitoramento.*`…).
- Sair do app (`/api/auth/logout`) não sai do portal.

## Versões

| Versão | O que mudou |
| ------ | ----------- |
| 1.0.0 | primeira; modo código, redirecionamento com 302 |
| 1.1.0 | redireciona pelo navegador (200 + HTML); página de erro |
| 1.2.0 | **modo token** (`SSO_PUBLIC_KEY`): token pelo navegador, sem chamada do app ao portal |

## Publicar uma versão

1. Alterar `src/`, rodar `npm run build` (atualiza `dist/`) e subir a `version` do `package.json`.
2. Commit com o `dist/`, tag `vX.Y.Z` e push da tag.
3. Nos apps, trocar `vX.Y.Z` no endereço do arquivo da versão e reconstruir no Studio Creator.
