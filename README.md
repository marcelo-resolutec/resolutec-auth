# @resolutec/auth

Login único dos apps Resolutec. O app **não tem tela de login**: o usuário entra pelo
Portal Resolutec e volta para o app já identificado, com as permissões que tem neste app.
Decisão e fases: ADR-025 no cofre do portal.

```
navegador ──► app /api/auth/login ──► portal /api/sso/authorize ──(sessão do portal)──►
app /api/auth/callback?code ──► servidor do app troca o código em /api/sso/token ──► JWT (15 min)
──► cookie HTTP-only do app ──► cada requisição confere a assinatura com /api/sso/jwks
```

Token vencido = repetir o login. Enquanto a sessão do portal valer (12 h), o usuário volta
na hora, sem ver tela nenhuma.

## Instalar

Repositório **público**, versão por tag (o `dist/` vai no repositório, já compilado). Instale pelo
**arquivo da versão**, sem Git:

```json
"dependencies": {
  "@resolutec/auth": "https://github.com/marcelo-resolutec/resolutec-auth/archive/refs/tags/v1.1.0.tar.gz"
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
| `SSO_CLIENT_SECRET` | gerado por `node db/sso-chaves.mjs segredo chamados` no portal |
| `SSO_REDIRECT_URI` | `https://<app>.studio-creator.skyone.cloud/api/auth/callback` |
| `COOKIE_SECURE` | `false` só em `http://localhost` |

## Usar no middleware do Vite (mesmo padrão do portal)

```ts
import { criarAuth, configDoAmbiente, pode } from "@resolutec/auth";

const auth = criarAuth(configDoAmbiente());

server.middlewares.use(async (req, res, next) => {
  if (!req.url?.startsWith("/api/")) return next();
  // /api/auth/login?destino=/x, /api/auth/callback, /api/auth/logout, /api/auth/me
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

1. No portal: `node db/sso-chaves.mjs segredo chamados` → o segredo vai em `SSO_CLIENT_SECRET` do app; o hash vai no banco.
2. Banco do portal:
   ```sql
   INSERT INTO main.sso_clientes (id, nome, redirect_uris, segredo_hash, ativo)
   VALUES ('chamados', 'Abertura de chamado', 'https://<app>/api/auth/callback', '<hash>', true);
   INSERT INTO main.app_permissoes (permissao, app_id, label, descricao) VALUES
     ('chamados', 'chamados', 'Abrir chamados', '...'),
     ('chamados.atender', 'chamados', 'Atender', '...');
   ```
3. No portal, `SSO_ATIVO=true` e `SSO_PRIVATE_KEY` nas variáveis do Studio Creator.
4. Dar as permissões aos grupos em Gestão > Grupos.

## Regras

- **Nunca** escrever em `main.*` do banco: usuários e acesso são do portal.
- Cada app usa o próprio schema (`chamados.*`, `monitoramento.*`…).
- Sair do app (`/api/auth/logout`) não sai do portal.

## Publicar uma versão

1. Alterar `src/`, rodar `npm run build` (atualiza `dist/`) e subir a `version` do `package.json`.
2. Commit com o `dist/`, tag `vX.Y.Z` e push da tag.
3. Nos apps, trocar `vX.Y.Z` no endereço do arquivo da versão e reconstruir no Studio Creator.
