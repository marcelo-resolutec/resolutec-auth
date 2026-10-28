# @resolutec/auth

Login único dos apps Resolutec. O app **não tem tela de login**: o usuário entra pelo
Portal Resolutec e volta para o app já identificado, com as permissões que tem neste app.
Decisão e fases: ADR-025 no cofre do portal.

## Ligar um app novo ao login único (passo a passo)

| # | Quem | O quê |
| - | ---- | ----- |
| 1 | dev | Criar o app pelo **chat do Studio Creator**, no projeto **General** (não importar do GitHub: app importado não ganha endereço público). Usar o [pedido modelo](#pedido-modelo-para-o-chat-do-creator). |
| 2 | dev | Anotar o endereço do app: `https://<nome-sem-hífens>-resolutec.studio-creator.skyone.cloud` (ex.: app `app-piloto-sso` → `apppilotosso-resolutec…`). |
| 3 | dev → admin | Pedir ao admin do portal o cadastro: **id** do app (ex.: `chamados`), **endereço de retorno** (`<endereço do app>/api/auth/callback`), **nome** e a **lista de permissões** (`chamados`, `chamados.atender`…). |
| 4 | dev | Colocar as [variáveis](#variáveis-do-app) na aba **Config** do app e clicar em **Reconstruir**. |
| 5 | dev | Ligar o **Preview público** (aba **Publicar**). |
| 6 | dev | [Testar](#testar). |
| 7 | admin | Dar as permissões aos grupos em **Gestão > Grupos** do portal (cliente a cliente). |
| 8 | admin | (opcional) Pôr o ícone do app no Início do portal, para quem tem a permissão. |

> Quem é **admin do portal** faz os passos 3, 7 e 8 (banco e permissões são do portal). O app **nunca**
> escreve em `main.*`.

## Pedido modelo para o chat do Creator

Trocar `<…>` e colar no chat do Creator (modo **Local Agent**):

```text
Crie o app <nome> (React + Vite + TypeScript, backend no middleware do Vite, como o portal).
Login: use o pacote @resolutec/auth (leia o README em https://github.com/marcelo-resolutec/resolutec-auth).
- package.json: "@resolutec/auth": "https://github.com/marcelo-resolutec/resolutec-auth/archive/refs/tags/v1.2.1.tar.gz"
- Trave "@swc/core": "1.16.2" em "overrides" E em "pnpm.overrides".
- No middleware: todas as rotas /api/* (GET e POST) passam primeiro por auth.rotas(req, res);
  as rotas do app usam auth.exigirUsuario(req, res) e pode(usuario, "<id>.<nível>").
- Variáveis (sem valor no código): PORTAL_URL, SSO_CLIENT_ID, SSO_REDIRECT_URI, SSO_PUBLIC_KEY, COOKIE_SECURE.
  Sem elas, /api/* responde 503 "faltam as variáveis" e a tela avisa "App sem configuração".
- No front: chamar /api/auth/me; se vier 401, window.location.assign("/api/auth/login?destino=" + rota atual).
- Mostrar o nome do usuário e um botão "Sair deste app" (<a href="/api/auth/logout">, navegação completa).
- Banco: só o schema <id>.* (nunca main.*).
Ao terminar, rode a checagem de TypeScript e me diga quais arquivos criou.
```

> O chat do Creator segue o pedido à risca, mas **confira o que ele afirma** (já disse que não havia lock
> quando havia). Quando ele muda dependência, pede **Reconstruir**.

## Variáveis do app

| Variável | Valor |
| --- | --- |
| `PORTAL_URL` | `https://portal-resolutec.studio-creator.skyone.cloud` |
| `SSO_CLIENT_ID` | o id do app no portal (ex.: `chamados`), também prefixo das permissões |
| `SSO_REDIRECT_URI` | `<endereço do app>/api/auth/callback` — **igual**, letra por letra, ao cadastrado no portal |
| `SSO_PUBLIC_KEY` | chave **pública** do portal em **PEM base64** (comando abaixo). Não é segredo |
| `COOKIE_SECURE` | `true` no Creator; `false` só em `http://localhost` |
| `SSO_CLIENT_SECRET` | só no modo código (fora do Creator) |

Gerar a `SSO_PUBLIC_KEY` (Node 18+, em qualquer máquina):

```bash
node -e "fetch('https://portal-resolutec.studio-creator.skyone.cloud/api/sso/jwks').then(r=>r.json()).then(j=>console.log(Buffer.from(require('crypto').createPublicKey({key:j.keys[0],format:'jwk'}).export({type:'spki',format:'pem'})).toString('base64')))"
```

> **Use o PEM base64, não o JSON do `/api/sso/jwks`**: o Creator tira as aspas do valor das variáveis
> e o JSON quebra. O pacote também aceita JSON, JWK ou PEM inteiro — fora do Creator.
>
> Se o portal trocar a chave (`SSO_PRIVATE_KEY`), gerar de novo e atualizar a `SSO_PUBLIC_KEY` de **todos** os apps.

## Testar

1. Sem entrar: `<endereço do app>/api/auth/me` → **401** "Não autenticado" (se vier **503**, falta variável).
2. Abrir o app no navegador → vai ao portal (login, se preciso) → volta ao app **já identificado**.
3. Usuário sem permissão no app → página "Seu usuário não tem acesso a este app." (permissão se dá em Gestão > Grupos).
4. "Sair deste app" → página "Você saiu deste app" (o portal continua logado).
5. No portal, **Gestão > Log de acessos** mostra "Entrada em app (login único)" com o id do app.

## Problemas comuns

| Sintoma | Causa e solução |
| ------- | --------------- |
| `{"error":"Proxy error: "}` (502) depois de reiniciar | da plataforma: **Reconstruir** |
| "Failed to load native binding" (`@swc/core`) | faltou travar `@swc/core` 1.16.2 em `overrides` e `pnpm.overrides` |
| instalação falha com código 128 (`cannot run ssh`) | dependência com `github:`/`git+https:`; use o endereço `.tar.gz` da versão |
| app sem endereço público, `403 {"error":"Forbidden."}` | app importado ou Preview público desligado: criar pelo chat do Creator e ligar o Preview público |
| "Chave do token diferente da configurada" | `SSO_PUBLIC_KEY` desatualizada: gerar de novo |
| "Endereço de retorno não autorizado" | `SSO_REDIRECT_URI` diferente do cadastrado no portal |
| volta do portal sem acesso (`access_denied`) | o usuário não tem permissão do app em nenhum grupo |
| login entra e sai sozinho / perde o `state` | algum redirecionamento com 302: no Creator, todos têm de ser pelo navegador (o pacote já faz) |

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
- Usuário com senha provisória (1º acesso) passa pela tela "Crie a sua senha" do portal antes de voltar ao app.

Sem `SSO_PUBLIC_KEY`, o pacote usa o **modo código** (o servidor troca o código em `/api/sso/token`
com `SSO_CLIENT_SECRET` e busca a chave em `/api/sso/jwks`) — só onde o app alcança o portal.

## O que vem no token

`sub` (id do usuário), `name`, `email`, `username`, `role`, `empresa_id`, `empresa` (nome),
`lojas` (lista de lojas ou `"todas"`) e `permissoes` (só as deste app). Validade: 15 min.

## Instalar

Repositório **público**, versão por tag (o `dist/` vai no repositório, já compilado). Instale pelo
**arquivo da versão**, sem Git:

```json
"dependencies": {
  "@resolutec/auth": "https://github.com/marcelo-resolutec/resolutec-auth/archive/refs/tags/v1.2.1.tar.gz"
},
"overrides": { "@swc/core": "1.16.2" },
"pnpm": { "overrides": { "@swc/core": "1.16.2" } }
```

> Não use `github:...` nem `git+https://...` no Studio Creator: a instalação de lá roda sem SSH e sem
> credencial do GitHub, e o instalador tenta SSH para repositórios do GitHub (erro 128). O arquivo da
> versão é baixado por HTTPS comum. O Creator instala com **pnpm** (cai para `npm install` se falhar):
> por isso o `@swc/core` travado nos dois campos.
>
> O pacote é público de propósito: ele **não tem segredo** (só confere o token com a chave pública do
> portal). Segredos ficam nas variáveis de cada app. Nunca colocar chave, segredo ou endereço interno aqui.

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

## Regras

- **Nunca** escrever em `main.*` do banco: usuários e acesso são do portal.
- Cada app usa o próprio schema (`chamados.*`, `monitoramento.*`…).
- Sair do app (`/api/auth/logout`) não sai do portal: mostra a página "Você saiu deste app" com "Entrar de novo" e "Ir para o Portal".

## Versões

| Versão | O que mudou |
| ------ | ----------- |
| 1.0.0 | primeira; modo código, redirecionamento com 302 |
| 1.1.0 | redireciona pelo navegador (200 + HTML); página de erro |
| 1.2.0 | **modo token** (`SSO_PUBLIC_KEY`): token pelo navegador, sem chamada do app ao portal |
| 1.2.1 | "Sair deste app" mostra a página "Você saiu deste app" (antes voltava para `/` e o app entrava de novo sozinho pelo portal) |

## Publicar uma versão

1. Alterar `src/`, rodar `npm run build` (atualiza `dist/`) e subir a `version` do `package.json`.
2. Commit com o `dist/`, tag `vX.Y.Z` e push da tag.
3. Nos apps, trocar `vX.Y.Z` no endereço do arquivo da versão e reconstruir no Studio Creator.
