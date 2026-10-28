import crypto from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * Login único dos apps Resolutec (ADR-025, cofre do Portal).
 *
 * O app não tem tela de login: manda o usuário para o Portal Resolutec e volta com um
 * JWT RS256 de 15 min, que fica num cookie HTTP-only do próprio app. Cada requisição
 * confere a assinatura com a chave pública do portal. Token vencido = repetir o login:
 * com a sessão do portal valendo, o usuário volta na hora, sem ver a tela de login.
 *
 * Dois modos:
 * - **token** (com `publicKey`, o padrão no Studio Creator): o portal entrega o token pelo
 *   navegador, no fragmento da volta (#access_token=…); a página de volta envia o token ao
 *   servidor do app, que valida com a chave pública da variável. Nenhuma chamada de
 *   servidor a servidor — no Creator um app não alcança outro (UND_ERR_CONNECT_TIMEOUT).
 * - **código** (sem `publicKey`): o servidor do app troca o código no /api/sso/token com o
 *   segredo e busca a chave em /api/sso/jwks. Só onde o app alcança o portal.
 *
 * Todo redirecionamento é feito no navegador (200 + HTML): o proxy do Creator segue 302
 * no servidor e perde os cookies. Só para o servidor do app (Node). Sem dependências.
 */

export interface ConfigAuth {
  /** Endereço do portal, sem barra no fim. Ex.: https://portal-resolutec.studio-creator.skyone.cloud */
  portalUrl: string;
  /** Id do app em main.sso_clientes (também é o prefixo das permissões). */
  clientId: string;
  /** Endereço de volta, cadastrado em main.sso_clientes.redirect_uris. Ex.: https://<app>/api/auth/callback */
  redirectUri: string;
  /**
   * Chave pública do portal (variável SSO_PUBLIC_KEY): o JSON do /api/sso/jwks, uma chave JWK
   * ou um PEM (inteiro ou em base64). Com ela o app usa o **modo token**.
   */
  publicKey?: string;
  /** Segredo do app (variável SSO_CLIENT_SECRET). Só no modo código. */
  clientSecret?: string;
  /** Cookie só em HTTPS. Padrão: true (use false em http://localhost). */
  cookieSeguro?: boolean;
  /** Prefixo das rotas que `rotas()` atende. Padrão: /api/auth */
  prefixo?: string;
}

export interface UsuarioResolutec {
  id: number;
  nome: string;
  email: string;
  username: string;
  role: string;
  empresaId: number | null;
  empresa: string | null;
  /** Ids das lojas liberadas, ou "todas" (admin do portal). */
  lojas: string[] | "todas";
  /** Permissões do usuário neste app ("app" ou "app.nivel"). */
  permissoes: string[];
  /** Quando o token vence (ms desde 1970). */
  expiraEm: number;
}

export class ErroAuth extends Error {
  constructor(
    public status: number,
    public codigo: string,
    message: string,
  ) {
    super(message);
  }
}

const JWKS_CACHE_MS = 60 * 60 * 1000;
const STATE_TTL_S = 300;
const CORPO_MAX = 64_000;

function lerCookies(req: IncomingMessage): Record<string, string> {
  const saida: Record<string, string> = {};
  for (const parte of (req.headers.cookie ?? "").split(";")) {
    const i = parte.indexOf("=");
    if (i < 0) continue;
    const nome = parte.slice(0, i).trim();
    if (nome) saida[nome] = decodeURIComponent(parte.slice(i + 1).trim());
  }
  return saida;
}

function adicionarCookie(res: ServerResponse, valor: string): void {
  const atual = res.getHeader("Set-Cookie");
  const lista = Array.isArray(atual) ? atual : atual ? [String(atual)] : [];
  res.setHeader("Set-Cookie", [...lista, valor]);
}

function escaparHtml(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function emJs(v: string): string {
  return JSON.stringify(v).replace(/</g, "\\u003c");
}

/**
 * Redireciona **no navegador** (200 + HTML), nunca com 302: o proxy do Studio Creator segue
 * respostas 302 no servidor e entrega só a resposta final, sem os cookies do meio. Assim o
 * navegador de fato vai ao portal (onde está a sessão) e volta ao app.
 */
export function redirecionarNoNavegador(res: ServerResponse, destino: string): void {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  const attr = escaparHtml(destino);
  res.end(
    `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="robots" content="noindex">` +
      `<meta http-equiv="refresh" content="0;url=${attr}"><title>Entrando…</title></head>` +
      `<body style="font:15px system-ui,sans-serif;padding:24px;color:#55637a">Entrando… ` +
      `<a href="${attr}">continuar</a><script>location.replace(${emJs(destino)})</script></body></html>`,
  );
}

const ESTILO_PAGINA =
  `body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#f6f8fa;color:#121c2d;font:15px/1.55 Inter,"Segoe UI",system-ui,sans-serif;padding:24px 16px}` +
  `main{max-width:440px;background:#fff;border:1px solid #dde2ea;border-radius:24px;padding:32px}` +
  `h1{margin:0 0 8px;font-size:22px;letter-spacing:-.02em}p{margin:0 0 24px;color:#55637a}` +
  `a{display:inline-flex;align-items:center;height:40px;padding:0 18px;border-radius:999px;background:#2459ca;color:#fff;font-weight:600;text-decoration:none}` +
  `@media(prefers-color-scheme:dark){body{background:#0a0f19;color:#f2f5f8}main{background:#111927;border-color:#232d3e}p{color:#9faabc}a{background:#3e71e0}}`;

function blocoDeErro(mensagem: string, tentarDeNovo: string, oculto: boolean): string {
  return (
    `<main id="erro"${oculto ? " hidden" : ""}><h1>Não foi possível entrar</h1><p id="msg">${escaparHtml(mensagem)}</p>` +
    `<a href="${escaparHtml(tentarDeNovo)}">Tentar de novo</a></main>`
  );
}

/** Página de erro do login (sem acesso, login expirado…), com "Tentar de novo". */
function paginaDeErro(res: ServerResponse, status: number, mensagem: string, tentarDeNovo: string): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(
    `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<title>Não foi possível entrar</title><style>${ESTILO_PAGINA}</style></head><body>${blocoDeErro(mensagem, tentarDeNovo, false)}</body></html>`,
  );
}

/**
 * Página da volta no modo token: lê o fragmento (#access_token, state, error), tira o
 * fragmento da barra de endereço e envia ao servidor do app (POST no mesmo caminho, corpo
 * octet-stream — o gateway do Creator só deixa passar POST assim). O servidor valida e
 * responde { destino } ou { message }.
 */
function paginaDeVolta(res: ServerResponse, tentarDeNovo: string): void {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  const script =
    `(async function(){var f=new URLSearchParams(location.hash.slice(1));` +
    `try{history.replaceState(null,"",location.pathname)}catch(e){}` +
    `var erro=function(m){document.getElementById("entrando").hidden=true;document.getElementById("msg").textContent=m;document.getElementById("erro").hidden=false};` +
    `try{var r=await fetch(location.pathname,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/octet-stream"},` +
    `body:JSON.stringify({access_token:f.get("access_token"),state:f.get("state"),error:f.get("error")})});` +
    `var c=await r.json().catch(function(){return {}});if(r.ok&&c.destino){location.replace(c.destino)}else{erro(c.message||"Não foi possível concluir o login.")}}` +
    `catch(e){erro("Não foi possível falar com este app. Tente de novo.")}})();`;
  res.end(
    `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<meta name="robots" content="noindex"><meta name="referrer" content="no-referrer"><title>Entrando…</title><style>${ESTILO_PAGINA}</style></head>` +
      `<body><p id="entrando" style="color:#55637a">Entrando…</p>${blocoDeErro("", tentarDeNovo, true)}<script>${script}</script></body></html>`,
  );
}

function responderJson(res: ServerResponse, status: number, corpo: unknown): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(corpo));
}

/** Corpo JSON do POST (aceita corpo já lido por outra camada, como no portal). */
async function lerCorpoJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const pre = (req as IncomingMessage & { body?: unknown; rawBody?: unknown }).body ?? (req as IncomingMessage & { rawBody?: unknown }).rawBody;
  let texto: string | null = null;
  if (pre instanceof Uint8Array) texto = Buffer.from(pre).toString("utf8");
  else if (typeof pre === "string") texto = pre;
  else if (pre && typeof pre === "object" && Object.keys(pre).length) return pre as Record<string, unknown>;
  if (texto === null) {
    if (req.readableEnded) return {};
    texto = await new Promise<string>((resolve, reject) => {
      const partes: Buffer[] = [];
      let tamanho = 0;
      req.on("data", (p: Buffer) => {
        tamanho += p.length;
        if (tamanho > CORPO_MAX) {
          req.destroy();
          reject(new ErroAuth(413, "corpo_grande", "Requisição grande demais."));
        } else partes.push(p);
      });
      req.on("end", () => resolve(Buffer.concat(partes).toString("utf8")));
      req.on("error", reject);
    });
  }
  try {
    return texto ? (JSON.parse(texto) as Record<string, unknown>) : {};
  } catch {
    throw new ErroAuth(400, "corpo_invalido", "Requisição inválida.");
  }
}

/** Só caminhos internos do app (evita redirecionamento aberto). */
function destinoSeguro(v: string | null | undefined): string {
  if (!v || !v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\")) return "/";
  return v;
}

function iguais(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** SSO_PUBLIC_KEY → chave. Aceita o JSON do /api/sso/jwks, uma JWK ou PEM (inteiro ou base64). */
function lerChavePublica(bruto: string): { chave: crypto.KeyObject; kid: string | null } {
  const v = bruto.trim();
  if (v.startsWith("{")) {
    const json = JSON.parse(v) as { keys?: (crypto.JsonWebKey & { kid?: string })[] } & crypto.JsonWebKey & { kid?: string };
    const jwk = json.keys?.[0] ?? json;
    return { chave: crypto.createPublicKey({ key: jwk, format: "jwk" }), kid: jwk.kid ?? null };
  }
  const pem = v.startsWith("-----BEGIN") ? v.replace(/\\n/g, "\n") : Buffer.from(v, "base64").toString("utf8");
  return { chave: crypto.createPublicKey(pem), kid: null };
}

export function criarAuth(config: ConfigAuth) {
  const portal = config.portalUrl.replace(/\/+$/, "");
  const seguro = config.cookieSeguro ?? true;
  const prefixo = (config.prefixo ?? "/api/auth").replace(/\/+$/, "");
  const cookieSessao = `${config.clientId}_sessao`;
  const cookieState = `${config.clientId}_state`;
  const atributos = `HttpOnly; SameSite=Lax; Path=/${seguro ? "; Secure" : ""}`;
  const fixa = config.publicKey ? lerChavePublica(config.publicKey) : null;
  const modoToken = fixa !== null;
  if (!modoToken && !config.clientSecret) throw new Error("@resolutec/auth: informe publicKey (modo token) ou clientSecret (modo código).");

  let jwks: { chaves: Map<string, crypto.KeyObject>; buscadoEm: number } | null = null;

  async function chavePublica(kid: string): Promise<crypto.KeyObject> {
    if (fixa) {
      if (fixa.kid && fixa.kid !== kid) throw new ErroAuth(401, "token_invalido", "Chave do token diferente da configurada (SSO_PUBLIC_KEY desatualizada?).");
      return fixa.chave;
    }
    const vencido = !jwks || Date.now() - jwks.buscadoEm > JWKS_CACHE_MS;
    // kid desconhecido = o portal trocou a chave: busca de novo (no máximo 1x por minuto).
    const kidNovo = jwks && !jwks.chaves.has(kid) && Date.now() - jwks.buscadoEm > 60_000;
    if (vencido || kidNovo) {
      const r = await fetch(`${portal}/api/sso/jwks`);
      if (!r.ok) throw new ErroAuth(503, "portal_indisponivel", `Portal respondeu ${r.status} no JWKS.`);
      const corpo = (await r.json()) as { keys: (crypto.JsonWebKey & { kid: string })[] };
      jwks = {
        chaves: new Map(corpo.keys.map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })])),
        buscadoEm: Date.now(),
      };
    }
    const chave = jwks!.chaves.get(kid);
    if (!chave) throw new ErroAuth(401, "token_invalido", "Chave do token desconhecida.");
    return chave;
  }

  /** Confere assinatura, validade, app (aud) e emissor (iss); devolve os claims. */
  async function conferir(token: string): Promise<Record<string, unknown>> {
    const partes = token.split(".");
    if (partes.length !== 3) throw new ErroAuth(401, "token_invalido", "Token inválido.");
    const [h, c, s] = partes;
    let header: { alg?: string; kid?: string };
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
      claims = JSON.parse(Buffer.from(c, "base64url").toString("utf8"));
    } catch {
      throw new ErroAuth(401, "token_invalido", "Token inválido.");
    }
    if (header.alg !== "RS256" || !header.kid) throw new ErroAuth(401, "token_invalido", "Algoritmo do token não aceito.");
    const ok = crypto.verify("sha256", Buffer.from(`${h}.${c}`), await chavePublica(header.kid), Buffer.from(s, "base64url"));
    if (!ok) throw new ErroAuth(401, "token_invalido", "Assinatura do token não confere.");
    if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now()) throw new ErroAuth(401, "token_vencido", "Token vencido.");
    if (claims.aud !== config.clientId) throw new ErroAuth(401, "token_invalido", "Token de outro app.");
    if (String(claims.iss).replace(/\/+$/, "") !== portal) throw new ErroAuth(401, "token_invalido", "Token de outro emissor.");
    return claims;
  }

  function paraUsuario(claims: Record<string, unknown>): UsuarioResolutec {
    return {
      id: Number(claims.sub),
      nome: String(claims.name ?? ""),
      email: String(claims.email ?? ""),
      username: String(claims.username ?? ""),
      role: String(claims.role ?? ""),
      empresaId: typeof claims.empresa_id === "number" ? claims.empresa_id : null,
      empresa: typeof claims.empresa === "string" ? claims.empresa : null,
      lojas: claims.lojas === "todas" ? "todas" : Array.isArray(claims.lojas) ? claims.lojas.map(String) : [],
      permissoes: Array.isArray(claims.permissoes) ? claims.permissoes.map(String) : [],
      expiraEm: Number(claims.exp) * 1000,
    };
  }

  async function verificar(token: string): Promise<UsuarioResolutec> {
    return paraUsuario(await conferir(token));
  }

  /** Manda o usuário para o login do portal; depois volta para `destino` (caminho interno). */
  function iniciarLogin(res: ServerResponse, destino = "/"): void {
    const state = crypto.randomBytes(16).toString("base64url");
    const volta = Buffer.from(destinoSeguro(destino)).toString("base64url");
    adicionarCookie(res, `${cookieState}=${state}.${volta}; Max-Age=${STATE_TTL_S}; ${atributos}`);
    const url = new URL(`${portal}/api/sso/authorize`);
    url.searchParams.set("app", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("state", state);
    if (modoToken) url.searchParams.set("response_type", "token");
    redirecionarNoNavegador(res, url.toString());
  }

  /** Confere o state recebido com o do cookie (e apaga o cookie). Devolve o destino guardado. */
  function conferirState(req: IncomingMessage, res: ServerResponse, state: string): { stateGuardado: string; destino: string } {
    const [stateGuardado = "", voltaB64 = ""] = (lerCookies(req)[cookieState] ?? "").split(".");
    adicionarCookie(res, `${cookieState}=; Max-Age=0; ${atributos}`);
    if (!stateGuardado || !iguais(state, stateGuardado)) throw new ErroAuth(400, "state_invalido", "Login expirou ou veio de outra aba. Tente de novo.");
    let destino = "/";
    try {
      destino = destinoSeguro(Buffer.from(voltaB64, "base64url").toString("utf8"));
    } catch {
      destino = "/";
    }
    return { stateGuardado, destino };
  }

  function gravarSessao(res: ServerResponse, token: string, expiraEm: number): void {
    const maxAge = Math.max(0, Math.floor((expiraEm - Date.now()) / 1000));
    adicionarCookie(res, `${cookieSessao}=${token}; Max-Age=${maxAge}; ${atributos}`);
  }

  /** Modo token: a página de volta mandou o token; valida (inclusive nonce = state) e grava a sessão. */
  async function concluirLoginToken(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const corpo = await lerCorpoJson(req);
    const state = typeof corpo.state === "string" ? corpo.state : "";
    const { stateGuardado, destino } = conferirState(req, res, state);
    if (corpo.error === "access_denied") throw new ErroAuth(403, "sem_acesso", "Seu usuário não tem acesso a este app.");
    const token = typeof corpo.access_token === "string" ? corpo.access_token : "";
    if (!token) throw new ErroAuth(400, "sem_token", "O portal não devolveu o acesso.");
    const claims = await conferir(token);
    if (typeof claims.nonce !== "string" || !iguais(claims.nonce, stateGuardado)) throw new ErroAuth(400, "state_invalido", "Login expirou ou veio de outra aba. Tente de novo.");
    const usuario = paraUsuario(claims);
    gravarSessao(res, token, usuario.expiraEm);
    return destino;
  }

  /** Modo código: volta do portal com ?code; troca o código (com o segredo) e grava a sessão. Devolve o destino. */
  async function concluirLogin(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://app");
    const { destino } = conferirState(req, res, url.searchParams.get("state") ?? "");
    if (url.searchParams.get("error") === "access_denied") throw new ErroAuth(403, "sem_acesso", "Seu usuário não tem acesso a este app.");
    const code = url.searchParams.get("code");
    if (!code) throw new ErroAuth(400, "sem_codigo", "O portal não devolveu o código de acesso.");

    // O gateway do Studio Creator só deixa passar POST com corpo octet-stream/text (ADR-002 do portal).
    const r = await fetch(`${portal}/api/sso/token`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectUri,
      }),
    });
    const corpo = (await r.json().catch(() => ({}))) as { access_token?: string; message?: string };
    if (!r.ok || !corpo.access_token) throw new ErroAuth(r.status === 403 ? 403 : 502, "troca_falhou", corpo.message ?? `Portal respondeu ${r.status}.`);

    const usuario = await verificar(corpo.access_token);
    gravarSessao(res, corpo.access_token, usuario.expiraEm);
    return destino;
  }

  /** Usuário da sessão do app, ou null (sem cookie, token vencido ou inválido). */
  async function usuario(req: IncomingMessage): Promise<UsuarioResolutec | null> {
    const token = lerCookies(req)[cookieSessao];
    if (!token) return null;
    try {
      return await verificar(token);
    } catch (err) {
      if (err instanceof ErroAuth && err.codigo === "portal_indisponivel") throw err;
      return null;
    }
  }

  /** Para rotas /api do app: devolve o usuário ou responde 401 (o front manda para `${prefixo}/login`). */
  async function exigirUsuario(req: IncomingMessage, res: ServerResponse): Promise<UsuarioResolutec | null> {
    const u = await usuario(req);
    if (!u) {
      responderJson(res, 401, { success: false, message: "Não autenticado.", login: `${prefixo}/login` });
      return null;
    }
    return u;
  }

  /**
   * Dados atuais no portal (bloqueio e permissões sem esperar o token vencer).
   * Só no modo código: no modo token o app não alcança o portal (devolve null).
   */
  async function consultarPortal(req: IncomingMessage): Promise<Record<string, unknown> | null> {
    if (modoToken) return null;
    const token = lerCookies(req)[cookieSessao];
    if (!token) return null;
    const r = await fetch(`${portal}/api/sso/me`, { headers: { authorization: `Bearer ${token}` } });
    return r.ok ? ((await r.json()) as Record<string, unknown>) : null;
  }

  /** Sai só deste app (a sessão do portal continua; sair de tudo é pelo portal). */
  function sair(res: ServerResponse): void {
    adicionarCookie(res, `${cookieSessao}=; Max-Age=0; ${atributos}`);
  }

  /**
   * Rotas prontas: GET {prefixo}/login?destino=/x, {prefixo}/callback (e POST no modo token),
   * {prefixo}/logout e {prefixo}/me. Devolve true se atendeu. Uso: `if (await auth.rotas(req, res)) return;`
   */
  async function rotas(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? "/", "http://app");
    if (!url.pathname.startsWith(`${prefixo}/`)) return false;
    const rota = url.pathname.slice(prefixo.length);
    const metodo = req.method ?? "GET";
    const tentarDeNovo = `${prefixo}/login`;
    if (metodo === "POST" && rota === "/callback" && modoToken) {
      try {
        responderJson(res, 200, { destino: await concluirLoginToken(req, res) });
      } catch (err) {
        if (!(err instanceof ErroAuth)) throw err;
        responderJson(res, err.status, { success: false, error: err.codigo, message: err.message });
      }
      return true;
    }
    if (metodo !== "GET") return false;
    try {
      if (rota === "/login") {
        iniciarLogin(res, url.searchParams.get("destino") ?? "/");
      } else if (rota === "/callback") {
        if (modoToken) paginaDeVolta(res, tentarDeNovo);
        else redirecionarNoNavegador(res, await concluirLogin(req, res));
      } else if (rota === "/logout") {
        sair(res);
        redirecionarNoNavegador(res, "/");
      } else if (rota === "/me") {
        const u = await exigirUsuario(req, res);
        if (u) responderJson(res, 200, u);
      } else {
        return false;
      }
    } catch (err) {
      if (!(err instanceof ErroAuth)) throw err;
      // Login e volta do portal são navegação: página legível. /me é chamada do front: JSON.
      if (rota === "/me") responderJson(res, err.status, { success: false, error: err.codigo, message: err.message });
      else paginaDeErro(res, err.status, err.message, tentarDeNovo);
    }
    return true;
  }

  return { modo: modoToken ? ("token" as const) : ("codigo" as const), iniciarLogin, concluirLogin, concluirLoginToken, usuario, exigirUsuario, consultarPortal, sair, rotas, verificar };
}

/** Tem a permissão? (o portal já manda só as permissões deste app). */
export function pode(usuario: Pick<UsuarioResolutec, "permissoes">, permissao: string): boolean {
  return usuario.permissoes.includes(permissao);
}

/**
 * Config a partir das variáveis do app: PORTAL_URL, SSO_CLIENT_ID, SSO_REDIRECT_URI, COOKIE_SECURE e
 * SSO_PUBLIC_KEY (modo token, o do Studio Creator) ou SSO_CLIENT_SECRET (modo código).
 */
export function configDoAmbiente(env: Record<string, string | undefined> = process.env): ConfigAuth {
  const faltando = ["PORTAL_URL", "SSO_CLIENT_ID", "SSO_REDIRECT_URI"].filter((k) => !env[k]);
  if (!env.SSO_PUBLIC_KEY && !env.SSO_CLIENT_SECRET) faltando.push("SSO_PUBLIC_KEY");
  if (faltando.length) throw new Error(`@resolutec/auth: faltam as variáveis ${faltando.join(", ")}`);
  return {
    portalUrl: env.PORTAL_URL!,
    clientId: env.SSO_CLIENT_ID!,
    redirectUri: env.SSO_REDIRECT_URI!,
    publicKey: env.SSO_PUBLIC_KEY || undefined,
    clientSecret: env.SSO_CLIENT_SECRET || undefined,
    cookieSeguro: env.COOKIE_SECURE !== "false",
  };
}
