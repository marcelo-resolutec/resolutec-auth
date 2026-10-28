import crypto from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * Login único dos apps Resolutec (ADR-025, cofre do Portal).
 *
 * O app não tem tela de login: manda o usuário para o Portal Resolutec, recebe um
 * código, troca o código (com o segredo do app) por um JWT RS256 de 15 min e guarda
 * o JWT num cookie HTTP-only do próprio app. Cada requisição confere a assinatura com
 * a chave pública do portal (/api/sso/jwks). Token vencido = repetir o login: com a
 * sessão do portal valendo, o usuário volta na hora, sem ver a tela de login.
 *
 * Só para o servidor do app (middleware do Vite / Node). Sem dependências.
 */

export interface ConfigAuth {
  /** Endereço do portal, sem barra no fim. Ex.: https://portal-resolutec.studio-creator.skyone.cloud */
  portalUrl: string;
  /** Id do app em main.sso_clientes (também é o prefixo das permissões). */
  clientId: string;
  /** Segredo do app (variável SSO_CLIENT_SECRET; o portal guarda só o hash). */
  clientSecret: string;
  /** Endereço de volta, cadastrado em main.sso_clientes.redirect_uris. Ex.: https://<app>/api/auth/callback */
  redirectUri: string;
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

function redirecionar(res: ServerResponse, destino: string): void {
  res.statusCode = 302;
  res.setHeader("Location", destino);
  res.end();
}

function responderJson(res: ServerResponse, status: number, corpo: unknown): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(corpo));
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

export function criarAuth(config: ConfigAuth) {
  const portal = config.portalUrl.replace(/\/+$/, "");
  const seguro = config.cookieSeguro ?? true;
  const prefixo = (config.prefixo ?? "/api/auth").replace(/\/+$/, "");
  const cookieSessao = `${config.clientId}_sessao`;
  const cookieState = `${config.clientId}_state`;
  const atributos = `HttpOnly; SameSite=Lax; Path=/${seguro ? "; Secure" : ""}`;

  let jwks: { chaves: Map<string, crypto.KeyObject>; buscadoEm: number } | null = null;

  async function chavePublica(kid: string): Promise<crypto.KeyObject> {
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

  /** Confere assinatura, validade, app (aud) e emissor (iss) do token. */
  async function verificar(token: string): Promise<UsuarioResolutec> {
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
      expiraEm: claims.exp * 1000,
    };
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
    redirecionar(res, url.toString());
  }

  /** Volta do portal: confere o state, troca o código pelo token e grava a sessão do app. Devolve o destino. */
  async function concluirLogin(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://app");
    const [stateGuardado = "", voltaB64 = ""] = (lerCookies(req)[cookieState] ?? "").split(".");
    adicionarCookie(res, `${cookieState}=; Max-Age=0; ${atributos}`);
    const state = url.searchParams.get("state") ?? "";
    if (!stateGuardado || !iguais(state, stateGuardado)) throw new ErroAuth(400, "state_invalido", "Login expirou ou veio de outra aba. Tente de novo.");
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
    const maxAge = Math.max(0, Math.floor((usuario.expiraEm - Date.now()) / 1000));
    adicionarCookie(res, `${cookieSessao}=${corpo.access_token}; Max-Age=${maxAge}; ${atributos}`);
    try {
      return destinoSeguro(Buffer.from(voltaB64, "base64url").toString("utf8"));
    } catch {
      return "/";
    }
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

  /** Dados atuais no portal (bloqueio e permissões sem esperar o token vencer). */
  async function consultarPortal(req: IncomingMessage): Promise<Record<string, unknown> | null> {
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
   * Rotas prontas: GET {prefixo}/login?destino=/x, {prefixo}/callback, {prefixo}/logout e {prefixo}/me.
   * Devolve true se atendeu a requisição. Uso: `if (await auth.rotas(req, res)) return;`
   */
  async function rotas(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? "/", "http://app");
    if (req.method !== "GET" || !url.pathname.startsWith(`${prefixo}/`)) return false;
    const rota = url.pathname.slice(prefixo.length);
    try {
      if (rota === "/login") {
        iniciarLogin(res, url.searchParams.get("destino") ?? "/");
      } else if (rota === "/callback") {
        redirecionar(res, await concluirLogin(req, res));
      } else if (rota === "/logout") {
        sair(res);
        redirecionar(res, "/");
      } else if (rota === "/me") {
        const u = await exigirUsuario(req, res);
        if (u) responderJson(res, 200, u);
      } else {
        return false;
      }
    } catch (err) {
      if (!(err instanceof ErroAuth)) throw err;
      responderJson(res, err.status, { success: false, error: err.codigo, message: err.message });
    }
    return true;
  }

  return { iniciarLogin, concluirLogin, usuario, exigirUsuario, consultarPortal, sair, rotas, verificar };
}

/** Tem a permissão? (o portal já manda só as permissões deste app). */
export function pode(usuario: Pick<UsuarioResolutec, "permissoes">, permissao: string): boolean {
  return usuario.permissoes.includes(permissao);
}

/** Config a partir das variáveis do app: PORTAL_URL, SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_REDIRECT_URI, COOKIE_SECURE. */
export function configDoAmbiente(env: Record<string, string | undefined> = process.env): ConfigAuth {
  const faltando = ["PORTAL_URL", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET", "SSO_REDIRECT_URI"].filter((k) => !env[k]);
  if (faltando.length) throw new Error(`@resolutec/auth: faltam as variáveis ${faltando.join(", ")}`);
  return {
    portalUrl: env.PORTAL_URL!,
    clientId: env.SSO_CLIENT_ID!,
    clientSecret: env.SSO_CLIENT_SECRET!,
    redirectUri: env.SSO_REDIRECT_URI!,
    cookieSeguro: env.COOKIE_SECURE !== "false",
  };
}
