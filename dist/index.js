import crypto from "node:crypto";
export class ErroAuth extends Error {
    status;
    codigo;
    constructor(status, codigo, message) {
        super(message);
        this.status = status;
        this.codigo = codigo;
    }
}
const JWKS_CACHE_MS = 60 * 60 * 1000;
const STATE_TTL_S = 300;
function lerCookies(req) {
    const saida = {};
    for (const parte of (req.headers.cookie ?? "").split(";")) {
        const i = parte.indexOf("=");
        if (i < 0)
            continue;
        const nome = parte.slice(0, i).trim();
        if (nome)
            saida[nome] = decodeURIComponent(parte.slice(i + 1).trim());
    }
    return saida;
}
function adicionarCookie(res, valor) {
    const atual = res.getHeader("Set-Cookie");
    const lista = Array.isArray(atual) ? atual : atual ? [String(atual)] : [];
    res.setHeader("Set-Cookie", [...lista, valor]);
}
function escaparHtml(v) {
    return v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
/**
 * Redireciona **no navegador** (200 + HTML), nunca com 302: o proxy do Studio Creator segue
 * respostas 302 no servidor e entrega só a resposta final, sem os cookies do meio. Assim o
 * navegador de fato vai ao portal (onde está a sessão) e volta ao app.
 */
export function redirecionarNoNavegador(res, destino) {
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    const attr = escaparHtml(destino);
    const js = JSON.stringify(destino).replace(/</g, "\\u003c");
    res.end(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="robots" content="noindex">` +
        `<meta http-equiv="refresh" content="0;url=${attr}"><title>Entrando…</title></head>` +
        `<body style="font:15px system-ui,sans-serif;padding:24px;color:#55637a">Entrando… ` +
        `<a href="${attr}">continuar</a><script>location.replace(${js})</script></body></html>`);
}
/** Página de erro do login (sem acesso, login expirado…), com "Tentar de novo". */
function paginaDeErro(res, status, mensagem, tentarDeNovo) {
    res.statusCode = status;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
        `<title>Não foi possível entrar</title><style>` +
        `body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#f6f8fa;color:#121c2d;font:15px/1.55 Inter,"Segoe UI",system-ui,sans-serif;padding:24px 16px}` +
        `main{max-width:440px;background:#fff;border:1px solid #dde2ea;border-radius:24px;padding:32px}` +
        `h1{margin:0 0 8px;font-size:22px;letter-spacing:-.02em}p{margin:0 0 24px;color:#55637a}` +
        `a{display:inline-flex;align-items:center;height:40px;padding:0 18px;border-radius:999px;background:#2459ca;color:#fff;font-weight:600;text-decoration:none}` +
        `@media(prefers-color-scheme:dark){body{background:#0a0f19;color:#f2f5f8}main{background:#111927;border-color:#232d3e}p{color:#9faabc}a{background:#3e71e0}}` +
        `</style></head><body><main><h1>Não foi possível entrar</h1><p>${escaparHtml(mensagem)}</p>` +
        `<a href="${escaparHtml(tentarDeNovo)}">Tentar de novo</a></main></body></html>`);
}
function responderJson(res, status, corpo) {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(corpo));
}
/** Só caminhos internos do app (evita redirecionamento aberto). */
function destinoSeguro(v) {
    if (!v || !v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\"))
        return "/";
    return v;
}
function iguais(a, b) {
    const x = Buffer.from(a);
    const y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}
export function criarAuth(config) {
    const portal = config.portalUrl.replace(/\/+$/, "");
    const seguro = config.cookieSeguro ?? true;
    const prefixo = (config.prefixo ?? "/api/auth").replace(/\/+$/, "");
    const cookieSessao = `${config.clientId}_sessao`;
    const cookieState = `${config.clientId}_state`;
    const atributos = `HttpOnly; SameSite=Lax; Path=/${seguro ? "; Secure" : ""}`;
    let jwks = null;
    async function chavePublica(kid) {
        const vencido = !jwks || Date.now() - jwks.buscadoEm > JWKS_CACHE_MS;
        // kid desconhecido = o portal trocou a chave: busca de novo (no máximo 1x por minuto).
        const kidNovo = jwks && !jwks.chaves.has(kid) && Date.now() - jwks.buscadoEm > 60_000;
        if (vencido || kidNovo) {
            const r = await fetch(`${portal}/api/sso/jwks`);
            if (!r.ok)
                throw new ErroAuth(503, "portal_indisponivel", `Portal respondeu ${r.status} no JWKS.`);
            const corpo = (await r.json());
            jwks = {
                chaves: new Map(corpo.keys.map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })])),
                buscadoEm: Date.now(),
            };
        }
        const chave = jwks.chaves.get(kid);
        if (!chave)
            throw new ErroAuth(401, "token_invalido", "Chave do token desconhecida.");
        return chave;
    }
    /** Confere assinatura, validade, app (aud) e emissor (iss) do token. */
    async function verificar(token) {
        const partes = token.split(".");
        if (partes.length !== 3)
            throw new ErroAuth(401, "token_invalido", "Token inválido.");
        const [h, c, s] = partes;
        let header;
        let claims;
        try {
            header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
            claims = JSON.parse(Buffer.from(c, "base64url").toString("utf8"));
        }
        catch {
            throw new ErroAuth(401, "token_invalido", "Token inválido.");
        }
        if (header.alg !== "RS256" || !header.kid)
            throw new ErroAuth(401, "token_invalido", "Algoritmo do token não aceito.");
        const ok = crypto.verify("sha256", Buffer.from(`${h}.${c}`), await chavePublica(header.kid), Buffer.from(s, "base64url"));
        if (!ok)
            throw new ErroAuth(401, "token_invalido", "Assinatura do token não confere.");
        if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now())
            throw new ErroAuth(401, "token_vencido", "Token vencido.");
        if (claims.aud !== config.clientId)
            throw new ErroAuth(401, "token_invalido", "Token de outro app.");
        if (String(claims.iss).replace(/\/+$/, "") !== portal)
            throw new ErroAuth(401, "token_invalido", "Token de outro emissor.");
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
    function iniciarLogin(res, destino = "/") {
        const state = crypto.randomBytes(16).toString("base64url");
        const volta = Buffer.from(destinoSeguro(destino)).toString("base64url");
        adicionarCookie(res, `${cookieState}=${state}.${volta}; Max-Age=${STATE_TTL_S}; ${atributos}`);
        const url = new URL(`${portal}/api/sso/authorize`);
        url.searchParams.set("app", config.clientId);
        url.searchParams.set("redirect_uri", config.redirectUri);
        url.searchParams.set("state", state);
        redirecionarNoNavegador(res, url.toString());
    }
    /** Volta do portal: confere o state, troca o código pelo token e grava a sessão do app. Devolve o destino. */
    async function concluirLogin(req, res) {
        const url = new URL(req.url ?? "/", "http://app");
        const [stateGuardado = "", voltaB64 = ""] = (lerCookies(req)[cookieState] ?? "").split(".");
        adicionarCookie(res, `${cookieState}=; Max-Age=0; ${atributos}`);
        const state = url.searchParams.get("state") ?? "";
        if (!stateGuardado || !iguais(state, stateGuardado))
            throw new ErroAuth(400, "state_invalido", "Login expirou ou veio de outra aba. Tente de novo.");
        if (url.searchParams.get("error") === "access_denied")
            throw new ErroAuth(403, "sem_acesso", "Seu usuário não tem acesso a este app.");
        const code = url.searchParams.get("code");
        if (!code)
            throw new ErroAuth(400, "sem_codigo", "O portal não devolveu o código de acesso.");
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
        const corpo = (await r.json().catch(() => ({})));
        if (!r.ok || !corpo.access_token)
            throw new ErroAuth(r.status === 403 ? 403 : 502, "troca_falhou", corpo.message ?? `Portal respondeu ${r.status}.`);
        const usuario = await verificar(corpo.access_token);
        const maxAge = Math.max(0, Math.floor((usuario.expiraEm - Date.now()) / 1000));
        adicionarCookie(res, `${cookieSessao}=${corpo.access_token}; Max-Age=${maxAge}; ${atributos}`);
        try {
            return destinoSeguro(Buffer.from(voltaB64, "base64url").toString("utf8"));
        }
        catch {
            return "/";
        }
    }
    /** Usuário da sessão do app, ou null (sem cookie, token vencido ou inválido). */
    async function usuario(req) {
        const token = lerCookies(req)[cookieSessao];
        if (!token)
            return null;
        try {
            return await verificar(token);
        }
        catch (err) {
            if (err instanceof ErroAuth && err.codigo === "portal_indisponivel")
                throw err;
            return null;
        }
    }
    /** Para rotas /api do app: devolve o usuário ou responde 401 (o front manda para `${prefixo}/login`). */
    async function exigirUsuario(req, res) {
        const u = await usuario(req);
        if (!u) {
            responderJson(res, 401, { success: false, message: "Não autenticado.", login: `${prefixo}/login` });
            return null;
        }
        return u;
    }
    /** Dados atuais no portal (bloqueio e permissões sem esperar o token vencer). */
    async function consultarPortal(req) {
        const token = lerCookies(req)[cookieSessao];
        if (!token)
            return null;
        const r = await fetch(`${portal}/api/sso/me`, { headers: { authorization: `Bearer ${token}` } });
        return r.ok ? (await r.json()) : null;
    }
    /** Sai só deste app (a sessão do portal continua; sair de tudo é pelo portal). */
    function sair(res) {
        adicionarCookie(res, `${cookieSessao}=; Max-Age=0; ${atributos}`);
    }
    /**
     * Rotas prontas: GET {prefixo}/login?destino=/x, {prefixo}/callback, {prefixo}/logout e {prefixo}/me.
     * Devolve true se atendeu a requisição. Uso: `if (await auth.rotas(req, res)) return;`
     */
    async function rotas(req, res) {
        const url = new URL(req.url ?? "/", "http://app");
        if (req.method !== "GET" || !url.pathname.startsWith(`${prefixo}/`))
            return false;
        const rota = url.pathname.slice(prefixo.length);
        try {
            if (rota === "/login") {
                iniciarLogin(res, url.searchParams.get("destino") ?? "/");
            }
            else if (rota === "/callback") {
                redirecionarNoNavegador(res, await concluirLogin(req, res));
            }
            else if (rota === "/logout") {
                sair(res);
                redirecionarNoNavegador(res, "/");
            }
            else if (rota === "/me") {
                const u = await exigirUsuario(req, res);
                if (u)
                    responderJson(res, 200, u);
            }
            else {
                return false;
            }
        }
        catch (err) {
            if (!(err instanceof ErroAuth))
                throw err;
            // Login e volta do portal são navegação: página legível. /me é chamada do front: JSON.
            if (rota === "/me")
                responderJson(res, err.status, { success: false, error: err.codigo, message: err.message });
            else
                paginaDeErro(res, err.status, err.message, `${prefixo}/login`);
        }
        return true;
    }
    return { iniciarLogin, concluirLogin, usuario, exigirUsuario, consultarPortal, sair, rotas, verificar };
}
/** Tem a permissão? (o portal já manda só as permissões deste app). */
export function pode(usuario, permissao) {
    return usuario.permissoes.includes(permissao);
}
/** Config a partir das variáveis do app: PORTAL_URL, SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_REDIRECT_URI, COOKIE_SECURE. */
export function configDoAmbiente(env = process.env) {
    const faltando = ["PORTAL_URL", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET", "SSO_REDIRECT_URI"].filter((k) => !env[k]);
    if (faltando.length)
        throw new Error(`@resolutec/auth: faltam as variáveis ${faltando.join(", ")}`);
    return {
        portalUrl: env.PORTAL_URL,
        clientId: env.SSO_CLIENT_ID,
        clientSecret: env.SSO_CLIENT_SECRET,
        redirectUri: env.SSO_REDIRECT_URI,
        cookieSeguro: env.COOKIE_SECURE !== "false",
    };
}
