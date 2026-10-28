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
export declare class ErroAuth extends Error {
    status: number;
    codigo: string;
    constructor(status: number, codigo: string, message: string);
}
/**
 * Redireciona **no navegador** (200 + HTML), nunca com 302: o proxy do Studio Creator segue
 * respostas 302 no servidor e entrega só a resposta final, sem os cookies do meio. Assim o
 * navegador de fato vai ao portal (onde está a sessão) e volta ao app.
 */
export declare function redirecionarNoNavegador(res: ServerResponse, destino: string): void;
export declare function criarAuth(config: ConfigAuth): {
    modo: "token" | "codigo";
    iniciarLogin: (res: ServerResponse, destino?: string) => void;
    concluirLogin: (req: IncomingMessage, res: ServerResponse) => Promise<string>;
    concluirLoginToken: (req: IncomingMessage, res: ServerResponse) => Promise<string>;
    usuario: (req: IncomingMessage) => Promise<UsuarioResolutec | null>;
    exigirUsuario: (req: IncomingMessage, res: ServerResponse) => Promise<UsuarioResolutec | null>;
    consultarPortal: (req: IncomingMessage) => Promise<Record<string, unknown> | null>;
    sair: (res: ServerResponse) => void;
    rotas: (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;
    verificar: (token: string) => Promise<UsuarioResolutec>;
};
/** Tem a permissão? (o portal já manda só as permissões deste app). */
export declare function pode(usuario: Pick<UsuarioResolutec, "permissoes">, permissao: string): boolean;
/**
 * Config a partir das variáveis do app: PORTAL_URL, SSO_CLIENT_ID, SSO_REDIRECT_URI, COOKIE_SECURE e
 * SSO_PUBLIC_KEY (modo token, o do Studio Creator) ou SSO_CLIENT_SECRET (modo código).
 */
export declare function configDoAmbiente(env?: Record<string, string | undefined>): ConfigAuth;
