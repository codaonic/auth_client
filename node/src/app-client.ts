import type { JWTPayload } from "jose";
import { TokenValidationError, TokenValidator } from "./validator.js";

const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

/**
 * Thrown when the auth service could not process a logout (network failure,
 * wrong client credentials, or an unexpected response).
 */
export class LogoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogoutError";
  }
}

/**
 * Thrown when the auth service refused to exchange an authorization code, or
 * could not be reached. `error` is its error code (e.g. "invalid_grant" for a
 * code that was already used, has expired, or doesn't match the PKCE
 * verifier), or undefined when there was no response.
 */
export class TokenExchangeError extends Error {
  readonly error?: string;

  constructor(message: string, error?: string) {
    super(message);
    this.name = "TokenExchangeError";
    this.error = error;
  }
}

/** Thrown when the auth service could not answer an introspection request. */
export class IntrospectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntrospectionError";
  }
}

/** What the auth service's /token endpoint returns. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  refresh_token: string;
  /** Present when the sign-in asked for the `openid` scope. */
  id_token?: string;
}

/** What /introspect returns: just `{ active: false }` for a token that's no longer good. */
export interface IntrospectionResponse {
  active: boolean;
  [claim: string]: unknown;
}

export interface ExchangeCodeOptions {
  /**
   * Optional; when given it must be the one the code was issued for (for an
   * embedded sign-in, your page's origin).
   */
  redirectUri?: string;
}

export interface AuthServiceClientOptions {
  /** Confidential clients only; omit for a public client. */
  clientSecret?: string;
  /** Overrides the global `fetch` (e.g. for tests or a custom agent). */
  fetch?: typeof fetch;
  /** Overrides the "{issuer}/jwks.json" keys used to check ID and logout tokens. */
  jwksUrl?: string;
}

export interface LogoutUrlOptions {
  /** Must be listed under the application's "After-logout URLs" in the admin console. */
  postLogoutRedirectUri?: string;
  state?: string;
  /** The person's ID token, if you have it. */
  idTokenHint?: string;
}

/**
 * Calls the auth service on behalf of an application that signs users in --
 * a website backend, a mobile or desktop app. Separate from TokenValidator,
 * which a resource server uses to check incoming tokens.
 */
export class AuthServiceClient {
  readonly issuer: string;
  readonly clientId: string;

  private readonly clientSecret?: string;
  private readonly fetchImpl: typeof fetch;
  private ownTokens?: TokenValidator;
  private readonly jwksUrl?: string;

  constructor(issuer: string, clientId: string, options: AuthServiceClientOptions = {}) {
    this.issuer = issuer.replace(/\/+$/, "");
    this.clientId = clientId;
    this.clientSecret = options.clientSecret;
    this.fetchImpl = options.fetch ?? fetch;
    this.jwksUrl = options.jwksUrl;
  }

  get logoutEndpoint(): string {
    return `${this.issuer}/logout`;
  }

  get tokenEndpoint(): string {
    return `${this.issuer}/token`;
  }

  get introspectionEndpoint(): string {
    return `${this.issuer}/introspect`;
  }

  /**
   * Exchanges an authorization code for tokens at the auth service's /token
   * endpoint. Works for every sign-in flow: the redirect, the popup widget,
   * and the embedded sign-in (Auth Elements), whose `success` event hands
   * your page `code` and `codeVerifier` to post to your backend.
   *
   * Rejects with TokenExchangeError when the code is refused or the auth
   * service can't be reached.
   */
  async exchangeCode(code: string, codeVerifier: string, options: ExchangeCodeOptions = {}): Promise<TokenResponse> {
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code,
      code_verifier: codeVerifier,
    });
    if (options.redirectUri) form.set("redirect_uri", options.redirectUri);
    return this.postToken(form, "code exchange failed");
  }

  /**
   * New tokens for a refresh token. The old one stops working; store the new
   * one. Rejects with TokenExchangeError when it's refused (e.g. the person
   * was signed out or lost access).
   */
  async refresh(refreshToken: string): Promise<TokenResponse> {
    const form = new URLSearchParams({ grant_type: "refresh_token", client_id: this.clientId, refresh_token: refreshToken });
    return this.postToken(form, "refresh failed");
  }

  /**
   * Checks an ID token from the token response and returns its claims (sub,
   * email, name, roles...). Pass the `nonce` you sent when starting the
   * sign-in. Rejects with TokenValidationError.
   */
  async verifyIdToken(idToken: string, nonce?: string): Promise<JWTPayload> {
    const { payload, header } = await this.validator().verify(idToken);
    if (header.typ === "at+jwt" || header.typ === "logout+jwt" || !("at_hash" in payload)) {
      throw new TokenValidationError("not an ID token");
    }
    if ((payload.azp ?? this.clientId) !== this.clientId) throw new TokenValidationError("ID token was issued to another app");
    if (nonce !== undefined && payload.nonce !== nonce) throw new TokenValidationError("nonce does not match");
    return payload;
  }

  /**
   * Checks the `logout_token` posted to your back-channel logout URL and
   * returns its claims: end the sessions matching `sub` (and `sid`, when
   * present). Rejects with TokenValidationError.
   */
  async verifyLogoutToken(logoutToken: string): Promise<JWTPayload> {
    const { payload, header } = await this.validator().verify(logoutToken);
    const events = (payload.events ?? {}) as Record<string, unknown>;
    if ((header.typ !== undefined && header.typ !== "logout+jwt") || !(BACKCHANNEL_LOGOUT_EVENT in events)) {
      throw new TokenValidationError("not a logout token");
    }
    if ("nonce" in payload || !(payload.sub || payload.sid)) throw new TokenValidationError("not a logout token");
    return payload;
  }

  /**
   * Asks whether a token is still good right now: `{ active: false }` once its
   * person is signed out, loses access, or it was revoked. Needs a client
   * secret (a confidential app).
   */
  async introspect(token: string): Promise<IntrospectionResponse> {
    const basic = Buffer.from(`${encodeURIComponent(this.clientId)}:${encodeURIComponent(this.clientSecret ?? "")}`).toString("base64");
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.introspectionEndpoint, {
        method: "POST",
        body: new URLSearchParams({ token }),
        headers: { Authorization: `Basic ${basic}` },
      });
    } catch (err) {
      throw new IntrospectionError(`introspection failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    const body = (await resp.json().catch(() => undefined)) as IntrospectionResponse | undefined;
    if (resp.status === 200 && body && typeof body.active === "boolean") return body;
    throw new IntrospectionError(`introspection failed: ${resp.status}`);
  }

  // The service's issuer always ends in "/"; ID and logout tokens are
  // addressed to this app, so the audience is the client ID.
  private validator(): TokenValidator {
    this.ownTokens ??= new TokenValidator(`${this.issuer}/`, this.clientId, { jwksUrl: this.jwksUrl });
    return this.ownTokens;
  }

  private async postToken(form: URLSearchParams, failure: string): Promise<TokenResponse> {
    if (this.clientSecret) form.set("client_secret", this.clientSecret);
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.tokenEndpoint, { method: "POST", body: form });
    } catch (err) {
      throw new TokenExchangeError(`${failure}: ${err instanceof Error ? err.message : String(err)}`);
    }

    let body: unknown;
    try {
      body = await resp.json();
    } catch {
      body = undefined;
    }
    if (resp.status === 200 && typeof body === "object" && body !== null && "access_token" in body) {
      return body as TokenResponse;
    }
    const detail = typeof body === "object" && body !== null ? (body as { detail?: unknown }).detail : undefined;
    const error = typeof detail === "string" ? detail.split(":", 1)[0] : undefined;
    throw new TokenExchangeError(`${failure}: ${resp.status} ${typeof detail === "string" ? detail : ""}`.trim(), error);
  }

  /**
   * Signs the user who owns `refreshToken` out of this application. Only
   * this application is affected: the user stays signed in to every other
   * application, including ones in the same login group. Every refresh token
   * this application holds for them is revoked.
   *
   * Resolves true when the user was signed out, false when the auth service
   * no longer recognizes the token (already used, expired, or revoked) -- in
   * both cases the caller should clear its own session. Rejects with
   * LogoutError for anything else.
   */
  async logout(refreshToken: string): Promise<boolean> {
    const form = new URLSearchParams({ client_id: this.clientId, refresh_token: refreshToken });
    if (this.clientSecret) form.set("client_secret", this.clientSecret);

    let resp: Response;
    try {
      resp = await this.fetchImpl(this.logoutEndpoint, { method: "POST", body: form });
    } catch (err) {
      throw new LogoutError(`logout failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (resp.status === 200) return true;

    let detail: unknown;
    try {
      detail = ((await resp.json()) as { detail?: unknown }).detail;
    } catch {
      detail = undefined;
    }
    if (resp.status === 400 && detail === "invalid_grant") return false;
    throw new LogoutError(`logout failed: ${resp.status} ${typeof detail === "string" ? detail : ""}`.trim());
  }

  /**
   * URL to redirect the user's browser to, for an application that holds no
   * refresh token.
   */
  logoutUrl(options: LogoutUrlOptions = {}): string {
    const params = new URLSearchParams({ client_id: this.clientId });
    if (options.idTokenHint) params.set("id_token_hint", options.idTokenHint);
    if (options.postLogoutRedirectUri) params.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    if (options.state) params.set("state", options.state);
    return `${this.logoutEndpoint}?${params}`;
  }
}
