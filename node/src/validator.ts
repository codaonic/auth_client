import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/**
 * Thrown by TokenValidator.validate when a token is malformed, expired, or
 * fails signature/issuer/audience verification.
 */
export class TokenValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenValidationError";
  }
}

export interface TokenValidatorOptions {
  /** Overrides the default "{issuer}/jwks.json" JWKS endpoint. */
  jwksUrl?: string;
  /** How long a fetched JWKS is cached, in milliseconds. Defaults to 5 minutes. */
  cacheMaxAgeMs?: number;
  /**
   * Minimum gap between JWKS refetches triggered by a token with an unknown
   * `kid`, in milliseconds. Defaults to 30 seconds.
   */
  refreshCooldownMs?: number;
  /**
   * Also require the token's `client_id` claim to be one of these. The
   * audience alone says which API a token is for, not which application the
   * user signed in through -- any client of the auth service can get a token
   * for your API, signed in as one of its own users. Set this when only your
   * own application(s) should get in.
   */
  allowedClientIds?: string[];
}

/**
 * Fetches and caches the auth service's JWKS, and verifies bearer tokens
 * locally. No network call to the auth service happens per request -- only
 * when the JWKS cache is cold or a token references an unknown `kid` (e.g.
 * right after key rotation).
 */
export class TokenValidator {
  readonly issuer: string;
  readonly resourceId: string;

  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private readonly allowedClientIds?: ReadonlySet<string>;

  constructor(issuer: string, resourceId: string, options: TokenValidatorOptions = {}) {
    this.issuer = issuer;
    this.resourceId = resourceId;
    const jwksUrl = options.jwksUrl ?? `${issuer.replace(/\/+$/, "")}/jwks.json`;
    this.jwks = createRemoteJWKSet(new URL(jwksUrl), {
      cacheMaxAge: options.cacheMaxAgeMs ?? 5 * 60 * 1000,
      cooldownDuration: options.refreshCooldownMs ?? 30 * 1000,
    });
    if (options.allowedClientIds) this.allowedClientIds = new Set(options.allowedClientIds);
  }

  /**
   * Verifies a bearer token's signature (RS256 only), `exp`, `iss`, `aud` (must
   * equal resourceId) and, if `allowedClientIds` was given, `client_id`. Returns the decoded claims on success, or throws
   * TokenValidationError.
   */
  async validate(token: string): Promise<JWTPayload> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.resourceId,
        algorithms: ["RS256"],
      }));
    } catch (err) {
      throw new TokenValidationError(err instanceof Error ? err.message : "invalid token");
    }
    if (this.allowedClientIds && !this.allowedClientIds.has(String(payload.client_id))) {
      throw new TokenValidationError("token was not issued to an allowed client");
    }
    return payload;
  }

  /** Reports whether claims carries the given scope in its space-separated `scope` claim. */
  static hasScope(claims: JWTPayload, scope: string): boolean {
    const raw = claims.scope;
    if (typeof raw !== "string") return false;
    return raw.split(/\s+/).filter(Boolean).includes(scope);
  }
}
