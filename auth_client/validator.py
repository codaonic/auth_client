from __future__ import annotations

import time
from collections.abc import Iterable

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey
from joserfc.jws import extract_compact
from joserfc.jwt import JWTClaimsRegistry

# AuthService signs every token with RS256. The algorithm is fixed here rather
# than read from the token's own header -- a token must never get to choose
# how it is checked.
ALGORITHM = "RS256"


class TokenValidationError(Exception):
    pass


class TokenValidator:
    """Fetches and caches the auth service's JWKS, and verifies bearer tokens locally.

    No network call to the auth service happens per request -- only when the
    JWKS cache is cold or a token references an unknown `kid` (e.g. right
    after key rotation). Unknown-`kid` refetches are spaced at least
    `refresh_cooldown` seconds apart, so tokens with made-up key IDs can't
    turn every request into a call to the auth service.

    `allowed_client_ids`, when given, also requires the token's `client_id`
    claim to be one of them. The audience alone says which API a token is
    for, not which application the user signed in through -- any client of
    the auth service can get a token for your API, signed in as one of its
    own users. Set this when only your own application(s) should get in.
    """

    def __init__(
        self,
        issuer: str,
        resource_id: str,
        jwks_url: str | None = None,
        cache_ttl: int = 300,
        http_client: httpx.Client | None = None,
        allowed_client_ids: Iterable[str] | None = None,
        refresh_cooldown: float = 30,
    ):
        self.issuer = issuer
        self.resource_id = resource_id
        self.jwks_url = jwks_url or f"{issuer.rstrip('/')}/jwks.json"
        self.cache_ttl = cache_ttl
        self.allowed_client_ids = None if allowed_client_ids is None else frozenset(allowed_client_ids)
        self.refresh_cooldown = refresh_cooldown
        self._http = http_client or httpx.Client(timeout=3)
        self._jwks: dict = {}
        self._cache_expiry = 0.0
        self._fetched_at = float("-inf")
        self._claims = JWTClaimsRegistry(
            iss={"essential": True, "value": issuer},
            aud={"essential": True, "value": resource_id},
            exp={"essential": True},
        )

    def _get_jwks(self, force_refresh: bool = False) -> dict:
        if force_refresh or time.time() > self._cache_expiry:
            resp = self._http.get(self.jwks_url)
            resp.raise_for_status()
            self._jwks = resp.json()
            self._fetched_at = time.time()
            self._cache_expiry = self._fetched_at + self.cache_ttl
        return self._jwks

    def _find_key(self, kid: str) -> dict | None:
        jwks = self._get_jwks()
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if key is None and time.time() - self._fetched_at >= self.refresh_cooldown:
            jwks = self._get_jwks(force_refresh=True)
            key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        return key

    def validate(self, token: str) -> dict:
        """Verify signature (RS256 only), `exp`, `iss`, `aud` (must equal this
        resource_id) and, if `allowed_client_ids` was given, `client_id`.

        Returns the decoded claims on success, or raises TokenValidationError.
        """
        try:
            kid = extract_compact(token.encode()).headers().get("kid")
        except (JoseError, ValueError) as exc:
            raise TokenValidationError("malformed token") from exc

        key = self._find_key(kid) if isinstance(kid, str) else None
        if key is None:
            raise TokenValidationError("unknown signing key")

        try:
            claims = jwt.decode(token, RSAKey.import_key(key), algorithms=[ALGORITHM]).claims
            self._claims.validate(claims)
        except (JoseError, ValueError) as exc:
            raise TokenValidationError(str(exc) or type(exc).__name__) from exc

        if self.allowed_client_ids is not None and claims.get("client_id") not in self.allowed_client_ids:
            raise TokenValidationError("token was not issued to an allowed client")
        return claims

    @staticmethod
    def has_scope(claims: dict, scope: str) -> bool:
        return scope in (claims.get("scope") or "").split()
