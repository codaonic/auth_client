from __future__ import annotations

from urllib.parse import urlencode

import httpx

from .validator import TokenValidationError, TokenValidator

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class LogoutError(Exception):
    """The auth service could not process a logout (network failure, wrong
    client credentials, or an unexpected response)."""


class TokenExchangeError(Exception):
    """The auth service refused to exchange an authorization code, or could
    not be reached. `error` is its error code (e.g. "invalid_grant" for a
    code that was already used, has expired, or doesn't match the PKCE
    verifier), or None when there was no response."""

    def __init__(self, message: str, error: str | None = None):
        super().__init__(message)
        self.error = error


class IntrospectionError(Exception):
    """The auth service could not answer an introspection request (network
    failure, wrong client credentials, or an unexpected response)."""


class AuthServiceClient:
    """Calls the auth service on behalf of an application that signs users in
    -- a website backend, a mobile or desktop app.

    Separate from TokenValidator, which a resource server uses to check
    incoming tokens: this is the application's own side of the conversation.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
    ):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self._http = http_client
        self._async_http = async_http_client
        self._own_tokens: TokenValidator | None = None

    @property
    def logout_endpoint(self) -> str:
        return f"{self.issuer}/logout"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/token"

    @property
    def introspection_endpoint(self) -> str:
        return f"{self.issuer}/introspect"

    def _code_form(self, code: str, code_verifier: str, redirect_uri: str | None) -> dict:
        form = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": code_verifier,
        }
        if redirect_uri:
            form["redirect_uri"] = redirect_uri
        if self.client_secret:
            form["client_secret"] = self.client_secret
        return form

    @staticmethod
    def _token_result(resp: httpx.Response) -> dict:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code == 200 and isinstance(body, dict) and "access_token" in body:
            return body
        detail = body.get("detail") if isinstance(body, dict) else None
        error = detail.split(":", 1)[0] if isinstance(detail, str) else None
        raise TokenExchangeError(f"code exchange failed: {resp.status_code} {detail or resp.text}", error)

    def exchange_code(self, code: str, code_verifier: str, redirect_uri: str | None = None) -> dict:
        """Exchange an authorization code for tokens at the auth service's
        /token endpoint.

        Works for every sign-in flow: the redirect, the popup widget, and
        the embedded sign-in (Auth Elements), whose `success` event hands
        your page `code` and `codeVerifier` to post to your backend.
        `redirect_uri` is optional; when given it must be the one the code
        was issued for (for an embedded sign-in, your page's origin).

        Returns the token response: `access_token`, `token_type`,
        `expires_in`, `scope` and `refresh_token`. Raises TokenExchangeError
        when the code is refused or the auth service can't be reached.
        """
        http = self._http or httpx.Client(timeout=5)
        try:
            resp = http.post(self.token_endpoint, data=self._code_form(code, code_verifier, redirect_uri))
        except httpx.HTTPError as exc:
            raise TokenExchangeError(f"code exchange failed: {exc}") from exc
        finally:
            if self._http is None:
                http.close()
        return self._token_result(resp)

    async def aexchange_code(self, code: str, code_verifier: str, redirect_uri: str | None = None) -> dict:
        """Async form of exchange_code(), for use inside an async request handler."""
        http = self._async_http or httpx.AsyncClient(timeout=5)
        try:
            resp = await http.post(self.token_endpoint, data=self._code_form(code, code_verifier, redirect_uri))
        except httpx.HTTPError as exc:
            raise TokenExchangeError(f"code exchange failed: {exc}") from exc
        finally:
            if self._async_http is None:
                await http.aclose()
        return self._token_result(resp)

    def _refresh_form(self, refresh_token: str) -> dict:
        form = {"grant_type": "refresh_token", "client_id": self.client_id, "refresh_token": refresh_token}
        if self.client_secret:
            form["client_secret"] = self.client_secret
        return form

    def refresh(self, refresh_token: str) -> dict:
        """New tokens for a refresh token. The old refresh token stops working;
        store the new one. Raises TokenExchangeError when it's refused (e.g.
        the person was signed out or lost access)."""
        http = self._http or httpx.Client(timeout=5)
        try:
            resp = http.post(self.token_endpoint, data=self._refresh_form(refresh_token))
        except httpx.HTTPError as exc:
            raise TokenExchangeError(f"refresh failed: {exc}") from exc
        finally:
            if self._http is None:
                http.close()
        return self._token_result(resp)

    async def arefresh(self, refresh_token: str) -> dict:
        """Async form of refresh()."""
        http = self._async_http or httpx.AsyncClient(timeout=5)
        try:
            resp = await http.post(self.token_endpoint, data=self._refresh_form(refresh_token))
        except httpx.HTTPError as exc:
            raise TokenExchangeError(f"refresh failed: {exc}") from exc
        finally:
            if self._async_http is None:
                await http.aclose()
        return self._token_result(resp)

    # --- Tokens issued to this app ---

    def _validator(self) -> TokenValidator:
        # The service's issuer always ends in "/". ID and logout tokens are
        # addressed to this app, so the audience is the client ID.
        if self._own_tokens is None:
            self._own_tokens = TokenValidator(self.issuer + "/", self.client_id, http_client=self._http)
        return self._own_tokens

    def verify_id_token(self, id_token: str, nonce: str | None = None) -> dict:
        """Check an ID token from the token response and return its claims
        (sub, email, name, roles...). Pass the `nonce` you sent when starting
        the sign-in. Raises TokenValidationError."""
        header, claims = self._validator()._verify(id_token)
        if header.get("typ") in ("at+jwt", "logout+jwt") or "at_hash" not in claims:
            raise TokenValidationError("not an ID token")
        if claims.get("azp", self.client_id) != self.client_id:
            raise TokenValidationError("ID token was issued to another app")
        if nonce is not None and claims.get("nonce") != nonce:
            raise TokenValidationError("nonce does not match")
        return claims

    def verify_logout_token(self, logout_token: str) -> dict:
        """Check the `logout_token` posted to your back-channel logout URL and
        return its claims: end the sessions matching `sub` (and `sid`, when
        present). Raises TokenValidationError."""
        header, claims = self._validator()._verify(logout_token)
        if header.get("typ") not in (None, "logout+jwt"):
            raise TokenValidationError("not a logout token")
        if BACKCHANNEL_LOGOUT_EVENT not in (claims.get("events") or {}):
            raise TokenValidationError("not a logout token")
        if "nonce" in claims or not (claims.get("sub") or claims.get("sid")):
            raise TokenValidationError("not a logout token")
        return claims

    def _introspect_result(self, resp: httpx.Response) -> dict:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code == 200 and isinstance(body, dict) and "active" in body:
            return body
        raise IntrospectionError(f"introspection failed: {resp.status_code} {resp.text}")

    def introspect(self, token: str) -> dict:
        """Ask whether a token is still good right now: {"active": False}
        once its person is signed out, loses access, or it was revoked.
        Needs a client secret (a confidential app)."""
        http = self._http or httpx.Client(timeout=5)
        try:
            resp = http.post(self.introspection_endpoint, data={"token": token}, auth=(self.client_id, self.client_secret or ""))
        except httpx.HTTPError as exc:
            raise IntrospectionError(f"introspection failed: {exc}") from exc
        finally:
            if self._http is None:
                http.close()
        return self._introspect_result(resp)

    async def aintrospect(self, token: str) -> dict:
        """Async form of introspect()."""
        http = self._async_http or httpx.AsyncClient(timeout=5)
        try:
            resp = await http.post(
                self.introspection_endpoint, data={"token": token}, auth=(self.client_id, self.client_secret or "")
            )
        except httpx.HTTPError as exc:
            raise IntrospectionError(f"introspection failed: {exc}") from exc
        finally:
            if self._async_http is None:
                await http.aclose()
        return self._introspect_result(resp)

    def _logout_form(self, refresh_token: str) -> dict:
        form = {"client_id": self.client_id, "refresh_token": refresh_token}
        if self.client_secret:
            form["client_secret"] = self.client_secret
        return form

    @staticmethod
    def _logout_result(resp: httpx.Response) -> bool:
        if resp.status_code == 200:
            return True
        detail = None
        try:
            detail = resp.json().get("detail")
        except ValueError:
            pass
        if resp.status_code == 400 and detail == "invalid_grant":
            return False
        raise LogoutError(f"logout failed: {resp.status_code} {detail or resp.text}")

    def logout(self, refresh_token: str) -> bool:
        """Sign the user who owns `refresh_token` out of this application.

        Only this application is affected: the user stays signed in to every
        other application, including ones in the same login group. Every
        refresh token this application holds for them is revoked.

        Returns True when the user was signed out, False when the auth
        service no longer recognizes the token (already used, expired, or
        revoked) -- in both cases the caller should clear its own session.
        Raises LogoutError for anything else.
        """
        http = self._http or httpx.Client(timeout=5)
        try:
            resp = http.post(self.logout_endpoint, data=self._logout_form(refresh_token))
        except httpx.HTTPError as exc:
            raise LogoutError(f"logout failed: {exc}") from exc
        finally:
            if self._http is None:
                http.close()
        return self._logout_result(resp)

    async def alogout(self, refresh_token: str) -> bool:
        """Async form of logout(), for use inside an async request handler."""
        http = self._async_http or httpx.AsyncClient(timeout=5)
        try:
            resp = await http.post(self.logout_endpoint, data=self._logout_form(refresh_token))
        except httpx.HTTPError as exc:
            raise LogoutError(f"logout failed: {exc}") from exc
        finally:
            if self._async_http is None:
                await http.aclose()
        return self._logout_result(resp)

    def logout_url(
        self, post_logout_redirect_uri: str | None = None, state: str | None = None, id_token_hint: str | None = None
    ) -> str:
        """URL to redirect the user's browser to, for an application that
        holds no refresh token. `post_logout_redirect_uri` must be listed
        under the application's "After-logout URLs" in the admin console.
        Pass the person's ID token as `id_token_hint` if you have it.
        """
        params = {"client_id": self.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
        return f"{self.logout_endpoint}?{urlencode(params)}"
