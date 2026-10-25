from __future__ import annotations

from urllib.parse import urlencode

import httpx


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

    @property
    def logout_endpoint(self) -> str:
        return f"{self.issuer}/logout"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/token"

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

    def logout_url(self, post_logout_redirect_uri: str | None = None, state: str | None = None) -> str:
        """URL to redirect the user's browser to, for an application that
        holds no refresh token. `post_logout_redirect_uri` must be listed
        under the application's "After-logout URLs" in the admin console.
        """
        params = {"client_id": self.client_id}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
        return f"{self.logout_endpoint}?{urlencode(params)}"
