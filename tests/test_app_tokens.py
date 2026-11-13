"""ID tokens, back-channel logout tokens, refresh and introspection."""

import time
import uuid
from urllib.parse import parse_qs

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from auth_client import AuthServiceClient, IntrospectionError, TokenExchangeError, TokenValidationError
from tests.helpers import ISSUER

EVENT = "http://schemas.openid.net/event/backchannel-logout"


def _sign(keypair, claims: dict, typ: str | None = None) -> str:
    header = {"alg": "RS256", "kid": keypair["kid"]}
    if typ:
        header["typ"] = typ
    now = int(time.time())
    body = {"iss": ISSUER + "/", "aud": "my-app", "iat": now, "exp": now + 300, "jti": str(uuid.uuid4()), **claims}
    return jwt.encode(header, body, RSAKey.import_key(keypair["pem"]))


def _client(keypair, handler=None, secret="s3cret"):
    def default(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair["jwks"])

    transport = httpx.MockTransport(handler or default)
    return AuthServiceClient(
        ISSUER,
        "my-app",
        client_secret=secret,
        http_client=httpx.Client(transport=transport),
        async_http_client=httpx.AsyncClient(transport=transport),
    )


def test_verify_id_token_checks_nonce(keypair):
    token = _sign(keypair, {"sub": "u1", "azp": "my-app", "at_hash": "x", "nonce": "n1", "email": "a@b.c"}, typ="JWT")
    client = _client(keypair)
    assert client.verify_id_token(token, nonce="n1")["email"] == "a@b.c"
    with pytest.raises(TokenValidationError):
        client.verify_id_token(token, nonce="other")


def test_verify_id_token_rejects_access_and_logout_tokens(keypair):
    client = _client(keypair)
    with pytest.raises(TokenValidationError):
        client.verify_id_token(_sign(keypair, {"sub": "u1", "client_id": "my-app"}, typ="at+jwt"))
    with pytest.raises(TokenValidationError):
        client.verify_id_token(_sign(keypair, {"sub": "u1", "events": {EVENT: {}}}, typ="logout+jwt"))


def test_verify_id_token_rejects_another_apps_token(keypair):
    other = _sign(keypair, {"sub": "u1", "aud": "other-app", "at_hash": "x"})
    with pytest.raises(TokenValidationError):
        _client(keypair).verify_id_token(other)


def test_verify_logout_token(keypair):
    token = _sign(keypair, {"sub": "u1", "sid": "s1", "events": {EVENT: {}}}, typ="logout+jwt")
    assert _client(keypair).verify_logout_token(token)["sid"] == "s1"


def test_logout_token_needs_the_event_and_no_nonce(keypair):
    client = _client(keypair)
    with pytest.raises(TokenValidationError):
        client.verify_logout_token(_sign(keypair, {"sub": "u1"}, typ="logout+jwt"))
    with pytest.raises(TokenValidationError):
        client.verify_logout_token(_sign(keypair, {"sub": "u1", "nonce": "n", "events": {EVENT: {}}}, typ="logout+jwt"))


def test_refresh_posts_the_refresh_token(keypair):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt2", "token_type": "Bearer", "expires_in": 600, "scope": ""})

    assert _client(keypair, handler).refresh("rt1")["refresh_token"] == "rt2"
    assert seen[0]["grant_type"] == ["refresh_token"] and seen[0]["refresh_token"] == ["rt1"]


def test_refresh_refused(keypair):
    def handler(request):
        return httpx.Response(400, json={"detail": "invalid_grant"})

    with pytest.raises(TokenExchangeError) as err:
        _client(keypair, handler).refresh("rt1")
    assert err.value.error == "invalid_grant"


def test_introspect_uses_basic_auth(keypair):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"active": False})

    assert _client(keypair, handler).introspect("tok") == {"active": False}
    assert seen[0].url.path == "/introspect" and seen[0].headers["authorization"].startswith("Basic ")


def test_introspect_error(keypair):
    with pytest.raises(IntrospectionError):
        _client(keypair, lambda r: httpx.Response(401, json={"detail": "invalid_client"})).introspect("tok")


@pytest.mark.asyncio
async def test_async_forms(keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/introspect":
            return httpx.Response(200, json={"active": True})
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt2"})

    client = _client(keypair, handler)
    assert (await client.aintrospect("t"))["active"] is True
    assert (await client.arefresh("rt"))["refresh_token"] == "rt2"


def test_logout_url_with_id_token_hint():
    url = AuthServiceClient(ISSUER, "my-app").logout_url(id_token_hint="idt", post_logout_redirect_uri="https://a/b")
    assert "id_token_hint=idt" in url and "client_id=my-app" in url
