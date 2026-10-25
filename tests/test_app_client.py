from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from auth_client import AuthServiceClient, LogoutError, TokenExchangeError
from tests.helpers import ISSUER


def _transport(status: int, body: dict, seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def _client(status=200, body=None, seen=None, secret="s3cret"):
    transport = _transport(status, body if body is not None else {"status": "signed_out"}, seen if seen is not None else [])
    return AuthServiceClient(
        ISSUER,
        "my-app",
        client_secret=secret,
        http_client=httpx.Client(transport=transport),
        async_http_client=httpx.AsyncClient(transport=transport),
    )


def test_logout_posts_client_credentials_and_refresh_token():
    seen: list = []
    assert _client(seen=seen).logout("rt-123") is True

    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == f"{ISSUER}/logout"
    form = parse_qs(request.content.decode())
    assert form == {"client_id": ["my-app"], "client_secret": ["s3cret"], "refresh_token": ["rt-123"]}


def test_public_client_sends_no_secret():
    seen: list = []
    _client(seen=seen, secret=None).logout("rt-123")
    assert "client_secret" not in parse_qs(seen[0].content.decode())


def test_logout_returns_false_when_token_is_no_longer_known():
    assert _client(status=400, body={"detail": "invalid_grant"}).logout("stale") is False


def test_logout_raises_on_bad_client_credentials():
    with pytest.raises(LogoutError):
        _client(status=401, body={"detail": "invalid_client"}).logout("rt-123")


def test_logout_raises_on_network_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = AuthServiceClient(ISSUER, "my-app", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(LogoutError):
        client.logout("rt-123")


async def test_alogout_behaves_like_logout():
    seen: list = []
    assert await _client(seen=seen).alogout("rt-123") is True
    assert parse_qs(seen[0].content.decode())["refresh_token"] == ["rt-123"]
    assert await _client(status=400, body={"detail": "invalid_grant"}).alogout("stale") is False


def test_logout_url():
    client = AuthServiceClient(f"{ISSUER}/", "my app")
    assert client.logout_url() == f"{ISSUER}/logout?client_id=my+app"

    url = urlparse(client.logout_url("https://app.example.com/signed-out?x=1", state="abc"))
    assert parse_qs(url.query) == {
        "client_id": ["my app"],
        "post_logout_redirect_uri": ["https://app.example.com/signed-out?x=1"],
        "state": ["abc"],
    }


TOKENS = {
    "access_token": "at-1",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "openid",
    "refresh_token": "rt-1",
}


def test_exchange_code_posts_code_verifier_and_client_credentials():
    seen: list = []
    assert _client(body=TOKENS, seen=seen).exchange_code("code-1", "verifier-1") == TOKENS

    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == f"{ISSUER}/token"
    assert parse_qs(request.content.decode()) == {
        "grant_type": ["authorization_code"],
        "client_id": ["my-app"],
        "client_secret": ["s3cret"],
        "code": ["code-1"],
        "code_verifier": ["verifier-1"],
    }


def test_exchange_code_sends_redirect_uri_only_when_given():
    seen: list = []
    client = _client(body=TOKENS, seen=seen, secret=None)
    client.exchange_code("code-1", "verifier-1")
    client.exchange_code("code-2", "verifier-2", redirect_uri="https://app.example.com")

    first, second = (parse_qs(r.content.decode()) for r in seen)
    assert "redirect_uri" not in first and "client_secret" not in first
    assert second["redirect_uri"] == ["https://app.example.com"]


def test_exchange_code_raises_with_error_code_when_refused():
    with pytest.raises(TokenExchangeError) as exc_info:
        _client(status=400, body={"detail": "invalid_grant"}).exchange_code("used", "verifier-1")
    assert exc_info.value.error == "invalid_grant"

    with pytest.raises(TokenExchangeError) as exc_info:
        _client(status=400, body={"detail": "invalid_target: resource is disabled"}).exchange_code("c", "v")
    assert exc_info.value.error == "invalid_target"


def test_exchange_code_raises_on_network_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = AuthServiceClient(ISSUER, "my-app", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(TokenExchangeError) as exc_info:
        client.exchange_code("code-1", "verifier-1")
    assert exc_info.value.error is None


async def test_aexchange_code_behaves_like_exchange_code():
    seen: list = []
    assert await _client(body=TOKENS, seen=seen).aexchange_code("code-1", "verifier-1") == TOKENS
    assert parse_qs(seen[0].content.decode())["code"] == ["code-1"]
    with pytest.raises(TokenExchangeError):
        await _client(status=400, body={"detail": "invalid_grant"}).aexchange_code("used", "verifier-1")
