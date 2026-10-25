import base64
import hashlib
import hmac
import json
import time

import httpx
import pytest
from joserfc.jwk import RSAKey

from auth_client import TokenValidationError, TokenValidator
from tests.helpers import ISSUER, RESOURCE_ID, make_token


def _validator(mock_transport) -> TokenValidator:
    return TokenValidator(
        issuer=ISSUER,
        resource_id=RESOURCE_ID,
        jwks_url="https://auth.example.com/jwks.json",
        http_client=httpx.Client(transport=mock_transport),
    )


def test_valid_token_returns_claims(keypair, mock_transport):
    validator = _validator(mock_transport)
    token = make_token(keypair, sub="user-123")

    claims = validator.validate(token)

    assert claims["sub"] == "user-123"
    assert claims["aud"] == RESOURCE_ID


def test_wrong_audience_rejected(keypair, mock_transport):
    validator = _validator(mock_transport)
    token = make_token(keypair, aud="https://other.example.com")

    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_wrong_issuer_rejected(keypair, mock_transport):
    validator = _validator(mock_transport)
    token = make_token(keypair, iss="https://not-the-real-as.example.com")

    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_expired_token_rejected(keypair, mock_transport):
    validator = _validator(mock_transport)
    token = make_token(keypair, ttl=-60)

    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_unknown_kid_rejected(keypair):
    empty_jwks_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": []}))
    validator = TokenValidator(
        issuer=ISSUER,
        resource_id=RESOURCE_ID,
        jwks_url="https://auth.example.com/jwks.json",
        http_client=httpx.Client(transport=empty_jwks_transport),
    )
    token = make_token(keypair)

    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_has_scope(keypair, mock_transport):
    validator = _validator(mock_transport)
    token = make_token(keypair, scope="profile email")
    claims = validator.validate(token)

    assert validator.has_scope(claims, "profile") is True
    assert validator.has_scope(claims, "admin") is False


def test_jwks_cached_across_calls(keypair):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=keypair["jwks"])

    validator = TokenValidator(
        issuer=ISSUER,
        resource_id=RESOURCE_ID,
        jwks_url="https://auth.example.com/jwks.json",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    token = make_token(keypair)

    validator.validate(token)
    validator.validate(token)

    assert calls["count"] == 1


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forged(keypair, alg: str, secret: bytes = b"") -> str:
    header = _b64(json.dumps({"alg": alg, "kid": keypair["kid"], "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": "attacker", "aud": RESOURCE_ID, "iss": ISSUER, "exp": int(time.time()) + 600}).encode())
    signing_input = f"{header}.{body}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest() if alg == "HS256" else b""
    return f"{header}.{body}.{_b64(signature)}"


def test_token_cannot_pick_its_own_algorithm(keypair, mock_transport):
    """Only RS256 is accepted -- whatever `alg` the token's header claims."""
    validator = _validator(mock_transport)
    public_pem = RSAKey.import_key(keypair["jwks"]["keys"][0]).as_pem(private=False)

    for token in (_forged(keypair, "HS256", public_pem), _forged(keypair, "none")):
        with pytest.raises(TokenValidationError):
            validator.validate(token)


def test_allowed_client_ids_accepts_only_listed_clients(keypair, mock_transport):
    validator = TokenValidator(
        issuer=ISSUER,
        resource_id=RESOURCE_ID,
        jwks_url="https://auth.example.com/jwks.json",
        http_client=httpx.Client(transport=mock_transport),
        allowed_client_ids=["my-app"],
    )

    assert validator.validate(make_token(keypair, client_id="my-app"))["client_id"] == "my-app"
    with pytest.raises(TokenValidationError):
        validator.validate(make_token(keypair, client_id="someone-else"))


def test_without_allowed_client_ids_any_client_is_accepted(keypair, mock_transport):
    validator = _validator(mock_transport)
    assert validator.validate(make_token(keypair, client_id="anything"))["client_id"] == "anything"


def test_unknown_kids_do_not_refetch_jwks_on_every_request(keypair):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=keypair["jwks"])

    validator = TokenValidator(
        issuer=ISSUER,
        resource_id=RESOURCE_ID,
        jwks_url="https://auth.example.com/jwks.json",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    for i in range(5):
        with pytest.raises(TokenValidationError):
            validator.validate(make_token(keypair, kid=f"made-up-{i}"))

    assert calls["count"] == 1  # the cold-cache fetch only; refetches wait for the cooldown


def test_unknown_kid_refetches_once_the_cooldown_has_passed(keypair):
    """A key rotated in after the last fetch is still picked up."""
    served = {"jwks": {"keys": []}}
    validator = TokenValidator(
        issuer=ISSUER,
        resource_id=RESOURCE_ID,
        jwks_url="https://auth.example.com/jwks.json",
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=served["jwks"]))),
        refresh_cooldown=0,
    )
    with pytest.raises(TokenValidationError):
        validator.validate(make_token(keypair))

    served["jwks"] = keypair["jwks"]  # the new key is published
    assert validator.validate(make_token(keypair))["iss"] == ISSUER
