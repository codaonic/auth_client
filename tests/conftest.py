import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc.jwk import RSAKey


@pytest.fixture(scope="module")
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    kid = "test-key-1"
    public_jwk = RSAKey.import_key(pem).as_dict(private=False)
    public_jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"pem": pem.decode(), "kid": kid, "jwks": {"keys": [public_jwk]}}


@pytest.fixture
def mock_transport(keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=keypair["jwks"])

    return httpx.MockTransport(handler)
