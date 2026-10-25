import time
import uuid

from joserfc import jwt
from joserfc.jwk import RSAKey

ISSUER = "https://auth.example.com"
RESOURCE_ID = "https://api.example.com"


def make_token(
    keypair, *, aud=RESOURCE_ID, iss=ISSUER, scope="profile email", ttl=600, sub=None, client_id="my-app", kid=None
):
    now = int(time.time())
    payload = {
        "sub": sub or str(uuid.uuid4()),
        "aud": aud,
        "iss": iss,
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "client_id": client_id,
    }
    header = {"alg": "RS256", "kid": kid or keypair["kid"]}
    return jwt.encode(header, payload, RSAKey.import_key(keypair["pem"]))
