# auth-client

![version](https://img.shields.io/badge/version-0.4.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Go](https://img.shields.io/badge/go-1.21%2B-blue)
![Node](https://img.shields.io/badge/node-18%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Official Python, Node and Go client for [AuthService](https://github.com/codaonic/AuthService), a self-hosted OAuth 2.1 and OpenID Connect server.

- **APIs and MCP servers** use `TokenValidator` to check access tokens locally against the cached JWKS.
- **Applications that sign people in** use `AuthServiceClient` to exchange codes, verify ID tokens, refresh, log out and handle back-channel logout.

## Contents

- [Install](#install)
- [Protecting an API or MCP server](#protecting-an-api-or-mcp-server)
- [Signing people in](#signing-people-in)
- [API reference](#api-reference)
- [Compatibility](#compatibility)
- [Development](#development)
- [Releasing](#releasing)
- [License](#license)

## Install

Releases are published as files on [GitHub Releases](https://github.com/codaonic/auth-client/releases), not on PyPI or npm.

```bash
# Python (add [fastapi] for the FastAPI helpers)
pip install "auth-client[fastapi] @ https://github.com/codaonic/auth-client/releases/download/v0.4.0/auth_client-0.4.0-py3-none-any.whl"

# Node
npm install "https://github.com/codaonic/auth-client/releases/download/v0.4.0/auth-client-0.4.0.tgz"

# Go
go get github.com/codaonic/auth-client/go@v0.4.0
```

<details>
<summary>Installing from a private repository</summary>

Download the file with a token first, then install it locally:

```bash
curl -L -H "Authorization: Bearer $GITHUB_TOKEN" -O \
  "https://github.com/codaonic/auth-client/releases/download/v0.4.0/auth_client-0.4.0-py3-none-any.whl"
pip install "./auth_client-0.4.0-py3-none-any.whl[fastapi]"
```

</details>

## Protecting an API or MCP server

`TokenValidator` checks the signature (RS256 only), `iss`, `aud` and `exp`. It fetches the JWKS once and caches it; there is no call to the auth service per request.

### Python (FastAPI)

```python
from fastapi import Depends, FastAPI
from auth_client import TokenValidator
from auth_client.fastapi import make_auth_dependency, make_scope_dependency
from auth_client.protected_resource import protected_resource_router

ISSUER = "https://auth.yourdomain.com/"
RESOURCE_ID = "https://api.yourdomain.com"

validator = TokenValidator(issuer=ISSUER, resource_id=RESOURCE_ID)
require_auth = make_auth_dependency(validator)

app = FastAPI()
app.include_router(protected_resource_router(RESOURCE_ID, ISSUER, resource_name="Your API"))

@app.get("/me")
async def me(claims: dict = Depends(require_auth)):
    return {"sub": claims["sub"], "roles": claims.get("roles", [])}

@app.get("/profile")
async def profile(claims: dict = Depends(make_scope_dependency(validator, "profile"))):
    return {"sub": claims["sub"]}
```

Without FastAPI, call `validator.validate(token)` directly; it returns the claims or raises `TokenValidationError`.

### Node (Express)

```ts
import express from "express";
import { TokenValidator, protectedResourceRouter } from "auth-client";
import { makeAuthMiddleware } from "auth-client/express";

const ISSUER = "https://auth.yourdomain.com/";
const RESOURCE_ID = "https://api.yourdomain.com";

const validator = new TokenValidator(ISSUER, RESOURCE_ID);
const app = express();
app.use(protectedResourceRouter(RESOURCE_ID, ISSUER, "Your API"));

app.get("/me", makeAuthMiddleware(validator), (req, res) => res.json({ sub: req.claims?.sub }));
```

### Go (net/http)

```go
validator := authclient.New("https://auth.yourdomain.com/", "https://api.yourdomain.com")

mux := http.NewServeMux()
authclient.RegisterProtectedResource(mux, "https://api.yourdomain.com", "https://auth.yourdomain.com/", "Your API")
mux.Handle("/me", authclient.RequireAuth(validator, http.HandlerFunc(me)))

func me(w http.ResponseWriter, r *http.Request) {
    claims, _ := authclient.ClaimsFromContext(r.Context())
    _ = claims["sub"]
}
```

### Behaviour

- No or invalid token: `401` with `WWW-Authenticate: Bearer resource_metadata="..."`, so MCP clients can discover the auth service.
- Missing scope: `403`.
- `issuer` is the auth service's issuer exactly as it appears in its discovery document (it ends with `/`).

### Only your own applications

The audience says which API a token is for, not which application it was issued to. To accept tokens only from your own applications, list their client IDs:

| Python | Node | Go |
|---|---|---|
| `allowed_client_ids=["your-app"]` | `{ allowedClientIds: ["your-app"] }` | `authclient.WithAllowedClientIDs("your-app")` |

### Checking a token is still good

Access tokens live 10 minutes. To reject one as soon as its person signs out or loses access, ask the auth service with a confidential application's credentials:

```python
auth = AuthServiceClient(ISSUER, "your-api-client", client_secret=SECRET)
if not auth.introspect(token)["active"]:
    ...  # reject
```

## Signing people in

`AuthServiceClient` covers an application's side of the flow. A complete Python example:

```python
from auth_client import AuthServiceClient, TokenExchangeError

auth = AuthServiceClient(
    "https://auth.yourdomain.com",
    "your-app",
    client_secret=CLIENT_SECRET,  # omit for a public client
)

# 1. After the redirect back, exchange the code
tokens = auth.exchange_code(code, code_verifier, redirect_uri)

# 2. Check the ID token (when you asked for the openid scope)
user = auth.verify_id_token(tokens["id_token"], nonce=saved_nonce)

# 3. Renew before the access token expires; store the new refresh token
try:
    tokens = auth.refresh(tokens["refresh_token"])
except TokenExchangeError:
    ...  # signed out or lost access: clear your session

# 4. Log out of this application only
auth.logout(tokens["refresh_token"])
# or redirect the browser:
url = auth.logout_url("https://yourapp.com/signed-out", id_token_hint=tokens["id_token"])
```

Every network method has an async form (`aexchange_code`, `arefresh`, `alogout`, `aintrospect`).

### Back-channel logout

Set your application's back-channel logout URL in the AuthService admin console. When someone is signed out of your application, the auth service posts a signed `logout_token` there:

```python
@app.post("/auth/backchannel-logout")
async def backchannel_logout(logout_token: str = Form(...)):
    claims = auth.verify_logout_token(logout_token)
    end_sessions(user_id=claims["sub"], sid=claims.get("sid"))  # your code
    return Response(status_code=200)
```

Only the application being signed out of is told. Other applications stay signed in.

### Embedded sign-in

AuthService's embedded sign-in (`auth-elements.js`) hands your page a `code` and `codeVerifier`. Post both to your backend and call `exchange_code(code, code_verifier)`; no `redirect_uri` is needed.

## API reference

### `AuthServiceClient`

| Python | Node | Go | Purpose |
|---|---|---|---|
| `exchange_code(code, verifier, redirect_uri=None)` | `exchangeCode(code, verifier, { redirectUri })` | `ExchangeCode(ctx, code, verifier, redirectURI)` | Code → tokens |
| `refresh(refresh_token)` | `refresh(refreshToken)` | `Refresh(ctx, refreshToken)` | Renew tokens |
| `verify_id_token(id_token, nonce=None)` | `verifyIdToken(idToken, nonce?)` | `VerifyIDToken(idToken, nonce)` | Check an ID token |
| `verify_logout_token(token)` | `verifyLogoutToken(token)` | `VerifyLogoutToken(token)` | Check a back-channel logout token |
| `introspect(token)` | `introspect(token)` | `Introspect(ctx, token)` | Is the token still good? |
| `logout(refresh_token)` | `logout(refreshToken)` | `Logout(ctx, refreshToken)` | Log out of this application |
| `logout_url(redirect, state, id_token_hint)` | `logoutUrl({ postLogoutRedirectUri, state, idTokenHint })` | `LogoutURL(redirect, state)`, `LogoutURLWithIDToken(hint, redirect, state)` | Browser logout URL |

### `TokenValidator`

| Python | Node | Go | Purpose |
|---|---|---|---|
| `TokenValidator(issuer, resource_id, ...)` | `new TokenValidator(issuer, resourceId, options)` | `New(issuer, resourceID, opts...)` | Create |
| `validate(token)` | `validate(token)` | `Validate(token)` | Check an access token |
| `has_scope(claims, scope)` | `TokenValidator.hasScope(claims, scope)` | `HasScope(claims, scope)` | Scope check |

### Errors

| Error | Raised when | `logout` result |
|---|---|---|
| `TokenValidationError` | A token fails any check | — |
| `TokenExchangeError` | A code or refresh token is refused (`error` holds the code, e.g. `invalid_grant`) or the service is unreachable | — |
| `IntrospectionError` | Introspection fails (bad credentials, unreachable) | — |
| `LogoutError` | Logout fails for any reason other than an unknown token | `false` when the token was already gone; clear your session either way |

## Compatibility

| auth-client | AuthService |
|---|---|
| 0.4.x | November 2026 or later (ID tokens, introspection, back-channel logout) |
| 0.3.x | October 2026 or later |

## Development

```bash
uv sync && uv run pytest              # Python
cd node && npm install && npm test    # Node
cd go && go test ./...                # Go
```

Each suite runs offline against a local JWKS.

## Releasing

The three clients share one version.

1. Set the version in `pyproject.toml` and `node/package.json`, and add a dated section to [CHANGELOG.md](CHANGELOG.md).
2. Push the tag: `git tag v0.4.0 && git push origin v0.4.0`.
3. The release workflow runs all tests, attaches the Python wheel and Node tarball to a GitHub Release, and tags `go/v0.4.0` for the Go module.

## License

MIT. See [LICENSE](LICENSE).
