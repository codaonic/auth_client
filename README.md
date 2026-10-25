# auth-client

![version](https://img.shields.io/badge/version-0.3.1-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Go](https://img.shields.io/badge/go-1.21%2B-blue)
![Node](https://img.shields.io/badge/node-18%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Token validation and web-framework integration helpers for any service that sits
behind [AuthService](https://github.com/codaonic/AuthService) — a website's API, an
MCP server, or any other OAuth 2.1 / OIDC resource server. Token validation never
talks to the auth service except to fetch and cache its JWKS; every request is verified
locally. For applications that sign users in, each client also wraps the auth service's
[logout](#sign-in-timeout-and-logout).

A client is available for:

- [Python](#python) — `auth_client`, with FastAPI helpers and `AuthServiceClient`
- [Go](#go) — `github.com/codaonic/auth-client/go`, with `net/http` middleware and `Client`
- [Node / TypeScript](#node--typescript) — `auth-client`, with Express middleware and `AuthServiceClient`

None of these are published to a package registry. Each tagged release attaches
installable files (a Python wheel/sdist, an npm tarball) directly to the matching
[GitHub Release](https://github.com/codaonic/auth-client/releases) — installed over
plain HTTPS, with no `git` binary required in the installing environment. Go needs
no release asset at all; `go get` already fetches over HTTPS via the Go module
proxy.

## Contents

- [Python](#python)
  - [Install](#install)
  - [Framework-agnostic validation](#framework-agnostic-validation)
  - [FastAPI](#fastapi)
  - [Custom middleware with your own authorization logic](#custom-middleware-with-your-own-authorization-logic)
- [Go](#go)
- [Node / TypeScript](#node--typescript)
- [Registering your service](#registering-your-service)
- [Sign-in timeout and logout](#sign-in-timeout-and-logout)
- [Embedded sign-in: exchanging the code](#embedded-sign-in-exchanging-the-code)
- [Local development](#local-development)
- [Versioning](#versioning)
- [License](#license)

## Python

### Install

This isn't on PyPI. Every tagged release attaches a wheel and an sdist to its
[GitHub Release](https://github.com/codaonic/auth-client/releases) — install
straight from that URL, no `git` required. Pick a version (e.g. `v0.3.1`) and
substitute it below:

```bash
# uv
uv add "https://github.com/codaonic/auth-client/releases/download/v0.3.1/auth_client-0.3.1-py3-none-any.whl"
# with the FastAPI helpers:
uv add "auth-client[fastapi] @ https://github.com/codaonic/auth-client/releases/download/v0.3.1/auth_client-0.3.1-py3-none-any.whl"

# pip
pip install "auth-client[fastapi] @ https://github.com/codaonic/auth-client/releases/download/v0.3.1/auth_client-0.3.1-py3-none-any.whl"
```

If this repo is private for you, that URL needs an auth header pip/uv don't send
by default — download it with a token first, then install the local file:

```bash
curl -L -H "Authorization: Bearer $GITHUB_TOKEN" \
  -o auth_client-0.3.1-py3-none-any.whl \
  "https://github.com/codaonic/auth-client/releases/download/v0.3.1/auth_client-0.3.1-py3-none-any.whl"
pip install "./auth_client-0.3.1-py3-none-any.whl[fastapi]"
```

### Framework-agnostic validation

```python
from auth_client import TokenValidator, TokenValidationError

validator = TokenValidator(
    issuer="https://auth.yourdomain.com",
    resource_id="https://api.yourdomain.com",  # must match the `resource=` this token was issued for
    allowed_client_ids=["your-app"],  # optional -- see below
)

try:
    claims = validator.validate(token)  # verifies signature, exp, iss, aud (and client_id)
except TokenValidationError:
    ...  # reject the request
```

**Who may get in.** The audience (`aud`) says which API a token is for, not
which application the user signed in through. Any client of the auth service
-- including ones anyone can register for themselves -- can get a token for
your API, signed in as one of *its* users. When only your own application(s)
should get in (an admin panel, an internal API), pass `allowed_client_ids`: a
token whose `client_id` isn't listed is rejected. Go: `WithAllowedClientIDs`;
Node: `allowedClientIds`.

### FastAPI

```python
from fastapi import Depends, FastAPI

from auth_client import TokenValidator
from auth_client.fastapi import make_auth_dependency, make_scope_dependency
from auth_client.protected_resource import protected_resource_router

ISSUER = "https://auth.yourdomain.com"
RESOURCE_ID = "https://api.yourdomain.com"

validator = TokenValidator(issuer=ISSUER, resource_id=RESOURCE_ID)
require_auth = make_auth_dependency(validator)
require_profile_scope = make_scope_dependency(validator, "profile")

app = FastAPI()

# RFC 9728 metadata, served BY this resource server, pointing back at the auth service.
# MCP clients fetch this after a 401 to discover which authorization server to use.
app.include_router(protected_resource_router(RESOURCE_ID, ISSUER, resource_name="Your API"))


@app.get("/me")
async def me(claims: dict = Depends(require_auth)):
    return {"sub": claims["sub"]}


@app.get("/profile")
async def profile(claims: dict = Depends(require_profile_scope)):
    return {"sub": claims["sub"]}
```

A request with no/invalid token gets a `401` with a
`WWW-Authenticate: Bearer resource_metadata="…"` header pointing at your
`/.well-known/oauth-protected-resource` — the same 401-then-discover pattern an
MCP client expects.

### Custom middleware with your own authorization logic

`make_auth_dependency` / `make_scope_dependency` cover the common case, but
`TokenValidator` is plain Python — nothing stops you from calling it yourself
from an ASGI middleware and layering on whatever authorization rules your
service needs (roles, tenant checks, per-route policy, etc.) instead of, or
alongside, scopes:

```python
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from auth_client import TokenValidator, TokenValidationError

validator = TokenValidator(issuer=ISSUER, resource_id=RESOURCE_ID)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return JSONResponse({"detail": "missing_bearer_token"}, status_code=401)

        try:
            claims = validator.validate(header.removeprefix("Bearer ").strip())
        except TokenValidationError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=401)

        # your own authorization logic goes here, e.g. role- or tenant-based checks
        if request.url.path.startswith("/admin") and claims.get("role") != "admin":
            return JSONResponse({"detail": "forbidden"}, status_code=403)

        request.state.claims = claims
        return await call_next(request)


app = FastAPI()
app.add_middleware(AuthMiddleware)


@app.get("/me")
async def me(request: Request):
    return {"sub": request.state.claims["sub"]}
```

This works the same way outside FastAPI too — any ASGI/WSGI middleware, or a
plain decorator, can call `validator.validate(token)` and apply its own checks
against the returned claims dict.

## Go

Lives in [`go/`](go/) as its own module. `go get` already fetches over HTTPS via
the Go module proxy — no `git` binary needed, and no release asset either:

```bash
go get github.com/codaonic/auth-client/go@main    # latest commit
go get github.com/codaonic/auth-client/go@v0.3.1   # pinned to a release
```

Framework-agnostic validation:

```go
import authclient "github.com/codaonic/auth-client/go"

validator := authclient.New(
    "https://auth.yourdomain.com",   // issuer
    "https://api.yourdomain.com",    // resource ID — must match this token's `aud`
    authclient.WithAllowedClientIDs("your-app"), // optional — only tokens issued to your app
)

claims, err := validator.Validate(token) // verifies signature, exp, iss, aud (and client_id)
if err != nil {
    // reject the request
}
```

`net/http` middleware, including the RFC 9728 Protected Resource Metadata
endpoint:

```go
package main

import (
    "net/http"

    authclient "github.com/codaonic/auth-client/go"
)

const (
    issuer     = "https://auth.yourdomain.com"
    resourceID = "https://api.yourdomain.com"
)

func main() {
    validator := authclient.New(issuer, resourceID)
    mux := http.NewServeMux()

    authclient.RegisterProtectedResource(mux, resourceID, issuer, "Your API")

    mux.Handle("/me", authclient.RequireAuth(validator, http.HandlerFunc(me)))
    mux.Handle("/profile", authclient.RequireScope(validator, "profile")(http.HandlerFunc(profile)))

    http.ListenAndServe(":8080", mux)
}

func me(w http.ResponseWriter, r *http.Request) {
    claims, _ := authclient.ClaimsFromContext(r.Context())
    // claims["sub"], etc.
}

func profile(w http.ResponseWriter, r *http.Request) {
    claims, _ := authclient.ClaimsFromContext(r.Context())
    // claims["sub"], etc.
}
```

Same rules as the Python SDK: a request with no/invalid token gets a `401` with
a `WWW-Authenticate` challenge header; `RequireScope` additionally enforces the
given scopes and responds `403` when any are missing. `RequireAuth` and
`RequireScope` return a plain `http.Handler` / middleware function, so they
compose with any router built on `net/http` (chi, gorilla/mux, etc.).

Run the Go test suite from `go/`:

```bash
cd go
go test ./...
```

## Node / TypeScript

Lives in [`node/`](node/) as its own package, built on
[`jose`](https://github.com/panva/jose) for JWKS fetching/caching and JWT
verification. Not on npm — every tagged release attaches a tarball to its
[GitHub Release](https://github.com/codaonic/auth-client/releases); install
straight from that URL, no `git` required:

```bash
npm install "https://github.com/codaonic/auth-client/releases/download/v0.3.1/auth-client-0.3.1.tgz"
```

Private repo? Same workaround as the Python package — download the asset with
an auth header first, then install the local file:

```bash
curl -L -H "Authorization: Bearer $GITHUB_TOKEN" \
  -o auth-client-0.3.1.tgz \
  "https://github.com/codaonic/auth-client/releases/download/v0.3.1/auth-client-0.3.1.tgz"
npm install ./auth-client-0.3.1.tgz
```

Framework-agnostic validation:

```ts
import { TokenValidator, TokenValidationError } from "auth-client";

const validator = new TokenValidator(
  "https://auth.yourdomain.com", // issuer
  "https://api.yourdomain.com",  // resource ID — must match this token's `aud`
  { allowedClientIds: ["your-app"] }, // optional — only tokens issued to your app
);

try {
  const claims = await validator.validate(token); // verifies signature, exp, iss, aud (and client_id)
} catch (err) {
  if (err instanceof TokenValidationError) {
    // reject the request
  }
}
```

Express middleware, including the RFC 9728 Protected Resource Metadata
endpoint:

```ts
import express from "express";
import { TokenValidator } from "auth-client";
import { protectedResourceRouter } from "auth-client";
import { makeAuthMiddleware, makeScopeMiddleware } from "auth-client/express";

const ISSUER = "https://auth.yourdomain.com";
const RESOURCE_ID = "https://api.yourdomain.com";

const validator = new TokenValidator(ISSUER, RESOURCE_ID);
const requireAuth = makeAuthMiddleware(validator);
const requireProfileScope = makeScopeMiddleware(validator, "profile");

const app = express();

// MCP clients fetch this after a 401 to discover which authorization server to use.
app.use(protectedResourceRouter(RESOURCE_ID, ISSUER, "Your API"));

app.get("/me", requireAuth, (req, res) => {
  res.json({ sub: req.claims?.sub });
});

app.get("/profile", requireProfileScope, (req, res) => {
  res.json({ sub: req.claims?.sub });
});
```

Same 401-then-discover / 403-on-missing-scope behavior as the Python and Go
clients. `express` is an optional peer dependency — the core `TokenValidator`
has no framework dependency, so it works the same way in a plain Node HTTP
server, Fastify, Koa, or an MCP server's own request handling.

Run the Node test suite from `node/`:

```bash
cd node
npm install
npm test
```

## Registering your service

Before any of this works, the auth service needs to know about your resource
and your client — either via its `/admin` UI or its CLI, from the AuthService
repo itself:

```bash
uv run python -m app.cli register-resource --resource-id "https://api.yourdomain.com" --name "Your API"
uv run python -m app.cli register-client --client-id your-app --type public --redirect-uri "https://yourdomain.com/callback"
```

Or, for a client that registers itself at runtime (e.g. an MCP client), use
Dynamic Client Registration: `POST {issuer}/register`.

See the [AuthService repo](https://github.com/codaonic/AuthService) for the
auth server itself, its admin UI, and complete runnable example resource
servers built on these SDKs.

## Sign-in timeout and logout

An application registered with AuthService can have its own **sign-in
timeout** (on by default for websites, at 7 days; off for MCP clients, AI
assistants and services, which follow the standard session and refresh-token
lifetimes) and can **log a user out of itself** without affecting any other application — including ones that share
its login group. Which of these you need to handle depends on what your
service is.

### If your service only validates tokens (an API or MCP server)

Nothing changes. These clients verify each access token locally, so a token
stays valid until its own `exp` (10 minutes by default) even after the user
logs out or their sign-in times out. That short lifetime is the revocation
window; there is no per-request call back to the auth service.

### If your service signs users in (a website backend, a mobile or desktop app)

Two things to handle.

**1. A refused refresh means the sign-in is over.** Once the application's
timeout (if it has one) has passed, or the user has been logged out,
`POST {issuer}/token` with `grant_type=refresh_token` returns
`400 invalid_grant`. Clear your own session and send the user through
`/authorize` again. Refresh tokens are one-time-use, so always store the new
one from a successful refresh.

**2. Log out through this SDK.** Clearing your own session cookie is not
enough — the auth service would recognize the browser and sign the user
straight back in. Each client ships an `AuthServiceClient` for this, so the
call lives in the same library as your token validation. The auth service
renders no logout page of its own; this sits behind your own logout button.

`logout(refresh_token)` reports whether the user was signed out:

| Result | Meaning | What to do |
|---|---|---|
| `true` | Signed out; every refresh token your application held for that user is revoked | Clear your own session |
| `false` | The auth service no longer knows that token (already used, expired, or revoked) | Clear your own session — there is nothing left to sign out |
| `LogoutError` | Network failure, wrong client credentials, or an unexpected response | Retry or surface the error |

Python:

```python
from auth_client import AuthServiceClient, LogoutError

auth = AuthServiceClient(
    "https://auth.yourdomain.com",
    "your-app",
    client_secret=CLIENT_SECRET,  # omit for a public client
)

signed_out = auth.logout(refresh_token)          # sync
signed_out = await auth.alogout(refresh_token)   # inside an async handler
```

Go:

```go
auth := authclient.NewClient(
    "https://auth.yourdomain.com",
    "your-app",
    authclient.WithClientSecret(clientSecret), // omit for a public client
)

signedOut, err := auth.Logout(ctx, refreshToken)
```

Node / TypeScript:

```ts
import { AuthServiceClient, LogoutError } from "auth-client";

const auth = new AuthServiceClient("https://auth.yourdomain.com", "your-app", {
  clientSecret: CLIENT_SECRET, // omit for a public client
});

const signedOut = await auth.logout(refreshToken);
```

**If you hold no refresh token**, redirect the browser instead. Each client
builds the URL for you:

```python
auth.logout_url("https://yourapp.com/signed-out", state="abc")
```

```go
auth.LogoutURL("https://yourapp.com/signed-out", "abc")
```

```ts
auth.logoutUrl({ postLogoutRedirectUri: "https://yourapp.com/signed-out", state: "abc" });
```

The return URL must be listed under the application's "After-logout URLs" in
the admin UI; the user comes back to it with `state` appended. The endpoint is
also published as `end_session_endpoint` in
`{issuer}/.well-known/openid-configuration`, so a standard OIDC library can
discover it.

Logging out never signs the user out of any other application.

## Embedded sign-in: exchanging the code

AuthService can show its login and signup forms **inside your own page**,
styled to your design (Auth Elements, `{issuer}/static/js/auth-elements.js`;
see the AuthService README, §6). An admin first adds your site's origin under
the application's **Embed origins** in the admin UI.

When the user signs in, the form's `success` event gives your page a one-time
`code` and its PKCE `codeVerifier`. Post both to your backend, which exchanges
them for tokens with `AuthServiceClient`. The same call works for codes from
the redirect and popup flows too.

```js
// your page
signIn.on("success", async ({ code, codeVerifier }) => {
  await fetch("/api/auth/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, codeVerifier }),
  });
  location.reload();
});
```

Python:

```python
from auth_client import AuthServiceClient, TokenExchangeError

tokens = auth.exchange_code(code, code_verifier)           # sync
tokens = await auth.aexchange_code(code, code_verifier)    # inside an async handler
# tokens["access_token"], tokens["refresh_token"], tokens["expires_in"], ...
```

Go:

```go
tokens, err := auth.ExchangeCode(ctx, code, codeVerifier, "")
// tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresIn, ...
```

Node / TypeScript:

```ts
import { AuthServiceClient, TokenExchangeError } from "auth-client";

const tokens = await auth.exchangeCode(code, codeVerifier);
// tokens.access_token, tokens.refresh_token, tokens.expires_in, ...
```

Keep the tokens in your own server-side session, never in the page. The
`redirect_uri` argument is optional; if you pass it, it must be the one the
code was issued for (for an embedded sign-in, your page's origin).

A refused code raises `TokenExchangeError` (a `*TokenExchangeError` in Go)
with the auth service's error code in `error` (`Code` in Go). `invalid_grant`
means the code was already used, has expired (codes are one-time and
short-lived), or doesn't match the verifier: show the sign-in form again. With
no error code, the auth service couldn't be reached.

## Local development

```bash
git clone https://github.com/codaonic/auth-client.git
cd auth-client

# Python
uv sync
uv run pytest

# Go
cd go && go test ./... && cd ..

# Node
cd node && npm install && npm test && cd ..
```

Every test suite is fully self-contained (a mocked/local JWKS endpoint in each
language) — none of them ever talk to a real auth service.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). See
[CHANGELOG.md](CHANGELOG.md) for release notes. The Python, Go, and Node
clients are versioned and released together, from the same tag.

Cutting a release (`.github/workflows/release.yml`):

1. Bump `version` in `pyproject.toml` and `node/package.json` to the same
   value, and add a dated section to `CHANGELOG.md`. Commit.
2. Push a tag matching that version: `git tag v0.3.1 && git push origin v0.3.1`.
3. The workflow runs all three test suites, builds the Python wheel/sdist and
   the Node tarball, attaches them to a new GitHub Release, and tags
   `go/v0.3.1` so `go get .../go@v0.3.1` resolves correctly (Go's module proxy
   needs a path-prefixed tag for a module that lives in a subdirectory).

A version mismatch between the tag and either `pyproject.toml` or
`node/package.json` fails the release before anything is published.

## License

MIT — see [LICENSE](LICENSE).
