# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-10-26

### Added

- Authorization-code exchange for applications that sign users in, at parity across all three clients: Python `AuthServiceClient.exchange_code` (and async `aexchange_code`) with `TokenExchangeError`; Go `Client.ExchangeCode` returning a `*TokenResponse`, with `*TokenExchangeError`; Node `AuthServiceClient.exchangeCode` with `TokenExchangeError`. Posts the code and PKCE verifier to AuthService's `POST /token`. Made for AuthService's embedded sign-in (Auth Elements), whose `success` event hands the page a code and verifier for the backend to exchange; it works the same for codes from the redirect and popup flows. The error carries AuthService's error code (e.g. `invalid_grant`).
- README: "Embedded sign-in: exchanging the code".

## [0.3.0] - 2026-10-25

### Security

- Python: `TokenValidator` now only accepts RS256. It used to verify with whatever `alg` the token's own header named, letting the token choose how it was checked. (Go and Node already pinned RS256.)
- Python: replaced `python-jose` with `joserfc`. `python-jose` is unmaintained and depends on `ecdsa`, which has a known timing side-channel with no fix.
- Python and Go: a token with an unknown `kid` no longer forces a JWKS refetch every time. Refetches are now at least 30 seconds apart (`refresh_cooldown` / `WithRefreshCooldown`), so made-up key IDs can't turn every request into a call to the auth service. A real key rotation is still picked up on the first token that uses the new key. (Node's `jose` already did this; `refreshCooldownMs` now exposes the setting.)
- Go: `github.com/golang-jwt/jwt/v5` 5.2.1 → 5.3.0 (fixes excessive memory use when parsing crafted headers, CVE-2025-30204).

### Added

- Optional allow-list of client IDs, at parity across all three clients: Python `allowed_client_ids=[...]`, Go `WithAllowedClientIDs(...)`, Node `allowedClientIds: [...]`. When set, a token whose `client_id` claim isn't listed is rejected. The audience alone doesn't say which application the user signed in through. Any client of the auth service can get a token for your API, so set this when only your own application(s) should get in.

### Changed

- Python now requires `joserfc>=1.6` instead of `python-jose`. The public API is unchanged, and existing code keeps working without changes.

## [0.2.0] - 2026-10-11

### Changed

- Renamed the project from `authservice-client` to `auth-client` (Python distribution name, Python module `auth_client`, repo name).

### Added

- Go client (`go/`, module `github.com/codaonic/auth-client/go`): `TokenValidator`, `net/http` middleware (`RequireAuth`, `RequireScope`), and a protected-resource-metadata handler, at feature parity with the Python client.
- Node / TypeScript client (`node/`, package `auth-client`): `TokenValidator` (built on `jose`), Express middleware (`makeAuthMiddleware`, `makeScopeMiddleware`), and `protectedResourceRouter`, at feature parity with the Python client.
- Logout for applications that sign users in, at parity across all three clients: Python `AuthServiceClient` (`logout`, async `alogout`, `logout_url`) with `LogoutError`; Go `Client` via `NewClient` (`Logout`, `LogoutURL`) with `*LogoutError`; Node `AuthServiceClient` (`logout`, `logoutUrl`) with `LogoutError`. Each signs a user out of the calling application only, via AuthService's `POST /logout`, or builds the browser-redirect URL.
- README: "Sign-in timeout and logout" — how services behind AuthService handle the per-application sign-in timeout and log users out, with Python, Go, and Node examples.
- `.github/workflows/release.yml`: tagging `vX.Y.Z` runs all three test suites, builds the Python wheel/sdist and Node tarball, attaches them to a GitHub Release, and tags `go/vX.Y.Z` for the Go module proxy. Lets Python and Node be installed over plain HTTPS from the release assets — no `git` required in the installing environment.

## [0.1.0] - 2026-09-27

### Added

- `TokenValidator` — verifies a bearer token's signature, `exp`, `iss`, and `aud` against a cached JWKS, with no per-request network call to the auth service.
- `auth_client.fastapi.make_auth_dependency` / `make_scope_dependency` — FastAPI dependencies for requiring a valid token, optionally with specific scopes.
- `auth_client.protected_resource.protected_resource_router` — serves RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`), enabling the 401-then-discover flow MCP clients expect.
- Initial extraction from the main AuthService monorepo into its own installable, versioned package.
