package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// IntrospectionError is returned by Introspect when the auth service could not
// answer (network failure, wrong client credentials, or an unexpected response).
type IntrospectionError struct {
	msg string
}

func (e *IntrospectionError) Error() string { return e.msg }

// LogoutError is returned by Logout when the auth service could not process the
// request (network failure, wrong client credentials, or an unexpected response).
type LogoutError struct {
	msg string
}

func (e *LogoutError) Error() string { return e.msg }

// TokenExchangeError is returned by ExchangeCode when the auth service refused
// to exchange the code, or could not be reached. Code is its error code (e.g.
// "invalid_grant" for a code that was already used, has expired, or doesn't
// match the PKCE verifier), or empty when there was no response.
type TokenExchangeError struct {
	Code string
	msg  string
}

func (e *TokenExchangeError) Error() string { return e.msg }

// TokenResponse is what the auth service's /token endpoint returns for an
// authorization code.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	// IDToken is present when the sign-in asked for the openid scope.
	IDToken string `json:"id_token,omitempty"`
}

// Client calls the auth service on behalf of an application that signs users
// in — a website backend, a mobile or desktop app. It is separate from
// TokenValidator, which a resource server uses to check incoming tokens.
type Client struct {
	Issuer   string
	ClientID string

	clientSecret string
	httpClient   *http.Client
	jwksURL      string

	ownTokensOnce sync.Once
	ownTokens     *TokenValidator
}

// ClientOption configures a Client constructed with NewClient.
type ClientOption func(*Client)

// WithClientSecret sets the secret of a confidential client. Omit it for a
// public client.
func WithClientSecret(secret string) ClientOption {
	return func(c *Client) { c.clientSecret = secret }
}

// WithClientHTTPClient overrides the default HTTP client used to call the auth service.
func WithClientHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = client }
}

// WithClientJWKSURL overrides the "{issuer}/jwks.json" keys used to check ID and
// logout tokens.
func WithClientJWKSURL(url string) ClientOption {
	return func(c *Client) { c.jwksURL = url }
}

// NewClient builds a Client for the given issuer and application client ID.
func NewClient(issuer, clientID string, opts ...ClientOption) *Client {
	c := &Client{
		Issuer:     strings.TrimRight(issuer, "/"),
		ClientID:   clientID,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// LogoutEndpoint is the auth service's logout endpoint.
func (c *Client) LogoutEndpoint() string {
	return c.Issuer + "/logout"
}

// TokenEndpoint is the auth service's token endpoint.
func (c *Client) TokenEndpoint() string {
	return c.Issuer + "/token"
}

// IntrospectionEndpoint is the auth service's token introspection endpoint.
func (c *Client) IntrospectionEndpoint() string {
	return c.Issuer + "/introspect"
}

// ExchangeCode exchanges an authorization code for tokens at the auth service's
// /token endpoint. It works for every sign-in flow: the redirect, the popup
// widget, and the embedded sign-in (Auth Elements), whose "success" event hands
// your page the code and codeVerifier to post to your backend.
//
// redirectURI is optional; when given it must be the one the code was issued
// for (for an embedded sign-in, your page's origin). A refused code or an
// unreachable auth service is returned as a *TokenExchangeError.
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.ClientID},
		"code":          {code},
		"code_verifier": {codeVerifier},
	}
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	return c.postToken(ctx, form, "code exchange failed")
}

// Refresh gets new tokens for a refresh token. The old one stops working;
// store the new one. A refused refresh (e.g. the person was signed out or lost
// access) is returned as a *TokenExchangeError.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "refresh_token": {refreshToken}}
	return c.postToken(ctx, form, "refresh failed")
}

func (c *Client) postToken(ctx context.Context, form url.Values, failure string) (*TokenResponse, error) {
	if c.clientSecret != "" {
		form.Set("client_secret", c.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &TokenExchangeError{msg: fmt.Sprintf("%s: %v", failure, err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &TokenExchangeError{msg: fmt.Sprintf("%s: %v", failure, err)}
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusOK {
		var tokens TokenResponse
		if err := json.Unmarshal(raw, &tokens); err == nil && tokens.AccessToken != "" {
			return &tokens, nil
		}
	}

	var body struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &body)
	errorCode, _, _ := strings.Cut(body.Detail, ":")
	return nil, &TokenExchangeError{
		Code: errorCode,
		msg:  strings.TrimSpace(fmt.Sprintf("%s: %d %s", failure, resp.StatusCode, body.Detail)),
	}
}

// Introspect asks whether a token is still good right now. The result has
// "active": false once its person is signed out, loses access, or it was
// revoked. It needs a client secret (a confidential app).
func (c *Client) Introspect(ctx context.Context, token string) (map[string]any, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.IntrospectionEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &IntrospectionError{msg: fmt.Sprintf("introspection failed: %v", err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.clientSecret))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &IntrospectionError{msg: fmt.Sprintf("introspection failed: %v", err)}
	}
	defer resp.Body.Close()

	var body map[string]any
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusOK && json.Unmarshal(raw, &body) == nil {
		if _, ok := body["active"].(bool); ok {
			return body, nil
		}
	}
	return nil, &IntrospectionError{msg: fmt.Sprintf("introspection failed: %d", resp.StatusCode)}
}

// validator checks tokens addressed to this app (ID and logout tokens). The
// service's issuer always ends in "/".
func (c *Client) validator() *TokenValidator {
	c.ownTokensOnce.Do(func() {
		opts := []Option{WithHTTPClient(c.httpClient)}
		if c.jwksURL != "" {
			opts = append(opts, WithJWKSURL(c.jwksURL))
		}
		c.ownTokens = New(c.Issuer+"/", c.ClientID, opts...)
	})
	return c.ownTokens
}

// VerifyIDToken checks an ID token from the token response and returns its
// claims (sub, email, name, roles...). Pass the nonce you sent when starting
// the sign-in, or "" to skip that check. Failures are *TokenValidationError.
func (c *Client) VerifyIDToken(idToken, nonce string) (jwt.MapClaims, error) {
	claims, header, err := c.validator().verify(idToken)
	if err != nil {
		return nil, err
	}
	typ, _ := header["typ"].(string)
	if _, ok := claims["at_hash"]; typ == "at+jwt" || typ == "logout+jwt" || !ok {
		return nil, validationErrorf("not an ID token")
	}
	if azp, ok := claims["azp"].(string); ok && azp != c.ClientID {
		return nil, validationErrorf("ID token was issued to another app")
	}
	if nonce != "" && claims["nonce"] != nonce {
		return nil, validationErrorf("nonce does not match")
	}
	return claims, nil
}

// VerifyLogoutToken checks the logout_token posted to your back-channel logout
// URL and returns its claims: end the sessions matching sub (and sid, when
// present). Failures are *TokenValidationError.
func (c *Client) VerifyLogoutToken(logoutToken string) (jwt.MapClaims, error) {
	claims, header, err := c.validator().verify(logoutToken)
	if err != nil {
		return nil, err
	}
	typ, hasTyp := header["typ"].(string)
	events, _ := claims["events"].(map[string]any)
	_, hasEvent := events[backchannelLogoutEvent]
	_, hasNonce := claims["nonce"]
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	if (hasTyp && typ != "logout+jwt") || !hasEvent || hasNonce || (sub == "" && sid == "") {
		return nil, validationErrorf("not a logout token")
	}
	return claims, nil
}

// Logout signs the user who owns refreshToken out of this application. Only
// this application is affected: the user stays signed in to every other
// application, including ones in the same login group. Every refresh token this
// application holds for them is revoked.
//
// It returns true when the user was signed out, and false (with a nil error)
// when the auth service no longer recognizes the token — already used, expired,
// or revoked. In both cases the caller should clear its own session. Anything
// else is returned as a *LogoutError.
func (c *Client) Logout(ctx context.Context, refreshToken string) (bool, error) {
	form := url.Values{"client_id": {c.ClientID}, "refresh_token": {refreshToken}}
	if c.clientSecret != "" {
		form.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.LogoutEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return false, &LogoutError{msg: fmt.Sprintf("logout failed: %v", err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, &LogoutError{msg: fmt.Sprintf("logout failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	var body struct {
		Detail string `json:"detail"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode == http.StatusBadRequest && body.Detail == "invalid_grant" {
		return false, nil
	}
	return false, &LogoutError{msg: strings.TrimSpace(fmt.Sprintf("logout failed: %d %s", resp.StatusCode, body.Detail))}
}

// LogoutURLWithIDToken is LogoutURL with the person's ID token as id_token_hint.
func (c *Client) LogoutURLWithIDToken(idTokenHint, postLogoutRedirectURI, state string) string {
	u := c.LogoutURL(postLogoutRedirectURI, state)
	if idTokenHint == "" {
		return u
	}
	return u + "&" + url.Values{"id_token_hint": {idTokenHint}}.Encode()
}

// LogoutURL is the URL to redirect the user's browser to, for an application
// that holds no refresh token. postLogoutRedirectURI and state are optional;
// the redirect URI must be listed under the application's "After-logout URLs"
// in the admin console.
func (c *Client) LogoutURL(postLogoutRedirectURI, state string) string {
	params := url.Values{"client_id": {c.ClientID}}
	if postLogoutRedirectURI != "" {
		params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if state != "" {
		params.Set("state", state)
	}
	return c.LogoutEndpoint() + "?" + params.Encode()
}
