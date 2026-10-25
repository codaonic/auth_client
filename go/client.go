package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
}

// Client calls the auth service on behalf of an application that signs users
// in — a website backend, a mobile or desktop app. It is separate from
// TokenValidator, which a resource server uses to check incoming tokens.
type Client struct {
	Issuer   string
	ClientID string

	clientSecret string
	httpClient   *http.Client
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
	if c.clientSecret != "" {
		form.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &TokenExchangeError{msg: fmt.Sprintf("code exchange failed: %v", err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &TokenExchangeError{msg: fmt.Sprintf("code exchange failed: %v", err)}
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
		msg:  strings.TrimSpace(fmt.Sprintf("code exchange failed: %d %s", resp.StatusCode, body.Detail)),
	}
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
