package authclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func logoutServer(t *testing.T, status int, body string, seen *url.Values) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/logout" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if seen != nil {
			*seen = r.PostForm
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestLogoutPostsClientCredentialsAndRefreshToken(t *testing.T) {
	var seen url.Values
	server := logoutServer(t, http.StatusOK, `{"status":"signed_out"}`, &seen)
	client := NewClient(server.URL+"/", "my-app", WithClientSecret("s3cret"))

	ok, err := client.Logout(context.Background(), "rt-123")
	if err != nil || !ok {
		t.Fatalf("Logout = %v, %v; want true, nil", ok, err)
	}
	if seen.Get("client_id") != "my-app" || seen.Get("client_secret") != "s3cret" || seen.Get("refresh_token") != "rt-123" {
		t.Errorf("unexpected form: %v", seen)
	}
}

func TestLogoutPublicClientSendsNoSecret(t *testing.T) {
	var seen url.Values
	server := logoutServer(t, http.StatusOK, `{}`, &seen)

	if _, err := NewClient(server.URL, "my-app").Logout(context.Background(), "rt-123"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, present := seen["client_secret"]; present {
		t.Errorf("client_secret should not be sent: %v", seen)
	}
}

func TestLogoutReturnsFalseWhenTokenIsNoLongerKnown(t *testing.T) {
	server := logoutServer(t, http.StatusBadRequest, `{"detail":"invalid_grant"}`, nil)

	ok, err := NewClient(server.URL, "my-app").Logout(context.Background(), "stale")
	if err != nil || ok {
		t.Fatalf("Logout = %v, %v; want false, nil", ok, err)
	}
}

func TestLogoutErrorsOnBadClientCredentials(t *testing.T) {
	server := logoutServer(t, http.StatusUnauthorized, `{"detail":"invalid_client"}`, nil)

	_, err := NewClient(server.URL, "my-app").Logout(context.Background(), "rt-123")
	var logoutErr *LogoutError
	if !errors.As(err, &logoutErr) {
		t.Fatalf("err = %v; want *LogoutError", err)
	}
}

func TestLogoutErrorsOnNetworkFailure(t *testing.T) {
	server := logoutServer(t, http.StatusOK, `{}`, nil)
	client := NewClient(server.URL, "my-app")
	server.Close()

	_, err := client.Logout(context.Background(), "rt-123")
	var logoutErr *LogoutError
	if !errors.As(err, &logoutErr) {
		t.Fatalf("err = %v; want *LogoutError", err)
	}
}

func TestLogoutURL(t *testing.T) {
	client := NewClient(testIssuer+"/", "my app")

	if got, want := client.LogoutURL("", ""), testIssuer+"/logout?client_id=my+app"; got != want {
		t.Errorf("LogoutURL = %q; want %q", got, want)
	}

	parsed, err := url.Parse(client.LogoutURL("https://app.example.com/signed-out?x=1", "abc"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != "my app" ||
		query.Get("post_logout_redirect_uri") != "https://app.example.com/signed-out?x=1" ||
		query.Get("state") != "abc" {
		t.Errorf("unexpected query: %v", query)
	}
}

func tokenServer(t *testing.T, status int, body string, seen *[]url.Values) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if seen != nil {
			*seen = append(*seen, r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

const tokensBody = `{"access_token":"at-1","token_type":"Bearer","expires_in":900,"scope":"openid","refresh_token":"rt-1"}`

func TestExchangeCodePostsCodeVerifierAndClientCredentials(t *testing.T) {
	var seen []url.Values
	server := tokenServer(t, http.StatusOK, tokensBody, &seen)
	client := NewClient(server.URL+"/", "my-app", WithClientSecret("s3cret"))

	tokens, err := client.ExchangeCode(context.Background(), "code-1", "verifier-1", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	want := TokenResponse{AccessToken: "at-1", TokenType: "Bearer", ExpiresIn: 900, Scope: "openid", RefreshToken: "rt-1"}
	if *tokens != want {
		t.Errorf("tokens = %+v; want %+v", *tokens, want)
	}
	form := seen[0]
	if form.Get("grant_type") != "authorization_code" || form.Get("client_id") != "my-app" ||
		form.Get("client_secret") != "s3cret" || form.Get("code") != "code-1" || form.Get("code_verifier") != "verifier-1" {
		t.Errorf("unexpected form: %v", form)
	}
	if _, present := form["redirect_uri"]; present {
		t.Errorf("redirect_uri should not be sent: %v", form)
	}
}

func TestExchangeCodeSendsRedirectURIWhenGiven(t *testing.T) {
	var seen []url.Values
	server := tokenServer(t, http.StatusOK, tokensBody, &seen)

	if _, err := NewClient(server.URL, "my-app").ExchangeCode(context.Background(), "code-1", "verifier-1", "https://app.example.com"); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if seen[0].Get("redirect_uri") != "https://app.example.com" {
		t.Errorf("unexpected form: %v", seen[0])
	}
	if _, present := seen[0]["client_secret"]; present {
		t.Errorf("client_secret should not be sent: %v", seen[0])
	}
}

func TestExchangeCodeErrorsWithCodeWhenRefused(t *testing.T) {
	for detail, want := range map[string]string{
		"invalid_grant":                        "invalid_grant",
		"invalid_target: resource is disabled": "invalid_target",
	} {
		server := tokenServer(t, http.StatusBadRequest, `{"detail":"`+detail+`"}`, nil)

		_, err := NewClient(server.URL, "my-app").ExchangeCode(context.Background(), "used", "verifier-1", "")
		var exchangeErr *TokenExchangeError
		if !errors.As(err, &exchangeErr) || exchangeErr.Code != want {
			t.Errorf("detail %q: err = %v; want *TokenExchangeError with Code %q", detail, err, want)
		}
	}
}

func TestExchangeCodeErrorsOnNetworkFailure(t *testing.T) {
	server := tokenServer(t, http.StatusOK, tokensBody, nil)
	client := NewClient(server.URL, "my-app")
	server.Close()

	_, err := client.ExchangeCode(context.Background(), "code-1", "verifier-1", "")
	var exchangeErr *TokenExchangeError
	if !errors.As(err, &exchangeErr) || exchangeErr.Code != "" {
		t.Fatalf("err = %v; want *TokenExchangeError with no Code", err)
	}
}
