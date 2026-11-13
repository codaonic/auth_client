package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (kp *testKeypair) sign(t *testing.T, claims jwt.MapClaims, typ string) string {
	t.Helper()
	now := time.Now()
	full := jwt.MapClaims{"iss": testIssuer + "/", "aud": "my-app", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		full[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, full)
	token.Header["kid"] = testKid
	if typ != "" {
		token.Header["typ"] = typ
	}
	signed, err := token.SignedString(kp.private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func appClient(t *testing.T, kp *testKeypair, handler http.HandlerFunc) *Client {
	t.Helper()
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(kp.jwks)
	}))
	t.Cleanup(jwks.Close)
	issuer := testIssuer
	if handler != nil {
		api := httptest.NewServer(handler)
		t.Cleanup(api.Close)
		issuer = api.URL
	}
	return NewClient(issuer, "my-app", WithClientSecret("s3cret"), WithClientJWKSURL(jwks.URL))
}

const event = "http://schemas.openid.net/event/backchannel-logout"

func TestVerifyIDToken(t *testing.T) {
	kp := newTestKeypair(t)
	c := appClient(t, kp, nil)
	token := kp.sign(t, jwt.MapClaims{"sub": "u1", "azp": "my-app", "at_hash": "x", "nonce": "n1", "email": "a@b.c"}, "JWT")

	claims, err := c.VerifyIDToken(token, "n1")
	if err != nil || claims["email"] != "a@b.c" {
		t.Fatalf("VerifyIDToken = %v, %v", claims, err)
	}
	if _, err := c.VerifyIDToken(token, "other"); err == nil {
		t.Error("wrong nonce accepted")
	}
	if _, err := c.VerifyIDToken(kp.sign(t, jwt.MapClaims{"sub": "u1"}, "at+jwt"), ""); err == nil {
		t.Error("access token accepted as ID token")
	}
}

func TestVerifyLogoutToken(t *testing.T) {
	kp := newTestKeypair(t)
	c := appClient(t, kp, nil)
	good := kp.sign(t, jwt.MapClaims{"sub": "u1", "sid": "s1", "events": map[string]any{event: map[string]any{}}}, "logout+jwt")
	claims, err := c.VerifyLogoutToken(good)
	if err != nil || claims["sid"] != "s1" {
		t.Fatalf("VerifyLogoutToken = %v, %v", claims, err)
	}
	var verr *TokenValidationError
	_, err = c.VerifyLogoutToken(kp.sign(t, jwt.MapClaims{"sub": "u1"}, "logout+jwt"))
	if !errors.As(err, &verr) {
		t.Errorf("token without the event: err = %v", err)
	}
}

func TestRefreshAndIntrospect(t *testing.T) {
	kp := newTestKeypair(t)
	c := appClient(t, kp, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/token":
			if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("client_secret") != "s3cret" {
				t.Errorf("unexpected form %v", r.PostForm)
			}
			_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt2"}`))
		case "/introspect":
			if user, pass, ok := r.BasicAuth(); !ok || user != "my-app" || pass != "s3cret" {
				t.Errorf("no basic auth")
			}
			_, _ = w.Write([]byte(`{"active":false}`))
		}
	})

	tokens, err := c.Refresh(context.Background(), "rt1")
	if err != nil || tokens.RefreshToken != "rt2" {
		t.Fatalf("Refresh = %v, %v", tokens, err)
	}
	body, err := c.Introspect(context.Background(), "t")
	if err != nil || body["active"] != false {
		t.Fatalf("Introspect = %v, %v", body, err)
	}
}

func TestIntrospectError(t *testing.T) {
	kp := newTestKeypair(t)
	c := appClient(t, kp, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	var ierr *IntrospectionError
	if _, err := c.Introspect(context.Background(), "t"); !errors.As(err, &ierr) {
		t.Errorf("err = %v", err)
	}
}

func TestLogoutURLWithIDToken(t *testing.T) {
	u := NewClient(testIssuer, "my-app").LogoutURLWithIDToken("idt", "", "")
	if !strings.Contains(u, "id_token_hint=idt") || !strings.Contains(u, "client_id=my-app") {
		t.Errorf("url = %s", u)
	}
}
