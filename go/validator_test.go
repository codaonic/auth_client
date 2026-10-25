package authclient

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer     = "https://auth.example.com"
	testResourceID = "https://api.example.com"
	testKid        = "test-key-1"
)

type testKeypair struct {
	private *rsa.PrivateKey
	jwks    jwksDocument
}

func newTestKeypair(t *testing.T) *testKeypair {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := jsonWebKey{
		Kid: testKid,
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(private.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(private.PublicKey.E)).Bytes()),
	}
	return &testKeypair{private: private, jwks: jwksDocument{Keys: []jsonWebKey{jwk}}}
}

type tokenOpts struct {
	aud      string
	iss      string
	scope    string
	sub      string
	ttl      time.Duration
	clientID string
	kid      string
}

func (kp *testKeypair) makeToken(t *testing.T, opts tokenOpts) string {
	t.Helper()
	if opts.aud == "" {
		opts.aud = testResourceID
	}
	if opts.iss == "" {
		opts.iss = testIssuer
	}
	if opts.scope == "" {
		opts.scope = "profile email"
	}
	if opts.sub == "" {
		opts.sub = "user-123"
	}
	if opts.ttl == 0 {
		opts.ttl = 10 * time.Minute
	}
	if opts.clientID == "" {
		opts.clientID = "my-app"
	}
	if opts.kid == "" {
		opts.kid = testKid
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       opts.sub,
		"aud":       opts.aud,
		"iss":       opts.iss,
		"scope":     opts.scope,
		"iat":       now.Unix(),
		"exp":       now.Add(opts.ttl).Unix(),
		"client_id": opts.clientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = opts.kid
	signed, err := token.SignedString(kp.private)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newJWKSServer(t *testing.T, kp *testKeypair) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(kp.jwks)
	}))
	t.Cleanup(server.Close)
	return server
}

func newValidator(t *testing.T, kp *testKeypair) *TokenValidator {
	server := newJWKSServer(t, kp)
	return New(testIssuer, testResourceID, WithJWKSURL(server.URL))
}

func TestValidTokenReturnsClaims(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{sub: "user-123"})

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}
	if claims["aud"] != testResourceID {
		t.Errorf("aud = %v, want %v", claims["aud"], testResourceID)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{aud: "https://other.example.com"})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestWrongIssuerRejected(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{iss: "https://not-the-real-as.example.com"})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{ttl: -time.Minute})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestUnknownKidRejected(t *testing.T) {
	kp := newTestKeypair(t)
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jsonWebKey{}})
	}))
	defer empty.Close()

	v := New(testIssuer, testResourceID, WithJWKSURL(empty.URL))
	token := kp.makeToken(t, tokenOpts{})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestHasScope(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{scope: "profile email"})

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !HasScope(claims, "profile") {
		t.Error("expected profile scope")
	}
	if HasScope(claims, "admin") {
		t.Error("did not expect admin scope")
	}
}

func TestJWKSCachedAcrossCalls(t *testing.T) {
	kp := newTestKeypair(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(kp.jwks)
	}))
	defer server.Close()

	v := New(testIssuer, testResourceID, WithJWKSURL(server.URL))
	token := kp.makeToken(t, tokenOpts{})

	if _, err := v.Validate(token); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := v.Validate(token); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if calls != 1 {
		t.Errorf("jwks fetched %d times, want 1", calls)
	}
}

func TestAllowedClientIDsAcceptsOnlyListedClients(t *testing.T) {
	kp := newTestKeypair(t)
	server := newJWKSServer(t, kp)
	v := New(testIssuer, testResourceID, WithJWKSURL(server.URL), WithAllowedClientIDs("my-app"))

	if _, err := v.Validate(kp.makeToken(t, tokenOpts{clientID: "my-app"})); err != nil {
		t.Fatalf("listed client rejected: %v", err)
	}
	if _, err := v.Validate(kp.makeToken(t, tokenOpts{clientID: "someone-else"})); err == nil {
		t.Fatal("expected error for a client that isn't listed")
	}
}

func TestTokenCannotPickItsOwnAlgorithm(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	claims := jwt.MapClaims{"sub": "attacker", "aud": testResourceID, "iss": testIssuer, "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = testKid
	forged, err := token.SignedString([]byte(kp.jwks.Keys[0].N))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := v.Validate(forged); err == nil {
		t.Fatal("expected an HS256 token to be rejected")
	}
}

func TestUnknownKidsDoNotRefetchJWKSOnEveryRequest(t *testing.T) {
	kp := newTestKeypair(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(kp.jwks)
	}))
	defer server.Close()

	v := New(testIssuer, testResourceID, WithJWKSURL(server.URL))
	for i := 0; i < 5; i++ {
		if _, err := v.Validate(kp.makeToken(t, tokenOpts{kid: fmt.Sprintf("made-up-%d", i)})); err == nil {
			t.Fatal("expected error for unknown kid")
		}
	}
	if calls != 1 {
		t.Errorf("JWKS fetched %d times, want 1 (refetches wait for the cooldown)", calls)
	}
}

func TestUnknownKidRefetchesOnceTheCooldownHasPassed(t *testing.T) {
	kp := newTestKeypair(t)
	published := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if published {
			_ = json.NewEncoder(w).Encode(kp.jwks)
			return
		}
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jsonWebKey{}})
	}))
	defer server.Close()

	v := New(testIssuer, testResourceID, WithJWKSURL(server.URL), WithRefreshCooldown(0))
	if _, err := v.Validate(kp.makeToken(t, tokenOpts{})); err == nil {
		t.Fatal("expected error before the key is published")
	}
	published = true
	if _, err := v.Validate(kp.makeToken(t, tokenOpts{})); err != nil {
		t.Fatalf("rotated-in key not picked up: %v", err)
	}
}
