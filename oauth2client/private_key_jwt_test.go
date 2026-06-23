package oauth2client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// generateTestKeyFileJSON returns a ZITADEL service-account key JSON and the underlying RSA key.
func generateTestKeyFileJSON(tb testing.TB) (string, *rsa.PrivateKey) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate RSA key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	payload := map[string]string{
		"type":     "application",
		"keyId":    "test-key-id",
		"key":      string(keyPEM),
		"clientId": "test-client-id",
		"appId":    "test-app-id",
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		tb.Fatalf("failed to marshal key JSON: %v", err)
	}

	return string(jsonBytes), privateKey
}

// tokenResponseHandler returns an HTTP handler that always responds with a valid token JSON.
func tokenResponseHandler(accessToken string, expiresIn int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":%d}`, accessToken, expiresIn)
	}
}

func TestNewPrivateKeyJWTTokenManager_ValidKeyFile(t *testing.T) {
	keyJSON, _ := generateTestKeyFileJSON(t)

	tm, err := NewPrivateKeyJWTTokenManager(
		context.Background(),
		"https://issuer.example.com",
		keyJSON,
		"openid",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm == nil {
		t.Fatal("expected non-nil TokenManager")
	}
}

func TestNewPrivateKeyJWTTokenManager_InvalidKeyFile(t *testing.T) {
	tests := []struct {
		name    string
		keyJSON string
		wantErr string
	}{
		{
			name:    "invalid JSON",
			keyJSON: `{invalid`,
			wantErr: "failed to parse key file",
		},
		{
			name:    "empty key field",
			keyJSON: `{"type":"application","keyId":"k1","key":"","clientId":"c1"}`,
			wantErr: "failed to parse key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPrivateKeyJWTTokenManager(context.Background(), "https://example.com", tt.keyJSON, "openid")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewPrivateKeyJWTTokenManager_InvalidIssuerURI(t *testing.T) {
	keyJSON, _ := generateTestKeyFileJSON(t)

	tests := []struct {
		name      string
		issuerURI string
		wantErr   string
	}{
		{
			name:      "plain HTTP",
			issuerURI: "http://issuer.example.com",
			wantErr:   "must use https",
		},
		{
			name:      "relative URL",
			issuerURI: "issuer.example.com",
			wantErr:   "must be absolute",
		},
		{
			name:      "missing host",
			issuerURI: "https:///issuer",
			wantErr:   "host is required",
		},
		{
			name:      "user info",
			issuerURI: "https://user:pass@issuer.example.com",
			wantErr:   "must not include user info",
		},
		{
			name:      "query string",
			issuerURI: "https://issuer.example.com?token=leak",
			wantErr:   "must not include query or fragment",
		},
		{
			name:      "fragment",
			issuerURI: "https://issuer.example.com#fragment",
			wantErr:   "must not include query or fragment",
		},
		{
			name:      "loopback IPv4",
			issuerURI: "https://127.0.0.1",
			wantErr:   "local or private",
		},
		{
			name:      "private IPv4",
			issuerURI: "https://192.168.1.1",
			wantErr:   "local or private",
		},
		{
			name:      "loopback IPv6",
			issuerURI: "https://[::1]",
			wantErr:   "local or private",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPrivateKeyJWTTokenManager(context.Background(), tt.issuerURI, keyJSON, "openid")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestPrivateKeyJWTFetcher_BlocksRedirect(t *testing.T) {
	_, privateKey := generateTestKeyFileJSON(t)

	var attackerReceived atomic.Bool

	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("assertion") != "" {
			attackerReceived.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer tokenEndpoint.Close()

	// Build the fetcher directly (bypasses issuer URI validation) to use plain HTTP test servers.
	f := &privateKeyJWTFetcher{
		privateKey: privateKey,
		keyID:      "test-key-id",
		clientID:   "test-client-id",
		issuerURI:  tokenEndpoint.URL,
		scopes:     []string{"openid"},
		httpClient: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	// fetchToken will fail (307 is not 200), but that's expected — we only care that
	// the assertion body was not forwarded to the attacker server.
	_, _ = f.fetchToken(context.Background())

	if attackerReceived.Load() {
		t.Error("attacker server received the assertion body — redirect was followed")
	}
}

func TestPrivateKeyJWTFetcher_AssertionClaims(t *testing.T) {
	_, privateKey := generateTestKeyFileJSON(t)

	var capturedAssertion string
	var capturedGrantType string
	var capturedScope string

	// Plain HTTP server: issuer URI validation is bypassed when building the fetcher directly.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		capturedAssertion = r.FormValue("assertion")
		capturedGrantType = r.FormValue("grant_type")
		capturedScope = r.FormValue("scope")
		tokenResponseHandler("test-token", 3600)(w, r)
	}))
	defer server.Close()

	f := &privateKeyJWTFetcher{
		privateKey: privateKey,
		keyID:      "test-key-id",
		clientID:   "test-client-id",
		issuerURI:  server.URL,
		scopes:     []string{"openid"},
		httpClient: http.DefaultClient,
	}

	_, err := f.fetchToken(context.Background())
	if err != nil {
		t.Fatalf("failed to fetch token: %v", err)
	}

	// Verify grant type
	if capturedGrantType != grantTypeJWTBearer {
		t.Errorf("expected grant_type=%q, got %q", grantTypeJWTBearer, capturedGrantType)
	}

	// Verify scope
	if capturedScope != "openid" {
		t.Errorf("expected scope=openid, got %q", capturedScope)
	}

	if capturedAssertion == "" {
		t.Fatal("no assertion captured")
	}

	// Parse and verify the JWT assertion
	parsedToken, err := jwt.ParseWithClaims(
		capturedAssertion,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return &privateKey.PublicKey, nil
		},
	)
	if err != nil {
		t.Fatalf("failed to parse assertion JWT: %v", err)
	}

	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}

	if claims.Issuer != "test-client-id" {
		t.Errorf("expected iss=test-client-id, got %q", claims.Issuer)
	}
	if claims.Subject != "test-client-id" {
		t.Errorf("expected sub=test-client-id, got %q", claims.Subject)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != server.URL {
		t.Errorf("expected aud=%q, got %v", server.URL, claims.Audience)
	}
	if claims.ID == "" {
		t.Error("expected non-empty jti")
	}

	// Verify exp - iat ≈ 60s
	exp := claims.ExpiresAt.Time
	iat := claims.IssuedAt.Time
	diff := exp.Sub(iat)
	if diff < 59*time.Second || diff > 61*time.Second {
		t.Errorf("expected exp-iat≈60s, got %v", diff)
	}

	// Verify kid in header
	kid, ok := parsedToken.Header["kid"]
	if !ok {
		t.Error("expected kid in JWT header")
	}
	if kid != "test-key-id" {
		t.Errorf("expected kid=test-key-id, got %v", kid)
	}
}

func TestPrivateKeyJWTTokenManager_CachingBehavior(t *testing.T) {
	_, privateKey := generateTestKeyFileJSON(t)

	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		tokenResponseHandler("cached-token", 3600)(w, nil)
	}))
	defer server.Close()

	f := &privateKeyJWTFetcher{
		privateKey: privateKey,
		keyID:      "test-key-id",
		clientID:   "test-client-id",
		issuerURI:  server.URL,
		scopes:     []string{"openid"},
		httpClient: http.DefaultClient,
	}
	tm := newTokenManagerWithFetcher(context.Background(), f)

	// First call: cache miss
	token1, err := tm.GetTokenWithContext(context.Background())
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if requestCount.Load() != 1 {
		t.Errorf("expected 1 request after first call, got %d", requestCount.Load())
	}

	// Second call: cache hit
	token2, err := tm.GetTokenWithContext(context.Background())
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if requestCount.Load() != 1 {
		t.Errorf("expected still 1 request after cached call, got %d", requestCount.Load())
	}
	if token1 != token2 {
		t.Error("expected same token from cache")
	}

	// Expire the cached token
	tm.token = &oauth2.Token{Expiry: time.Now().Add(-time.Hour)}

	// Third call: cache miss (token expired)
	_, err = tm.GetTokenWithContext(context.Background())
	if err != nil {
		t.Fatalf("third call failed: %v", err)
	}
	if requestCount.Load() != 2 {
		t.Errorf("expected 2 requests after refresh, got %d", requestCount.Load())
	}
}

func TestPrivateKeyJWTTokenManager_ErrorPropagation(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantInErr  string
	}{
		{name: "401 unauthorized", statusCode: http.StatusUnauthorized, wantInErr: "401"},
		{name: "500 server error", statusCode: http.StatusInternalServerError, wantInErr: "500"},
	}

	_, privateKey := generateTestKeyFileJSON(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"test_error"}`, tt.statusCode)
			}))
			defer server.Close()

			f := &privateKeyJWTFetcher{
				privateKey: privateKey,
				keyID:      "test-key-id",
				clientID:   "test-client-id",
				issuerURI:  server.URL,
				scopes:     []string{"openid"},
				httpClient: http.DefaultClient,
			}
			tm := newTokenManagerWithFetcher(context.Background(), f)

			_, fetchErr := tm.GetTokenWithContext(context.Background())
			if fetchErr == nil {
				t.Fatal("expected error for non-200 response")
			}
			if !strings.Contains(fetchErr.Error(), tt.wantInErr) {
				t.Errorf("expected %q in error, got: %v", tt.wantInErr, fetchErr)
			}

			// Token must not be cached after error
			if tm.token != nil {
				t.Error("expected nil cached token after error")
			}
		})
	}
}

func TestPrivateKeyJWTTokenManager_TimeoutContextCancelled(t *testing.T) {
	_, privateKey := generateTestKeyFileJSON(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
		http.Error(w, "timeout", http.StatusGatewayTimeout)
	}))
	defer server.Close()

	f := &privateKeyJWTFetcher{
		privateKey: privateKey,
		keyID:      "test-key-id",
		clientID:   "test-client-id",
		issuerURI:  server.URL,
		scopes:     []string{"openid"},
		httpClient: &http.Client{Transport: &http.Transport{DisableKeepAlives: true}},
	}
	tm := newTokenManagerWithFetcher(context.Background(), f)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := tm.GetTokenWithContext(ctx)
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
}

func TestPrivateKeyJWTTokenManager_TimeoutHTTPClient(t *testing.T) {
	_, privateKey := generateTestKeyFileJSON(t)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond) // hang longer than client timeout
	}))
	defer server.Close()

	f := &privateKeyJWTFetcher{
		privateKey: privateKey,
		keyID:      "test-key-id",
		clientID:   "test-client-id",
		issuerURI:  server.URL,
		scopes:     []string{"openid"},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}
	tm := newTokenManagerWithFetcher(context.Background(), f)

	_, err := tm.GetTokenWithContext(context.Background())
	if err == nil {
		t.Fatal("expected error when http.Client timeout fires")
	}
}

func TestNewPrivateKeyJWTTokenManager_WithHTTPClient(t *testing.T) {
	keyJSON, _ := generateTestKeyFileJSON(t)

	customClient := &http.Client{
		Timeout: 42 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tm, err := NewPrivateKeyJWTTokenManager(
		context.Background(),
		"https://issuer.example.com",
		keyJSON,
		"openid",
		WithHTTPClient(customClient),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fetcher, ok := tm.fetcher.(*privateKeyJWTFetcher)
	if !ok {
		t.Fatal("expected privateKeyJWTFetcher")
	}
	if fetcher.httpClient != customClient {
		t.Error("expected WithHTTPClient override to be applied to fetcher")
	}
}

func TestNewPrivateKeyJWTTokenManager_WithHTTPClient_NoRedirect(t *testing.T) {
	keyJSON, _ := generateTestKeyFileJSON(t)

	clientWithoutRedirect := &http.Client{Timeout: 5 * time.Second}

	tm, err := NewPrivateKeyJWTTokenManager(
		context.Background(),
		"https://issuer.example.com",
		keyJSON,
		"openid",
		WithHTTPClient(clientWithoutRedirect),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fetcher, ok := tm.fetcher.(*privateKeyJWTFetcher)
	if !ok {
		t.Fatal("expected privateKeyJWTFetcher")
	}
	if fetcher.httpClient == clientWithoutRedirect {
		t.Error("expected a copy with CheckRedirect set, not the original client")
	}
	if fetcher.httpClient.CheckRedirect == nil {
		t.Error("expected CheckRedirect to be set on the copied client")
	}
}
