package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// NewLocalHTTPServer starts an HTTP server bound to IPv4 loopback only.
// The sandbox blocks IPv6 listeners, so force tcp4 to keep tests runnable.
func NewLocalHTTPServer(tb testing.TB, handler http.Handler) *httptest.Server {
	tb.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("failed to create IPv4 listener: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()

	return server
}

// RoundTripFunc allows inlining http.RoundTripper implementations.
type RoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls the underlying function.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// MockOAuth2Server simulates an OAuth2 token endpoint without real sockets.
// It records requests and serves responses through a custom RoundTripper.
type MockOAuth2Server struct {
	URL      string
	Ctx      context.Context
	Requests []*http.Request
}

// NewMockOAuth2Server builds a mock OAuth2 endpoint backed by an in-memory RoundTripper.
// If handler is nil, it returns a default successful token response.
func NewMockOAuth2Server(tb testing.TB, handler RoundTripFunc) *MockOAuth2Server {
	tb.Helper()

	server := &MockOAuth2Server{
		URL: "https://mock-oauth.example.com",
	}

	if handler == nil {
		handler = StaticJSONResponse(`{
			"access_token": "mock-access-token",
			"token_type": "Bearer",
			"expires_in": 3600
		}`)
	}

	rt := RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		server.Requests = append(server.Requests, req)
		return handler(req)
	})

	prevTransport := http.DefaultTransport
	prevClient := http.DefaultClient
	http.DefaultTransport = rt
	http.DefaultClient = &http.Client{Transport: rt}
	tb.Cleanup(func() {
		http.DefaultTransport = prevTransport
		http.DefaultClient = prevClient
	})

	server.Ctx = context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: rt,
	})

	return server
}

// Close is a no-op to mirror httptest.Server usage in tests.
func (m *MockOAuth2Server) Close() {}

// StaticJSONResponse returns a RoundTripper that always responds with the provided JSON body.
func StaticJSONResponse(body string) RoundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}
}

// WriteTestCACert writes a self-signed CA certificate to the provided path for TLS tests.
func WriteTestCACert(tb testing.TB, path string) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		Subject:               pkix.Name{CommonName: "test-ca"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		tb.Fatalf("failed to create CA certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		tb.Fatalf("failed to write CA certificate: %v", err)
	}
}

// WriteTestCertAndKey writes a self-signed certificate and key to the provided paths.
func WriteTestCertAndKey(tb testing.TB, certPath, keyPath string) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: "test-cert"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		tb.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		tb.Fatalf("failed to write certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		tb.Fatalf("failed to write key: %v", err)
	}
}

// CreateJWKSServer creates a mock JWKS server with proper RSA public key encoding.
// This is used for JWT validation integration tests.
func CreateJWKSServer(tb testing.TB, publicKey *rsa.PublicKey) *httptest.Server {
	tb.Helper()

	// Encode public key modulus and exponent to base64url
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	n := encodeBase64URL(nBytes)
	e := encodeBase64URL(eBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "test-key-1",
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			tb.Fatalf("failed to encode JWKS: %v", err)
		}
	}))

	return server
}

// encodeBase64URL encodes bytes to base64url (without padding) as required by JWK spec.
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// TestKeyPair holds an RSA key pair for JWT testing.
type TestKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// GenerateTestKeyPair generates a new RSA key pair for testing.
func GenerateTestKeyPair(tb testing.TB) *TestKeyPair {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate RSA key pair: %v", err)
	}

	return &TestKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}
}

// JWTTestSetup contains all components needed for JWT validation testing.
type JWTTestSetup struct {
	KeyPair    *TestKeyPair
	JWKSServer *httptest.Server
	Issuer     string
	Audience   string
}

// NewJWTTestSetup creates a complete test setup with JWKS server and key pair.
func NewJWTTestSetup(tb testing.TB) *JWTTestSetup {
	tb.Helper()

	keyPair := GenerateTestKeyPair(tb)
	jwksServer := CreateJWKSServer(tb, keyPair.PublicKey)

	tb.Cleanup(func() {
		jwksServer.Close()
	})

	return &JWTTestSetup{
		KeyPair:    keyPair,
		JWKSServer: jwksServer,
		Issuer:     "https://auth.example.com",
		Audience:   "my-api",
	}
}

// JWTClaims provides a builder pattern for creating test JWT claims.
type JWTClaims struct {
	claims jwt.MapClaims
}

// NewJWTClaims creates a new JWTClaims builder with default valid claims.
func NewJWTClaims(issuer, audience, subject string) *JWTClaims {
	return &JWTClaims{
		claims: jwt.MapClaims{
			"iss": issuer,
			"aud": []string{audience},
			"sub": subject,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Add(-time.Minute).Unix(),
		},
	}
}

// WithExpiry sets a custom expiry time.
func (c *JWTClaims) WithExpiry(exp time.Time) *JWTClaims {
	c.claims["exp"] = exp.Unix()
	return c
}

// WithIssuedAt sets a custom issued at time.
func (c *JWTClaims) WithIssuedAt(iat time.Time) *JWTClaims {
	c.claims["iat"] = iat.Unix()
	return c
}

// WithScope sets the scope claim (space-separated string).
func (c *JWTClaims) WithScope(scope string) *JWTClaims {
	c.claims["scope"] = scope
	return c
}

// WithScopeArray sets the scope claim as an array.
func (c *JWTClaims) WithScopeArray(scopes []string) *JWTClaims {
	scopeInterfaces := make([]interface{}, len(scopes))
	for i, s := range scopes {
		scopeInterfaces[i] = s
	}
	c.claims["scope"] = scopeInterfaces
	return c
}

// WithScp sets the scp claim (alternative scope format).
func (c *JWTClaims) WithScp(scp string) *JWTClaims {
	c.claims["scp"] = scp
	return c
}

// WithEmail sets the email claim.
func (c *JWTClaims) WithEmail(email string) *JWTClaims {
	c.claims["email"] = email
	return c
}

// WithIssuer overrides the issuer.
func (c *JWTClaims) WithIssuer(issuer string) *JWTClaims {
	c.claims["iss"] = issuer
	return c
}

// WithAudience overrides the audience.
func (c *JWTClaims) WithAudience(audience []string) *JWTClaims {
	c.claims["aud"] = audience
	return c
}

// WithSubject overrides the subject.
func (c *JWTClaims) WithSubject(subject string) *JWTClaims {
	c.claims["sub"] = subject
	return c
}

// WithoutClaim removes a specific claim.
func (c *JWTClaims) WithoutClaim(key string) *JWTClaims {
	delete(c.claims, key)
	return c
}

// WithCustomClaim adds a custom claim.
func (c *JWTClaims) WithCustomClaim(key string, value interface{}) *JWTClaims {
	c.claims[key] = value
	return c
}

// Build returns the underlying jwt.MapClaims.
func (c *JWTClaims) Build() jwt.MapClaims {
	return c.claims
}

// SignToken signs the claims with the given private key and returns the token string.
func (c *JWTClaims) SignToken(tb testing.TB, privateKey *rsa.PrivateKey) string {
	tb.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c.claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		tb.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

// CreateSignedToken is a convenience function to create a signed token directly.
func CreateSignedToken(tb testing.TB, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	tb.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		tb.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

// CreateExpiredToken creates a token that has already expired.
func CreateExpiredToken(tb testing.TB, setup *JWTTestSetup, subject string) string {
	tb.Helper()

	return NewJWTClaims(setup.Issuer, setup.Audience, subject).
		WithExpiry(time.Now().Add(-time.Hour)).
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateValidToken creates a valid token with default claims.
func CreateValidToken(tb testing.TB, setup *JWTTestSetup, subject string) string {
	tb.Helper()

	return NewJWTClaims(setup.Issuer, setup.Audience, subject).
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateTokenWithWrongIssuer creates a token with an incorrect issuer.
func CreateTokenWithWrongIssuer(tb testing.TB, setup *JWTTestSetup, subject string) string {
	tb.Helper()

	return NewJWTClaims("https://wrong-issuer.com", setup.Audience, subject).
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateTokenWithWrongAudience creates a token with an incorrect audience.
func CreateTokenWithWrongAudience(tb testing.TB, setup *JWTTestSetup, subject string) string {
	tb.Helper()

	return NewJWTClaims(setup.Issuer, "wrong-audience", subject).
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateTokenWithoutSubject creates a token without a subject claim.
func CreateTokenWithoutSubject(tb testing.TB, setup *JWTTestSetup) string {
	tb.Helper()

	return NewJWTClaims(setup.Issuer, setup.Audience, "").
		WithSubject("").
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateTokenWithoutExpiry creates a token without an expiry claim.
func CreateTokenWithoutExpiry(tb testing.TB, setup *JWTTestSetup, subject string) string {
	tb.Helper()

	return NewJWTClaims(setup.Issuer, setup.Audience, subject).
		WithoutClaim("exp").
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateTokenWithoutIssuedAt creates a token without an issued at claim.
func CreateTokenWithoutIssuedAt(tb testing.TB, setup *JWTTestSetup, subject string) string {
	tb.Helper()

	return NewJWTClaims(setup.Issuer, setup.Audience, subject).
		WithoutClaim("iat").
		SignToken(tb, setup.KeyPair.PrivateKey)
}

// CreateJWKSServerWithMultipleKeys creates a JWKS server with multiple keys.
func CreateJWKSServerWithMultipleKeys(tb testing.TB, keyPairs ...*TestKeyPair) *httptest.Server {
	tb.Helper()

	keys := make([]map[string]interface{}, len(keyPairs))
	for i, kp := range keyPairs {
		nBytes := kp.PublicKey.N.Bytes()
		eBytes := big.NewInt(int64(kp.PublicKey.E)).Bytes()

		keys[i] = map[string]interface{}{
			"kty": "RSA",
			"kid": "test-key-" + string(rune('1'+i)),
			"use": "sig",
			"alg": "RS256",
			"n":   encodeBase64URL(nBytes),
			"e":   encodeBase64URL(eBytes),
		}
	}

	jwks := map[string]interface{}{"keys": keys}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			tb.Fatalf("failed to encode JWKS: %v", err)
		}
	}))

	return server
}

// CreateJWKSServerWithDelay creates a JWKS server that delays responses.
func CreateJWKSServerWithDelay(tb testing.TB, publicKey *rsa.PublicKey, delay time.Duration) *httptest.Server {
	tb.Helper()

	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "test-key-1",
				"use": "sig",
				"alg": "RS256",
				"n":   encodeBase64URL(nBytes),
				"e":   encodeBase64URL(eBytes),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			tb.Fatalf("failed to encode JWKS: %v", err)
		}
	}))

	return server
}

// CreateFailingJWKSServer creates a JWKS server that returns errors.
func CreateFailingJWKSServer(tb testing.TB, statusCode int, body string) *httptest.Server {
	tb.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body)) // Error intentionally ignored in test helper
	}))

	return server
}
