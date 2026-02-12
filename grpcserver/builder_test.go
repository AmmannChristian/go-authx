package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/internal/testutil"
)

func TestNewValidatorBuilder(t *testing.T) {
	issuer := "https://auth.example.com"
	audience := "my-api"

	builder := NewValidatorBuilder(issuer, audience)

	if builder.issuerURL != issuer {
		t.Errorf("expected issuer %s, got %s", issuer, builder.issuerURL)
	}
	if builder.audience != audience {
		t.Errorf("expected audience %s, got %s", audience, builder.audience)
	}
	if builder.cacheTTL != time.Hour {
		t.Errorf("expected default cache TTL of 1 hour, got %v", builder.cacheTTL)
	}
	if builder.httpClient == nil {
		t.Error("expected HTTP client to be initialized")
	}
}

func TestValidatorBuilder_WithJWKSURL(t *testing.T) {
	builder := NewValidatorBuilder("https://auth.example.com", "my-api")
	customURL := "https://auth.example.com/custom/jwks"

	builder.WithJWKSURL(customURL)

	if builder.jwksURL != customURL {
		t.Errorf("expected JWKS URL %s, got %s", customURL, builder.jwksURL)
	}
}

func TestValidatorBuilder_WithCacheTTL(t *testing.T) {
	builder := NewValidatorBuilder("https://auth.example.com", "my-api")
	customTTL := 30 * time.Minute

	builder.WithCacheTTL(customTTL)

	if builder.cacheTTL != customTTL {
		t.Errorf("expected cache TTL %v, got %v", customTTL, builder.cacheTTL)
	}
}

func TestValidatorBuilder_WithHTTPClient(t *testing.T) {
	builder := NewValidatorBuilder("https://auth.example.com", "my-api")
	customClient := &http.Client{Timeout: 5 * time.Second}

	builder.WithHTTPClient(customClient)

	if builder.httpClient != customClient {
		t.Error("expected custom HTTP client to be set")
	}
}

func TestValidatorBuilder_WithLogger(t *testing.T) {
	builder := NewValidatorBuilder("https://auth.example.com", "my-api")
	logger := &mockLogger{}

	builder.WithLogger(logger)

	if builder.logger != logger {
		t.Error("expected custom logger to be set")
	}
}

func TestValidatorBuilder_WithOpaqueTokenIntrospection(t *testing.T) {
	builder := NewValidatorBuilder("https://auth.example.com", "my-api")

	builder.WithOpaqueTokenIntrospection(
		"https://auth.example.com/oauth2/introspect",
		"client-id",
		"client-secret",
	)

	if !builder.useOpaqueToken {
		t.Error("expected opaque token mode to be enabled")
	}
	if builder.introspectionURL != "https://auth.example.com/oauth2/introspect" {
		t.Errorf("unexpected introspection URL: %s", builder.introspectionURL)
	}
	if builder.introspectionAuthConfig.Method != IntrospectionClientAuthMethodClientSecretBasic {
		t.Errorf("unexpected introspection method: %s", builder.introspectionAuthConfig.Method)
	}
	if builder.introspectionAuthConfig.ClientID != "client-id" {
		t.Errorf("unexpected client ID: %s", builder.introspectionAuthConfig.ClientID)
	}
	if builder.introspectionAuthConfig.ClientSecret != "client-secret" {
		t.Errorf("unexpected client secret: %s", builder.introspectionAuthConfig.ClientSecret)
	}
}

func TestValidatorBuilder_WithOpaqueTokenIntrospectionAuth(t *testing.T) {
	builder := NewValidatorBuilder("https://auth.example.com", "my-api")

	authConfig := IntrospectionClientAuthConfig{
		Method:                 IntrospectionClientAuthMethodPrivateKeyJWT,
		ClientID:               "client-id",
		PrivateKey:             "private-key",
		PrivateKeyJWTKeyID:     "kid-1",
		PrivateKeyJWTAlgorithm: IntrospectionPrivateKeyJWTAlgorithmRS256,
	}

	builder.WithOpaqueTokenIntrospectionAuth("https://auth.example.com/oauth2/introspect", authConfig)

	if builder.introspectionAuthConfig != authConfig {
		t.Fatalf("unexpected introspection auth config: %+v", builder.introspectionAuthConfig)
	}
}

func TestValidatorBuilder_FluentAPI(t *testing.T) {
	// Test that all builder methods return the builder for chaining
	builder := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithJWKSURL("https://custom.jwks.url").
		WithCacheTTL(15 * time.Minute).
		WithHTTPClient(&http.Client{}).
		WithLogger(&mockLogger{})

	if builder.jwksURL != "https://custom.jwks.url" {
		t.Error("fluent API failed to set JWKS URL")
	}
	if builder.cacheTTL != 15*time.Minute {
		t.Error("fluent API failed to set cache TTL")
	}
}

func TestValidatorBuilder_Build_MissingIssuer(t *testing.T) {
	builder := &ValidatorBuilder{
		audience: "my-api",
	}

	_, err := builder.Build()
	if err == nil {
		t.Error("expected error when issuer is missing")
	}
	if !strings.Contains(err.Error(), "issuer URL is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidatorBuilder_Build_MissingAudience(t *testing.T) {
	builder := &ValidatorBuilder{
		issuerURL: "https://auth.example.com",
	}

	_, err := builder.Build()
	if err == nil {
		t.Error("expected error when audience is missing")
	}
	if !strings.Contains(err.Error(), "audience is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeriveJWKSURL(t *testing.T) {
	tests := []struct {
		name      string
		issuerURL string
		want      string
	}{
		{
			name:      "without trailing slash",
			issuerURL: "https://auth.example.com",
			want:      "https://auth.example.com/.well-known/jwks.json",
		},
		{
			name:      "with trailing slash",
			issuerURL: "https://auth.example.com/",
			want:      "https://auth.example.com/.well-known/jwks.json",
		},
		{
			name:      "with path",
			issuerURL: "https://auth.example.com/oauth/v2",
			want:      "https://auth.example.com/oauth/v2/.well-known/jwks.json",
		},
		{
			name:      "with path and trailing slash",
			issuerURL: "https://auth.example.com/oauth/v2/",
			want:      "https://auth.example.com/oauth/v2/.well-known/jwks.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveJWKSURL(tt.issuerURL)
			if got != tt.want {
				t.Errorf("deriveJWKSURL(%s) = %s, want %s", tt.issuerURL, got, tt.want)
			}
		})
	}
}

func TestValidatorBuilder_Build_InvalidJWKS(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("server error")),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		}),
		Timeout: 1 * time.Second,
	}

	builder := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithJWKSURL("https://auth.example.com/jwks.json").
		WithHTTPClient(client)

	_, err := builder.Build()
	if err == nil {
		t.Error("expected error when JWKS URL returns error")
	}
	if !strings.Contains(err.Error(), "failed to build validator") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidatorBuilder_Build_Success(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
				Request:    r,
			}, nil
		}),
		Timeout: 1 * time.Second,
	}

	// Build validator with mock JWKS server
	validator, err := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithJWKSURL("https://auth.example.com/jwks.json").
		WithCacheTTL(5 * time.Minute).
		WithLogger(&mockLogger{}).
		WithHTTPClient(client).
		Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validator == nil {
		t.Fatal("expected validator to be created")
	}

	// Clean up
	if v, ok := validator.(*JWTTokenValidator); ok {
		v.Close()
	}
}

func TestValidatorBuilder_Build_DerivedJWKSURL(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/.well-known/jwks.json" {
				return nil, fmt.Errorf("unexpected path: %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
				Request:    r,
			}, nil
		}),
		Timeout: 1 * time.Second,
	}

	// Build validator without explicit JWKS URL (should derive it)
	logger := &mockLogger{}
	validator, err := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithLogger(logger).
		WithHTTPClient(client).
		Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validator == nil {
		t.Fatal("expected validator to be created")
	}

	// Verify that logger was called with derived JWKS URL message
	if len(logger.getMessages()) == 0 {
		t.Error("expected logger to log derived JWKS URL")
	}

	// Clean up
	if v, ok := validator.(*JWTTokenValidator); ok {
		v.Close()
	}
}

func TestValidatorBuilder_Build_OpaqueTokenValidator(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://auth.example.com/oauth2/introspect" {
				return nil, fmt.Errorf("unexpected URL: %s", r.URL.String())
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"active": true,
					"iss": "https://auth.example.com",
					"aud": ["my-api"],
					"sub": "user-123"
				}`)),
				Request: r,
			}, nil
		}),
	}

	validator, err := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithOpaqueTokenIntrospection("https://auth.example.com/oauth2/introspect", "client-id", "client-secret").
		WithHTTPClient(client).
		Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := validator.(*OpaqueTokenValidator); !ok {
		t.Fatalf("expected *OpaqueTokenValidator, got %T", validator)
	}

	if _, err := validator.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("validator should validate opaque token response: %v", err)
	}
}

func TestValidatorBuilder_Build_OpaqueTokenValidator_MissingConfig(t *testing.T) {
	_, err := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithOpaqueTokenIntrospection("", "client-id", "client-secret").
		Build()
	if err == nil {
		t.Fatal("expected error for missing introspection URL")
	}
	if !strings.Contains(err.Error(), "failed to build opaque token validator") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatorBuilder_Build_OpaqueTokenValidator_PrivateKeyJWT(t *testing.T) {
	privateKeyPEM := mustGeneratePrivateKeyPEM(t)

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				return nil, fmt.Errorf("expected no authorization header, got %q", authHeader)
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
			values, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				return nil, fmt.Errorf("failed to parse body: %w", err)
			}
			if values.Get("token") != "opaque-token" {
				return nil, fmt.Errorf("unexpected token value %q", values.Get("token"))
			}
			if values.Get("token_type_hint") != "access_token" {
				return nil, fmt.Errorf("unexpected token_type_hint %q", values.Get("token_type_hint"))
			}
			if values.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
				return nil, fmt.Errorf("unexpected assertion type %q", values.Get("client_assertion_type"))
			}
			if values.Get("client_assertion") == "" {
				return nil, fmt.Errorf("missing client_assertion")
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"active": true,
					"iss": "https://auth.example.com",
					"aud": ["my-api"],
					"sub": "user-123"
				}`)),
				Request: r,
			}, nil
		}),
	}

	validator, err := NewValidatorBuilder("https://auth.example.com", "my-api").
		WithOpaqueTokenIntrospectionAuth(
			"https://auth.example.com/oauth2/introspect",
			IntrospectionClientAuthConfig{
				Method:             IntrospectionClientAuthMethodPrivateKeyJWT,
				ClientID:           "client-id",
				PrivateKey:         privateKeyPEM,
				PrivateKeyJWTKeyID: "kid-1",
			},
		).
		WithHTTPClient(client).
		Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := validator.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("validator should validate opaque token response: %v", err)
	}
}

// mockLogger is a simple logger implementation for testing
type mockLogger struct {
	mu       sync.Mutex
	messages []string
}

func (m *mockLogger) Printf(format string, args ...any) {
	// Store messages for verification in tests
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, format)
}

func (m *mockLogger) getMessages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to avoid race conditions
	msgs := make([]string, len(m.messages))
	copy(msgs, m.messages)
	return msgs
}

func mustGeneratePrivateKeyPEM(tb testing.TB) string {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate rsa key: %v", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		tb.Fatalf("failed to marshal private key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}))
}
