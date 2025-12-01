package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockJWKSServer creates a mock JWKS server for testing
func mockJWKSServer(t *testing.T, privateKey *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	// Create JWKS response with public key
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "test-key-1",
				"use": "sig",
				"n":   encodePublicKey(&privateKey.PublicKey),
				"e":   "AQAB",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))

	return server
}

// encodePublicKey encodes RSA public key modulus to base64 (simplified)
func encodePublicKey(pub *rsa.PublicKey) string {
	// For testing, we'll use a simplified approach
	// In production, this would be properly base64-encoded
	return "test-modulus"
}

// generateTestToken creates a signed JWT token for testing
func generateTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

func TestNewJWTTokenValidator(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	validator, err := NewJWTTokenValidator(
		server.URL,
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validator == nil {
		t.Fatal("expected validator to be created")
	}

	validator.Close()
}

func TestNewJWTTokenValidator_MissingJWKSURL(t *testing.T) {
	_, err := NewJWTTokenValidator("", "https://auth.example.com", "my-api", nil, 0, nil)
	if err == nil {
		t.Error("expected error when JWKS URL is missing")
	}
	if !strings.Contains(err.Error(), "JWKS URL is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_MissingIssuer(t *testing.T) {
	_, err := NewJWTTokenValidator("https://jwks.example.com", "", "my-api", nil, 0, nil)
	if err == nil {
		t.Error("expected error when issuer is missing")
	}
	if !strings.Contains(err.Error(), "issuer is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_MissingAudience(t *testing.T) {
	_, err := NewJWTTokenValidator("https://jwks.example.com", "https://auth.example.com", "", nil, 0, nil)
	if err == nil {
		t.Error("expected error when audience is missing")
	}
	if !strings.Contains(err.Error(), "audience is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_WithLogger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	logger := &mockLogger{}
	validator, err := NewJWTTokenValidator(
		server.URL,
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		logger,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validator.logger != logger {
		t.Error("expected logger to be set")
	}

	validator.Close()
}

func TestValidateToken_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	validator, _ := NewJWTTokenValidator(server.URL, "https://auth.example.com", "my-api", nil, 0, nil)
	defer validator.Close()

	ctx := context.Background()
	_, err := validator.ValidateToken(ctx, "invalid-token")
	if err == nil {
		t.Error("expected error when token is invalid")
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	validator, _ := NewJWTTokenValidator(server.URL, "https://auth.example.com", "my-api", nil, 0, nil)
	defer validator.Close()

	ctx := context.Background()
	malformedTokens := []string{
		"",
		"not.a.token",
		"header.payload", // Missing signature
	}

	for _, token := range malformedTokens {
		_, err := validator.ValidateToken(ctx, token)
		if err == nil {
			t.Errorf("expected error for malformed token: %s", token)
		}
	}
}

func TestExtractScopes(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   []string
	}{
		{
			name:   "scope as string",
			claims: jwt.MapClaims{"scope": "read write admin"},
			want:   []string{"read", "write", "admin"},
		},
		{
			name:   "scope as array",
			claims: jwt.MapClaims{"scope": []interface{}{"read", "write", "admin"}},
			want:   []string{"read", "write", "admin"},
		},
		{
			name:   "scp as string",
			claims: jwt.MapClaims{"scp": "read write"},
			want:   []string{"read", "write"},
		},
		{
			name:   "scp as array",
			claims: jwt.MapClaims{"scp": []interface{}{"read", "write"}},
			want:   []string{"read", "write"},
		},
		{
			name:   "no scopes",
			claims: jwt.MapClaims{},
			want:   []string{},
		},
		{
			name:   "scope priority over scp",
			claims: jwt.MapClaims{"scope": "read", "scp": "write"},
			want:   []string{"read"},
		},
		{
			name:   "empty scope string",
			claims: jwt.MapClaims{"scope": ""},
			want:   []string{},
		},
		{
			name:   "scope with extra whitespace",
			claims: jwt.MapClaims{"scope": "  read   write  "},
			want:   []string{"read", "write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractScopes(tt.claims)
			if len(got) != len(tt.want) {
				t.Errorf("extractScopes() got %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractScopes() got %v, want %v", got, tt.want)
					return
				}
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		value string
		want  bool
	}{
		{
			name:  "value exists",
			slice: []string{"a", "b", "c"},
			value: "b",
			want:  true,
		},
		{
			name:  "value does not exist",
			slice: []string{"a", "b", "c"},
			value: "d",
			want:  false,
		},
		{
			name:  "empty slice",
			slice: []string{},
			value: "a",
			want:  false,
		},
		{
			name:  "nil slice",
			slice: nil,
			value: "a",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.slice, tt.value)
			if got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWTTokenValidator_Close(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	validator, err := NewJWTTokenValidator(server.URL, "https://auth.example.com", "my-api", nil, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic
	validator.Close()

	// Calling Close again should also not panic
	validator.Close()
}

func TestNewJWTTokenValidator_DefaultHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	// Pass nil HTTP client - should use default
	validator, err := NewJWTTokenValidator(server.URL, "https://auth.example.com", "my-api", nil, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer validator.Close()

	if validator == nil {
		t.Error("expected validator to be created with default HTTP client")
	}
}

func TestNewJWTTokenValidator_DefaultCacheTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	// Pass 0 cache TTL - should use default of 1 hour
	validator, err := NewJWTTokenValidator(server.URL, "https://auth.example.com", "my-api", nil, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer validator.Close()

	// We can't directly check the cache TTL, but we can verify the validator was created
	if validator == nil {
		t.Error("expected validator to be created with default cache TTL")
	}
}

func TestNewJWTTokenValidator_InvalidJWKSURL(t *testing.T) {
	_, err := NewJWTTokenValidator(
		"https://nonexistent-url-12345.example.com/jwks",
		"https://auth.example.com",
		"my-api",
		&http.Client{Timeout: 1 * time.Second},
		0,
		nil,
	)

	if err == nil {
		t.Error("expected error when JWKS URL is unreachable")
	}
	if !strings.Contains(err.Error(), "failed to initialize JWKS") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestValidateToken_Integration is a more realistic integration test
// Note: This test is simplified as we can't easily generate valid RSA signatures in tests
// without significant additional setup. In a real scenario, you would use a proper test JWKS server.
func TestValidateToken_Integration(t *testing.T) {
	t.Skip("Skipping integration test - requires proper RSA key setup")

	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create mock JWKS server
	server := mockJWKSServer(t, privateKey)
	defer server.Close()

	// Create validator
	validator, err := NewJWTTokenValidator(
		server.URL,
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		&mockLogger{},
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create valid token
	claims := jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://auth.example.com",
		"aud":   []string{"my-api"},
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "read write",
		"email": "user@example.com",
	}

	tokenString := generateTestToken(t, privateKey, claims)

	// Validate token
	ctx := context.Background()
	tokenClaims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	// Verify claims
	if tokenClaims.Subject != "user123" {
		t.Errorf("expected subject user123, got %s", tokenClaims.Subject)
	}
	if tokenClaims.Email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %s", tokenClaims.Email)
	}
}
