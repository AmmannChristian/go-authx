package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestValidateToken_FullIntegration tests the complete token validation flow
// with real RSA keys and proper JWT tokens
func TestValidateToken_FullIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create JWKS server with proper key format
	jwksServer := createJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	// Create validator
	validator, err := NewJWTTokenValidator(
		jwksServer.URL+"/jwks.json",
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
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://auth.example.com",
		"aud":   []interface{}{"my-api"},
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read write",
		"email": "user@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

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
	if len(tokenClaims.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(tokenClaims.Scopes))
	}
	if tokenClaims.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer https://auth.example.com, got %s", tokenClaims.Issuer)
	}
}

func TestValidateToken_InvalidIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksServer := createJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	validator, err := NewJWTTokenValidator(
		jwksServer.URL+"/jwks.json",
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token with wrong issuer
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://wrong-issuer.com",
		"aud": []interface{}{"my-api"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for invalid issuer")
	}
}

func TestValidateToken_InvalidAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksServer := createJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	validator, err := NewJWTTokenValidator(
		jwksServer.URL+"/jwks.json",
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token with wrong audience
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []interface{}{"wrong-api"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for invalid audience")
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksServer := createJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	validator, err := NewJWTTokenValidator(
		jwksServer.URL+"/jwks.json",
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create expired token
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []interface{}{"my-api"},
		"exp": now.Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat": now.Add(-2 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidateToken_ScopesArray(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksServer := createJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	validator, err := NewJWTTokenValidator(
		jwksServer.URL+"/jwks.json",
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token with scopes as array
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "user123",
		"iss":   "https://auth.example.com",
		"aud":   []interface{}{"my-api"},
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": []interface{}{"read", "write", "admin"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	tokenClaims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if len(tokenClaims.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(tokenClaims.Scopes))
	}
}

func TestValidateToken_NoEmail(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksServer := createJWKSServer(t, &privateKey.PublicKey)
	defer jwksServer.Close()

	validator, err := NewJWTTokenValidator(
		jwksServer.URL+"/jwks.json",
		"https://auth.example.com",
		"my-api",
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token without email
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []interface{}{"my-api"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	tokenClaims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if tokenClaims.Email != "" {
		t.Errorf("expected empty email, got %s", tokenClaims.Email)
	}
}

// createJWKSServer creates a mock JWKS server with proper RSA public key
func createJWKSServer(t *testing.T, publicKey *rsa.PublicKey) *httptest.Server {
	t.Helper()

	// Encode public key modulus and exponent to base64url
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	n := base64.RawURLEncoding.EncodeToString(nBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

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
		json.NewEncoder(w).Encode(jwks)
	}))

	return server
}

func TestNewJWTTokenValidator_WithCustomHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	customClient := &http.Client{Timeout: 5 * time.Second}

	validator, err := NewJWTTokenValidator(
		server.URL,
		"https://auth.example.com",
		"my-api",
		customClient,
		10*time.Minute,
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
