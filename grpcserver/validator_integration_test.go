package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/internal/testutil"
	"github.com/golang-jwt/jwt/v5"
)

func jwksStub(t testing.TB, publicKey *rsa.PublicKey) (string, *http.Client) {
	t.Helper()

	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	body := `{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"` + n + `","e":"` + e + `"}]}`

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
		Timeout: 5 * time.Second,
	}

	return "https://auth.example.com/.well-known/jwks.json", client
}

// TestValidateToken_FullIntegration tests the complete token validation flow
// with real RSA keys and proper JWT tokens
func TestValidateToken_FullIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	// Create validator
	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
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

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
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

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
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

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
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

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
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

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
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

func TestValidateToken_MissingSubject(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token without subject claim
	now := time.Now()
	claims := jwt.MapClaims{
		// "sub" is missing
		"iss": "https://auth.example.com",
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
		t.Fatal("expected error for missing subject")
	}
	if !strings.Contains(err.Error(), "invalid subject claim") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_MissingExpiry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token without expiry claim
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []interface{}{"my-api"},
		// "exp" is missing
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Fatal("expected error for missing expiry")
	}
	if !strings.Contains(err.Error(), "invalid expiry claim") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_MissingIssuedAt(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwksURL, client := jwksStub(t, &privateKey.PublicKey)

	validator, err := NewJWTTokenValidator(
		jwksURL,
		"https://auth.example.com",
		"my-api",
		client,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token without issued at claim
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"aud": []interface{}{"my-api"},
		"exp": now.Add(time.Hour).Unix(),
		// "iat" is missing
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Fatal("expected error for missing issued at")
	}
	if !strings.Contains(err.Error(), "invalid issued at claim") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_RefreshErrorHandler(t *testing.T) {
	refreshCount := 0
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			refreshCount++
			if refreshCount > 1 {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("refresh error")),
					Header:     make(http.Header),
					Request:    r,
				}, nil
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

	logger := &mockLogger{}
	validator, err := NewJWTTokenValidator(
		"https://auth.example.com/jwks.json",
		"https://auth.example.com",
		"my-api",
		client,
		100*time.Millisecond, // Short refresh interval
		logger,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Wait for refresh to occur
	time.Sleep(250 * time.Millisecond)

	// Check that logger received refresh error
	found := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "JWKS refresh error") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected logger to receive JWKS refresh error")
	}
}

func TestNewJWTTokenValidator_WithCustomHTTPClient(t *testing.T) {
	customClient := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
				Request:    r,
			}, nil
		}),
		Timeout: 5 * time.Second,
	}

	validator, err := NewJWTTokenValidator(
		"https://auth.example.com/jwks.json",
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
