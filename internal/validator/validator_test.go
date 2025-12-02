package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/internal/testutil"
	"github.com/golang-jwt/jwt/v5"
)

const testJWKSURL = "https://auth.example.com/jwks.json"

// mockLogger implements the Logger interface for testing
type mockLogger struct {
	mu       sync.Mutex
	messages []string
}

func (m *mockLogger) Printf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.messages == nil {
		m.messages = make([]string, 0)
	}
	m.messages = append(m.messages, fmt.Sprintf(format, args...))
}

func (m *mockLogger) getMessages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	msgs := make([]string, len(m.messages))
	copy(msgs, m.messages)
	return msgs
}

func stubJWKSClient(body string, status int) *http.Client {
	return &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
		Timeout: 5 * time.Second,
	}
}

func TestNewJWTTokenValidator(t *testing.T) {
	client := stubJWKSClient(`{"keys":[]}`, http.StatusOK)
	validator, err := NewJWTTokenValidator(
		testJWKSURL,
		"https://auth.example.com",
		"my-api",
		client,
		0,
		nil,
		"test",
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
	_, err := NewJWTTokenValidator("", "https://auth.example.com", "my-api", nil, 0, nil, "test")
	if err == nil {
		t.Error("expected error when JWKS URL is missing")
	}
	if !strings.Contains(err.Error(), "JWKS URL is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_MissingIssuer(t *testing.T) {
	_, err := NewJWTTokenValidator("https://jwks.example.com", "", "my-api", nil, 0, nil, "test")
	if err == nil {
		t.Error("expected error when issuer is missing")
	}
	if !strings.Contains(err.Error(), "issuer is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_MissingAudience(t *testing.T) {
	_, err := NewJWTTokenValidator("https://jwks.example.com", "https://auth.example.com", "", nil, 0, nil, "test")
	if err == nil {
		t.Error("expected error when audience is missing")
	}
	if !strings.Contains(err.Error(), "audience is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_WithLogger(t *testing.T) {
	client := stubJWKSClient(`{"keys":[]}`, http.StatusOK)
	logger := &mockLogger{}
	validator, err := NewJWTTokenValidator(
		testJWKSURL,
		"https://auth.example.com",
		"my-api",
		client,
		0,
		logger,
		"test",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validator.logger != logger {
		t.Error("expected logger to be set")
	}

	validator.Close()
}

func TestNewJWTTokenValidator_DefaultHTTPClient(t *testing.T) {
	prev := http.DefaultClient
	http.DefaultClient = stubJWKSClient(`{"keys":[]}`, http.StatusOK)
	defer func() { http.DefaultClient = prev }()

	// Pass nil HTTP client - should use default
	validator, err := NewJWTTokenValidator(testJWKSURL, "https://auth.example.com", "my-api", nil, 0, nil, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer validator.Close()

	if validator == nil {
		t.Error("expected validator to be created with default HTTP client")
	}
}

func TestNewJWTTokenValidator_DefaultCacheTTL(t *testing.T) {
	prev := http.DefaultClient
	http.DefaultClient = stubJWKSClient(`{"keys":[]}`, http.StatusOK)
	defer func() { http.DefaultClient = prev }()

	// Pass 0 cache TTL - should use default of 1 hour
	validator, err := NewJWTTokenValidator(testJWKSURL, "https://auth.example.com", "my-api", nil, 0, nil, "test")
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
	client := stubJWKSClient("server error", http.StatusInternalServerError)

	_, err := NewJWTTokenValidator(
		testJWKSURL,
		"https://auth.example.com",
		"my-api",
		client,
		0,
		nil,
		"test",
	)

	if err == nil {
		t.Error("expected error when JWKS URL returns error")
	}
	if !strings.Contains(err.Error(), "failed to initialize JWKS") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewJWTTokenValidator_CustomCacheTTL(t *testing.T) {
	client := stubJWKSClient(`{"keys":[]}`, http.StatusOK)

	validator, err := NewJWTTokenValidator(
		testJWKSURL,
		"https://auth.example.com",
		"my-api",
		client,
		30*time.Minute, // Custom cache TTL
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer validator.Close()

	if validator == nil {
		t.Error("expected validator to be created with custom cache TTL")
	}
}

func TestValidateToken_Success(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		WithEmail("user@example.com").
		WithScope("read write admin").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("expected subject 'user123', got '%s'", claims.Subject)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got '%s'", claims.Email)
	}
	if claims.Issuer != setup.Issuer {
		t.Errorf("expected issuer '%s', got '%s'", setup.Issuer, claims.Issuer)
	}
	if len(claims.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(claims.Scopes))
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != setup.Audience {
		t.Errorf("expected audience '%s', got '%v'", setup.Audience, claims.Audience)
	}
}

func TestValidateToken_SuccessWithLogger(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)
	logger := &mockLogger{}

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		logger,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.CreateValidToken(t, setup, "user123")

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	// Check that logger was called
	messages := logger.getMessages()
	if len(messages) == 0 {
		t.Error("expected logger to be called on successful validation")
	}

	foundValidationLog := false
	for _, msg := range messages {
		if strings.Contains(msg, "validated token for subject") {
			foundValidationLog = true
			break
		}
	}
	if !foundValidationLog {
		t.Error("expected validation log message")
	}
}

func TestValidateToken_SuccessWithoutEmail(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Token without email claim
	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if claims.Email != "" {
		t.Errorf("expected empty email, got '%s'", claims.Email)
	}
}

func TestValidateToken_SuccessWithMultipleAudiences(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Token with multiple audiences including the expected one
	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		WithAudience([]string{"other-api", setup.Audience, "another-api"}).
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("expected subject 'user123', got '%s'", claims.Subject)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	client := stubJWKSClient(`{"keys":[]}`, http.StatusOK)

	validator, _ := NewJWTTokenValidator(testJWKSURL, "https://auth.example.com", "my-api", client, 0, nil, "test")
	defer validator.Close()

	ctx := context.Background()
	_, err := validator.ValidateToken(ctx, "invalid-token")
	if err == nil {
		t.Error("expected error when token is invalid")
	}
	if !strings.Contains(err.Error(), "token validation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	client := stubJWKSClient(`{"keys":[]}`, http.StatusOK)

	validator, _ := NewJWTTokenValidator(testJWKSURL, "https://auth.example.com", "my-api", client, 0, nil, "test")
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

func TestValidateToken_ExpiredToken(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.CreateExpiredToken(t, setup, "user123")

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "token validation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_WrongIssuer(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.CreateTokenWithWrongIssuer(t, setup, "user123")

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
	if !strings.Contains(err.Error(), "invalid issuer") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_WrongAudience(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.CreateTokenWithWrongAudience(t, setup, "user123")

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for wrong audience")
	}
	if !strings.Contains(err.Error(), "invalid audience") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_EmptySubject(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for empty subject")
	}
	if !strings.Contains(err.Error(), "invalid subject") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_MissingExpiry(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.CreateTokenWithoutExpiry(t, setup, "user123")

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for missing expiry")
	}
	if !strings.Contains(err.Error(), "invalid expiry") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_MissingIssuedAt(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.CreateTokenWithoutIssuedAt(t, setup, "user123")

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for missing issued at")
	}
	if !strings.Contains(err.Error(), "invalid issued at") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_MissingSubject(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "temp").
		WithoutClaim("sub").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for missing subject")
	}
}

func TestValidateToken_MissingAudience(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		WithoutClaim("aud").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for missing audience")
	}
	if !strings.Contains(err.Error(), "invalid audience") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateToken_WrongSigningKey(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Generate a different key pair and sign with it
	differentKeyPair := testutil.GenerateTestKeyPair(t)
	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		SignToken(t, differentKeyPair.PrivateKey)

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Error("expected error for wrong signing key")
	}
	if !strings.Contains(err.Error(), "token validation failed") {
		t.Errorf("unexpected error message: %v", err)
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
		{
			name:   "scope array with non-string values",
			claims: jwt.MapClaims{"scope": []interface{}{"read", 123, "write", nil}},
			want:   []string{"read", "write"},
		},
		{
			name:   "scp array with non-string values",
			claims: jwt.MapClaims{"scp": []interface{}{"read", 456, "write"}},
			want:   []string{"read", "write"},
		},
		{
			name:   "scope as non-string non-array",
			claims: jwt.MapClaims{"scope": 12345},
			want:   []string{},
		},
		{
			name:   "scp as non-string non-array",
			claims: jwt.MapClaims{"scp": 12345},
			want:   []string{},
		},
		{
			name:   "empty scope array",
			claims: jwt.MapClaims{"scope": []interface{}{}},
			want:   []string{},
		},
		{
			name:   "empty scp array",
			claims: jwt.MapClaims{"scp": []interface{}{}},
			want:   []string{},
		},
		{
			name:   "single scope",
			claims: jwt.MapClaims{"scope": "admin"},
			want:   []string{"admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractScopes(tt.claims)
			if len(got) != len(tt.want) {
				t.Errorf("ExtractScopes() got %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ExtractScopes() got %v, want %v", got, tt.want)
					return
				}
			}
		})
	}
}

func TestJWTTokenValidator_Close(t *testing.T) {
	client := stubJWKSClient(`{"keys":[]}`, http.StatusOK)

	validator, err := NewJWTTokenValidator(testJWKSURL, "https://auth.example.com", "my-api", client, 0, nil, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic
	validator.Close()

	// Calling Close again should also not panic
	validator.Close()
}

func TestJWTTokenValidator_CloseWithNilJWKS(t *testing.T) {
	// Create a validator and manually set jwks to nil to test nil safety
	validator := &JWTTokenValidator{
		jwks:     nil,
		issuer:   "test",
		audience: "test",
	}

	// Should not panic
	validator.Close()
}

func TestTokenClaims_Fields(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	now := time.Now()
	expiry := now.Add(time.Hour)

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user456").
		WithEmail("test@example.com").
		WithScope("read write").
		WithExpiry(expiry).
		WithIssuedAt(now).
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	// Verify all fields are populated
	if claims.Subject != "user456" {
		t.Errorf("Subject: expected 'user456', got '%s'", claims.Subject)
	}
	if claims.Issuer != setup.Issuer {
		t.Errorf("Issuer: expected '%s', got '%s'", setup.Issuer, claims.Issuer)
	}
	if len(claims.Audience) == 0 {
		t.Error("Audience: expected non-empty slice")
	}
	if claims.Email != "test@example.com" {
		t.Errorf("Email: expected 'test@example.com', got '%s'", claims.Email)
	}
	if len(claims.Scopes) != 2 {
		t.Errorf("Scopes: expected 2 scopes, got %d", len(claims.Scopes))
	}
	if claims.Expiry.IsZero() {
		t.Error("Expiry: expected non-zero time")
	}
	if claims.IssuedAt.IsZero() {
		t.Error("IssuedAt: expected non-zero time")
	}
}

func TestValidateToken_WithScopesArray(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		WithScopeArray([]string{"read", "write", "delete"}).
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if len(claims.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d: %v", len(claims.Scopes), claims.Scopes)
	}
}

func TestValidateToken_WithScpClaim(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		WithScp("api:read api:write").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if len(claims.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d: %v", len(claims.Scopes), claims.Scopes)
	}
}

func TestValidateToken_NoScopes(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Token without any scope claims
	tokenString := testutil.NewJWTClaims(setup.Issuer, setup.Audience, "user123").
		SignToken(t, setup.KeyPair.PrivateKey)

	ctx := context.Background()
	claims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if len(claims.Scopes) != 0 {
		t.Errorf("expected 0 scopes, got %d: %v", len(claims.Scopes), claims.Scopes)
	}
}

func TestValidateToken_SingleStringAudience(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		nil,
		0,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create token with single string audience instead of array
	claims := jwt.MapClaims{
		"iss": setup.Issuer,
		"aud": setup.Audience, // Single string, not array
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}

	tokenString := testutil.CreateSignedToken(t, setup.KeyPair.PrivateKey, claims)

	ctx := context.Background()
	tokenClaims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if tokenClaims.Subject != "user123" {
		t.Errorf("expected subject 'user123', got '%s'", tokenClaims.Subject)
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		slice  []string
		value  string
		expect bool
	}{
		{
			name:   "value present",
			slice:  []string{"a", "b", "c"},
			value:  "b",
			expect: true,
		},
		{
			name:   "value not present",
			slice:  []string{"a", "b", "c"},
			value:  "d",
			expect: false,
		},
		{
			name:   "empty slice",
			slice:  []string{},
			value:  "a",
			expect: false,
		},
		{
			name:   "empty value in non-empty slice",
			slice:  []string{"a", "", "c"},
			value:  "",
			expect: true,
		},
		{
			name:   "single element match",
			slice:  []string{"only"},
			value:  "only",
			expect: true,
		},
		{
			name:   "single element no match",
			slice:  []string{"only"},
			value:  "other",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.slice, tt.value)
			if got != tt.expect {
				t.Errorf("contains(%v, %q) = %v, want %v", tt.slice, tt.value, got, tt.expect)
			}
		})
	}
}

func TestValidateToken_MalformedClaims(t *testing.T) {
	setup := testutil.NewJWTTestSetup(t)

	validator, err := NewJWTTokenValidator(
		setup.JWKSServer.URL,
		setup.Issuer,
		setup.Audience,
		http.DefaultClient,
		time.Hour,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	t.Run("invalid audience claim type", func(t *testing.T) {
		// Create token with numeric audience (invalid type)
		claims := jwt.MapClaims{
			"iss": setup.Issuer,
			"aud": 12345, // Invalid type - should be string or []string
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Add(-time.Minute).Unix(),
		}

		tokenString := testutil.CreateSignedToken(t, setup.KeyPair.PrivateKey, claims)

		ctx := context.Background()
		_, err := validator.ValidateToken(ctx, tokenString)
		if err == nil {
			t.Error("expected error for invalid audience claim type, got nil")
		}
		if !strings.Contains(err.Error(), "audience") {
			t.Errorf("expected audience error, got: %v", err)
		}
	})

	t.Run("invalid subject claim type", func(t *testing.T) {
		// Create token with numeric subject (invalid type)
		claims := jwt.MapClaims{
			"iss": setup.Issuer,
			"aud": setup.Audience,
			"sub": 12345, // Invalid type - should be string
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Add(-time.Minute).Unix(),
		}

		tokenString := testutil.CreateSignedToken(t, setup.KeyPair.PrivateKey, claims)

		ctx := context.Background()
		_, err := validator.ValidateToken(ctx, tokenString)
		if err == nil {
			t.Error("expected error for invalid subject claim type, got nil")
		}
		if !strings.Contains(err.Error(), "subject") {
			t.Errorf("expected subject error, got: %v", err)
		}
	})

	t.Run("invalid expiry claim type", func(t *testing.T) {
		// Create token with string expiry (invalid type)
		claims := jwt.MapClaims{
			"iss": setup.Issuer,
			"aud": setup.Audience,
			"sub": "user123",
			"exp": "not-a-timestamp", // Invalid type - should be number
			"iat": time.Now().Add(-time.Minute).Unix(),
		}

		tokenString := testutil.CreateSignedToken(t, setup.KeyPair.PrivateKey, claims)

		ctx := context.Background()
		_, err := validator.ValidateToken(ctx, tokenString)
		if err == nil {
			t.Error("expected error for invalid expiry claim type, got nil")
		}
		// JWT library returns "token validation failed" or "invalid type for claim: exp"
		if !strings.Contains(err.Error(), "token validation failed") && !strings.Contains(err.Error(), "exp") {
			t.Errorf("expected validation error for invalid expiry, got: %v", err)
		}
	})

	t.Run("invalid issued at claim type", func(t *testing.T) {
		// Create token with string iat (invalid type)
		claims := jwt.MapClaims{
			"iss": setup.Issuer,
			"aud": setup.Audience,
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": "not-a-timestamp", // Invalid type - should be number
		}

		tokenString := testutil.CreateSignedToken(t, setup.KeyPair.PrivateKey, claims)

		ctx := context.Background()
		_, err := validator.ValidateToken(ctx, tokenString)
		if err == nil {
			t.Error("expected error for invalid iat claim type, got nil")
		}
		if !strings.Contains(err.Error(), "issued at") {
			t.Errorf("expected issued at error, got: %v", err)
		}
	})
}

func TestJWTTokenValidator_ImplementsTokenValidator(t *testing.T) {
	// Compile-time check that JWTTokenValidator implements TokenValidator
	var _ TokenValidator = (*JWTTokenValidator)(nil)
}
