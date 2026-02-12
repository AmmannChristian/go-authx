package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/internal/testutil"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewOpaqueTokenValidator_Success(t *testing.T) {
	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected validator to be created")
	}
}

func TestNewOpaqueTokenValidator_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		issuer       string
		audience     string
		clientID     string
		clientSecret string
		wantErr      string
	}{
		{
			name:         "missing introspection URL",
			issuer:       "https://auth.example.com",
			audience:     "my-api",
			clientID:     "id",
			clientSecret: "secret",
			wantErr:      "introspection URL is required",
		},
		{
			name:         "missing issuer",
			url:          "https://auth.example.com/introspect",
			audience:     "my-api",
			clientID:     "id",
			clientSecret: "secret",
			wantErr:      "issuer is required",
		},
		{
			name:         "missing audience",
			url:          "https://auth.example.com/introspect",
			issuer:       "https://auth.example.com",
			clientID:     "id",
			clientSecret: "secret",
			wantErr:      "audience is required",
		},
		{
			name:         "missing client ID",
			url:          "https://auth.example.com/introspect",
			issuer:       "https://auth.example.com",
			audience:     "my-api",
			clientSecret: "secret",
			wantErr:      "introspection client ID is required",
		},
		{
			name:     "missing client secret",
			url:      "https://auth.example.com/introspect",
			issuer:   "https://auth.example.com",
			audience: "my-api",
			clientID: "id",
			wantErr:  "introspection client secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOpaqueTokenValidator(tt.url, tt.issuer, tt.audience, tt.clientID, tt.clientSecret, nil, nil)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewOpaqueTokenValidator_InvalidIntrospectionURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "invalid URL syntax",
			url:     "://invalid",
			wantErr: "invalid introspection URL",
		},
		{
			name:    "relative URL",
			url:     "/oauth2/introspect",
			wantErr: "must be absolute",
		},
		{
			name:    "non-https URL",
			url:     "http://auth.example.com/oauth2/introspect",
			wantErr: "must use https",
		},
		{
			name:    "URL with userinfo",
			url:     "https://user:pass@auth.example.com/oauth2/introspect",
			wantErr: "must not include user info",
		},
		{
			name:    "URL with query",
			url:     "https://auth.example.com/oauth2/introspect?x=1",
			wantErr: "must not include query or fragment",
		},
		{
			name:    "private IP",
			url:     "https://127.0.0.1/oauth2/introspect",
			wantErr: "must not use local or private IP addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOpaqueTokenValidator(
				tt.url,
				"https://auth.example.com",
				"my-api",
				"client-id",
				"client-secret",
				nil,
				nil,
			)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestOpaqueTokenValidator_ValidateToken_Success(t *testing.T) {
	now := time.Now().UTC()

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			if r.URL.String() != "https://auth.example.com/oauth2/introspect" {
				t.Fatalf("unexpected URL: %s", r.URL.String())
			}

			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id:client-secret"))
			if authHeader != expectedAuth {
				t.Fatalf("unexpected Authorization header: %s", authHeader)
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			body := string(bodyBytes)
			if !strings.Contains(body, "token=opaque-token") {
				t.Fatalf("expected token in request body, got %s", body)
			}

			responseBody := `{
				"active": true,
				"iss": "https://auth.example.com",
				"aud": ["my-api"],
				"sub": "user-123",
				"scope": "read write",
				"email": "user@example.com",
				"exp": ` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `,
				"iat": ` + strconv.FormatInt(now.Unix(), 10) + `
			}`

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(responseBody)),
				Request:    r,
			}, nil
		}),
	}

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	claims, err := v.ValidateToken(context.Background(), "opaque-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Fatalf("expected subject user-123, got %s", claims.Subject)
	}
	if claims.Issuer != "https://auth.example.com" {
		t.Fatalf("unexpected issuer: %s", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "my-api" {
		t.Fatalf("unexpected audience: %v", claims.Audience)
	}
	if len(claims.Scopes) != 2 {
		t.Fatalf("unexpected scopes: %v", claims.Scopes)
	}
	if claims.Email != "user@example.com" {
		t.Fatalf("unexpected email: %s", claims.Email)
	}
	if claims.Expiry.IsZero() {
		t.Fatal("expected non-zero expiry")
	}
}

func TestOpaqueTokenValidator_ValidateToken_SuccessWithLogger(t *testing.T) {
	now := time.Now().UTC()
	logger := &mockLogger{}

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"active": true,
					"iss": "https://auth.example.com",
					"aud": ["my-api"],
					"sub": "user-logger",
					"scope": "read write",
					"exp": ` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `,
					"iat": ` + strconv.FormatInt(now.Unix(), 10) + `
				}`)),
				Request: r,
			}, nil
		}),
	}

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		logger,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, msg := range logger.getMessages() {
		if strings.Contains(msg, "introspected opaque token for subject user-logger") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected introspection success log, got %v", logger.getMessages())
	}
}

func TestOpaqueTokenValidator_ValidateToken_Inactive(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"active": false}`)),
				Request:    r,
			}, nil
		}),
	}

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = v.ValidateToken(context.Background(), "opaque-token")
	if err == nil {
		t.Fatal("expected error for inactive token")
	}
	if !strings.Contains(err.Error(), "opaque token is inactive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_InvalidIssuer(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"active": true, "iss": "https://other.example.com", "sub": "user", "aud": ["my-api"]}`)),
				Request:    r,
			}, nil
		}),
	}

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = v.ValidateToken(context.Background(), "opaque-token")
	if err == nil {
		t.Fatal("expected error for invalid issuer")
	}
	if !strings.Contains(err.Error(), "invalid issuer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_InvalidAudience(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"active": true, "iss": "https://auth.example.com", "sub": "user", "aud": ["other-api"]}`)),
				Request:    r,
			}, nil
		}),
	}

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = v.ValidateToken(context.Background(), "opaque-token")
	if err == nil {
		t.Fatal("expected error for invalid audience")
	}
	if !strings.Contains(err.Error(), "invalid audience") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_Expired(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			responseBody := `{
				"active": true,
				"iss": "https://auth.example.com",
				"aud": ["my-api"],
				"sub": "user-123",
				"exp": ` + strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10) + `
			}`

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(responseBody)),
				Request:    r,
			}, nil
		}),
	}

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = v.ValidateToken(context.Background(), "opaque-token")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "opaque token has expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_EmptyToken(t *testing.T) {
	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = v.ValidateToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !strings.Contains(err.Error(), "token is empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewOpaqueTokenValidatorWithAuth_DefaultMethodClientSecretBasic(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id:client-secret"))
			if authHeader != expectedAuth {
				t.Fatalf("unexpected Authorization header: %s", authHeader)
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			values, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				t.Fatalf("failed to parse request body: %v", err)
			}
			if values.Get("client_assertion") != "" {
				t.Fatal("did not expect client_assertion for basic auth")
			}
			if values.Get("client_assertion_type") != "" {
				t.Fatal("did not expect client_assertion_type for basic auth")
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

	v, err := NewOpaqueTokenValidatorWithAuth(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		IntrospectionClientAuthConfig{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_PrivateKeyJWTRequestAndClaims(t *testing.T) {
	privateKey := mustGenerateRSAKey(t)
	privateKeyPEM := mustEncodePKCS8PrivateKeyPEM(t, privateKey)
	jtis := make([]string, 0, 2)
	now := time.Now().UTC()

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				t.Fatalf("expected no Authorization header for private_key_jwt, got %q", authHeader)
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			values, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				t.Fatalf("failed to parse form body: %v", err)
			}
			if values.Get("token") != "opaque-token" {
				t.Fatalf("unexpected token value: %q", values.Get("token"))
			}
			if values.Get("token_type_hint") != "access_token" {
				t.Fatalf("unexpected token_type_hint: %q", values.Get("token_type_hint"))
			}
			if values.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
				t.Fatalf("unexpected client_assertion_type: %q", values.Get("client_assertion_type"))
			}

			assertion := values.Get("client_assertion")
			if assertion == "" {
				t.Fatal("client_assertion must be set")
			}

			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(
				assertion,
				claims,
				func(parsedToken *jwt.Token) (any, error) {
					return &privateKey.PublicKey, nil
				},
				jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			)
			if err != nil {
				t.Fatalf("failed to parse assertion JWT: %v", err)
			}
			if !token.Valid {
				t.Fatal("expected assertion JWT to be valid")
			}

			if token.Header["kid"] != "kid-1" {
				t.Fatalf("unexpected kid header: %v", token.Header["kid"])
			}
			if claims.Issuer != "client-id" {
				t.Fatalf("unexpected assertion iss: %q", claims.Issuer)
			}
			if claims.Subject != "client-id" {
				t.Fatalf("unexpected assertion sub: %q", claims.Subject)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != "https://auth.example.com/oauth2/introspect" {
				t.Fatalf("unexpected assertion aud: %v", claims.Audience)
			}
			if claims.IssuedAt == nil || claims.ExpiresAt == nil {
				t.Fatal("expected iat and exp claims")
			}
			lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
			if lifetime > time.Minute {
				t.Fatalf("unexpected assertion lifetime: %s", lifetime)
			}
			if claims.IssuedAt.Time.Before(now.Add(-10*time.Second)) || claims.IssuedAt.Time.After(time.Now().UTC().Add(10*time.Second)) {
				t.Fatalf("unexpected iat value: %s", claims.IssuedAt.Time)
			}
			if claims.ID == "" {
				t.Fatal("expected jti claim to be set")
			}
			jtis = append(jtis, claims.ID)

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

	v, err := NewOpaqueTokenValidatorWithAuth(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		IntrospectionClientAuthConfig{
			Method:                 IntrospectionClientAuthMethodPrivateKeyJWT,
			ClientID:               "client-id",
			PrivateKey:             privateKeyPEM,
			PrivateKeyJWTKeyID:     "kid-1",
			PrivateKeyJWTAlgorithm: "",
		},
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected error on first validation: %v", err)
	}
	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected error on second validation: %v", err)
	}
	if len(jtis) != 2 {
		t.Fatalf("expected 2 jti values, got %d", len(jtis))
	}
	if jtis[0] == jtis[1] {
		t.Fatal("expected unique jti per request")
	}
}

func TestOpaqueTokenValidator_ValidateToken_PrivateKeyJWT_ES256(t *testing.T) {
	privateKey := mustGenerateECKey(t)
	privateKeyPEM := mustEncodePKCS8PrivateKeyPEM(t, privateKey)

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			values, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				t.Fatalf("failed to parse form body: %v", err)
			}

			assertion := values.Get("client_assertion")
			if assertion == "" {
				t.Fatal("expected client_assertion for private_key_jwt")
			}

			token, err := jwt.Parse(
				assertion,
				func(parsedToken *jwt.Token) (any, error) {
					return &privateKey.PublicKey, nil
				},
				jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
			)
			if err != nil {
				t.Fatalf("failed to verify client_assertion: %v", err)
			}
			if !token.Valid {
				t.Fatal("expected assertion token to be valid")
			}
			if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
				t.Fatalf("unexpected signing method: %s", token.Method.Alg())
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

	v, err := NewOpaqueTokenValidatorWithAuth(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		IntrospectionClientAuthConfig{
			Method:                 IntrospectionClientAuthMethodPrivateKeyJWT,
			ClientID:               "client-id",
			PrivateKey:             privateKeyPEM,
			PrivateKeyJWTAlgorithm: IntrospectionPrivateKeyJWTAlgorithmES256,
		},
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestParsePrivateKeyJWK_EC_Success(t *testing.T) {
	privateKey := mustGenerateECKey(t)
	jwk := mustEncodeECKeyAsJWK(t, privateKey, "ec-kid", "ES256")

	parsedPrivateKey, keyID, algorithm, err := parsePrivateKeyJWK(jwk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecPrivateKey, ok := parsedPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsedPrivateKey)
	}
	if ecPrivateKey.Curve != elliptic.P256() {
		t.Fatalf("unexpected curve: %v", ecPrivateKey.Curve)
	}
	if keyID != "ec-kid" {
		t.Fatalf("unexpected keyID: %q", keyID)
	}
	if algorithm != "ES256" {
		t.Fatalf("unexpected algorithm: %q", algorithm)
	}
}

func TestParsePrivateKeyJWK_EC_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jwk     string
		wantErr string
	}{
		{
			name:    "unsupported curve",
			jwk:     `{"kty":"EC","kid":"k","crv":"P-384","d":"AQ"}`,
			wantErr: "unsupported introspection EC JWK curve",
		},
		{
			name:    "missing d",
			jwk:     `{"kty":"EC","kid":"k","crv":"P-256"}`,
			wantErr: "invalid d in introspection JWK",
		},
		{
			name:    "mismatched x/y",
			jwk:     `{"kty":"EC","kid":"k","crv":"P-256","d":"AQ","x":"AQ","y":"AQ"}`,
			wantErr: "x/y do not match private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parsePrivateKeyJWK(tt.jwk)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParsePrivateKeyJWK_RSA_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jwk     string
		wantErr string
	}{
		{
			name:    "unsupported kty",
			jwk:     `{"kty":"oct"}`,
			wantErr: "unsupported introspection JWK key type",
		},
		{
			name:    "invalid json",
			jwk:     `{"kty":`,
			wantErr: "invalid introspection private JWK",
		},
		{
			name:    "missing p and q",
			jwk:     `{"kty":"RSA","n":"AQ","e":"Aw","d":"AQ"}`,
			wantErr: "requires p and q",
		},
		{
			name:    "invalid exponent",
			jwk:     `{"kty":"RSA","n":"AQ","e":"Ag","d":"AQ","p":"AQ","q":"AQ"}`,
			wantErr: "exponent must be >= 3",
		},
		{
			name:    "invalid p",
			jwk:     `{"kty":"RSA","n":"AQ","e":"Aw","d":"AQ","p":"%%%","q":"AQ"}`,
			wantErr: "invalid p in introspection JWK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parsePrivateKeyJWK(tt.jwk)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParseIntrospectionPrivateKeyJSON_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "invalid json",
			input:   `{"key":`,
			wantErr: "invalid introspection private key JSON",
		},
		{
			name:    "unknown json shape",
			input:   `{"foo":"bar"}`,
			wantErr: "expected JWK or Zitadel key JSON",
		},
		{
			name:    "zitadel without key",
			input:   `{"keyId":"1","clientId":"2","key":""}`,
			wantErr: "key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := parseIntrospectionPrivateKey(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParsePrivateKeyPEM_UnsupportedKeyType(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal ed25519 key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	_, err = parsePrivateKeyPEM(string(privateKeyPEM))
	if err == nil {
		t.Fatal("expected error for unsupported private key type")
	}
	if !strings.Contains(err.Error(), "unsupported introspection private key type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePrivateKeyPEM_PKCS8RSA(t *testing.T) {
	privateKey := mustGenerateRSAKey(t)
	privateKeyPEM := mustEncodePKCS8PrivateKeyPEM(t, privateKey)

	parsed, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsedRSA, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if parsedRSA.N.Cmp(privateKey.N) != 0 {
		t.Fatal("parsed RSA key does not match original key")
	}
}

func TestParsePrivateKeyPEM_PKCS8EC(t *testing.T) {
	privateKey := mustGenerateECKey(t)
	privateKeyPEM := mustEncodePKCS8PrivateKeyPEM(t, privateKey)

	parsed, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsedEC, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if parsedEC.D.Cmp(privateKey.D) != 0 {
		t.Fatal("parsed EC key does not match original key")
	}
}

func TestParseUnixTimeClaim_CoversTypes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	unixSeconds := now.Unix()

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{name: "float64", value: float64(unixSeconds)},
		{name: "int64", value: unixSeconds},
		{name: "int", value: int(unixSeconds)},
		{name: "json number", value: json.Number(strconv.FormatInt(unixSeconds, 10))},
		{name: "string", value: strconv.FormatInt(unixSeconds, 10)},
		{name: "invalid string", value: "nope", wantErr: true},
		{name: "invalid type", value: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedTime, err := parseUnixTimeClaim(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsedTime.Unix() != unixSeconds {
				t.Fatalf("unexpected unix time: %d", parsedTime.Unix())
			}
		})
	}
}

func TestExtractAudience_CoversTypes(t *testing.T) {
	audFromString := extractAudience("api")
	if len(audFromString) != 1 || audFromString[0] != "api" {
		t.Fatalf("unexpected audience from string: %v", audFromString)
	}

	audFromInterfaces := extractAudience([]interface{}{"api", "api-2", 5})
	if len(audFromInterfaces) != 2 || audFromInterfaces[0] != "api" || audFromInterfaces[1] != "api-2" {
		t.Fatalf("unexpected audience from []interface{}: %v", audFromInterfaces)
	}

	audFromStrings := extractAudience([]string{"x", "y"})
	if len(audFromStrings) != 2 || audFromStrings[0] != "x" || audFromStrings[1] != "y" {
		t.Fatalf("unexpected audience from []string: %v", audFromStrings)
	}

	audFromUnknown := extractAudience(map[string]string{"aud": "api"})
	if len(audFromUnknown) != 0 {
		t.Fatalf("expected empty audience, got %v", audFromUnknown)
	}
}

func TestDecodeJWKBase64URL_Errors(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "empty", value: "", wantErr: "empty"},
		{name: "invalid base64url", value: "%%%not-base64%%%", wantErr: "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeJWKBase64URL("x", tt.value)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestDecodeJWKBigInt_ZeroValue(t *testing.T) {
	_, err := decodeJWKBigInt("n", "AA")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "value must be > 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInferPrivateKeyJWTAlgorithm_UnsupportedKeyType(t *testing.T) {
	algorithm, err := inferPrivateKeyJWTAlgorithm(struct{}{})
	if err == nil {
		t.Fatal("expected error")
	}
	if algorithm != "" {
		t.Fatalf("expected empty algorithm, got %q", algorithm)
	}
}

func TestValidatePrivateKeyJWTAlgorithm_ES256WrongCurve(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}

	err = validatePrivateKeyJWTAlgorithm(IntrospectionPrivateKeyJWTAlgorithmES256, privateKey)
	if err == nil {
		t.Fatal("expected error for wrong EC curve")
	}
	if !strings.Contains(err.Error(), "requires an EC P-256 private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewOpaqueTokenValidatorWithAuth_PrivateKeyJWTValidationErrors(t *testing.T) {
	ecKey := mustGenerateECKey(t)
	ecKeyPEM := mustEncodePKCS8PrivateKeyPEM(t, ecKey)

	tests := []struct {
		name      string
		auth      IntrospectionClientAuthConfig
		wantError string
	}{
		{
			name: "missing client id",
			auth: IntrospectionClientAuthConfig{
				Method:     IntrospectionClientAuthMethodPrivateKeyJWT,
				PrivateKey: ecKeyPEM,
			},
			wantError: "introspection client ID is required",
		},
		{
			name: "missing private key",
			auth: IntrospectionClientAuthConfig{
				Method:   IntrospectionClientAuthMethodPrivateKeyJWT,
				ClientID: "client-id",
			},
			wantError: "introspection private key is required",
		},
		{
			name: "invalid private key",
			auth: IntrospectionClientAuthConfig{
				Method:     IntrospectionClientAuthMethodPrivateKeyJWT,
				ClientID:   "client-id",
				PrivateKey: "not-a-key",
			},
			wantError: "invalid introspection private key",
		},
		{
			name: "algorithm key mismatch",
			auth: IntrospectionClientAuthConfig{
				Method:                 IntrospectionClientAuthMethodPrivateKeyJWT,
				ClientID:               "client-id",
				PrivateKey:             ecKeyPEM,
				PrivateKeyJWTAlgorithm: IntrospectionPrivateKeyJWTAlgorithmRS256,
			},
			wantError: "algorithm RS256 requires an RSA private key",
		},
		{
			name: "unsupported auth method",
			auth: IntrospectionClientAuthConfig{
				Method:   "something_else",
				ClientID: "client-id",
			},
			wantError: "unsupported introspection client auth method",
		},
		{
			name: "unsupported algorithm",
			auth: IntrospectionClientAuthConfig{
				Method:                 IntrospectionClientAuthMethodPrivateKeyJWT,
				ClientID:               "client-id",
				PrivateKey:             ecKeyPEM,
				PrivateKeyJWTAlgorithm: "RS512",
			},
			wantError: "unsupported introspection private_key_jwt algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOpaqueTokenValidatorWithAuth(
				"https://auth.example.com/oauth2/introspect",
				"https://auth.example.com",
				"my-api",
				tt.auth,
				nil,
				nil,
			)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected error containing %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestOpaqueTokenValidator_ValidateToken_IntrospectionFailures(t *testing.T) {
	tests := []struct {
		name       string
		roundTrip  testutil.RoundTripFunc
		wantErrMsg string
	}{
		{
			name: "http status failure",
			roundTrip: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"error":"server_error"}`)),
					Request:    r,
				}, nil
			},
			wantErrMsg: "introspection endpoint returned status",
		},
		{
			name: "invalid json response",
			roundTrip: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("{not-json")),
					Request:    r,
				}, nil
			},
			wantErrMsg: "invalid introspection response",
		},
		{
			name: "body read error",
			roundTrip: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       failingReadCloser{},
					Request:    r,
				}, nil
			},
			wantErrMsg: "failed to read introspection response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewOpaqueTokenValidator(
				"https://auth.example.com/oauth2/introspect",
				"https://auth.example.com",
				"my-api",
				"client-id",
				"client-secret",
				&http.Client{Transport: tt.roundTrip},
				nil,
			)
			if err != nil {
				t.Fatalf("failed to create validator: %v", err)
			}

			_, err = v.ValidateToken(context.Background(), "opaque-token")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErrMsg, err)
			}
		})
	}
}

func TestOpaqueTokenValidator_ValidateToken_NilContext(t *testing.T) {
	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
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

	v, err := NewOpaqueTokenValidator(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		"client-id",
		"client-secret",
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	var nilCtx context.Context

	claims, err := v.ValidateToken(nilCtx, "opaque-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
}

func TestOpaqueTokenValidator_NewIntrospectionRequest_UnsupportedMethod(t *testing.T) {
	v := &OpaqueTokenValidator{
		introspectionURL: "https://auth.example.com/oauth2/introspect",
		authConfig: IntrospectionClientAuthConfig{
			Method: "unsupported",
		},
	}

	_, err := v.newIntrospectionRequest(context.Background(), "opaque-token")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported introspection client auth method") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildPrivateKeyJWTClientAssertion_UnsupportedSigningMethod(t *testing.T) {
	privateKey := mustGenerateRSAKey(t)

	v := &OpaqueTokenValidator{
		introspectionURL: "https://auth.example.com/oauth2/introspect",
		authConfig: IntrospectionClientAuthConfig{
			ClientID:               "client-id",
			PrivateKeyJWTAlgorithm: "invalid-alg",
		},
		privateKey: privateKey,
	}

	_, err := v.buildPrivateKeyJWTClientAssertion()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported introspection private_key_jwt algorithm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_PrivateKeyJWTWithJWK(t *testing.T) {
	privateKey := mustGenerateRSAKey(t)
	privateKeyJWK := mustEncodeRSAKeyAsJWK(t, privateKey, "kid-jwk", "RS256")

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			values, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				t.Fatalf("failed to parse form body: %v", err)
			}
			assertion := values.Get("client_assertion")
			if assertion == "" {
				t.Fatal("expected client_assertion for private_key_jwt")
			}

			token, err := jwt.Parse(
				assertion,
				func(parsedToken *jwt.Token) (any, error) {
					return &privateKey.PublicKey, nil
				},
				jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			)
			if err != nil {
				t.Fatalf("failed to verify client_assertion: %v", err)
			}
			if !token.Valid {
				t.Fatal("expected assertion token to be valid")
			}
			if token.Header["kid"] != "kid-jwk" {
				t.Fatalf("unexpected kid: %v", token.Header["kid"])
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

	v, err := NewOpaqueTokenValidatorWithAuth(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		IntrospectionClientAuthConfig{
			Method:     IntrospectionClientAuthMethodPrivateKeyJWT,
			ClientID:   "client-id",
			PrivateKey: privateKeyJWK,
		},
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestOpaqueTokenValidator_ValidateToken_PrivateKeyJWTWithZitadelJSON(t *testing.T) {
	privateKey := mustGenerateRSAKey(t)
	privateKeyPEM := mustEncodeRSAKeyPEM(t, privateKey)
	zitadelKeyJSON := mustEncodeZitadelPrivateKeyEnvelope(
		t,
		privateKeyPEM,
		"359593541808160778",
		"359593526608003082",
	)

	client := &http.Client{
		Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			values, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				t.Fatalf("failed to parse form body: %v", err)
			}
			assertion := values.Get("client_assertion")
			if assertion == "" {
				t.Fatal("expected client_assertion for private_key_jwt")
			}

			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(
				assertion,
				claims,
				func(parsedToken *jwt.Token) (any, error) {
					return &privateKey.PublicKey, nil
				},
				jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			)
			if err != nil {
				t.Fatalf("failed to verify client_assertion: %v", err)
			}
			if !token.Valid {
				t.Fatal("expected assertion token to be valid")
			}
			if token.Header["kid"] != "359593541808160778" {
				t.Fatalf("unexpected kid: %v", token.Header["kid"])
			}
			if claims.Issuer != "359593526608003082" {
				t.Fatalf("unexpected iss claim: %q", claims.Issuer)
			}
			if claims.Subject != "359593526608003082" {
				t.Fatalf("unexpected sub claim: %q", claims.Subject)
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

	v, err := NewOpaqueTokenValidatorWithAuth(
		"https://auth.example.com/oauth2/introspect",
		"https://auth.example.com",
		"my-api",
		IntrospectionClientAuthConfig{
			Method:     IntrospectionClientAuthMethodPrivateKeyJWT,
			PrivateKey: zitadelKeyJSON,
		},
		client,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if _, err := v.ValidateToken(context.Background(), "opaque-token"); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func mustGenerateRSAKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate RSA key: %v", err)
	}

	return privateKey
}

func mustGenerateECKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("failed to generate EC key: %v", err)
	}

	return privateKey
}

func mustEncodePKCS8PrivateKeyPEM(tb testing.TB, privateKey any) string {
	tb.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		tb.Fatalf("failed to marshal private key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

func mustEncodeRSAKeyAsJWK(tb testing.TB, privateKey *rsa.PrivateKey, keyID, algorithm string) string {
	tb.Helper()

	encodeBigInt := func(value *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(value.Bytes())
	}

	jwk := `{"kty":"RSA","kid":"` + keyID + `","alg":"` + algorithm + `","n":"` + encodeBigInt(privateKey.N) +
		`","e":"` + base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()) +
		`","d":"` + encodeBigInt(privateKey.D) +
		`","p":"` + encodeBigInt(privateKey.Primes[0]) +
		`","q":"` + encodeBigInt(privateKey.Primes[1]) + `"}`

	return jwk
}

func mustEncodeECKeyAsJWK(tb testing.TB, privateKey *ecdsa.PrivateKey, keyID, algorithm string) string {
	tb.Helper()

	encodeBigInt := func(value *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(value.Bytes())
	}

	jwk := `{"kty":"EC","kid":"` + keyID + `","alg":"` + algorithm + `","crv":"P-256","x":"` +
		encodeBigInt(privateKey.PublicKey.X) + `","y":"` + encodeBigInt(privateKey.PublicKey.Y) + `","d":"` +
		encodeBigInt(privateKey.D) + `"}`

	return jwk
}

func mustEncodeRSAKeyPEM(tb testing.TB, privateKey *rsa.PrivateKey) string {
	tb.Helper()

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}))
}

func mustEncodeZitadelPrivateKeyEnvelope(tb testing.TB, privateKeyPEM, keyID, clientID string) string {
	tb.Helper()

	payload := map[string]string{
		"type":     "application",
		"keyId":    keyID,
		"key":      privateKeyPEM,
		"appId":    "example-app-id",
		"clientId": clientID,
	}

	rawJSON, err := json.Marshal(payload)
	if err != nil {
		tb.Fatalf("failed to marshal zitadel envelope: %v", err)
	}

	return string(rawJSON)
}

type failingReadCloser struct{}

func (failingReadCloser) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (failingReadCloser) Close() error {
	return nil
}
