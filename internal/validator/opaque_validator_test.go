package validator

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/internal/testutil"
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
