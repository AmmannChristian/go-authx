package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_AuthorizationPolicyIntegration_Allow(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return &TokenClaims{
				Subject: "user-1",
				Scopes:  []string{"read"},
				RawClaims: map[string]any{
					"roles": []any{"admin"},
				},
			}, nil
		},
	}

	handler := Middleware(validator,
		WithAuthorizationPolicy(AuthorizationPolicy{
			RequiredRoles: []string{"admin"},
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_AuthorizationPolicyIntegration_Deny(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return &TokenClaims{
				Subject: "user-1",
				Scopes:  []string{"read"},
				RawClaims: map[string]any{
					"roles": []any{"viewer"},
				},
			}, nil
		},
	}

	handler := Middleware(validator,
		WithAuthorizationPolicy(AuthorizationPolicy{
			RequiredRoles: []string{"admin"},
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestMiddleware_AuthorizationPolicyIntegration_ExemptPath(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("validator should not be called for exempt path")
		},
	}

	handler := Middleware(validator,
		WithExemptPaths("/health"),
		WithAuthorizationPolicy(AuthorizationPolicy{
			RequiredRoles: []string{"admin"},
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for exempt path, got %d", rr.Code)
	}
}
