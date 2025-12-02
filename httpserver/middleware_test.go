package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockValidator implements TokenValidator for testing
type mockValidator struct {
	validateFunc func(ctx context.Context, token string) (*TokenClaims, error)
}

func (m *mockValidator) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return &TokenClaims{
		Subject:  "user123",
		Issuer:   "https://auth.example.com",
		Audience: []string{"my-api"},
		Expiry:   time.Now().Add(time.Hour),
		IssuedAt: time.Now(),
		Scopes:   []string{"read", "write"},
		Email:    "user@example.com",
	}, nil
}

func TestMiddleware_Success(t *testing.T) {
	validator := &mockValidator{}

	// Create a test handler that checks for claims in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := TokenClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims to be present in context")
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		if claims.Subject != "user123" {
			t.Errorf("expected subject user123, got %s", claims.Subject)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Wrap with middleware
	middleware := Middleware(validator)
	wrappedHandler := middleware(handler)

	// Create test request with Bearer token
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	// Execute request
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "success" {
		t.Errorf("expected body 'success', got %s", rr.Body.String())
	}
}

func TestMiddleware_MissingAuthHeader(t *testing.T) {
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when auth fails")
	})

	middleware := Middleware(validator)
	wrappedHandler := middleware(handler)

	// Create request without Authorization header
	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidAuthFormat(t *testing.T) {
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when auth fails")
	})

	middleware := Middleware(validator)
	wrappedHandler := middleware(handler)

	tests := []struct {
		name       string
		authHeader string
	}{
		{
			name:       "invalid format",
			authHeader: "invalid-format",
		},
		{
			name:       "Basic auth",
			authHeader: "Basic dXNlcjpwYXNz",
		},
		{
			name:       "Bearer without token",
			authHeader: "Bearer",
		},
		{
			name:       "Bearer with space only",
			authHeader: "Bearer ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/users", nil)
			req.Header.Set("Authorization", tt.authHeader)
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", rr.Code)
			}
		})
	}
}

func TestMiddleware_ValidationError(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when validation fails")
	})

	middleware := Middleware(validator)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

func TestMiddleware_ExemptPath(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt path")
			return nil, errors.New("should not be called")
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify claims are NOT in context for exempt path
		_, ok := TokenClaimsFromContext(r.Context())
		if ok {
			t.Error("expected no claims in context for exempt path")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator, WithExemptPaths("/health", "/metrics"))
	wrappedHandler := middleware(handler)

	// Test exempt paths
	exemptPaths := []string{"/health", "/metrics"}
	for _, path := range exemptPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			// No Authorization header
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200 for exempt path %s, got %d", path, rr.Code)
			}
		})
	}
}

func TestMiddleware_ExemptPathPrefix(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt path prefix")
			return nil, errors.New("should not be called")
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator, WithExemptPathPrefixes("/public/", "/static/"))
	wrappedHandler := middleware(handler)

	// Test paths matching exempt prefixes
	exemptPaths := []string{"/public/index.html", "/public/css/style.css", "/static/js/app.js"}
	for _, path := range exemptPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200 for exempt path %s, got %d", path, rr.Code)
			}
		})
	}
}

func TestMiddleware_NonExemptPath(t *testing.T) {
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator, WithExemptPaths("/health"))
	wrappedHandler := middleware(handler)

	// Request to non-exempt path without auth should fail
	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for non-exempt path, got %d", rr.Code)
	}
}

func TestMiddleware_WithLogger(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator, WithMiddlewareLogger(logger))
	wrappedHandler := middleware(handler)

	// Successful request
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	// Verify logger was called
	if len(logger.messages) == 0 {
		t.Error("expected logger to be called")
	}
}

func TestMiddleware_WithLogger_ExemptPath(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator,
		WithExemptPaths("/health"),
		WithMiddlewareLogger(logger),
	)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	// Verify logger was called with exempt path message
	if len(logger.messages) == 0 {
		t.Error("expected logger to log exempt path")
	}
	found := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "exempt") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected logger to log exempt path message")
	}
}

func TestMiddleware_WithLogger_AuthFailure(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	middleware := Middleware(validator, WithMiddlewareLogger(logger))
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	// Verify logger was called with auth failure
	if len(logger.messages) == 0 {
		t.Error("expected logger to log auth failure")
	}
	found := false
	for _, msg := range logger.messages {
		if strings.Contains(msg, "authentication failed") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected logger to log authentication failed message")
	}
}

func TestMiddleware_CustomTokenExtractor(t *testing.T) {
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Custom extractor that reads from X-API-Key header
	customExtractor := func(r *http.Request) (string, bool) {
		token := r.Header.Get("X-API-Key")
		if token == "" {
			return "", false
		}
		return token, true
	}

	middleware := Middleware(validator, WithTokenExtractor(customExtractor))
	wrappedHandler := middleware(handler)

	// Test with custom header
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("X-API-Key", "custom-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestMiddleware_CustomUnauthorizedHandler(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	customUnauthorizedCalled := false
	customHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		customUnauthorizedCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden) // Use 403 instead of 401
		w.Write([]byte(`{"error":"custom error"}`))
	}

	middleware := Middleware(validator, WithUnauthorizedHandler(customHandler))
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if !customUnauthorizedCalled {
		t.Error("expected custom unauthorized handler to be called")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type to be application/json")
	}
}

func TestMiddleware_MultipleExemptOptions(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (*TokenClaims, error) {
			t.Error("validator should not be called for exempt paths")
			return nil, errors.New("should not be called")
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Combine exact paths and prefixes
	middleware := Middleware(validator,
		WithExemptPaths("/health", "/metrics"),
		WithExemptPathPrefixes("/public/", "/static/"),
	)
	wrappedHandler := middleware(handler)

	testPaths := []string{
		"/health",
		"/metrics",
		"/public/index.html",
		"/static/css/style.css",
	}

	for _, path := range testPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200 for path %s, got %d", path, rr.Code)
			}
		})
	}
}

func TestIsExempt(t *testing.T) {
	config := &MiddlewareConfig{
		exemptPaths: map[string]bool{
			"/health":  true,
			"/metrics": true,
		},
		exemptPathPrefixes: []string{"/public/", "/static/"},
	}

	tests := []struct {
		path   string
		exempt bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/public/index.html", true},
		{"/static/css/style.css", true},
		{"/api/users", false},
		{"/healthcheck", false},    // Not exact match
		{"/pub/index.html", false}, // Prefix doesn't match
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isExempt(tt.path, config)
			if got != tt.exempt {
				t.Errorf("isExempt(%s) = %v, want %v", tt.path, got, tt.exempt)
			}
		})
	}
}

func TestMiddleware_ContextPropagation(t *testing.T) {
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify original context values are still present
		if val := r.Context().Value("test-key"); val != "test-value" {
			t.Error("expected original context values to be preserved")
		}

		// Verify claims were added
		claims, ok := TokenClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in context")
		}
		if claims.Subject != "user123" {
			t.Errorf("expected subject user123, got %s", claims.Subject)
		}

		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator)
	wrappedHandler := middleware(handler)

	// Create request with custom context value
	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), "test-key", "test-value")
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer valid-token")

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestMiddleware_DifferentHTTPMethods(t *testing.T) {
	validator := &mockValidator{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(validator)
	wrappedHandler := middleware(handler)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/users", nil)
			req.Header.Set("Authorization", "Bearer valid-token")
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200 for %s, got %d", method, rr.Code)
			}
		})
	}
}

func TestMiddleware_ChainedMiddleware(t *testing.T) {
	validator := &mockValidator{}

	// Create a chain of middleware
	loggerMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add a marker to context to verify chain order
			ctx := context.WithValue(r.Context(), "logged", true)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify both middleware ran
		if val := r.Context().Value("logged"); val != true {
			t.Error("expected logger middleware to run first")
		}
		if _, ok := TokenClaimsFromContext(r.Context()); !ok {
			t.Error("expected auth middleware to add claims")
		}
		w.WriteHeader(http.StatusOK)
	})

	// Chain: logger -> auth -> handler
	authMiddleware := Middleware(validator)
	wrappedHandler := loggerMiddleware(authMiddleware(handler))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}
