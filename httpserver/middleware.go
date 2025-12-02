package httpserver

import (
	"net/http"
	"strings"
)

// MiddlewareConfig holds configuration for authentication middleware.
type MiddlewareConfig struct {
	validator           TokenValidator
	exemptPaths         map[string]bool // Exact path matches
	exemptPathPrefixes  []string        // Prefix matches
	logger              Logger          // optional logger
	tokenExtractor      TokenExtractor  // custom token extraction logic (optional)
	unauthorizedHandler UnauthorizedHandler
}

// MiddlewareOption is a functional option for configuring middleware.
type MiddlewareOption func(*MiddlewareConfig)

// TokenExtractor is a function that extracts a token from an HTTP request.
// It returns the token string and a boolean indicating whether extraction succeeded.
type TokenExtractor func(r *http.Request) (string, bool)

// UnauthorizedHandler is a function that handles authentication failures.
// It allows custom error responses for unauthenticated requests.
type UnauthorizedHandler func(w http.ResponseWriter, r *http.Request, err error)

// WithExemptPaths specifies HTTP paths that don't require authentication.
// These paths must match exactly.
//
// Example:
//
//	WithExemptPaths("/health", "/metrics", "/favicon.ico")
func WithExemptPaths(paths ...string) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		if c.exemptPaths == nil {
			c.exemptPaths = make(map[string]bool)
		}
		for _, path := range paths {
			c.exemptPaths[path] = true
		}
	}
}

// WithExemptPathPrefixes specifies HTTP path prefixes that don't require authentication.
// Any path starting with these prefixes will be exempt.
//
// Example:
//
//	WithExemptPathPrefixes("/public/", "/static/", "/.well-known/")
func WithExemptPathPrefixes(prefixes ...string) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.exemptPathPrefixes = append(c.exemptPathPrefixes, prefixes...)
	}
}

// WithMiddlewareLogger sets a logger for the middleware.
func WithMiddlewareLogger(logger Logger) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.logger = logger
	}
}

// WithTokenExtractor sets a custom token extraction function.
// By default, tokens are extracted from the "Authorization" header as "Bearer <token>".
func WithTokenExtractor(extractor TokenExtractor) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.tokenExtractor = extractor
	}
}

// WithUnauthorizedHandler sets a custom handler for authentication failures.
// By default, returns HTTP 401 with a plain text error message.
func WithUnauthorizedHandler(handler UnauthorizedHandler) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.unauthorizedHandler = handler
	}
}

// Middleware returns an HTTP middleware that validates OAuth2/OIDC Bearer tokens.
//
// The middleware:
// - Extracts the Bearer token from the "Authorization" header
// - Validates the token using the provided TokenValidator
// - Stores the TokenClaims in the request context (accessible via TokenClaimsFromContext)
// - Returns HTTP 401 Unauthorized if authentication fails
// - Optionally exempts specific paths from authentication
//
// Usage:
//
//	validator, _ := httpserver.NewValidatorBuilder(issuerURL, audience).Build()
//	mux := http.NewServeMux()
//	mux.HandleFunc("/api/users", getUsersHandler)
//
//	// Wrap with authentication middleware
//	authHandler := httpserver.Middleware(validator)(mux)
//	http.ListenAndServe(":8080", authHandler)
func Middleware(validator TokenValidator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	config := &MiddlewareConfig{
		validator:   validator,
		exemptPaths: make(map[string]bool),
		unauthorizedHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		},
	}

	for _, opt := range opts {
		opt(config)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is exempt from authentication
			if isExempt(r.URL.Path, config) {
				if config.logger != nil {
					config.logger.Printf("httpserver: path %s is exempt from authentication", r.URL.Path)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Extract and validate token
			claims, err := extractAndValidateToken(r, config)
			if err != nil {
				if config.logger != nil {
					config.logger.Printf("httpserver: authentication failed for %s %s: %v", r.Method, r.URL.Path, err)
				}
				config.unauthorizedHandler(w, r, err)
				return
			}

			// Add claims to context
			ctx := WithTokenClaims(r.Context(), claims)
			r = r.WithContext(ctx)

			if config.logger != nil {
				config.logger.Printf("httpserver: authenticated request for %s %s (subject: %s)", r.Method, r.URL.Path, claims.Subject)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isExempt checks if a path is exempt from authentication.
func isExempt(path string, config *MiddlewareConfig) bool {
	// Check exact path matches
	if config.exemptPaths[path] {
		return true
	}

	// Check prefix matches
	for _, prefix := range config.exemptPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// extractAndValidateToken extracts the Bearer token from the request and validates it.
func extractAndValidateToken(r *http.Request, config *MiddlewareConfig) (*TokenClaims, error) {
	// Extract token using custom extractor or default logic
	var token string
	if config.tokenExtractor != nil {
		var extracted bool
		token, extracted = config.tokenExtractor(r)
		if !extracted {
			return nil, http.ErrNoCookie // Use a standard error for missing token
		}
	} else {
		// Default extraction: "Authorization: Bearer <token>"
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return nil, http.ErrNoCookie
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			return nil, http.ErrNoCookie
		}

		token = strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			return nil, http.ErrNoCookie
		}
	}

	// Validate token
	claims, err := config.validator.ValidateToken(r.Context(), token)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
