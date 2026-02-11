// Package httpserver provides server-side OAuth2/OIDC authentication for HTTP services.
//
// This package enables HTTP servers to validate incoming JWT Bearer tokens from OAuth2/OIDC providers,
// extract user claims, and make them available to HTTP handlers. It follows the same design patterns
// as the rest of the go-authx library: fluent builders, secure defaults, and provider-agnostic implementation.
//
// # Features
//
//   - JWT token validation with JWKS (JSON Web Key Set)
//   - Opaque token validation via OAuth2 introspection (RFC 7662)
//   - Automatic JWKS caching and refresh
//   - HTTP middleware for standard http.Handler
//   - Context-based claims extraction in handlers
//   - Path exemption (e.g., for health checks, metrics)
//   - Configurable logging
//   - Thread-safe
//   - Provider-agnostic (works with any OIDC-compliant provider)
//
// # Quick Start
//
// Create a token validator and wrap your HTTP handlers with authentication middleware:
//
//	validator, err := httpserver.NewValidatorBuilder(
//	    "https://auth.example.com",  // OIDC issuer URL
//	    "my-api",                     // Expected audience
//	).Build()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/api/users", getUsersHandler)
//
//	// Wrap with authentication middleware
//	authHandler := httpserver.Middleware(validator)(mux)
//	http.ListenAndServe(":8080", authHandler)
//
// # Accessing Claims in Handlers
//
// Token claims are automatically extracted and stored in the request context:
//
//	func getUsersHandler(w http.ResponseWriter, r *http.Request) {
//	    claims, ok := httpserver.TokenClaimsFromContext(r.Context())
//	    if !ok {
//	        http.Error(w, "not authenticated", http.StatusUnauthorized)
//	        return
//	    }
//
//	    userID := claims.Subject
//	    scopes := claims.Scopes
//	    // ... use claims for authorization ...
//	}
//
// # Advanced Configuration
//
// Customize JWKS URL, cache TTL, and exempt specific paths:
//
//	validator, err := httpserver.NewValidatorBuilder(issuerURL, audience).
//	    WithJWKSURL("https://custom-jwks-url.example.com/keys").
//	    WithCacheTTL(30 * time.Minute).
//	    WithLogger(log.Default()).
//	    Build()
//
//	middleware := httpserver.Middleware(
//	    validator,
//	    httpserver.WithExemptPaths("/health", "/metrics"),
//	    httpserver.WithExemptPathPrefixes("/public/"),
//	    httpserver.WithMiddlewareLogger(log.Default()),
//	)
//
//	http.ListenAndServe(":8080", middleware(mux))
//
// Opaque token validation can be enabled using introspection:
//
//	validator, err := httpserver.NewValidatorBuilder(issuerURL, audience).
//	    WithOpaqueTokenIntrospection(
//	        "https://auth.example.com/oauth2/introspect",
//	        "introspection-client-id",
//	        "introspection-client-secret",
//	    ).
//	    Build()
//
// # Security Considerations
//
//   - Tokens are validated against JWKS from the OIDC provider
//   - JWT signatures are verified using RS256, RS384, RS512, ES256, ES384, or ES512
//   - Token expiry, issuer, and audience are strictly validated
//   - JWKS keys are cached securely with automatic refresh
//   - TLS 1.2+ is enforced for JWKS fetching
//
// # Provider Compatibility
//
// This package works with any OIDC-compliant provider, including:
//   - Zitadel
//   - Auth0
//   - Keycloak
//   - Okta
//   - Google Identity Platform
//   - Azure AD
//   - AWS Cognito
//
// # Thread Safety
//
// All types in this package are thread-safe and can be used concurrently from multiple goroutines.
// The JWKS cache is protected by internal locking and can safely handle concurrent token validations.
//
// # Error Handling
//
// Authentication failures return HTTP 401 Unauthorized by default.
// You can customize the status code and error response using WithUnauthorizedHandler:
//
//	middleware := httpserver.Middleware(
//	    validator,
//	    httpserver.WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request, err error) {
//	        w.Header().Set("Content-Type", "application/json")
//	        w.WriteHeader(http.StatusUnauthorized)
//	        json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
//	    }),
//	)
package httpserver
