package httpserver

import "context"

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// tokenClaimsKey is the context key for storing TokenClaims.
	tokenClaimsKey contextKey = "httpserver.token_claims"
)

// WithTokenClaims returns a new context with the provided TokenClaims.
// This is used by the middleware to store validated token claims in the request context.
//
// Example:
//
//	ctx = httpserver.WithTokenClaims(ctx, claims)
func WithTokenClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, tokenClaimsKey, claims)
}

// TokenClaimsFromContext extracts TokenClaims from the context.
// Returns the claims and true if found, or nil and false if not present.
//
// This function should be used in HTTP handlers to access the authenticated user's claims.
//
// Example:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    claims, ok := httpserver.TokenClaimsFromContext(r.Context())
//	    if !ok {
//	        http.Error(w, "not authenticated", http.StatusUnauthorized)
//	        return
//	    }
//	    userID := claims.Subject
//	    // ... use claims ...
//	}
func TokenClaimsFromContext(ctx context.Context) (*TokenClaims, bool) {
	claims, ok := ctx.Value(tokenClaimsKey).(*TokenClaims)
	return claims, ok
}

// MustTokenClaimsFromContext extracts TokenClaims from the context and panics if not found.
// This should only be used in handlers where authentication is guaranteed by the middleware.
//
// Example:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    claims := httpserver.MustTokenClaimsFromContext(r.Context())
//	    userID := claims.Subject
//	    // ... use claims ...
//	}
func MustTokenClaimsFromContext(ctx context.Context) *TokenClaims {
	claims, ok := TokenClaimsFromContext(ctx)
	if !ok {
		panic("httpserver: token claims not found in context")
	}
	return claims
}
