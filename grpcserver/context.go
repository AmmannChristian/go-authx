package grpcserver

import "context"

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// #nosec G101 -- context key, not a credential
const (
	// tokenClaimsKey is the context key for storing TokenClaims.
	tokenClaimsKey contextKey = "grpcserver.token_claims" //nolint:gosec // context key, not a credential
)

// WithTokenClaims returns a new context with the provided TokenClaims.
// This is used by the interceptors to store validated token claims in the request context.
//
// Example:
//
//	ctx = grpcserver.WithTokenClaims(ctx, claims)
func WithTokenClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, tokenClaimsKey, claims)
}

// TokenClaimsFromContext extracts TokenClaims from the context.
// Returns the claims and true if found, or nil and false if not present.
//
// This function should be used in gRPC handlers to access the authenticated user's claims.
//
// Example:
//
//	func (s *server) MyMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//	    claims, ok := grpcserver.TokenClaimsFromContext(ctx)
//	    if !ok {
//	        return nil, status.Error(codes.Unauthenticated, "not authenticated")
//	    }
//	    userID := claims.Subject
//	    // ... use claims ...
//	}
func TokenClaimsFromContext(ctx context.Context) (*TokenClaims, bool) {
	claims, ok := ctx.Value(tokenClaimsKey).(*TokenClaims)
	return claims, ok
}

// MustTokenClaimsFromContext extracts TokenClaims from the context and panics if not found.
// This should only be used in handlers where authentication is guaranteed by the interceptor.
//
// Example:
//
//	func (s *server) MyMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//	    claims := grpcserver.MustTokenClaimsFromContext(ctx)
//	    userID := claims.Subject
//	    // ... use claims ...
//	}
func MustTokenClaimsFromContext(ctx context.Context) *TokenClaims {
	claims, ok := TokenClaimsFromContext(ctx)
	if !ok {
		panic("grpcserver: token claims not found in context")
	}
	return claims
}
