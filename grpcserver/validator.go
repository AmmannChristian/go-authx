package grpcserver

import (
	"net/http"
	"time"

	"github.com/AmmannChristian/go-authx/internal/validator"
)

// NewJWTTokenValidator creates a new JWT token validator for gRPC servers.
//
// Parameters:
//   - jwksURL: URL to the JWKS endpoint (e.g., "https://auth.example.com/.well-known/jwks.json")
//   - issuer: Expected token issuer (iss claim)
//   - audience: Expected token audience (aud claim)
//   - httpClient: HTTP client for fetching JWKS (optional, uses http.DefaultClient if nil)
//   - cacheTTL: Duration to cache JWKS before refreshing (0 uses default of 1 hour)
//   - logger: Optional logger for debugging (can be nil)
//
// Returns:
//   - *JWTTokenValidator: Configured validator instance
//   - error: Error if JWKS initialization fails
func NewJWTTokenValidator(jwksURL, issuer, audience string, httpClient *http.Client, cacheTTL time.Duration, logger Logger) (*JWTTokenValidator, error) {
	return validator.NewJWTTokenValidator(jwksURL, issuer, audience, httpClient, cacheTTL, logger, "grpcserver")
}

// NewOpaqueTokenValidator creates a new opaque token validator for gRPC servers.
//
// Parameters:
//   - introspectionURL: OAuth2 introspection endpoint URL
//   - issuer: Expected token issuer
//   - audience: Expected token audience
//   - clientID: OAuth2 client ID for introspection endpoint authentication
//   - clientSecret: OAuth2 client secret for introspection endpoint authentication
//   - httpClient: HTTP client for introspection requests (optional, uses http.DefaultClient if nil)
//   - logger: Optional logger for debugging (can be nil)
//
// Returns:
//   - *OpaqueTokenValidator: Configured validator instance
//   - error: Error if validator initialization fails
func NewOpaqueTokenValidator(
	introspectionURL,
	issuer,
	audience,
	clientID,
	clientSecret string,
	httpClient *http.Client,
	logger Logger,
) (*OpaqueTokenValidator, error) {
	return validator.NewOpaqueTokenValidator(
		introspectionURL,
		issuer,
		audience,
		clientID,
		clientSecret,
		httpClient,
		logger,
	)
}
