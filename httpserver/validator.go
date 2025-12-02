package httpserver

import (
	"net/http"
	"time"

	"github.com/AmmannChristian/go-authx/internal/validator"
)

// NewJWTTokenValidator creates a new JWT token validator for HTTP servers.
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
	return validator.NewJWTTokenValidator(jwksURL, issuer, audience, httpClient, cacheTTL, logger, "httpserver")
}
