package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator validates OAuth2/OIDC JWT tokens.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
}

// TokenClaims represents the claims extracted from a validated JWT token.
type TokenClaims struct {
	Subject  string    // Subject (sub) - user identifier
	Issuer   string    // Issuer (iss) - token issuer
	Audience []string  // Audience (aud) - intended recipients
	Expiry   time.Time // Expiry time (exp)
	IssuedAt time.Time // Issued at (iat)
	Scopes   []string  // Scopes - extracted from "scope" or "scp" claim
	Email    string    // Email - optional user email
}

// JWTTokenValidator validates JWT tokens against JWKS from an OAuth2/OIDC provider.
// It caches public keys and automatically refreshes them when needed.
type JWTTokenValidator struct {
	jwks     *keyfunc.JWKS
	issuer   string
	audience string
	logger   Logger // optional logger
}

// Logger is an interface for optional logging in JWTTokenValidator.
type Logger interface {
	Printf(format string, args ...any)
}

// NewJWTTokenValidator creates a new JWT token validator.
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
	if jwksURL == "" {
		return nil, errors.New("grpcserver: JWKS URL is required")
	}
	if issuer == "" {
		return nil, errors.New("grpcserver: issuer is required")
	}
	if audience == "" {
		return nil, errors.New("grpcserver: audience is required")
	}

	// Use default HTTP client if not provided
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Use default cache TTL if not specified
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}

	// Configure JWKS options
	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			if logger != nil {
				logger.Printf("grpcserver: JWKS refresh error: %v", err)
			}
		},
		RefreshInterval:   cacheTTL,
		RefreshRateLimit:  time.Minute * 5, // Minimum 5 minutes between refreshes
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true, // Refresh when encountering unknown key IDs
		Client:            httpClient,
	}

	// Initialize JWKS
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("grpcserver: failed to initialize JWKS: %w", err)
	}

	return &JWTTokenValidator{
		jwks:     jwks,
		issuer:   issuer,
		audience: audience,
		logger:   logger,
	}, nil
}

// ValidateToken validates a JWT token and extracts its claims.
//
// This method:
// - Parses and validates the JWT signature using JWKS
// - Verifies the token expiry, issuer, and audience
// - Extracts standard and custom claims
//
// Parameters:
//   - ctx: Context for the validation (currently unused but available for future use)
//   - tokenString: JWT token string to validate
//
// Returns:
//   - *TokenClaims: Extracted token claims if validation succeeds
//   - error: Error if validation fails
func (v *JWTTokenValidator) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Parse and validate the JWT token
	token, err := jwt.Parse(tokenString, v.jwks.Keyfunc, jwt.WithValidMethods([]string{
		jwt.SigningMethodRS256.Name,
		jwt.SigningMethodRS384.Name,
		jwt.SigningMethodRS512.Name,
		jwt.SigningMethodES256.Name,
		jwt.SigningMethodES384.Name,
		jwt.SigningMethodES512.Name,
	}))
	if err != nil {
		return nil, fmt.Errorf("grpcserver: token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("grpcserver: token is invalid")
	}

	// Extract standard claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("grpcserver: failed to extract token claims")
	}

	// Verify issuer
	iss, err := claims.GetIssuer()
	if err != nil || iss != v.issuer {
		return nil, fmt.Errorf("grpcserver: invalid issuer: expected %s, got %s", v.issuer, iss)
	}

	// Verify audience
	aud, err := claims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("grpcserver: invalid audience claim: %w", err)
	}
	if !contains(aud, v.audience) {
		return nil, fmt.Errorf("grpcserver: invalid audience: expected %s in %v", v.audience, aud)
	}

	// Extract subject
	sub, err := claims.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("grpcserver: invalid subject claim: %w", err)
	}
	if sub == "" {
		return nil, errors.New("grpcserver: invalid subject claim: empty")
	}

	// Extract expiry
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("grpcserver: invalid expiry claim: %w", err)
	}
	if exp == nil {
		return nil, errors.New("grpcserver: invalid expiry claim: missing")
	}

	// Extract issued at
	iat, err := claims.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("grpcserver: invalid issued at claim: %w", err)
	}
	if iat == nil {
		return nil, errors.New("grpcserver: invalid issued at claim: missing")
	}

	// Extract scopes (can be "scope" or "scp" claim, space-separated string or array)
	scopes := extractScopes(claims)

	// Extract email (optional)
	email := ""
	if emailVal, ok := claims["email"].(string); ok {
		email = emailVal
	}

	tokenClaims := &TokenClaims{
		Subject:  sub,
		Issuer:   iss,
		Audience: aud,
		Expiry:   exp.Time,
		IssuedAt: iat.Time,
		Scopes:   scopes,
		Email:    email,
	}

	if v.logger != nil {
		v.logger.Printf("grpcserver: validated token for subject %s with scopes %v", sub, scopes)
	}

	return tokenClaims, nil
}

// Close releases resources used by the validator.
// Should be called when the validator is no longer needed.
func (v *JWTTokenValidator) Close() {
	if v.jwks != nil {
		v.jwks.EndBackground()
	}
}

// extractScopes extracts scopes from JWT claims.
// Supports both "scope" and "scp" claims, and handles both string and array formats.
func extractScopes(claims jwt.MapClaims) []string {
	// Try "scope" claim first (common in OAuth2)
	if scope, ok := claims["scope"].(string); ok {
		return strings.Fields(scope) // Split space-separated scopes
	}

	// Try "scope" as array
	if scopeArray, ok := claims["scope"].([]interface{}); ok {
		scopes := make([]string, 0, len(scopeArray))
		for _, s := range scopeArray {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
		return scopes
	}

	// Try "scp" claim (alternative format)
	if scp, ok := claims["scp"].(string); ok {
		return strings.Fields(scp)
	}

	// Try "scp" as array
	if scpArray, ok := claims["scp"].([]interface{}); ok {
		scopes := make([]string, 0, len(scpArray))
		for _, s := range scpArray {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
		return scopes
	}

	return []string{}
}

// contains checks if a string slice contains a specific value.
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
