package httpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ValidatorBuilder provides a fluent interface for constructing a TokenValidator
// with OAuth2/OIDC configuration.
type ValidatorBuilder struct {
	issuerURL  string
	audience   string
	jwksURL    string
	cacheTTL   time.Duration
	httpClient *http.Client
	logger     Logger
}

// NewValidatorBuilder creates a new validator builder with required parameters.
//
// Parameters:
//   - issuerURL: OAuth2/OIDC issuer URL (e.g., "https://auth.example.com")
//   - audience: Expected token audience (e.g., "my-api" or "https://api.example.com")
//
// The builder uses secure defaults:
//   - JWKS URL is automatically derived from issuerURL as {issuerURL}/.well-known/jwks.json
//   - Cache TTL is set to 1 hour
//   - HTTP client uses TLS 1.2+ with system root CAs
func NewValidatorBuilder(issuerURL, audience string) *ValidatorBuilder {
	return &ValidatorBuilder{
		issuerURL: issuerURL,
		audience:  audience,
		cacheTTL:  time.Hour,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

// WithJWKSURL sets a custom JWKS endpoint URL.
// By default, the JWKS URL is derived from the issuer URL as {issuerURL}/.well-known/jwks.json.
//
// Use this method if your OAuth2 provider uses a different JWKS endpoint location.
//
// Example:
//
//	builder.WithJWKSURL("https://auth.example.com/protocol/openid-connect/certs")
func (b *ValidatorBuilder) WithJWKSURL(url string) *ValidatorBuilder {
	b.jwksURL = url
	return b
}

// WithCacheTTL sets the duration for caching JWKS keys before automatic refresh.
// Default is 1 hour.
//
// A longer TTL reduces load on the JWKS endpoint but may delay key rotation detection.
// A shorter TTL increases JWKS endpoint load but detects key changes faster.
//
// Example:
//
//	builder.WithCacheTTL(30 * time.Minute)
func (b *ValidatorBuilder) WithCacheTTL(ttl time.Duration) *ValidatorBuilder {
	b.cacheTTL = ttl
	return b
}

// WithHTTPClient sets a custom HTTP client for fetching JWKS.
// This is useful for configuring custom timeouts, proxies, or TLS settings.
//
// Example:
//
//	customClient := &http.Client{
//	    Timeout: 30 * time.Second,
//	    Transport: customTransport,
//	}
//	builder.WithHTTPClient(customClient)
func (b *ValidatorBuilder) WithHTTPClient(client *http.Client) *ValidatorBuilder {
	b.httpClient = client
	return b
}

// WithLogger sets a logger for debugging token validation.
// The logger will receive messages about token validation and JWKS refresh events.
//
// Example:
//
//	builder.WithLogger(log.Default())
func (b *ValidatorBuilder) WithLogger(logger Logger) *ValidatorBuilder {
	b.logger = logger
	return b
}

// Build constructs the TokenValidator with the configured options.
//
// This method:
//   - Validates the configuration
//   - Derives the JWKS URL if not explicitly set
//   - Initializes the JWKS cache
//   - Returns a ready-to-use TokenValidator
//
// Returns:
//   - TokenValidator: Configured validator instance
//   - error: Error if configuration is invalid or JWKS initialization fails
func (b *ValidatorBuilder) Build() (TokenValidator, error) {
	// Validate required fields
	if b.issuerURL == "" {
		return nil, errors.New("httpserver: issuer URL is required")
	}
	if b.audience == "" {
		return nil, errors.New("httpserver: audience is required")
	}

	// Derive JWKS URL if not explicitly set
	jwksURL := b.jwksURL
	if jwksURL == "" {
		jwksURL = deriveJWKSURL(b.issuerURL)
		if b.logger != nil {
			b.logger.Printf("httpserver: using derived JWKS URL: %s", jwksURL)
		}
	}

	// Create validator
	validator, err := NewJWTTokenValidator(
		jwksURL,
		b.issuerURL,
		b.audience,
		b.httpClient,
		b.cacheTTL,
		b.logger,
	)
	if err != nil {
		return nil, fmt.Errorf("httpserver: failed to build validator: %w", err)
	}

	return validator, nil
}

// deriveJWKSURL constructs the standard OIDC JWKS URL from an issuer URL.
// For example:
//   - "https://auth.example.com" -> "https://auth.example.com/.well-known/jwks.json"
//   - "https://auth.example.com/" -> "https://auth.example.com/.well-known/jwks.json"
func deriveJWKSURL(issuerURL string) string {
	// Remove trailing slash if present
	issuerURL = strings.TrimSuffix(issuerURL, "/")
	return issuerURL + "/.well-known/jwks.json"
}
