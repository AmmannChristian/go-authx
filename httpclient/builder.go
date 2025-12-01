package httpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/AmmannChristian/go-authx/oauth2client"
)

// Builder provides a fluent interface for constructing HTTP clients
// with optional OAuth2 authentication and TLS/mTLS support.
type Builder struct {
	// OAuth2 configuration
	tokenManager *oauth2client.TokenManager

	// TLS configuration
	tlsEnabled    bool
	tlsCAFile     string
	tlsCertFile   string
	tlsKeyFile    string
	tlsSkipVerify bool

	// HTTP client configuration
	timeout         time.Duration
	baseTransport   http.RoundTripper
	followRedirects bool
}

// NewBuilder creates a new HTTP client builder.
func NewBuilder() *Builder {
	return &Builder{
		timeout:         30 * time.Second, // Default 30s timeout
		followRedirects: true,
	}
}

// WithTokenManager sets the OAuth2 token manager for automatic authentication.
func (b *Builder) WithTokenManager(tm *oauth2client.TokenManager) *Builder {
	b.tokenManager = tm
	return b
}

// WithOAuth2 enables OAuth2 client credentials authentication by creating a new TokenManager.
//
// Parameters:
//   - ctx: Context for token requests
//   - tokenURL: OAuth2 token endpoint (e.g., "https://auth.example.com/oauth/v2/token")
//   - clientID: OAuth2 client identifier
//   - clientSecret: OAuth2 client secret
//   - scopes: Space-separated list of OAuth2 scopes (e.g., "openid profile email")
func (b *Builder) WithOAuth2(ctx context.Context, tokenURL, clientID, clientSecret, scopes string) *Builder {
	b.tokenManager = oauth2client.NewTokenManager(ctx, tokenURL, clientID, clientSecret, scopes)
	return b
}

// WithTLS enables TLS for the connection.
//
// Parameters:
//   - caFile: Path to CA certificate for server verification (optional, uses system roots if empty)
//   - certFile: Path to client certificate for mTLS (optional, must be paired with keyFile)
//   - keyFile: Path to client private key for mTLS (optional, must be paired with certFile)
func (b *Builder) WithTLS(caFile, certFile, keyFile string) *Builder {
	b.tlsEnabled = true
	b.tlsCAFile = caFile
	b.tlsCertFile = certFile
	b.tlsKeyFile = keyFile
	return b
}

// WithInsecureSkipVerify disables TLS certificate verification (NOT RECOMMENDED for production).
// This should only be used for testing or development purposes.
func (b *Builder) WithInsecureSkipVerify() *Builder {
	b.tlsSkipVerify = true
	return b
}

// WithTimeout sets the request timeout for the HTTP client.
// Default is 30 seconds if not specified.
func (b *Builder) WithTimeout(timeout time.Duration) *Builder {
	b.timeout = timeout
	return b
}

// WithBaseTransport sets a custom base transport.
// This is useful for adding custom middleware or using a custom connection pool.
func (b *Builder) WithBaseTransport(transport http.RoundTripper) *Builder {
	b.baseTransport = transport
	return b
}

// WithoutRedirects disables automatic redirect following.
// By default, the client follows up to 10 redirects.
func (b *Builder) WithoutRedirects() *Builder {
	b.followRedirects = false
	return b
}

// Build constructs the HTTP client with the configured options.
//
// Returns:
//   - *http.Client: Configured HTTP client
//   - error: Error if configuration is invalid
func (b *Builder) Build() (*http.Client, error) {
	// Build base transport
	transport := b.baseTransport
	if transport == nil {
		if httpTransport, ok := http.DefaultTransport.(*http.Transport); ok {
			httpTransport = httpTransport.Clone()

			if b.tlsEnabled || b.tlsSkipVerify {
				tlsConfig, err := b.buildTLSConfig()
				if err != nil {
					return nil, fmt.Errorf("httpclient: TLS config failed: %w", err)
				}
				httpTransport.TLSClientConfig = tlsConfig
			} else {
				// Set secure TLS defaults even when TLS is not explicitly configured
				httpTransport.TLSClientConfig = &tls.Config{
					MinVersion: tls.VersionTLS12,
				}
			}

			transport = httpTransport
		} else {
			// Fallback to whatever default transport is configured (e.g., a test stub)
			transport = http.DefaultTransport
			if b.tlsEnabled || b.tlsSkipVerify {
				if base, ok := transport.(*http.Transport); ok {
					tlsConfig, err := b.buildTLSConfig()
					if err != nil {
						return nil, fmt.Errorf("httpclient: TLS config failed: %w", err)
					}
					cloned := base.Clone()
					cloned.TLSClientConfig = tlsConfig
					transport = cloned
				}
			}
		}
	}

	// Wrap with OAuth2 transport if token manager is set
	if b.tokenManager != nil {
		transport = NewOAuth2Transport(b.tokenManager, transport)
	}

	// Build HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   b.timeout,
	}

	// Configure redirect policy
	if !b.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}

// buildTLSConfig constructs the TLS configuration for the HTTP client.
func (b *Builder) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: b.tlsSkipVerify, // #nosec G402
	}

	// Load CA certificate for server verification
	if b.tlsCAFile != "" {
		caCert, err := os.ReadFile(b.tlsCAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = certPool
	}

	// Load client certificate for mTLS (if both cert and key are provided)
	if b.tlsCertFile != "" && b.tlsKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(b.tlsCertFile, b.tlsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else if b.tlsCertFile != "" || b.tlsKeyFile != "" {
		return nil, errors.New("both TLS cert and key files must be provided for mTLS")
	}

	return tlsConfig, nil
}

// NewHTTPClient is a convenience function that creates a simple HTTP client with OAuth2 authentication.
// For more configuration options, use Builder instead.
//
// Example:
//
//	tm := oauth2client.NewTokenManager(ctx, tokenURL, clientID, clientSecret, scopes)
//	client := httpclient.NewHTTPClient(tm)
//	resp, err := client.Get("https://api.example.com/data")
func NewHTTPClient(tm *oauth2client.TokenManager) *http.Client {
	transport := NewOAuth2Transport(tm, nil)
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}
