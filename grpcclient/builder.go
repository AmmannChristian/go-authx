package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/AmmannChristian/go-authx/oauth2client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Builder provides a fluent interface for constructing gRPC client connections
// with optional OAuth2 authentication and TLS/mTLS support.
type Builder struct {
	address string

	// OAuth2 configuration
	oauth2Enabled      bool
	oauth2TokenURL     string
	oauth2ClientID     string
	oauth2ClientSecret string
	oauth2Scopes       string

	// TLS configuration
	tlsEnabled    bool
	tlsCAFile     string
	tlsCertFile   string
	tlsKeyFile    string
	tlsServerName string

	// Additional dial options
	dialOpts []grpc.DialOption
}

// NewBuilder creates a new gRPC client builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// WithAddress sets the server address (e.g., "server.example.com:9090").
func (b *Builder) WithAddress(address string) *Builder {
	b.address = address
	return b
}

// WithOAuth2 enables OAuth2 client credentials authentication.
//
// Parameters:
//   - tokenURL: OAuth2 token endpoint (e.g., "https://auth.example.com/oauth/v2/token")
//   - clientID: OAuth2 client identifier
//   - clientSecret: OAuth2 client secret
//   - scopes: Space-separated list of OAuth2 scopes (e.g., "openid profile email")
func (b *Builder) WithOAuth2(tokenURL, clientID, clientSecret, scopes string) *Builder {
	b.oauth2Enabled = true
	b.oauth2TokenURL = tokenURL
	b.oauth2ClientID = clientID
	b.oauth2ClientSecret = clientSecret
	b.oauth2Scopes = scopes
	return b
}

// WithTLS enables TLS for the connection.
//
// Parameters:
//   - caFile: Path to CA certificate for server verification (required)
//   - certFile: Path to client certificate for mTLS (optional, must be paired with keyFile)
//   - keyFile: Path to client private key for mTLS (optional, must be paired with certFile)
//   - serverName: Expected server name for TLS verification (optional, overrides SNI)
func (b *Builder) WithTLS(caFile, certFile, keyFile, serverName string) *Builder {
	b.tlsEnabled = true
	b.tlsCAFile = caFile
	b.tlsCertFile = certFile
	b.tlsKeyFile = keyFile
	b.tlsServerName = serverName
	return b
}

// WithDialOptions adds custom gRPC dial options.
// These options are applied after OAuth2 and TLS options.
func (b *Builder) WithDialOptions(opts ...grpc.DialOption) *Builder {
	b.dialOpts = append(b.dialOpts, opts...)
	return b
}

// Build constructs the gRPC client connection with the configured options.
//
// Returns:
//   - *grpc.ClientConn: Established gRPC connection
//   - error: Error if connection fails
func (b *Builder) Build(ctx context.Context) (*grpc.ClientConn, error) {
	if b.address == "" {
		return nil, errors.New("grpcclient: server address is required")
	}

	var opts []grpc.DialOption

	// Add OAuth2 interceptors if enabled
	if b.oauth2Enabled {
		if err := b.validateOAuth2Config(); err != nil {
			return nil, err
		}

		tm := oauth2client.NewTokenManager(
			ctx,
			b.oauth2TokenURL,
			b.oauth2ClientID,
			b.oauth2ClientSecret,
			b.oauth2Scopes,
		)

		opts = append(opts,
			grpc.WithUnaryInterceptor(tm.UnaryClientInterceptor()),
			grpc.WithStreamInterceptor(tm.StreamClientInterceptor()),
		)
	}

	// Add TLS credentials if enabled
	if b.tlsEnabled {
		tlsConfig, err := b.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("grpcclient: TLS config failed: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		// Default to TLS with system roots to avoid accidental plaintext connections.
		// Set MinVersion to TLS 1.2 for secure defaults.
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})))
	}

	// Add custom dial options
	opts = append(opts, b.dialOpts...)

	// Create connection
	conn, err := grpc.NewClient(b.address, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpcclient: dial failed: %w", err)
	}

	return conn, nil
}

// validateOAuth2Config ensures OAuth2 configuration is complete.
func (b *Builder) validateOAuth2Config() error {
	if b.oauth2TokenURL == "" {
		return errors.New("grpcclient: OAuth2 token URL is required")
	}
	if b.oauth2ClientID == "" {
		return errors.New("grpcclient: OAuth2 client ID is required")
	}
	if b.oauth2ClientSecret == "" {
		return errors.New("grpcclient: OAuth2 client secret is required")
	}
	return nil
}

// buildTLSConfig constructs the TLS configuration for the gRPC connection.
func (b *Builder) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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

	// Set server name override if provided
	if b.tlsServerName != "" {
		tlsConfig.ServerName = b.tlsServerName
	}

	return tlsConfig, nil
}
