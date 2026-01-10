package grpcserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TLSConfig holds TLS configuration for the gRPC server.
type TLSConfig struct {
	// CertFile is the path to the server certificate file (PEM format)
	CertFile string

	// KeyFile is the path to the server private key file (PEM format)
	KeyFile string

	// CAFile is the path to the CA certificate for client verification (optional)
	// If empty, client certificates will not be verified
	CAFile string

	// ClientAuth specifies the server's policy for TLS client authentication
	// Common values:
	//   - tls.NoClientCert: don't request client certificates
	//   - tls.RequestClientCert: request but don't require valid client certificates
	//   - tls.RequireAnyClientCert: require client certificates but don't verify
	//   - tls.VerifyClientCertIfGiven: verify client certificates if provided
	//   - tls.RequireAndVerifyClientCert: require and verify client certificates (mTLS)
	ClientAuth tls.ClientAuthType

	// MinVersion specifies the minimum TLS version to accept
	// Default: TLS 1.2
	MinVersion uint16
}

// NewServerCredentials creates gRPC credentials from TLS configuration.
// This is used to enable TLS/mTLS for gRPC servers with automatic certificate reloading.
//
// The function:
//   - Validates the server certificate and private key at startup (fail-fast)
//   - Configures automatic certificate reloading on each TLS handshake
//   - Optionally loads a CA certificate for client verification (mTLS)
//   - Creates a TLS configuration with secure defaults (TLS 1.2+)
//   - Returns gRPC TransportCredentials that can be used with grpc.Creds()
//
// Automatic Certificate Reload:
// Certificates are loaded fresh from disk on each new TLS connection, enabling
// zero-downtime certificate rotation. This is perfect for environments using
// certificate management tools like Vault Agent or cert-manager that automatically
// renew certificates. The server continues running and serves new connections with
// the updated certificates without requiring a restart.
//
// Example usage:
//
//	tlsConfig := &grpcserver.TLSConfig{
//	    CertFile:   "/path/to/server.crt",
//	    KeyFile:    "/path/to/server.key",
//	    CAFile:     "/path/to/ca.crt",
//	    ClientAuth: tls.RequireAndVerifyClientCert,
//	}
//	creds, err := grpcserver.NewServerCredentials(tlsConfig)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server := grpc.NewServer(grpc.Creds(creds))
func NewServerCredentials(cfg *TLSConfig) (credentials.TransportCredentials, error) {
	if cfg == nil {
		return nil, errors.New("grpcserver: TLS config is nil")
	}

	if cfg.CertFile == "" {
		return nil, errors.New("grpcserver: server certificate file is required")
	}
	if cfg.KeyFile == "" {
		return nil, errors.New("grpcserver: server key file is required")
	}

	// Create base TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: cfg.ClientAuth,
	}

	// Allow custom minimum TLS version
	if cfg.MinVersion > 0 {
		tlsConfig.MinVersion = cfg.MinVersion
	}

	// Validate that server certificate and key can be loaded initially
	// This ensures we fail fast at startup if certificates are invalid or missing
	_, err := loadCertificate(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpcserver: load server certificate: %w", err)
	}

	// Configure automatic certificate reloading on each TLS handshake
	// This allows certificates to be rotated without restarting the server
	certFile := cfg.CertFile
	keyFile := cfg.KeyFile
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := loadCertificate(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}

	// Load CA certificate for client verification if provided
	if cfg.CAFile != "" {
		caCertPool, err := loadCACertificate(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("grpcserver: load CA certificate: %w", err)
		}
		tlsConfig.ClientCAs = caCertPool
	}

	return credentials.NewTLS(tlsConfig), nil
}

// ServerOption is a convenience function that creates a grpc.ServerOption from TLS config.
// This can be used directly when constructing a gRPC server.
//
// Example usage:
//
//	tlsConfig := &grpcserver.TLSConfig{
//	    CertFile:   "/path/to/server.crt",
//	    KeyFile:    "/path/to/server.key",
//	    CAFile:     "/path/to/ca.crt",
//	    ClientAuth: tls.RequireAndVerifyClientCert,
//	}
//	tlsOpt, err := grpcserver.ServerOption(tlsConfig)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server := grpc.NewServer(tlsOpt, grpc.UnaryInterceptor(...))
func ServerOption(cfg *TLSConfig) (grpc.ServerOption, error) {
	creds, err := NewServerCredentials(cfg)
	if err != nil {
		return nil, err
	}
	return grpc.Creds(creds), nil
}

// loadCertificate loads a TLS certificate from files using secure path handling.
func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := readTLSFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read certificate file: %w", err)
	}

	keyPEM, err := readTLSFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}

// loadCACertificate loads a CA certificate pool from file using secure path handling.
func loadCACertificate(caFile string) (*x509.CertPool, error) {
	caCert, err := readTLSFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}

	return caCertPool, nil
}

// readTLSFile reads a TLS-related file (certificate, key, CA) with secure path handling.
func readTLSFile(path string) ([]byte, error) {
	absPath, err := sanitizeTLSPath(path)
	if err != nil {
		return nil, err
	}
	return readFileWithinRoot(absPath)
}

// sanitizeTLSPath validates and converts a path to an absolute path.
func sanitizeTLSPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("grpcserver: empty TLS file path")
	}
	clean := filepath.Clean(path)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("grpcserver: resolve TLS path %q: %w", path, err)
	}
	return abs, nil
}

// readFileWithinRoot reads a file using os.OpenInRoot for additional security.
func readFileWithinRoot(absPath string) ([]byte, error) {
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)
	f, err := os.OpenInRoot(dir, base)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
