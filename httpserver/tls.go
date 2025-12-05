package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// TLSConfig holds TLS configuration for the HTTP server.
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

// NewTLSConfig creates a *tls.Config from TLS configuration.
// This is used to enable TLS/mTLS for HTTP servers.
//
// The function:
//   - Loads the server certificate and private key
//   - Optionally loads a CA certificate for client verification (mTLS)
//   - Creates a TLS configuration with secure defaults
//   - Returns a *tls.Config that can be assigned to http.Server.TLSConfig
//
// Example usage:
//
//	tlsConfig := &httpserver.TLSConfig{
//	    CertFile:   "/path/to/server.crt",
//	    KeyFile:    "/path/to/server.key",
//	    CAFile:     "/path/to/ca.crt",
//	    ClientAuth: tls.RequireAndVerifyClientCert,
//	}
//	tlsCfg, err := httpserver.NewTLSConfig(tlsConfig)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server := &http.Server{
//	    Addr:      ":8443",
//	    Handler:   handler,
//	    TLSConfig: tlsCfg,
//	}
//	server.ListenAndServeTLS("", "") // cert/key loaded via TLSConfig
func NewTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("httpserver: TLS config is nil")
	}

	if cfg.CertFile == "" {
		return nil, errors.New("httpserver: server certificate file is required")
	}
	if cfg.KeyFile == "" {
		return nil, errors.New("httpserver: server key file is required")
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

	// Load server certificate and key
	cert, err := loadCertificate(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("httpserver: load server certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Load CA certificate for client verification if provided
	if cfg.CAFile != "" {
		caCertPool, err := loadCACertificate(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("httpserver: load CA certificate: %w", err)
		}
		tlsConfig.ClientCAs = caCertPool
	}

	return tlsConfig, nil
}

// ConfigureServer configures an existing http.Server with TLS settings.
// This is a convenience function that sets up TLS on an http.Server.
//
// Example usage:
//
//	server := &http.Server{
//	    Addr:    ":8443",
//	    Handler: handler,
//	}
//	tlsConfig := &httpserver.TLSConfig{
//	    CertFile:   "/path/to/server.crt",
//	    KeyFile:    "/path/to/server.key",
//	    CAFile:     "/path/to/ca.crt",
//	    ClientAuth: tls.RequireAndVerifyClientCert,
//	}
//	if err := httpserver.ConfigureServer(server, tlsConfig); err != nil {
//	    log.Fatal(err)
//	}
//	server.ListenAndServeTLS("", "")
func ConfigureServer(server *http.Server, cfg *TLSConfig) error {
	if server == nil {
		return errors.New("httpserver: server is nil")
	}

	tlsConfig, err := NewTLSConfig(cfg)
	if err != nil {
		return err
	}

	server.TLSConfig = tlsConfig
	return nil
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
		return "", errors.New("httpserver: empty TLS file path")
	}
	clean := filepath.Clean(path)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("httpserver: resolve TLS path %q: %w", path, err)
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
