package httpserver_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/httpserver"
)

// generateTestCert generates a self-signed certificate for testing
func generateTestCert(t *testing.T, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte, []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent_ := &template
	parentKey_ := priv
	if parent != nil {
		parent_ = parent
		parentKey_ = parentKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent_, &priv.PublicKey, parentKey_)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return cert, priv, certPEM, keyPEM
}

func TestNewTLSConfig_WithRealCertificates(t *testing.T) {
	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Generate CA certificate
	caCert, caKey, caCertPEM, _ := generateTestCert(t, true, nil, nil)

	// Generate server certificate signed by CA
	_, _, serverCertPEM, serverKeyPEM := generateTestCert(t, false, caCert, caKey)

	// Write certificates to files
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(certFile, serverCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	tests := []struct {
		name    string
		config  *httpserver.TLSConfig
		wantErr bool
	}{
		{
			name: "valid TLS config",
			config: &httpserver.TLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
			wantErr: false,
		},
		{
			name: "valid mTLS config",
			config: &httpserver.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				CAFile:     caFile,
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantErr: false,
		},
		{
			name: "custom MinVersion",
			config: &httpserver.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				MinVersion: tls.VersionTLS13,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := httpserver.NewTLSConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if tlsConfig == nil {
					t.Error("Expected non-nil TLS config")
				}
				if tlsConfig.MinVersion < tls.VersionTLS12 {
					t.Error("Expected MinVersion >= TLS 1.2")
				}
			}
		})
	}
}

func TestConfigureServer_WithRealCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate certificates
	caCert, caKey, caCertPEM, _ := generateTestCert(t, true, nil, nil)
	_, _, serverCertPEM, serverKeyPEM := generateTestCert(t, false, caCert, caKey)

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(certFile, serverCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	tests := []struct {
		name    string
		config  *httpserver.TLSConfig
		wantErr bool
	}{
		{
			name: "valid TLS config",
			config: &httpserver.TLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
			wantErr: false,
		},
		{
			name: "valid mTLS config",
			config: &httpserver.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				CAFile:     caFile,
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &http.Server{
				Addr: ":0",
			}

			err := httpserver.ConfigureServer(server, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if server.TLSConfig == nil {
					t.Error("Expected non-nil TLS config on server")
				}
				if server.TLSConfig.ClientAuth != tt.config.ClientAuth {
					t.Errorf("ClientAuth = %v, want %v", server.TLSConfig.ClientAuth, tt.config.ClientAuth)
				}
			}
		})
	}
}

func TestTLSConfig_InvalidCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create invalid certificate files
	certFile := filepath.Join(tmpDir, "invalid.crt")
	keyFile := filepath.Join(tmpDir, "invalid.key")

	// Write invalid data
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	config := &httpserver.TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	_, err := httpserver.NewTLSConfig(config)
	if err == nil {
		t.Error("Expected error with invalid certificate")
	}
}

func TestTLSConfig_InvalidCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid server certificate
	caCert, caKey, _, _ := generateTestCert(t, true, nil, nil)
	_, _, serverCertPEM, serverKeyPEM := generateTestCert(t, false, caCert, caKey)

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	caFile := filepath.Join(tmpDir, "invalid-ca.crt")

	if err := os.WriteFile(certFile, serverCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	// Write invalid CA
	if err := os.WriteFile(caFile, []byte("not a CA certificate"), 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	config := &httpserver.TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	_, err := httpserver.NewTLSConfig(config)
	if err == nil {
		t.Error("Expected error with invalid CA certificate")
	}
}

func TestTLSConfig_MismatchedCertAndKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate two different certificates
	_, _, cert1PEM, _ := generateTestCert(t, false, nil, nil)
	_, _, _, key2PEM := generateTestCert(t, false, nil, nil)

	certFile := filepath.Join(tmpDir, "cert1.crt")
	keyFile := filepath.Join(tmpDir, "key2.key")

	if err := os.WriteFile(certFile, cert1PEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, key2PEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	config := &httpserver.TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	_, err := httpserver.NewTLSConfig(config)
	if err == nil {
		t.Error("Expected error with mismatched certificate and key")
	}
}

func TestTLSConfig_AllClientAuthModes(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate certificates
	caCert, caKey, caCertPEM, _ := generateTestCert(t, true, nil, nil)
	_, _, serverCertPEM, serverKeyPEM := generateTestCert(t, false, caCert, caKey)

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	if err := os.WriteFile(certFile, serverCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	modes := []tls.ClientAuthType{
		tls.NoClientCert,
		tls.RequestClientCert,
		tls.RequireAnyClientCert,
		tls.VerifyClientCertIfGiven,
		tls.RequireAndVerifyClientCert,
	}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			config := &httpserver.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				CAFile:     caFile,
				ClientAuth: mode,
			}

			tlsConfig, err := httpserver.NewTLSConfig(config)
			if err != nil {
				t.Fatalf("NewTLSConfig() error = %v", err)
			}

			if tlsConfig.ClientAuth != mode {
				t.Errorf("ClientAuth = %v, want %v", tlsConfig.ClientAuth, mode)
			}
		})
	}
}
