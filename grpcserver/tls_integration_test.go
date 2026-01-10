package grpcserver_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AmmannChristian/go-authx/grpcserver"
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

func TestNewServerCredentials_WithRealCertificates(t *testing.T) {
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

	if err := os.WriteFile(certFile, serverCertPEM, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0o644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	tests := []struct {
		name    string
		config  *grpcserver.TLSConfig
		wantErr bool
	}{
		{
			name: "valid TLS config",
			config: &grpcserver.TLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
			wantErr: false,
		},
		{
			name: "valid mTLS config",
			config: &grpcserver.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				CAFile:     caFile,
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantErr: false,
		},
		{
			name: "custom MinVersion",
			config: &grpcserver.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				MinVersion: tls.VersionTLS13,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := grpcserver.NewServerCredentials(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServerCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && creds == nil {
				t.Error("Expected non-nil credentials")
			}
		})
	}
}

func TestServerOption_WithRealCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate certificates
	caCert, caKey, _, _ := generateTestCert(t, true, nil, nil)
	_, _, serverCertPEM, serverKeyPEM := generateTestCert(t, false, caCert, caKey)

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(certFile, serverCertPEM, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	config := &grpcserver.TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	opt, err := grpcserver.ServerOption(config)
	if err != nil {
		t.Fatalf("ServerOption() error = %v", err)
	}
	if opt == nil {
		t.Error("Expected non-nil ServerOption")
	}
}

func TestTLSConfig_InvalidCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create invalid certificate files
	certFile := filepath.Join(tmpDir, "invalid.crt")
	keyFile := filepath.Join(tmpDir, "invalid.key")

	// Write invalid data
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	config := &grpcserver.TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	_, err := grpcserver.NewServerCredentials(config)
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

	if err := os.WriteFile(certFile, serverCertPEM, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	// Write invalid CA
	if err := os.WriteFile(caFile, []byte("not a CA certificate"), 0o644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	config := &grpcserver.TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	_, err := grpcserver.NewServerCredentials(config)
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

	if err := os.WriteFile(certFile, cert1PEM, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, key2PEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	config := &grpcserver.TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	_, err := grpcserver.NewServerCredentials(config)
	if err == nil {
		t.Error("Expected error with mismatched certificate and key")
	}
}

func TestCertificateReload(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA certificate
	caCert, caKey, _, _ := generateTestCert(t, true, nil, nil)

	// Generate first server certificate
	cert1, _, cert1PEM, key1PEM := generateTestCert(t, false, caCert, caKey)

	// Write first certificate to files
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(certFile, cert1PEM, 0o644); err != nil {
		t.Fatalf("Failed to write initial cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, key1PEM, 0o600); err != nil {
		t.Fatalf("Failed to write initial key file: %v", err)
	}

	// Create our own TLS config mimicking what NewServerCredentials does
	// This allows us to test the certificate reload pattern directly
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			// This mimics the implementation in grpcserver/tls.go
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				return nil, err
			}
			keyPEM, err := os.ReadFile(keyFile)
			if err != nil {
				return nil, err
			}
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}

	// Create a test TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	// Get the first certificate's serial number
	firstSerial := cert1.SerialNumber

	// Accept connections in a goroutine
	connChan := make(chan *tls.Conn, 1)
	errChan := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			errChan <- err
			return
		}
		connChan <- tlsConn
	}()

	// Connect as a client (without verification for this test)
	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to connect as client: %v", err)
	}

	// Get the server connection
	var serverConn *tls.Conn
	select {
	case serverConn = <-connChan:
	case err := <-errChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for connection")
	}

	// Verify the first certificate was used
	state := clientConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("No peer certificates received")
	}
	if state.PeerCertificates[0].SerialNumber.Cmp(firstSerial) != 0 {
		t.Error("First connection did not use the initial certificate")
	}

	// Close the first connection
	clientConn.Close()
	serverConn.Close()

	// Now generate and write a second certificate
	cert2, _, cert2PEM, key2PEM := generateTestCert(t, false, caCert, caKey)
	secondSerial := cert2.SerialNumber

	// Ensure the serial numbers are different
	if firstSerial.Cmp(secondSerial) == 0 {
		t.Fatal("Test setup error: both certificates have the same serial number")
	}

	// Replace the certificate files
	if err := os.WriteFile(certFile, cert2PEM, 0o644); err != nil {
		t.Fatalf("Failed to write updated cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, key2PEM, 0o600); err != nil {
		t.Fatalf("Failed to write updated key file: %v", err)
	}

	// Wait a bit to ensure filesystem changes are visible
	time.Sleep(100 * time.Millisecond)

	// Accept another connection
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			errChan <- err
			return
		}
		connChan <- tlsConn
	}()

	// Connect as a client again
	clientConn2, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to connect as client (second connection): %v", err)
	}
	defer clientConn2.Close()

	// Get the server connection
	select {
	case serverConn = <-connChan:
		defer serverConn.Close()
	case err := <-errChan:
		t.Fatalf("Second server handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for second connection")
	}

	// Verify the second certificate was used
	state2 := clientConn2.ConnectionState()
	if len(state2.PeerCertificates) == 0 {
		t.Fatal("No peer certificates received on second connection")
	}

	receivedSerial := state2.PeerCertificates[0].SerialNumber
	if receivedSerial.Cmp(secondSerial) != 0 {
		t.Errorf("Certificate not reloaded: expected serial %v, got %v", secondSerial, receivedSerial)
		t.Logf("First serial: %v", firstSerial)
		t.Logf("Second serial (expected): %v", secondSerial)
		t.Logf("Received serial: %v", receivedSerial)
	}
}

func TestCertificateReloadFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate initial valid certificate
	caCert, caKey, _, _ := generateTestCert(t, true, nil, nil)
	_, _, certPEM, keyPEM := generateTestCert(t, false, caCert, caKey)

	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create our own TLS config mimicking what NewServerCredentials does
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			// This mimics the implementation in grpcserver/tls.go
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				return nil, err
			}
			keyPEM, err := os.ReadFile(keyFile)
			if err != nil {
				return nil, err
			}
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}

	// Now corrupt the certificate file
	if err := os.WriteFile(certFile, []byte("invalid certificate"), 0o644); err != nil {
		t.Fatalf("Failed to write invalid cert: %v", err)
	}

	// Try to create a TLS listener and accept a connection
	// The handshake should fail because the certificate is now invalid
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	errChan := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		tlsConn := conn.(*tls.Conn)
		err = tlsConn.Handshake()
		conn.Close()
		errChan <- err
	}()

	// Connect as a client
	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})

	// Either the client connection fails or the server handshake fails
	var handshakeErr error
	if err != nil {
		handshakeErr = err
	} else {
		clientConn.Close()
		select {
		case handshakeErr = <-errChan:
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for handshake error")
		}
	}

	// We expect an error because the certificate is now invalid
	if handshakeErr == nil {
		t.Error("Expected handshake to fail with invalid certificate, but it succeeded")
	}
}
