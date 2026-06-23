package grpcserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestCertFiles writes a self-signed ECDSA cert+key to a temp dir and
// returns their paths. The files are cleaned up automatically via t.TempDir().
func generateTestCertFiles(tb testing.TB) (certFile, keyFile string) {
	tb.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		tb.Fatalf("marshal key: %v", err)
	}

	dir := tb.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		tb.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		tb.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func TestReadTLSFile_EmptyPath(t *testing.T) {
	_, err := readTLSFile("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "empty TLS file path") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadCertificate_EmptyPaths(t *testing.T) {
	if _, err := loadCertificate("", "key.pem"); err == nil {
		t.Fatal("expected error for empty cert path")
	}
	certFile, keyFile := generateTestCertFiles(t)
	if _, err := loadCertificate(certFile, ""); err == nil {
		t.Fatal("expected error for empty key path")
	}
	_ = keyFile
}

func TestLoadCACertificate_EmptyPath(t *testing.T) {
	if _, err := loadCACertificate(""); err == nil {
		t.Fatal("expected error for empty CA path")
	}
}

func TestCertCache_ReloadError(t *testing.T) {
	certFile, keyFile := generateTestCertFiles(t)

	cache, err := newCertCache(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	// Corrupt the files then call reload — should return an error.
	if err := os.WriteFile(certFile, []byte("garbage"), 0600); err != nil {
		t.Fatalf("overwrite cert: %v", err)
	}
	if reloadErr := cache.reload(); reloadErr == nil {
		t.Error("expected reload to fail after corrupting cert files")
	}

	// Cert in memory should still be valid from the initial load.
	cert, err := cache.getCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert == nil {
		t.Errorf("expected cached cert to be returned after failed reload: %v", err)
	}
}

// TestNewServerCredentials_CertificateNotReloadedPerHandshake verifies that
// repeated calls to GetCertificate (one per TLS handshake) do NOT trigger
// additional disk reads. After the initial load the cert files are replaced
// with garbage; getCertificate must still succeed because the cert is cached.
func TestNewServerCredentials_CertificateNotReloadedPerHandshake(t *testing.T) {
	certFile, keyFile := generateTestCertFiles(t)

	cache, err := newCertCache(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	// Overwrite both files with invalid content to poison any future disk read.
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("overwrite cert: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatalf("overwrite key: %v", err)
	}

	// Simulate 10 TLS handshakes; each must succeed from the in-memory cache.
	for i := range 10 {
		cert, err := cache.getCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatalf("handshake %d: getCertificate failed — cert was re-read from disk: %v", i+1, err)
		}
		if cert == nil {
			t.Fatalf("handshake %d: getCertificate returned nil", i+1)
		}
	}
}
