package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// NewLocalHTTPServer starts an HTTP server bound to IPv4 loopback only.
// The sandbox blocks IPv6 listeners, so force tcp4 to keep tests runnable.
func NewLocalHTTPServer(tb testing.TB, handler http.Handler) *httptest.Server {
	tb.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("failed to create IPv4 listener: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()

	return server
}

// RoundTripFunc allows inlining http.RoundTripper implementations.
type RoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls the underlying function.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// MockOAuth2Server simulates an OAuth2 token endpoint without real sockets.
// It records requests and serves responses through a custom RoundTripper.
type MockOAuth2Server struct {
	URL      string
	Ctx      context.Context
	Requests []*http.Request
}

// NewMockOAuth2Server builds a mock OAuth2 endpoint backed by an in-memory RoundTripper.
// If handler is nil, it returns a default successful token response.
func NewMockOAuth2Server(tb testing.TB, handler RoundTripFunc) *MockOAuth2Server {
	tb.Helper()

	server := &MockOAuth2Server{
		URL: "https://mock-oauth.example.com",
	}

	if handler == nil {
		handler = StaticJSONResponse(`{
			"access_token": "mock-access-token",
			"token_type": "Bearer",
			"expires_in": 3600
		}`)
	}

	rt := RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		server.Requests = append(server.Requests, req)
		return handler(req)
	})

	prevTransport := http.DefaultTransport
	prevClient := http.DefaultClient
	http.DefaultTransport = rt
	http.DefaultClient = &http.Client{Transport: rt}
	tb.Cleanup(func() {
		http.DefaultTransport = prevTransport
		http.DefaultClient = prevClient
	})

	server.Ctx = context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: rt,
	})

	return server
}

// Close is a no-op to mirror httptest.Server usage in tests.
func (m *MockOAuth2Server) Close() {}

// StaticJSONResponse returns a RoundTripper that always responds with the provided JSON body.
func StaticJSONResponse(body string) RoundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}
}

// WriteTestCACert writes a self-signed CA certificate to the provided path for TLS tests.
func WriteTestCACert(tb testing.TB, path string) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		Subject:               pkix.Name{CommonName: "test-ca"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		tb.Fatalf("failed to create CA certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		tb.Fatalf("failed to write CA certificate: %v", err)
	}
}

// WriteTestCertAndKey writes a self-signed certificate and key to the provided paths.
func WriteTestCertAndKey(tb testing.TB, certPath, keyPath string) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: "test-cert"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		tb.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		tb.Fatalf("failed to write certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		tb.Fatalf("failed to write key: %v", err)
	}
}
